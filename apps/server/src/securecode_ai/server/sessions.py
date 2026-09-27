"""Opaque hashed sessions and single-use, identity-bound capability tokens."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import RLock

from .identity import Principal, Role
from .ports import VerifiedIdentity

_CAPABILITY_CLEANUP_BATCH = 256
_SESSION_CLEANUP_BATCH = 256
_MAX_ID_LENGTH = 256


class SessionError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class SessionReceipt:
    subject_id: str
    tenant_id: str
    expires_at: datetime
    token_id: str


@dataclass(frozen=True, slots=True)
class CapabilityReceipt:
    tenant_id: str
    repository_id: str
    run_id: str
    action: str
    execution_identity_hash: str
    expires_at: datetime
    token_id: str


@dataclass(slots=True)
class _Record:
    receipt: object
    expires_at: datetime
    revoked: bool = False
    used: bool = False


class SessionStore:
    def __init__(
        self,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        max_sessions: int = 100_000,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        if (
            not callable(now)
            or type(max_sessions) is not int
            or not 1 <= max_sessions <= 1_000_000
            or (connection is not None and type(connection) is not sqlite3.Connection)
        ):
            raise SessionError()
        self._now = now
        self._lock = RLock()
        self._max_sessions = max_sessions
        self._connection = connection
        self._sessions: dict[str, tuple[_Record, Principal]] = {}
        self._capabilities: dict[str, _Record] = {}

    def issue_session(
        self, principal: Principal, *, lifetime_seconds: int = 900
    ) -> tuple[str, SessionReceipt]:
        if (
            type(principal) is not Principal
            or type(principal.subject_id) is not str
            or not _safe_identity_value(principal.subject_id)
            or type(principal.tenant_id) is not str
            or not _safe_identity_value(principal.tenant_id)
            or type(principal.roles) is not frozenset
            or not principal.roles
            or not all(type(role) is Role for role in principal.roles)
            or type(principal.repository_grants) is not frozenset
            or len(principal.repository_grants) > 128
            or not all(
                _safe_identity_value(value)
                for value in principal.repository_grants
            )
        ):
            raise SessionError()
        token = _token()
        with self._lock:
            try:
                now = self._now()
                if type(now) is not datetime or now.tzinfo is None:
                    raise SessionError()
                now = now.astimezone(UTC)
                expiry = now + timedelta(seconds=_lifetime(lifetime_seconds))
                receipt = SessionReceipt(
                    principal.subject_id, principal.tenant_id, expiry, _token_id(token)
                )
                token_hash = _hash(token)
                if self._connection is None:
                    self._discard_inactive_sessions(now)
                    if len(self._sessions) >= self._max_sessions:
                        raise SessionError()
                    self._sessions[token_hash] = (_Record(receipt, expiry), principal)
                else:
                    self._issue_persisted_session(token_hash, principal, expiry, now)
            except SessionError:
                raise
            except Exception:
                raise SessionError() from None
        return token, receipt

    def verify_session(self, token: str) -> Principal:
        if type(token) is not str or not token.isascii() or not 1 <= len(token) <= 8192:
            raise SessionError()
        try:
            with self._lock:
                token_hash = _hash(token)
                now = self._now()
                if type(now) is not datetime or now.utcoffset() is None:
                    raise SessionError()
                now = now.astimezone(UTC)
                if self._connection is None:
                    record = self._sessions.get(token_hash)
                    if record is None or not _active(record[0], now):
                        raise SessionError()
                    return record[1]
                return self._verify_persisted_session(token_hash, now)
        except SessionError:
            raise
        except Exception:
            raise SessionError() from None

    def revoke_session(self, token: str) -> None:
        if type(token) is not str or not token.isascii() or not 1 <= len(token) <= 8192:
            raise SessionError()
        try:
            with self._lock:
                token_hash = _hash(token)
                if self._connection is not None:
                    had_transaction = self._connection.in_transaction
                    self._connection.execute("SAVEPOINT session_revoke")
                    changed = self._connection.execute(
                        "UPDATE auth_sessions SET revoked=1 WHERE token_hash=? AND revoked=0",
                        (token_hash,),
                    ).rowcount
                    if changed != 1:
                        _rollback_savepoint(self._connection, "session_revoke")
                        raise SessionError()
                    self._connection.execute("RELEASE session_revoke")
                    if not had_transaction:
                        self._connection.commit()
                    return
                record = self._sessions.get(token_hash)
        except (AttributeError, UnicodeEncodeError, ValueError, sqlite3.Error):
            if self._connection is not None:
                _rollback_savepoint(self._connection, "session_revoke")
            raise SessionError() from None
        if record is None:
            raise SessionError()
        with self._lock:
            record[0].revoked = True

    def purge_inactive_sessions(
        self,
        *,
        max_items: int = 100,
        now: datetime | None = None,
    ) -> int:
        """Delete a bounded batch of expired or revoked persisted sessions."""

        if type(max_items) is not int or not 1 <= max_items <= 10_000:
            raise SessionError()
        try:
            current = self._now() if now is None else now
            if type(current) is not datetime or current.utcoffset() is None:
                raise SessionError()
            current = current.astimezone(UTC)
            with self._lock:
                if self._connection is None:
                    inactive: list[str] = []
                    for token_hash, (record, _) in self._sessions.items():
                        if record.revoked or record.expires_at <= current:
                            inactive.append(token_hash)
                            if len(inactive) >= max_items:
                                break
                    for token_hash in inactive:
                        del self._sessions[token_hash]
                    return len(inactive)
                had_transaction = self._connection.in_transaction
                self._connection.execute("SAVEPOINT session_purge")
                changed = self._connection.execute(
                    """DELETE FROM auth_sessions
                       WHERE token_hash IN (
                           SELECT token_hash FROM auth_sessions
                           WHERE revoked=1 OR expires_at<=?
                           ORDER BY expires_at, token_hash LIMIT ?
                       )""",
                    (current.isoformat(timespec="microseconds"), max_items),
                ).rowcount
                self._connection.execute("RELEASE session_purge")
                if not had_transaction:
                    self._connection.commit()
                return changed
        except SessionError:
            if self._connection is not None:
                _rollback_savepoint(self._connection, "session_purge")
            raise
        except Exception:
            if self._connection is not None:
                _rollback_savepoint(self._connection, "session_purge")
            raise SessionError() from None

    def has_inactive_sessions(self, *, now: datetime | None = None) -> bool:
        try:
            current = self._now() if now is None else now
            if type(current) is not datetime or current.utcoffset() is None:
                raise SessionError()
            current = current.astimezone(UTC)
            with self._lock:
                if self._connection is None:
                    return any(
                        record.revoked or record.expires_at <= current
                        for record, _ in self._sessions.values()
                    )
                row = self._connection.execute(
                    """SELECT 1 FROM auth_sessions
                       WHERE revoked=1 OR expires_at<=? LIMIT 1""",
                    (current.isoformat(timespec="microseconds"),),
                ).fetchone()
                return row is not None
        except SessionError:
            raise
        except Exception:
            raise SessionError() from None

    def rotate_session(
        self, token: str, *, lifetime_seconds: int = 900
    ) -> tuple[str, SessionReceipt]:
        with self._lock:
            if self._connection is None:
                principal = self.verify_session(token)
                rotated = self.issue_session(
                    principal, lifetime_seconds=lifetime_seconds
                )
                try:
                    self.revoke_session(token)
                except Exception:
                    self._sessions.pop(_hash(rotated[0]), None)
                    raise SessionError() from None
                return rotated

            connection = self._connection
            savepoint_active = False
            try:
                connection.execute("SAVEPOINT session_rotate")
                savepoint_active = True
                principal = self.verify_session(token)
                self.revoke_session(token)
                rotated = self.issue_session(
                    principal, lifetime_seconds=lifetime_seconds
                )
                connection.execute("RELEASE session_rotate")
                savepoint_active = False
                return rotated
            except Exception:
                if savepoint_active:
                    _rollback_savepoint(connection, "session_rotate")
                raise SessionError() from None

    def issue_capability(
        self,
        principal: Principal,
        *,
        repository_id: str,
        run_id: str,
        action: str,
        execution_identity_hash: str,
        lifetime_seconds: int = 300,
    ) -> tuple[str, CapabilityReceipt]:
        if (
            type(principal) is not Principal
            or not principal.allows(action=action, repository_id=repository_id)
            or not _valid_capability_binding(
                principal.tenant_id,
                repository_id,
                run_id,
                action,
                execution_identity_hash,
            )
        ):
            raise SessionError()
        token = _token()
        try:
            now = self._now()
            if type(now) is not datetime or now.utcoffset() is None:
                raise SessionError()
            now = now.astimezone(UTC)
            expiry = now + timedelta(seconds=_lifetime(lifetime_seconds))
            receipt = CapabilityReceipt(
                principal.tenant_id,
                repository_id,
                run_id,
                action,
                execution_identity_hash,
                expiry,
                _token_id(token),
            )
            with self._lock:
                token_hash = _hash(token)
                if self._connection is None:
                    self._discard_inactive_capabilities(now)
                    if len(self._capabilities) >= self._max_sessions:
                        raise SessionError()
                    self._capabilities[token_hash] = _Record(receipt, expiry)
                else:
                    self._issue_persisted_capability(token_hash, receipt, now)
        except SessionError:
            raise
        except Exception:
            raise SessionError() from None
        return token, receipt

    def consume_capability(
        self,
        token: str,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        action: str,
        execution_identity_hash: str,
    ) -> CapabilityReceipt:
        if (
            type(token) is not str
            or not token.isascii()
            or not 1 <= len(token) <= 8192
            or not _valid_capability_binding(
                tenant_id,
                repository_id,
                run_id,
                action,
                execution_identity_hash,
            )
        ):
            raise SessionError()
        with self._lock:
            if self._connection is None:
                now = self._now()
                if type(now) is not datetime or now.utcoffset() is None:
                    raise SessionError()
                now = now.astimezone(UTC)
                record = self._capabilities.get(_hash(token))
                if (
                    record is None
                    or not _active(record, now)
                    or record.used
                    or not isinstance(record.receipt, CapabilityReceipt)
                ):
                    raise SessionError()
                receipt = record.receipt
                if (
                    receipt.tenant_id,
                    receipt.repository_id,
                    receipt.run_id,
                    receipt.action,
                    receipt.execution_identity_hash,
                ) != (tenant_id, repository_id, run_id, action, execution_identity_hash):
                    raise SessionError()
                record.used = True
                return receipt
            return self._consume_persisted_capability(
                _hash(token),
                tenant_id=tenant_id,
                repository_id=repository_id,
                run_id=run_id,
                action=action,
                execution_identity_hash=execution_identity_hash,
            )

    def _issue_persisted_capability(
        self, token_hash: str, receipt: CapabilityReceipt, now: datetime
    ) -> None:
        connection = self._connection
        if connection is None:  # pragma: no cover - guarded by caller
            raise SessionError()
        had_transaction = connection.in_transaction
        savepoint_active = False
        try:
            connection.execute("SAVEPOINT capability_issue")
            savepoint_active = True
            connection.execute(
                """DELETE FROM auth_capabilities
                   WHERE token_hash IN (
                       SELECT token_hash FROM auth_capabilities
                       WHERE used=1 OR expires_at<=?
                       ORDER BY expires_at, token_hash LIMIT ?
                   )""",
                (now.isoformat(timespec="microseconds"), _CAPABILITY_CLEANUP_BATCH),
            )
            count = connection.execute(
                "SELECT COUNT(*) FROM auth_capabilities"
            ).fetchone()
            if count is None or type(count[0]) is not int:
                raise SessionError()
            if count[0] >= self._max_sessions:
                # Preserve bounded reclamation even when issuance is rejected.
                # Otherwise a full store of expired or consumed capabilities
                # would roll back the cleanup and remain permanently wedged.
                connection.execute("RELEASE capability_issue")
                savepoint_active = False
                if not had_transaction:
                    connection.commit()
                raise SessionError()
            connection.execute(
                """INSERT INTO auth_capabilities
                   (token_hash, tenant_id, repository_id, run_id, action,
                    execution_identity_hash, expires_at, used)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 0)""",
                (
                    token_hash,
                    receipt.tenant_id,
                    receipt.repository_id,
                    receipt.run_id,
                    receipt.action,
                    receipt.execution_identity_hash,
                    receipt.expires_at.astimezone(UTC).isoformat(timespec="microseconds"),
                ),
            )
            connection.execute("RELEASE capability_issue")
            savepoint_active = False
            if not had_transaction:
                connection.commit()
        except Exception:
            if savepoint_active:
                _rollback_savepoint(connection, "capability_issue")
            raise SessionError() from None

    def _discard_inactive_capabilities(self, now: datetime) -> None:
        inactive = tuple(
            token_hash
            for token_hash, record in self._capabilities.items()
            if record.used or record.expires_at <= now
        )[:_CAPABILITY_CLEANUP_BATCH]
        for token_hash in inactive:
            del self._capabilities[token_hash]

    def _consume_persisted_capability(
        self,
        token_hash: str,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        action: str,
        execution_identity_hash: str,
    ) -> CapabilityReceipt:
        connection = self._connection
        if connection is None:  # pragma: no cover - guarded by caller
            raise SessionError()
        had_transaction = connection.in_transaction
        now = self._now()
        if type(now) is not datetime or now.utcoffset() is None:
            raise SessionError()
        now = now.astimezone(UTC)
        now_text = now.isoformat(timespec="microseconds")
        try:
            connection.execute("SAVEPOINT capability_consume")
            row = connection.execute(
                """SELECT tenant_id, repository_id, run_id, action,
                          execution_identity_hash, expires_at, used
                   FROM auth_capabilities WHERE token_hash=?""",
                (token_hash,),
            ).fetchone()
            if row is None or len(row) != 7:
                raise SessionError()
            stored_tenant, stored_repository, stored_run, stored_action = row[:4]
            stored_identity_hash, expiry_text, used = row[4:]
            if (
                type(stored_tenant) is not str
                or type(stored_repository) is not str
                or type(stored_run) is not str
                or type(stored_action) is not str
                or type(stored_identity_hash) is not str
                or type(expiry_text) is not str
                or type(used) is not int
                or used not in (0, 1)
                or not _valid_capability_binding(
                    stored_tenant,
                    stored_repository,
                    stored_run,
                    stored_action,
                    stored_identity_hash,
                )
            ):
                raise SessionError()
            expiry = datetime.fromisoformat(expiry_text)
            if expiry.tzinfo is None or expiry.astimezone(UTC) <= now:
                raise SessionError()
            if (
                (
                    stored_tenant,
                    stored_repository,
                    stored_run,
                    stored_action,
                    stored_identity_hash,
                )
                != (
                    tenant_id,
                    repository_id,
                    run_id,
                    action,
                    execution_identity_hash,
                )
                or used != 0
            ):
                raise SessionError()
            changed = connection.execute(
                """UPDATE auth_capabilities SET used=1
                   WHERE token_hash=? AND tenant_id=? AND repository_id=?
                     AND run_id=? AND action=? AND execution_identity_hash=?
                     AND expires_at>? AND used=0""",
                (
                    token_hash,
                    tenant_id,
                    repository_id,
                    run_id,
                    action,
                    execution_identity_hash,
                    now_text,
                ),
            ).rowcount
            if changed != 1:
                raise SessionError()
            receipt = CapabilityReceipt(
                tenant_id,
                repository_id,
                run_id,
                action,
                execution_identity_hash,
                expiry.astimezone(UTC),
                token_hash[:16],
            )
            connection.execute("RELEASE capability_consume")
            if not had_transaction:
                connection.commit()
            return receipt
        except SessionError:
            _rollback_savepoint(connection, "capability_consume")
            raise
        except Exception:
            _rollback_savepoint(connection, "capability_consume")
            raise SessionError() from None

    def _discard_inactive_sessions(self, now: datetime) -> None:
        expired = tuple(
            token_hash
            for token_hash, (record, _) in self._sessions.items()
            if record.revoked or record.expires_at <= now
        )
        for token_hash in expired:
            del self._sessions[token_hash]

    def _issue_persisted_session(
        self,
        token_hash: str,
        principal: Principal,
        expiry: datetime,
        now: datetime,
    ) -> None:
        connection = self._connection
        if connection is None:  # pragma: no cover - guarded by caller
            raise SessionError()
        had_transaction = connection.in_transaction
        savepoint_active = False
        try:
            connection.execute("SAVEPOINT session_issue")
            savepoint_active = True
            connection.execute(
                """DELETE FROM auth_sessions
                   WHERE token_hash IN (
                       SELECT token_hash FROM auth_sessions
                       WHERE revoked=1 OR expires_at<=?
                       ORDER BY expires_at, token_hash LIMIT ?
                   )""",
                (now.isoformat(timespec="microseconds"), _SESSION_CLEANUP_BATCH),
            )
            count = connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()
            if count is None or type(count[0]) is not int:
                raise SessionError()
            if count[0] >= self._max_sessions:
                # Keep bounded reclamation even when the new session cannot
                # fit, so expired sessions do not permanently occupy capacity.
                connection.execute("RELEASE session_issue")
                savepoint_active = False
                if not had_transaction:
                    connection.commit()
                raise SessionError()
            connection.execute(
                """INSERT INTO auth_sessions
                   (token_hash, subject_id, tenant_id, roles_json,
                    repository_grants_json, expires_at, revoked)
                   VALUES (?, ?, ?, ?, ?, ?, 0)""",
                (
                    token_hash,
                    principal.subject_id,
                    principal.tenant_id,
                    json.dumps(
                        sorted(role.value for role in principal.roles), separators=(",", ":")
                    ),
                    json.dumps(sorted(principal.repository_grants), separators=(",", ":")),
                    expiry.astimezone(UTC).isoformat(timespec="microseconds"),
                ),
            )
            connection.execute("RELEASE session_issue")
            savepoint_active = False
            if not had_transaction:
                connection.commit()
        except SessionError:
            if savepoint_active:
                _rollback_savepoint(connection, "session_issue")
            raise
        except Exception:
            if savepoint_active:
                _rollback_savepoint(connection, "session_issue")
            raise SessionError() from None

    def _verify_persisted_session(self, token_hash: str, now: datetime) -> Principal:
        connection = self._connection
        if connection is None:  # pragma: no cover - guarded by caller
            raise SessionError()
        try:
            row = connection.execute(
                """SELECT subject_id, tenant_id, roles_json, repository_grants_json,
                          expires_at, revoked
                   FROM auth_sessions WHERE token_hash=?""",
                (token_hash,),
            ).fetchone()
            if row is None or type(row[5]) is not int or row[5] != 0:
                raise SessionError()
            subject_id, tenant_id, roles_json, grants_json, expiry_text, _ = row
            if (
                type(subject_id) is not str
                or not _safe_identity_value(subject_id)
                or type(tenant_id) is not str
                or not _safe_identity_value(tenant_id)
                or type(roles_json) is not str
                or len(roles_json) > 2048
                or type(grants_json) is not str
                or len(grants_json) > 32_768
                or type(expiry_text) is not str
            ):
                raise SessionError()
            expiry = datetime.fromisoformat(expiry_text)
            roles_value = json.loads(roles_json)
            grants_value = json.loads(grants_json)
            if (
                expiry.tzinfo is None
                or expiry <= now
                or type(roles_value) is not list
                or not 1 <= len(roles_value) <= len(Role)
                or not all(type(role) is str for role in roles_value)
                or roles_value != sorted(set(roles_value))
                or type(grants_value) is not list
                or len(grants_value) > 128
                or not all(_safe_identity_value(grant) for grant in grants_value)
                or grants_value != sorted(set(grants_value))
            ):
                raise SessionError()
            roles = frozenset(Role(value) for value in roles_value)
            return Principal(
                subject_id=subject_id,
                tenant_id=tenant_id,
                roles=roles,
                repository_grants=frozenset(grants_value),
            )
        except SessionError:
            raise
        except Exception:
            raise SessionError() from None


class SessionIdentityVerifier:
    """Resolve opaque session bearers into the same identity contract as JWTs."""

    __slots__ = ("_principal_is_active", "_store")

    def __init__(
        self,
        store: SessionStore,
        *,
        principal_is_active: Callable[[Principal], bool | None] | None = None,
    ) -> None:
        if type(store) is not SessionStore or (
            principal_is_active is not None and not callable(principal_is_active)
        ):
            raise SessionError()
        self._store = store
        self._principal_is_active = principal_is_active

    def verify_bearer(self, token: str) -> VerifiedIdentity | None:
        try:
            principal = self._store.verify_session(token)
            if self._principal_is_active is not None:
                state = self._principal_is_active(principal)
                if state is False:
                    self._store.revoke_session(token)
                    return None
                if state is not True:
                    return None
        except Exception:
            return None
        try:
            return VerifiedIdentity(
                subject_id=principal.subject_id,
                tenant_id=principal.tenant_id,
                roles=frozenset(role.value for role in principal.roles),
                repository_ids=principal.repository_grants,
            )
        except Exception:
            return None


def _token() -> str:
    return secrets.token_urlsafe(32)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _token_id(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()[:16]


def _active(record: _Record, now: datetime) -> bool:
    return not record.revoked and record.expires_at > now


def _lifetime(value: int) -> int:
    if type(value) is not int or not 1 <= value <= 3600:
        raise SessionError()
    return value


def _safe_identity_value(value: object) -> bool:
    if (
        type(value) is not str
        or not 1 <= len(value) <= _MAX_ID_LENGTH
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        return False
    try:
        return len(value.encode("utf-8")) <= _MAX_ID_LENGTH * 4
    except UnicodeEncodeError:
        return False


def _valid_capability_binding(
    tenant_id: object,
    repository_id: object,
    run_id: object,
    action: object,
    execution_identity_hash: object,
) -> bool:
    values = (tenant_id, repository_id, run_id)
    if any(
        type(value) is not str
        or not 1 <= len(value) <= 256
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        for value in values
    ):
        return False
    return (
        type(action) is str
        and 1 <= len(action) <= 128
        and action == action.strip()
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in action)
        and type(execution_identity_hash) is str
        and len(execution_identity_hash) == 64
        and all(character in "0123456789abcdef" for character in execution_identity_hash)
    )


def _rollback_savepoint(connection: sqlite3.Connection, name: str) -> None:
    try:
        connection.execute(f"ROLLBACK TO {name}")
        connection.execute(f"RELEASE {name}")
    except sqlite3.Error:
        pass
