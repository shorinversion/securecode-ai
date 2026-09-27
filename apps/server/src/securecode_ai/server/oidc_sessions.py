"""OIDC replay nonce ledger and injected safe session issuer."""

from __future__ import annotations

import hashlib
import heapq
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Protocol

from .identity import Principal, Role
from .oidc import OidcDenied, OidcReceipt
from .sessions import SessionReceipt, SessionStore

_DEFAULT_MAX_ENTRIES = 100_000
_MAX_NONCE_LENGTH = 1_024
_MAX_SUBJECT_LENGTH = 2_048
_SOURCE_HASH_LENGTH = 64


class SessionIssuer(Protocol):
    def issue(self, principal: Principal, *, token_expires_at: int) -> IssuedOidcSession: ...


class LoginStatePort(Protocol):
    def create(self, *, state: str, nonce: str, expires_at: int) -> None: ...

    def matches(self, *, state: str, nonce: str, now: int) -> bool: ...

    def consume(self, *, state: str, nonce: str, now: int) -> bool: ...

    def charge_attempt(self, *, bucket: str, now: int, limit: int, window_seconds: int) -> None: ...


class SqliteOidcLoginState:
    """Share one-use OIDC state across server processes without storing tokens."""

    __slots__ = ("_connection", "_lock")

    def __init__(self, connection: sqlite3.Connection) -> None:
        if type(connection) is not sqlite3.Connection:
            raise OidcDenied()
        self._connection = connection
        self._lock = Lock()

    def create(self, *, state: str, nonce: str, expires_at: int) -> None:
        state_hash = _state_hash(b"state", state)
        nonce_hash = _state_hash(b"nonce", nonce)
        now = int(datetime.now(UTC).timestamp())
        if type(expires_at) is not int or not now < expires_at <= now + 600:
            raise OidcDenied()
        with self._lock:
            had_transaction = self._connection.in_transaction
            try:
                self._connection.execute("SAVEPOINT oidc_state_create")
                self._connection.execute(
                    "DELETE FROM oidc_login_states WHERE expires_at<=?",
                    (int(datetime.now(UTC).timestamp()),),
                )
                count = self._connection.execute(
                    "SELECT COUNT(*) FROM oidc_login_states"
                ).fetchone()
                if count is None or type(count[0]) is not int or count[0] >= _DEFAULT_MAX_ENTRIES:
                    raise OidcDenied()
                self._connection.execute(
                    "INSERT INTO oidc_login_states (state_hash, nonce_hash, expires_at) VALUES (?, ?, ?)",
                    (state_hash, nonce_hash, expires_at),
                )
                self._connection.execute("RELEASE oidc_state_create")
                if not had_transaction:
                    self._connection.commit()
            except OidcDenied:
                _rollback_savepoint(self._connection, "oidc_state_create")
                raise
            except Exception:
                _rollback_savepoint(self._connection, "oidc_state_create")
                raise OidcDenied() from None

    def matches(self, *, state: str, nonce: str, now: int) -> bool:
        state_hash = _state_hash(b"state", state)
        nonce_hash = _state_hash(b"nonce", nonce)
        if type(now) is not int or now < 0:
            raise OidcDenied()
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT 1 FROM oidc_login_states "
                    "WHERE state_hash=? AND nonce_hash=? AND expires_at>?",
                    (state_hash, nonce_hash, now),
                ).fetchone()
                return row is not None and type(row[0]) is int and row[0] == 1
            except Exception:
                raise OidcDenied() from None

    def consume(self, *, state: str, nonce: str, now: int) -> bool:
        state_hash = _state_hash(b"state", state)
        nonce_hash = _state_hash(b"nonce", nonce)
        if type(now) is not int or now < 0:
            raise OidcDenied()
        with self._lock:
            had_transaction = self._connection.in_transaction
            try:
                self._connection.execute("SAVEPOINT oidc_state_consume")
                self._connection.execute(
                    "DELETE FROM oidc_login_states WHERE expires_at<=?", (now,)
                )
                changed = self._connection.execute(
                    "DELETE FROM oidc_login_states WHERE state_hash=? AND nonce_hash=? AND expires_at>?",
                    (state_hash, nonce_hash, now),
                ).rowcount
                self._connection.execute("RELEASE oidc_state_consume")
                if not had_transaction:
                    self._connection.commit()
                return changed == 1
            except Exception:
                _rollback_savepoint(self._connection, "oidc_state_consume")
                raise OidcDenied() from None

    def purge_expired(self, *, now: int, max_items: int = 100) -> int:
        """Delete a bounded batch of expired state and nonce hashes."""

        if (
            type(now) is not int
            or now < 0
            or type(max_items) is not int
            or not 1 <= max_items <= 10_000
        ):
            raise OidcDenied()
        with self._lock:
            had_transaction = self._connection.in_transaction
            try:
                self._connection.execute("SAVEPOINT oidc_state_purge")
                changed = self._connection.execute(
                    """DELETE FROM oidc_login_states
                       WHERE state_hash IN (
                           SELECT state_hash FROM oidc_login_states
                           WHERE expires_at<=? ORDER BY expires_at, state_hash LIMIT ?
                       )""",
                    (now, max_items),
                ).rowcount
                self._connection.execute("RELEASE oidc_state_purge")
                if not had_transaction:
                    self._connection.commit()
                return changed
            except Exception:
                _rollback_savepoint(self._connection, "oidc_state_purge")
                raise OidcDenied() from None

    def has_expired(self, *, now: int) -> bool:
        if type(now) is not int or now < 0:
            raise OidcDenied()
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT 1 FROM oidc_login_states WHERE expires_at<=? LIMIT 1",
                    (now,),
                ).fetchone()
                return row is not None
            except Exception:
                raise OidcDenied() from None

    def charge_attempt(self, *, bucket: str, now: int, limit: int, window_seconds: int) -> None:
        if (
            type(bucket) is not str
            or bucket not in {"start", "callback"}
            or type(now) is not int
            or now < 0
            or type(limit) is not int
            or not 1 <= limit <= _DEFAULT_MAX_ENTRIES
            or type(window_seconds) is not int
            or not 1 <= window_seconds <= 3600
        ):
            raise OidcDenied()
        with self._lock:
            had_transaction = self._connection.in_transaction
            try:
                self._connection.execute("SAVEPOINT oidc_attempt_charge")
                row = self._connection.execute(
                    "SELECT window_started_at, attempts FROM oidc_login_rate_limit WHERE bucket=?",
                    (bucket,),
                ).fetchone()
                if row is None:
                    self._connection.execute(
                        "INSERT INTO oidc_login_rate_limit (bucket, window_started_at, attempts) VALUES (?, ?, 1)",
                        (bucket, now),
                    )
                else:
                    started, attempts = row
                    if (
                        type(started) is not int
                        or started < 0
                        or type(attempts) is not int
                        or attempts < 1
                    ):
                        raise OidcDenied()
                    if now < started:
                        raise OidcDenied()
                    if now - started >= window_seconds:
                        self._connection.execute(
                            "UPDATE oidc_login_rate_limit SET window_started_at=?, attempts=1 WHERE bucket=?",
                            (now, bucket),
                        )
                    elif attempts >= limit:
                        raise OidcDenied()
                    else:
                        self._connection.execute(
                            "UPDATE oidc_login_rate_limit SET attempts=attempts+1 WHERE bucket=?",
                            (bucket,),
                        )
                self._connection.execute("RELEASE oidc_attempt_charge")
                if not had_transaction:
                    self._connection.commit()
            except OidcDenied:
                _rollback_savepoint(self._connection, "oidc_attempt_charge")
                raise
            except Exception:
                _rollback_savepoint(self._connection, "oidc_attempt_charge")
                raise OidcDenied() from None

    def charge_source_attempt(
        self,
        *,
        bucket: str,
        source_hash: str,
        now: int,
        limit: int,
        window_seconds: int,
    ) -> None:
        """Charge a hashed source bucket shared by all server replicas.

        ``source_hash`` is intentionally accepted only as a lowercase SHA-256
        hex digest.  This keeps raw network identifiers out of the durable
        login state while allowing the login service to maintain a per-source
        limit independently from the aggregate bucket above.
        """

        if (
            type(bucket) is not str
            or bucket not in {"start", "callback"}
            or type(source_hash) is not str
            or len(source_hash) != _SOURCE_HASH_LENGTH
            or any(character not in "0123456789abcdef" for character in source_hash)
            or type(now) is not int
            or now < 0
            or type(limit) is not int
            or not 1 <= limit <= _DEFAULT_MAX_ENTRIES
            or type(window_seconds) is not int
            or not 1 <= window_seconds <= 3600
        ):
            raise OidcDenied()
        with self._lock:
            rate_limited = False
            had_transaction = self._connection.in_transaction
            try:
                self._connection.execute("SAVEPOINT oidc_source_attempt_charge")
                self._connection.execute(
                    "DELETE FROM oidc_login_source_rate_limit "
                    "WHERE window_started_at <= ? "
                    "AND window_started_at + window_seconds <= ?",
                    (now, now),
                )
                row = self._connection.execute(
                    "SELECT window_started_at, window_seconds, attempts "
                    "FROM oidc_login_source_rate_limit "
                    "WHERE bucket=? AND source_hash=?",
                    (bucket, source_hash),
                ).fetchone()
                if row is None:
                    count = self._connection.execute(
                        "SELECT COUNT(*) FROM oidc_login_source_rate_limit"
                    ).fetchone()
                    if (
                        count is None
                        or type(count[0]) is not int
                    ):
                        raise OidcDenied()
                    if count[0] >= _DEFAULT_MAX_ENTRIES:
                        rate_limited = True
                    else:
                        self._connection.execute(
                            "INSERT INTO oidc_login_source_rate_limit "
                            "(bucket, source_hash, window_started_at, window_seconds, attempts) "
                            "VALUES (?, ?, ?, ?, 1)",
                            (bucket, source_hash, now, window_seconds),
                        )
                else:
                    started, stored_window, attempts = row
                    if (
                        type(started) is not int
                        or started < 0
                        or type(stored_window) is not int
                        or not 1 <= stored_window <= 3600
                        or type(attempts) is not int
                        or attempts < 1
                    ):
                        raise OidcDenied()
                    if now < started:
                        raise OidcDenied()
                    if now - started >= window_seconds:
                        self._connection.execute(
                            "UPDATE oidc_login_source_rate_limit "
                            "SET window_started_at=?, window_seconds=?, attempts=1 "
                            "WHERE bucket=? AND source_hash=?",
                            (now, window_seconds, bucket, source_hash),
                        )
                    elif attempts >= limit:
                        rate_limited = True
                    else:
                        self._connection.execute(
                            "UPDATE oidc_login_source_rate_limit SET attempts=attempts+1 "
                            "WHERE bucket=? AND source_hash=?",
                            (bucket, source_hash),
                        )
                self._connection.execute("RELEASE oidc_source_attempt_charge")
                if not had_transaction:
                    self._connection.commit()
            except OidcDenied:
                _rollback_savepoint(self._connection, "oidc_source_attempt_charge")
                raise
            except Exception:
                _rollback_savepoint(self._connection, "oidc_source_attempt_charge")
                raise OidcDenied() from None
            if rate_limited:
                raise OidcDenied()


@dataclass(frozen=True, slots=True)
class IssuedOidcSession:
    token: str = field(repr=False)
    receipt: OidcReceipt


class OpaqueSessionIssuer:
    """Issue opaque API sessions whose lifetime cannot exceed the signed token."""

    __slots__ = ("_store",)

    def __init__(self, store: SessionStore) -> None:
        if type(store) is not SessionStore:
            raise OidcDenied()
        self._store = store

    def issue(self, principal: Principal, *, token_expires_at: int) -> IssuedOidcSession:
        if (
            type(principal) is not Principal
            or type(principal.subject_id) is not str
            or not 1 <= len(principal.subject_id) <= 256
            or not _safe_principal_value(principal.subject_id)
            or type(principal.tenant_id) is not str
            or not 1 <= len(principal.tenant_id) <= 256
            or not _safe_principal_value(principal.tenant_id)
            or type(principal.roles) is not frozenset
            or not principal.roles
            or not all(type(role) is Role for role in principal.roles)
            or type(principal.repository_grants) is not frozenset
            or len(principal.repository_grants) > 128
            or not all(
                type(grant) is str
                and 1 <= len(grant) <= 256
                and _safe_principal_value(grant)
                for grant in principal.repository_grants
            )
            or type(token_expires_at) is not int
        ):
            raise OidcDenied()
        now = datetime.now(UTC)
        remaining = token_expires_at - int(now.timestamp()) - 1
        if not 1 <= remaining <= 86_400:
            raise OidcDenied()
        try:
            token, session = self._store.issue_session(
                principal,
                lifetime_seconds=min(3600, remaining),
            )
        except Exception:
            raise OidcDenied() from None
        token_expiry = datetime.fromtimestamp(token_expires_at, UTC)
        session_expiry = session.expires_at if type(session) is SessionReceipt else None
        expiry_is_valid = False
        if type(session_expiry) is datetime:
            try:
                expiry_is_valid = session_expiry.utcoffset() is not None
            except Exception:
                expiry_is_valid = False
        if (
            type(token) is not str
            or not 32 <= len(token) <= 8192
            or not token.isascii()
            or type(session) is not SessionReceipt
            or session.subject_id != principal.subject_id
            or session.tenant_id != principal.tenant_id
            or not expiry_is_valid
            or session_expiry is None
            or not now < session_expiry <= token_expiry
            or session_expiry > now + timedelta(seconds=3600)
        ):
            if type(token) is str and token.isascii() and 1 <= len(token) <= 8192:
                try:
                    self._store.revoke_session(token)
                except Exception:
                    pass
            raise OidcDenied()
        receipt = OidcReceipt(
            subject_id=session.subject_id,
            tenant_id=session.tenant_id,
            roles=tuple(sorted(role.value for role in principal.roles)),
            expires_at=int(session.expires_at.timestamp()),
        )
        return IssuedOidcSession(token=token, receipt=receipt)


class NonceReplayLedger:
    def __init__(
        self,
        *,
        now: Callable[[], int] = lambda: int(datetime.now(UTC).timestamp()),
        max_entries: int = _DEFAULT_MAX_ENTRIES,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        if (
            not callable(now)
            or type(max_entries) is not int
            or not 1 <= max_entries <= _DEFAULT_MAX_ENTRIES
            or (connection is not None and type(connection) is not sqlite3.Connection)
        ):
            raise OidcDenied()

        self._now = now
        self._max_entries = max_entries
        self._connection = connection
        self._values: dict[tuple[str, str], int] = {}
        self._expiry_heap: list[tuple[int, str, str]] = []
        self._lock = Lock()

    def consume(self, receipt: OidcReceipt, nonce: str) -> None:
        if (
            type(receipt) is not OidcReceipt
            or type(receipt.subject_id) is not str
            or not 0 < len(receipt.subject_id) <= _MAX_SUBJECT_LENGTH
            or type(receipt.expires_at) is not int
            or not _safe_hash_value(nonce)
        ):
            raise OidcDenied()

        key = (receipt.subject_id, nonce)
        with self._lock:
            try:
                current_time = self._now()
            except Exception:
                raise OidcDenied() from None
            if type(current_time) is not int or current_time < 0:
                raise OidcDenied()

            if receipt.expires_at <= current_time:
                raise OidcDenied()
            if self._connection is not None:
                self._consume_persisted(receipt.subject_id, nonce, receipt.expires_at, current_time)
                return
            self._discard_expired(current_time)
            if key in self._values:
                raise OidcDenied()
            if len(self._values) >= self._max_entries:
                raise OidcDenied()

            self._values[key] = receipt.expires_at
            heapq.heappush(
                self._expiry_heap,
                (receipt.expires_at, receipt.subject_id, nonce),
            )

    def purge_expired(self, *, now: int | None = None, max_items: int = 100) -> int:
        """Delete a bounded batch of consumed nonce replay hashes."""

        if type(max_items) is not int or not 1 <= max_items <= 10_000:
            raise OidcDenied()
        try:
            current_time = self._now()
        except Exception:
            raise OidcDenied() from None
        if (
            type(current_time) is not int
            or current_time < 0
            or (now is not None and (type(now) is not int or now < 0 or now > current_time))
        ):
            raise OidcDenied()
        effective_now = current_time if now is None else now
        with self._lock:
            if self._connection is None:
                removed = 0
                inspected = 0
                while (
                    self._expiry_heap
                    and self._expiry_heap[0][0] <= effective_now
                    and inspected < max_items
                ):
                    expires_at, subject_id, nonce = heapq.heappop(self._expiry_heap)
                    inspected += 1
                    key = (subject_id, nonce)
                    if self._values.get(key) == expires_at:
                        del self._values[key]
                        removed += 1
                return removed
            connection = self._connection
            had_transaction = connection.in_transaction
            try:
                connection.execute("SAVEPOINT oidc_nonce_purge")
                changed = connection.execute(
                    """DELETE FROM oidc_nonce_replays
                       WHERE rowid IN (
                           SELECT rowid FROM oidc_nonce_replays
                           WHERE expires_at<=? ORDER BY expires_at LIMIT ?
                       )""",
                    (effective_now, max_items),
                ).rowcount
                connection.execute("RELEASE oidc_nonce_purge")
                if not had_transaction:
                    connection.commit()
                return changed
            except Exception:
                _rollback_savepoint(connection, "oidc_nonce_purge")
                raise OidcDenied() from None

    def has_expired(self, *, now: int | None = None) -> bool:
        try:
            effective_now = self._now() if now is None else now
        except Exception:
            raise OidcDenied() from None
        if type(effective_now) is not int or effective_now < 0:
            raise OidcDenied()
        with self._lock:
            if self._connection is None:
                return bool(self._expiry_heap and self._expiry_heap[0][0] <= effective_now)
            try:
                row = self._connection.execute(
                    "SELECT 1 FROM oidc_nonce_replays WHERE expires_at<=? LIMIT 1",
                    (effective_now,),
                ).fetchone()
                return row is not None
            except Exception:
                raise OidcDenied() from None

    def _consume_persisted(self, subject: str, nonce: str, expires_at: int, now: int) -> None:
        connection = self._connection
        if connection is None:  # pragma: no cover - guarded by caller
            raise OidcDenied()
        subject_hash = _state_hash(b"subject", subject)
        nonce_hash = _state_hash(b"nonce", nonce)
        had_transaction = connection.in_transaction
        try:
            connection.execute("SAVEPOINT oidc_nonce_consume")
            connection.execute("DELETE FROM oidc_nonce_replays WHERE expires_at<=?", (now,))
            count = connection.execute("SELECT COUNT(*) FROM oidc_nonce_replays").fetchone()
            if count is None or type(count[0]) is not int or count[0] >= self._max_entries:
                raise OidcDenied()
            connection.execute(
                "INSERT INTO oidc_nonce_replays (subject_hash, nonce_hash, expires_at) VALUES (?, ?, ?)",
                (subject_hash, nonce_hash, expires_at),
            )
            connection.execute("RELEASE oidc_nonce_consume")
            if not had_transaction:
                connection.commit()
        except OidcDenied:
            _rollback_savepoint(connection, "oidc_nonce_consume")
            raise
        except Exception:
            _rollback_savepoint(connection, "oidc_nonce_consume")
            raise OidcDenied() from None

    def _discard_expired(self, current_time: int) -> None:
        while self._expiry_heap and self._expiry_heap[0][0] <= current_time:
            expires_at, subject_id, nonce = heapq.heappop(self._expiry_heap)
            key = (subject_id, nonce)
            if self._values.get(key) == expires_at:
                del self._values[key]


def _state_hash(purpose: bytes, value: str) -> str:
    if not _safe_hash_value(value):
        raise OidcDenied()
    return hashlib.sha256(
        b"securecode.oidc." + purpose + b".v1\0" + value.encode("utf-8")
    ).hexdigest()


def _safe_hash_value(value: object) -> bool:
    if (
        type(value) is not str
        or not 0 < len(value) <= _MAX_NONCE_LENGTH
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        return False
    try:
        return len(value.encode("utf-8")) <= _MAX_NONCE_LENGTH * 4
    except UnicodeEncodeError:
        return False


def _safe_principal_value(value: str) -> bool:
    return value == value.strip() and not any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    )


def _rollback_savepoint(connection: sqlite3.Connection, name: str) -> None:
    try:
        connection.execute(f"ROLLBACK TO {name}")
        connection.execute(f"RELEASE {name}")
    except sqlite3.Error:
        pass
