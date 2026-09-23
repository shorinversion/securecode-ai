"""OIDC replay nonce ledger and injected safe session issuer."""

from __future__ import annotations

import hashlib
import heapq
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Lock
from typing import Protocol

from .identity import Principal
from .oidc import OidcDenied, OidcReceipt
from .sessions import SessionStore

_DEFAULT_MAX_ENTRIES = 100_000
_MAX_NONCE_LENGTH = 1_024
_MAX_SUBJECT_LENGTH = 2_048


class SessionIssuer(Protocol):
    def issue(self, principal: Principal, *, token_expires_at: int) -> IssuedOidcSession: ...


class LoginStatePort(Protocol):
    def create(self, *, state: str, nonce: str, expires_at: int) -> None: ...

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
            except OidcDenied:
                _rollback_savepoint(self._connection, "oidc_state_create")
                raise
            except Exception:
                _rollback_savepoint(self._connection, "oidc_state_create")
                raise OidcDenied() from None

    def consume(self, *, state: str, nonce: str, now: int) -> bool:
        state_hash = _state_hash(b"state", state)
        nonce_hash = _state_hash(b"nonce", nonce)
        if type(now) is not int or now < 0:
            raise OidcDenied()
        with self._lock:
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
                return changed == 1
            except Exception:
                _rollback_savepoint(self._connection, "oidc_state_consume")
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
                    if type(started) is not int or type(attempts) is not int:
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
            except OidcDenied:
                _rollback_savepoint(self._connection, "oidc_attempt_charge")
                raise
            except Exception:
                _rollback_savepoint(self._connection, "oidc_attempt_charge")
                raise OidcDenied() from None


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
        if type(principal) is not Principal or type(token_expires_at) is not int:
            raise OidcDenied()
        remaining = token_expires_at - int(datetime.now(UTC).timestamp()) - 1
        if not 1 <= remaining <= 86_400:
            raise OidcDenied()
        token, session = self._store.issue_session(
            principal,
            lifetime_seconds=min(3600, remaining),
        )
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
            or type(nonce) is not str
            or not 0 < len(nonce) <= _MAX_NONCE_LENGTH
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

    def _consume_persisted(self, subject: str, nonce: str, expires_at: int, now: int) -> None:
        connection = self._connection
        if connection is None:  # pragma: no cover - guarded by caller
            raise OidcDenied()
        subject_hash = _state_hash(b"subject", subject)
        nonce_hash = _state_hash(b"nonce", nonce)
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
    if type(value) is not str or not value or len(value) > _MAX_NONCE_LENGTH or not value.isascii():
        raise OidcDenied()
    return hashlib.sha256(
        b"securecode.oidc." + purpose + b".v1\0" + value.encode("ascii")
    ).hexdigest()


def _rollback_savepoint(connection: sqlite3.Connection, name: str) -> None:
    try:
        connection.execute(f"ROLLBACK TO {name}")
        connection.execute(f"RELEASE {name}")
    except sqlite3.Error:
        pass
