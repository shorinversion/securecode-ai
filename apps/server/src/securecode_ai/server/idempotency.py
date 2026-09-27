"""Request replay stores for exactly-once control-plane mutations."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock, get_ident
from typing import Protocol

from .ports import ServiceResponse

_DEFAULT_CLAIM_LEASE_MS = 300_000
_MAX_CLAIM_LEASE_MS = 86_400_000
_MAX_PURGE_ITEMS = 256
_CLAIM_SAVEPOINT = "securecode_idempotency_claim"
_COMPLETE_SAVEPOINT = "securecode_idempotency_complete"
_RELEASE_SAVEPOINT = "securecode_idempotency_release"
_PURGE_SAVEPOINT = "securecode_idempotency_purge"
_SQLITE_INTEGER_MAX = (1 << 63) - 1
_RETRYABLE_503_CODES = frozenset(
    {
        "HANDLER_UNAVAILABLE",
        "HEAD_UNAVAILABLE",
        "INVALID_CONFIGURATION",
    }
)


class ClaimState(StrEnum):
    NEW = "NEW"
    CONFLICT = "CONFLICT"
    IN_FLIGHT = "IN_FLIGHT"
    REPLAY = "REPLAY"


@dataclass(frozen=True, slots=True)
class ReplayClaim:
    state: ClaimState
    response: ServiceResponse | None = None


class RequestReplayStore(Protocol):
    def claim(
        self,
        *,
        tenant_id: str,
        key: str,
        method: str,
        path: str,
        body: bytes,
        precondition: str | None = None,
    ) -> ReplayClaim: ...

    def complete(
        self,
        *,
        tenant_id: str,
        key: str,
        response: ServiceResponse,
    ) -> None: ...

    def release(self, *, tenant_id: str, key: str) -> None: ...


class InMemoryRequestReplayStore:
    def __init__(self) -> None:
        self._values: dict[tuple[str, str], tuple[str, ServiceResponse | None, object]] = {}
        self._lock = RLock()

    def claim(
        self,
        *,
        tenant_id: str,
        key: str,
        method: str,
        path: str,
        body: bytes,
        precondition: str | None = None,
    ) -> ReplayClaim:
        digest = _request_digest(method, path, body, precondition=precondition)
        record_key = (tenant_id, key)
        owner = _execution_owner()
        with self._lock:
            previous = self._values.get(record_key)
            if previous is None:
                self._values[record_key] = (digest, None, owner)
                return ReplayClaim(ClaimState.NEW)
            if previous[0] != digest:
                return ReplayClaim(ClaimState.CONFLICT)
            if previous[1] is None:
                return ReplayClaim(ClaimState.IN_FLIGHT)
            return ReplayClaim(ClaimState.REPLAY, previous[1])

    def complete(
        self,
        *,
        tenant_id: str,
        key: str,
        response: ServiceResponse,
    ) -> None:
        with self._lock:
            previous = self._values.get((tenant_id, key))
            if previous is None:
                raise ValueError("request replay claim is missing")
            if previous[2] != _execution_owner() or previous[1] is not None:
                raise ValueError("request replay claim is missing or owned by another request")
            if _is_retryable_response(response):
                del self._values[(tenant_id, key)]
                return
            self._values[(tenant_id, key)] = (previous[0], response, previous[2])

    def release(self, *, tenant_id: str, key: str) -> None:
        with self._lock:
            record_key = (tenant_id, key)
            previous = self._values.get(record_key)
            if (
                previous is None
                or previous[1] is not None
                or previous[2] != _execution_owner()
            ):
                raise ValueError("request replay claim is missing or owned by another request")
            del self._values[record_key]


class SqliteRequestReplayStore:
    """Restart-safe replay state with an explicit in-flight claim."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        clock: Callable[[], int] | None = None,
        claim_lease_ms: int = _DEFAULT_CLAIM_LEASE_MS,
    ) -> None:
        if (
            type(claim_lease_ms) is not int
            or claim_lease_ms <= 0
            or claim_lease_ms > _MAX_CLAIM_LEASE_MS
        ):
            raise ValueError("request replay claim lease is invalid")
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        self._clock = clock or (lambda: time.time_ns() // 1_000_000)
        self._claim_lease_ms = claim_lease_ms
        self._claims: dict[tuple[str, str, object], int] = {}
        self._lock = RLock()

    def claim(
        self,
        *,
        tenant_id: str,
        key: str,
        method: str,
        path: str,
        body: bytes,
        precondition: str | None = None,
    ) -> ReplayClaim:
        digest = _request_digest(method, path, body, precondition=precondition)
        claimed_at_ms = self._now_ms()
        with self._lock:
            cursor = self._connection.cursor()
            active = False
            owns_transaction = False
            try:
                owns_transaction = _begin_atomic(cursor, self._connection, _CLAIM_SAVEPOINT)
                active = True
                row = cursor.execute(
                    """SELECT request_sha256, response_status, response_json,
                              response_headers_json, claimed_at_ms
                       FROM http_idempotency_records
                       WHERE tenant_id=? AND idempotency_key=?""",
                    (tenant_id, key),
                ).fetchone()
                if row is None:
                    cursor.execute(
                        """INSERT INTO http_idempotency_records
                           (tenant_id, idempotency_key, request_sha256, response_status,
                            response_json, response_headers_json, claimed_at_ms)
                           VALUES (?, ?, ?, NULL, NULL, NULL, ?)""",
                        (tenant_id, key, digest, claimed_at_ms),
                    )
                    _finish_atomic(cursor, self._connection, _CLAIM_SAVEPOINT, owns_transaction)
                    active = False
                    self._remember_claim(tenant_id, key, claimed_at_ms)
                    return ReplayClaim(ClaimState.NEW)
                if row["request_sha256"] != digest:
                    _finish_atomic(cursor, self._connection, _CLAIM_SAVEPOINT, owns_transaction)
                    active = False
                    return ReplayClaim(ClaimState.CONFLICT)
                if row["response_status"] is None:
                    if self._claim_expired(row["claimed_at_ms"], claimed_at_ms):
                        cursor.execute(
                            """UPDATE http_idempotency_records
                               SET claimed_at_ms=?
                               WHERE tenant_id=? AND idempotency_key=?
                                 AND request_sha256=? AND response_status IS NULL""",
                            (claimed_at_ms, tenant_id, key, digest),
                        )
                        if cursor.rowcount != 1:
                            raise ValueError("request replay claim changed during recovery")
                        _finish_atomic(cursor, self._connection, _CLAIM_SAVEPOINT, owns_transaction)
                        active = False
                        self._remember_claim(tenant_id, key, claimed_at_ms)
                        return ReplayClaim(ClaimState.NEW)
                    _finish_atomic(cursor, self._connection, _CLAIM_SAVEPOINT, owns_transaction)
                    active = False
                    return ReplayClaim(ClaimState.IN_FLIGHT)
                document = json.loads(row["response_json"])
                headers = json.loads(row["response_headers_json"] or "{}")
                if not isinstance(document, dict) or not isinstance(headers, dict):
                    raise ValueError("stored replay response is invalid")
                response = ServiceResponse(row["response_status"], document, headers)
                _finish_atomic(cursor, self._connection, _CLAIM_SAVEPOINT, owns_transaction)
                active = False
                return ReplayClaim(ClaimState.REPLAY, response)
            except Exception:
                if active:
                    _rollback_atomic(cursor, self._connection, _CLAIM_SAVEPOINT, owns_transaction)
                raise
            finally:
                cursor.close()

    def _now_ms(self) -> int:
        value = self._clock()
        if type(value) is not int or not 0 <= value <= _SQLITE_INTEGER_MAX:
            raise ValueError("request replay clock is invalid")
        return value

    def _claim_expired(self, claimed_at_ms: object, now_ms: int) -> bool:
        if claimed_at_ms is None:
            return True
        if type(claimed_at_ms) is not int or not 0 <= claimed_at_ms <= now_ms:
            return False
        return now_ms - claimed_at_ms >= self._claim_lease_ms

    def complete(
        self,
        *,
        tenant_id: str,
        key: str,
        response: ServiceResponse,
    ) -> None:
        claim_token = self._claim_token(tenant_id, key)
        with self._lock:
            cursor = self._connection.cursor()
            active = False
            owns_transaction = False
            try:
                owns_transaction = _begin_atomic(cursor, self._connection, _COMPLETE_SAVEPOINT)
                active = True
                if _is_retryable_response(response):
                    cursor.execute(
                        """DELETE FROM http_idempotency_records
                           WHERE tenant_id=? AND idempotency_key=? AND response_status IS NULL
                             AND claimed_at_ms=?""",
                        (tenant_id, key, claim_token),
                    )
                    if cursor.rowcount != 1:
                        raise ValueError("request replay claim is missing or complete")
                    _finish_atomic(cursor, self._connection, _COMPLETE_SAVEPOINT, owns_transaction)
                    active = False
                    self._forget_claim(tenant_id, key, claim_token)
                    return
                cursor.execute(
                    """UPDATE http_idempotency_records
                       SET response_status=?, response_json=?, response_headers_json=?
                       WHERE tenant_id=? AND idempotency_key=? AND response_status IS NULL
                         AND claimed_at_ms=?""",
                    (
                        response.status,
                        _canonical(dict(response.document)),
                        _canonical(dict(response.headers or {})),
                        tenant_id,
                        key,
                        claim_token,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ValueError("request replay claim is missing or complete")
                _finish_atomic(cursor, self._connection, _COMPLETE_SAVEPOINT, owns_transaction)
                active = False
                self._forget_claim(tenant_id, key, claim_token)
            except Exception:
                if active:
                    _rollback_atomic(cursor, self._connection, _COMPLETE_SAVEPOINT, owns_transaction)
                raise
            finally:
                cursor.close()

    def release(self, *, tenant_id: str, key: str) -> None:
        claim_token = self._claim_token(tenant_id, key)
        with self._lock:
            cursor = self._connection.cursor()
            active = False
            owns_transaction = False
            try:
                owns_transaction = _begin_atomic(cursor, self._connection, _RELEASE_SAVEPOINT)
                active = True
                cursor.execute(
                    """DELETE FROM http_idempotency_records
                       WHERE tenant_id=? AND idempotency_key=? AND response_status IS NULL
                         AND claimed_at_ms=?""",
                    (tenant_id, key, claim_token),
                )
                if cursor.rowcount != 1:
                    raise ValueError("request replay claim is missing or changed")
                _finish_atomic(cursor, self._connection, _RELEASE_SAVEPOINT, owns_transaction)
                active = False
                self._forget_claim(tenant_id, key, claim_token)
            except Exception:
                if active:
                    _rollback_atomic(cursor, self._connection, _RELEASE_SAVEPOINT, owns_transaction)
                raise
            finally:
                cursor.close()

    def purge_expired_claims(
        self,
        *,
        tenant_id: str,
        now_ms: int,
        max_items: int = _MAX_PURGE_ITEMS,
    ) -> int:
        """Remove only abandoned in-flight claims after their lease expires."""

        _validate_purge_arguments(tenant_id, now_ms, max_items)
        cutoff_ms = now_ms - self._claim_lease_ms
        with self._lock:
            cursor = self._connection.cursor()
            active = False
            owns_transaction = False
            try:
                owns_transaction = _begin_atomic(cursor, self._connection, _PURGE_SAVEPOINT)
                active = True
                changed = cursor.execute(
                    """DELETE FROM http_idempotency_records
                       WHERE rowid IN (
                           SELECT rowid FROM http_idempotency_records
                           WHERE tenant_id=? AND response_status IS NULL
                             AND (claimed_at_ms IS NULL OR claimed_at_ms<=?)
                           ORDER BY claimed_at_ms, idempotency_key LIMIT ?
                       )""",
                    (tenant_id, cutoff_ms, max_items),
                ).rowcount
                _finish_atomic(cursor, self._connection, _PURGE_SAVEPOINT, owns_transaction)
                active = False
                return changed
            except sqlite3.Error as error:
                if active:
                    _rollback_atomic(cursor, self._connection, _PURGE_SAVEPOINT, owns_transaction)
                raise ValueError("request replay cleanup is unavailable") from error
            finally:
                cursor.close()

    def has_expired_claims(self, *, tenant_id: str, now_ms: int) -> bool:
        _validate_purge_arguments(tenant_id, now_ms, 1)
        with self._lock:
            row = self._connection.execute(
                """SELECT 1 FROM http_idempotency_records
                   WHERE tenant_id=? AND response_status IS NULL
                     AND (claimed_at_ms IS NULL OR claimed_at_ms<=?)
                   LIMIT 1""",
                (tenant_id, now_ms - self._claim_lease_ms),
            ).fetchone()
        return row is not None

    def _remember_claim(self, tenant_id: str, key: str, claim_token: int) -> None:
        with self._lock:
            self._claims[(tenant_id, key, _execution_owner())] = claim_token

    def _claim_token(self, tenant_id: str, key: str) -> int:
        claim_key = (tenant_id, key, _execution_owner())
        with self._lock:
            claim_token = self._claims.get(claim_key)
        if claim_token is None:
            raise ValueError("request replay claim is not owned by this request context")
        return claim_token

    def _forget_claim(self, tenant_id: str, key: str, claim_token: int) -> None:
        claim_key = (tenant_id, key, _execution_owner())
        with self._lock:
            if self._claims.get(claim_key) == claim_token:
                del self._claims[claim_key]


def _execution_owner() -> object:
    """Return the async request task, or thread identity for sync callers."""

    try:
        task = asyncio.current_task()
    except RuntimeError:
        task = None
    return task if task is not None else ("thread", get_ident())


def _request_digest(
    method: str,
    path: str,
    body: bytes,
    *,
    precondition: str | None = None,
) -> str:
    request = method.encode("ascii") + b"\x00" + path.encode("utf-8") + b"\x00" + body
    if precondition is None:
        return hashlib.sha256(request).hexdigest()
    if type(precondition) is not str or not precondition.isascii():
        raise ValueError("request precondition is invalid")
    fields = (
        method.encode("ascii"),
        path.encode("utf-8"),
        body,
        precondition.encode("ascii"),
    )
    digest = hashlib.sha256(b"securecode-http-idempotency-v2\x00")
    for field in fields:
        digest.update(len(field).to_bytes(8, "big"))
        digest.update(field)
    return digest.hexdigest()


def _is_retryable_response(response: ServiceResponse) -> bool:
    """Release only responses known to be produced before a mutation."""

    if response.status != 503:
        return False
    error = response.document.get("error")
    if type(error) is not dict:
        return False
    code = error.get("code")
    return type(code) is str and code in _RETRYABLE_503_CODES


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _validate_purge_arguments(tenant_id: str, now_ms: int, max_items: int) -> None:
    if type(tenant_id) is not str or not tenant_id or len(tenant_id) > 256:
        raise ValueError("request replay tenant is invalid")
    if type(now_ms) is not int or not 0 <= now_ms <= _SQLITE_INTEGER_MAX:
        raise ValueError("request replay cleanup clock is invalid")
    if type(max_items) is not int or not 1 <= max_items <= _MAX_PURGE_ITEMS:
        raise ValueError("request replay cleanup batch is invalid")


def _rollback_savepoint(cursor: sqlite3.Cursor, name: str) -> None:
    try:
        cursor.execute(f"ROLLBACK TO SAVEPOINT {name}")
        cursor.execute(f"RELEASE SAVEPOINT {name}")
    except sqlite3.Error:
        pass


def _begin_atomic(
    cursor: sqlite3.Cursor,
    connection: sqlite3.Connection,
    name: str,
) -> bool:
    """Start an immediate transaction, or nest safely in an existing one."""

    if connection.in_transaction:
        cursor.execute(f"SAVEPOINT {name}")
        return False
    cursor.execute("BEGIN IMMEDIATE")
    return True


def _finish_atomic(
    cursor: sqlite3.Cursor,
    connection: sqlite3.Connection,
    name: str,
    owns_transaction: bool,
) -> None:
    if owns_transaction:
        connection.commit()
    else:
        cursor.execute(f"RELEASE SAVEPOINT {name}")


def _rollback_atomic(
    cursor: sqlite3.Cursor,
    connection: sqlite3.Connection,
    name: str,
    owns_transaction: bool,
) -> None:
    if owns_transaction:
        connection.rollback()
    else:
        _rollback_savepoint(cursor, name)


__all__ = [
    "ClaimState",
    "InMemoryRequestReplayStore",
    "ReplayClaim",
    "RequestReplayStore",
    "SqliteRequestReplayStore",
]
