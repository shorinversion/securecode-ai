"""Request replay stores for exactly-once control-plane mutations."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Protocol

from .ports import ServiceResponse

_DEFAULT_CLAIM_LEASE_MS = 300_000
_MAX_CLAIM_LEASE_MS = 86_400_000
_SQLITE_INTEGER_MAX = (1 << 63) - 1


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
        self._values: dict[tuple[str, str], tuple[str, ServiceResponse | None]] = {}
        self._lock = RLock()

    def claim(
        self,
        *,
        tenant_id: str,
        key: str,
        method: str,
        path: str,
        body: bytes,
    ) -> ReplayClaim:
        digest = _request_digest(method, path, body)
        record_key = (tenant_id, key)
        with self._lock:
            previous = self._values.get(record_key)
            if previous is None:
                self._values[record_key] = (digest, None)
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
            self._values[(tenant_id, key)] = (previous[0], response)

    def release(self, *, tenant_id: str, key: str) -> None:
        with self._lock:
            self._values.pop((tenant_id, key), None)


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
        self._claims: dict[tuple[str, str], int] = {}
        self._lock = RLock()

    def claim(
        self,
        *,
        tenant_id: str,
        key: str,
        method: str,
        path: str,
        body: bytes,
    ) -> ReplayClaim:
        digest = _request_digest(method, path, body)
        claimed_at_ms = self._now_ms()
        cursor = self._connection.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
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
                self._connection.commit()
                self._remember_claim(tenant_id, key, claimed_at_ms)
                return ReplayClaim(ClaimState.NEW)
            if row["request_sha256"] != digest:
                self._connection.commit()
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
                    self._connection.commit()
                    self._remember_claim(tenant_id, key, claimed_at_ms)
                    return ReplayClaim(ClaimState.NEW)
                self._connection.commit()
                return ReplayClaim(ClaimState.IN_FLIGHT)
            document = json.loads(row["response_json"])
            headers = json.loads(row["response_headers_json"] or "{}")
            if not isinstance(document, dict) or not isinstance(headers, dict):
                raise ValueError("stored replay response is invalid")
            self._connection.commit()
            return ReplayClaim(
                ClaimState.REPLAY,
                ServiceResponse(row["response_status"], document, headers),
            )
        except Exception:
            self._connection.rollback()
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
        cursor = self._connection.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
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
            self._connection.commit()
            self._forget_claim(tenant_id, key, claim_token)
        except Exception:
            self._connection.rollback()
            raise
        finally:
            cursor.close()

    def release(self, *, tenant_id: str, key: str) -> None:
        claim_token = self._claim_token(tenant_id, key)
        cursor = self._connection.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            cursor.execute(
                """DELETE FROM http_idempotency_records
                   WHERE tenant_id=? AND idempotency_key=? AND response_status IS NULL
                     AND claimed_at_ms=?""",
                (tenant_id, key, claim_token),
            )
            if cursor.rowcount != 1:
                raise ValueError("request replay claim is missing or changed")
            self._connection.commit()
            self._forget_claim(tenant_id, key, claim_token)
        except Exception:
            self._connection.rollback()
            raise
        finally:
            cursor.close()

    def _remember_claim(self, tenant_id: str, key: str, claim_token: int) -> None:
        with self._lock:
            self._claims[(tenant_id, key)] = claim_token

    def _claim_token(self, tenant_id: str, key: str) -> int:
        with self._lock:
            claim_token = self._claims.get((tenant_id, key))
        if claim_token is None:
            raise ValueError("request replay claim is not owned by this process")
        return claim_token

    def _forget_claim(self, tenant_id: str, key: str, claim_token: int) -> None:
        with self._lock:
            if self._claims.get((tenant_id, key)) == claim_token:
                del self._claims[(tenant_id, key)]


def _request_digest(method: str, path: str, body: bytes) -> str:
    return hashlib.sha256(
        method.encode("ascii") + b"\x00" + path.encode("utf-8") + b"\x00" + body
    ).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


__all__ = [
    "ClaimState",
    "InMemoryRequestReplayStore",
    "ReplayClaim",
    "RequestReplayStore",
    "SqliteRequestReplayStore",
]
