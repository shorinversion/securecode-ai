"""Restart-safe, tenant-scoped token bucket backed by the control-plane DB."""

from __future__ import annotations

import sqlite3
import time
from threading import Lock
from typing import Final

from .tenant_rate_limiter import (
    RateLimitDecision,
    RateLimitError,
    RateLimitErrorCode,
    _valid_tenant_id,
)

_TOKEN_UNIT: Final = 1_000_000
_MAX_TENANTS: Final = 100_000
_MAX_CAPACITY: Final = 10_000
_MAX_REFILL_PER_SECOND: Final = 10_000
_MAX_CLOCK_NS: Final = (1 << 63) - 1
_MAX_TENANT_ID_LENGTH: Final = 128
_MAX_IDLE_PURGE: Final = 256
_SAVEPOINT: Final = "securecode_tenant_rate_limit"

SQLITE_RATE_LIMIT_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS tenant_rate_limit_buckets (
        tenant_id TEXT NOT NULL PRIMARY KEY,
        tokens_micro INTEGER NOT NULL CHECK(tokens_micro >= 0),
        updated_ms INTEGER NOT NULL CHECK(updated_ms >= 0),
        last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms >= 0)
    )""",
    "CREATE INDEX IF NOT EXISTS tenant_rate_limit_last_seen_idx "
    "ON tenant_rate_limit_buckets(last_seen_ms, tenant_id)",
)


class SqliteTenantTokenBucketRateLimiter:
    """Atomically charge one token across processes sharing the same database."""

    __slots__ = (
        "_capacity_micro",
        "_connection",
        "_idle_timeout_ms",
        "_lock",
        "_max_tenants",
        "_refill_per_second",
    )

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        capacity: int = 120,
        refill_per_second: int = 2,
        max_tenants: int = 10_000,
        idle_timeout_seconds: int = 300,
    ) -> None:
        if (
            not isinstance(connection, sqlite3.Connection)
            or type(capacity) is not int
            or not 1 <= capacity <= _MAX_CAPACITY
            or type(refill_per_second) is not int
            or not 1 <= refill_per_second <= _MAX_REFILL_PER_SECOND
            or type(max_tenants) is not int
            or not 1 <= max_tenants <= _MAX_TENANTS
            or type(idle_timeout_seconds) is not int
            or not 1 <= idle_timeout_seconds <= 86_400
        ):
            raise RateLimitError(RateLimitErrorCode.INVALID_INPUT)
        self._connection = connection
        self._capacity_micro = capacity * _TOKEN_UNIT
        self._refill_per_second = refill_per_second
        self._max_tenants = max_tenants
        self._idle_timeout_ms = idle_timeout_seconds * 1000
        self._lock = Lock()
        had_transaction = connection.in_transaction
        try:
            for statement in SQLITE_RATE_LIMIT_SCHEMA_STATEMENTS:
                connection.execute(statement)
        except sqlite3.Error:
            if not had_transaction:
                connection.rollback()
            raise RateLimitError(RateLimitErrorCode.STORE_UNAVAILABLE) from None
        if not had_transaction:
            try:
                connection.commit()
            except sqlite3.Error:
                connection.rollback()
                raise RateLimitError(RateLimitErrorCode.STORE_UNAVAILABLE) from None

    def allow(
        self,
        *,
        tenant_id: object,
        now_ns: object = None,
    ) -> RateLimitDecision:
        if not _valid_tenant_id(tenant_id):
            raise RateLimitError(RateLimitErrorCode.INVALID_INPUT)
        if now_ns is None:
            current_ns = time.time_ns()
        elif type(now_ns) is int:
            current_ns = now_ns
        else:
            raise RateLimitError(RateLimitErrorCode.INVALID_INPUT)
        if not 0 <= current_ns <= _MAX_CLOCK_NS:
            raise RateLimitError(RateLimitErrorCode.CLOCK_INVALID)
        now_ms = current_ns // 1_000_000
        with self._lock:
            return self._charge(tenant_id, now_ms)

    def _charge(self, tenant_id: str, now_ms: int) -> RateLimitDecision:
        cursor: sqlite3.Cursor | None = None
        active = False
        try:
            cursor = self._connection.cursor()
            cursor.execute(f"SAVEPOINT {_SAVEPOINT}")
            active = True
            cursor.execute(
                """DELETE FROM tenant_rate_limit_buckets
                   WHERE tenant_id IN (
                       SELECT tenant_id FROM tenant_rate_limit_buckets
                       WHERE last_seen_ms<=?
                       ORDER BY last_seen_ms, tenant_id
                       LIMIT ?
                   )""",
                (now_ms - self._idle_timeout_ms, _MAX_IDLE_PURGE),
            )
            row = cursor.execute(
                "SELECT tokens_micro, updated_ms FROM tenant_rate_limit_buckets WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            if row is None:
                count = cursor.execute("SELECT COUNT(*) FROM tenant_rate_limit_buckets").fetchone()[
                    0
                ]
                if type(count) is not int or count >= self._max_tenants:
                    cursor.execute(f"RELEASE SAVEPOINT {_SAVEPOINT}")
                    active = False
                    raise RateLimitError(RateLimitErrorCode.STATE_FULL)
                tokens = self._capacity_micro - _TOKEN_UNIT
                cursor.execute(
                    "INSERT INTO tenant_rate_limit_buckets "
                    "(tenant_id, tokens_micro, updated_ms, last_seen_ms) "
                    "VALUES (?, ?, ?, ?)",
                    (tenant_id, tokens, now_ms, now_ms),
                )
                cursor.execute(f"RELEASE SAVEPOINT {_SAVEPOINT}")
                active = False
                return RateLimitDecision(True, 0)

            tokens, updated_ms = row
            if (
                type(tokens) is not int
                or type(updated_ms) is not int
                or not 0 <= tokens <= _MAX_CAPACITY * _TOKEN_UNIT
                or not 0 <= updated_ms <= now_ms
            ):
                raise RateLimitError(RateLimitErrorCode.CLOCK_INVALID)
            stored_tokens = tokens
            # The bucket survives a restart, while the operator may lower the
            # configured capacity between deployments.  A balance recorded
            # under the old profile must not turn every request into a
            # persistent CLOCK_INVALID outage.  Rebase it to the new ceiling
            # before applying refill and charge logic.
            tokens = min(tokens, self._capacity_micro)
            elapsed_ms = now_ms - updated_ms
            refill_micro = elapsed_ms * self._refill_per_second * 1000
            available = min(self._capacity_micro, tokens + refill_micro)
            if available >= _TOKEN_UNIT:
                remaining = available - _TOKEN_UNIT
                cursor.execute(
                    "UPDATE tenant_rate_limit_buckets "
                    "SET tokens_micro=?, updated_ms=?, last_seen_ms=? "
                    "WHERE tenant_id=? AND tokens_micro=? AND updated_ms=?",
                    (remaining, now_ms, now_ms, tenant_id, stored_tokens, updated_ms),
                )
                if cursor.rowcount != 1:
                    raise RateLimitError(RateLimitErrorCode.STORE_UNAVAILABLE)
                cursor.execute(f"RELEASE SAVEPOINT {_SAVEPOINT}")
                active = False
                return RateLimitDecision(True, 0)

            cursor.execute(
                "UPDATE tenant_rate_limit_buckets SET tokens_micro=?, updated_ms=?, "
                "last_seen_ms=? WHERE tenant_id=? AND tokens_micro=? AND updated_ms=?",
                (available, now_ms, now_ms, tenant_id, stored_tokens, updated_ms),
            )
            if cursor.rowcount != 1:
                raise RateLimitError(RateLimitErrorCode.STORE_UNAVAILABLE)
            deficit = _TOKEN_UNIT - available
            denominator = self._refill_per_second * _TOKEN_UNIT
            retry_after = max(1, (deficit + denominator - 1) // denominator)
            cursor.execute(f"RELEASE SAVEPOINT {_SAVEPOINT}")
            active = False
            return RateLimitDecision(False, retry_after)
        except sqlite3.Error:
            raise RateLimitError(RateLimitErrorCode.STORE_UNAVAILABLE) from None
        finally:
            if active and cursor is not None:
                try:
                    cursor.execute(f"ROLLBACK TO SAVEPOINT {_SAVEPOINT}")
                    cursor.execute(f"RELEASE SAVEPOINT {_SAVEPOINT}")
                except sqlite3.Error:
                    pass
            if cursor is not None:
                cursor.close()


__all__ = ["SQLITE_RATE_LIMIT_SCHEMA_STATEMENTS", "SqliteTenantTokenBucketRateLimiter"]
