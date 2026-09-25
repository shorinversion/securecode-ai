"""Restart-safe per-tenant API quotas stored in the control-plane database."""

from __future__ import annotations

import sqlite3
from threading import Lock

from .request_quota import (
    MAX_REQUESTS_PER_WINDOW,
    MAX_SPEND_MICROUNITS,
    MAX_TENANTS,
    MAX_WINDOW_SECONDS,
    QuotaDecision,
    QuotaError,
    QuotaErrorCode,
    _valid_tenant_id,
)

SQLITE_REQUEST_QUOTA_SCHEMA_STATEMENTS = (
    """CREATE TABLE IF NOT EXISTS request_quota_windows (
        tenant_id TEXT NOT NULL PRIMARY KEY,
        started_ms INTEGER NOT NULL,
        requests INTEGER NOT NULL,
        spend_microunits INTEGER NOT NULL
    )""",
)

_QUOTA_SAVEPOINT = "securecode_quota_charge"
_QUOTA_PURGE_SAVEPOINT = "securecode_quota_purge"
_MAX_WINDOW_MS = MAX_WINDOW_SECONDS * 1000
_SQLITE_INTEGER_MAX = (1 << 63) - 1


class SqliteQuotaLedger:
    """Atomically charge all authenticated tenants against a persistent ceiling."""

    __slots__ = (
        "_connection",
        "_lock",
        "_max_requests",
        "_max_spend_microunits",
        "_max_tenants",
        "_window_ms",
    )

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        window_seconds: int,
        max_requests: int,
        max_spend_microunits: int = MAX_SPEND_MICROUNITS,
        max_tenants: int = MAX_TENANTS,
    ) -> None:
        if (
            not isinstance(connection, sqlite3.Connection)
            or type(window_seconds) is not int
            or not 1 <= window_seconds <= MAX_WINDOW_SECONDS
            or type(max_requests) is not int
            or not 1 <= max_requests <= MAX_REQUESTS_PER_WINDOW
            or type(max_spend_microunits) is not int
            or not 0 <= max_spend_microunits <= MAX_SPEND_MICROUNITS
            or type(max_tenants) is not int
            or not 1 <= max_tenants <= MAX_TENANTS
        ):
            raise QuotaError(QuotaErrorCode.INVALID_CONFIGURATION)
        self._connection = connection
        self._window_ms = window_seconds * 1000
        self._max_requests = max_requests
        self._max_spend_microunits = max_spend_microunits
        self._max_tenants = max_tenants
        self._lock = Lock()

    def check(
        self,
        *,
        tenant_id: object,
        now_ms: object,
        cost_microunits: int = 0,
    ) -> QuotaDecision:
        if (
            not _valid_tenant_id(tenant_id)
            or type(now_ms) is not int
            or not 0 <= now_ms <= _SQLITE_INTEGER_MAX
            or type(cost_microunits) is not int
            or not 0 <= cost_microunits <= MAX_SPEND_MICROUNITS
        ):
            raise QuotaError(QuotaErrorCode.INVALID_CONFIGURATION)
        with self._lock:
            return self._charge(tenant_id, now_ms, cost_microunits)

    def purge_expired_windows(self, *, now_ms: int, max_items: int = 100) -> int:
        """Delete a bounded batch older than every supported quota window."""

        if (
            type(now_ms) is not int
            or not 0 <= now_ms <= _SQLITE_INTEGER_MAX
            or type(max_items) is not int
            or not 1 <= max_items <= MAX_TENANTS
        ):
            raise QuotaError(QuotaErrorCode.INVALID_CONFIGURATION)
        cutoff_ms = now_ms - _MAX_WINDOW_MS
        with self._lock:
            cursor: sqlite3.Cursor | None = None
            active = False
            try:
                cursor = self._connection.cursor()
                cursor.execute(f"SAVEPOINT {_QUOTA_PURGE_SAVEPOINT}")
                active = True
                changed = cursor.execute(
                    """DELETE FROM request_quota_windows
                       WHERE tenant_id IN (
                           SELECT tenant_id FROM request_quota_windows
                           WHERE started_ms<=? ORDER BY started_ms, tenant_id LIMIT ?
                       )""",
                    (cutoff_ms, max_items),
                ).rowcount
                cursor.execute(f"RELEASE SAVEPOINT {_QUOTA_PURGE_SAVEPOINT}")
                active = False
                return changed
            except sqlite3.Error:
                if active and cursor is not None:
                    try:
                        cursor.execute(f"ROLLBACK TO SAVEPOINT {_QUOTA_PURGE_SAVEPOINT}")
                        cursor.execute(f"RELEASE SAVEPOINT {_QUOTA_PURGE_SAVEPOINT}")
                    except sqlite3.Error:
                        pass
                raise QuotaError(QuotaErrorCode.STORE_UNAVAILABLE) from None
            finally:
                if cursor is not None:
                    cursor.close()

    def has_expired_windows(self, *, now_ms: int) -> bool:
        if type(now_ms) is not int or not 0 <= now_ms <= _SQLITE_INTEGER_MAX:
            raise QuotaError(QuotaErrorCode.INVALID_CONFIGURATION)
        try:
            row = self._connection.execute(
                "SELECT 1 FROM request_quota_windows WHERE started_ms<=? LIMIT 1",
                (now_ms - _MAX_WINDOW_MS,),
            ).fetchone()
            return row is not None
        except sqlite3.Error:
            raise QuotaError(QuotaErrorCode.STORE_UNAVAILABLE) from None

    def _charge(self, tenant_id: str, now_ms: int, cost_microunits: int) -> QuotaDecision:
        cursor: sqlite3.Cursor | None = None
        savepoint_active = False
        try:
            cursor = self._connection.cursor()
            # The control-plane connection is shared by repositories that may
            # already have an open transaction.  A top-level BEGIN would fail
            # in that case, while commit/rollback would also affect unrelated
            # writes.  A savepoint keeps this charge atomic and composable.
            cursor.execute(f"SAVEPOINT {_QUOTA_SAVEPOINT}")
            savepoint_active = True
            cursor.execute(
                "DELETE FROM request_quota_windows WHERE started_ms + ? <= ?",
                (self._window_ms, now_ms),
            )
            row = cursor.execute(
                "SELECT started_ms, requests, spend_microunits FROM request_quota_windows "
                "WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            if row is None:
                if cost_microunits > self._max_spend_microunits:
                    cursor.execute(f"ROLLBACK TO SAVEPOINT {_QUOTA_SAVEPOINT}")
                    cursor.execute(f"RELEASE SAVEPOINT {_QUOTA_SAVEPOINT}")
                    savepoint_active = False
                    return _refused(self._window_ms // 1000)
                count = cursor.execute("SELECT COUNT(*) FROM request_quota_windows").fetchone()[0]
                if type(count) is not int or count >= self._max_tenants:
                    # Persist expiry cleanup so stale tenants cannot occupy
                    # every slot and cause permanent refusals.
                    cursor.execute(f"RELEASE SAVEPOINT {_QUOTA_SAVEPOINT}")
                    savepoint_active = False
                    return _refused(self._window_ms // 1000)
                cursor.execute(
                    "INSERT INTO request_quota_windows "
                    "(tenant_id, started_ms, requests, spend_microunits) VALUES (?, ?, 1, ?)",
                    (tenant_id, now_ms, cost_microunits),
                )
                cursor.execute(f"RELEASE SAVEPOINT {_QUOTA_SAVEPOINT}")
                savepoint_active = False
                return QuotaDecision(
                    True,
                    self._max_requests - 1,
                    self._max_spend_microunits - cost_microunits,
                    0,
                )
            started_ms, requests, spend = row
            if (
                type(started_ms) is not int
                or type(requests) is not int
                or type(spend) is not int
                or started_ms > now_ms
                or requests < 0
                or spend < 0
            ):
                cursor.execute(f"ROLLBACK TO SAVEPOINT {_QUOTA_SAVEPOINT}")
                cursor.execute(f"RELEASE SAVEPOINT {_QUOTA_SAVEPOINT}")
                savepoint_active = False
                return _refused(self._window_ms // 1000)
            if (
                requests + 1 > self._max_requests
                or spend + cost_microunits > self._max_spend_microunits
            ):
                retry_ms = started_ms + self._window_ms - now_ms
                cursor.execute(f"ROLLBACK TO SAVEPOINT {_QUOTA_SAVEPOINT}")
                cursor.execute(f"RELEASE SAVEPOINT {_QUOTA_SAVEPOINT}")
                savepoint_active = False
                return _refused(
                    max(1, (retry_ms + 999) // 1000),
                    remaining_requests=max(0, self._max_requests - requests),
                    remaining_spend=max(0, self._max_spend_microunits - spend),
                )
            cursor.execute(
                "UPDATE request_quota_windows SET requests=?, spend_microunits=? "
                "WHERE tenant_id=? AND started_ms=?",
                (requests + 1, spend + cost_microunits, tenant_id, started_ms),
            )
            if cursor.rowcount != 1:
                cursor.execute(f"ROLLBACK TO SAVEPOINT {_QUOTA_SAVEPOINT}")
                cursor.execute(f"RELEASE SAVEPOINT {_QUOTA_SAVEPOINT}")
                savepoint_active = False
                return _refused(self._window_ms // 1000)
            cursor.execute(f"RELEASE SAVEPOINT {_QUOTA_SAVEPOINT}")
            savepoint_active = False
            return QuotaDecision(
                True,
                self._max_requests - requests - 1,
                self._max_spend_microunits - spend - cost_microunits,
                0,
            )
        except sqlite3.Error:
            if savepoint_active and cursor is not None:
                try:
                    cursor.execute(f"ROLLBACK TO SAVEPOINT {_QUOTA_SAVEPOINT}")
                    cursor.execute(f"RELEASE SAVEPOINT {_QUOTA_SAVEPOINT}")
                except sqlite3.Error:
                    pass
            raise QuotaError(QuotaErrorCode.STORE_UNAVAILABLE) from None
        finally:
            if cursor is not None:
                cursor.close()


def _refused(
    retry_after_seconds: int,
    *,
    remaining_requests: int = 0,
    remaining_spend: int = 0,
) -> QuotaDecision:
    return QuotaDecision(
        False,
        remaining_requests,
        remaining_spend,
        retry_after_seconds,
    )


__all__ = ["SQLITE_REQUEST_QUOTA_SCHEMA_STATEMENTS", "SqliteQuotaLedger"]
