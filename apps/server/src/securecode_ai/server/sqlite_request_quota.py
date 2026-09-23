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
)

SQLITE_REQUEST_QUOTA_SCHEMA_STATEMENTS = (
    """CREATE TABLE IF NOT EXISTS request_quota_windows (
        tenant_id TEXT NOT NULL PRIMARY KEY,
        started_ms INTEGER NOT NULL,
        requests INTEGER NOT NULL,
        spend_microunits INTEGER NOT NULL
    )""",
)


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
            type(tenant_id) is not str
            or not tenant_id
            or len(tenant_id) > 128
            or not tenant_id[0].isascii()
            or not tenant_id[0].isalnum()
            or any(
                not character.isascii() or not (character.isalnum() or character in "._:-")
                for character in tenant_id
            )
            or type(now_ms) is not int
            or now_ms < 0
            or type(cost_microunits) is not int
            or not 0 <= cost_microunits <= MAX_SPEND_MICROUNITS
        ):
            raise QuotaError(QuotaErrorCode.INVALID_CONFIGURATION)
        with self._lock:
            return self._charge(tenant_id, now_ms, cost_microunits)

    def _charge(self, tenant_id: str, now_ms: int, cost_microunits: int) -> QuotaDecision:
        cursor: sqlite3.Cursor | None = None
        try:
            cursor = self._connection.cursor()
            cursor.execute("BEGIN IMMEDIATE")
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
                    self._connection.rollback()
                    return _refused(self._window_ms // 1000)
                count = cursor.execute("SELECT COUNT(*) FROM request_quota_windows").fetchone()[0]
                if type(count) is not int or count >= self._max_tenants:
                    # Persist expiry cleanup so stale tenants cannot occupy
                    # every slot and cause permanent refusals.
                    self._connection.commit()
                    return _refused(self._window_ms // 1000)
                cursor.execute(
                    "INSERT INTO request_quota_windows "
                    "(tenant_id, started_ms, requests, spend_microunits) VALUES (?, ?, 1, ?)",
                    (tenant_id, now_ms, cost_microunits),
                )
                self._connection.commit()
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
                self._connection.rollback()
                return _refused(self._window_ms // 1000)
            if (
                requests + 1 > self._max_requests
                or spend + cost_microunits > self._max_spend_microunits
            ):
                retry_ms = started_ms + self._window_ms - now_ms
                self._connection.rollback()
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
                self._connection.rollback()
                return _refused(self._window_ms // 1000)
            self._connection.commit()
            return QuotaDecision(
                True,
                self._max_requests - requests - 1,
                self._max_spend_microunits - spend - cost_microunits,
                0,
            )
        except sqlite3.Error:
            self._connection.rollback()
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
