"""Durable, bounded SQLite implementation of the remote spend budget port."""

from __future__ import annotations

import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from threading import Lock
from typing import Final, Iterator, TypeGuard, cast

from securecode_ai.adapters.remote_provider_budget import (
    RemoteProviderBudgetError,
    RemoteProviderBudgetPort,
    RemoteProviderSpendLease,
    RemoteProviderSpendPolicy,
    RemoteProviderSpendRequest,
    RemoteProviderSpendUsage,
)

_TABLE: Final = "remote_provider_budget_events"
_SAVEPOINT: Final = "securecode_remote_provider_budget"
_REQUEST_INDEX: Final = "remote_provider_budget_request_attempt"
_SCOPE_INDEX: Final = "remote_provider_budget_scope_time"
_MAX_POLICIES: Final = 256
_MAX_RECORDS: Final = 65_536
_MAX_TOTAL_EVENTS: Final = 100_000
_MAX_CLEANUP_ITEMS: Final = 10_000
_MAX_SQLITE_INTEGER: Final = (1 << 63) - 1
_MAX_POLICY_WINDOW_MS: Final = 86_400_000
_MICRO: Final = 1_000_000

SQLITE_REMOTE_PROVIDER_BUDGET_SCHEMA_STATEMENTS = (
    f"""CREATE TABLE IF NOT EXISTS {_TABLE} (
        lease_id TEXT NOT NULL PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        model_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        attempt INTEGER NOT NULL CHECK (attempt BETWEEN 1 AND 10),
        timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
        max_input_tokens INTEGER NOT NULL CHECK (max_input_tokens > 0),
        max_output_tokens INTEGER NOT NULL CHECK (max_output_tokens > 0),
        tokens INTEGER NOT NULL CHECK (tokens >= 0),
        cost_microunits INTEGER NOT NULL CHECK (cost_microunits >= 0),
        reserved INTEGER NOT NULL CHECK (reserved IN (0, 1)),
        UNIQUE (tenant_id, model_id, request_id, attempt)
    )""",
    f"""CREATE INDEX IF NOT EXISTS {_SCOPE_INDEX}
        ON {_TABLE} (tenant_id, model_id, timestamp_ms)""",
    f"""CREATE UNIQUE INDEX IF NOT EXISTS {_REQUEST_INDEX}
        ON {_TABLE} (tenant_id, model_id, request_id, attempt)""",
)


@dataclass(frozen=True, slots=True)
class _StoredLease:
    lease_id: str
    tenant_id: str
    model_id: str
    request_id: str
    attempt: int
    max_input_tokens: int
    max_output_tokens: int
    timestamp_ms: int
    tokens: int
    cost_microunits: int
    reserved: int


class SqliteRemoteProviderBudget(RemoteProviderBudgetPort):
    """Persist per-tenant/model budget events with atomic SQLite savepoints."""

    __slots__ = ("_connection", "_lock", "_policies")

    def __init__(
        self,
        connection: sqlite3.Connection,
        policies: tuple[RemoteProviderSpendPolicy, ...],
    ) -> None:
        if (
            not isinstance(connection, sqlite3.Connection)
            or type(policies) is not tuple
            or not policies
            or len(policies) > _MAX_POLICIES
            or any(type(policy) is not RemoteProviderSpendPolicy for policy in policies)
        ):
            raise RemoteProviderBudgetError("INVALID_STATE")
        configured = {(policy.tenant_id, policy.model_id): policy for policy in policies}
        if len(configured) != len(policies):
            raise RemoteProviderBudgetError("INVALID_STATE")
        self._connection = connection
        self._lock = Lock()
        self._policies = configured
        self._initialize_schema()

    def reserve(self, request: RemoteProviderSpendRequest) -> RemoteProviderSpendLease:
        if type(request) is not RemoteProviderSpendRequest:
            raise RemoteProviderBudgetError("INVALID_STATE")
        key = (request.tenant_id, request.model_id)
        policy = self._policies.get(key)
        if policy is None:
            raise RemoteProviderBudgetError("NOT_CONFIGURED")
        now_ms = _now_ms()
        request_key = (request.tenant_id, request.model_id, request.request_id, request.attempt)
        reserved_tokens = request.max_input_tokens + request.max_output_tokens
        reserved_cost = _cost_microunits(
            request.max_input_tokens, policy.input_cost_microunits_per_million_tokens
        ) + _cost_microunits(
            request.max_output_tokens, policy.output_cost_microunits_per_million_tokens
        )
        lease_id = secrets.token_hex(24)
        with self._lock, self._transaction() as cursor:
            self._purge_cursor(cursor, now_ms=now_ms, max_items=256)
            total = cursor.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()
            if not _is_row(total) or len(total) != 1 or type(total[0]) is not int:
                raise RemoteProviderBudgetError("INVALID_STATE")
            if total[0] >= _MAX_TOTAL_EVENTS:
                raise RemoteProviderBudgetError("LIMIT_EXCEEDED")
            active_total = cursor.execute(
                f"SELECT COUNT(*) FROM {_TABLE} WHERE reserved=1"
            ).fetchone()
            if (
                not _is_row(active_total)
                or len(active_total) != 1
                or type(active_total[0]) is not int
            ):
                raise RemoteProviderBudgetError("INVALID_STATE")
            if active_total[0] >= _MAX_RECORDS:
                raise RemoteProviderBudgetError("LIMIT_EXCEEDED")
            if cursor.execute(
                f"SELECT 1 FROM {_TABLE} WHERE tenant_id=? AND model_id=? AND request_id=? AND attempt=?",
                request_key,
            ).fetchone() is not None:
                raise RemoteProviderBudgetError("INVALID_STATE")

            cutoff_ms = now_ms - policy.window_ms
            rows = cursor.execute(
                f"""SELECT timestamp_ms, max_input_tokens, max_output_tokens,
                           tokens, cost_microunits, reserved
                    FROM {_TABLE}
                    WHERE tenant_id=? AND model_id=? AND (timestamp_ms>? OR reserved=1)
                    ORDER BY timestamp_ms, lease_id LIMIT ?""",
                (*key, cutoff_ms, _MAX_TOTAL_EVENTS + 1),
            ).fetchall()
            if len(rows) > _MAX_TOTAL_EVENTS:
                raise RemoteProviderBudgetError("INVALID_STATE")
            calls = tokens = cost = active = 0
            for row in rows:
                event = _stored_values(row)
                if event.timestamp_ms < 0 or event.tokens < 0 or event.cost_microunits < 0:
                    raise RemoteProviderBudgetError("INVALID_STATE")
                if event.reserved not in {0, 1}:
                    raise RemoteProviderBudgetError("INVALID_STATE")
                calls += 1
                tokens += event.tokens
                cost += event.cost_microunits
                active += event.reserved
            if active >= policy.max_concurrent_calls:
                raise RemoteProviderBudgetError("LIMIT_EXCEEDED")
            if (
                calls >= policy.max_calls_per_window
                or tokens + reserved_tokens > policy.max_tokens_per_window
                or cost + reserved_cost > policy.max_cost_microunits_per_window
            ):
                raise RemoteProviderBudgetError("LIMIT_EXCEEDED")
            cursor.execute(
                f"""INSERT INTO {_TABLE}
                    (lease_id, tenant_id, model_id, request_id, attempt, timestamp_ms,
                     max_input_tokens, max_output_tokens, tokens, cost_microunits, reserved)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                (
                    lease_id,
                    request.tenant_id,
                    request.model_id,
                    request.request_id,
                    request.attempt,
                    now_ms,
                    request.max_input_tokens,
                    request.max_output_tokens,
                    reserved_tokens,
                    reserved_cost,
                ),
            )
        return RemoteProviderSpendLease(
            lease_id=lease_id,
            tenant_id=request.tenant_id,
            model_id=request.model_id,
            request_id=request.request_id,
            attempt=request.attempt,
            max_input_tokens=request.max_input_tokens,
            max_output_tokens=request.max_output_tokens,
            reserved_cost_microunits=reserved_cost,
        )

    def settle(
        self, lease: RemoteProviderSpendLease, usage: RemoteProviderSpendUsage
    ) -> None:
        if type(usage) is not RemoteProviderSpendUsage:
            raise RemoteProviderBudgetError("INVALID_STATE")
        over_budget = False
        with self._lock, self._transaction() as cursor:
            event, policy = self._active_lease(cursor, lease)
            actual_tokens = usage.input_tokens + usage.output_tokens
            actual_cost = _cost_microunits(
                usage.input_tokens, policy.input_cost_microunits_per_million_tokens
            ) + _cost_microunits(
                usage.output_tokens, policy.output_cost_microunits_per_million_tokens
            )
            cursor.execute(
                f"""UPDATE {_TABLE}
                    SET timestamp_ms=?, tokens=?, cost_microunits=?, reserved=0
                    WHERE lease_id=? AND reserved=1""",
                (_now_ms(), actual_tokens, actual_cost, event.lease_id),
            )
            if cursor.rowcount != 1:
                raise RemoteProviderBudgetError("INVALID_STATE")
            over_budget = (
                usage.input_tokens > lease.max_input_tokens
                or usage.output_tokens > lease.max_output_tokens
                or actual_cost > lease.reserved_cost_microunits
            )
        if over_budget:
            raise RemoteProviderBudgetError("LIMIT_EXCEEDED")

    def charge_maximum(self, lease: RemoteProviderSpendLease) -> None:
        with self._lock, self._transaction() as cursor:
            event, _ = self._active_lease(cursor, lease)
            cursor.execute(
                f"UPDATE {_TABLE} SET timestamp_ms=?, reserved=0 WHERE lease_id=? AND reserved=1",
                (_now_ms(), event.lease_id),
            )
            if cursor.rowcount != 1:
                raise RemoteProviderBudgetError("INVALID_STATE")

    def release(self, lease: RemoteProviderSpendLease) -> None:
        with self._lock, self._transaction() as cursor:
            event, _ = self._active_lease(cursor, lease)
            cursor.execute(f"DELETE FROM {_TABLE} WHERE lease_id=? AND reserved=1", (event.lease_id,))
            if cursor.rowcount != 1:
                raise RemoteProviderBudgetError("INVALID_STATE")

    def purge_expired(self, *, now_ms: object = None, max_items: int = 100) -> int:
        if type(max_items) is not int or not 1 <= max_items <= _MAX_CLEANUP_ITEMS:
            raise RemoteProviderBudgetError("INVALID_STATE")
        timestamp = _now_ms() if now_ms is None else now_ms
        if type(timestamp) is not int or not 0 <= timestamp <= _MAX_SQLITE_INTEGER:
            raise RemoteProviderBudgetError("INVALID_STATE")
        with self._lock, self._transaction() as cursor:
            return self._purge_cursor(cursor, now_ms=timestamp, max_items=max_items)

    def _initialize_schema(self) -> None:
        with self._lock, self._transaction() as cursor:
            for statement in SQLITE_REMOTE_PROVIDER_BUDGET_SCHEMA_STATEMENTS:
                cursor.execute(statement)
            cursor.execute(
                f"""SELECT lease_id, tenant_id, model_id, request_id, attempt,
                           timestamp_ms, max_input_tokens, max_output_tokens,
                           tokens, cost_microunits, reserved
                    FROM {_TABLE} LIMIT 0"""
            )
            columns = tuple(item[1] for item in cursor.execute(f"PRAGMA table_info({_TABLE})"))
            expected = (
                "lease_id", "tenant_id", "model_id", "request_id", "attempt",
                "timestamp_ms", "max_input_tokens", "max_output_tokens", "tokens",
                "cost_microunits", "reserved",
            )
            if columns != expected:
                raise RemoteProviderBudgetError("INVALID_STATE")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        cursor: sqlite3.Cursor | None = None
        active = False
        try:
            cursor = self._connection.cursor()
            cursor.execute(f"SAVEPOINT {_SAVEPOINT}")
            active = True
            yield cursor
            cursor.execute(f"RELEASE SAVEPOINT {_SAVEPOINT}")
            active = False
        except RemoteProviderBudgetError as error:
            if error.code == "LIMIT_EXCEEDED" and active and cursor is not None:
                try:
                    cursor.execute(f"RELEASE SAVEPOINT {_SAVEPOINT}")
                    active = False
                except sqlite3.Error:
                    self._rollback(cursor, active)
                    raise RemoteProviderBudgetError("INVALID_STATE") from None
                raise
            self._rollback(cursor, active)
            raise
        except Exception:
            self._rollback(cursor, active)
            raise RemoteProviderBudgetError("INVALID_STATE") from None
        finally:
            if cursor is not None:
                cursor.close()

    def _active_lease(
        self,
        cursor: sqlite3.Cursor,
        lease: RemoteProviderSpendLease,
    ) -> tuple[_StoredLease, RemoteProviderSpendPolicy]:
        if type(lease) is not RemoteProviderSpendLease:
            raise RemoteProviderBudgetError("INVALID_STATE")
        policy = self._policies.get((lease.tenant_id, lease.model_id))
        row = cursor.execute(
            f"""SELECT lease_id, tenant_id, model_id, request_id, attempt,
                       timestamp_ms, max_input_tokens, max_output_tokens,
                       tokens, cost_microunits, reserved
                FROM {_TABLE} WHERE lease_id=?""",
            (lease.lease_id,),
        ).fetchone()
        if policy is None or row is None:
            raise RemoteProviderBudgetError("INVALID_STATE")
        event = _stored_lease(row)
        if (
            event.lease_id != lease.lease_id
            or event.tenant_id != lease.tenant_id
            or event.model_id != lease.model_id
            or event.request_id != lease.request_id
            or event.attempt != lease.attempt
            or event.max_input_tokens != lease.max_input_tokens
            or event.max_output_tokens != lease.max_output_tokens
            or event.tokens != lease.max_input_tokens + lease.max_output_tokens
            or event.cost_microunits != lease.reserved_cost_microunits
            or event.reserved != 1
        ):
            raise RemoteProviderBudgetError("INVALID_STATE")
        return event, policy

    def _purge_cursor(
        self,
        cursor: sqlite3.Cursor,
        *,
        now_ms: int,
        max_items: int,
    ) -> int:
        removed = 0
        for (tenant_id, model_id), policy in self._policies.items():
            remaining = max_items - removed
            if remaining <= 0:
                break
            cutoff = now_ms - policy.window_ms
            rows = cursor.execute(
                f"""SELECT lease_id FROM {_TABLE}
                    WHERE tenant_id=? AND model_id=? AND timestamp_ms<=? AND reserved=0
                    ORDER BY timestamp_ms, lease_id LIMIT ?""",
                (tenant_id, model_id, cutoff, remaining),
            ).fetchall()
            if not rows:
                continue
            lease_ids = tuple(row[0] for row in rows)
            if any(type(value) is not str or not value for value in lease_ids):
                raise RemoteProviderBudgetError("INVALID_STATE")
            for lease_id in lease_ids:
                cursor.execute(f"DELETE FROM {_TABLE} WHERE lease_id=?", (lease_id,))
                if cursor.rowcount != 1:
                    raise RemoteProviderBudgetError("INVALID_STATE")
                removed += 1
        remaining = max_items - removed
        if remaining > 0:
            cutoff = now_ms - _MAX_POLICY_WINDOW_MS
            rows = cursor.execute(
                f"""SELECT lease_id FROM {_TABLE}
                    WHERE timestamp_ms<=?
                    ORDER BY timestamp_ms, lease_id LIMIT ?""",
                (cutoff, remaining),
            ).fetchall()
            lease_ids = tuple(row[0] for row in rows)
            if any(type(value) is not str or not value for value in lease_ids):
                raise RemoteProviderBudgetError("INVALID_STATE")
            for lease_id in lease_ids:
                cursor.execute(f"DELETE FROM {_TABLE} WHERE lease_id=?", (lease_id,))
                if cursor.rowcount != 1:
                    raise RemoteProviderBudgetError("INVALID_STATE")
                removed += 1
        return removed

    @staticmethod
    def _rollback(cursor: sqlite3.Cursor | None, active: bool) -> None:
        if active and cursor is not None:
            try:
                cursor.execute(f"ROLLBACK TO SAVEPOINT {_SAVEPOINT}")
                cursor.execute(f"RELEASE SAVEPOINT {_SAVEPOINT}")
            except sqlite3.Error:
                pass


def _stored_values(row: object) -> _StoredLease:
    if not _is_row(row) or len(row) != 6 or any(type(value) is not int for value in row):
        raise RemoteProviderBudgetError("INVALID_STATE")
    timestamp_ms, input_tokens, output_tokens, tokens, cost, reserved = cast(
        tuple[int, int, int, int, int, int], tuple(row)
    )
    if (
        timestamp_ms < 0
        or input_tokens < 1
        or output_tokens < 1
        or tokens < 0
        or cost < 0
        or reserved not in {0, 1}
    ):
        raise RemoteProviderBudgetError("INVALID_STATE")
    return _StoredLease(
        lease_id="stored",
        tenant_id="stored",
        model_id="stored",
        request_id="stored",
        attempt=1,
        timestamp_ms=timestamp_ms,
        max_input_tokens=input_tokens,
        max_output_tokens=output_tokens,
        tokens=tokens,
        cost_microunits=cost,
        reserved=reserved,
    )


def _stored_lease(row: object) -> _StoredLease:
    if not _is_row(row) or len(row) != 11:
        raise RemoteProviderBudgetError("INVALID_STATE")
    if any(type(row[index]) is not str or not row[index] for index in (0, 1, 2, 3)):
        raise RemoteProviderBudgetError("INVALID_STATE")
    if any(type(row[index]) is not int for index in range(4, 11)):
        raise RemoteProviderBudgetError("INVALID_STATE")
    event = _StoredLease(
        lease_id=cast(str, row[0]),
        tenant_id=cast(str, row[1]),
        model_id=cast(str, row[2]),
        request_id=cast(str, row[3]),
        attempt=cast(int, row[4]),
        timestamp_ms=cast(int, row[5]),
        max_input_tokens=cast(int, row[6]),
        max_output_tokens=cast(int, row[7]),
        tokens=cast(int, row[8]),
        cost_microunits=cast(int, row[9]),
        reserved=cast(int, row[10]),
    )
    if (
        not 1 <= event.attempt <= 10
        or event.timestamp_ms < 0
        or event.max_input_tokens < 1
        or event.max_output_tokens < 1
        or event.tokens < 0
        or event.cost_microunits < 0
        or event.reserved not in {0, 1}
    ):
        raise RemoteProviderBudgetError("INVALID_STATE")
    return event


def _is_row(value: object) -> TypeGuard[tuple[object, ...] | sqlite3.Row]:
    return isinstance(value, (tuple, sqlite3.Row))


def _now_ms() -> int:
    value = time.time_ns() // 1_000_000
    if not 0 <= value <= _MAX_SQLITE_INTEGER:
        raise RemoteProviderBudgetError("INVALID_STATE")
    return value


def _cost_microunits(tokens: int, rate_per_million: int) -> int:
    if tokens == 0 or rate_per_million == 0:
        return 0
    return (tokens * rate_per_million + _MICRO - 1) // _MICRO


__all__ = ["SQLITE_REMOTE_PROVIDER_BUDGET_SCHEMA_STATEMENTS", "SqliteRemoteProviderBudget"]
