"""Durable, bounded SQLite implementation of the remote spend budget port."""

from __future__ import annotations

import re
import secrets
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from threading import Lock
from typing import Final, TypeGuard, cast

from securecode_ai.adapters.remote_provider_budget import (
    RemoteProviderBudgetError,
    RemoteProviderBudgetPort,
    RemoteProviderCostReceipt,
    RemoteProviderSpendLease,
    RemoteProviderSpendPolicy,
    RemoteProviderSpendRequest,
    RemoteProviderSpendUsage,
    remote_provider_pricing_pin,
)

_TABLE: Final = "remote_provider_budget_events"
_PRICING_TABLE: Final = "remote_provider_budget_pricing"
_PRICING_PIN: Final = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MODEL_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_REQUEST_INDEX: Final = "remote_provider_budget_request_attempt"
_SCOPE_INDEX: Final = "remote_provider_budget_scope_time"
_MAX_POLICIES: Final = 256
_MAX_RECORDS: Final = 65_536
_MAX_TOTAL_EVENTS: Final = 100_000
_MAX_CLEANUP_ITEMS: Final = 10_000
_MAX_SQLITE_INTEGER: Final = (1 << 63) - 1
_MAX_POLICY_WINDOW_MS: Final = 86_400_000
_MAX_TOKENS: Final = 1_000_000_000
_MAX_SLOT_TIMEOUT_MS: Final = 86_400_000
_DEFAULT_SLOT_TIMEOUT_MS: Final = 300_000
# Match the adapter receipt bound: a request is admitted against the lower
# policy ceiling, while an over-limit provider response may report up to the
# sum of the independently bounded input and output charges.
_MAX_COST_MICROUNITS: Final = 2_000_000_000_000_000
_MAX_RATE_MICROUNITS_PER_MILLION: Final = 1_000_000_000_000
_PRICING_VERSION: Final = "v1"
_MICRO: Final = 1_000_000

SQLITE_REMOTE_PROVIDER_BUDGET_SCHEMA_STATEMENTS = (
    f"""CREATE TABLE IF NOT EXISTS {_TABLE} (
        lease_id TEXT NOT NULL PRIMARY KEY,
        run_id TEXT NOT NULL,
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
        slot_active INTEGER NOT NULL CHECK (slot_active IN (0, 1)),
        slot_expires_at_ms INTEGER NOT NULL CHECK (slot_expires_at_ms >= 0),
        replay_blocked INTEGER NOT NULL CHECK (replay_blocked IN (0, 1)),
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
    run_id: str
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
    slot_active: int
    slot_expires_at_ms: int
    replay_blocked: int


@dataclass(frozen=True, slots=True)
class _PricingRecord:
    tenant_id: str
    model_id: str
    run_id: str
    pricing_version: str
    input_rate: int
    output_rate: int
    pricing_pin: str


class SqliteRemoteProviderBudget(RemoteProviderBudgetPort):
    """Persist bounded budget events with run-scoped pricing pins."""

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
        try:
            self._connection.execute("PRAGMA busy_timeout=5000")
        except sqlite3.Error:
            raise RemoteProviderBudgetError("INVALID_STATE") from None
        self._initialize_schema()

    def reserve(self, request: RemoteProviderSpendRequest) -> RemoteProviderSpendLease:
        if type(request) is not RemoteProviderSpendRequest:
            raise RemoteProviderBudgetError("INVALID_STATE")
        key = (request.tenant_id, request.model_id)
        policy = self._policies.get(key)
        if policy is None:
            raise RemoteProviderBudgetError("NOT_CONFIGURED")
        now_ms = _now_ms()
        request_key = (
            request.tenant_id,
            request.model_id,
            request.request_id,
            request.attempt,
        )
        reserved_tokens = request.max_input_tokens + request.max_output_tokens
        reserved_cost = _cost_microunits(
            request.max_input_tokens, policy.input_cost_microunits_per_million_tokens
        ) + _cost_microunits(
            request.max_output_tokens, policy.output_cost_microunits_per_million_tokens
        )
        lease_id = secrets.token_hex(24)
        with self._lock, self._transaction() as cursor:
            self._purge_cursor(cursor, now_ms=now_ms, max_items=256)
            self._ensure_pricing_pin(
                cursor,
                tenant_id=request.tenant_id,
                model_id=request.model_id,
                run_id=request.run_id,
                policy=policy,
            )
            self._reconcile_expired_slots(cursor, now_ms=now_ms, max_items=256)
            total = cursor.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()
            if not _is_row(total) or len(total) != 1 or type(total[0]) is not int:
                raise RemoteProviderBudgetError("INVALID_STATE")
            if total[0] >= _MAX_TOTAL_EVENTS:
                raise RemoteProviderBudgetError("LIMIT_EXCEEDED")
            active_total = cursor.execute(
                f"SELECT COUNT(*) FROM {_TABLE} WHERE slot_active=1"
            ).fetchone()
            if (
                not _is_row(active_total)
                or len(active_total) != 1
                or type(active_total[0]) is not int
            ):
                raise RemoteProviderBudgetError("INVALID_STATE")
            if active_total[0] >= _MAX_RECORDS:
                raise RemoteProviderBudgetError("LIMIT_EXCEEDED")
            if (
                cursor.execute(
                    f"""SELECT 1 FROM {_TABLE}
                    WHERE tenant_id=? AND model_id=? AND request_id=? AND attempt=?""",
                    request_key,
                ).fetchone()
                is not None
            ):
                raise RemoteProviderBudgetError("INVALID_STATE")

            cutoff_ms = now_ms - policy.window_ms
            rows = cursor.execute(
                f"""SELECT timestamp_ms, max_input_tokens, max_output_tokens,
                           tokens, cost_microunits, reserved, slot_active,
                           slot_expires_at_ms, replay_blocked
                    FROM {_TABLE}
                    WHERE tenant_id=? AND model_id=?
                      AND (timestamp_ms>? OR reserved=1 OR slot_active=1)
                    ORDER BY timestamp_ms, lease_id LIMIT ?""",
                (*key, cutoff_ms, _MAX_TOTAL_EVENTS + 1),
            ).fetchall()
            if len(rows) > _MAX_TOTAL_EVENTS:
                raise RemoteProviderBudgetError("INVALID_STATE")
            calls = tokens = cost = active = 0
            for row in rows:
                event = _stored_values(row)
                if (
                    event.timestamp_ms < 0
                    or event.timestamp_ms > now_ms
                    or event.tokens < 0
                    or event.cost_microunits < 0
                ):
                    raise RemoteProviderBudgetError("INVALID_STATE")
                if event.reserved not in {0, 1}:
                    raise RemoteProviderBudgetError("INVALID_STATE")
                if event.slot_active not in {0, 1}:
                    raise RemoteProviderBudgetError("INVALID_STATE")
                if event.replay_blocked not in {0, 1}:
                    raise RemoteProviderBudgetError("INVALID_STATE")
                if event.reserved == 1 and event.slot_active != 1:
                    raise RemoteProviderBudgetError("INVALID_STATE")
                if event.replay_blocked == 1 and (event.reserved == 1 or event.slot_active == 1):
                    raise RemoteProviderBudgetError("INVALID_STATE")
                if event.slot_active == 1 and event.slot_expires_at_ms <= now_ms:
                    raise RemoteProviderBudgetError("INVALID_STATE")
                if event.slot_active == 0 and event.slot_expires_at_ms != 0:
                    raise RemoteProviderBudgetError("INVALID_STATE")
                if event.timestamp_ms > cutoff_ms:
                    calls += 1
                # An unsettled lease still represents spend that may happen.
                # Keep its full reservation in the budget even if the call
                # started before the rolling window, otherwise a long-running
                # provider request could be counted again by a fresh lease.
                if event.timestamp_ms > cutoff_ms or event.reserved:
                    tokens += event.tokens
                    cost += event.cost_microunits
                active += event.slot_active
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
                     (lease_id, run_id, tenant_id, model_id, request_id, attempt, timestamp_ms,
                      max_input_tokens, max_output_tokens, tokens, cost_microunits,
                      reserved, slot_active, slot_expires_at_ms, replay_blocked)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    lease_id,
                    request.run_id,
                    request.tenant_id,
                    request.model_id,
                    request.request_id,
                    request.attempt,
                    now_ms,
                    request.max_input_tokens,
                    request.max_output_tokens,
                    reserved_tokens,
                    reserved_cost,
                    1,
                    1,
                    now_ms
                    + (
                        request.slot_timeout_ms
                        if request.slot_timeout_ms is not None
                        else _DEFAULT_SLOT_TIMEOUT_MS
                    ),
                    0,
                ),
            )
        return RemoteProviderSpendLease(
            lease_id=lease_id,
            run_id=request.run_id,
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
    ) -> RemoteProviderCostReceipt:
        if type(usage) is not RemoteProviderSpendUsage:
            raise RemoteProviderBudgetError("INVALID_STATE")
        over_budget = False
        with self._lock, self._transaction() as cursor:
            event, _, pricing = self._active_lease(cursor, lease)
            if pricing is None:
                raise RemoteProviderBudgetError("INVALID_STATE")
            actual_tokens = usage.input_tokens + usage.output_tokens
            actual_cost = _cost_microunits(
                usage.input_tokens, pricing.input_rate
            ) + _cost_microunits(usage.output_tokens, pricing.output_rate)
            cursor.execute(
                f"""UPDATE {_TABLE}
                    SET timestamp_ms=?, tokens=?, cost_microunits=?, reserved=0,
                        slot_active=0, slot_expires_at_ms=0, replay_blocked=0
                    WHERE lease_id=? AND reserved=1 AND slot_active=1""",
                (
                    max(event.timestamp_ms, _now_ms()),
                    actual_tokens,
                    actual_cost,
                    event.lease_id,
                ),
            )
            if cursor.rowcount != 1:
                raise RemoteProviderBudgetError("INVALID_STATE")
            over_budget = (
                usage.input_tokens > lease.max_input_tokens
                or usage.output_tokens > lease.max_output_tokens
                or actual_cost > lease.reserved_cost_microunits
            )
        receipt = _cost_receipt(lease, actual_cost, maximum_charged=False)
        if over_budget:
            raise RemoteProviderBudgetError("LIMIT_EXCEEDED", cost_receipt=receipt)
        return receipt

    def charge_maximum(self, lease: RemoteProviderSpendLease) -> RemoteProviderCostReceipt:
        with self._lock, self._transaction() as cursor:
            event, _, _ = self._active_lease(cursor, lease, require_reserved=False)
            if event.reserved == 1 or event.slot_active == 1:
                cursor.execute(
                    f"UPDATE {_TABLE} SET timestamp_ms=?, reserved=0, slot_active=0,"
                    "slot_expires_at_ms=0, replay_blocked=1 "
                    "WHERE lease_id=? AND (reserved=1 OR slot_active=1)",
                    (max(event.timestamp_ms, _now_ms()), event.lease_id),
                )
                if cursor.rowcount != 1:
                    raise RemoteProviderBudgetError("INVALID_STATE")
            elif (
                event.tokens != lease.max_input_tokens + lease.max_output_tokens
                or event.cost_microunits != lease.reserved_cost_microunits
            ):
                raise RemoteProviderBudgetError("INVALID_STATE")
        return _cost_receipt(lease, lease.reserved_cost_microunits, maximum_charged=True)

    def release(self, lease: RemoteProviderSpendLease) -> None:
        with self._lock, self._transaction() as cursor:
            event, _, _ = self._active_lease(cursor, lease, require_pricing=False)
            cursor.execute(
                f"DELETE FROM {_TABLE} WHERE lease_id=? AND reserved=1 AND slot_active=1",
                (event.lease_id,),
            )
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

    @staticmethod
    def _reconcile_expired_slots(cursor: sqlite3.Cursor, *, now_ms: int, max_items: int) -> int:
        rows = cursor.execute(
            f"SELECT lease_id FROM {_TABLE} WHERE slot_active=1 "
            "AND slot_expires_at_ms<=? ORDER BY slot_expires_at_ms,lease_id LIMIT ?",
            (now_ms, max_items),
        ).fetchall()
        for row in rows:
            if not _is_row(row) or len(row) != 1 or type(row[0]) is not str:
                raise RemoteProviderBudgetError("INVALID_STATE")
            cursor.execute(
                f"UPDATE {_TABLE} SET timestamp_ms=?, reserved=0, slot_active=0, "
                "slot_expires_at_ms=0, replay_blocked=1 WHERE lease_id=? AND slot_active=1",
                (now_ms, row[0]),
            )
            if cursor.rowcount != 1:
                raise RemoteProviderBudgetError("INVALID_STATE")
        return len(rows)

    @staticmethod
    def _normalize_legacy_rows(cursor: sqlite3.Cursor) -> None:
        cursor.execute(
            f"UPDATE {_TABLE} SET reserved=0, slot_active=0, slot_expires_at_ms=0, "
            "replay_blocked=1 WHERE (reserved=1 AND slot_active=0) "
            "OR (run_id='' AND (reserved=1 OR slot_active=1))"
        )

    def _initialize_schema(self) -> None:
        with self._lock, self._transaction() as cursor:
            cursor.execute(SQLITE_REMOTE_PROVIDER_BUDGET_SCHEMA_STATEMENTS[0])
            columns = tuple(
                item[1]
                for item in cursor.execute(f"PRAGMA table_info({_quote_identifier(_TABLE)})")
            )
            legacy = (
                "lease_id",
                "tenant_id",
                "model_id",
                "request_id",
                "attempt",
                "timestamp_ms",
                "max_input_tokens",
                "max_output_tokens",
                "tokens",
                "cost_microunits",
                "reserved",
            )
            if columns == legacy:
                cursor.execute(f"ALTER TABLE {_TABLE} ADD COLUMN run_id TEXT NOT NULL DEFAULT ''")
                columns = tuple(
                    item[1]
                    for item in cursor.execute(f"PRAGMA table_info({_quote_identifier(_TABLE)})")
                )
            expected = (
                "lease_id",
                "run_id",
                "tenant_id",
                "model_id",
                "request_id",
                "attempt",
                "timestamp_ms",
                "max_input_tokens",
                "max_output_tokens",
                "tokens",
                "cost_microunits",
                "reserved",
                "slot_active",
                "slot_expires_at_ms",
                "replay_blocked",
            )
            legacy_with_run = (*legacy, "run_id")
            legacy_with_run_slots = (*legacy_with_run, "slot_active", "slot_expires_at_ms")
            prior_expected = expected[:-3]
            prior_with_slots = expected[:-1]
            if columns == prior_with_slots:
                cursor.execute(
                    f"ALTER TABLE {_TABLE} ADD COLUMN replay_blocked INTEGER NOT NULL DEFAULT 0"
                )
                columns = expected
            if columns not in {
                expected,
                legacy_with_run,
                legacy_with_run_slots,
                prior_expected,
            }:
                raise RemoteProviderBudgetError("INVALID_STATE")
            old_request_key = ("tenant_id", "model_id", "request_id", "attempt")
            run_scoped_request_key = (
                "tenant_id",
                "model_id",
                "run_id",
                "request_id",
                "attempt",
            )
            signatures = _unique_index_signatures(cursor, _TABLE)
            if (
                columns
                in {
                    legacy_with_run,
                    legacy_with_run_slots,
                    prior_expected,
                }
                or run_scoped_request_key in signatures
                or old_request_key not in signatures
            ):
                duplicate = cursor.execute(
                    f"SELECT 1 FROM {_TABLE} "
                    "GROUP BY tenant_id,model_id,request_id,attempt "
                    "HAVING COUNT(*)>1 LIMIT 1"
                ).fetchone()
                if duplicate is not None:
                    raise RemoteProviderBudgetError("INVALID_STATE")
                self._rebuild_schema(cursor)
            else:
                self._normalize_legacy_rows(cursor)
                cursor.execute(SQLITE_REMOTE_PROVIDER_BUDGET_SCHEMA_STATEMENTS[1])
                cursor.execute(SQLITE_REMOTE_PROVIDER_BUDGET_SCHEMA_STATEMENTS[2])
            cursor.execute(
                f"""SELECT lease_id, run_id, tenant_id, model_id, request_id, attempt,
                           timestamp_ms, max_input_tokens, max_output_tokens,
                           tokens, cost_microunits, reserved, slot_active,
                           slot_expires_at_ms, replay_blocked
                    FROM {_TABLE} LIMIT 0"""
            )
            self._initialize_pricing_table(cursor)
            self._validate_pricing_records(cursor)

    def _initialize_pricing_table(self, cursor: sqlite3.Cursor) -> None:
        expected = (
            "tenant_id",
            "model_id",
            "run_id",
            "pricing_version",
            "input_rate",
            "output_rate",
            "pricing_pin",
        )
        legacy = ("tenant_id", "model_id", "run_id", "pricing_pin")
        columns = tuple(row[1] for row in cursor.execute(f"PRAGMA table_info({_PRICING_TABLE})"))
        if columns == legacy:
            count = cursor.execute(f"SELECT COUNT(*) FROM {_PRICING_TABLE}").fetchone()
            if count is None or type(count[0]) is not int or count[0] != 0:
                raise RemoteProviderBudgetError("INVALID_STATE")
            cursor.execute(f"DROP TABLE {_PRICING_TABLE}")
            columns = ()
        if columns not in {(), expected}:
            raise RemoteProviderBudgetError("INVALID_STATE")
        if not columns:
            cursor.execute(
                f"""CREATE TABLE {_PRICING_TABLE} (
                    tenant_id TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    pricing_version TEXT NOT NULL,
                    input_rate INTEGER NOT NULL,
                    output_rate INTEGER NOT NULL,
                    pricing_pin TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, model_id, run_id)
                )"""
            )

    @staticmethod
    def _rebuild_schema(cursor: sqlite3.Cursor) -> None:
        columns = tuple(
            item[1] for item in cursor.execute(f"PRAGMA table_info({_quote_identifier(_TABLE)})")
        )
        run_id_second = len(columns) > 1 and columns[1] == "run_id"
        has_slots = "slot_active" in columns and "slot_expires_at_ms" in columns
        has_replay = "replay_blocked" in columns
        if run_id_second:
            identity_select = (
                "lease_id, run_id, tenant_id, model_id, request_id, attempt, "
                "timestamp_ms, max_input_tokens, max_output_tokens, tokens, cost_microunits, reserved"
            )
        else:
            identity_select = (
                "lease_id, tenant_id, model_id, request_id, attempt, timestamp_ms, "
                "max_input_tokens, max_output_tokens, tokens, cost_microunits, reserved, run_id"
            )
        slot_select = ", slot_active, slot_expires_at_ms" if has_slots else ""
        replay_select = ", replay_blocked" if has_replay else ""
        rows = cursor.execute(
            f"""SELECT {identity_select}{slot_select}{replay_select}
                FROM {_quote_identifier(_TABLE)}"""
        ).fetchall()
        if len(rows) > _MAX_TOTAL_EVENTS:
            raise RemoteProviderBudgetError("INVALID_STATE")
        migrated: list[tuple[object, ...]] = []
        for row in rows:
            event = _stored_lease(row)
            reserved = event.reserved
            slot_active = event.slot_active
            slot_expires_at_ms = event.slot_expires_at_ms
            replay_blocked = event.replay_blocked
            if (reserved == 1 and (not has_slots or slot_active == 0)) or (
                event.run_id == "" and (reserved == 1 or slot_active == 1)
            ):
                reserved = 0
                slot_active = 0
                slot_expires_at_ms = 0
                replay_blocked = 1
            migrated.append(
                (
                    event.lease_id,
                    event.run_id,
                    event.tenant_id,
                    event.model_id,
                    event.request_id,
                    event.attempt,
                    event.timestamp_ms,
                    event.max_input_tokens,
                    event.max_output_tokens,
                    event.tokens,
                    event.cost_microunits,
                    reserved,
                    slot_active,
                    slot_expires_at_ms,
                    replay_blocked,
                )
            )
        legacy_table = f"{_TABLE}_legacy"
        if _sqlite_object_exists(cursor, legacy_table):
            raise RemoteProviderBudgetError("INVALID_STATE")
        cursor.execute(f"DROP INDEX IF EXISTS {_quote_identifier(_REQUEST_INDEX)}")
        cursor.execute(f"DROP INDEX IF EXISTS {_quote_identifier(_SCOPE_INDEX)}")
        cursor.execute(
            f"ALTER TABLE {_quote_identifier(_TABLE)} RENAME TO {_quote_identifier(legacy_table)}"
        )
        cursor.execute(SQLITE_REMOTE_PROVIDER_BUDGET_SCHEMA_STATEMENTS[0])
        for values in migrated:
            cursor.execute(
                f"""INSERT INTO {_quote_identifier(_TABLE)}
                    (lease_id, run_id, tenant_id, model_id, request_id, attempt, timestamp_ms,
                     max_input_tokens, max_output_tokens, tokens, cost_microunits, reserved,
                     slot_active, slot_expires_at_ms, replay_blocked)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                values,
            )
        cursor.execute(f"DROP TABLE {_quote_identifier(legacy_table)}")
        cursor.execute(SQLITE_REMOTE_PROVIDER_BUDGET_SCHEMA_STATEMENTS[1])
        cursor.execute(SQLITE_REMOTE_PROVIDER_BUDGET_SCHEMA_STATEMENTS[2])

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        cursor: sqlite3.Cursor | None = None
        active = False
        try:
            cursor = self._connection.cursor()
            # Admission reads and its INSERT must share one write lock.  A
            # deferred SAVEPOINT allowed two processes to read the same
            # totals before either reservation was visible.
            cursor.execute("BEGIN IMMEDIATE")
            active = True
            yield cursor
            cursor.execute("COMMIT")
            active = False
        except RemoteProviderBudgetError:
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
        *,
        require_pricing: bool = True,
        require_reserved: bool = True,
    ) -> tuple[_StoredLease, RemoteProviderSpendPolicy, _PricingRecord | None]:
        if type(lease) is not RemoteProviderSpendLease:
            raise RemoteProviderBudgetError("INVALID_STATE")
        policy = self._policies.get((lease.tenant_id, lease.model_id))
        row = cursor.execute(
            f"""SELECT lease_id, run_id, tenant_id, model_id, request_id, attempt,
                       timestamp_ms, max_input_tokens, max_output_tokens,
                       tokens, cost_microunits, reserved, slot_active,
                       slot_expires_at_ms, replay_blocked
                FROM {_TABLE} WHERE lease_id=?""",
            (lease.lease_id,),
        ).fetchone()
        if policy is None or row is None:
            raise RemoteProviderBudgetError("INVALID_STATE")
        event = _stored_lease(row)
        if (
            event.lease_id != lease.lease_id
            or event.run_id != lease.run_id
            or event.tenant_id != lease.tenant_id
            or event.model_id != lease.model_id
            or event.request_id != lease.request_id
            or event.attempt != lease.attempt
            or event.max_input_tokens != lease.max_input_tokens
            or event.max_output_tokens != lease.max_output_tokens
            or event.tokens != lease.max_input_tokens + lease.max_output_tokens
            or event.cost_microunits != lease.reserved_cost_microunits
            or (require_reserved and event.reserved != 1)
            or (require_reserved and event.slot_active != 1)
        ):
            raise RemoteProviderBudgetError("INVALID_STATE")
        pricing = None
        if require_pricing:
            pricing = self._require_pricing_pin(
                cursor,
                tenant_id=lease.tenant_id,
                model_id=lease.model_id,
                run_id=lease.run_id,
            )
        return event, policy, pricing

    def _ensure_pricing_pin(
        self,
        cursor: sqlite3.Cursor,
        *,
        tenant_id: str,
        model_id: str,
        run_id: str,
        policy: RemoteProviderSpendPolicy,
    ) -> None:
        row = cursor.execute(
            f"SELECT tenant_id,model_id,run_id,pricing_version,input_rate,output_rate,pricing_pin "
            f"FROM {_PRICING_TABLE} "
            "WHERE tenant_id=? AND model_id=? AND run_id=?",
            (tenant_id, model_id, run_id),
        ).fetchone()
        if row is not None:
            stored = self._pricing_record(row)
            expected = _PricingRecord(
                tenant_id=policy.tenant_id,
                model_id=policy.model_id,
                run_id=run_id,
                pricing_version=policy.pricing_version,
                input_rate=policy.input_cost_microunits_per_million_tokens,
                output_rate=policy.output_cost_microunits_per_million_tokens,
                pricing_pin=policy.pricing_pin,
            )
            if stored != expected:
                raise RemoteProviderBudgetError("INVALID_STATE")
            return
        legacy_event = cursor.execute(
            f"SELECT 1 FROM {_TABLE} AS events LEFT JOIN {_PRICING_TABLE} AS pricing "
            "ON pricing.tenant_id=events.tenant_id "
            "AND pricing.model_id=events.model_id AND pricing.run_id=events.run_id "
            "WHERE events.tenant_id=? AND events.model_id=? AND events.run_id=? "
            "AND pricing.run_id IS NULL LIMIT 1",
            (tenant_id, model_id, run_id),
        ).fetchone()
        if legacy_event is not None:
            raise RemoteProviderBudgetError("INVALID_STATE")
        total = cursor.execute(f"SELECT COUNT(*) FROM {_PRICING_TABLE}").fetchone()
        if not _is_row(total) or len(total) != 1 or type(total[0]) is not int:
            raise RemoteProviderBudgetError("INVALID_STATE")
        if total[0] >= _MAX_TOTAL_EVENTS:
            raise RemoteProviderBudgetError("LIMIT_EXCEEDED")
        cursor.execute(
            f"INSERT INTO {_PRICING_TABLE} "
            "(tenant_id,model_id,run_id,pricing_version,input_rate,output_rate,pricing_pin) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                tenant_id,
                model_id,
                run_id,
                policy.pricing_version,
                policy.input_cost_microunits_per_million_tokens,
                policy.output_cost_microunits_per_million_tokens,
                policy.pricing_pin,
            ),
        )

    def _require_pricing_pin(
        self,
        cursor: sqlite3.Cursor,
        *,
        tenant_id: str,
        model_id: str,
        run_id: str,
    ) -> _PricingRecord:
        row = cursor.execute(
            f"SELECT tenant_id,model_id,run_id,pricing_version,input_rate,output_rate,pricing_pin "
            f"FROM {_PRICING_TABLE} "
            "WHERE tenant_id=? AND model_id=? AND run_id=?",
            (tenant_id, model_id, run_id),
        ).fetchone()
        if row is None:
            raise RemoteProviderBudgetError("INVALID_STATE")
        return self._pricing_record(row)

    @staticmethod
    def _pricing_record(row: object) -> _PricingRecord:
        if not _is_row(row) or len(row) != 7:
            raise RemoteProviderBudgetError("INVALID_STATE")
        values = tuple(row)
        tenant_id, model_id, run_id, version, input_rate, output_rate, pricing_pin = values
        if (
            type(tenant_id) is not str
            or not _IDENTIFIER.fullmatch(tenant_id)
            or type(model_id) is not str
            or not _MODEL_ID.fullmatch(model_id)
            or type(run_id) is not str
            or not _IDENTIFIER.fullmatch(run_id)
            or type(version) is not str
            or version != _PRICING_VERSION
            or type(input_rate) is not int
            or not 0 <= input_rate <= _MAX_RATE_MICROUNITS_PER_MILLION
            or type(output_rate) is not int
            or not 0 <= output_rate <= _MAX_RATE_MICROUNITS_PER_MILLION
            or input_rate + output_rate == 0
            or type(pricing_pin) is not str
            or not _PRICING_PIN.fullmatch(pricing_pin)
        ):
            raise RemoteProviderBudgetError("INVALID_STATE")
        try:
            expected = remote_provider_pricing_pin(
                tenant_id=tenant_id,
                model_id=model_id,
                input_cost_microunits_per_million_tokens=input_rate,
                output_cost_microunits_per_million_tokens=output_rate,
                pricing_version=version,
            )
        except RemoteProviderBudgetError:
            raise RemoteProviderBudgetError("INVALID_STATE") from None
        if expected != pricing_pin:
            raise RemoteProviderBudgetError("INVALID_STATE")
        return _PricingRecord(
            tenant_id=tenant_id,
            model_id=model_id,
            run_id=run_id,
            pricing_version=version,
            input_rate=input_rate,
            output_rate=output_rate,
            pricing_pin=pricing_pin,
        )

    def _validate_pricing_records(self, cursor: sqlite3.Cursor) -> None:
        rows = cursor.execute(
            f"SELECT tenant_id,model_id,run_id,pricing_version,input_rate,output_rate,pricing_pin "
            f"FROM {_PRICING_TABLE}"
        ).fetchall()
        if len(rows) > _MAX_TOTAL_EVENTS:
            raise RemoteProviderBudgetError("INVALID_STATE")
        for row in rows:
            self._pricing_record(row)

    def _purge_cursor(
        self,
        cursor: sqlite3.Cursor,
        *,
        now_ms: int,
        max_items: int,
    ) -> int:
        self._reconcile_expired_slots(cursor, now_ms=now_ms, max_items=max_items)
        removed = 0
        for (tenant_id, model_id), policy in self._policies.items():
            remaining = max_items - removed
            if remaining <= 0:
                break
            cutoff = now_ms - policy.window_ms
            rows = cursor.execute(
                f"""SELECT lease_id FROM {_TABLE}
                    WHERE tenant_id=? AND model_id=? AND timestamp_ms<=?
                      AND reserved=0 AND slot_active=0 AND replay_blocked=0
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
                    WHERE timestamp_ms<=? AND reserved=0 AND slot_active=0
                      AND replay_blocked=0
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
            with suppress(sqlite3.Error):
                cursor.execute("ROLLBACK")


def _stored_values(row: object) -> _StoredLease:
    if not _is_row(row) or len(row) != 9 or any(type(value) is not int for value in row):
        raise RemoteProviderBudgetError("INVALID_STATE")
    (
        timestamp_ms,
        input_tokens,
        output_tokens,
        tokens,
        cost,
        reserved,
        slot_active,
        slot_expires_at_ms,
        replay_blocked,
    ) = cast(tuple[int, int, int, int, int, int, int, int, int], tuple(row))
    if (
        timestamp_ms < 0
        or timestamp_ms > _MAX_SQLITE_INTEGER
        or input_tokens < 1
        or input_tokens > _MAX_TOKENS
        or output_tokens < 1
        or output_tokens > _MAX_TOKENS
        or tokens < 0
        or tokens > _MAX_TOKENS * 2
        or cost < 0
        or cost > _MAX_COST_MICROUNITS
        or reserved not in {0, 1}
        or (reserved == 1 and tokens != input_tokens + output_tokens)
        or slot_active not in {0, 1}
        or replay_blocked not in {0, 1}
        or (reserved == 1 and slot_active != 1)
        or (replay_blocked == 1 and (reserved == 1 or slot_active == 1))
        or (slot_active == 1 and slot_expires_at_ms <= timestamp_ms)
        or slot_expires_at_ms > timestamp_ms + _MAX_SLOT_TIMEOUT_MS
        or (slot_active == 0 and slot_expires_at_ms != 0)
    ):
        raise RemoteProviderBudgetError("INVALID_STATE")
    return _StoredLease(
        lease_id="stored",
        run_id="stored",
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
        slot_active=slot_active,
        slot_expires_at_ms=slot_expires_at_ms,
        replay_blocked=replay_blocked,
    )


def _stored_lease(row: object) -> _StoredLease:
    if not _is_row(row) or len(row) not in {12, 14, 15}:
        raise RemoteProviderBudgetError("INVALID_STATE")
    if any(type(row[index]) is not str or (index != 1 and not row[index]) for index in range(5)):
        raise RemoteProviderBudgetError("INVALID_STATE")
    if any(type(row[index]) is not int for index in range(5, len(row))):
        raise RemoteProviderBudgetError("INVALID_STATE")
    slot_active = 0 if len(row) == 12 else cast(int, row[12])
    slot_expires_at_ms = 0 if len(row) == 12 else cast(int, row[13])
    replay_blocked = 0 if len(row) < 15 else cast(int, row[14])
    event = _StoredLease(
        lease_id=cast(str, row[0]),
        run_id=cast(str, row[1]),
        tenant_id=cast(str, row[2]),
        model_id=cast(str, row[3]),
        request_id=cast(str, row[4]),
        attempt=cast(int, row[5]),
        timestamp_ms=cast(int, row[6]),
        max_input_tokens=cast(int, row[7]),
        max_output_tokens=cast(int, row[8]),
        tokens=cast(int, row[9]),
        cost_microunits=cast(int, row[10]),
        reserved=cast(int, row[11]),
        slot_active=slot_active,
        slot_expires_at_ms=slot_expires_at_ms,
        replay_blocked=replay_blocked,
    )
    if (
        not 1 <= event.attempt <= 10
        or event.timestamp_ms < 0
        or event.timestamp_ms > _MAX_SQLITE_INTEGER
        or event.max_input_tokens < 1
        or event.max_input_tokens > _MAX_TOKENS
        or event.max_output_tokens < 1
        or event.max_output_tokens > _MAX_TOKENS
        or event.tokens < 0
        or event.tokens > _MAX_TOKENS * 2
        or event.cost_microunits < 0
        or event.cost_microunits > _MAX_COST_MICROUNITS
        or event.reserved not in {0, 1}
        or (
            event.reserved == 1 and event.tokens != event.max_input_tokens + event.max_output_tokens
        )
        or event.slot_active not in {0, 1}
        or (len(row) != 12 and event.reserved == 1 and event.slot_active != 1)
        or event.replay_blocked not in {0, 1}
        or (event.replay_blocked == 1 and (event.reserved == 1 or event.slot_active == 1))
        or (event.slot_active == 1 and event.slot_expires_at_ms <= event.timestamp_ms)
        or event.slot_expires_at_ms > event.timestamp_ms + _MAX_SLOT_TIMEOUT_MS
        or (event.slot_active == 0 and event.slot_expires_at_ms != 0)
        or (event.run_id != "" and _IDENTIFIER.fullmatch(event.run_id) is None)
    ):
        raise RemoteProviderBudgetError("INVALID_STATE")
    if event.run_id:
        try:
            RemoteProviderSpendRequest(
                run_id=event.run_id,
                tenant_id=event.tenant_id,
                model_id=event.model_id,
                request_id=event.request_id,
                attempt=event.attempt,
                max_input_tokens=event.max_input_tokens,
                max_output_tokens=event.max_output_tokens,
            )
        except RemoteProviderBudgetError:
            raise RemoteProviderBudgetError("INVALID_STATE") from None
    return event


def _is_row(value: object) -> TypeGuard[tuple[object, ...] | sqlite3.Row]:
    return isinstance(value, (tuple, sqlite3.Row))


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _sqlite_object_exists(cursor: sqlite3.Cursor, name: str) -> bool:
    row = cursor.execute("SELECT 1 FROM sqlite_master WHERE name=? LIMIT 1", (name,)).fetchone()
    return row is not None


def _unique_index_signatures(cursor: sqlite3.Cursor, table: str) -> set[tuple[str, ...]]:
    signatures: set[tuple[str, ...]] = set()
    rows = cursor.execute(f"PRAGMA index_list({_quote_identifier(table)})").fetchall()
    for row in rows:
        if not _is_row(row) or len(row) < 3 or type(row[1]) is not str or type(row[2]) is not int:
            raise RemoteProviderBudgetError("INVALID_STATE")
        if row[2] != 1:
            continue
        index_name = row[1]
        info_rows = cursor.execute(f"PRAGMA index_info({_quote_identifier(index_name)})").fetchall()
        indexed: list[tuple[int, str]] = []
        for info in info_rows:
            if (
                not _is_row(info)
                or len(info) < 3
                or type(info[0]) is not int
                or type(info[2]) is not str
                or not info[2]
            ):
                raise RemoteProviderBudgetError("INVALID_STATE")
            indexed.append((info[0], info[2]))
        indexed.sort(key=lambda item: item[0])
        if any(sequence != index for index, (sequence, _) in enumerate(indexed)):
            raise RemoteProviderBudgetError("INVALID_STATE")
        signatures.add(tuple(name for _, name in indexed))
    return signatures


def _now_ms() -> int:
    value = time.time_ns() // 1_000_000
    if not 0 <= value <= _MAX_SQLITE_INTEGER:
        raise RemoteProviderBudgetError("INVALID_STATE")
    return value


def _cost_microunits(tokens: int, rate_per_million: int) -> int:
    if tokens == 0 or rate_per_million == 0:
        return 0
    return (tokens * rate_per_million + _MICRO - 1) // _MICRO


def _cost_receipt(
    lease: RemoteProviderSpendLease,
    cost_microunits: int,
    *,
    maximum_charged: bool,
) -> RemoteProviderCostReceipt:
    return RemoteProviderCostReceipt(
        run_id=lease.run_id,
        tenant_id=lease.tenant_id,
        model_id=lease.model_id,
        request_id=lease.request_id,
        attempt=lease.attempt,
        cost_microunits=cost_microunits,
        maximum_charged=maximum_charged,
    )


__all__ = ["SQLITE_REMOTE_PROVIDER_BUDGET_SCHEMA_STATEMENTS", "SqliteRemoteProviderBudget"]
