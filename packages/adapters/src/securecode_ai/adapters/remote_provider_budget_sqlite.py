"""Durable SQLite spend accounting for approved remote model calls."""

from __future__ import annotations

import re
import sqlite3
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from secrets import token_hex
from threading import RLock
from typing import Final

from .remote_provider_budget import (
    RemoteProviderBudgetError,
    RemoteProviderBudgetPort,
    RemoteProviderCostReceipt,
    RemoteProviderSpendLease,
    RemoteProviderSpendPolicy,
    RemoteProviderSpendRequest,
    RemoteProviderSpendUsage,
    remote_provider_pricing_pin,
)

_TABLE: Final = "securecode_remote_provider_spend"
_PRICING_TABLE: Final = "securecode_remote_provider_pricing"
_PRICING_PIN: Final = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MODEL_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_MAX_RECORDS: Final = 65_536
_MAX_TOTAL_EVENTS: Final = 100_000
_MAX_SQLITE_INTEGER: Final = (1 << 63) - 1
_MAX_TOKENS: Final = 1_000_000_000
_MAX_OBSERVED_COST_MICROUNITS: Final = 2_000_000_000_000_000
_MAX_RATE_MICROUNITS_PER_MILLION: Final = 1_000_000_000_000
_MAX_SLOT_TIMEOUT_MS: Final = 86_400_000
_DEFAULT_SLOT_TIMEOUT_MS: Final = 300_000
_PRICING_VERSION: Final = "v1"
_MICRO: Final = 1_000_000


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
    """Atomic, restart-safe implementation of ``RemoteProviderBudgetPort``.

    Policies are immutable for the lifetime of one worker process. Spend
    events remain in SQLite, so a restarted worker cannot reset a tenant's
    rolling window or replay an admitted request. A run-scoped pricing pin
    remains after event expiry and rejects rate-card drift.
    """

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
            or len(policies) > 256
            or any(type(policy) is not RemoteProviderSpendPolicy for policy in policies)
        ):
            raise RemoteProviderBudgetError("INVALID_STATE")
        configured = {(item.tenant_id, item.model_id): item for item in policies}
        if len(configured) != len(policies):
            raise RemoteProviderBudgetError("INVALID_STATE")
        self._connection = connection
        self._lock = RLock()
        self._policies = configured
        self._initialize()

    @classmethod
    def open(
        cls,
        path: str | Path,
        policy: RemoteProviderSpendPolicy,
    ) -> SqliteRemoteProviderBudget:
        if type(policy) is not RemoteProviderSpendPolicy:
            raise RemoteProviderBudgetError("INVALID_STATE")
        candidate = Path(path)
        connection: sqlite3.Connection | None = None
        try:
            if not candidate.is_absolute() or candidate.is_symlink():
                raise ValueError
            parent = candidate.parent
            if not parent.is_dir() or parent.is_symlink():
                raise ValueError
            connection = sqlite3.connect(
                str(candidate), timeout=5.0, check_same_thread=False, isolation_level=None
            )
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA foreign_keys=ON")
            return cls(connection, (policy,))
        except RemoteProviderBudgetError:
            if connection is not None:
                with suppress(sqlite3.Error):
                    connection.close()
            raise
        except Exception:
            if connection is not None:
                with suppress(sqlite3.Error):
                    connection.close()
            raise RemoteProviderBudgetError("INVALID_STATE") from None

    def reserve(self, request: RemoteProviderSpendRequest) -> RemoteProviderSpendLease:
        if type(request) is not RemoteProviderSpendRequest:
            raise RemoteProviderBudgetError("INVALID_STATE")
        policy = self._policies.get((request.tenant_id, request.model_id))
        if policy is None:
            raise RemoteProviderBudgetError("NOT_CONFIGURED")
        now_ms = _now_ms()
        reserved_tokens = request.max_input_tokens + request.max_output_tokens
        reserved_cost = _cost(
            request.max_input_tokens, policy.input_cost_microunits_per_million_tokens
        ) + _cost(request.max_output_tokens, policy.output_cost_microunits_per_million_tokens)
        request_key = (
            request.tenant_id,
            request.model_id,
            request.request_id,
            request.attempt,
        )
        lease_id = token_hex(24)
        denied = False
        with self._transaction() as cursor:
            # Prune every configured scope while holding the same immediate
            # write transaction used by admission. Otherwise idle model scopes
            # can fill the global bounded event table and block unrelated
            # tenants forever.
            for configured_policy in self._policies.values():
                self._purge(cursor, configured_policy, now_ms)
            self._ensure_pricing_pin(
                cursor,
                tenant_id=request.tenant_id,
                model_id=request.model_id,
                run_id=request.run_id,
                policy=policy,
            )
            row = cursor.execute(
                f"SELECT 1 FROM {_TABLE} WHERE tenant_id=? AND model_id=? "
                "AND request_id=? AND attempt=? LIMIT 1",
                request_key,
            ).fetchone()
            if row is not None:
                raise RemoteProviderBudgetError("INVALID_STATE")
            self._reconcile_expired_slots(cursor, now_ms=now_ms, max_items=256)
            total = cursor.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()
            if total is None or type(total[0]) is not int:
                raise RemoteProviderBudgetError("INVALID_STATE")
            active_total = cursor.execute(
                f"SELECT COUNT(*) FROM {_TABLE} WHERE slot_active=1"
            ).fetchone()
            if active_total is None or type(active_total[0]) is not int:
                raise RemoteProviderBudgetError("INVALID_STATE")
            if active_total[0] >= _MAX_RECORDS or total[0] >= _MAX_TOTAL_EVENTS:
                denied = True
            else:
                cutoff = now_ms - policy.window_ms
                records = cursor.execute(
                    f"SELECT tokens,cost_microunits,reserved,slot_active,"
                    f"slot_expires_at_ms,replay_blocked,timestamp_ms FROM {_TABLE} "
                    "WHERE tenant_id=? AND model_id=? AND "
                    "(timestamp_ms>? OR reserved=1 OR slot_active=1)",
                    (request.tenant_id, request.model_id, cutoff),
                ).fetchall()
                calls = tokens = cost = active = 0
                for (
                    stored_tokens,
                    stored_cost,
                    reserved,
                    slot_active,
                    slot_expires_at_ms,
                    replay_blocked,
                    timestamp,
                ) in records:
                    if any(
                        type(value) is not int
                        for value in (
                            stored_tokens,
                            stored_cost,
                            reserved,
                            slot_active,
                            slot_expires_at_ms,
                            replay_blocked,
                            timestamp,
                        )
                    ):
                        raise RemoteProviderBudgetError("INVALID_STATE")
                    if (
                        reserved not in {0, 1}
                        or slot_active not in {0, 1}
                        or replay_blocked not in {0, 1}
                        or (reserved == 1 and slot_active != 1)
                        or (replay_blocked == 1 and (reserved == 1 or slot_active == 1))
                        or (slot_active == 1 and slot_expires_at_ms <= now_ms)
                        or slot_expires_at_ms > timestamp + _MAX_SLOT_TIMEOUT_MS
                        or (slot_active == 0 and slot_expires_at_ms != 0)
                        or slot_expires_at_ms < 0
                        or timestamp < 0
                        or timestamp > now_ms
                        or stored_tokens < 0
                        or stored_tokens > _MAX_TOKENS * 2
                        or stored_cost < 0
                        or stored_cost > _MAX_OBSERVED_COST_MICROUNITS
                    ):
                        raise RemoteProviderBudgetError("INVALID_STATE")
                    if timestamp > cutoff:
                        calls += 1
                    if timestamp > cutoff or reserved:
                        tokens += stored_tokens
                        cost += stored_cost
                    active += slot_active
                denied = (
                    active >= policy.max_concurrent_calls
                    or calls >= policy.max_calls_per_window
                    or tokens + reserved_tokens > policy.max_tokens_per_window
                    or cost + reserved_cost > policy.max_cost_microunits_per_window
                )
                if not denied:
                    cursor.execute(
                        f"INSERT INTO {_TABLE} (lease_id,tenant_id,model_id,run_id,request_id,attempt,"
                        "timestamp_ms,max_input_tokens,max_output_tokens,tokens,cost_microunits,"
                        "reserved,slot_active,slot_expires_at_ms,replay_blocked) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            lease_id,
                            request.tenant_id,
                            request.model_id,
                            request.run_id,
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
        if denied:
            # Raising inside `_transaction` would roll back the purge above.
            # Commit maintenance and admission failure together so a full event
            # table drains in bounded batches instead of locking out all future
            # provider traffic permanently.
            raise RemoteProviderBudgetError("LIMIT_EXCEEDED")
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
        with self._transaction() as cursor:
            row, _, pricing = self._lease(cursor, lease)
            if pricing is None:
                raise RemoteProviderBudgetError("INVALID_STATE")
            actual_cost = _cost(usage.input_tokens, pricing.input_rate) + _cost(
                usage.output_tokens, pricing.output_rate
            )
            cursor.execute(
                f"UPDATE {_TABLE} SET timestamp_ms=?,tokens=?,cost_microunits=?,reserved=0,"
                "slot_active=0,slot_expires_at_ms=0,replay_blocked=0 "
                "WHERE lease_id=? AND reserved=1 AND slot_active=1",
                (_now_ms(), usage.input_tokens + usage.output_tokens, actual_cost, row[0]),
            )
            if cursor.rowcount != 1:
                raise RemoteProviderBudgetError("INVALID_STATE")
            over = (
                usage.input_tokens > lease.max_input_tokens
                or usage.output_tokens > lease.max_output_tokens
                or actual_cost > lease.reserved_cost_microunits
            )
        receipt = _receipt(lease, actual_cost, maximum_charged=False)
        if over:
            raise RemoteProviderBudgetError("LIMIT_EXCEEDED", cost_receipt=receipt)
        return receipt

    def charge_maximum(self, lease: RemoteProviderSpendLease) -> RemoteProviderCostReceipt:
        with self._transaction() as cursor:
            row, _, _ = self._lease(cursor, lease, require_reserved=False)
            if row[10] == 1 or row[12] == 1:
                timestamp_ms = row[11]
                if type(timestamp_ms) is not int:  # already validated by _lease
                    raise RemoteProviderBudgetError("INVALID_STATE")
                cursor.execute(
                    f"UPDATE {_TABLE} SET timestamp_ms=?,reserved=0,slot_active=0,"
                    "slot_expires_at_ms=0,replay_blocked=1 "
                    "WHERE lease_id=? AND (reserved=1 OR slot_active=1)",
                    (max(timestamp_ms, _now_ms()), row[0]),
                )
                if cursor.rowcount != 1:
                    raise RemoteProviderBudgetError("INVALID_STATE")
            elif (
                row[8] != lease.max_input_tokens + lease.max_output_tokens
                or row[9] != lease.reserved_cost_microunits
            ):
                raise RemoteProviderBudgetError("INVALID_STATE")
        return _receipt(lease, lease.reserved_cost_microunits, maximum_charged=True)

    def release(self, lease: RemoteProviderSpendLease) -> None:
        with self._transaction() as cursor:
            row, _, _ = self._lease(cursor, lease, require_pricing=False)
            cursor.execute(
                f"DELETE FROM {_TABLE} WHERE lease_id=? AND reserved=1 AND slot_active=1",
                (row[0],),
            )
            if cursor.rowcount != 1:
                raise RemoteProviderBudgetError("INVALID_STATE")

    def close(self) -> None:
        with self._lock:
            try:
                self._connection.close()
            except sqlite3.Error:
                raise RemoteProviderBudgetError("INVALID_STATE") from None

    @staticmethod
    def _reconcile_expired_slots(cursor: sqlite3.Cursor, *, now_ms: int, max_items: int) -> int:
        rows = cursor.execute(
            f"SELECT lease_id FROM {_TABLE} WHERE slot_active=1 "
            "AND slot_expires_at_ms<=? ORDER BY slot_expires_at_ms,lease_id LIMIT ?",
            (now_ms, max_items),
        ).fetchall()
        for row in rows:
            if not isinstance(row, tuple) or len(row) != 1 or type(row[0]) is not str:
                raise RemoteProviderBudgetError("INVALID_STATE")
            cursor.execute(
                f"UPDATE {_TABLE} SET timestamp_ms=?,reserved=0,slot_active=0,"
                "slot_expires_at_ms=0,replay_blocked=1 "
                "WHERE lease_id=? AND slot_active=1",
                (now_ms, row[0]),
            )
            if cursor.rowcount != 1:
                raise RemoteProviderBudgetError("INVALID_STATE")
        return len(rows)

    def _initialize(self) -> None:
        with self._transaction() as cursor:
            cursor.execute(
                f"CREATE TABLE IF NOT EXISTS {_TABLE} ("
                "lease_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, model_id TEXT NOT NULL,"
                "run_id TEXT NOT NULL, request_id TEXT NOT NULL, attempt INTEGER NOT NULL,"
                "timestamp_ms INTEGER NOT NULL, max_input_tokens INTEGER NOT NULL,"
                "max_output_tokens INTEGER NOT NULL, tokens INTEGER NOT NULL,"
                "cost_microunits INTEGER NOT NULL, reserved INTEGER NOT NULL,"
                "slot_active INTEGER NOT NULL CHECK (slot_active IN (0, 1)),"
                "slot_expires_at_ms INTEGER NOT NULL CHECK (slot_expires_at_ms >= 0),"
                "replay_blocked INTEGER NOT NULL CHECK (replay_blocked IN (0, 1)))"
            )
            columns = tuple(row[1] for row in cursor.execute(f"PRAGMA table_info({_TABLE})"))
            legacy = (
                "lease_id",
                "tenant_id",
                "model_id",
                "run_id",
                "request_id",
                "attempt",
                "timestamp_ms",
                "max_input_tokens",
                "max_output_tokens",
                "tokens",
                "cost_microunits",
                "reserved",
            )
            prior_expected = (*legacy, "slot_active", "slot_expires_at_ms")
            expected = (*prior_expected, "replay_blocked")
            if columns == legacy:
                cursor.execute(
                    f"ALTER TABLE {_TABLE} ADD COLUMN slot_active INTEGER NOT NULL DEFAULT 0"
                )
                cursor.execute(
                    f"ALTER TABLE {_TABLE} ADD COLUMN slot_expires_at_ms INTEGER NOT NULL DEFAULT 0"
                )
                cursor.execute(
                    f"ALTER TABLE {_TABLE} ADD COLUMN replay_blocked INTEGER NOT NULL DEFAULT 0"
                )
                columns = expected
            elif columns == prior_expected:
                cursor.execute(
                    f"ALTER TABLE {_TABLE} ADD COLUMN replay_blocked INTEGER NOT NULL DEFAULT 0"
                )
                columns = expected
            if columns != expected:
                raise RemoteProviderBudgetError("INVALID_STATE")
            cursor.execute(
                f"UPDATE {_TABLE} SET reserved=0,slot_active=0,slot_expires_at_ms=0,"
                "replay_blocked=1 WHERE (reserved=1 AND slot_active=0) "
                "OR (run_id='' AND (reserved=1 OR slot_active=1))"
            )
            duplicate = cursor.execute(
                f"SELECT 1 FROM {_TABLE} GROUP BY tenant_id,model_id,request_id,attempt "
                "HAVING COUNT(*)>1 LIMIT 1"
            ).fetchone()
            if duplicate is not None:
                raise RemoteProviderBudgetError("INVALID_STATE")
            cursor.execute(f"DROP INDEX IF EXISTS {_TABLE}_request")
            cursor.execute(
                f"CREATE UNIQUE INDEX IF NOT EXISTS {_TABLE}_request ON {_TABLE} "
                "(tenant_id,model_id,request_id,attempt)"
            )
            cursor.execute(
                f"CREATE INDEX IF NOT EXISTS {_TABLE}_scope ON {_TABLE} "
                "(tenant_id,model_id,timestamp_ms)"
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
                f"CREATE TABLE {_PRICING_TABLE} ("
                "tenant_id TEXT NOT NULL, model_id TEXT NOT NULL, run_id TEXT NOT NULL,"
                "pricing_version TEXT NOT NULL, input_rate INTEGER NOT NULL,"
                "output_rate INTEGER NOT NULL, pricing_pin TEXT NOT NULL,"
                "PRIMARY KEY (tenant_id,model_id,run_id))"
            )

    def _lease(
        self,
        cursor: sqlite3.Cursor,
        lease: RemoteProviderSpendLease,
        *,
        require_pricing: bool = True,
        require_reserved: bool = True,
    ) -> tuple[tuple[object, ...], RemoteProviderSpendPolicy, _PricingRecord | None]:
        if type(lease) is not RemoteProviderSpendLease:
            raise RemoteProviderBudgetError("INVALID_STATE")
        policy = self._policies.get((lease.tenant_id, lease.model_id))
        row = cursor.execute(
            f"SELECT lease_id,run_id,tenant_id,model_id,request_id,attempt,"
            "max_input_tokens,max_output_tokens,tokens,cost_microunits,reserved,timestamp_ms,"
            "slot_active,slot_expires_at_ms,replay_blocked "
            f"FROM {_TABLE} WHERE lease_id=?",
            (lease.lease_id,),
        ).fetchone()
        if policy is None or row is None or len(row) != 15:
            raise RemoteProviderBudgetError("INVALID_STATE")
        if (
            tuple(row[:6])
            != (
                lease.lease_id,
                lease.run_id,
                lease.tenant_id,
                lease.model_id,
                lease.request_id,
                lease.attempt,
            )
            or tuple(row[6:8]) != (lease.max_input_tokens, lease.max_output_tokens)
            or row[8] != lease.max_input_tokens + lease.max_output_tokens
            or row[9] != lease.reserved_cost_microunits
            or (require_reserved and row[10] != 1)
            or (require_reserved and row[12] != 1)
            or type(row[12]) is not int
            or row[12] not in {0, 1}
            or type(row[13]) is not int
            or row[13] < 0
            or (row[12] == 1 and row[13] <= row[11])
            or row[13] > row[11] + _MAX_SLOT_TIMEOUT_MS
            or (row[12] == 0 and row[13] != 0)
            or type(row[14]) is not int
            or row[14] not in {0, 1}
            or (row[14] == 1 and (row[10] == 1 or row[12] == 1))
            or type(row[11]) is not int
            or row[11] < 0
            or row[11] > _now_ms()
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
        return tuple(row), policy, pricing

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
            f"FROM {_PRICING_TABLE} WHERE tenant_id=? AND model_id=? AND run_id=?",
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
        if total is None or type(total[0]) is not int:
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
            f"FROM {_PRICING_TABLE} WHERE tenant_id=? AND model_id=? AND run_id=?",
            (tenant_id, model_id, run_id),
        ).fetchone()
        if row is None:
            raise RemoteProviderBudgetError("INVALID_STATE")
        return self._pricing_record(row)

    @staticmethod
    def _pricing_record(row: object) -> _PricingRecord:
        if not isinstance(row, (tuple, sqlite3.Row)) or len(row) != 7:
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

    @staticmethod
    def _purge(cursor: sqlite3.Cursor, policy: RemoteProviderSpendPolicy, now_ms: int) -> None:
        cursor.execute(
            f"DELETE FROM {_TABLE} WHERE tenant_id=? AND model_id=? AND reserved=0 "
            "AND slot_active=0 AND replay_blocked=0 AND timestamp_ms<=?",
            (policy.tenant_id, policy.model_id, now_ms - policy.window_ms),
        )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cursor = self._connection.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                yield cursor
                cursor.execute("COMMIT")
            except RemoteProviderBudgetError:
                self._rollback(cursor)
                raise
            except sqlite3.IntegrityError:
                self._rollback(cursor)
                raise RemoteProviderBudgetError("INVALID_STATE") from None
            except Exception:
                self._rollback(cursor)
                raise RemoteProviderBudgetError("INVALID_STATE") from None
            finally:
                cursor.close()

    def _rollback(self, cursor: sqlite3.Cursor) -> None:
        with suppress(sqlite3.Error):
            cursor.execute("ROLLBACK")


def build_sqlite_remote_provider_budget(
    environment: Mapping[str, str], *, policy: RemoteProviderSpendPolicy
) -> SqliteRemoteProviderBudget | None:
    """Build durable accounting only from a complete, explicitly pinned path."""

    raw_path = environment.get("SECURECODE_REMOTE_SPEND_DB")
    if not isinstance(raw_path, str) or not raw_path or len(raw_path) > 1024:
        return None
    try:
        return SqliteRemoteProviderBudget.open(raw_path, policy)
    except RemoteProviderBudgetError:
        return None


def _now_ms() -> int:
    value = time.time_ns() // 1_000_000
    if not 0 <= value <= _MAX_SQLITE_INTEGER:
        raise RemoteProviderBudgetError("INVALID_STATE")
    return value


def _cost(tokens: int, rate: int) -> int:
    if tokens == 0 or rate == 0:
        return 0
    return (tokens * rate + _MICRO - 1) // _MICRO


def _receipt(
    lease: RemoteProviderSpendLease, cost_microunits: int, *, maximum_charged: bool
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


__all__ = ["SqliteRemoteProviderBudget", "build_sqlite_remote_provider_budget"]
