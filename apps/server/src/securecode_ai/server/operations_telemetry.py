"""Bounded source-free operational measurements."""

from __future__ import annotations

import sqlite3
from collections import Counter
from collections.abc import Mapping
from math import ceil
from threading import RLock

from securecode_ai.core.operational_telemetry import OperationalObservation

_OPERATIONS = frozenset({"run", "worker", "artifact", "approval", "export"})
_OUTCOMES = frozenset(
    {"success", "error", "cancelled", "superseded", "pass", "fail", "indeterminate"}
)
_REQUEST_ACTION_OPERATIONS = {
    "worker_sessions.create": "worker",
    "worker_sessions.heartbeat": "worker",
    "worker_sessions.events.append": "worker",
    "worker_sessions.artifacts.commit": "artifact",
    "worker_sessions.complete": "worker",
    "worker_sessions.osv.query": "worker",
    "artifacts.authorize": "artifact",
    "artifacts.upload": "artifact",
    "backups.create": "artifact",
    "backups.read": "artifact",
    "backups.execute": "artifact",
    "backups.restore": "artifact",
    "backups.restore.resolve": "artifact",
    "secrets.grant": "artifact",
    "secrets.read": "artifact",
    "secrets.rotate": "artifact",
    "secrets.revoke": "artifact",
    "lifecycle.deletions.create": "artifact",
    "lifecycle.deletions.read": "artifact",
    "lifecycle.deletions.approve": "artifact",
    "lifecycle.deletions.legal_hold": "artifact",
    "lifecycle.deletions.execute": "artifact",
    "audit.export": "export",
    "runs.audit.read": "export",
    "approvals.create": "approval",
    "approvals.read": "approval",
    "approvals.decide": "approval",
    "waivers.create": "approval",
    "waivers.read": "approval",
    "waivers.revoke": "approval",
    "scm.runs.resolve": "run",
    "policies.read": "run",
}
_REQUEST_STATUS_OUTCOMES = {2: "success", 4: "error", 5: "error"}
_MAX_ACTION_LENGTH = 64
_MAX_ELAPSED_MS = 86_400_000
_RESOURCE_FIELDS = frozenset(
    {"tokens", "cost_microunits", "cpu_ms", "peak_memory_bytes", "wall_ms"}
)
_MAX_RESOURCE_VALUE = 9_223_372_036_854_775_807
_LATENCY_BUCKETS_MS = (
    1,
    5,
    10,
    25,
    50,
    100,
    250,
    500,
    1_000,
    5_000,
    30_000,
    120_000,
    600_000,
    3_600_000,
    _MAX_ELAPSED_MS,
)
_LATENCY_QUANTILES = (("p50", 0.50), ("p95", 0.95))

_DURABLE_TELEMETRY_SCHEMA = """CREATE TABLE IF NOT EXISTS operations_telemetry_buckets (
    operation TEXT NOT NULL,
    outcome TEXT NOT NULL,
    bucket_index INTEGER NOT NULL,
    count INTEGER NOT NULL,
    total_elapsed_ms INTEGER NOT NULL,
    resource_samples INTEGER NOT NULL,
    tokens_total INTEGER NOT NULL,
    cost_microunits_total INTEGER NOT NULL,
    cpu_ms_total INTEGER NOT NULL,
    peak_memory_bytes_max INTEGER NOT NULL,
    wall_ms_total INTEGER NOT NULL,
    PRIMARY KEY (operation, outcome, bucket_index)
)"""


class OperationsTelemetry:
    """Keep low-cardinality counters without tenant or source payloads."""

    def __init__(self, connection: sqlite3.Connection | None = None) -> None:
        if connection is not None and not isinstance(connection, sqlite3.Connection):
            raise TypeError("telemetry connection is invalid")
        self._counts: Counter[tuple[str, str]] = Counter()
        self._latency: Counter[str] = Counter()
        self._latency_histogram: dict[str, list[int]] = {}
        self._resource_totals: dict[tuple[str, str], Counter[str]] = {}
        self._resource_peak_memory: Counter[tuple[str, str]] = Counter()
        self._lock = RLock()
        self._connection = connection
        if connection is not None:
            self._install_durable_store(connection)
            self._load_durable_store(connection)

    def record(
        self,
        *,
        operation: str | None = None,
        outcome: str | None = None,
        elapsed_ms: int | None = None,
        action: str | None = None,
        status: int | None = None,
        duration_ms: int | None = None,
        resource_usage: Mapping[str, int] | None = None,
    ) -> None:
        request_shape = action is not None or status is not None or duration_ms is not None
        operation_shape = operation is not None or outcome is not None or elapsed_ms is not None
        if request_shape == operation_shape:
            return
        if request_shape:
            if (
                operation is not None
                or outcome is not None
                or elapsed_ms is not None
                or type(action) is not str
                or not 1 <= len(action) <= _MAX_ACTION_LENGTH
                or not action.isascii()
                or any(not (character.isalnum() or character in "._:-") for character in action)
                or type(status) is not int
                or not 100 <= status <= 599
                or type(duration_ms) is not int
            ):
                return
            operation = _REQUEST_ACTION_OPERATIONS.get(action, "run")
            outcome = _REQUEST_STATUS_OUTCOMES.get(status // 100, "error")
            elapsed_ms = duration_ms
        elif action is not None or status is not None or duration_ms is not None:
            return
        if (
            operation not in _OPERATIONS
            or outcome not in _OUTCOMES
            or type(elapsed_ms) is not int
            or not 0 <= elapsed_ms <= _MAX_ELAPSED_MS
        ):
            return
        safe_resource_usage: dict[str, int] | None = None
        if resource_usage is not None:
            try:
                candidate = dict(resource_usage)
            except Exception:
                candidate = {}
            if (
                set(candidate) == _RESOURCE_FIELDS
                and all(
                    type(key) is str
                    and type(value) is int
                    and 0 <= value <= _MAX_RESOURCE_VALUE
                    for key, value in candidate.items()
                )
            ):
                safe_resource_usage = candidate
        try:
            safe_observation = OperationalObservation(
                name="server.operation",
                attributes={"operation": operation, "outcome": outcome},
                duration_ms=elapsed_ms,
                resource_usage=safe_resource_usage,
            )
        except (TypeError, ValueError):
            return
        safe_resource_usage = (
            dict(safe_observation.resource_usage)
            if safe_observation.resource_usage is not None
            else None
        )
        with self._lock:
            bucket_index = _latency_bucket_index(elapsed_ms)
            self._persist(
                operation=operation,
                outcome=outcome,
                bucket_index=bucket_index,
                elapsed_ms=elapsed_ms,
                resource_usage=safe_resource_usage,
            )
            self._counts[operation, outcome] += 1
            self._latency[operation] += elapsed_ms
            buckets = self._latency_histogram.setdefault(
                operation, [0] * len(_LATENCY_BUCKETS_MS)
            )
            buckets[bucket_index] += 1
            if safe_resource_usage is not None:
                key = (operation, outcome)
                totals = self._resource_totals.setdefault(key, Counter())
                totals["samples"] += 1
                for name in ("tokens", "cost_microunits", "cpu_ms", "wall_ms"):
                    totals[name] += safe_resource_usage[name]
                self._resource_peak_memory[key] = max(
                    self._resource_peak_memory[key], safe_resource_usage["peak_memory_bytes"]
                )

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            counters = tuple(
                {
                    "operation": operation,
                    "outcome": outcome,
                    "count": count,
                }
                for (operation, outcome), count in sorted(self._counts.items())
            )
            latency = tuple(
                {"operation": operation, "total": total, "count": self._sample_count(operation)}
                for operation, total in sorted(self._latency.items())
            )
            quantiles = tuple(
                {
                    "operation": operation,
                    **{
                        name: _histogram_quantile(buckets, quantile)
                        for name, quantile in _LATENCY_QUANTILES
                    },
                }
                for operation, buckets in sorted(self._latency_histogram.items())
            )
            resource_usage = tuple(
                {
                    "operation": operation,
                    "outcome": outcome,
                    "samples": totals["samples"],
                    "tokens_total": totals["tokens"],
                    "cost_microunits_total": totals["cost_microunits"],
                    "cpu_ms_total": totals["cpu_ms"],
                    "peak_memory_bytes_max": self._resource_peak_memory[(operation, outcome)],
                    "wall_ms_total": totals["wall_ms"],
                }
                for (operation, outcome), totals in sorted(self._resource_totals.items())
            )
        result: dict[str, object] = {
            "counters": counters,
            "latency_ms": latency,
            "latency_percentiles_ms": quantiles,
        }
        # Keep the established source-free snapshot shape when no worker
        # supplied measured usage.  The resource projection is additive and
        # appears only once it contains a sample.
        if resource_usage:
            result["resource_usage"] = resource_usage
        return result

    def _sample_count(self, operation: str) -> int:
        return sum(self._latency_histogram[operation])

    @staticmethod
    def _install_durable_store(connection: sqlite3.Connection) -> None:
        savepoint = "securecode_operations_telemetry_schema"
        outer_transaction = connection.in_transaction
        try:
            connection.execute(f"SAVEPOINT {savepoint}")
            connection.execute(_DURABLE_TELEMETRY_SCHEMA)
            connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            if not outer_transaction:
                connection.commit()
        except sqlite3.Error as failure:
            try:
                connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            except sqlite3.Error:
                pass
            if not outer_transaction:
                connection.rollback()
            raise

    def _load_durable_store(self, connection: sqlite3.Connection) -> None:
        try:
            rows = connection.execute(
                """SELECT operation, outcome, bucket_index, count,
                          total_elapsed_ms, resource_samples, tokens_total,
                          cost_microunits_total, cpu_ms_total,
                          peak_memory_bytes_max, wall_ms_total
                   FROM operations_telemetry_buckets
                   ORDER BY operation, outcome, bucket_index"""
            ).fetchall()
        except sqlite3.Error as failure:
            raise RuntimeError("durable telemetry store is unavailable") from None
        for row in rows:
            if not _valid_durable_row(row):
                raise RuntimeError("durable telemetry store is invalid")
            operation = row[0]
            outcome = row[1]
            bucket_index = row[2]
            count = row[3]
            self._counts[operation, outcome] += count
            self._latency[operation] += row[4]
            buckets = self._latency_histogram.setdefault(
                operation, [0] * len(_LATENCY_BUCKETS_MS)
            )
            buckets[bucket_index] += count
            samples = row[5]
            if samples:
                totals = self._resource_totals.setdefault((operation, outcome), Counter())
                totals["samples"] += samples
                totals["tokens"] += row[6]
                totals["cost_microunits"] += row[7]
                totals["cpu_ms"] += row[8]
                totals["wall_ms"] += row[10]
                self._resource_peak_memory[operation, outcome] = max(
                    self._resource_peak_memory[operation, outcome], row[9]
                )

    def _persist(
        self,
        *,
        operation: str,
        outcome: str,
        bucket_index: int,
        elapsed_ms: int,
        resource_usage: Mapping[str, int] | None,
    ) -> None:
        connection = self._connection
        if connection is None:
            return
        usage = resource_usage or {}
        savepoint = "securecode_operations_telemetry"
        outer_transaction = connection.in_transaction
        try:
            # The telemetry connection is shared with request handlers.  A
            # connection-wide commit/rollback here could commit or erase an
            # unrelated domain transaction.  A savepoint confines this
            # best-effort write to its own unit of work.  When no outer
            # transaction is active, commit the savepoint's transaction so a
            # read-only request's measurement survives a process restart.
            connection.execute(f"SAVEPOINT {savepoint}")
            connection.execute(
                """INSERT INTO operations_telemetry_buckets (
                       operation, outcome, bucket_index, count,
                       total_elapsed_ms, resource_samples, tokens_total,
                       cost_microunits_total, cpu_ms_total,
                       peak_memory_bytes_max, wall_ms_total
                   ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(operation, outcome, bucket_index) DO UPDATE SET
                       count=count + 1,
                       total_elapsed_ms=total_elapsed_ms + excluded.total_elapsed_ms,
                       resource_samples=resource_samples + excluded.resource_samples,
                       tokens_total=tokens_total + excluded.tokens_total,
                       cost_microunits_total=cost_microunits_total
                           + excluded.cost_microunits_total,
                       cpu_ms_total=cpu_ms_total + excluded.cpu_ms_total,
                       peak_memory_bytes_max=MAX(
                           peak_memory_bytes_max, excluded.peak_memory_bytes_max
                       ),
                       wall_ms_total=wall_ms_total + excluded.wall_ms_total""",
                (
                    operation,
                    outcome,
                    bucket_index,
                    elapsed_ms,
                    1 if resource_usage is not None else 0,
                    usage.get("tokens", 0),
                    usage.get("cost_microunits", 0),
                    usage.get("cpu_ms", 0),
                    usage.get("peak_memory_bytes", 0),
                    usage.get("wall_ms", 0),
                ),
            )
            connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            if not outer_transaction:
                connection.commit()
        except sqlite3.Error as failure:
            try:
                connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            except sqlite3.Error:
                pass
            if not outer_transaction:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
            raise RuntimeError("durable telemetry write failed") from failure


def _latency_bucket_index(elapsed_ms: int) -> int:
    for index, boundary in enumerate(_LATENCY_BUCKETS_MS):
        if elapsed_ms <= boundary:
            return index
    return len(_LATENCY_BUCKETS_MS) - 1


def _valid_durable_row(row: sqlite3.Row | tuple[object, ...]) -> bool:
    if len(row) != 11:
        return False
    operation, outcome, bucket_index, count, total, samples, *usage = row
    return (
        type(operation) is str
        and operation in _OPERATIONS
        and type(outcome) is str
        and outcome in _OUTCOMES
        and type(bucket_index) is int
        and 0 <= bucket_index < len(_LATENCY_BUCKETS_MS)
        and type(count) is int
        and count > 0
        and type(total) is int
        and total >= 0
        and type(samples) is int
        and 0 <= samples <= count
        and all(type(value) is int and value >= 0 for value in usage)
    )


def _histogram_quantile(buckets: list[int], quantile: float) -> int:
    count = sum(buckets)
    if count == 0:
        return 0
    rank = max(1, ceil(count * quantile))
    cumulative = 0
    for boundary, bucket_count in zip(_LATENCY_BUCKETS_MS, buckets, strict=True):
        cumulative += bucket_count
        if cumulative >= rank:
            return boundary
    return _MAX_ELAPSED_MS


__all__ = ["OperationsTelemetry"]
