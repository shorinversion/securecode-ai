"""Bounded source-free operational measurements."""

from __future__ import annotations

from collections import Counter
from math import ceil
from threading import RLock

_OPERATIONS = frozenset({"run", "worker", "artifact", "approval", "export"})
_OUTCOMES = frozenset({"success", "error", "cancelled", "superseded"})
_MAX_ELAPSED_MS = 86_400_000
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


class OperationsTelemetry:
    """Keep low-cardinality counters without tenant or source payloads."""

    def __init__(self) -> None:
        self._counts: Counter[tuple[str, str]] = Counter()
        self._latency: Counter[str] = Counter()
        self._latency_histogram: dict[str, list[int]] = {}
        self._lock = RLock()

    def record(self, *, operation: str, outcome: str, elapsed_ms: int) -> None:
        if (
            operation not in _OPERATIONS
            or outcome not in _OUTCOMES
            or type(elapsed_ms) is not int
            or not 0 <= elapsed_ms <= _MAX_ELAPSED_MS
        ):
            return
        with self._lock:
            self._counts[operation, outcome] += 1
            self._latency[operation] += elapsed_ms
            buckets = self._latency_histogram.setdefault(operation, [0] * len(_LATENCY_BUCKETS_MS))
            for index, boundary in enumerate(_LATENCY_BUCKETS_MS):
                if elapsed_ms <= boundary:
                    buckets[index] += 1
                    break

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
        return {
            "counters": counters,
            "latency_ms": latency,
            "latency_percentiles_ms": quantiles,
        }

    def _sample_count(self, operation: str) -> int:
        return sum(self._latency_histogram[operation])


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
