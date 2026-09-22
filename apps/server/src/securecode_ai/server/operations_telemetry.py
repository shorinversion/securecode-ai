"""Bounded source-free operational measurements."""

from __future__ import annotations

from collections import Counter
from threading import RLock

_OPERATIONS = frozenset({"run", "worker", "artifact", "approval", "export"})
_OUTCOMES = frozenset({"success", "error", "cancelled", "superseded"})
_MAX_ELAPSED_MS = 86_400_000


class OperationsTelemetry:
    """Keep low-cardinality counters without tenant or source payloads."""

    def __init__(self) -> None:
        self._counts: Counter[tuple[str, str]] = Counter()
        self._latency: Counter[str] = Counter()
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
                {"operation": operation, "total": total}
                for operation, total in sorted(self._latency.items())
            )
        return {"counters": counters, "latency_ms": latency}


__all__ = ["OperationsTelemetry"]
