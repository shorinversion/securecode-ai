"""Deterministic SLI windows where absence is never success."""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil

_OUTCOMES = frozenset({"success", "error", "cancelled", "superseded"})
_METRICS = frozenset(
    {
        "availability",
        "completion",
        "cancellation",
        "supersession",
        "error_rate",
        "queue_latency",
        "run_latency",
        "queue_p50",
        "queue_p95",
        "run_p50",
        "run_p95",
        "queue_latency_p50",
        "queue_latency_p95",
        "run_latency_p50",
        "run_latency_p95",
    }
)


@dataclass(frozen=True, slots=True)
class Sample:
    outcome: str
    queue_ms: int
    run_ms: int

    def __post_init__(self) -> None:
        if (
            self.outcome not in _OUTCOMES
            or type(self.queue_ms) is not int
            or self.queue_ms < 0
            or type(self.run_ms) is not int
            or self.run_ms < 0
        ):
            raise ValueError("SLI sample is invalid")


@dataclass(frozen=True, slots=True)
class SliWindow:
    samples: tuple[Sample, ...]

    def __post_init__(self) -> None:
        if type(self.samples) is not tuple or any(
            type(item) is not Sample for item in self.samples
        ):
            raise ValueError("SLI window is invalid")

    def value(self, name: str) -> float | None:
        if type(name) is not str or name not in _METRICS:
            raise ValueError("SLI metric is invalid")
        if not self.samples:
            return None
        count = len(self.samples)
        if name == "availability":
            return sum(item.outcome != "error" for item in self.samples) / count
        if name == "completion":
            return sum(item.outcome in _OUTCOMES for item in self.samples) / count
        if name == "cancellation":
            return sum(item.outcome == "cancelled" for item in self.samples) / count
        if name == "supersession":
            return sum(item.outcome == "superseded" for item in self.samples) / count
        if name == "error_rate":
            return sum(item.outcome == "error" for item in self.samples) / count
        if name == "queue_latency":
            return sum(item.queue_ms for item in self.samples) / count
        if name == "run_latency":
            return sum(item.run_ms for item in self.samples) / count
        if name in {"queue_p50", "queue_latency_p50"}:
            return _percentile(tuple(item.queue_ms for item in self.samples), 0.50)
        if name in {"queue_p95", "queue_latency_p95"}:
            return _percentile(tuple(item.queue_ms for item in self.samples), 0.95)
        if name in {"run_p50", "run_latency_p50"}:
            return _percentile(tuple(item.run_ms for item in self.samples), 0.50)
        if name in {"run_p95", "run_latency_p95"}:
            return _percentile(tuple(item.run_ms for item in self.samples), 0.95)
        return None


def _percentile(values: tuple[int, ...], fraction: float) -> float:
    """Return the conservative nearest-rank percentile of integer timings."""

    ordered = sorted(values)
    rank = max(1, ceil(fraction * len(ordered))) - 1
    return float(ordered[rank])


__all__ = ["Sample", "SliWindow"]
