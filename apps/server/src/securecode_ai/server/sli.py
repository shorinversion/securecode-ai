"""Deterministic SLI windows where absence is never success."""

from __future__ import annotations

from dataclasses import dataclass

_OUTCOMES = frozenset({"success", "error", "cancelled", "superseded"})


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
        return None


__all__ = ["Sample", "SliWindow"]
