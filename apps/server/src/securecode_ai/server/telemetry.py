"""P8.8 bounded request telemetry, wired into the control-plane request path.

Observations are redacted before they leave the process: only the route action,
the response status and the measured duration are recorded — never bodies,
identifiers or credentials. The buffer is bounded, so an absent or failing
exporter degrades to a drop rather than unbounded memory growth.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from threading import Lock
from typing import Final

from .observability import Exporter, Observation, RedactedExporter
from .operations_telemetry import OperationsTelemetry

DEFAULT_CAPACITY: Final = 512
# the counter store keeps low-cardinality buckets, so route actions collapse
# onto its declared operation vocabulary and status classes onto outcomes
_COUNTER_OPERATION: Final = {
    "worker_sessions.create": "worker",
    "worker_sessions.heartbeat": "worker",
    "worker_sessions.events.append": "worker",
    "worker_sessions.artifacts.commit": "artifact",
    "worker_sessions.complete": "worker",
    "artifacts.authorize": "artifact",
    "artifacts.upload": "artifact",
    "audit.export": "export",
}
_COUNTER_OUTCOME: Final = {2: "success", 4: "error", 5: "error"}
MAX_ACTION_LENGTH: Final = 64
MIN_DURATION_MS: Final = 0
MAX_DURATION_MS: Final = 3_600_000


class TelemetryError(ValueError):
    """Bounded telemetry configuration or record failure."""


@dataclass(frozen=True, slots=True)
class TelemetryFlush:
    """Outcome of one flush attempt."""

    accepted: bool
    exported: int
    pending: int
    dropped: int = 0


class TelemetryRecorder:
    """Buffer bounded observations and export them through a redacting seam."""

    __slots__ = ("_buffer", "_capacity", "_counters", "_dropped", "_exporter", "_lock")

    def __init__(
        self,
        *,
        exporter: Exporter | None = None,
        counters: OperationsTelemetry | None = None,
        capacity: int = DEFAULT_CAPACITY,
    ) -> None:
        if type(capacity) is not int or not 1 <= capacity <= 65_536:
            raise TelemetryError("telemetry capacity is invalid")
        if counters is not None and type(counters) is not OperationsTelemetry:
            raise TelemetryError("telemetry counters are invalid")
        self._capacity = capacity
        self._buffer: deque[Observation] = deque(maxlen=capacity)
        self._counters = counters
        self._dropped = 0
        self._exporter = RedactedExporter(exporter) if exporter is not None else None
        self._lock = Lock()

    @property
    def capacity(self) -> int:
        return self._capacity

    def record(self, *, action: str, status: int, duration_ms: int) -> None:
        """Record one bounded request observation; invalid input is rejected."""

        if (
            type(action) is not str
            or not 1 <= len(action) <= MAX_ACTION_LENGTH
            or any(not (character.isalnum() or character in "._:-") for character in action)
            or type(status) is not int
            or not 100 <= status <= 599
            or type(duration_ms) is not int
            or not MIN_DURATION_MS <= duration_ms <= MAX_DURATION_MS
        ):
            raise TelemetryError("telemetry observation is invalid")
        observation = Observation(
            name="control-plane.request",
            attributes={"operation": action, "outcome": str(status // 100) + "xx"},
            duration_ms=duration_ms,
        )
        with self._lock:
            if len(self._buffer) == self._capacity:
                self._dropped += 1
            self._buffer.append(observation)
            counters = self._counters
        if counters is not None:
            counters.record(
                operation=_COUNTER_OPERATION.get(action, "run"),
                outcome=_COUNTER_OUTCOME.get(status // 100, "error"),
                elapsed_ms=duration_ms,
            )

    def pending(self) -> int:
        with self._lock:
            return len(self._buffer)

    def dropped(self) -> int:
        with self._lock:
            return self._dropped

    def drain(self) -> tuple[Observation, ...]:
        """Take every buffered observation, leaving the buffer empty."""

        with self._lock:
            batch = tuple(self._buffer)
            self._buffer.clear()
        return batch

    def flush(self) -> TelemetryFlush:
        """Export the buffered batch; a missing or failing exporter keeps the data safe."""

        batch = self.drain()
        if not batch:
            return TelemetryFlush(accepted=True, exported=0, pending=0, dropped=self.dropped())
        if self._exporter is None:
            pending = self._restore(batch)
            return TelemetryFlush(
                accepted=False, exported=0, pending=pending, dropped=self.dropped()
            )
        try:
            result = self._exporter.export(batch)
        except Exception:
            result = None
        if result is None or not result.accepted:
            pending = self._restore(batch)
            return TelemetryFlush(
                accepted=False, exported=0, pending=pending, dropped=self.dropped()
            )
        return TelemetryFlush(
            accepted=True, exported=result.count, pending=0, dropped=self.dropped()
        )

    def _restore(self, batch: tuple[Observation, ...]) -> int:
        """Restore a failed batch ahead of concurrent arrivals, counting overflow."""

        with self._lock:
            concurrent = tuple(self._buffer)
            combined = batch + concurrent
            self._dropped += max(0, len(combined) - self._capacity)
            self._buffer.clear()
            self._buffer.extend(combined[: self._capacity])
            return len(self._buffer)


__all__ = [
    "DEFAULT_CAPACITY",
    "TelemetryError",
    "TelemetryFlush",
    "TelemetryRecorder",
]
