"""P8.8 bounded request telemetry, wired into the control-plane request path.

Observations are redacted before they leave the process: only the route action,
the response status and the measured duration are recorded — never bodies,
identifiers or credentials. The buffer is bounded, so an absent or failing
exporter degrades to a drop rather than unbounded memory growth.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from threading import Lock
from typing import Final

from securecode_ai.adapters.otlp_http import OtlpHttpExporter

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
    "worker_sessions.osv.query": "worker",
    "artifacts.authorize": "artifact",
    "artifacts.upload": "artifact",
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
}
_COUNTER_OUTCOME: Final = {2: "success", 4: "error", 5: "error"}
_TELEMETRY_OUTCOMES: Final = frozenset(
    {"success", "error", "cancelled", "superseded", "pass", "fail", "indeterminate"}
)
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

    __slots__ = (
        "_buffer",
        "_capacity",
        "_counters",
        "_dropped",
        "_exporter",
        "_flush_on_record",
        "_lock",
    )

    def __init__(
        self,
        *,
        exporter: Exporter | None = None,
        counters: OperationsTelemetry | None = None,
        capacity: int = DEFAULT_CAPACITY,
        flush_on_record: bool = False,
    ) -> None:
        if type(capacity) is not int or not 1 <= capacity <= 65_536:
            raise TelemetryError("telemetry capacity is invalid")
        if counters is not None and type(counters) is not OperationsTelemetry:
            raise TelemetryError("telemetry counters are invalid")
        if type(flush_on_record) is not bool:
            raise TelemetryError("telemetry flush configuration is invalid")
        self._capacity = capacity
        self._buffer: deque[Observation] = deque(maxlen=capacity)
        self._counters = counters
        self._dropped = 0
        self._exporter = RedactedExporter(exporter) if exporter is not None else None
        self._flush_on_record = flush_on_record
        self._lock = Lock()

    @property
    def capacity(self) -> int:
        return self._capacity

    def record(
        self,
        *,
        action: str,
        status: int,
        duration_ms: int,
        outcome: str | None = None,
        resource_usage: Mapping[str, int] | None = None,
    ) -> None:
        """Record one bounded request observation; invalid input is rejected."""

        resolved_outcome = outcome if outcome is not None else str(status // 100) + "xx"
        if (
            type(action) is not str
            or not 1 <= len(action) <= MAX_ACTION_LENGTH
            or not action.isascii()
            or any(not (character.isalnum() or character in "._:-") for character in action)
            or type(status) is not int
            or not 100 <= status <= 599
            or type(duration_ms) is not int
            or not MIN_DURATION_MS <= duration_ms <= MAX_DURATION_MS
            or type(resolved_outcome) is not str
            or resolved_outcome not in _TELEMETRY_OUTCOMES | {"1xx", "2xx", "3xx", "4xx", "5xx"}
        ):
            raise TelemetryError("telemetry observation is invalid")
        try:
            observation = Observation(
                name="control-plane.request",
                attributes={"operation": action, "outcome": resolved_outcome},
                duration_ms=duration_ms,
                resource_usage=resource_usage,
            )
        except (TypeError, ValueError) as error:
            raise TelemetryError("telemetry observation is invalid") from error
        with self._lock:
            if len(self._buffer) == self._capacity:
                self._dropped += 1
            self._buffer.append(observation)
            counters = self._counters
        if counters is not None:
            counters.record(
                operation=_COUNTER_OPERATION.get(action, "run"),
                outcome=(
                    outcome
                    if outcome in _TELEMETRY_OUTCOMES
                    else _COUNTER_OUTCOME.get(status // 100, "error")
                ),
                elapsed_ms=duration_ms,
                resource_usage=resource_usage,
            )
        if self._flush_on_record:
            self.flush()

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
            return TelemetryFlush(
                accepted=True,
                exported=0,
                pending=self.pending(),
                dropped=self.dropped(),
            )
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
            accepted=True,
            exported=result.count,
            pending=self.pending(),
            dropped=self.dropped(),
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
    "build_request_telemetry",
]


def build_request_telemetry(
    values: Mapping[str, str],
    *,
    counters: OperationsTelemetry | None = None,
) -> TelemetryRecorder:
    """Build the request recorder and optionally connect its OTLP sink.

    OTLP is opt-in. When no endpoint is configured this returns the normal
    bounded in-process recorder and performs no network work. A configured
    endpoint is flushed after each redacted request observation so the
    production process does not need an unbounded background queue or a
    shutdown-only delivery window.
    """

    if not isinstance(values, Mapping):
        raise TelemetryError("telemetry configuration is invalid")
    endpoint = values.get("SECURECODE_OTLP_ENDPOINT")
    if endpoint is None:
        return TelemetryRecorder(counters=counters)
    if type(endpoint) is not str:
        raise TelemetryError("telemetry configuration is invalid")
    try:
        timeout_ms = _telemetry_integer(
            values,
            "SECURECODE_OTLP_TIMEOUT_MS",
            default=5_000,
            minimum=1,
            maximum=60_000,
        )
        max_attempts = _telemetry_integer(
            values,
            "SECURECODE_OTLP_MAX_ATTEMPTS",
            default=3,
            minimum=1,
            maximum=5,
        )
        exporter = OtlpHttpExporter(
            endpoint=endpoint,
            timeout_ms=timeout_ms,
            max_attempts=max_attempts,
        )
    except (TypeError, ValueError):
        raise TelemetryError("telemetry configuration is invalid") from None
    return TelemetryRecorder(
        exporter=exporter,
        counters=counters,
        flush_on_record=True,
    )


def _telemetry_integer(
    values: Mapping[str, str],
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    value = values.get(name, str(default))
    if (
        type(value) is not str
        or not 1 <= len(value) <= 5
        or not value.isascii()
        or not value.isdecimal()
    ):
        raise TelemetryError("telemetry configuration is invalid")
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise TelemetryError("telemetry configuration is invalid")
    return parsed
