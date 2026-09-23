"""P8.8 request telemetry: bounded buffer, export semantics and counters."""

from __future__ import annotations

import pytest
from securecode_ai.server.operations_telemetry import OperationsTelemetry
from securecode_ai.server.telemetry import (
    DEFAULT_CAPACITY,
    TelemetryError,
    TelemetryRecorder,
)


class _Sink:
    def __init__(self, outcome: object = True) -> None:
        self._outcome = outcome
        self.batches: list[tuple[object, ...]] = []

    def export(self, observations: tuple[object, ...]) -> object:
        self.batches.append(observations)
        if self._outcome == "raise":
            raise RuntimeError("exporter unavailable")
        return self._outcome


class _ReentrantFailingSink:
    recorder: TelemetryRecorder | None = None

    def export(self, observations: tuple[object, ...]) -> bool:
        del observations
        if self.recorder is None:
            raise AssertionError("recorder was not configured")
        self.recorder.record(action="runs.read", status=200, duration_ms=2)
        self.recorder.record(action="runs.read", status=200, duration_ms=3)
        return False


def test_capacity_is_validated() -> None:
    for capacity in (0, -1, 65_537):
        with pytest.raises(TelemetryError):
            TelemetryRecorder(capacity=capacity)


def test_counters_argument_is_validated() -> None:
    with pytest.raises(TelemetryError):
        TelemetryRecorder(counters=object())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "observation",
    [
        {"action": "", "status": 200, "duration_ms": 1},
        {"action": "bad action!", "status": 200, "duration_ms": 1},
        {"action": "x" * 65, "status": 200, "duration_ms": 1},
        {"action": "runs.read", "status": 99, "duration_ms": 1},
        {"action": "runs.read", "status": 600, "duration_ms": 1},
        {"action": "runs.read", "status": 200, "duration_ms": -1},
        {"action": "runs.read", "status": 200, "duration_ms": 3_600_001},
    ],
)
def test_invalid_observations_are_rejected(observation: dict[str, object]) -> None:
    recorder = TelemetryRecorder()
    with pytest.raises(TelemetryError):
        recorder.record(**observation)  # type: ignore[arg-type]
    assert recorder.pending() == 0


def test_observations_expose_only_the_allowed_projection() -> None:
    recorder = TelemetryRecorder()
    recorder.record(action="runs.create", status=201, duration_ms=5)
    batch = recorder.drain()
    assert len(batch) == 1
    assert batch[0].name == "control-plane.request"
    assert batch[0].attributes == {"operation": "runs.create", "outcome": "2xx"}
    assert batch[0].duration_ms == 5


def test_buffer_is_bounded_and_keeps_the_most_recent() -> None:
    recorder = TelemetryRecorder(capacity=2)
    for index in range(5):
        recorder.record(action="runs.read", status=200, duration_ms=index)
    batch = recorder.drain()
    assert len(batch) == 2
    assert [item.duration_ms for item in batch] == [3, 4]
    assert recorder.dropped() == 3


def test_drain_empties_the_buffer() -> None:
    recorder = TelemetryRecorder()
    recorder.record(action="runs.read", status=200, duration_ms=1)
    assert len(recorder.drain()) == 1
    assert recorder.pending() == 0
    assert recorder.drain() == ()


def test_flush_accepted_exports_and_releases_the_buffer() -> None:
    sink = _Sink(True)
    recorder = TelemetryRecorder(exporter=sink, capacity=8)  # type: ignore[arg-type]
    recorder.record(action="runs.create", status=201, duration_ms=2)
    result = recorder.flush()
    assert result.accepted and result.exported == 1
    assert recorder.pending() == 0
    assert len(sink.batches) == 1


def test_flush_without_an_exporter_retains_observations() -> None:
    recorder = TelemetryRecorder(capacity=4)
    recorder.record(action="runs.read", status=200, duration_ms=1)
    result = recorder.flush()
    assert not result.accepted and result.exported == 0
    assert recorder.pending() == 1


@pytest.mark.parametrize("outcome", [False, "raise"])
def test_failing_exporter_retains_observations(outcome: object) -> None:
    sink = _Sink(outcome)
    recorder = TelemetryRecorder(exporter=sink, capacity=4)  # type: ignore[arg-type]
    recorder.record(action="runs.read", status=200, duration_ms=1)
    result = recorder.flush()
    assert not result.accepted and result.exported == 0
    assert recorder.pending() == 1


def test_failed_flush_restores_batch_before_concurrent_arrivals_and_counts_drops() -> None:
    sink = _ReentrantFailingSink()
    recorder = TelemetryRecorder(exporter=sink, capacity=2)
    sink.recorder = recorder
    recorder.record(action="runs.read", status=200, duration_ms=1)

    result = recorder.flush()

    assert not result.accepted
    assert result.pending == 2
    assert result.dropped == 1
    assert recorder.dropped() == 1
    assert [item.duration_ms for item in recorder.drain()] == [1, 2]


def test_empty_flush_is_accepted_without_touching_the_exporter() -> None:
    sink = _Sink(True)
    recorder = TelemetryRecorder(exporter=sink, capacity=4)  # type: ignore[arg-type]
    result = recorder.flush()
    assert result.accepted and result.exported == 0
    assert sink.batches == []


def test_counters_collapse_actions_and_status_classes() -> None:
    counters = OperationsTelemetry()
    recorder = TelemetryRecorder(counters=counters, capacity=16)
    recorder.record(action="worker_sessions.heartbeat", status=200, duration_ms=3)
    recorder.record(action="runs.create", status=201, duration_ms=4)
    recorder.record(action="secrets.grant", status=403, duration_ms=1)
    snapshot = counters.snapshot()
    counter_rows = snapshot["counters"]
    assert isinstance(counter_rows, tuple)
    counters_by_key = {}
    for row in counter_rows:
        assert isinstance(row, dict)
        counters_by_key[(row["operation"], row["outcome"])] = row["count"]
    assert counters_by_key[("worker", "success")] == 1
    assert counters_by_key[("run", "success")] == 1
    assert counters_by_key[("run", "error")] == 1
    latency_rows = snapshot["latency_ms"]
    assert isinstance(latency_rows, tuple)
    latency = {}
    for row in latency_rows:
        assert isinstance(row, dict)
        latency[row["operation"]] = row["total"]
    assert latency["worker"] == 3


def test_default_capacity_is_documented_and_positive() -> None:
    assert DEFAULT_CAPACITY > 0
    assert TelemetryRecorder().capacity == DEFAULT_CAPACITY
