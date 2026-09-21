"""Internal telemetry value, trace authority, and canonical-byte contracts."""

from __future__ import annotations

import json
from dataclasses import fields
from enum import StrEnum

import pytest
from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION
from securecode_ai.core import (
    TelemetryBoundaryError,
    TelemetryBoundaryErrorCode,
    TelemetryDraft,
    TelemetryEmitReason,
    TelemetryEmitResult,
    TelemetryEmitStatus,
    TelemetryEventCode,
    TelemetryMeasurement,
    TelemetryMeasurementName,
    TelemetryRecord,
    TraceAuthority,
    TraceAuthorization,
    TraceContext,
    canonical_telemetry_bytes,
    parse_telemetry_bytes,
)


class SequenceSource:
    def __init__(self, *values: object) -> None:
        self.values = list(values)
        self.calls: list[int] = []

    def token_bytes(self, length: int) -> object:
        self.calls.append(length)
        value = self.values.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


class ForeignBoundaryCode(StrEnum):
    TRACE_SOURCE_FAILURE = "TRACE_SOURCE_FAILURE"


def authority_and_root() -> tuple[TraceAuthority, TraceAuthorization]:
    source = SequenceSource(bytes(range(32)), b"\x01" * 16, b"\x02" * 8)
    authority = TraceAuthority.create(source)  # type: ignore[arg-type]
    return authority, authority.issue_root()


@pytest.mark.parametrize(
    "invalid",
    [
        "TRACE_SOURCE_FAILURE",
        ForeignBoundaryCode.TRACE_SOURCE_FAILURE,
        "API_KEY=RAW-CANARY",
        ["unhashable-canary"],
        None,
    ],
)
def test_boundary_error_rejects_non_exact_code_without_echo(invalid: object) -> None:
    with pytest.raises(TypeError) as captured:
        TelemetryBoundaryError(invalid)  # type: ignore[arg-type]
    assert str(captured.value) == "telemetry boundary error code is invalid"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert "CANARY" not in repr(captured.value)


def test_trace_authority_known_answer_and_exact_calls() -> None:
    source = SequenceSource(bytes(range(32)), b"\x01" * 16, b"\x02" * 8)
    authority = TraceAuthority.create(source)  # type: ignore[arg-type]
    authorization = authority.issue_root()
    assert source.calls == [32, 16, 8]
    assert authorization.context == TraceContext(
        schema_version=CONTRACT_SCHEMA_VERSION,
        trace_id="01" * 16,
        span_id="02" * 8,
        parent_span_id=None,
    )
    assert (
        authorization.authorization_sha256
        == "0f96b825bfa4f84abb6a081b56aa2ab36b521b0691e816643ba084fa24870e2e"
    )
    assert authority.verify(authorization)


def test_trace_authority_exposes_no_source_bypassing_mint_helper() -> None:
    authority, _ = authority_and_root()
    assert not hasattr(authority, "_authorization")
    assert not hasattr(authority, "_payload_issuer_key")


def test_child_preserves_trace_and_records_parent() -> None:
    source = SequenceSource(
        bytes(range(32)),
        b"\x01" * 16,
        b"\x02" * 8,
        b"\x03" * 8,
    )
    authority = TraceAuthority.create(source)  # type: ignore[arg-type]
    parent = authority.issue_root()
    child = authority.issue_child(parent)
    assert source.calls == [32, 16, 8, 8]
    assert child.context.trace_id == parent.context.trace_id
    assert child.context.parent_span_id == parent.context.span_id
    assert child.context.span_id == "03" * 8
    assert authority.verify(child)


def test_child_span_collision_is_one_shot_source_failure() -> None:
    source = SequenceSource(
        bytes(range(32)),
        b"\x01" * 16,
        b"\x02" * 8,
        b"\x02" * 8,
    )
    authority = TraceAuthority.create(source)  # type: ignore[arg-type]
    parent = authority.issue_root()
    with pytest.raises(TelemetryBoundaryError) as captured:
        authority.issue_child(parent)
    assert captured.value.code is TelemetryBoundaryErrorCode.TRACE_SOURCE_FAILURE
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert source.calls == [32, 16, 8, 8]


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        bytearray(32),
        b"short",
        b"\x00" * 32,
        RuntimeError("API_KEY=RAW-CANARY"),
    ],
)
def test_authority_creation_source_failures_are_fixed_and_context_free(value: object) -> None:
    source = SequenceSource(value)
    with pytest.raises(TelemetryBoundaryError) as captured:
        TraceAuthority.create(source)  # type: ignore[arg-type]
    assert source.calls == [32]
    assert captured.value.code is TelemetryBoundaryErrorCode.TRACE_SOURCE_FAILURE
    assert str(captured.value) == "trace identifier source failed"
    assert captured.value.args == ("trace identifier source failed",)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert "CANARY" not in repr(captured.value)


@pytest.mark.parametrize(
    ("length", "value"),
    [
        (16, None),
        (16, True),
        (16, bytearray(16)),
        (16, b"x" * 15),
        (16, b"x" * 17),
        (16, b"\x00" * 16),
        (8, RuntimeError("source canary")),
    ],
)
def test_identifier_values_fail_after_one_attempt(length: int, value: object) -> None:
    values: list[object] = [bytes(range(32))]
    if length == 16:
        values.append(value)
    else:
        values.extend((b"\x01" * 16, value))
    source = SequenceSource(*values)
    authority = TraceAuthority.create(source)  # type: ignore[arg-type]
    with pytest.raises(TelemetryBoundaryError) as captured:
        authority.issue_root()
    assert captured.value.code is TelemetryBoundaryErrorCode.TRACE_SOURCE_FAILURE
    assert source.calls.count(length) == 1


def test_foreign_and_tampered_parent_fail_before_source_call() -> None:
    first_source = SequenceSource(bytes(range(32)), b"\x01" * 16, b"\x02" * 8)
    second_source = SequenceSource(bytes(reversed(range(32))))
    first = TraceAuthority.create(first_source)  # type: ignore[arg-type]
    second = TraceAuthority.create(second_source)  # type: ignore[arg-type]
    parent = first.issue_root()
    with pytest.raises(TelemetryBoundaryError) as foreign:
        second.issue_child(parent)
    assert foreign.value.code is TelemetryBoundaryErrorCode.TRACE_AUTHORIZATION_INVALID
    assert second_source.calls == [32]
    object.__setattr__(parent, "authorization_sha256", "f" * 64)
    with pytest.raises(TelemetryBoundaryError) as tampered:
        first.issue_child(parent)
    assert tampered.value.code is TelemetryBoundaryErrorCode.TRACE_AUTHORIZATION_INVALID
    assert first_source.calls == [32, 16, 8]


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("schema_version", "0.2.1"),
        ("trace_id", "0" * 32),
        ("trace_id", "A" * 32),
        ("trace_id", "a" * 31),
        ("span_id", "0" * 16),
        ("span_id", "g" * 16),
        ("parent_span_id", "0" * 16),
        ("parent_span_id", "b" * 16),
    ],
)
def test_trace_context_rejects_invalid_fields(field_name: str, value: object) -> None:
    values: dict[str, object] = {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "trace_id": "a" * 32,
        "span_id": "b" * 16,
        "parent_span_id": None,
    }
    values[field_name] = value
    with pytest.raises((TypeError, ValueError)):
        TraceContext(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [-1, True, 9_007_199_254_740_992, 1.0, "1"])
def test_measurement_rejects_non_strict_or_out_of_range_values(value: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        TelemetryMeasurement(
            schema_version=CONTRACT_SCHEMA_VERSION,
            name=TelemetryMeasurementName.ITEM_COUNT,
            value=value,  # type: ignore[arg-type]
        )


def test_draft_requires_unique_canonical_measurement_order() -> None:
    attempt = TelemetryMeasurement(CONTRACT_SCHEMA_VERSION, TelemetryMeasurementName.ATTEMPT, 1)
    tools = TelemetryMeasurement(CONTRACT_SCHEMA_VERSION, TelemetryMeasurementName.TOOL_CALLS, 2)
    assert TelemetryDraft(TelemetryEventCode.FOUNDATION_STARTED, (attempt, tools))
    with pytest.raises(ValueError):
        TelemetryDraft(TelemetryEventCode.FOUNDATION_STARTED, (tools, attempt))
    with pytest.raises(ValueError):
        TelemetryDraft(TelemetryEventCode.FOUNDATION_STARTED, (attempt, attempt))


def test_internal_model_has_no_raw_string_or_extension_slot() -> None:
    assert [field.name for field in fields(TelemetryDraft)] == [
        "event_code",
        "measurements",
    ]
    assert [field.name for field in fields(TraceContext)] == [
        "schema_version",
        "trace_id",
        "span_id",
        "parent_span_id",
    ]
    assert [field.name for field in fields(TelemetryRecord)] == [
        "schema_version",
        "record_id",
        "occurred_at",
        "event_code",
        "severity",
        "safe_message",
        "data_class",
        "trace",
        "measurements",
    ]


def test_canonical_parser_rejects_noncanonical_and_unknown_content() -> None:
    from datetime import UTC, datetime

    from securecode_ai.adapters import InMemoryTelemetrySink
    from securecode_ai.core import TelemetryEmitter

    authority, authorization = authority_and_root()
    sink = InMemoryTelemetrySink()
    clock = type("Clock", (), {"now_utc": lambda self: datetime(2026, 1, 2, tzinfo=UTC)})()
    result = TelemetryEmitter(authority, clock, (sink,)).emit(
        TelemetryDraft(TelemetryEventCode.FOUNDATION_COMPLETED), authorization
    )
    assert result.status is TelemetryEmitStatus.EMITTED
    payload = sink.records[0][0]
    parsed = parse_telemetry_bytes(payload)
    assert canonical_telemetry_bytes(parsed) == payload
    document = json.loads(payload)
    document["raw_error"] = "API_KEY=RAW-CANARY"
    with pytest.raises(ValueError):
        parse_telemetry_bytes(json.dumps(document, sort_keys=True).encode() + b"\n")
    with pytest.raises(ValueError):
        parse_telemetry_bytes(payload.rstrip(b"\n"))
    with pytest.raises(ValueError):
        parse_telemetry_bytes(
            payload.replace(b'"schema_version":"0.2.0"', b'"schema_version":"0.3.0"', 1)
        )
    document = json.loads(payload)
    document["event_code"] = "API_KEY=RAW-CANARY"
    with pytest.raises(ValueError) as captured:
        parse_telemetry_bytes(
            json.dumps(document, separators=(",", ":"), sort_keys=True).encode() + b"\n"
        )
    assert str(captured.value) == "telemetry payload is invalid"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert "CANARY" not in repr(captured.value)


def test_canonical_renderer_snapshots_nested_state_before_render(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from datetime import UTC, datetime

    import securecode_ai.core.telemetry as telemetry_module
    from securecode_ai.adapters import InMemoryTelemetrySink
    from securecode_ai.core import TelemetryEmitter
    from securecode_ai.core.telemetry_primitives import _revalidate_record

    authority, authorization = authority_and_root()
    sink = InMemoryTelemetrySink()
    clock = type("Clock", (), {"now_utc": lambda self: datetime(2026, 1, 2, tzinfo=UTC)})()
    result = TelemetryEmitter(authority, clock, (sink,)).emit(
        TelemetryDraft(TelemetryEventCode.FOUNDATION_COMPLETED), authorization
    )
    assert result.status is TelemetryEmitStatus.EMITTED
    record = parse_telemetry_bytes(sink.records[0][0])
    expected_trace_id = record.trace.trace_id
    retained_trace = record.trace
    original_revalidate = _revalidate_record

    def snapshot_then_mutate(value: TelemetryRecord) -> TelemetryRecord:
        snapshot = original_revalidate(value)
        object.__setattr__(retained_trace, "trace_id", "API_KEY=RAW-CANARY")
        return snapshot

    monkeypatch.setattr(telemetry_module, "_revalidate_record", snapshot_then_mutate)
    rendered = canonical_telemetry_bytes(record)
    assert b"CANARY" not in rendered
    assert parse_telemetry_bytes(rendered).trace.trace_id == expected_trace_id


@pytest.mark.parametrize(
    "values",
    [
        {
            "status": TelemetryEmitStatus.EMITTED,
            "record_sha256": "a" * 64,
            "attempted_sink_count": 0,
            "emitted_sink_count": 0,
            "failed_sink_count": 0,
            "reason_code": TelemetryEmitReason.NONE,
        },
        {
            "status": TelemetryEmitStatus.PARTIAL,
            "record_sha256": "a" * 64,
            "attempted_sink_count": 1,
            "emitted_sink_count": 1,
            "failed_sink_count": 0,
            "reason_code": TelemetryEmitReason.SINK_FAILURE,
        },
        {
            "status": TelemetryEmitStatus.REJECTED,
            "record_sha256": None,
            "attempted_sink_count": 1,
            "emitted_sink_count": 0,
            "failed_sink_count": 1,
            "reason_code": TelemetryEmitReason.INVALID_RECORD,
        },
    ],
)
def test_emit_result_rejects_inconsistent_status_shapes(values: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        TelemetryEmitResult(**values)  # type: ignore[arg-type]
