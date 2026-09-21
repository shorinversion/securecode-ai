"""Fail-closed, framework-independent foundation telemetry primitives."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Protocol, final

from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION

_MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991
_MAX_MEASUREMENTS: Final = 32
_MAX_PAYLOAD_BYTES: Final = 16_384
_MAX_SINKS: Final = 16
_LOWER_HEX_16: Final = re.compile(r"^[0-9a-f]{16}$")
_LOWER_HEX_32: Final = re.compile(r"^[0-9a-f]{32}$")
_LOWER_HEX_64: Final = re.compile(r"^[0-9a-f]{64}$")


class TelemetryEventCode(StrEnum):
    FOUNDATION_STARTED = "FOUNDATION_STARTED"
    FOUNDATION_COMPLETED = "FOUNDATION_COMPLETED"
    FOUNDATION_NON_SUCCESS = "FOUNDATION_NON_SUCCESS"
    FOUNDATION_DENIED = "FOUNDATION_DENIED"
    FOUNDATION_FAILED = "FOUNDATION_FAILED"


class TelemetrySeverity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class TelemetryMeasurementName(StrEnum):
    ATTEMPT = "ATTEMPT"
    BYTE_COUNT = "BYTE_COUNT"
    ELAPSED_MS = "ELAPSED_MS"
    ITEM_COUNT = "ITEM_COUNT"
    TOKENS_USED = "TOKENS_USED"
    TOOL_CALLS = "TOOL_CALLS"


class TelemetryDataClass(StrEnum):
    INTERNAL_METADATA = "DC1_INTERNAL_METADATA"


class TelemetryEmitStatus(StrEnum):
    EMITTED = "EMITTED"
    PARTIAL = "PARTIAL"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


class TelemetryEmitReason(StrEnum):
    NONE = "NONE"
    INVALID_WIRING = "INVALID_WIRING"
    INVALID_RECORD = "INVALID_RECORD"
    INVALID_TRACE_AUTHORIZATION = "INVALID_TRACE_AUTHORIZATION"
    CLOCK_FAILURE = "CLOCK_FAILURE"
    NO_SINKS = "NO_SINKS"
    SINK_FAILURE = "SINK_FAILURE"


class TelemetryBoundaryErrorCode(StrEnum):
    TRACE_SOURCE_FAILURE = "TRACE_SOURCE_FAILURE"
    TRACE_AUTHORIZATION_INVALID = "TRACE_AUTHORIZATION_INVALID"
    REGISTRY_INVALID = "REGISTRY_INVALID"
    SINK_PAYLOAD_INVALID = "SINK_PAYLOAD_INVALID"
    STREAM_INVALID = "STREAM_INVALID"


_BOUNDARY_MESSAGES: Final = MappingProxyType(
    {
        TelemetryBoundaryErrorCode.TRACE_SOURCE_FAILURE: "trace identifier source failed",
        TelemetryBoundaryErrorCode.TRACE_AUTHORIZATION_INVALID: ("trace authorization is invalid"),
        TelemetryBoundaryErrorCode.REGISTRY_INVALID: "telemetry sink registry is invalid",
        TelemetryBoundaryErrorCode.SINK_PAYLOAD_INVALID: ("telemetry sink payload is invalid"),
        TelemetryBoundaryErrorCode.STREAM_INVALID: "telemetry stream is invalid",
    }
)


@final
class TelemetryBoundaryError(RuntimeError):
    """A closed, context-free error for telemetry trust boundaries."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: TelemetryBoundaryErrorCode) -> None:
        if type(code) is not TelemetryBoundaryErrorCode:
            raise TypeError("telemetry boundary error code is invalid") from None
        safe_message = _BOUNDARY_MESSAGES[code]
        self.code = code
        self.safe_message = safe_message
        super().__init__(safe_message)


def _boundary(code: TelemetryBoundaryErrorCode) -> TelemetryBoundaryError:
    return TelemetryBoundaryError(code)


_EVENT_POLICY: Final = MappingProxyType(
    {
        TelemetryEventCode.FOUNDATION_STARTED: (
            TelemetrySeverity.INFO,
            "foundation operation started",
        ),
        TelemetryEventCode.FOUNDATION_COMPLETED: (
            TelemetrySeverity.INFO,
            "foundation operation completed",
        ),
        TelemetryEventCode.FOUNDATION_NON_SUCCESS: (
            TelemetrySeverity.WARNING,
            "foundation operation did not complete successfully",
        ),
        TelemetryEventCode.FOUNDATION_DENIED: (
            TelemetrySeverity.WARNING,
            "foundation operation was denied",
        ),
        TelemetryEventCode.FOUNDATION_FAILED: (
            TelemetrySeverity.ERROR,
            "foundation operation failed",
        ),
    }
)


def _is_exact_int(value: object) -> bool:
    return type(value) is int


def _is_lower_hex(value: object, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _require_current_version(value: object) -> None:
    if type(value) is not str or value != CONTRACT_SCHEMA_VERSION:
        raise ValueError("telemetry schema version is not current")


@final
@dataclass(frozen=True, slots=True)
class TraceContext:
    schema_version: str
    trace_id: str
    span_id: str
    parent_span_id: str | None

    def __post_init__(self) -> None:
        _require_current_version(self.schema_version)
        if not _is_lower_hex(self.trace_id, _LOWER_HEX_32) or self.trace_id == "0" * 32:
            raise ValueError("trace_id is invalid")
        if not _is_lower_hex(self.span_id, _LOWER_HEX_16) or self.span_id == "0" * 16:
            raise ValueError("span_id is invalid")
        if self.parent_span_id is not None and (
            not _is_lower_hex(self.parent_span_id, _LOWER_HEX_16)
            or self.parent_span_id == "0" * 16
            or self.parent_span_id == self.span_id
        ):
            raise ValueError("parent_span_id is invalid")


@final
@dataclass(frozen=True, slots=True)
class TelemetryMeasurement:
    schema_version: str
    name: TelemetryMeasurementName
    value: int

    def __post_init__(self) -> None:
        _require_current_version(self.schema_version)
        if type(self.name) is not TelemetryMeasurementName:
            raise TypeError("measurement name must be a closed enum")
        if not _is_exact_int(self.value) or not 0 <= self.value <= _MAX_SAFE_INTEGER:
            raise ValueError("measurement value is invalid")


@final
@dataclass(frozen=True, slots=True)
class TelemetryRecord:
    """Internal exact-version record; this is deliberately not a public wire root."""

    schema_version: str
    record_id: str
    occurred_at: datetime
    event_code: TelemetryEventCode
    severity: TelemetrySeverity
    safe_message: str
    data_class: TelemetryDataClass
    trace: TraceContext
    measurements: tuple[TelemetryMeasurement, ...]

    def __post_init__(self) -> None:
        _require_current_version(self.schema_version)
        if not _is_lower_hex(self.record_id, _LOWER_HEX_64):
            raise ValueError("record_id is invalid")
        if type(self.occurred_at) is not datetime or self.occurred_at.tzinfo is not UTC:
            raise ValueError("occurred_at must use datetime.timezone.utc")
        if self.occurred_at.utcoffset() != timedelta(0):
            raise ValueError("occurred_at must be UTC")
        if type(self.event_code) is not TelemetryEventCode:
            raise TypeError("event_code must be a closed enum")
        expected = _EVENT_POLICY[self.event_code]
        if type(self.severity) is not TelemetrySeverity or self.severity is not expected[0]:
            raise ValueError("severity does not match event policy")
        if type(self.safe_message) is not str or self.safe_message != expected[1]:
            raise ValueError("safe_message does not match event policy")
        if self.data_class is not TelemetryDataClass.INTERNAL_METADATA:
            raise ValueError("telemetry data class must be DC1")
        if type(self.trace) is not TraceContext:
            raise TypeError("trace context type is invalid")
        _revalidate_trace(self.trace)
        _validate_measurements(self.measurements)
        if self.record_id != _record_id_for(self):
            raise ValueError("record_id does not match canonical record content")


@final
@dataclass(frozen=True, slots=True)
class TelemetryDraft:
    event_code: TelemetryEventCode
    measurements: tuple[TelemetryMeasurement, ...] = ()

    def __post_init__(self) -> None:
        if type(self.event_code) is not TelemetryEventCode:
            raise TypeError("event_code must be a closed enum")
        _validate_measurements(self.measurements)


@final
@dataclass(frozen=True, slots=True)
class TraceAuthorization:
    context: TraceContext
    authorization_sha256: str

    def __post_init__(self) -> None:
        if type(self.context) is not TraceContext:
            raise TypeError("trace authorization context is invalid")
        _revalidate_trace(self.context)
        if not _is_lower_hex(self.authorization_sha256, _LOWER_HEX_64):
            raise ValueError("trace authorization signature is invalid")


@final
@dataclass(frozen=True, slots=True)
class TelemetryEmitResult:
    status: TelemetryEmitStatus
    record_sha256: str | None
    attempted_sink_count: int
    emitted_sink_count: int
    failed_sink_count: int
    reason_code: TelemetryEmitReason

    def __post_init__(self) -> None:
        if type(self.status) is not TelemetryEmitStatus:
            raise TypeError("telemetry status type is invalid")
        if type(self.reason_code) is not TelemetryEmitReason:
            raise TypeError("telemetry reason type is invalid")
        if self.record_sha256 is not None and not _is_lower_hex(self.record_sha256, _LOWER_HEX_64):
            raise ValueError("record hash is invalid")
        counts = (
            self.attempted_sink_count,
            self.emitted_sink_count,
            self.failed_sink_count,
        )
        if any(not _is_exact_int(value) or value < 0 for value in counts):
            raise ValueError("telemetry sink counts are invalid")
        if self.emitted_sink_count + self.failed_sink_count != self.attempted_sink_count:
            raise ValueError("telemetry sink counts are inconsistent")
        _validate_emit_result(self)


class TraceIdSource(Protocol):
    def token_bytes(self, length: int) -> bytes: ...


class TelemetryClock(Protocol):
    def now_utc(self) -> datetime: ...


class TelemetrySink(Protocol):
    def emit(self, payload: object) -> None: ...


def _revalidate_trace(value: TraceContext) -> TraceContext:
    if type(value) is not TraceContext:
        raise TypeError("trace context type is invalid")
    return TraceContext(
        schema_version=value.schema_version,
        trace_id=value.trace_id,
        span_id=value.span_id,
        parent_span_id=value.parent_span_id,
    )


def _revalidate_measurement(value: TelemetryMeasurement) -> TelemetryMeasurement:
    if type(value) is not TelemetryMeasurement:
        raise TypeError("measurement type is invalid")
    return TelemetryMeasurement(
        schema_version=value.schema_version,
        name=value.name,
        value=value.value,
    )


def _validate_measurements(value: object) -> tuple[TelemetryMeasurement, ...]:
    if type(value) is not tuple or len(value) > _MAX_MEASUREMENTS:
        raise ValueError("measurements must be a bounded tuple")
    validated = tuple(_revalidate_measurement(item) for item in value)
    names = tuple(item.name.value for item in validated)
    if names != tuple(sorted(names)) or len(names) != len(set(names)):
        raise ValueError("measurements must be unique and canonically sorted")
    return validated


def _revalidate_draft(value: TelemetryDraft) -> TelemetryDraft:
    if type(value) is not TelemetryDraft:
        raise TypeError("telemetry draft type is invalid")
    return TelemetryDraft(
        event_code=value.event_code,
        measurements=_validate_measurements(value.measurements),
    )


def _trace_document(value: TraceContext) -> dict[str, object]:
    return {
        "parent_span_id": value.parent_span_id,
        "schema_version": value.schema_version,
        "span_id": value.span_id,
        "trace_id": value.trace_id,
    }


def _measurement_document(value: TelemetryMeasurement) -> dict[str, object]:
    return {
        "name": value.name.value,
        "schema_version": value.schema_version,
        "value": value.value,
    }


def _timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _record_document(value: TelemetryRecord, *, include_record_id: bool) -> dict[str, object]:
    document: dict[str, object] = {
        "data_class": value.data_class.value,
        "event_code": value.event_code.value,
        "measurements": [_measurement_document(item) for item in value.measurements],
        "occurred_at": _timestamp(value.occurred_at),
        "safe_message": value.safe_message,
        "schema_version": value.schema_version,
        "severity": value.severity.value,
        "trace": _trace_document(value.trace),
    }
    if include_record_id:
        document["record_id"] = value.record_id
    return document


def _canonical_json(value: object, *, terminal_lf: bool) -> bytes:
    rendered = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return rendered + (b"\n" if terminal_lf else b"")


def _record_id_for(value: TelemetryRecord) -> str:
    return hashlib.sha256(
        _canonical_json(_record_document(value, include_record_id=False), terminal_lf=True)
    ).hexdigest()


def canonical_telemetry_bytes(value: TelemetryRecord) -> bytes:
    """Revalidate and render one exact internal record as canonical JSONL."""

    validated = _revalidate_record(value)
    return _canonical_json(_record_document(validated, include_record_id=True), terminal_lf=True)


def _revalidate_record(value: TelemetryRecord) -> TelemetryRecord:
    if type(value) is not TelemetryRecord:
        raise TypeError("telemetry record type is invalid")
    trace = _revalidate_trace(value.trace)
    measurements = _validate_measurements(value.measurements)
    return TelemetryRecord(
        schema_version=value.schema_version,
        record_id=value.record_id,
        occurred_at=value.occurred_at,
        event_code=value.event_code,
        severity=value.severity,
        safe_message=value.safe_message,
        data_class=value.data_class,
        trace=trace,
        measurements=measurements,
    )


def _validate_emit_result(value: TelemetryEmitResult) -> None:
    expected: dict[TelemetryEmitStatus, tuple[TelemetryEmitReason, bool]] = {
        TelemetryEmitStatus.EMITTED: (TelemetryEmitReason.NONE, True),
        TelemetryEmitStatus.PARTIAL: (TelemetryEmitReason.SINK_FAILURE, True),
        TelemetryEmitStatus.REJECTED: (value.reason_code, False),
        TelemetryEmitStatus.FAILED: (
            value.reason_code,
            value.reason_code is TelemetryEmitReason.SINK_FAILURE
            or value.reason_code is TelemetryEmitReason.NO_SINKS,
        ),
    }
    reason, hash_required = expected[value.status]
    if value.status is TelemetryEmitStatus.REJECTED and value.reason_code not in {
        TelemetryEmitReason.INVALID_WIRING,
        TelemetryEmitReason.INVALID_RECORD,
        TelemetryEmitReason.INVALID_TRACE_AUTHORIZATION,
    }:
        raise ValueError("rejected telemetry reason is invalid")
    if value.status is TelemetryEmitStatus.FAILED and value.reason_code not in {
        TelemetryEmitReason.CLOCK_FAILURE,
        TelemetryEmitReason.NO_SINKS,
        TelemetryEmitReason.SINK_FAILURE,
    }:
        raise ValueError("failed telemetry reason is invalid")
    if (
        value.status in {TelemetryEmitStatus.EMITTED, TelemetryEmitStatus.PARTIAL}
        and value.reason_code is not reason
    ):
        raise ValueError("telemetry status/reason mapping is invalid")
    if (value.record_sha256 is not None) is not hash_required:
        raise ValueError("telemetry status/hash mapping is invalid")
    if value.status is TelemetryEmitStatus.EMITTED and (
        value.attempted_sink_count == 0
        or value.emitted_sink_count != value.attempted_sink_count
        or value.failed_sink_count != 0
    ):
        raise ValueError("emitted telemetry counts are invalid")
    if value.status is TelemetryEmitStatus.PARTIAL and not (
        0 < value.emitted_sink_count < value.attempted_sink_count and value.failed_sink_count > 0
    ):
        raise ValueError("partial telemetry counts are invalid")
    if value.status is TelemetryEmitStatus.REJECTED and any(
        (value.attempted_sink_count, value.emitted_sink_count, value.failed_sink_count)
    ):
        raise ValueError("rejected telemetry counts must be zero")
    if value.status is TelemetryEmitStatus.FAILED:
        if value.reason_code in {
            TelemetryEmitReason.CLOCK_FAILURE,
            TelemetryEmitReason.NO_SINKS,
        } and any((value.attempted_sink_count, value.emitted_sink_count, value.failed_sink_count)):
            raise ValueError("pre-sink telemetry failure counts must be zero")
        if value.reason_code is TelemetryEmitReason.SINK_FAILURE and not (
            value.attempted_sink_count > 0
            and value.emitted_sink_count == 0
            and value.failed_sink_count == value.attempted_sink_count
        ):
            raise ValueError("failed telemetry sink counts are invalid")
