"""Fail-closed, framework-independent foundation telemetry primitives."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, fields
from datetime import UTC, datetime, timedelta
from dis import get_instructions
from enum import StrEnum
from types import FrameType, MappingProxyType
from typing import Any, Final, Protocol, cast, final

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


def _strict_json_object(payload: bytes) -> dict[str, object]:
    if type(payload) is not bytes or not 1 <= len(payload) <= _MAX_PAYLOAD_BYTES:
        raise ValueError("telemetry payload size is invalid")
    if not payload.endswith(b"\n") or payload.endswith(b"\n\n"):
        raise ValueError("telemetry payload must contain one terminal LF")

    def pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    def reject_constant(_: str) -> object:
        raise ValueError("non-finite JSON value")

    decoded = json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=pairs_hook,
        parse_constant=reject_constant,
    )
    if type(decoded) is not dict:
        raise ValueError("telemetry payload root must be an object")
    return decoded


def _exact_keys(value: dict[str, object], expected: tuple[str, ...]) -> None:
    if set(value) != set(expected) or len(value) != len(expected):
        raise ValueError("telemetry object fields are invalid")


def _parse_trace(value: object) -> TraceContext:
    if type(value) is not dict:
        raise ValueError("trace must be an object")
    _exact_keys(value, ("schema_version", "trace_id", "span_id", "parent_span_id"))
    return TraceContext(
        schema_version=cast(str, value["schema_version"]),
        trace_id=cast(str, value["trace_id"]),
        span_id=cast(str, value["span_id"]),
        parent_span_id=cast(str | None, value["parent_span_id"]),
    )


def _parse_measurement(value: object) -> TelemetryMeasurement:
    if type(value) is not dict:
        raise ValueError("measurement must be an object")
    _exact_keys(value, ("schema_version", "name", "value"))
    name = value["name"]
    if type(name) is not str:
        raise ValueError("measurement name is invalid")
    return TelemetryMeasurement(
        schema_version=cast(str, value["schema_version"]),
        name=TelemetryMeasurementName(name),
        value=cast(int, value["value"]),
    )


def _parse_telemetry_bytes(payload: bytes) -> TelemetryRecord:
    document = _strict_json_object(payload)
    _exact_keys(
        document,
        (
            "schema_version",
            "record_id",
            "occurred_at",
            "event_code",
            "severity",
            "safe_message",
            "data_class",
            "trace",
            "measurements",
        ),
    )
    occurred_at = document["occurred_at"]
    if (
        type(occurred_at) is not str
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z",
            occurred_at,
        )
        is None
    ):
        raise ValueError("telemetry timestamp is not canonical")
    measurements = document["measurements"]
    if type(measurements) is not list:
        raise ValueError("measurements must be an array")
    event_code = document["event_code"]
    severity = document["severity"]
    data_class = document["data_class"]
    if any(type(value) is not str for value in (event_code, severity, data_class)):
        raise ValueError("telemetry enum value is invalid")
    record = TelemetryRecord(
        schema_version=cast(str, document["schema_version"]),
        record_id=cast(str, document["record_id"]),
        occurred_at=datetime.strptime(occurred_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC),
        event_code=TelemetryEventCode(cast(str, event_code)),
        severity=TelemetrySeverity(cast(str, severity)),
        safe_message=cast(str, document["safe_message"]),
        data_class=TelemetryDataClass(cast(str, data_class)),
        trace=_parse_trace(document["trace"]),
        measurements=tuple(_parse_measurement(item) for item in measurements),
    )
    if canonical_telemetry_bytes(record) != payload:
        raise ValueError("telemetry payload is not canonical")
    return record


def parse_telemetry_bytes(payload: bytes) -> TelemetryRecord:
    """Parse only the internal current writer without echoing rejected input."""

    failed = False
    record: TelemetryRecord | None = None
    try:
        record = _parse_telemetry_bytes(payload)
    except Exception:
        failed = True
    if failed or record is None:
        raise ValueError("telemetry payload is invalid")
    return record


def _authorization_message(context: TraceContext) -> bytes:
    return b"securecode-trace-authorization-v1\0" + _canonical_json(
        _trace_document(context), terminal_lf=False
    )


@final
class TraceAuthority:
    __slots__ = ("_key", "_key_check", "_seal", "_source_call")

    _key: bytes
    _key_check: bytes
    _seal: tuple[int, bytes]
    _source_call: Callable[[int], object]

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("TraceAuthority is immutable")
        object.__setattr__(self, name, value)

    @classmethod
    def create(cls, source: TraceIdSource) -> TraceAuthority:
        failed = False
        source_call: Callable[[int], object] | None = None
        key: object = None
        try:
            candidate: object = cast(Any, source).token_bytes
            if not callable(candidate):
                failed = True
            else:
                source_call = cast(Callable[[int], object], candidate)
                key = source_call(32)
        except Exception:
            failed = True
        if (
            failed
            or source_call is None
            or type(key) is not bytes
            or len(key) != 32
            or key == b"\x00" * 32
        ):
            raise _boundary(TelemetryBoundaryErrorCode.TRACE_SOURCE_FAILURE)
        instance = cls.__new__(cls)
        object.__setattr__(instance, "_source_call", source_call)
        object.__setattr__(instance, "_key", key)
        object.__setattr__(instance, "_key_check", hashlib.sha256(key).digest())
        object.__setattr__(
            instance,
            "_seal",
            (id(source_call), hashlib.sha256(key + b"trace-authority-v1").digest()),
        )
        return instance

    def _intact(self) -> bool:
        try:
            return (
                type(self) is TraceAuthority
                and type(self._key) is bytes
                and len(self._key) == 32
                and self._key != b"\x00" * 32
                and hashlib.sha256(self._key).digest() == self._key_check
                and callable(self._source_call)
                and self._seal
                == (
                    id(self._source_call),
                    hashlib.sha256(self._key + b"trace-authority-v1").digest(),
                )
            )
        except Exception:
            return False

    def _next(self, length: int) -> bytes:
        if not self._intact():
            raise _boundary(TelemetryBoundaryErrorCode.TRACE_AUTHORIZATION_INVALID)
        failed = False
        value: object = None
        try:
            value = self._source_call(length)
        except Exception:
            failed = True
        if not self._intact():
            raise _boundary(TelemetryBoundaryErrorCode.TRACE_AUTHORIZATION_INVALID)
        if failed or type(value) is not bytes or len(value) != length or value == b"\x00" * length:
            raise _boundary(TelemetryBoundaryErrorCode.TRACE_SOURCE_FAILURE)
        return value

    def issue_root(self) -> TraceAuthorization:
        trace_id = self._next(16).hex()
        span_id = self._next(8).hex()
        if not self._intact():
            raise _boundary(TelemetryBoundaryErrorCode.TRACE_AUTHORIZATION_INVALID)
        context = TraceContext(
            schema_version=CONTRACT_SCHEMA_VERSION,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=None,
        )
        signature = hmac.new(
            self._key,
            _authorization_message(context),
            hashlib.sha256,
        ).hexdigest()
        return TraceAuthorization(context=context, authorization_sha256=signature)

    def issue_child(self, parent: TraceAuthorization) -> TraceAuthorization:
        invalid_parent = False
        parent_snapshot: TraceAuthorization | None = None
        try:
            if type(parent) is not TraceAuthorization:
                raise TypeError
            parent_snapshot = TraceAuthorization(
                context=_revalidate_trace(parent.context),
                authorization_sha256=parent.authorization_sha256,
            )
        except Exception:
            invalid_parent = True
        if invalid_parent or parent_snapshot is None:
            raise _boundary(TelemetryBoundaryErrorCode.TRACE_AUTHORIZATION_INVALID)
        if not self.verify(parent_snapshot):
            raise _boundary(TelemetryBoundaryErrorCode.TRACE_AUTHORIZATION_INVALID)
        span_bytes = self._next(8)
        if span_bytes.hex() == parent_snapshot.context.span_id:
            raise _boundary(TelemetryBoundaryErrorCode.TRACE_SOURCE_FAILURE)
        if not self._intact():
            raise _boundary(TelemetryBoundaryErrorCode.TRACE_AUTHORIZATION_INVALID)
        context = TraceContext(
            schema_version=CONTRACT_SCHEMA_VERSION,
            trace_id=parent_snapshot.context.trace_id,
            span_id=span_bytes.hex(),
            parent_span_id=parent_snapshot.context.span_id,
        )
        signature = hmac.new(
            self._key,
            _authorization_message(context),
            hashlib.sha256,
        ).hexdigest()
        return TraceAuthorization(context=context, authorization_sha256=signature)

    def verify(self, authorization: object) -> bool:
        if not self._intact() or type(authorization) is not TraceAuthorization:
            return False
        try:
            validated = TraceAuthorization(
                context=_revalidate_trace(authorization.context),
                authorization_sha256=authorization.authorization_sha256,
            )
            expected = hmac.new(
                self._key,
                _authorization_message(validated.context),
                hashlib.sha256,
            ).hexdigest()
            return hmac.compare_digest(expected, validated.authorization_sha256)
        except Exception:
            return False


@final
class _TelemetryPayload:
    __slots__ = ("_canonical_bytes", "_issuer", "_payload_sha256", "_seal")

    _canonical_bytes: bytes
    _issuer: _PayloadIssuer
    _payload_sha256: str
    _seal: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("TelemetryPayload has no caller-usable constructor")

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("TelemetryPayload is immutable")
        object.__setattr__(self, name, value)


@final
class _PayloadIssuer:
    __slots__ = ("_key", "_key_check")

    _key: bytes
    _key_check: bytes

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("payload issuer has no caller-usable constructor")

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("payload issuer is immutable")
        object.__setattr__(self, name, value)

    def _intact(self) -> bool:
        try:
            return (
                type(self) is _PayloadIssuer
                and type(self._key) is bytes
                and len(self._key) == 32
                and hashlib.sha256(self._key).digest() == self._key_check
            )
        except Exception:
            return False

    def verify(
        self,
        payload: _TelemetryPayload,
        canonical_bytes: object,
        payload_sha256: object,
        seal: object,
    ) -> bool:
        if (
            not self._intact()
            or type(canonical_bytes) is not bytes
            or type(payload_sha256) is not str
            or not _is_lower_hex(payload_sha256, _LOWER_HEX_64)
            or type(seal) is not str
            or not _is_lower_hex(seal, _LOWER_HEX_64)
        ):
            return False
        material = (
            str(id(payload)).encode("ascii")
            + b"\0"
            + payload_sha256.encode("ascii")
            + b"\0"
            + canonical_bytes
        )
        expected = hmac.new(self._key, material, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, seal)


def _record_from_draft(
    draft: TelemetryDraft,
    trace: TraceContext,
    occurred_at: datetime,
) -> TelemetryRecord:
    severity, safe_message = _EVENT_POLICY[draft.event_code]
    placeholder = TelemetryRecord.__new__(TelemetryRecord)
    values: tuple[object, ...] = (
        CONTRACT_SCHEMA_VERSION,
        "0" * 64,
        occurred_at,
        draft.event_code,
        severity,
        safe_message,
        TelemetryDataClass.INTERNAL_METADATA,
        trace,
        draft.measurements,
    )
    for field, value in zip(fields(TelemetryRecord), values, strict=True):
        object.__setattr__(placeholder, field.name, value)
    record_id = _record_id_for(placeholder)
    return TelemetryRecord(
        schema_version=CONTRACT_SCHEMA_VERSION,
        record_id=record_id,
        occurred_at=occurred_at,
        event_code=draft.event_code,
        severity=severity,
        safe_message=safe_message,
        data_class=TelemetryDataClass.INTERNAL_METADATA,
        trace=trace,
        measurements=draft.measurements,
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


@final
class TelemetryEmitter:
    __slots__ = (
        "_authority",
        "_authority_verify",
        "_clock",
        "_clock_call",
        "_payload_issuer",
        "_sink_calls",
        "_sinks",
        "_wiring_seal",
    )

    _authority: TraceAuthority
    _authority_verify: Callable[[object], bool]
    _clock: object
    _clock_call: Callable[[], object]
    _payload_issuer: _PayloadIssuer
    _sink_calls: tuple[Callable[[object], object], ...]
    _sinks: tuple[object, ...]
    _wiring_seal: tuple[object, ...]

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("TelemetryEmitter is immutable")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        trace_authority: TraceAuthority,
        clock: object,
        sinks: tuple[object, ...],
    ) -> None:
        failed = False
        authority_verify: object = None
        clock_call: object = None
        sink_calls: tuple[Callable[[object], object], ...] = ()
        try:
            if (
                type(trace_authority) is not TraceAuthority
                or type(sinks) is not tuple
                or len(sinks) > _MAX_SINKS
                or len({id(sink) for sink in sinks}) != len(sinks)
            ):
                failed = True
            else:
                authority_verify = trace_authority.verify
                clock_call = cast(Any, clock).now_utc
                sink_calls = tuple(cast(Any, sink).emit for sink in sinks)
                if not trace_authority._intact():
                    failed = True
                issuer_key = hmac.new(
                    trace_authority._key,
                    b"securecode-telemetry-payload-v1",
                    hashlib.sha256,
                ).digest()
                issuer = object.__new__(_PayloadIssuer)
                object.__setattr__(issuer, "_key", issuer_key)
                object.__setattr__(issuer, "_key_check", hashlib.sha256(issuer_key).digest())
                if (
                    not callable(authority_verify)
                    or not callable(clock_call)
                    or not all(callable(call) for call in sink_calls)
                ):
                    failed = True
        except Exception:
            failed = True
        if failed:
            raise _boundary(TelemetryBoundaryErrorCode.REGISTRY_INVALID)
        object.__setattr__(self, "_authority", trace_authority)
        object.__setattr__(self, "_authority_verify", authority_verify)
        object.__setattr__(self, "_clock", clock)
        object.__setattr__(self, "_clock_call", clock_call)
        object.__setattr__(self, "_sinks", sinks)
        object.__setattr__(self, "_sink_calls", sink_calls)
        object.__setattr__(self, "_payload_issuer", issuer)
        object.__setattr__(self, "_wiring_seal", self._seal())

    def _seal(self) -> tuple[object, ...]:
        return (
            id(self._authority),
            id(self._authority_verify),
            id(self._clock),
            id(self._clock_call),
            tuple(id(sink) for sink in self._sinks),
            tuple(id(call) for call in self._sink_calls),
            id(self._payload_issuer),
        )

    def _intact(self) -> bool:
        try:
            return (
                type(self) is TelemetryEmitter
                and type(self._authority) is TraceAuthority
                and self._authority._intact()
                and type(self._sinks) is tuple
                and type(self._sink_calls) is tuple
                and len(self._sinks) == len(self._sink_calls)
                and type(self._payload_issuer) is _PayloadIssuer
                and self._payload_issuer._intact()
                and self._wiring_seal == self._seal()
            )
        except Exception:
            return False

    @staticmethod
    def _result(
        status: TelemetryEmitStatus,
        reason: TelemetryEmitReason,
        record_sha256: str | None = None,
        attempted: int = 0,
        emitted: int = 0,
        failed: int = 0,
    ) -> TelemetryEmitResult:
        return TelemetryEmitResult(
            status=status,
            record_sha256=record_sha256,
            attempted_sink_count=attempted,
            emitted_sink_count=emitted,
            failed_sink_count=failed,
            reason_code=reason,
        )

    def emit(
        self,
        draft: TelemetryDraft,
        trace_authorization: TraceAuthorization,
    ) -> TelemetryEmitResult:
        if not self._intact():
            return self._result(TelemetryEmitStatus.REJECTED, TelemetryEmitReason.INVALID_WIRING)
        authority_verify = self._authority_verify
        clock_call = self._clock_call
        payload_issuer = self._payload_issuer
        sink_calls = self._sink_calls
        try:
            validated_draft = _revalidate_draft(draft)
        except Exception:
            return self._result(TelemetryEmitStatus.REJECTED, TelemetryEmitReason.INVALID_RECORD)
        try:
            if type(trace_authorization) is not TraceAuthorization:
                raise TypeError
            authorization_snapshot = TraceAuthorization(
                context=_revalidate_trace(trace_authorization.context),
                authorization_sha256=trace_authorization.authorization_sha256,
            )
            authorized = authority_verify(authorization_snapshot)
        except Exception:
            authorized = False
        if authorized is not True:
            return self._result(
                TelemetryEmitStatus.REJECTED,
                TelemetryEmitReason.INVALID_TRACE_AUTHORIZATION,
            )
        if not self._intact():
            return self._result(TelemetryEmitStatus.REJECTED, TelemetryEmitReason.INVALID_WIRING)
        clock_failed = False
        occurred_at: object = None
        try:
            occurred_at = clock_call()
        except Exception:
            clock_failed = True
        if not self._intact():
            return self._result(TelemetryEmitStatus.REJECTED, TelemetryEmitReason.INVALID_WIRING)
        try:
            if _revalidate_draft(draft) != validated_draft:
                raise ValueError
        except Exception:
            return self._result(TelemetryEmitStatus.REJECTED, TelemetryEmitReason.INVALID_RECORD)
        try:
            current_authorization = TraceAuthorization(
                context=_revalidate_trace(trace_authorization.context),
                authorization_sha256=trace_authorization.authorization_sha256,
            )
            if current_authorization != authorization_snapshot:
                raise ValueError
            still_authorized = authority_verify(current_authorization)
        except Exception:
            still_authorized = False
        if still_authorized is not True:
            return self._result(
                TelemetryEmitStatus.REJECTED,
                TelemetryEmitReason.INVALID_TRACE_AUTHORIZATION,
            )
        if (
            clock_failed
            or type(occurred_at) is not datetime
            or occurred_at.tzinfo is not UTC
            or occurred_at.utcoffset() != timedelta(0)
        ):
            return self._result(TelemetryEmitStatus.FAILED, TelemetryEmitReason.CLOCK_FAILURE)
        try:
            record = _record_from_draft(
                validated_draft,
                authorization_snapshot.context,
                occurred_at,
            )
            canonical_bytes = canonical_telemetry_bytes(record)
            if len(canonical_bytes) > _MAX_PAYLOAD_BYTES:
                raise ValueError
            payload_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
        except Exception:
            return self._result(TelemetryEmitStatus.REJECTED, TelemetryEmitReason.INVALID_RECORD)
        if not sink_calls:
            return self._result(
                TelemetryEmitStatus.FAILED,
                TelemetryEmitReason.NO_SINKS,
                payload_sha256,
            )
        try:
            if not payload_issuer._intact():
                raise TypeError
            payload = object.__new__(_TelemetryPayload)
            object.__setattr__(payload, "_issuer", payload_issuer)
            object.__setattr__(payload, "_canonical_bytes", canonical_bytes)
            object.__setattr__(payload, "_payload_sha256", payload_sha256)
            material = (
                str(id(payload)).encode("ascii")
                + b"\0"
                + payload_sha256.encode("ascii")
                + b"\0"
                + canonical_bytes
            )
            object.__setattr__(
                payload,
                "_seal",
                hmac.new(payload_issuer._key, material, hashlib.sha256).hexdigest(),
            )
        except Exception:
            return self._result(TelemetryEmitStatus.REJECTED, TelemetryEmitReason.INVALID_WIRING)
        emitted = 0
        for sink_call in sink_calls:
            try:
                result = sink_call(payload)
            except (KeyboardInterrupt, SystemExit, GeneratorExit):
                raise
            except Exception:
                continue
            if result is None:
                emitted += 1
        attempted = len(sink_calls)
        failed = attempted - emitted
        if emitted == attempted:
            status = TelemetryEmitStatus.EMITTED
            reason = TelemetryEmitReason.NONE
        elif emitted:
            status = TelemetryEmitStatus.PARTIAL
            reason = TelemetryEmitReason.SINK_FAILURE
        else:
            status = TelemetryEmitStatus.FAILED
            reason = TelemetryEmitReason.SINK_FAILURE
        return self._result(
            status,
            reason,
            payload_sha256,
            attempted,
            emitted,
            failed,
        )


def _build_payload_opener(
    emit_method: Callable[
        [TelemetryEmitter, TelemetryDraft, TraceAuthorization], TelemetryEmitResult
    ],
) -> Callable[[object], tuple[bytes, str]]:
    """Bind payload admission to the real synchronous emitter execution frame."""

    emit_function = cast(Any, emit_method)
    emit_code = emit_function.__code__
    emit_globals: dict[str, object] = emit_function.__globals__
    emit_builtins: dict[str, object] = emit_function.__builtins__
    if emit_function.__closure__ is not None or emit_code.co_freevars:
        raise RuntimeError("telemetry emitter provenance is invalid")
    global_names = tuple(
        dict.fromkeys(
            instruction.argval
            for instruction in get_instructions(emit_code)
            if instruction.opname == "LOAD_GLOBAL" and type(instruction.argval) is str
        )
    )
    resolutions = tuple(
        (
            name,
            name in emit_globals,
            emit_globals.get(name),
            name in emit_builtins,
            emit_builtins.get(name),
        )
        for name in global_names
    )
    current_frame = sys._getframe
    payload_type = _TelemetryPayload
    issuer_type = _PayloadIssuer
    emitter_type = TelemetryEmitter
    exact_type = type
    bytes_type = bytes
    exact_len = len
    caught_exception = Exception
    invalid_payload = TelemetryBoundaryErrorCode.SINK_PAYLOAD_INVALID
    boundary = _boundary
    lower_hex = _is_lower_hex
    lower_hex_64 = _LOWER_HEX_64
    max_payload_bytes = _MAX_PAYLOAD_BYTES
    sha256 = hashlib.sha256
    parse = parse_telemetry_bytes

    def open_payload(payload: object) -> tuple[bytes, str]:
        failed = False
        canonical_bytes: object = None
        payload_sha256: object = None
        seal: object = None
        issuer: object = None
        try:
            if exact_type(payload) is not payload_type:
                failed = True
            else:
                payload_value = cast(_TelemetryPayload, payload)
                canonical_bytes = payload_value._canonical_bytes
                payload_sha256 = payload_value._payload_sha256
                seal = payload_value._seal
                issuer = payload_value._issuer
        except caught_exception:
            failed = True

        provenance_valid = False
        expected_issuer: object = None
        frame: FrameType | None = current_frame(1)
        try:
            while frame is not None:
                if frame.f_code is emit_code:
                    environment_valid = (
                        frame.f_globals is emit_globals
                        and frame.f_builtins is emit_builtins
                        and not emit_code.co_freevars
                    )
                    if environment_valid:
                        for (
                            name,
                            global_present,
                            global_value,
                            builtin_present,
                            builtin_value,
                        ) in resolutions:
                            if global_present:
                                if (
                                    name not in frame.f_globals
                                    or frame.f_globals[name] is not global_value
                                ):
                                    environment_valid = False
                                    break
                            elif name in frame.f_globals:
                                environment_valid = False
                                break
                            elif builtin_present:
                                if (
                                    name not in frame.f_builtins
                                    or frame.f_builtins[name] is not builtin_value
                                ):
                                    environment_valid = False
                                    break
                            elif name in frame.f_builtins:
                                environment_valid = False
                                break
                    if environment_valid:
                        emitter = frame.f_locals.get("self")
                        if exact_type(emitter) is emitter_type:
                            emitter_value = cast(TelemetryEmitter, emitter)
                            provenance_valid = (
                                emitter_value._intact() and frame.f_locals.get("payload") is payload
                            )
                            if provenance_valid:
                                expected_issuer = emitter_value._payload_issuer
                    break
                frame = frame.f_back
        except caught_exception:
            provenance_valid = False
        finally:
            frame = None

        if (
            failed
            or not provenance_valid
            or exact_type(issuer) is not issuer_type
            or issuer is not expected_issuer
            or exact_type(canonical_bytes) is not bytes_type
            or not 1 <= exact_len(cast(bytes, canonical_bytes)) <= max_payload_bytes
            or not lower_hex(payload_sha256, lower_hex_64)
            or not lower_hex(seal, lower_hex_64)
        ):
            raise boundary(invalid_payload)
        validated_payload = cast(_TelemetryPayload, payload)
        validated_issuer = cast(_PayloadIssuer, issuer)
        validated_bytes = cast(bytes, canonical_bytes)
        validated_sha256 = cast(str, payload_sha256)
        validated_seal = cast(str, seal)
        if (
            not validated_issuer.verify(
                validated_payload,
                validated_bytes,
                validated_sha256,
                validated_seal,
            )
            or sha256(validated_bytes).hexdigest() != validated_sha256
        ):
            raise boundary(invalid_payload)
        try:
            parse(validated_bytes)
        except caught_exception:
            failed = True
        if failed:
            raise boundary(invalid_payload)
        return validated_bytes, validated_sha256

    return open_payload


open_telemetry_payload = _build_payload_opener(TelemetryEmitter.emit)
del _build_payload_opener


__all__ = [
    "TelemetryBoundaryError",
    "TelemetryBoundaryErrorCode",
    "TelemetryClock",
    "TelemetryDataClass",
    "TelemetryDraft",
    "TelemetryEmitReason",
    "TelemetryEmitResult",
    "TelemetryEmitStatus",
    "TelemetryEmitter",
    "TelemetryEventCode",
    "TelemetryMeasurement",
    "TelemetryMeasurementName",
    "TelemetryRecord",
    "TelemetrySeverity",
    "TelemetrySink",
    "TraceAuthority",
    "TraceAuthorization",
    "TraceContext",
    "TraceIdSource",
    "canonical_telemetry_bytes",
    "open_telemetry_payload",
    "parse_telemetry_bytes",
]
