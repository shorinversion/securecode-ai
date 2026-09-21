"""Fail-closed, framework-independent foundation telemetry primitives."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import cast

from .telemetry_primitives import (
    _MAX_PAYLOAD_BYTES,
    TelemetryDataClass,
    TelemetryEventCode,
    TelemetryMeasurement,
    TelemetryMeasurementName,
    TelemetryRecord,
    TelemetrySeverity,
    TraceContext,
    _canonical_json,
    _trace_document,
    canonical_telemetry_bytes,
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
