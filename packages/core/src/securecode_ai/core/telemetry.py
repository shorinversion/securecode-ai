"""Fail-closed, framework-independent foundation telemetry primitives."""

from __future__ import annotations

import hashlib as hashlib
import hmac as hmac
from datetime import UTC as UTC
from datetime import datetime as datetime
from datetime import timedelta as timedelta

from .telemetry_authority import TraceAuthority
from .telemetry_emitter import (
    TelemetryEmitter,
)
from .telemetry_emitter import (
    _PayloadIssuer as _PayloadIssuer,
)
from .telemetry_emitter import (
    _record_from_draft as _record_from_draft,
)
from .telemetry_emitter import (
    _TelemetryPayload as _TelemetryPayload,
)
from .telemetry_opener import _build_payload_opener as _opener_factory
from .telemetry_parsing import (
    parse_telemetry_bytes,
)
from .telemetry_primitives import (
    _MAX_PAYLOAD_BYTES as _MAX_PAYLOAD_BYTES,
)
from .telemetry_primitives import (
    TelemetryBoundaryError,
    TelemetryBoundaryErrorCode,
    TelemetryClock,
    TelemetryDataClass,
    TelemetryDraft,
    TelemetryEmitReason,
    TelemetryEmitResult,
    TelemetryEmitStatus,
    TelemetryEventCode,
    TelemetryMeasurement,
    TelemetryMeasurementName,
    TelemetryRecord,
    TelemetrySeverity,
    TelemetrySink,
    TraceAuthorization,
    TraceContext,
    TraceIdSource,
    _canonical_json,
    _record_document,
    _revalidate_record,
)
from .telemetry_primitives import (
    _revalidate_draft as _revalidate_draft,
)
from .telemetry_primitives import (
    _revalidate_trace as _revalidate_trace,
)

for _telemetry_type in (
    TelemetryBoundaryError,
    TelemetryDraft,
    TelemetryEmitResult,
    TelemetryEmitter,
    TelemetryMeasurement,
    TelemetryRecord,
    TraceAuthority,
    TraceAuthorization,
    TraceContext,
):
    _telemetry_type.__module__ = __name__
del _telemetry_type


def canonical_telemetry_bytes(value: TelemetryRecord) -> bytes:
    """Snapshot and render an exact internal telemetry record as canonical JSONL."""

    validated = _revalidate_record(value)
    return _canonical_json(_record_document(validated, include_record_id=True), terminal_lf=True)


open_telemetry_payload = _opener_factory(TelemetryEmitter.emit, facade_globals=globals())
del _opener_factory

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
