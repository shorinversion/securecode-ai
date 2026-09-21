"""Fail-closed, framework-independent foundation telemetry primitives."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from dataclasses import fields
from datetime import UTC, datetime, timedelta
from typing import Any, cast, final

from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION

from .telemetry_authority import TraceAuthority
from .telemetry_primitives import (
    _EVENT_POLICY,
    _LOWER_HEX_64,
    _MAX_PAYLOAD_BYTES,
    _MAX_SINKS,
    TelemetryBoundaryErrorCode,
    TelemetryDataClass,
    TelemetryDraft,
    TelemetryEmitReason,
    TelemetryEmitResult,
    TelemetryEmitStatus,
    TelemetryRecord,
    TraceAuthorization,
    TraceContext,
    _boundary,
    _is_lower_hex,
    _record_id_for,
    _revalidate_draft,
    _revalidate_trace,
    canonical_telemetry_bytes,
)


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
