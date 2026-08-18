"""Fail-closed telemetry emission, payload-capability, and adapter matrices."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta, timezone
from threading import Barrier, BrokenBarrierError, Lock, Thread, local
from types import FunctionType
from typing import Any, cast

import pytest
from securecode_ai.adapters import (
    BinaryStreamTelemetrySink,
    InMemoryTelemetrySink,
    SystemTraceIdSource,
    SystemUTCClock,
)
from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION
from securecode_ai.core import (
    TelemetryBoundaryError,
    TelemetryBoundaryErrorCode,
    TelemetryDraft,
    TelemetryEmitReason,
    TelemetryEmitResult,
    TelemetryEmitStatus,
    TelemetryEmitter,
    TelemetryEventCode,
    TelemetryMeasurement,
    TelemetryMeasurementName,
    TraceAuthority,
    TraceAuthorization,
    TraceContext,
    open_telemetry_payload,
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


class FixedClock:
    def __init__(self, value: object) -> None:
        self.value = value
        self.calls = 0

    def now_utc(self) -> object:
        self.calls += 1
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


class CapturingSink:
    def __init__(self, result: object = None) -> None:
        self.calls = 0
        self.payloads: list[object] = []
        self.result = result

    def emit(self, payload: object) -> object:
        self.calls += 1
        self.payloads.append(payload)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class OpeningSink(CapturingSink):
    def __init__(self) -> None:
        super().__init__()
        self.opened: list[tuple[bytes, str]] = []

    def emit(self, payload: object) -> None:
        super().emit(payload)
        self.opened.append(open_telemetry_payload(payload))


class ProbingSink:
    def __init__(self, action: Callable[[object], object]) -> None:
        self.action = action
        self.errors: list[Exception] = []
        self.results: list[object] = []

    def emit(self, payload: object) -> None:
        try:
            self.results.append(self.action(payload))
        except Exception as error:
            self.errors.append(error)


class BinaryStream:
    def __init__(
        self,
        writes: list[object] | None = None,
        flush_result: object = None,
    ) -> None:
        self.buffer = bytearray()
        self.flush_calls = 0
        self.write_calls = 0
        self.writes = list(writes or [])
        self.flush_result = flush_result

    def write(self, value: bytes) -> object:
        self.write_calls += 1
        if self.writes:
            result = self.writes.pop(0)
            if isinstance(result, BaseException):
                raise result
            if type(result) is int and 0 < result <= len(value):
                self.buffer.extend(value[:result])
            return result
        self.buffer.extend(value)
        return len(value)

    def flush(self) -> object:
        self.flush_calls += 1
        if isinstance(self.flush_result, BaseException):
            raise self.flush_result
        return self.flush_result


def foundation() -> tuple[TraceAuthority, TraceAuthorization, FixedClock]:
    source = SequenceSource(bytes(range(32)), b"\x01" * 16, b"\x02" * 8)
    authority = TraceAuthority.create(source)  # type: ignore[arg-type]
    return authority, authority.issue_root(), FixedClock(datetime(2026, 1, 2, tzinfo=UTC))


def draft() -> TelemetryDraft:
    return TelemetryDraft(
        TelemetryEventCode.FOUNDATION_STARTED,
        (
            TelemetryMeasurement(
                CONTRACT_SCHEMA_VERSION,
                TelemetryMeasurementName.ITEM_COUNT,
                2,
            ),
        ),
    )


def captured_payload() -> object:
    authority, authorization, clock = foundation()
    sink = CapturingSink()
    result = TelemetryEmitter(authority, clock, (sink,)).emit(draft(), authorization)
    assert result.status is TelemetryEmitStatus.EMITTED
    return sink.payloads[0]


def emit_to_sink(sink: object) -> TelemetryEmitResult:
    authority, authorization, clock = foundation()
    return TelemetryEmitter(authority, clock, (sink,)).emit(draft(), authorization)


@pytest.mark.parametrize(
    ("event_code", "severity", "safe_message"),
    [
        (TelemetryEventCode.FOUNDATION_STARTED, "INFO", "foundation operation started"),
        (
            TelemetryEventCode.FOUNDATION_COMPLETED,
            "INFO",
            "foundation operation completed",
        ),
        (
            TelemetryEventCode.FOUNDATION_NON_SUCCESS,
            "WARNING",
            "foundation operation did not complete successfully",
        ),
        (
            TelemetryEventCode.FOUNDATION_DENIED,
            "WARNING",
            "foundation operation was denied",
        ),
        (TelemetryEventCode.FOUNDATION_FAILED, "ERROR", "foundation operation failed"),
    ],
)
def test_event_policy_is_closed(
    event_code: TelemetryEventCode,
    severity: str,
    safe_message: str,
) -> None:
    authority, authorization, clock = foundation()
    sink = InMemoryTelemetrySink()
    result = TelemetryEmitter(authority, clock, (sink,)).emit(
        TelemetryDraft(event_code), authorization
    )
    assert result.status is TelemetryEmitStatus.EMITTED
    record = parse_telemetry_bytes(sink.records[0][0])
    assert record.severity.value == severity
    assert record.safe_message == safe_message
    assert record.data_class.value == "DC1_INTERNAL_METADATA"


@pytest.mark.parametrize("sink_count", [1, 2, 3])
def test_multi_sink_fanout_uses_one_payload_and_identical_snapshots(sink_count: int) -> None:
    authority, authorization, clock = foundation()
    sinks = tuple(OpeningSink() for _ in range(sink_count))
    result = TelemetryEmitter(authority, clock, sinks).emit(draft(), authorization)
    assert result.status is TelemetryEmitStatus.EMITTED
    assert result.reason_code is TelemetryEmitReason.NONE
    assert result.attempted_sink_count == sink_count
    assert result.emitted_sink_count == sink_count
    assert result.failed_sink_count == 0
    payloads = [sink.payloads[0] for sink in sinks]
    assert all(payload is payloads[0] for payload in payloads)
    opened = [sink.opened[0] for sink in sinks]
    assert len(set(opened)) == 1
    assert opened[0][1] == result.record_sha256


@pytest.mark.parametrize(
    ("results", "status", "emitted", "failed"),
    [
        ((None,), TelemetryEmitStatus.EMITTED, 1, 0),
        ((None, False), TelemetryEmitStatus.PARTIAL, 1, 1),
        ((True, 1, b"x", object()), TelemetryEmitStatus.FAILED, 0, 4),
        ((RuntimeError("API_KEY=RAW-CANARY"),), TelemetryEmitStatus.FAILED, 0, 1),
    ],
)
def test_exact_sink_runtime_return_matrix(
    results: tuple[object, ...],
    status: TelemetryEmitStatus,
    emitted: int,
    failed: int,
) -> None:
    authority, authorization, clock = foundation()
    sinks = tuple(CapturingSink(result) for result in results)
    outcome = TelemetryEmitter(authority, clock, sinks).emit(draft(), authorization)
    assert outcome.status is status
    assert outcome.emitted_sink_count == emitted
    assert outcome.failed_sink_count == failed
    assert all(sink.calls == 1 for sink in sinks)
    assert "CANARY" not in repr(outcome)


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt(), SystemExit(), GeneratorExit()])
def test_base_exception_propagates_and_stops_fanout(interrupt: BaseException) -> None:
    authority, authorization, clock = foundation()
    first = CapturingSink(interrupt)
    second = CapturingSink()
    with pytest.raises(type(interrupt)):
        TelemetryEmitter(authority, clock, (first, second)).emit(draft(), authorization)
    assert first.calls == 1
    assert second.calls == 0


def test_zero_sinks_has_hash_but_no_attempts() -> None:
    authority, authorization, clock = foundation()
    result = TelemetryEmitter(authority, clock, ()).emit(draft(), authorization)
    assert result.status is TelemetryEmitStatus.FAILED
    assert result.reason_code is TelemetryEmitReason.NO_SINKS
    assert result.record_sha256 is not None
    assert result.attempted_sink_count == 0


@pytest.mark.parametrize(
    "clock_value",
    [
        None,
        True,
        datetime(2026, 1, 2, tzinfo=UTC).replace(tzinfo=None),
        datetime(2026, 1, 2, tzinfo=timezone(timedelta(hours=1))),
        RuntimeError("clock canary"),
    ],
)
def test_clock_failure_is_typed_and_calls_no_sink(clock_value: object) -> None:
    authority, authorization, _ = foundation()
    clock = FixedClock(clock_value)
    sink = CapturingSink()
    result = TelemetryEmitter(authority, clock, (sink,)).emit(draft(), authorization)
    assert result.status is TelemetryEmitStatus.FAILED
    assert result.reason_code is TelemetryEmitReason.CLOCK_FAILURE
    assert result.record_sha256 is None
    assert sink.calls == 0
    assert "canary" not in repr(result)


def test_invalid_authorization_precedes_clock_and_sinks() -> None:
    authority, authorization, clock = foundation()
    object.__setattr__(authorization, "authorization_sha256", "f" * 64)
    sink = CapturingSink()
    result = TelemetryEmitter(authority, clock, (sink,)).emit(draft(), authorization)
    assert result.status is TelemetryEmitStatus.REJECTED
    assert result.reason_code is TelemetryEmitReason.INVALID_TRACE_AUTHORIZATION
    assert result.record_sha256 is None
    assert clock.calls == 0
    assert sink.calls == 0


def test_clock_cannot_change_verified_trace_after_admission() -> None:
    authority, authorization, _ = foundation()

    class MutatingClock:
        def now_utc(self) -> datetime:
            object.__setattr__(
                authorization,
                "context",
                TraceContext(
                    CONTRACT_SCHEMA_VERSION,
                    "a" * 32,
                    "b" * 16,
                    None,
                ),
            )
            return datetime(2026, 1, 2, tzinfo=UTC)

    sink = InMemoryTelemetrySink()
    result = TelemetryEmitter(authority, MutatingClock(), (sink,)).emit(draft(), authorization)
    assert result.status is TelemetryEmitStatus.REJECTED
    assert result.reason_code is TelemetryEmitReason.INVALID_TRACE_AUTHORIZATION
    assert result.record_sha256 is None
    assert not authority.verify(authorization)
    assert sink.records == ()


@pytest.mark.parametrize("mutated_value", [777, -1])
def test_clock_cannot_change_nested_measurement_after_admission(
    mutated_value: int,
) -> None:
    authority, authorization, _ = foundation()
    value = draft()
    retained_measurement = value.measurements[0]

    class MutatingClock:
        def now_utc(self) -> datetime:
            object.__setattr__(retained_measurement, "value", mutated_value)
            return datetime(2026, 1, 2, tzinfo=UTC)

    sink = InMemoryTelemetrySink()
    result = TelemetryEmitter(authority, MutatingClock(), (sink,)).emit(value, authorization)
    assert result.status is TelemetryEmitStatus.REJECTED
    assert result.reason_code is TelemetryEmitReason.INVALID_RECORD
    assert result.record_sha256 is None
    assert sink.records == ()


def test_clock_cannot_corrupt_retained_trace_authority_before_emission() -> None:
    authority, authorization, _ = foundation()

    class MutatingClock:
        def now_utc(self) -> datetime:
            object.__setattr__(authority, "_key", b"x" * 32)
            return datetime(2026, 1, 2, tzinfo=UTC)

    sink = InMemoryTelemetrySink()
    result = TelemetryEmitter(authority, MutatingClock(), (sink,)).emit(draft(), authorization)
    assert result.status is TelemetryEmitStatus.REJECTED
    assert result.reason_code is TelemetryEmitReason.INVALID_WIRING
    assert result.record_sha256 is None
    assert not authority.verify(authorization)
    assert sink.records == ()


def test_source_cannot_change_parent_snapshot_used_by_child() -> None:
    class ParentMutatingSource:
        def __init__(self) -> None:
            self.calls: list[int] = []
            self.parent: TraceAuthorization | None = None

        def token_bytes(self, length: int) -> bytes:
            self.calls.append(length)
            if self.calls == [32]:
                return bytes(range(32))
            if self.calls == [32, 16]:
                return b"\x01" * 16
            if self.calls == [32, 16, 8]:
                return b"\x02" * 8
            assert self.parent is not None
            object.__setattr__(
                self.parent,
                "context",
                TraceContext(CONTRACT_SCHEMA_VERSION, "a" * 32, "b" * 16, None),
            )
            return b"\x03" * length

    source = ParentMutatingSource()
    authority = TraceAuthority.create(source)
    parent = authority.issue_root()
    admitted_context = parent.context
    source.parent = parent
    child = authority.issue_child(parent)
    assert not authority.verify(parent)
    assert child.context.trace_id == admitted_context.trace_id
    assert child.context.parent_span_id == admitted_context.span_id
    assert authority.verify(child)


@pytest.mark.parametrize("field_name", ["event_code", "measurements"])
def test_invalid_retained_draft_precedes_authority_clock_and_sinks(field_name: str) -> None:
    authority, authorization, clock = foundation()
    value = draft()
    object.__setattr__(value, field_name, "API_KEY=RAW-CANARY")
    sink = CapturingSink()
    result = TelemetryEmitter(authority, clock, (sink,)).emit(value, authorization)
    assert result.status is TelemetryEmitStatus.REJECTED
    assert result.reason_code is TelemetryEmitReason.INVALID_RECORD
    assert clock.calls == 0
    assert sink.calls == 0
    assert "CANARY" not in repr(result)


@pytest.mark.parametrize(
    "field_name",
    [
        "_authority",
        "_authority_verify",
        "_clock",
        "_clock_call",
        "_sinks",
        "_sink_calls",
        "_payload_issuer",
        "_wiring_seal",
    ],
)
def test_emitter_wiring_mutation_is_zero_effect(field_name: str) -> None:
    authority, authorization, clock = foundation()
    sink = CapturingSink()
    emitter = TelemetryEmitter(authority, clock, (sink,))
    object.__setattr__(emitter, field_name, object())
    result = emitter.emit(draft(), authorization)
    assert result.status is TelemetryEmitStatus.REJECTED
    assert result.reason_code is TelemetryEmitReason.INVALID_WIRING
    assert result.record_sha256 is None
    assert result.attempted_sink_count == 0
    assert clock.calls == 0
    assert sink.calls == 0


def test_clock_reentrant_wiring_replacement_stops_before_any_sink() -> None:
    authority, authorization, _ = foundation()
    registered = CapturingSink()
    alternate = CapturingSink()

    class RewiringClock:
        emitter: TelemetryEmitter

        def now_utc(self) -> datetime:
            object.__setattr__(self.emitter, "_sink_calls", (alternate.emit,))
            return datetime(2026, 1, 2, tzinfo=UTC)

    clock = RewiringClock()
    emitter = TelemetryEmitter(authority, clock, (registered,))
    clock.emitter = emitter
    result = emitter.emit(draft(), authorization)
    assert result.status is TelemetryEmitStatus.REJECTED
    assert result.reason_code is TelemetryEmitReason.INVALID_WIRING
    assert result.attempted_sink_count == 0
    assert registered.calls == 0
    assert alternate.calls == 0


@pytest.mark.parametrize("invalid", [b"API_KEY=RAW-CANARY", bytearray(b"x"), object(), None])
@pytest.mark.parametrize("sink_kind", ["memory", "stream"])
def test_first_party_sinks_reject_direct_raw_payload_without_effect(
    invalid: object,
    sink_kind: str,
) -> None:
    stream = BinaryStream()
    sink: Any = (
        InMemoryTelemetrySink() if sink_kind == "memory" else BinaryStreamTelemetrySink(stream)
    )
    with pytest.raises(TelemetryBoundaryError) as captured:
        sink.emit(invalid)
    assert captured.value.code is TelemetryBoundaryErrorCode.SINK_PAYLOAD_INVALID
    assert stream.write_calls == 0
    assert stream.flush_calls == 0
    if sink_kind == "memory":
        assert sink.records == ()


@pytest.mark.parametrize("sink_kind", ["memory", "stream"])
def test_first_party_sinks_reject_legacy_bytes_hash_pair_without_effect(
    sink_kind: str,
) -> None:
    stream = BinaryStream()
    sink: Any = (
        InMemoryTelemetrySink() if sink_kind == "memory" else BinaryStreamTelemetrySink(stream)
    )
    raw = b"API_KEY=RAW-CANARY"
    with pytest.raises(TelemetryBoundaryError) as captured:
        sink.emit(raw, hashlib.sha256(raw).hexdigest())
    assert captured.value.code is TelemetryBoundaryErrorCode.SINK_PAYLOAD_INVALID
    assert stream.write_calls == 0
    assert stream.flush_calls == 0
    if sink_kind == "memory":
        assert sink.records == ()


def test_copied_payload_fails_identity_seal() -> None:
    sink = InMemoryTelemetrySink()

    def attempt(original: object) -> None:
        copied = copy.copy(original)
        assert copied is not original
        sink.emit(copied)

    probe = ProbingSink(attempt)
    assert emit_to_sink(probe).status is TelemetryEmitStatus.EMITTED
    assert len(probe.errors) == 1
    assert isinstance(probe.errors[0], TelemetryBoundaryError)
    assert probe.errors[0].code is TelemetryBoundaryErrorCode.SINK_PAYLOAD_INVALID
    assert sink.records == ()


def test_resealed_payload_copy_is_not_an_issued_capability() -> None:
    sink = InMemoryTelemetrySink()

    def attempt(original: object) -> None:
        copied = copy.copy(original)
        issuer: Any = cast(Any, original)._issuer
        canonical_bytes: bytes = cast(Any, copied)._canonical_bytes
        payload_sha256: str = cast(Any, copied)._payload_sha256
        material = (
            str(id(copied)).encode("ascii")
            + b"\0"
            + payload_sha256.encode("ascii")
            + b"\0"
            + canonical_bytes
        )
        object.__setattr__(
            copied,
            "_seal",
            hmac.new(cast(Any, issuer)._key, material, hashlib.sha256).hexdigest(),
        )
        sink.emit(copied)

    probe = ProbingSink(attempt)
    assert emit_to_sink(probe).status is TelemetryEmitStatus.EMITTED
    assert len(probe.errors) == 1
    assert isinstance(probe.errors[0], TelemetryBoundaryError)
    assert probe.errors[0].code is TelemetryBoundaryErrorCode.SINK_PAYLOAD_INVALID
    assert sink.records == ()


def test_self_signed_exact_payload_with_unauthorized_trace_is_rejected() -> None:
    import securecode_ai.core.telemetry as telemetry_module

    sink = InMemoryTelemetrySink()
    observed_trace_ids: list[str] = []

    def attempt(original: object) -> None:
        canonical_bytes, _ = open_telemetry_payload(original)
        document = json.loads(canonical_bytes)
        document["trace"]["trace_id"] = "ab" * 16
        without_record_id = dict(document)
        del without_record_id["record_id"]
        document["record_id"] = hashlib.sha256(
            json.dumps(
                without_record_id,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        ).hexdigest()
        forged_bytes = (
            json.dumps(
                document,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        observed_trace_ids.append(parse_telemetry_bytes(forged_bytes).trace.trace_id)

        issuer: Any = object.__new__(telemetry_module._PayloadIssuer)
        issuer_key = b"k" * 32
        object.__setattr__(issuer, "_key", issuer_key)
        object.__setattr__(issuer, "_key_check", hashlib.sha256(issuer_key).digest())
        forged: Any = object.__new__(telemetry_module._TelemetryPayload)
        forged_sha256 = hashlib.sha256(forged_bytes).hexdigest()
        object.__setattr__(forged, "_issuer", issuer)
        object.__setattr__(forged, "_canonical_bytes", forged_bytes)
        object.__setattr__(forged, "_payload_sha256", forged_sha256)
        material = (
            str(id(forged)).encode("ascii")
            + b"\0"
            + forged_sha256.encode("ascii")
            + b"\0"
            + forged_bytes
        )
        object.__setattr__(
            forged,
            "_seal",
            hmac.new(issuer_key, material, hashlib.sha256).hexdigest(),
        )
        sink.emit(forged)

    probe = ProbingSink(attempt)
    assert emit_to_sink(probe).status is TelemetryEmitStatus.EMITTED
    assert observed_trace_ids == ["ab" * 16]
    assert len(probe.errors) == 1
    assert isinstance(probe.errors[0], TelemetryBoundaryError)
    assert probe.errors[0].code is TelemetryBoundaryErrorCode.SINK_PAYLOAD_INVALID
    assert sink.records == ()


def test_payload_expires_after_synchronous_fanout() -> None:
    payload = captured_payload()
    with pytest.raises(TelemetryBoundaryError) as captured:
        open_telemetry_payload(payload)
    assert captured.value.code is TelemetryBoundaryErrorCode.SINK_PAYLOAD_INVALID
    sink = InMemoryTelemetrySink()
    with pytest.raises(TelemetryBoundaryError) as captured:
        sink.emit(payload)
    assert captured.value.code is TelemetryBoundaryErrorCode.SINK_PAYLOAD_INVALID
    assert sink.records == ()


def test_cloned_emit_code_with_alternate_globals_cannot_issue_payload() -> None:
    import securecode_ai.core.telemetry as telemetry_module

    authority, authorization, clock = foundation()
    sink = InMemoryTelemetrySink()
    emitter = TelemetryEmitter(authority, clock, (sink,))
    cloned_emit = FunctionType(
        TelemetryEmitter.emit.__code__,
        dict(vars(telemetry_module)),
    )
    result = cloned_emit(emitter, draft(), authorization)
    assert result.status is TelemetryEmitStatus.FAILED
    assert result.reason_code is TelemetryEmitReason.SINK_FAILURE
    assert sink.records == ()


def test_builtin_shadow_in_real_globals_invalidates_payload_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import securecode_ai.core.telemetry as telemetry_module

    monkeypatch.setitem(vars(telemetry_module), "len", len)
    authority, authorization, clock = foundation()
    sink = InMemoryTelemetrySink()
    result = TelemetryEmitter(authority, clock, (sink,)).emit(draft(), authorization)
    assert result.status is TelemetryEmitStatus.FAILED
    assert result.reason_code is TelemetryEmitReason.SINK_FAILURE
    assert sink.records == ()


def test_payload_issuer_has_no_caller_usable_constructor() -> None:
    import securecode_ai.core.telemetry as telemetry_module

    assert not hasattr(telemetry_module, "_PAYLOAD_CONSTRUCTOR_TOKEN")
    assert not hasattr(telemetry_module, "_PAYLOAD_ISSUER_CONSTRUCTOR_TOKEN")
    assert not hasattr(telemetry_module, "_PAYLOAD_REGISTRY")
    assert not hasattr(telemetry_module, "_PAYLOAD_REGISTRY_LOCK")
    assert not hasattr(telemetry_module, "_bind_payload_emitter")
    assert not hasattr(telemetry_module, "_payload_capability_boundary")
    assert not hasattr(telemetry_module, "_build_payload_opener")
    with pytest.raises(TypeError):
        telemetry_module._PayloadIssuer(b"x" * 32)
    with pytest.raises(TypeError):
        telemetry_module._TelemetryPayload()

    authority, _, clock = foundation()
    emitter = TelemetryEmitter(authority, clock, (CapturingSink(),))
    assert not hasattr(emitter, "_payload_issue")
    assert not hasattr(type(cast(Any, emitter)._payload_issuer), "issue")
    assert not hasattr(type(cast(Any, emitter)._payload_issuer), "_seal")


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("_canonical_bytes", b"API_KEY=RAW-CANARY\n"),
        ("_payload_sha256", "f" * 64),
        ("_seal", "f" * 64),
        ("_issuer", object()),
    ],
)
def test_mutated_payload_fails_before_first_party_storage(
    field_name: str,
    replacement: object,
) -> None:
    sink = InMemoryTelemetrySink()

    def attempt(payload: object) -> None:
        object.__setattr__(payload, field_name, replacement)
        sink.emit(payload)

    probe = ProbingSink(attempt)
    assert emit_to_sink(probe).status is TelemetryEmitStatus.EMITTED
    assert len(probe.errors) == 1
    assert isinstance(probe.errors[0], TelemetryBoundaryError)
    assert probe.errors[0].code is TelemetryBoundaryErrorCode.SINK_PAYLOAD_INVALID
    assert sink.records == ()


def test_key_equivalent_issuer_replacement_fails_identity_admission() -> None:
    sink = InMemoryTelemetrySink()

    def attempt(payload: object) -> None:
        original: Any = cast(Any, payload)._issuer
        replacement: Any = object.__new__(type(original))
        object.__setattr__(replacement, "_key", original._key)
        object.__setattr__(replacement, "_key_check", original._key_check)
        object.__setattr__(payload, "_issuer", replacement)
        sink.emit(payload)

    probe = ProbingSink(attempt)
    assert emit_to_sink(probe).status is TelemetryEmitStatus.EMITTED
    assert len(probe.errors) == 1
    assert isinstance(probe.errors[0], TelemetryBoundaryError)
    assert probe.errors[0].code is TelemetryBoundaryErrorCode.SINK_PAYLOAD_INVALID
    assert sink.records == ()


def test_payload_mutation_after_opener_snapshot_cannot_change_written_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, authorization, clock = foundation()
    stream = BinaryStream()
    sink = BinaryStreamTelemetrySink(stream)
    emitter = TelemetryEmitter(authority, clock, (sink,))
    issuer: Any = cast(Any, emitter)._payload_issuer
    issuer_type: Any = type(issuer)
    original_verify = issuer_type.verify

    def mutate_after_snapshot(
        self: object,
        payload_value: object,
        canonical_bytes: object,
        payload_sha256: object,
        seal: object,
    ) -> bool:
        object.__setattr__(payload_value, "_canonical_bytes", b"API_KEY=RAW-CANARY\n")
        return bool(
            original_verify(
                self,
                payload_value,
                canonical_bytes,
                payload_sha256,
                seal,
            )
        )

    monkeypatch.setattr(issuer_type, "verify", mutate_after_snapshot)
    result = emitter.emit(draft(), authorization)
    assert result.status is TelemetryEmitStatus.EMITTED
    assert hashlib.sha256(stream.buffer).hexdigest() == result.record_sha256
    assert b"CANARY" not in stream.buffer


def test_payload_subclass_fails_exact_type_admission() -> None:
    sink = InMemoryTelemetrySink()

    def attempt(original: object) -> None:
        subclass: Any = type("ForgedPayload", (type(original),), {})
        forged: Any = object.__new__(subclass)
        original_type: Any = type(original)
        for name in original_type.__slots__:
            object.__setattr__(forged, name, getattr(original, name))
        sink.emit(forged)

    probe = ProbingSink(attempt)
    assert emit_to_sink(probe).status is TelemetryEmitStatus.EMITTED
    assert len(probe.errors) == 1
    assert isinstance(probe.errors[0], TelemetryBoundaryError)
    assert probe.errors[0].code is TelemetryBoundaryErrorCode.SINK_PAYLOAD_INVALID
    assert sink.records == ()


def test_binary_stream_short_writes_complete_then_flush_once() -> None:
    stream = BinaryStream([1, 2, 3])
    sink = BinaryStreamTelemetrySink(stream)
    result = emit_to_sink(sink)
    assert result.status is TelemetryEmitStatus.EMITTED
    assert hashlib.sha256(stream.buffer).hexdigest() == result.record_sha256
    assert stream.write_calls >= 4
    assert stream.flush_calls == 1


@pytest.mark.parametrize(
    "write_result",
    [0, -1, True, None, "1", b"1", 99_999, RuntimeError("write canary")],
)
def test_binary_stream_invalid_write_fails_without_flush(write_result: object) -> None:
    stream = BinaryStream([write_result])
    sink = BinaryStreamTelemetrySink(stream)
    result = emit_to_sink(sink)
    assert result.status is TelemetryEmitStatus.FAILED
    assert result.reason_code is TelemetryEmitReason.SINK_FAILURE
    assert stream.flush_calls == 0
    assert "canary" not in repr(result)


@pytest.mark.parametrize("flush_result", [False, True, 0, b"x", RuntimeError("flush canary")])
def test_binary_stream_invalid_flush_fails_after_complete_write(flush_result: object) -> None:
    stream = BinaryStream(flush_result=flush_result)
    sink = BinaryStreamTelemetrySink(stream)
    result = emit_to_sink(sink)
    assert result.status is TelemetryEmitStatus.FAILED
    assert result.reason_code is TelemetryEmitReason.SINK_FAILURE
    assert stream.write_calls == 1
    assert stream.flush_calls == 1
    assert "canary" not in repr(result)


class AccessorFailure:
    def __getattribute__(self, name: str) -> object:
        if name in {"write", "flush"}:
            raise RuntimeError("accessor API_KEY=RAW-CANARY")
        return super().__getattribute__(name)


def test_binary_stream_accessor_failure_is_fixed_and_context_free() -> None:
    with pytest.raises(TelemetryBoundaryError) as captured:
        BinaryStreamTelemetrySink(AccessorFailure())
    assert captured.value.code is TelemetryBoundaryErrorCode.STREAM_INVALID
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert "CANARY" not in repr(captured.value)


@pytest.mark.parametrize(
    "field_name",
    ["_active", "_write", "_flush", "_lock", "_wiring_seal"],
)
def test_binary_stream_wiring_mutation_precedes_payload_and_io(field_name: str) -> None:
    stream = BinaryStream()
    sink = BinaryStreamTelemetrySink(stream)
    object.__setattr__(sink, field_name, object())
    with pytest.raises(TelemetryBoundaryError) as captured:
        sink.emit(b"API_KEY=RAW-CANARY")
    assert captured.value.code is TelemetryBoundaryErrorCode.STREAM_INVALID
    assert stream.write_calls == 0
    assert stream.flush_calls == 0


@pytest.mark.parametrize("field_name", ["_write", "_flush"])
def test_binary_stream_reentrant_wiring_mutation_uses_no_alternate_io(
    field_name: str,
) -> None:
    primary = BinaryStream()
    alternate = BinaryStream()
    sink = BinaryStreamTelemetrySink(primary)

    def rewiring_write(value: bytes) -> int:
        primary.write_calls += 1
        primary.buffer.extend(value[:1])
        replacement = alternate.write if field_name == "_write" else alternate.flush
        object.__setattr__(sink, field_name, replacement)
        return 1 if field_name == "_write" else len(value)

    object.__setattr__(sink, "_write", rewiring_write)
    object.__setattr__(
        sink,
        "_wiring_seal",
        (id(rewiring_write), id(cast(Any, sink)._flush), id(cast(Any, sink)._lock)),
    )
    result = emit_to_sink(sink)
    assert result.status is TelemetryEmitStatus.FAILED
    assert result.reason_code is TelemetryEmitReason.SINK_FAILURE
    assert alternate.write_calls == 0
    assert alternate.flush_calls == 0
    assert primary.flush_calls == 0


def test_binary_stream_flush_wiring_mutation_uses_no_alternate_io() -> None:
    primary = BinaryStream()
    alternate = BinaryStream()
    sink = BinaryStreamTelemetrySink(primary)

    def rewiring_flush() -> None:
        primary.flush_calls += 1
        object.__setattr__(sink, "_write", alternate.write)

    object.__setattr__(sink, "_flush", rewiring_flush)
    object.__setattr__(
        sink,
        "_wiring_seal",
        (id(cast(Any, sink)._write), id(rewiring_flush), id(cast(Any, sink)._lock)),
    )
    result = emit_to_sink(sink)
    assert result.status is TelemetryEmitStatus.FAILED
    assert result.reason_code is TelemetryEmitReason.SINK_FAILURE
    assert primary.write_calls == 1
    assert primary.flush_calls == 1
    assert alternate.write_calls == 0
    assert alternate.flush_calls == 0


def test_binary_stream_same_thread_reentry_is_bounded_and_typed() -> None:
    class ReentrantStream(BinaryStream):
        sink: BinaryStreamTelemetrySink
        payload: object

        def __init__(self) -> None:
            super().__init__()
            self.nested_codes: list[TelemetryBoundaryErrorCode] = []

        def write(self, value: bytes) -> int:
            self.write_calls += 1
            try:
                self.sink.emit(self.payload)
            except TelemetryBoundaryError as error:
                self.nested_codes.append(error.code)
            self.buffer.extend(value)
            return len(value)

    stream = ReentrantStream()
    sink = BinaryStreamTelemetrySink(stream)
    stream.sink = sink

    class ForwardingSink:
        def emit(self, payload: object) -> None:
            stream.payload = payload
            sink.emit(payload)

    authority, authorization, clock = foundation()
    emitter = TelemetryEmitter(authority, clock, (ForwardingSink(),))
    results: list[TelemetryEmitResult] = []

    def emit_once() -> None:
        results.append(emitter.emit(draft(), authorization))

    thread = Thread(target=emit_once, daemon=True)
    thread.start()
    thread.join(timeout=1)
    assert not thread.is_alive()
    assert len(results) == 1
    assert results[0].status is TelemetryEmitStatus.EMITTED
    assert stream.nested_codes == [TelemetryBoundaryErrorCode.STREAM_INVALID]
    assert stream.write_calls == 1
    assert stream.flush_calls == 1
    assert hashlib.sha256(stream.buffer).hexdigest() == results[0].record_sha256


def test_in_memory_sink_is_bounded_without_eviction() -> None:
    sink = InMemoryTelemetrySink(max_records=1)
    assert emit_to_sink(sink).status is TelemetryEmitStatus.EMITTED
    retained = sink.records
    second = emit_to_sink(sink)
    assert second.status is TelemetryEmitStatus.FAILED
    assert second.reason_code is TelemetryEmitReason.SINK_FAILURE
    assert sink.records == retained


def test_in_memory_sink_retained_storage_is_not_in_place_mutable() -> None:
    sink = InMemoryTelemetrySink(max_records=1)
    retained = cast(Any, sink)._records
    assert type(retained) is tuple
    with pytest.raises(AttributeError):
        retained.append((b"API_KEY=RAW-CANARY\n", "f" * 64))  # type: ignore[attr-defined]
    assert sink.records == ()


@pytest.mark.parametrize("field_name", ["_lock", "_max_records", "_records", "_wiring_seal"])
def test_in_memory_sink_mutated_wiring_is_zero_effect(field_name: str) -> None:
    sink = InMemoryTelemetrySink(max_records=1)
    object.__setattr__(sink, field_name, object())
    probe = ProbingSink(sink.emit)
    assert emit_to_sink(probe).status is TelemetryEmitStatus.EMITTED
    assert len(probe.errors) == 1
    assert str(probe.errors[0]) == "telemetry sink failed"
    assert probe.errors[0].__cause__ is None


def test_in_memory_sink_concurrent_cap_is_atomic() -> None:
    sink = InMemoryTelemetrySink(max_records=4)
    start = Barrier(17)
    outcomes: list[str] = []
    outcomes_lock = Lock()

    def emit_once() -> None:
        authority, authorization, clock = foundation()
        emitter = TelemetryEmitter(authority, clock, (sink,))
        start.wait()
        result = emitter.emit(draft(), authorization)
        if result.status is TelemetryEmitStatus.EMITTED:
            outcome = "emitted"
        else:
            assert result.status is TelemetryEmitStatus.FAILED
            assert result.reason_code is TelemetryEmitReason.SINK_FAILURE
            outcome = "full"
        with outcomes_lock:
            outcomes.append(outcome)

    threads = [Thread(target=emit_once) for _ in range(16)]
    for thread in threads:
        thread.start()
    start.wait()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert outcomes.count("emitted") == 4
    assert outcomes.count("full") == 12
    assert len(sink.records) == 4


def test_binary_stream_concurrent_records_do_not_interleave() -> None:
    class FirstWriteRendezvousStream(BinaryStream):
        def __init__(self) -> None:
            super().__init__()
            self.first_writes = Barrier(2)
            self.thread_state = local()

        def write(self, value: bytes) -> int:
            if not getattr(self.thread_state, "wrote", False):
                self.thread_state.wrote = True
                self.write_calls += 1
                self.buffer.extend(value[:1])
                with suppress(BrokenBarrierError):
                    self.first_writes.wait(timeout=0.25)
                return 1
            return cast(int, super().write(value))

    stream = FirstWriteRendezvousStream()
    sink = BinaryStreamTelemetrySink(stream)
    start = Barrier(3)
    results: list[TelemetryEmitResult] = []
    results_lock = Lock()

    def emit_once() -> None:
        authority, authorization, clock = foundation()
        emitter = TelemetryEmitter(authority, clock, (sink,))
        start.wait()
        result = emitter.emit(draft(), authorization)
        with results_lock:
            results.append(result)

    threads = [Thread(target=emit_once) for _ in range(2)]
    for thread in threads:
        thread.start()
    start.wait()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert len(results) == 2
    assert all(result.status is TelemetryEmitStatus.EMITTED for result in results)
    records = bytes(stream.buffer).splitlines(keepends=True)
    assert len(records) == 2
    assert all(parse_telemetry_bytes(record) for record in records)
    assert {hashlib.sha256(record).hexdigest() for record in records} == {
        cast(str, result.record_sha256) for result in results
    }
    assert stream.flush_calls == 2


@pytest.mark.parametrize("value", [0, -1, True, 1025, 1.0, "1"])
def test_in_memory_sink_rejects_invalid_capacity(value: object) -> None:
    with pytest.raises(ValueError):
        InMemoryTelemetrySink(value)  # type: ignore[arg-type]


def test_system_adapters_use_exact_single_capabilities(monkeypatch: pytest.MonkeyPatch) -> None:
    source_calls: list[int] = []
    clock_calls: list[object] = []

    def token_bytes(length: int) -> bytes:
        source_calls.append(length)
        return b"x" * length

    fixed = datetime(2026, 1, 2, tzinfo=UTC)

    class DateTimeSpy:
        @staticmethod
        def now(tz: object) -> datetime:
            clock_calls.append(tz)
            return fixed

    monkeypatch.setattr("securecode_ai.adapters.telemetry.secrets.token_bytes", token_bytes)
    monkeypatch.setattr("securecode_ai.adapters.telemetry.datetime", DateTimeSpy)
    assert SystemTraceIdSource().token_bytes(16) == b"x" * 16
    assert SystemUTCClock().now_utc() == fixed
    assert source_calls == [16]
    assert clock_calls == [UTC]


def test_internal_telemetry_is_absent_from_public_schema_inventory() -> None:
    import securecode_ai.contracts as contracts
    from securecode_ai.contracts.schema_export import render_schema_documents

    assert not hasattr(contracts, "TelemetryRecord")
    assert "telemetry-record.schema.json" not in render_schema_documents()
