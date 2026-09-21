"""Fail-closed, framework-independent foundation telemetry primitives."""

from __future__ import annotations

import hashlib
import sys
from collections.abc import Callable
from dis import get_instructions
from types import FrameType
from typing import Any, cast

from .telemetry_emitter import TelemetryEmitter, _PayloadIssuer, _TelemetryPayload
from .telemetry_parsing import parse_telemetry_bytes
from .telemetry_primitives import (
    _LOWER_HEX_64,
    _MAX_PAYLOAD_BYTES,
    TelemetryBoundaryErrorCode,
    TelemetryDraft,
    TelemetryEmitResult,
    TraceAuthorization,
    _boundary,
    _is_lower_hex,
)


def _build_payload_opener(
    emit_method: Callable[
        [TelemetryEmitter, TelemetryDraft, TraceAuthorization], TelemetryEmitResult
    ],
    *,
    facade_globals: dict[str, object] | None = None,
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
    facade_namespace: dict[str, object] = {} if facade_globals is None else facade_globals
    facade_resolutions = (
        ()
        if facade_globals is None
        else tuple(
            (name, name in facade_namespace, facade_namespace.get(name)) for name in global_names
        )
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
                        for name, present, value in facade_resolutions:
                            if present:
                                if (
                                    name not in facade_namespace
                                    or facade_namespace[name] is not value
                                ):
                                    environment_valid = False
                                    break
                            elif name in facade_namespace:
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
