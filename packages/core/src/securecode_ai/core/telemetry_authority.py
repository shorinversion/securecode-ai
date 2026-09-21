"""Fail-closed, framework-independent foundation telemetry primitives."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from typing import Any, cast

from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION

from .telemetry_parsing import _authorization_message
from .telemetry_primitives import (
    TelemetryBoundaryErrorCode,
    TraceAuthorization,
    TraceContext,
    TraceIdSource,
    _boundary,
    _revalidate_trace,
)


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
