"""First-party system and sink adapters for the Core telemetry boundary."""

from __future__ import annotations

import secrets
from _thread import LockType
from _thread import RLock as RLockType
from collections.abc import Callable
from datetime import UTC, datetime
from threading import Lock, RLock
from typing import Any, cast, final

from securecode_ai.core.telemetry import (
    TelemetryBoundaryError,
    TelemetryBoundaryErrorCode,
    open_telemetry_payload,
)


@final
class SystemTraceIdSource:
    """Bounded OS CSPRNG adapter. Core validates the returned bytes."""

    __slots__ = ()

    def token_bytes(self, length: int) -> bytes:
        if type(length) is not int or length not in {8, 16, 32}:
            raise ValueError("trace identifier length is invalid")
        return secrets.token_bytes(length)


@final
class SystemUTCClock:
    """UTC wall-clock adapter. Core validates the returned datetime."""

    __slots__ = ()

    def now_utc(self) -> datetime:
        return datetime.now(UTC)


@final
class _TelemetrySinkFailure(RuntimeError):
    __slots__ = ()

    def __init__(self) -> None:
        super().__init__("telemetry sink failed")


@final
class InMemoryTelemetrySink:
    """Bounded first-party sink intended for tests and local diagnostics."""

    __slots__ = ("_lock", "_max_records", "_records", "_wiring_seal")

    _lock: LockType
    _max_records: int
    _records: tuple[tuple[bytes, str], ...]
    _wiring_seal: tuple[int, int, int]

    def __init__(self, max_records: int = 128) -> None:
        if type(max_records) is not int or not 1 <= max_records <= 1024:
            raise ValueError("max_records must be an integer from 1 through 1024")
        lock = Lock()
        records: tuple[tuple[bytes, str], ...] = ()
        object.__setattr__(self, "_lock", lock)
        object.__setattr__(self, "_max_records", max_records)
        object.__setattr__(self, "_records", records)
        object.__setattr__(self, "_wiring_seal", (id(lock), id(records), max_records))

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("InMemoryTelemetrySink wiring is immutable")
        object.__setattr__(self, name, value)

    @property
    def records(self) -> tuple[tuple[bytes, str], ...]:
        lock = self._lock_snapshot()
        with lock:
            if not self._intact():
                raise _TelemetrySinkFailure()
            return self._records

    def _lock_snapshot(self) -> LockType:
        try:
            lock = self._lock
            wiring_seal = self._wiring_seal
        except Exception:
            raise _TelemetrySinkFailure() from None
        if (
            type(self) is not InMemoryTelemetrySink
            or type(lock) is not LockType
            or type(wiring_seal) is not tuple
            or len(wiring_seal) != 3
            or type(wiring_seal[0]) is not int
            or wiring_seal[0] != id(lock)
        ):
            raise _TelemetrySinkFailure()
        return lock

    def _intact(self) -> bool:
        try:
            return (
                type(self) is InMemoryTelemetrySink
                and type(self._lock) is LockType
                and type(self._max_records) is int
                and 1 <= self._max_records <= 1024
                and type(self._records) is tuple
                and len(self._records) <= self._max_records
                and all(
                    type(record) is tuple
                    and len(record) == 2
                    and type(record[0]) is bytes
                    and type(record[1]) is str
                    for record in self._records
                )
                and self._wiring_seal == (id(self._lock), id(self._records), self._max_records)
            )
        except Exception:
            return False

    def emit(self, payload: object, *unexpected: object) -> None:
        if unexpected:
            raise TelemetryBoundaryError(TelemetryBoundaryErrorCode.SINK_PAYLOAD_INVALID)
        canonical_bytes, payload_sha256 = open_telemetry_payload(payload)
        lock = self._lock_snapshot()
        with lock:
            if not self._intact() or len(self._records) >= self._max_records:
                raise _TelemetrySinkFailure()
            records = (*self._records, (canonical_bytes, payload_sha256))
            object.__setattr__(self, "_records", records)
            object.__setattr__(
                self,
                "_wiring_seal",
                (id(self._lock), id(records), self._max_records),
            )


@final
class BinaryStreamTelemetrySink:
    """Validated binary-stream JSONL sink with exact short-write handling."""

    __slots__ = ("_active", "_flush", "_lock", "_wiring_seal", "_write")

    _active: bool
    _flush: Callable[[], object]
    _lock: RLockType
    _wiring_seal: tuple[int, int, int]
    _write: Callable[[bytes], object]

    def __init__(self, stream: object) -> None:
        failed = False
        write: object = None
        flush: object = None
        try:
            write = cast(Any, stream).write
            flush = cast(Any, stream).flush
            if not callable(write) or not callable(flush):
                failed = True
        except Exception:
            failed = True
        if failed:
            raise TelemetryBoundaryError(TelemetryBoundaryErrorCode.STREAM_INVALID)
        lock = RLock()
        object.__setattr__(self, "_active", False)
        object.__setattr__(self, "_write", write)
        object.__setattr__(self, "_flush", flush)
        object.__setattr__(self, "_lock", lock)
        object.__setattr__(self, "_wiring_seal", (id(write), id(flush), id(lock)))

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("BinaryStreamTelemetrySink wiring is immutable")
        object.__setattr__(self, name, value)

    def _intact(self) -> bool:
        try:
            return (
                type(self) is BinaryStreamTelemetrySink
                and type(self._active) is bool
                and callable(self._write)
                and callable(self._flush)
                and type(self._lock) is RLockType
                and self._wiring_seal == (id(self._write), id(self._flush), id(self._lock))
            )
        except Exception:
            return False

    def emit(self, payload: object, *unexpected: object) -> None:
        if not self._intact():
            raise TelemetryBoundaryError(TelemetryBoundaryErrorCode.STREAM_INVALID)
        write: Callable[[bytes], object] = self._write
        flush: Callable[[], object] = self._flush
        lock = self._lock
        if unexpected:
            raise TelemetryBoundaryError(TelemetryBoundaryErrorCode.SINK_PAYLOAD_INVALID)
        canonical_bytes, _ = open_telemetry_payload(payload)
        with lock:
            if not self._intact() or bool(self._active):
                raise TelemetryBoundaryError(TelemetryBoundaryErrorCode.STREAM_INVALID)
            object.__setattr__(self, "_active", True)
            try:
                offset = 0
                while offset < len(canonical_bytes):
                    failed = False
                    written: object = None
                    try:
                        written = write(canonical_bytes[offset:])
                    except Exception:
                        failed = True
                    remaining = len(canonical_bytes) - offset
                    if failed or type(written) is not int or not 1 <= written <= remaining:
                        raise _TelemetrySinkFailure()
                    if not self._intact() or self._active is not True:
                        raise TelemetryBoundaryError(TelemetryBoundaryErrorCode.STREAM_INVALID)
                    offset += written
                failed = False
                flush_result: object = None
                try:
                    flush_result = flush()
                except Exception:
                    failed = True
                if not self._intact() or self._active is not True:
                    raise TelemetryBoundaryError(TelemetryBoundaryErrorCode.STREAM_INVALID)
                if failed or flush_result is not None:
                    raise _TelemetrySinkFailure()
            finally:
                if type(self._active) is bool:
                    object.__setattr__(self, "_active", False)


__all__ = [
    "BinaryStreamTelemetrySink",
    "InMemoryTelemetrySink",
    "SystemTraceIdSource",
    "SystemUTCClock",
]
