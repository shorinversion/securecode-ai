"""Source-free process resource measurement for one worker execution."""

from __future__ import annotations

import importlib
import os
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

_MAX_INTEGER: Final = 9_223_372_036_854_775_807
_MISSING: Final = object()


class WorkerUsageError(ValueError):
    """A safe failure to produce bounded source-free counters."""


@dataclass(frozen=True, slots=True)
class WorkerResourceUsage:
    tokens: int
    cost_microunits: int
    cpu_ms: int
    peak_memory_bytes: int
    wall_ms: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or not 0 <= value <= _MAX_INTEGER
            for value in (
                self.tokens,
                self.cost_microunits,
                self.cpu_ms,
                self.peak_memory_bytes,
                self.wall_ms,
            )
        ):
            raise WorkerUsageError("worker resource usage is invalid")

    def document(self) -> dict[str, int]:
        return {
            "tokens": self.tokens,
            "cost_microunits": self.cost_microunits,
            "cpu_ms": self.cpu_ms,
            "peak_memory_bytes": self.peak_memory_bytes,
            "wall_ms": self.wall_ms,
        }


class WorkerUsageMeter:
    """Measure process-wide resource use during one product execution."""

    __slots__ = ("_cpu_started_ns", "_finished", "_wall_started_ns")

    def __init__(self) -> None:
        self._wall_started_ns = time.perf_counter_ns()
        self._cpu_started_ns = time.process_time_ns()
        self._finished = False

    def finish(self, result: object | None = None) -> WorkerResourceUsage:
        if self._finished:
            raise WorkerUsageError("worker resource meter is already finished")
        self._finished = True
        wall_ns = time.perf_counter_ns() - self._wall_started_ns
        cpu_ns = time.process_time_ns() - self._cpu_started_ns
        if wall_ns < 0 or cpu_ns < 0:
            raise WorkerUsageError("worker resource clock is invalid")
        tokens, cost_microunits = _model_counters(result)
        return WorkerResourceUsage(
            tokens=tokens,
            cost_microunits=cost_microunits,
            cpu_ms=_ceil_milliseconds(cpu_ns),
            peak_memory_bytes=_peak_memory_bytes(),
            wall_ms=_ceil_milliseconds(wall_ns),
        )


def _model_counters(result: object | None) -> tuple[int, int]:
    if result is None:
        raise WorkerUsageError("worker model usage is unavailable")
    candidates: list[tuple[int, int]] = []
    for attribute in ("model_usage", "resource_usage"):
        value = getattr(result, attribute, _MISSING)
        if value is not _MISSING and value is not None:
            candidates.append(_usage_counters(value))
    direct = _direct_model_counters(result)
    if direct is not None:
        candidates.append(direct)
    if not candidates:
        raise WorkerUsageError("worker model usage is unavailable")
    first = candidates[0]
    if any(candidate != first for candidate in candidates[1:]):
        raise WorkerUsageError("worker model usage is inconsistent")
    return first


def _direct_model_counters(result: object) -> tuple[int, int] | None:
    model_tokens = _optional_member(result, "model_tokens")
    model_cost = _optional_member(result, "model_cost_microunits")
    plain_tokens = _optional_member(result, "tokens")
    plain_cost = _optional_member(result, "cost_microunits")
    if model_tokens is not _MISSING or model_cost is not _MISSING:
        if model_tokens is _MISSING or model_cost is _MISSING:
            raise WorkerUsageError("worker model usage is incomplete")
        return (
            _counter(model_tokens, "model_tokens"),
            _counter(model_cost, "model_cost_microunits"),
        )
    if plain_tokens is not _MISSING or plain_cost is not _MISSING:
        if plain_tokens is _MISSING or plain_cost is _MISSING:
            raise WorkerUsageError("worker model usage is incomplete")
        return (
            _counter(plain_tokens, "tokens"),
            _counter(plain_cost, "cost_microunits"),
        )
    return None


def _usage_counters(value: object) -> tuple[int, int]:
    tokens = _member(value, "tokens")
    input_tokens = _member(value, "input_tokens")
    output_tokens = _member(value, "output_tokens")
    cost = _member(value, "cost_microunits")
    if cost is _MISSING:
        raise WorkerUsageError("worker model usage is incomplete")
    if tokens is not _MISSING:
        if input_tokens is not _MISSING or output_tokens is not _MISSING:
            raise WorkerUsageError("worker model token usage is ambiguous")
        token_count = _counter(tokens, "tokens")
    elif input_tokens is not _MISSING or output_tokens is not _MISSING:
        if input_tokens is _MISSING or output_tokens is _MISSING:
            raise WorkerUsageError("worker model token usage is incomplete")
        token_count = _add_counters(
            _counter(input_tokens, "input_tokens"),
            _counter(output_tokens, "output_tokens"),
        )
    else:
        raise WorkerUsageError("worker model usage is invalid")
    return token_count, _counter(cost, "cost_microunits")


def _member(value: object, key: str) -> object:
    if isinstance(value, Mapping):
        observed = value.get(key, _MISSING)
    else:
        observed = getattr(value, key, _MISSING)
    return _MISSING if observed is None else observed


def _optional_member(value: object, key: str) -> object:
    observed = getattr(value, key, _MISSING)
    return _MISSING if observed is None else observed


def _add_counters(left: int, right: int) -> int:
    total = left + right
    if total > _MAX_INTEGER:
        raise WorkerUsageError("worker model token usage is invalid")
    return total


def _counter(value: object, name: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_INTEGER:
        raise WorkerUsageError(f"worker {name} counter is invalid")
    return value


def _numeric_measurement(value: object) -> int | float | None:
    if type(value) is int:
        return value
    if type(value) is float:
        return value
    return None


def _ceil_milliseconds(nanoseconds: int) -> int:
    value = (nanoseconds + 999_999) // 1_000_000
    if value > _MAX_INTEGER:
        raise WorkerUsageError("worker duration is invalid")
    return value


def _peak_memory_bytes() -> int:
    value = _windows_peak_memory_bytes() if os.name == "nt" else _posix_peak_memory_bytes()
    if type(value) is not int or not 0 <= value <= _MAX_INTEGER:
        raise WorkerUsageError("worker peak memory usage is unavailable")
    return value


def _posix_peak_memory_bytes() -> int | None:
    try:
        resource_module: object = importlib.import_module("resource")
        getrusage = _optional_member(resource_module, "getrusage")
        usage_self = _optional_member(resource_module, "RUSAGE_SELF")
        if not callable(getrusage) or type(usage_self) is not int:
            return None
        usage = getrusage(usage_self)
        maximum = _optional_member(usage, "ru_maxrss")
        measured = _numeric_measurement(maximum)
        if measured is None or measured < 0:
            return None
        multiplier = 1 if sys.platform == "darwin" else 1024
        return int(measured * multiplier)
    except (ImportError, OSError, OverflowError, ValueError):
        return None


def _windows_peak_memory_bytes() -> int | None:
    try:
        import ctypes
        from ctypes import wintypes

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        process = ctypes.windll.kernel32.GetCurrentProcess()
        if not ctypes.windll.psapi.GetProcessMemoryInfo(
            process, ctypes.byref(counters), counters.cb
        ):
            return None
        return int(counters.PeakWorkingSetSize)
    except (AttributeError, OSError, TypeError, ValueError):
        return None


__all__ = [
    "WorkerResourceUsage",
    "WorkerUsageError",
    "WorkerUsageMeter",
]
