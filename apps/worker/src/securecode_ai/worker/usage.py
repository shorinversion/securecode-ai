"""Source-free process resource measurement for one worker execution."""

from __future__ import annotations

import ctypes
import os
import subprocess
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from securecode_ai.adapters.remote_provider_budget import RemoteProviderCostReceipt

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
    """Measure process resource use while one product execution is active."""

    __slots__ = (
        "_cpu_started_ns",
        "_cgroup_cpu_started_ns",
        "_execution_identity_hash",
        "_finished",
        "_finish_lock",
        "_memory_lock",
        "_memory_peak",
        "_memory_sampler",
        "_memory_stop",
        "_model_cost_microunits",
        "_model_observed",
        "_model_tokens",
        "_remote_receipts",
        "_usage_lock",
        "_run_id",
        "_wall_started_ns",
    )

    def __init__(
        self,
        *,
        run_id: str | None = None,
        execution_identity_hash: str | None = None,
    ) -> None:
        if (run_id is None) != (execution_identity_hash is None):
            raise WorkerUsageError("worker usage binding is incomplete")
        if run_id is not None and (
            type(run_id) is not str
            or not run_id
            or type(execution_identity_hash) is not str
            or len(execution_identity_hash) != 64
            or any(character not in "0123456789abcdef" for character in execution_identity_hash)
        ):
            raise WorkerUsageError("worker usage binding is invalid")
        self._run_id = run_id
        self._execution_identity_hash = execution_identity_hash
        self._wall_started_ns = time.perf_counter_ns()
        self._cpu_started_ns = time.process_time_ns()
        self._cgroup_cpu_started_ns = _cgroup_cpu_time_ns()
        self._finished = False
        self._finish_lock = threading.Lock()
        self._memory_lock = threading.Lock()
        self._memory_peak: int | None = None
        self._usage_lock = threading.Lock()
        self._model_tokens = 0
        self._model_cost_microunits = 0
        self._model_observed = False
        self._remote_receipts: dict[tuple[str, str, int], int] = {}
        self._memory_stop = threading.Event()
        self._record_memory()
        self._memory_sampler = threading.Thread(
            target=self._sample_memory,
            name="securecode-worker-memory-meter",
            daemon=True,
        )
        self._memory_sampler.start()

    def observe_model_usage(self, usage: object) -> None:
        """Record one completed model call before more work is admitted."""

        input_tokens = _counter(_member(usage, "input_tokens"), "input_tokens")
        output_tokens = _counter(_member(usage, "output_tokens"), "output_tokens")
        tokens = _add_counters(input_tokens, output_tokens)
        # ModelUsage intentionally carries token counters only. Paid-provider
        # cost is supplied separately as a run-bound RemoteProviderCostReceipt;
        # a local provider has an explicit zero cost in its result envelope.
        cost = _member(usage, "cost_microunits")
        if cost is _MISSING:
            cost = 0
        cost_value = _counter(cost, "cost_microunits")
        with self._usage_lock:
            if self._finished:
                raise WorkerUsageError("worker model usage was observed after finish")
            self._model_observed = True
            self._model_tokens = _add_counters(self._model_tokens, tokens)
            self._model_cost_microunits = _add_counters(
                self._model_cost_microunits,
                cost_value,
            )

    def observe_remote_cost(self, receipt: object) -> None:
        """Record one already-settled remote charge bound to this run."""

        if type(receipt) is not RemoteProviderCostReceipt:
            raise WorkerUsageError("worker remote cost receipt is invalid")
        if (
            self._run_id is None
            or receipt.run_id != self._run_id
            or type(receipt.cost_microunits) is not int
            or receipt.cost_microunits < 0
        ):
            raise WorkerUsageError("worker remote cost receipt is not bound to the run")
        key = (receipt.model_id, receipt.request_id, receipt.attempt)
        with self._usage_lock:
            if key in self._remote_receipts:
                if self._remote_receipts[key] != receipt.cost_microunits:
                    raise WorkerUsageError("worker remote cost receipt conflicts with replay")
                return
            if self._finished:
                raise WorkerUsageError("worker remote cost receipt was observed after finish")
            if len(self._remote_receipts) >= 65_536:
                raise WorkerUsageError("worker remote cost receipt limit exceeded")
            self._remote_receipts[key] = receipt.cost_microunits
            self._model_observed = True
            self._model_cost_microunits = _add_counters(
                self._model_cost_microunits,
                receipt.cost_microunits,
            )

    def snapshot(self, result: object | None = None) -> WorkerResourceUsage:
        """Return cumulative counters for live quota enforcement."""

        wall_ns = time.perf_counter_ns() - self._wall_started_ns
        cpu_ns = self._cpu_elapsed_ns()
        if wall_ns < 0 or cpu_ns < 0:
            raise WorkerUsageError("worker resource clock is invalid")
        self._record_memory()
        with self._memory_lock:
            peak_memory = self._memory_peak
        if peak_memory is None:
            raise WorkerUsageError("worker peak memory usage is unavailable")
        with self._usage_lock:
            if self._finished:
                raise WorkerUsageError("worker resource meter is already finished")
            tokens = self._model_tokens
            cost = self._model_cost_microunits
        if result is not None:
            self._validate_result_binding(result)
            result_tokens, result_cost = _model_counters(result)
            if (
                (self._model_observed and tokens != result_tokens)
                or (self._model_observed and result_cost not in {0, cost})
                or (not self._model_observed and (result_tokens != 0 or result_cost != 0))
            ):
                raise WorkerUsageError("worker model usage is inconsistent")
            tokens = result_tokens
            if self._model_observed:
                cost = self._model_cost_microunits
            else:
                cost = result_cost
        return WorkerResourceUsage(
            tokens=tokens,
            cost_microunits=cost,
            cpu_ms=_ceil_milliseconds(cpu_ns),
            peak_memory_bytes=peak_memory,
            wall_ms=_ceil_milliseconds(wall_ns),
        )

    def finish(self, result: object | None = None) -> WorkerResourceUsage:
        with self._finish_lock:
            with self._usage_lock:
                if self._finished:
                    raise WorkerUsageError("worker resource meter is already finished")
                self._finished = True
            self._memory_stop.set()
            self._memory_sampler.join(timeout=1.0)
            if self._memory_sampler.is_alive():
                raise WorkerUsageError("worker memory sampler did not stop")
            self._record_memory()
            wall_ns = time.perf_counter_ns() - self._wall_started_ns
            cpu_ns = self._cpu_elapsed_ns()
            if wall_ns < 0 or cpu_ns < 0:
                raise WorkerUsageError("worker resource clock is invalid")
            with self._memory_lock:
                peak_memory = self._memory_peak
            if peak_memory is None:
                raise WorkerUsageError("worker peak memory usage is unavailable")
            if result is None:
                with self._usage_lock:
                    tokens = self._model_tokens
                    cost_microunits = self._model_cost_microunits
            else:
                self._validate_result_binding(result)
                tokens, cost_microunits = _model_counters(result)
            with self._usage_lock:
                if self._model_observed and self._model_tokens != tokens:
                    raise WorkerUsageError("worker model usage is inconsistent")
                if (
                    self._model_observed
                    and cost_microunits != 0
                    and self._model_cost_microunits != cost_microunits
                ):
                    raise WorkerUsageError("worker model usage is inconsistent")
                if not self._model_observed and (tokens != 0 or cost_microunits != 0):
                    raise WorkerUsageError("worker model usage was not observed")
                if self._model_observed:
                    cost_microunits = self._model_cost_microunits
            return WorkerResourceUsage(
                tokens=tokens,
                cost_microunits=cost_microunits,
                cpu_ms=_ceil_milliseconds(cpu_ns),
                peak_memory_bytes=peak_memory,
                wall_ms=_ceil_milliseconds(wall_ns),
            )

    def _sample_memory(self) -> None:
        while not self._memory_stop.wait(0.1):
            self._record_memory()

    def _record_memory(self) -> None:
        measured = _resident_memory_bytes()
        if measured is None or measured < 0 or measured > _MAX_INTEGER:
            return
        with self._memory_lock:
            self._memory_peak = (
                measured if self._memory_peak is None else max(self._memory_peak, measured)
            )

    def _cpu_elapsed_ns(self) -> int:
        process_elapsed = time.process_time_ns() - self._cpu_started_ns
        if process_elapsed < 0:
            raise WorkerUsageError("worker resource clock is invalid")
        started = self._cgroup_cpu_started_ns
        if started is None:
            return process_elapsed
        current = _cgroup_cpu_time_ns()
        if current is None or current < started:
            return process_elapsed
        cgroup_elapsed = current - started
        # A cgroup CPU counter includes child processes, which is the resource
        # boundary enforced for a containerized worker.  Keep the process clock
        # as a lower bound in case a runtime reports a coarse counter.
        return max(process_elapsed, cgroup_elapsed)

    def _validate_result_binding(self, result: object | None) -> None:
        if self._run_id is None and self._execution_identity_hash is None:
            return
        bound_result = (
            getattr(result, "scan", _MISSING)
            if result is not None
            else _MISSING
        )
        if bound_result is _MISSING:
            bound_result = result
        composition = getattr(bound_result, "composition", _MISSING)
        run = getattr(composition, "run", _MISSING)
        observed_run_id = getattr(run, "run_id", _MISSING)
        identity = getattr(run, "execution_identity", _MISSING)
        observed_identity_hash = getattr(identity, "execution_identity_hash", _MISSING)
        if (
            observed_run_id is _MISSING
            or observed_identity_hash is _MISSING
            or observed_run_id != self._run_id
            or observed_identity_hash != self._execution_identity_hash
        ):
            raise WorkerUsageError("worker model usage is not bound to the claimed run")


def _model_counters(result: object | None) -> tuple[int, int]:
    if result is None:
        raise WorkerUsageError("worker model usage is unavailable")
    scan = getattr(result, "scan", _MISSING)
    if scan is not _MISSING:
        scan_tokens, scan_cost = _model_counters(scan)
        repair = getattr(result, "repair", _MISSING)
        if repair is _MISSING or repair is None:
            return scan_tokens, scan_cost
        repair_counters = _direct_model_counters(repair)
        if repair_counters is None:
            raise WorkerUsageError("worker repair usage is unavailable")
        return (
            _add_counters(scan_tokens, repair_counters[0]),
            _add_counters(scan_cost, repair_counters[1]),
        )
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


def _resident_memory_bytes() -> int | None:
    if os.name == "nt":
        return _windows_resident_memory_bytes()
    value = _cgroup_resident_memory_bytes()
    if value is not None:
        return value
    value = _proc_resident_memory_bytes()
    return value if value is not None else _ps_resident_memory_bytes()


def _cgroup_cpu_time_ns() -> int | None:
    """Read cumulative worker-container CPU time when the cgroup exposes it."""

    try:
        membership = Path("/proc/self/cgroup").read_bytes()
    except OSError:
        return None
    if len(membership) > 8192:
        return None
    candidates: list[tuple[Path, str]] = []
    for line in membership.splitlines():
        fields = line.split(b":", 2)
        if len(fields) != 3:
            continue
        controllers, raw_path = fields[1], fields[2]
        if not raw_path.startswith(b"/"):
            continue
        try:
            normalized_path = raw_path.decode("ascii").strip("/")
        except UnicodeDecodeError:
            continue
        relative = normalized_path.split("/") if normalized_path else []
        if any(part in {".", ".."} for part in relative):
            continue
        if not controllers:
            candidates.append((Path("/sys/fs/cgroup", *relative, "cpu.stat"), "usage_usec"))
        elif b"cpuacct" in controllers.split(b","):
            candidates.append(
                (Path("/sys/fs/cgroup/cpuacct", *relative, "cpuacct.usage"), "nanoseconds")
            )
            candidates.append(
                (
                    Path("/sys/fs/cgroup/cpu,cpuacct", *relative, "cpuacct.usage"),
                    "nanoseconds",
                )
            )
    for candidate, format_name in candidates:
        try:
            value = candidate.read_bytes()
        except OSError:
            continue
        if len(value) > 4096:
            continue
        if format_name == "nanoseconds":
            value = value.strip()
            if value.isascii() and value.isdigit():
                measured = int(value)
                if measured <= _MAX_INTEGER:
                    return measured
            continue
        for line in value.splitlines():
            fields = line.split()
            if len(fields) != 2 or fields[0] != b"usage_usec":
                continue
            if not fields[1].isascii() or not fields[1].isdigit():
                continue
            microseconds = int(fields[1])
            if microseconds <= _MAX_INTEGER // 1_000:
                return microseconds * 1_000
    return None


def _cgroup_resident_memory_bytes() -> int | None:
    """Measure the worker container, including its child processes, when available."""

    try:
        membership = Path("/proc/self/cgroup").read_bytes()
    except OSError:
        return None
    if len(membership) > 8192:
        return None
    candidates: list[Path] = []
    for line in membership.splitlines():
        fields = line.split(b":", 2)
        if len(fields) != 3:
            continue
        controllers, raw_path = fields[1], fields[2]
        if not raw_path.startswith(b"/"):
            continue
        try:
            normalized_path = raw_path.decode("ascii").strip("/")
        except UnicodeDecodeError:
            continue
        relative = normalized_path.split("/") if normalized_path else []
        if any(part in {".", ".."} for part in relative):
            continue
        if not controllers:
            candidates.append(Path("/sys/fs/cgroup", *relative, "memory.current"))
        elif b"memory" in controllers.split(b","):
            candidates.append(Path("/sys/fs/cgroup/memory", *relative, "memory.usage_in_bytes"))
    for candidate in candidates:
        try:
            value = candidate.read_bytes()
        except OSError:
            continue
        if len(value) > 32:
            continue
        value = value.strip()
        if value.isascii() and value.isdigit():
            measured = int(value)
            if measured <= _MAX_INTEGER:
                return measured
    return None


def _proc_resident_memory_bytes() -> int | None:
    try:
        values = Path("/proc/self/statm").read_text(encoding="ascii").split()
        if len(values) < 2 or not values[1].isascii() or not values[1].isdecimal():
            return None
        page_size = os.sysconf("SC_PAGE_SIZE")
        if type(page_size) is not int or page_size <= 0:
            return None
        resident_pages = int(values[1])
        measured = resident_pages * page_size
        return measured if measured <= _MAX_INTEGER else None
    except (OSError, OverflowError, ValueError):
        return None


def _ps_resident_memory_bytes() -> int | None:
    executable = next(
        (candidate for candidate in ("/bin/ps", "/usr/bin/ps") if Path(candidate).is_file()),
        None,
    )
    if executable is None:
        return None
    try:
        result = subprocess.run(
            [executable, "-o", "rss=", "-p", str(os.getpid())],
            capture_output=True,
            check=True,
            timeout=1.0,
            text=True,
            encoding="ascii",
        )
        value = result.stdout.strip()
        if not value.isascii() or not value.isdecimal():
            return None
        measured = int(value) * 1024
        return measured if measured <= _MAX_INTEGER else None
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        return None


def _windows_resident_memory_bytes() -> int | None:
    try:
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
        windll = vars(ctypes)["windll"]
        process = windll.kernel32.GetCurrentProcess()
        if not windll.psapi.GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb):
            return None
        return int(counters.WorkingSetSize)
    except (AttributeError, KeyError, OSError, TypeError, ValueError):
        return None


__all__ = [
    "WorkerResourceUsage",
    "WorkerUsageError",
    "WorkerUsageMeter",
]
