"""Hard-bounded host-owned scanner-worker invocation.

The host never calls a scanner callback in its own process. It starts a
separate standard-library worker, accepts only a size-limited JSON receipt,
and terminates that worker when the host budget expires. This is execution
separation, not a claim that the Python worker is an OS security sandbox.
"""

from __future__ import annotations

import json
import multiprocessing
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from time import monotonic_ns
from typing import Protocol

from securecode_ai.core.scanning import (
    DEFAULT_SCANNER_BUDGET,
    RawSignal,
    ScannerBudget,
    ScannerExecution,
    ScannerFailureCode,
    ScannerIdentity,
    ScannerIsolationMode,
    ScannerPlugin,
    ScannerPluginOutput,
    ScannerRequest,
    ScannerRunStatus,
    ScannerWorkerTarget,
    canonical_raw_signal,
    raw_signal_digest,
    raw_signal_payload_bytes,
)

_POLL_SECONDS = 0.05
_TEARDOWN_SECONDS = 0.2


_ScannerPluginFactory = Callable[[], ScannerPlugin]
_REGISTERED_WORKERS: dict[ScannerWorkerTarget, _ScannerPluginFactory] = {}


class _WorkerConnection(Protocol):
    """Portable subset shared by POSIX and Windows multiprocessing pipes."""

    def poll(self, timeout: float = 0.0) -> bool: ...

    def recv_bytes(self, maxlength: int | None = None) -> bytes: ...

    def send_bytes(self, buf: bytes) -> None: ...

    def close(self) -> None: ...


class _WorkerProcess(Protocol):
    """Portable lifecycle subset shared by spawn and fork process objects."""

    def start(self) -> None: ...

    def is_alive(self) -> bool: ...

    def terminate(self) -> None: ...

    def join(self, timeout: float | None = None) -> None: ...

    def kill(self) -> None: ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class ScannerPluginBinding:
    """Host-created binding of a scanner to its approved process boundary.

    ``FIRST_PARTY_IN_PROCESS`` remains representable for compatibility, but is
    deliberately not executable: no arbitrary callback may hold the host past
    its time budget. The worker receives only the admitted request bytes.
    """

    identity: ScannerIdentity
    worker: ScannerWorkerTarget
    isolation: ScannerIsolationMode = ScannerIsolationMode.APPROVED_ISOLATED_WORKER

    def __post_init__(self) -> None:
        try:
            valid_worker = type(self.worker) is ScannerWorkerTarget
        except Exception:
            valid_worker = False
        if (
            type(self.identity) is not ScannerIdentity
            or type(self.isolation) is not ScannerIsolationMode
            or not valid_worker
        ):
            raise ValueError("scanner plugin binding is invalid")


def register_scanner_worker(target: ScannerWorkerTarget, factory: _ScannerPluginFactory) -> None:
    """Register an approved, pickleable worker factory for isolated execution.

    Registration happens in the host process before the subprocess starts. The
    factory itself is still constructed and invoked only by the child process;
    this avoids host-side callback execution and runtime module imports.
    """

    if type(target) is not ScannerWorkerTarget or not callable(factory):
        raise TypeError("scanner worker registration is invalid")
    if factory.__module__ != target.module or factory.__qualname__ != target.qualname:
        raise ValueError("scanner worker target does not match factory")
    existing = _REGISTERED_WORKERS.get(target)
    if existing is not None and existing is not factory:
        raise ValueError("scanner worker target is already registered")
    _REGISTERED_WORKERS[target] = factory


def run_scanner_plugin(
    binding: ScannerPluginBinding,
    request: ScannerRequest,
    *,
    budget: ScannerBudget = DEFAULT_SCANNER_BUDGET,
    clock_ns: Callable[[], int] = monotonic_ns,
) -> ScannerExecution:
    """Issue one typed scanner receipt without allowing a callback to hang host.

    The configured ``clock_ns`` is retained for deterministic host receipt
    tests; physical monotonic time is also measured so a frozen logical clock
    cannot make the wait unbounded.
    """

    if (
        type(binding) is not ScannerPluginBinding
        or type(request) is not ScannerRequest
        or type(budget) is not ScannerBudget
        or not callable(clock_ns)
    ):
        raise TypeError("scanner plugin invocation is invalid")
    if request.file.size_bytes > budget.max_input_bytes:
        return _failure(
            binding,
            request,
            0,
            request.file.size_bytes,
            0,
            ScannerRunStatus.RESOURCE_EXHAUSTED,
            ScannerFailureCode.INPUT_BUDGET_EXCEEDED,
        )
    if binding.isolation is not ScannerIsolationMode.APPROVED_ISOLATED_WORKER:
        return _failure(
            binding,
            request,
            0,
            request.file.size_bytes,
            0,
            ScannerRunStatus.ISOLATION_FAILED,
            ScannerFailureCode.ISOLATION_REQUIRED,
        )
    try:
        logical_started_ns = _read_clock(clock_ns)
    except ValueError:
        return _failure(
            binding,
            request,
            0,
            request.file.size_bytes,
            0,
            ScannerRunStatus.ISOLATION_FAILED,
            ScannerFailureCode.ISOLATION_REQUIRED,
        )

    try:
        factory = _registered_worker_factory(binding.worker)
    except ValueError:
        return _failure(
            binding,
            request,
            0,
            request.file.size_bytes,
            0,
            ScannerRunStatus.ISOLATION_FAILED,
            ScannerFailureCode.WORKER_START_FAILED,
        )

    physical_started_ns = monotonic_ns()
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(
        target=_scanner_worker_main,
        args=(child, factory, request),
        daemon=True,
    )
    try:
        process.start()
    except Exception:
        _close_quietly(parent)
        _close_quietly(child)
        return _failure(
            binding,
            request,
            0,
            request.file.size_bytes,
            0,
            ScannerRunStatus.ISOLATION_FAILED,
            ScannerFailureCode.WORKER_START_FAILED,
        )
    _close_quietly(child)
    try:
        received = _receive_worker_receipt(
            parent,
            process,
            budget,
            clock_ns,
            logical_started_ns,
            physical_started_ns,
        )
    finally:
        _terminate_bounded(process)
        _close_quietly(parent)

    elapsed_ns, receipt, failure_code = received
    if failure_code is not None:
        status = (
            ScannerRunStatus.TIMEOUT
            if failure_code is ScannerFailureCode.TIME_BUDGET_EXCEEDED
            else ScannerRunStatus.RESOURCE_EXHAUSTED
            if failure_code is ScannerFailureCode.OUTPUT_BUDGET_EXCEEDED
            else ScannerRunStatus.CRASHED
            if failure_code is ScannerFailureCode.PLUGIN_CRASHED
            else ScannerRunStatus.ISOLATION_FAILED
        )
        return _failure(
            binding, request, elapsed_ns, request.file.size_bytes, 0, status, failure_code
        )
    if receipt is None:
        return _failure(
            binding,
            request,
            elapsed_ns,
            request.file.size_bytes,
            0,
            ScannerRunStatus.INVALID_OUTPUT,
            ScannerFailureCode.PLUGIN_OUTPUT_INVALID,
        )
    try:
        signals = _validate_receipt(receipt, binding, request)
        output_bytes = sum(raw_signal_payload_bytes(signal) for signal in signals)
    except (TypeError, ValueError):
        return _failure(
            binding,
            request,
            elapsed_ns,
            request.file.size_bytes,
            0,
            ScannerRunStatus.INVALID_OUTPUT,
            ScannerFailureCode.PLUGIN_OUTPUT_INVALID,
        )
    if len(signals) > budget.max_signals:
        return _failure(
            binding,
            request,
            elapsed_ns,
            request.file.size_bytes,
            0,
            ScannerRunStatus.RESOURCE_EXHAUSTED,
            ScannerFailureCode.SIGNAL_BUDGET_EXCEEDED,
        )
    if any(raw_signal_payload_bytes(signal) > budget.max_fact_bytes for signal in signals) or (
        output_bytes > budget.max_output_bytes
    ):
        return _failure(
            binding,
            request,
            elapsed_ns,
            request.file.size_bytes,
            0,
            ScannerRunStatus.RESOURCE_EXHAUSTED,
            ScannerFailureCode.OUTPUT_BUDGET_EXCEEDED,
        )
    return ScannerExecution(
        request_id=request.request_id,
        scanner=binding.identity,
        isolation=binding.isolation,
        status=ScannerRunStatus.SUCCEEDED,
        elapsed_ns=elapsed_ns,
        input_bytes=request.file.size_bytes,
        output_bytes=output_bytes,
        signals=signals,
        signal_digest=raw_signal_digest(signals),
        failure_code=None,
    )


def _scanner_worker_main(
    connection: _WorkerConnection, factory: _ScannerPluginFactory, request: ScannerRequest
) -> None:
    """Emit an inert JSON receipt; worker exceptions and details never cross."""

    try:
        plugin = _load_worker(factory)
        output = plugin.scan(request)
        if type(output) is not ScannerPluginOutput:
            receipt: dict[str, object] = {"request_id": request.request_id, "status": "INVALID"}
        else:
            receipt = {
                "request_id": request.request_id,
                "status": "COMPLETED",
                "signals": [
                    canonical_raw_signal(signal).model_dump(mode="json")
                    for signal in output.signals
                ],
            }
    except BaseException:
        receipt = {"request_id": request.request_id, "status": "CRASHED"}
    try:
        payload = json.dumps(
            receipt, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        connection.send_bytes(payload)
    except BaseException:
        pass
    finally:
        _close_quietly(connection)


def _registered_worker_factory(target: ScannerWorkerTarget) -> _ScannerPluginFactory:
    try:
        return _REGISTERED_WORKERS[target]
    except KeyError as error:
        raise ValueError("scanner worker is not registered") from error


def _load_worker(factory: _ScannerPluginFactory) -> ScannerPlugin:
    plugin = factory()
    if not callable(getattr(plugin, "scan", None)):
        raise TypeError("scanner worker is invalid")
    return plugin


def _receive_worker_receipt(
    connection: _WorkerConnection,
    process: _WorkerProcess,
    budget: ScannerBudget,
    clock_ns: Callable[[], int],
    logical_started_ns: int,
    physical_started_ns: int,
) -> tuple[int, dict[str, object] | None, ScannerFailureCode | None]:
    while True:
        elapsed_ns = _elapsed_ns(clock_ns, logical_started_ns, physical_started_ns)
        if elapsed_ns is None:
            return 0, None, ScannerFailureCode.ISOLATION_REQUIRED
        if elapsed_ns > budget.max_elapsed_ns:
            return elapsed_ns, None, ScannerFailureCode.TIME_BUDGET_EXCEEDED
        remaining_seconds = (budget.max_elapsed_ns - elapsed_ns) / 1_000_000_000
        try:
            if connection.poll(min(_POLL_SECONDS, remaining_seconds)):
                payload = connection.recv_bytes(maxlength=budget.max_transport_bytes)
                receipt = json.loads(payload.decode("ascii"))
                if type(receipt) is not dict:
                    return elapsed_ns, None, None
                if receipt.get("status") == "CRASHED":
                    return elapsed_ns, None, ScannerFailureCode.PLUGIN_CRASHED
                return elapsed_ns, receipt, None
        except EOFError:
            return elapsed_ns, None, ScannerFailureCode.PLUGIN_CRASHED
        except OSError:
            return elapsed_ns, None, ScannerFailureCode.OUTPUT_BUDGET_EXCEEDED
        except (UnicodeDecodeError, json.JSONDecodeError):
            return elapsed_ns, None, None
        if not process.is_alive():
            return elapsed_ns, None, ScannerFailureCode.PLUGIN_CRASHED


def _validate_receipt(
    receipt: dict[str, object], binding: ScannerPluginBinding, request: ScannerRequest
) -> tuple[RawSignal, ...]:
    if set(receipt) != {"request_id", "status", "signals"}:
        raise ValueError("scanner worker receipt is invalid")
    if receipt["request_id"] != request.request_id or receipt["status"] != "COMPLETED":
        raise ValueError("scanner worker receipt is invalid")
    raw_signals = receipt["signals"]
    if type(raw_signals) is not list:
        raise ValueError("scanner worker receipt is invalid")
    signals = tuple(
        canonical_raw_signal(
            RawSignal.model_validate_json(
                json.dumps(
                    signal,
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
            )
        )
        for signal in raw_signals
    )
    if (
        tuple(signal.raw_signal_id for signal in signals)
        != tuple(sorted(signal.raw_signal_id for signal in signals))
        or len({signal.raw_signal_id for signal in signals}) != len(signals)
        or any(
            signal.tenant_id != request.tenant_id
            or signal.head_sha != request.head_sha
            or signal.location.path != request.file.path
            or signal.location.content_sha256 != request.file.content_sha256
            or signal.producer != binding.identity.producer
            for signal in signals
        )
    ):
        raise ValueError("scanner worker receipt is invalid")
    return signals


def _read_clock(clock_ns: Callable[[], int]) -> int:
    value = clock_ns()
    if type(value) is not int or value < 0:
        raise ValueError("scanner clock is invalid")
    return value


def _elapsed_ns(
    clock_ns: Callable[[], int], logical_started_ns: int, physical_started_ns: int
) -> int | None:
    try:
        logical_now_ns = _read_clock(clock_ns)
    except ValueError:
        return None
    logical_elapsed_ns = logical_now_ns - logical_started_ns
    if logical_elapsed_ns < 0:
        return None
    return max(logical_elapsed_ns, monotonic_ns() - physical_started_ns)


def _terminate_bounded(process: _WorkerProcess) -> None:
    try:
        if process.is_alive():
            process.terminate()
            process.join(_TEARDOWN_SECONDS)
        if process.is_alive():
            process.kill()
            process.join(_TEARDOWN_SECONDS)
    except Exception:
        pass
    finally:
        with suppress(Exception):
            process.close()


def _close_quietly(connection: _WorkerConnection) -> None:
    with suppress(OSError):
        connection.close()


def _failure(
    binding: ScannerPluginBinding,
    request: ScannerRequest,
    elapsed_ns: int,
    input_bytes: int,
    output_bytes: int,
    status: ScannerRunStatus,
    failure_code: ScannerFailureCode,
) -> ScannerExecution:
    return ScannerExecution(
        request_id=request.request_id,
        scanner=binding.identity,
        isolation=binding.isolation,
        status=status,
        elapsed_ns=elapsed_ns,
        input_bytes=input_bytes,
        output_bytes=output_bytes,
        signals=(),
        signal_digest=raw_signal_digest(()),
        failure_code=failure_code,
    )


__all__ = ["ScannerPluginBinding", "register_scanner_worker", "run_scanner_plugin"]
