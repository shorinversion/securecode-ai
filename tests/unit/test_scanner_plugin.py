"""Deferred P2.8 scanner-plugin contract and bounded-outcome tests."""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Callable
from pathlib import Path

import pytest
from securecode_ai.adapters.scanner_plugin import (
    ScannerPluginBinding,
    register_scanner_worker,
    run_scanner_plugin,
)
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ArtifactRef,
    DataClass,
    ProducerRef,
    RawSignal,
    SourceLocation,
    SourcePosition,
)
from securecode_ai.core.repository import RepositoryFile
from securecode_ai.core.scanning import (
    ScannerBudget,
    ScannerFailureCode,
    ScannerIdentity,
    ScannerIsolationMode,
    ScannerPlugin,
    ScannerPluginOutput,
    ScannerRequest,
    ScannerRunStatus,
    ScannerWorkerTarget,
)

TENANT_ID = "tenant-1"
REPOSITORY_ID = "example/application"
HEAD_SHA = "a" * 40
SOURCE = b"value = request.args.get('id')\n"


@pytest.fixture(autouse=True)
def _make_scanner_test_module_spawn_importable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))


def _producer() -> ProducerRef:
    return ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="securecode-test-scanner",
        producer_version="1.0.0",
        producer_sha256="1" * 64,
    )


IDENTITY = ScannerIdentity(_producer())


def _request(source: bytes = SOURCE) -> ScannerRequest:
    return ScannerRequest(
        request_id="scan-request-1",
        tenant_id=TENANT_ID,
        repository_id=REPOSITORY_ID,
        head_sha=HEAD_SHA,
        file=RepositoryFile("app.py", len(source), hashlib.sha256(source).hexdigest()),
        source=source,
    )


def _signal(request: ScannerRequest, *, path: str | None = None) -> RawSignal:
    return RawSignal(
        schema_version=CONTRACT_SCHEMA_VERSION,
        raw_signal_id="signal-1",
        tenant_id=request.tenant_id,
        head_sha=request.head_sha,
        producer=IDENTITY.producer,
        rule_id="python-cwe89",
        location=SourceLocation(
            schema_version=CONTRACT_SCHEMA_VERSION,
            path=request.file.path if path is None else path,
            start=SourcePosition(schema_version=CONTRACT_SCHEMA_VERSION, line=1, column=1),
            end=SourcePosition(schema_version=CONTRACT_SCHEMA_VERSION, line=1, column=6),
            content_sha256=request.file.content_sha256,
        ),
        payload_classification=DataClass.CONFIDENTIAL_SOURCE,
        payload_ref=ArtifactRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=request.tenant_id,
            content_id="source-artifact-1",
            content_sha256=request.file.content_sha256,
            size_bytes=request.file.size_bytes,
            data_class=DataClass.CONFIDENTIAL_SOURCE,
        ),
        signal_sha256=hashlib.sha256(b"signal-1").hexdigest(),
    )


class _ZeroPlugin:
    def scan(self, request: ScannerRequest) -> ScannerPluginOutput:
        del request
        return ScannerPluginOutput(())


class _SignalPlugin:
    def scan(self, request: ScannerRequest) -> ScannerPluginOutput:
        return ScannerPluginOutput((_signal(request),))


class _MismatchedPlugin:
    def scan(self, request: ScannerRequest) -> ScannerPluginOutput:
        return ScannerPluginOutput((_signal(request, path="other.py"),))


class _CrashingPlugin:
    def scan(self, request: ScannerRequest) -> ScannerPluginOutput:
        del request
        raise RuntimeError("PRIVATE_SCANNER_CRASH_CANARY")


class _NeverReturningPlugin:
    def scan(self, request: ScannerRequest) -> ScannerPluginOutput:
        del request
        while True:
            pass


def _binding(
    worker_name: str,
    *,
    isolation: ScannerIsolationMode = ScannerIsolationMode.APPROVED_ISOLATED_WORKER,
) -> ScannerPluginBinding:
    target = ScannerWorkerTarget(__name__, worker_name)
    factory: Callable[[], ScannerPlugin]
    if worker_name == "_ZeroPlugin":
        factory = _ZeroPlugin
    elif worker_name == "_SignalPlugin":
        factory = _SignalPlugin
    elif worker_name == "_MismatchedPlugin":
        factory = _MismatchedPlugin
    elif worker_name == "_CrashingPlugin":
        factory = _CrashingPlugin
    elif worker_name == "_NeverReturningPlugin":
        factory = _NeverReturningPlugin
    else:
        raise ValueError("test scanner worker is unknown")
    register_scanner_worker(target, factory)
    return ScannerPluginBinding(
        IDENTITY,
        target,
        isolation,
    )


def test_completed_zero_is_scanner_coverage_not_a_product_pass() -> None:
    result = run_scanner_plugin(_binding("_ZeroPlugin"), _request())

    assert result.status is ScannerRunStatus.SUCCEEDED
    assert result.failure_code is None
    assert result.signals == ()
    assert len(result.signal_digest) == 64
    assert "PASS" not in {item.value for item in ScannerRunStatus}


def test_plugin_emits_the_normative_raw_signal_fact_without_verdict_fields() -> None:
    request = _request()
    result = run_scanner_plugin(_binding("_SignalPlugin"), request)

    assert result.signals == (_signal(request),)
    assert {"finding", "severity", "verdict"}.isdisjoint(RawSignal.model_fields)
    assert result.signals[0].location.content_sha256 == request.file.content_sha256


def test_mismatched_fact_identity_is_rejected_without_retaining_signal() -> None:
    result = run_scanner_plugin(_binding("_MismatchedPlugin"), _request())

    assert result.status is ScannerRunStatus.INVALID_OUTPUT
    assert result.failure_code is ScannerFailureCode.PLUGIN_OUTPUT_INVALID
    assert result.signals == ()


def test_host_clock_turns_late_return_into_timeout_without_retaining_output() -> None:
    request = _request()
    ticks = iter((100, 111))
    result = run_scanner_plugin(
        _binding("_SignalPlugin"),
        request,
        budget=ScannerBudget(max_elapsed_ns=10),
        clock_ns=lambda: next(ticks),
    )

    assert result.status is ScannerRunStatus.TIMEOUT
    assert result.failure_code is ScannerFailureCode.TIME_BUDGET_EXCEEDED
    assert result.signals == ()


def test_plugin_crash_is_non_echoing_typed_outcome() -> None:
    result = run_scanner_plugin(_binding("_CrashingPlugin"), _request())

    assert result.status is ScannerRunStatus.CRASHED
    assert result.failure_code is ScannerFailureCode.PLUGIN_CRASHED
    assert "PRIVATE_SCANNER_CRASH_CANARY" not in repr(result)


def test_input_and_retained_output_budgets_fail_closed() -> None:
    request = _request()
    oversized_input = run_scanner_plugin(
        _binding("_ZeroPlugin"), request, budget=ScannerBudget(max_input_bytes=1)
    )
    oversized_output = run_scanner_plugin(
        _binding("_SignalPlugin"), request, budget=ScannerBudget(max_fact_bytes=1)
    )

    assert oversized_input.failure_code is ScannerFailureCode.INPUT_BUDGET_EXCEEDED
    assert oversized_output.failure_code is ScannerFailureCode.OUTPUT_BUDGET_EXCEEDED


def test_in_process_callback_is_rejected_before_worker_start() -> None:
    result = run_scanner_plugin(
        _binding("_ZeroPlugin", isolation=ScannerIsolationMode.FIRST_PARTY_IN_PROCESS), _request()
    )

    assert result.status is ScannerRunStatus.ISOLATION_FAILED
    assert result.failure_code is ScannerFailureCode.ISOLATION_REQUIRED


def test_never_returning_plugin_times_out_without_running_in_host_process() -> None:
    result = run_scanner_plugin(
        _binding("_NeverReturningPlugin"),
        _request(),
        budget=ScannerBudget(max_elapsed_ns=1_000_000),
    )

    assert result.status is ScannerRunStatus.TIMEOUT
    assert result.failure_code is ScannerFailureCode.TIME_BUDGET_EXCEEDED
    assert result.signals == ()


def test_plugin_port_has_no_path_shell_network_or_filesystem_arguments() -> None:
    assert set(inspect.signature(run_scanner_plugin).parameters).isdisjoint(
        {"path", "shell", "command", "network", "endpoint", "environment"}
    )
    assert set(ScannerWorkerTarget.__dataclass_fields__) == {"module", "qualname"}
    assert set(ScannerRequest.__dataclass_fields__) == {
        "request_id",
        "tenant_id",
        "repository_id",
        "head_sha",
        "file",
        "source",
    }
