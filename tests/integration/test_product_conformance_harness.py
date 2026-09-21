"""Actual Core/authorized harness with scripted sockets, not LIVE qualification."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import Protocol, runtime_checkable

import pytest
from securecode_ai.adapters import (
    AuthorizedProviderHarness,
    EndpointAuthorizationIssuer,
    ProviderProfileRegistry,
)
from securecode_ai.adapters.local_provider_admission import AuditorCandidateEvidence
from securecode_ai.adapters.native_sources import NativeSourceCatalogue
from securecode_ai.adapters.product_conformance import (
    ProductAuditorEvidenceRecorder,
    ProductConformanceError,
)
from securecode_ai.adapters.product_execution_stages import ProductDeterministicExecution
from securecode_ai.adapters.product_runtime import (
    ProductAuditorInvocationObservation,
    ProductAuditorInvoker,
    ProductDiscoveryBackend,
)
from securecode_ai.adapters.product_scan import (
    ProductCandidateFlow,
    ProductCompositionFailure,
    run_product_candidate_flow,
)
from securecode_ai.adapters.product_scanner import ProductDeterministicScanResult
from securecode_ai.contracts import (
    AuditRunOutcome,
    EgressPolicyDocument,
    ModelCallStatus,
    ModelPurpose,
    ModelRequest,
)
from securecode_ai.core.evidence_graph import EvidenceGraph
from securecode_ai.core.evidence_package import EvidencePackage
from securecode_ai.core.investigation import (
    AuditorInvestigationReceipt,
    AuditorInvoker,
    InvestigationBudget,
    ReadOnlyEvidenceContext,
)
from securecode_ai.core.model_discovery import (
    ModelNativeDiscoveryBackend,
    ModelNativeDiscoveryPlan,
    RepositoryToolSession,
)

from tests.integration import test_product_runtime_harness as runtime_fixture
from tests.integration import test_product_scan_flow as flow_fixture
from tests.unit.test_endpoint_policy import ScriptedResolver
from tests.unit.test_provider_preflight import _issuer, _request


@runtime_checkable
class _RecordedEndpoint(Protocol):
    requests: list[tuple[str, dict[str, str], bytes]]


def _recorded_flow(
    monkeypatch: pytest.MonkeyPatch,
    *,
    count: int = 1,
    delay: float = 0.0,
    collector_raises: bool = False,
    auditor_fault: bool = False,
    substitute_graph: bool = False,
    substitute_success_elapsed: int | None = None,
    finalize_before_substitution: bool = False,
) -> tuple[
    ProductCandidateFlow,
    tuple[AuditorCandidateEvidence, ...],
    _RecordedEndpoint,
    Mapping[str, object],
]:
    original_run = run_product_candidate_flow
    original_auditor = runtime_fixture._auditor_composition
    original_discovery = runtime_fixture._composition
    recorders: list[ProductAuditorEvidenceRecorder] = []
    clock = [100.0]

    def discovery_with_shared_policy(
        local_monkeypatch: pytest.MonkeyPatch,
        *,
        policy_name: str = "egress.valid.private-model-source.json",
        body: bytes | None = None,
    ) -> tuple[
        ProductDiscoveryBackend,
        RepositoryToolSession,
        ModelRequest,
        _RecordedEndpoint,
        ScriptedResolver,
    ]:
        backend, tools, request, endpoint, resolver = original_discovery(
            local_monkeypatch, policy_name=policy_name, body=body
        )
        executor = backend._executor
        policy_data = executor._policy.model_dump(mode="json")
        policy_data["policy_version"] = "1.0.1"
        policy_data["rules"][0]["purposes"].append(ModelPurpose.CANDIDATE_INVESTIGATION.value)
        shared_policy = EgressPolicyDocument.model_validate_json(json.dumps(policy_data))
        executor._policy = shared_policy
        executor._harness = AuthorizedProviderHarness(
            model_issuer=_issuer(executor._profile, shared_policy),
            endpoint_issuer=EndpointAuthorizationIssuer(
                provider_registry=ProviderProfileRegistry((executor._profile,))
            ),
        )
        shared_request = _request(
            executor._profile, shared_policy, ModelPurpose.MODEL_NATIVE_DISCOVERY
        )
        request_data = request.model_dump(mode="json")
        request_data["execution_identity"] = shared_request.execution_identity.model_dump(
            mode="json"
        )
        request = ModelRequest.model_validate_json(json.dumps(request_data))
        return backend, tools, request, endpoint, resolver

    def run_with_recorder(
        *,
        catalogue: NativeSourceCatalogue,
        model_plan: ModelNativeDiscoveryPlan,
        model_backend: ModelNativeDiscoveryBackend,
        deterministic_scanner: Callable[
            [NativeSourceCatalogue], EvidenceGraph | ProductDeterministicScanResult
        ],
        auditor_factory: Callable[[EvidenceGraph], AuditorInvoker],
        investigation_budget: InvestigationBudget,
        context_factory: Callable[[EvidenceGraph], ReadOnlyEvidenceContext] | None = None,
        deterministic_execution: ProductDeterministicExecution | None = None,
    ) -> ProductCandidateFlow | ProductCompositionFailure:
        recorder = ProductAuditorEvidenceRecorder(
            discovery_request=model_plan.request,
            investigation_budget=investigation_budget,
        )
        recorders.append(recorder)
        return original_run(
            catalogue=catalogue,
            model_plan=model_plan,
            model_backend=model_backend,
            deterministic_scanner=deterministic_scanner,
            auditor_factory=auditor_factory,
            investigation_budget=investigation_budget,
            context_factory=context_factory,
            deterministic_execution=deterministic_execution,
        )

    def observe(capture: ProductAuditorInvocationObservation) -> None:
        recorders[0].observe(capture)
        clock[0] += delay
        if collector_raises:
            raise RuntimeError("public fixture collector failed")

    def auditor_with_observer(
        local_monkeypatch: pytest.MonkeyPatch,
        *,
        resolution: str = "valid",
        wrong_pin: bool = False,
        request_calls: int = 8,
        factory_delay: bool = False,
        observer: Callable[[ProductAuditorInvocationObservation], None] | None = None,
        body: bytes | None = None,
    ) -> tuple[ProductAuditorInvoker, EvidencePackage, _RecordedEndpoint, RepositoryToolSession]:
        del observer
        invoker, package, endpoint, tools = original_auditor(
            local_monkeypatch,
            resolution=resolution,
            wrong_pin=wrong_pin,
            request_calls=request_calls,
            factory_delay=factory_delay,
            observer=observe,
            body=body,
        )
        invoker._executor._now = lambda: clock[0]
        return invoker, package, endpoint, tools

    monkeypatch.setattr(flow_fixture, "_composition", discovery_with_shared_policy)
    monkeypatch.setattr(flow_fixture, "run_product_candidate_flow", run_with_recorder)
    monkeypatch.setattr(flow_fixture, "_auditor_composition", auditor_with_observer)
    flow, native_endpoint, observed = flow_fixture._flow(
        monkeypatch, count=count, auditor_fault=auditor_fault
    )
    assert isinstance(flow, ProductCandidateFlow)
    assert isinstance(native_endpoint, _RecordedEndpoint)
    if finalize_before_substitution:
        recorders[0].finalize(flow)
    if substitute_graph:
        flow = replace(flow, graph=replace(flow.graph, graph_id="foreign-same-head-graph"))
    if substitute_success_elapsed is not None:
        receipt = flow.investigations[0]
        assert isinstance(receipt, AuditorInvestigationReceipt)
        attempt = replace(receipt.attempts[0], elapsed_ms=substitute_success_elapsed)
        receipt = replace(receipt, attempts=(attempt,), elapsed_ms=substitute_success_elapsed)
        flow = replace(flow, investigations=(receipt,))
    evidence = recorders[0].finalize(flow)
    return flow, evidence, native_endpoint, observed


@pytest.mark.parametrize("count", [0, 1, 2])
def test_core_harness_captures_reconcile_every_normalized_candidate(
    monkeypatch: pytest.MonkeyPatch, count: int
) -> None:
    flow, evidence, native_endpoint, observed = _recorded_flow(monkeypatch, count=count)
    assert len(evidence) == len(flow.graph.candidates) == len(flow.investigations) == count
    assert len(native_endpoint.requests) == 1
    assert flow.required_terminal_outcome is None
    for item, candidate, receipt in zip(
        evidence, flow.graph.candidates, flow.investigations, strict=True
    ):
        assert isinstance(receipt, AuditorInvestigationReceipt)
        assert len(item.invocations) == len(receipt.attempts) == 1
        capture = item.invocations[0]
        assert capture.package.candidate_id == candidate.candidate_id == receipt.candidate_id
        assert capture.package.candidate_version == candidate.candidate_version
        assert capture.request.evidence == capture.package.model_evidence
        assert capture.usage.input_tokens + capture.usage.output_tokens == receipt.tokens_used
        assert capture.usage.repository_calls == receipt.tool_calls
        assert capture.usage.elapsed_ms == receipt.elapsed_ms
        assert "execute(value)" not in repr(item)
        assert "public fixture source is selected" not in repr(item)
        assert not hasattr(item, "origin")
    if count:
        auditor_endpoint = observed["auditor_endpoint"]
        assert isinstance(auditor_endpoint, _RecordedEndpoint)
        assert len(auditor_endpoint.requests) == count


@pytest.mark.parametrize(
    ("delay", "collector_raises", "expected"),
    [
        (0.25, False, ModelCallStatus.SUCCEEDED),
        (0.25, True, ModelCallStatus.GUARDRAIL_BLOCKED),
        (6.0, False, ModelCallStatus.BUDGET_EXHAUSTED),
        (6.0, True, ModelCallStatus.BUDGET_EXHAUSTED),
    ],
)
def test_final_core_receipts_include_collector_time_and_downgrade(
    monkeypatch: pytest.MonkeyPatch,
    delay: float,
    collector_raises: bool,
    expected: ModelCallStatus,
) -> None:
    flow, evidence, _, _ = _recorded_flow(
        monkeypatch, delay=delay, collector_raises=collector_raises
    )
    receipt = flow.investigations[0]
    assert isinstance(receipt, AuditorInvestigationReceipt)
    attempt = receipt.attempts[0]
    usage = evidence[0].invocations[0].usage
    assert attempt.model_call_status is expected
    assert usage.elapsed_ms == attempt.elapsed_ms == int(delay * 1000)
    assert usage.input_tokens + usage.output_tokens == attempt.tokens_used == 15
    assert usage.repository_calls == attempt.tool_calls == 1
    if expected is not ModelCallStatus.SUCCEEDED:
        assert flow.required_terminal_outcome is AuditRunOutcome.INDETERMINATE
        assert receipt.is_indeterminate


def test_actual_invalid_model_schema_stays_non_successful_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, evidence, _, _ = _recorded_flow(monkeypatch, auditor_fault=True)
    assert flow.required_terminal_outcome is AuditRunOutcome.INDETERMINATE
    receipt = flow.investigations[0]
    assert isinstance(receipt, AuditorInvestigationReceipt)
    attempt = receipt.attempts[0]
    assert attempt.model_call_status is ModelCallStatus.INVALID_SCHEMA
    usage = evidence[0].invocations[0].usage
    assert usage.input_tokens + usage.output_tokens == attempt.tokens_used
    assert usage.repository_calls == attempt.tool_calls


def test_actual_captures_reject_same_head_foreign_graph_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(
        ProductConformanceError, match=r"^product auditor conformance collection failed$"
    ):
        _recorded_flow(monkeypatch, substitute_graph=True)


def test_actual_captures_reject_success_receipt_at_request_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(
        ProductConformanceError, match=r"^product auditor conformance collection failed$"
    ):
        _recorded_flow(monkeypatch, substitute_success_elapsed=5000)


def test_finalized_actual_captures_reject_foreign_graph_identity_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(
        ProductConformanceError, match=r"^product auditor conformance collection failed$"
    ):
        _recorded_flow(monkeypatch, substitute_graph=True, finalize_before_substitution=True)
