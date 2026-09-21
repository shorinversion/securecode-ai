"""Focused source-free conformance recorder checks."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace

import pytest
from securecode_ai.adapters.local_provider_admission import auditor_selection_sha256
from securecode_ai.adapters.native_sources import NativeSourceCatalogue
from securecode_ai.adapters.product_conformance import (
    ProductAuditorEvidenceRecorder,
    ProductConformanceError,
)
from securecode_ai.adapters.product_execution_stages import ProductDeterministicExecution
from securecode_ai.adapters.product_runtime import ProductAuditorInvocationObservation
from securecode_ai.adapters.product_scan import (
    ProductCandidateFlow,
    ProductCandidatePreparationFailure,
    ProductCompositionFailure,
    run_product_candidate_flow,
)
from securecode_ai.adapters.product_scanner import ProductDeterministicScanResult
from securecode_ai.contracts import (
    AuditRunOutcome,
    FindingVerdict,
    ModelCallStatus,
    ModelRequest,
    ModelUsage,
    RunExecutionIdentity,
)
from securecode_ai.core.evidence_graph import EvidenceGraph
from securecode_ai.core.evidence_package import DEFAULT_EVIDENCE_PACKAGE_LIMITS, EvidencePackage
from securecode_ai.core.investigation import (
    AuditorInvestigationReceipt,
    AuditorInvoker,
    InvestigationBudget,
    InvestigationDisposition,
    InvestigationStopReason,
    ReadOnlyEvidenceContext,
)
from securecode_ai.core.model_discovery import ModelNativeDiscoveryBackend, ModelNativeDiscoveryPlan

from tests.integration import test_product_scan_flow as flow_fixture
from tests.integration.test_product_runtime_harness import _auditor_composition


def _recorded_flow(
    monkeypatch: pytest.MonkeyPatch,
    *,
    count: int = 1,
    collect: bool = True,
    transform: Callable[[ProductAuditorInvocationObservation], ProductAuditorInvocationObservation]
    | None = None,
) -> tuple[
    ProductAuditorEvidenceRecorder,
    ProductCandidateFlow,
    list[ProductAuditorInvocationObservation],
]:
    original_run = run_product_candidate_flow
    original_auditor = _auditor_composition
    discovery_requests: list[ModelRequest] = []
    recorders: list[ProductAuditorEvidenceRecorder] = []
    observations: list[ProductAuditorInvocationObservation] = []

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
        discovery_requests.append(model_plan.request)
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

    def observe(observation: ProductAuditorInvocationObservation) -> None:
        observations.append(observation)
        if collect:
            request_data = observation.request.model_dump(mode="json")
            request_data["execution_identity"] = discovery_requests[
                0
            ].execution_identity.model_dump(mode="json")
            compatible = replace(
                observation,
                request=ModelRequest.model_validate_json(json.dumps(request_data)),
            )
            recorders[0].observe(compatible if transform is None else transform(compatible))

    auditor_composition: Callable[..., object] = original_auditor

    def auditor_with_observer(
        local_monkeypatch: pytest.MonkeyPatch,
        **kwargs: object,
    ) -> object:
        return auditor_composition(local_monkeypatch, observer=observe, **kwargs)

    monkeypatch.setattr(flow_fixture, "run_product_candidate_flow", run_with_recorder)
    monkeypatch.setattr(flow_fixture, "_auditor_composition", auditor_with_observer)
    flow, _, _ = flow_fixture._flow(monkeypatch, count=count)
    assert isinstance(flow, ProductCandidateFlow)
    return recorders[0], flow, observations


def _request_for_attempt(request: ModelRequest, *, attempt: int) -> ModelRequest:
    value = request.model_dump(mode="json")
    value.update(
        attempt=attempt,
        request_id=f"{request.request_id}-attempt-{attempt}",
        idempotency_key=f"{request.idempotency_key}-attempt-{attempt}",
    )
    return ModelRequest.model_validate_json(json.dumps(value))


def _with_execution_identity(request: ModelRequest, identity: RunExecutionIdentity) -> ModelRequest:
    value = request.model_dump(mode="json")
    value["execution_identity"] = identity.model_dump(mode="json")
    return ModelRequest.model_validate_json(json.dumps(value))


def _with_package(request: ModelRequest, package: EvidencePackage) -> ModelRequest:
    value = request.model_dump(mode="json")
    value["evidence"] = [item.model_dump(mode="json") for item in package.model_evidence]
    return ModelRequest.model_validate_json(json.dumps(value))


def _rehashed_package(package: EvidencePackage) -> EvidencePackage:
    return replace(
        package,
        selection_sha256=auditor_selection_sha256(package, DEFAULT_EVIDENCE_PACKAGE_LIMITS),
    )


def test_two_candidates_are_graph_ordered_and_snapshotted(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder, flow, observations = _recorded_flow(monkeypatch, count=2)

    evidence = recorder.finalize(flow)

    assert len(evidence) == len(observations) == 2
    assert [item.invocations[0].package.candidate_id for item in evidence] == [
        item.candidate_id for item in flow.graph.candidates
    ]
    for item, observation, receipt in zip(evidence, observations, flow.investigations, strict=True):
        assert isinstance(receipt, AuditorInvestigationReceipt)
        invocation = item.invocations[0]
        assert invocation.request is not observation.request
        assert invocation.package is not observation.package
        assert invocation.usage.input_tokens + invocation.usage.output_tokens == receipt.tokens_used
        assert invocation.usage.repository_calls == receipt.tool_calls
        assert invocation.usage.elapsed_ms == receipt.elapsed_ms
        assert "public fixture source is selected" not in repr(invocation)


@pytest.mark.parametrize("mode", ["missing", "duplicate", "extra", "preparation", "composition"])
def test_coverage_and_composition_mismatches_latch_safe_error(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    recorder, flow, observations = _recorded_flow(monkeypatch, collect=mode != "missing")

    final_flow = flow
    if mode == "duplicate":
        with pytest.raises(
            ProductConformanceError, match=r"^product auditor conformance collection failed$"
        ):
            recorder.observe(observations[0])
    elif mode == "extra":
        extra = replace(
            observations[0],
            request=_with_execution_identity(
                _request_for_attempt(observations[0].request, attempt=2),
                recorder._discovery_request.execution_identity,
            ),
        )
        recorder.observe(extra)
    elif mode == "preparation":
        candidate = flow.graph.candidates[0]
        final_flow = replace(
            flow,
            investigations=(
                ProductCandidatePreparationFailure(
                    candidate, flow.graph.tenant_id, flow.graph.head_sha
                ),
            ),
            required_terminal_outcome=AuditRunOutcome.INDETERMINATE,
        )
    elif mode == "composition":
        final_flow = object.__new__(ProductCandidateFlow)

    with pytest.raises(
        ProductConformanceError, match=r"^product auditor conformance collection failed$"
    ):
        recorder.finalize(final_flow)


def test_capture_non_success_cannot_be_promoted_by_successful_final_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def non_success(
        observation: ProductAuditorInvocationObservation,
    ) -> ProductAuditorInvocationObservation:
        return replace(
            observation,
            model_call_status_before_collection=ModelCallStatus.PROVIDER_ERROR,
            schema_valid_result_before_collection=False,
        )

    recorder, flow, _ = _recorded_flow(monkeypatch, transform=non_success)

    receipt = flow.investigations[0]
    assert isinstance(receipt, AuditorInvestigationReceipt)
    assert receipt.final_model_call_status is ModelCallStatus.SUCCEEDED
    with pytest.raises(
        ProductConformanceError, match=r"^product auditor conformance collection failed$"
    ):
        recorder.finalize(flow)


def test_non_success_overage_is_retained_for_final_diagnostic_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def known_overage(
        observation: ProductAuditorInvocationObservation,
    ) -> ProductAuditorInvocationObservation:
        usage = observation.usage_before_collection.model_dump(mode="json")
        usage["input_tokens"] = observation.request.budget.max_input_tokens + 1
        return replace(
            observation,
            usage_before_collection=ModelUsage.model_validate_json(json.dumps(usage)),
            model_call_status_before_collection=ModelCallStatus.PROVIDER_ERROR,
            schema_valid_result_before_collection=False,
        )

    recorder, flow, _ = _recorded_flow(monkeypatch, transform=known_overage)

    receipt = flow.investigations[0]
    assert isinstance(receipt, AuditorInvestigationReceipt)
    assert receipt.final_model_call_status is ModelCallStatus.SUCCEEDED
    with pytest.raises(
        ProductConformanceError, match=r"^product auditor conformance collection failed$"
    ):
        recorder.finalize(flow)


@pytest.mark.parametrize("kind", ["foreign_graph", "foreign_content"])
def test_rehashed_same_head_package_substitution_is_rejected_at_finalization(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    def substituted(
        observation: ProductAuditorInvocationObservation,
    ) -> ProductAuditorInvocationObservation:
        if kind == "foreign_graph":
            package = _rehashed_package(
                replace(
                    observation.package,
                    graph_id="foreign-same-head-graph",
                    graph_sha256="b" * 64,
                )
            )
            return replace(observation, package=package)
        selected = replace(observation.package.selected[0], content_id="kid:foreign-content")
        package = _rehashed_package(replace(observation.package, selected=(selected,)))
        return replace(
            observation,
            package=package,
            request=_with_package(observation.request, package),
        )

    recorder, flow, _ = _recorded_flow(monkeypatch, transform=substituted)

    with pytest.raises(
        ProductConformanceError, match=r"^product auditor conformance collection failed$"
    ):
        recorder.finalize(flow)


def test_initial_selection_must_match_the_first_executed_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder, flow, _ = _recorded_flow(monkeypatch)
    receipt = flow.investigations[0]
    assert type(receipt) is AuditorInvestigationReceipt
    flow = replace(flow, investigations=(replace(receipt, initial_selection_sha256="b" * 64),))

    with pytest.raises(
        ProductConformanceError, match=r"^product auditor conformance collection failed$"
    ):
        recorder.finalize(flow)


def test_successful_attempt_at_request_timeout_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder, flow, _ = _recorded_flow(monkeypatch)
    receipt = flow.investigations[0]
    assert type(receipt) is AuditorInvestigationReceipt
    timeout = recorder._captures[(receipt.candidate_id, 1, 1)].request.budget.timeout_ms
    attempt = replace(receipt.attempts[0], elapsed_ms=timeout)
    flow = replace(
        flow,
        investigations=(replace(receipt, attempts=(attempt,), elapsed_ms=timeout),),
    )

    with pytest.raises(
        ProductConformanceError, match=r"^product auditor conformance collection failed$"
    ):
        recorder.finalize(flow)


def test_non_success_attempt_retains_observed_overdeadline_elapsed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def non_success(
        observation: ProductAuditorInvocationObservation,
    ) -> ProductAuditorInvocationObservation:
        return replace(
            observation,
            model_call_status_before_collection=ModelCallStatus.PROVIDER_ERROR,
            schema_valid_result_before_collection=False,
        )

    recorder, flow, _ = _recorded_flow(monkeypatch, transform=non_success)
    receipt = flow.investigations[0]
    assert type(receipt) is AuditorInvestigationReceipt
    timeout = recorder._captures[(receipt.candidate_id, 1, 1)].request.budget.timeout_ms
    attempt = replace(
        receipt.attempts[0],
        model_call_status=ModelCallStatus.PROVIDER_ERROR,
        schema_valid_result=False,
        verdict_id=None,
        finding_verdict=None,
        cited_evidence_ids=(),
        rationale_sha256=None,
        elapsed_ms=timeout,
    )
    flow = replace(
        flow,
        investigations=(
            replace(
                receipt,
                attempts=(attempt,),
                elapsed_ms=timeout,
                final_model_call_status=ModelCallStatus.PROVIDER_ERROR,
                finding_verdict=FindingVerdict.NOT_EVALUATED,
                disposition=InvestigationDisposition.INDETERMINATE,
                stop_reason=InvestigationStopReason.MODEL_NON_SUCCESS,
            ),
        ),
        required_terminal_outcome=AuditRunOutcome.INDETERMINATE,
    )

    evidence = recorder.finalize(flow)

    assert evidence[0].invocations[0].usage.elapsed_ms == timeout


def test_successful_finalization_is_deterministic_and_closes_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder, flow, observations = _recorded_flow(monkeypatch)

    evidence = recorder.finalize(flow)

    assert recorder.finalize(flow) is evidence
    with pytest.raises(
        ProductConformanceError, match=r"^product auditor conformance collection failed$"
    ):
        recorder.observe(observations[0])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("context_rounds", 2),
        ("no_progress_count", 1),
        ("tenant_id", "tenant-other"),
    ],
)
def test_finalized_replay_rejects_mutated_receipt_controls(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: int | str,
) -> None:
    recorder, flow, _ = _recorded_flow(monkeypatch)
    receipt = flow.investigations[0]
    assert type(receipt) is AuditorInvestigationReceipt

    recorder.finalize(flow)
    object.__setattr__(receipt, field, value)

    with pytest.raises(
        ProductConformanceError, match=r"^product auditor conformance collection failed$"
    ):
        recorder.finalize(flow)


def test_two_attempts_reconcile_without_clamping_final_budgeted_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder, flow, observations = _recorded_flow(monkeypatch)
    original = flow.investigations[0]
    assert type(original) is AuditorInvestigationReceipt
    first = original.attempts[0]
    second = replace(original.attempts[0], attempt=2)
    receipt = AuditorInvestigationReceipt(
        candidate_id=original.candidate_id,
        candidate_version=original.candidate_version,
        tenant_id=original.tenant_id,
        head_sha=original.head_sha,
        initial_selection_sha256=original.initial_selection_sha256,
        final_selection_sha256=original.final_selection_sha256,
        attempts=(first, second),
        context_rounds=2,
        tokens_used=first.tokens_used + second.tokens_used,
        tool_calls=first.tool_calls + second.tool_calls,
        elapsed_ms=first.elapsed_ms + second.elapsed_ms,
        no_progress_count=0,
        final_model_call_status=ModelCallStatus.SUCCEEDED,
        finding_verdict=FindingVerdict.CONFIRMED,
        disposition=InvestigationDisposition.CONFIRMED,
        stop_reason=InvestigationStopReason.CONFIRMED,
    )
    flow = replace(flow, investigations=(receipt,))
    second_capture = replace(
        observations[0],
        request=_with_execution_identity(
            _request_for_attempt(observations[0].request, attempt=2),
            recorder._discovery_request.execution_identity,
        ),
    )
    recorder.observe(second_capture)

    evidence = recorder.finalize(flow)

    assert len(evidence[0].invocations) == 2
    assert [item.usage.input_tokens for item in evidence[0].invocations] == [10, 10]
    assert [item.usage.elapsed_ms for item in evidence[0].invocations] == [0, 0]
