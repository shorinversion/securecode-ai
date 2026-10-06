"""Focused P3.3 tests for the bounded, evidence-gated Auditor loop."""

from __future__ import annotations

from collections.abc import Sequence

from securecode_ai.contracts import DataClass, FindingVerdict, ModelCallStatus
from securecode_ai.core.auditor import AuditorResponse, AuditorVerdict
from securecode_ai.core.evidence_package import EvidenceContextRef, EvidencePackage
from securecode_ai.core.investigation import (
    AuditorInvocation,
    InvestigationBudget,
    InvestigationDisposition,
    InvestigationStopReason,
    run_auditor_investigation,
)


def _package(*, evidence_id: str = "evidence-a", selection: str = "a") -> EvidencePackage:
    return _package_with(evidence_ids=(evidence_id,), selection=selection)


def _package_with(*, evidence_ids: tuple[str, ...], selection: str) -> EvidencePackage:
    references = tuple(
        EvidenceContextRef(
            evidence_id=evidence_id,
            content_id=f"content-{evidence_id}",
            data_class=DataClass.CONFIDENTIAL_SECURITY,
            evidence_sha256="b" * 64,
            producer_id="scanner",
            producer_version="1.0.0",
            producer_sha256="c" * 64,
            context_bytes=4,
            estimated_tokens=1,
        )
        for evidence_id in evidence_ids
    )
    return EvidencePackage(
        candidate_id="candidate-a",
        candidate_version=1,
        tenant_id="tenant-a",
        head_sha="1" * 40,
        graph_id="graph-a",
        graph_sha256="d" * 64,
        selection_sha256=selection * 64,
        selected=references,
        omitted_evidence_ids=(),
        total_context_bytes=4 * len(references),
        total_input_tokens=len(references),
        truncated=False,
    )


def _response(verdict: FindingVerdict) -> AuditorResponse:
    return AuditorResponse(
        model_call_status=ModelCallStatus.SUCCEEDED,
        schema_valid_result=True,
        verdict=AuditorVerdict(
            verdict_id=f"verdict-{verdict.value.lower()}",
            finding_verdict=verdict,
            cited_evidence_ids=("evidence-a",),
            rationale_sha256="e" * 64,
        ),
    )


class _Auditor:
    def __init__(self, invocations: Sequence[AuditorInvocation]) -> None:
        self._invocations = iter(invocations)
        self.calls = 0

    def invoke(self, package: EvidencePackage, *, attempt: int) -> AuditorInvocation:
        del package, attempt
        self.calls += 1
        return next(self._invocations)


class _Context:
    def __init__(self, next_package: EvidencePackage | None) -> None:
        self.next = next_package
        self.calls = 0

    def next_package(self, package: EvidencePackage, *, attempt: int) -> EvidencePackage | None:
        del package, attempt
        self.calls += 1
        return self.next


def _invocation(verdict: FindingVerdict, *, tokens: int = 1) -> AuditorInvocation:
    return AuditorInvocation(
        response=_response(verdict),
        tokens_used=tokens,
        tool_calls=1,
        elapsed_ms=2,
    )


def test_confirmation_is_terminal_and_is_not_a_product_pass() -> None:
    auditor = _Auditor((_invocation(FindingVerdict.CONFIRMED),))
    context = _Context(
        _package_with(
            evidence_ids=("evidence-a", "evidence-b"),
            selection="f",
        )
    )

    receipt = run_auditor_investigation(
        _package(),
        budget=InvestigationBudget(2, 10, 10, 10),
        auditor=auditor,
        context=context,
    )

    assert receipt.disposition is InvestigationDisposition.CONFIRMED
    assert receipt.stop_reason is InvestigationStopReason.CONFIRMED
    assert receipt.finding_verdict is FindingVerdict.CONFIRMED
    assert auditor.calls == 1
    assert context.calls == 0
    assert not hasattr(receipt, "route")


def test_only_new_selected_evidence_permits_second_context_round() -> None:
    first = _invocation(FindingVerdict.NEEDS_MORE_EVIDENCE)
    second_response = AuditorResponse(
        model_call_status=ModelCallStatus.SUCCEEDED,
        schema_valid_result=True,
        verdict=AuditorVerdict(
            verdict_id="verdict-reject",
            finding_verdict=FindingVerdict.REJECTED_WITH_EVIDENCE,
            cited_evidence_ids=("evidence-b",),
            rationale_sha256="f" * 64,
        ),
    )
    auditor = _Auditor((first, AuditorInvocation(second_response, 1, 1, 2)))
    context = _Context(
        _package_with(
            evidence_ids=("evidence-a", "evidence-b"),
            selection="f",
        )
    )

    receipt = run_auditor_investigation(
        _package(),
        budget=InvestigationBudget(3, 10, 10, 10),
        auditor=auditor,
        context=context,
    )

    assert receipt.disposition is InvestigationDisposition.REJECTED_WITH_EVIDENCE
    assert receipt.context_rounds == 2
    assert tuple(item.selection_sha256 for item in receipt.attempts) == (
        "a" * 64,
        "f" * 64,
    )
    assert auditor.calls == 2


def test_repeated_context_is_no_progress_and_never_clean() -> None:
    auditor = _Auditor((_invocation(FindingVerdict.NEEDS_MORE_EVIDENCE),))
    context = _Context(_package())

    receipt = run_auditor_investigation(
        _package(),
        budget=InvestigationBudget(3, 10, 10, 10),
        auditor=auditor,
        context=context,
    )

    assert receipt.is_indeterminate
    assert receipt.finding_verdict is FindingVerdict.NOT_EVALUATED
    assert receipt.stop_reason is InvestigationStopReason.NO_NEW_EVIDENCE
    assert receipt.final_model_call_status is ModelCallStatus.INCOMPLETE
    assert auditor.calls == 1


def test_context_replacing_prior_evidence_is_no_progress_and_never_clean() -> None:
    auditor = _Auditor((_invocation(FindingVerdict.NEEDS_MORE_EVIDENCE),))
    context = _Context(_package(evidence_id="evidence-b", selection="f"))

    receipt = run_auditor_investigation(
        _package(),
        budget=InvestigationBudget(3, 10, 10, 10),
        auditor=auditor,
        context=context,
    )

    assert receipt.is_indeterminate
    assert receipt.stop_reason is InvestigationStopReason.NO_NEW_EVIDENCE
    assert receipt.finding_verdict is FindingVerdict.NOT_EVALUATED
    assert auditor.calls == 1


def test_non_success_is_terminal_not_evaluated() -> None:
    non_success = AuditorInvocation(
        response=AuditorResponse(ModelCallStatus.TIMEOUT, False, None),
        tokens_used=1,
        tool_calls=1,
        elapsed_ms=2,
    )
    auditor = _Auditor((non_success,))

    receipt = run_auditor_investigation(
        _package(),
        budget=InvestigationBudget(3, 10, 10, 10),
        auditor=auditor,
        context=_Context(None),
    )

    assert receipt.is_indeterminate
    assert receipt.stop_reason is InvestigationStopReason.MODEL_NON_SUCCESS
    assert receipt.finding_verdict is FindingVerdict.NOT_EVALUATED
    assert receipt.final_model_call_status is ModelCallStatus.TIMEOUT


def test_exhausted_host_budget_overrides_successful_provider_output() -> None:
    auditor = _Auditor((_invocation(FindingVerdict.CONFIRMED, tokens=2),))

    receipt = run_auditor_investigation(
        _package(),
        budget=InvestigationBudget(3, 2, 10, 10),
        auditor=auditor,
        context=_Context(None),
    )

    assert receipt.is_indeterminate
    assert receipt.stop_reason is InvestigationStopReason.BUDGET_EXHAUSTED
    assert receipt.final_model_call_status is ModelCallStatus.BUDGET_EXHAUSTED


def test_context_rounds_are_hard_capped_at_two() -> None:
    auditor = _Auditor(
        (
            _invocation(FindingVerdict.NEEDS_MORE_EVIDENCE),
            _invocation(FindingVerdict.NEEDS_MORE_EVIDENCE),
        )
    )
    second = _package_with(
        evidence_ids=("evidence-a", "evidence-b"),
        selection="f",
    )
    context = _Context(second)

    receipt = run_auditor_investigation(
        _package(),
        budget=InvestigationBudget(3, 10, 10, 10, max_context_rounds=2),
        auditor=auditor,
        context=context,
    )

    assert receipt.is_indeterminate
    assert receipt.context_rounds == 2
    assert receipt.stop_reason is InvestigationStopReason.CONTEXT_ROUNDS_EXHAUSTED
    assert auditor.calls == 2
    assert context.calls == 1


def _malformed() -> AuditorInvocation:
    return AuditorInvocation(
        response=AuditorResponse(ModelCallStatus.INVALID_SCHEMA, False, None),
        tokens_used=1,
        tool_calls=1,
        elapsed_ms=2,
    )


def test_malformed_answer_is_regenerated_within_the_attempt_budget() -> None:
    auditor = _Auditor((_malformed(), _invocation(FindingVerdict.CONFIRMED)))

    receipt = run_auditor_investigation(
        _package(),
        budget=InvestigationBudget(2, 10, 10, 10),
        auditor=auditor,
        context=_Context(None),
    )

    assert auditor.calls == 2
    assert receipt.finding_verdict is FindingVerdict.CONFIRMED


def test_malformed_answers_beyond_the_attempt_budget_stay_indeterminate() -> None:
    auditor = _Auditor((_malformed(), _malformed()))

    receipt = run_auditor_investigation(
        _package(),
        budget=InvestigationBudget(2, 10, 10, 10),
        auditor=auditor,
        context=_Context(None),
    )

    assert auditor.calls == 2
    assert receipt.is_indeterminate
    assert receipt.final_model_call_status is ModelCallStatus.INVALID_SCHEMA
