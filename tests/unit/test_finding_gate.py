"""Focused P3.5 policy routing contracts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

import pytest
from securecode_ai.contracts import FindingGateState, FindingVerdict, ModelCallStatus
from securecode_ai.core.classification import FindingSeverity
from securecode_ai.core.finding_gate import (
    FindingGateContractError,
    FindingGateInput,
    FindingGateReason,
    FindingRoute,
    InvestigationTerminalStatus,
    route_finding,
)
from securecode_ai.core.skeptic import SkepticObjection, SkepticObjectionKind

HEAD = "a" * 40
AUDITOR_RECEIPT = "b" * 64
SKEPTIC_RECEIPT = "c" * 64


def _input(
    *,
    severity: FindingSeverity = FindingSeverity.MEDIUM,
    auditor_status: ModelCallStatus = ModelCallStatus.SUCCEEDED,
    skeptic_status: ModelCallStatus = ModelCallStatus.SUCCEEDED,
    auditor_verdict: FindingVerdict = FindingVerdict.CONFIRMED,
    skeptic_verdict: FindingVerdict = FindingVerdict.CONFIRMED,
    effective_verdict: FindingVerdict = FindingVerdict.CONFIRMED,
    objections: tuple[SkepticObjection, ...] = (),
    skeptic_citations: tuple[str, ...] = (),
    terminal_status: InvestigationTerminalStatus = InvestigationTerminalStatus.COMPLETED,
) -> FindingGateInput:
    return FindingGateInput(
        candidate_id="candidate-1",
        candidate_version=1,
        head_sha=HEAD,
        severity=severity,
        known_evidence_ids=("evidence-1", "evidence-2"),
        auditor_identity="auditor-1",
        auditor_receipt_sha256=AUDITOR_RECEIPT,
        auditor_model_call_status=auditor_status,
        auditor_verdict=auditor_verdict,
        auditor_cited_evidence_ids=("evidence-1",),
        skeptic_identity="skeptic-1",
        skeptic_receipt_sha256=SKEPTIC_RECEIPT,
        skeptic_model_call_status=skeptic_status,
        skeptic_verdict=skeptic_verdict,
        skeptic_effective_verdict=effective_verdict,
        skeptic_objections=objections,
        skeptic_cited_evidence_ids=skeptic_citations,
        investigation_terminal_status=terminal_status,
    )


def test_confirmed_route_is_policy_selected_blocking_and_preserves_receipt_metadata() -> None:
    result = route_finding(_input())

    assert result.route is FindingRoute.CONFIRMED
    assert result.finding_gate_state is FindingGateState.BLOCKING
    assert result.reason is FindingGateReason.CONFIRMED
    assert result.auditor_cited_evidence_ids == ("evidence-1",)
    assert result.skeptic_cited_evidence_ids == ()
    assert result.auditor_receipt_sha256 == AUDITOR_RECEIPT
    assert result.skeptic_receipt_sha256 == SKEPTIC_RECEIPT


def test_only_matching_cited_rejection_can_be_clean() -> None:
    result = route_finding(
        _input(
            auditor_verdict=FindingVerdict.REJECTED_WITH_EVIDENCE,
            skeptic_verdict=FindingVerdict.REJECTED_WITH_EVIDENCE,
            effective_verdict=FindingVerdict.REJECTED_WITH_EVIDENCE,
        )
    )

    assert result.route is FindingRoute.REJECTED_WITH_EVIDENCE
    assert result.finding_gate_state is FindingGateState.CLEAN
    assert result.reason is FindingGateReason.REJECTED_WITH_EVIDENCE


def test_needs_more_evidence_is_inconclusive_not_clean() -> None:
    result = route_finding(
        _input(
            auditor_verdict=FindingVerdict.NEEDS_MORE_EVIDENCE,
            skeptic_verdict=FindingVerdict.NEEDS_MORE_EVIDENCE,
            effective_verdict=FindingVerdict.NEEDS_MORE_EVIDENCE,
        )
    )

    assert result.route is FindingRoute.NEEDS_MORE_EVIDENCE
    assert result.finding_gate_state is FindingGateState.INCONCLUSIVE


@pytest.mark.parametrize("severity", [FindingSeverity.HIGH, FindingSeverity.CRITICAL])
def test_high_and_critical_auditor_skeptic_conflict_requires_human_escalation(
    severity: FindingSeverity,
) -> None:
    objection = SkepticObjection(
        SkepticObjectionKind.CONTRADICTORY_EVIDENCE,
        ("evidence-2",),
    )
    result = route_finding(
        _input(
            severity=severity,
            skeptic_verdict=FindingVerdict.REJECTED_WITH_EVIDENCE,
            effective_verdict=FindingVerdict.CONFLICTING,
            objections=(objection,),
            skeptic_citations=("evidence-2",),
        )
    )

    assert result.route is FindingRoute.HUMAN_ESCALATION
    assert result.finding_gate_state is FindingGateState.INCONCLUSIVE
    assert result.reason is FindingGateReason.HIGH_CRITICAL_CONFLICT
    assert result.auditor_verdict is FindingVerdict.CONFIRMED
    assert result.skeptic_verdict is FindingVerdict.REJECTED_WITH_EVIDENCE
    assert result.skeptic_objections == (objection,)


def test_any_other_auditor_skeptic_conflict_still_cannot_route_automatically() -> None:
    objection = SkepticObjection(
        SkepticObjectionKind.INSUFFICIENT_EVIDENCE,
        ("evidence-2",),
    )
    result = route_finding(
        _input(
            severity=FindingSeverity.LOW,
            skeptic_verdict=FindingVerdict.NEEDS_MORE_EVIDENCE,
            effective_verdict=FindingVerdict.CONFLICTING,
            objections=(objection,),
            skeptic_citations=("evidence-2",),
        )
    )

    assert result.route is FindingRoute.HUMAN_ESCALATION
    assert result.finding_gate_state is FindingGateState.INCONCLUSIVE
    assert result.reason is FindingGateReason.AUDITOR_SKEPTIC_CONFLICT


@pytest.mark.parametrize(
    "status",
    [item for item in ModelCallStatus if item is not ModelCallStatus.SUCCEEDED],
)
def test_every_model_non_success_is_indeterminate_never_clean(status: ModelCallStatus) -> None:
    for value in (
        _input(auditor_status=status),
        _input(skeptic_status=status),
    ):
        result = route_finding(value)
        assert result.route is FindingRoute.INDETERMINATE
        assert result.finding_gate_state is FindingGateState.INCONCLUSIVE


@pytest.mark.parametrize(
    ("terminal_status", "reason"),
    [
        (
            InvestigationTerminalStatus.BUDGET_EXHAUSTED,
            FindingGateReason.INVESTIGATION_BUDGET_EXHAUSTED,
        ),
        (InvestigationTerminalStatus.NO_PROGRESS, FindingGateReason.INVESTIGATION_NO_PROGRESS),
        (
            InvestigationTerminalStatus.CONTEXT_EXHAUSTED,
            FindingGateReason.INVESTIGATION_CONTEXT_EXHAUSTED,
        ),
        (InvestigationTerminalStatus.CANCELLED, FindingGateReason.INVESTIGATION_CANCELLED),
        (
            InvestigationTerminalStatus.INVALID_RECEIPT,
            FindingGateReason.INVESTIGATION_INVALID_RECEIPT,
        ),
    ],
)
def test_investigation_exhaustion_and_non_progress_can_never_be_clean(
    terminal_status: InvestigationTerminalStatus,
    reason: FindingGateReason,
) -> None:
    result = route_finding(_input(terminal_status=terminal_status))

    assert result.route is FindingRoute.INDETERMINATE
    assert result.finding_gate_state is FindingGateState.INCONCLUSIVE
    assert result.reason is reason


@pytest.mark.parametrize(
    "build_value",
    [
        lambda: replace(_input(), auditor_cited_evidence_ids=()),
        lambda: replace(_input(), auditor_cited_evidence_ids=("unknown-evidence",)),
        lambda: replace(_input(), skeptic_receipt_sha256=None),
        lambda: replace(_input(), skeptic_effective_verdict=FindingVerdict.REJECTED_WITH_EVIDENCE),
    ],
)
def test_missing_or_invalid_evidence_cannot_become_clean(
    build_value: Callable[[], FindingGateInput],
) -> None:
    result = route_finding(build_value())

    assert result.route is FindingRoute.INDETERMINATE
    assert result.finding_gate_state is FindingGateState.INCONCLUSIVE
    assert result.reason is FindingGateReason.EVIDENCE_INTEGRITY_FAILURE


def test_same_identity_is_rejected_at_trusted_input_boundary() -> None:
    with pytest.raises(FindingGateContractError) as error:
        replace(_input(), skeptic_identity="auditor-1")

    assert str(error.value) == "finding gate contract validation failed"


def test_retained_input_mutation_is_revalidated_to_an_indeterminate_route() -> None:
    value = _input()
    object.__setattr__(value, "auditor_cited_evidence_ids", ("foreign",))

    result = route_finding(value)

    assert result.route is FindingRoute.INDETERMINATE
    assert result.finding_gate_state is FindingGateState.INCONCLUSIVE


def test_decision_constructor_and_tamper_reject_citations_outside_retained_evidence() -> None:
    decision = route_finding(_input())

    with pytest.raises(FindingGateContractError):
        replace(decision, auditor_cited_evidence_ids=("foreign",))

    object.__setattr__(decision, "known_evidence_ids", ())
    with pytest.raises(FindingGateContractError):
        replace(decision)
