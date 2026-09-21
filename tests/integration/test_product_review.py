"""Product review composition over the existing scripted ProductCandidateFlow."""

from __future__ import annotations

import pytest
from securecode_ai.adapters.product_review import (
    ProductReviewFailureCode,
    SkepticInvocation,
    run_product_candidate_review,
)
from securecode_ai.adapters.product_scan import (
    ProductCandidateFlow,
    ProductCandidatePreparationFailure,
)
from securecode_ai.contracts import (
    AuditRunOutcome,
    CoverageStatus,
    DiscoveryCandidate,
    FindingVerdict,
    ModelCallStatus,
)
from securecode_ai.core.classification import FindingSeverity
from securecode_ai.core.finding_gate import FindingGateReason, FindingRoute
from securecode_ai.core.investigation import AuditorInvestigationReceipt
from securecode_ai.core.skeptic import (
    AuditorSnapshot,
    SkepticObjection,
    SkepticObjectionKind,
    SkepticOutput,
)

from tests.integration.test_product_scan_flow import _candidate_flow


class _ScriptedSkeptic:
    def __init__(self, invocation: SkepticInvocation) -> None:
        self.invocation = invocation
        self.snapshots: list[AuditorSnapshot] = []

    def review(self, snapshot: AuditorSnapshot) -> SkepticInvocation:
        self.snapshots.append(snapshot)
        return self.invocation


def _identity(candidate: DiscoveryCandidate, receipt: AuditorInvestigationReceipt) -> str:
    assert candidate.candidate_id == receipt.candidate_id
    return "auditor-scripted"


def _high(_candidate: DiscoveryCandidate) -> FindingSeverity:
    return FindingSeverity.HIGH


def test_actual_flow_uses_independent_skeptic_and_routes_high_disagreement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, _, _ = _candidate_flow(monkeypatch, count=1)
    evidence_id = flow.graph.candidates[0].evidence_ids[0]
    skeptic = _ScriptedSkeptic(
        SkepticInvocation(
            "skeptic-scripted",
            ModelCallStatus.SUCCEEDED,
            SkepticOutput(
                FindingVerdict.REJECTED_WITH_EVIDENCE,
                (SkepticObjection(SkepticObjectionKind.CONTRADICTORY_EVIDENCE, (evidence_id,)),),
            ),
        )
    )

    result = run_product_candidate_review(
        flow,
        auditor_identity_for=_identity,
        severity_for=_high,
        skeptic=skeptic,
    )

    outcome = result.outcomes[0]
    assert result.tenant_id == flow.graph.tenant_id
    assert result.head_sha == flow.graph.head_sha
    assert result.discovery is flow.discovery
    assert not result.upstream_incomplete
    assert len(skeptic.snapshots) == 1
    assert outcome.finding_gate is not None
    assert outcome.finding_gate.route is FindingRoute.HUMAN_ESCALATION
    assert outcome.finding_gate.reason is FindingGateReason.HIGH_CRITICAL_CONFLICT
    assert all(unit.coverage_status is CoverageStatus.COMPLETED for unit in outcome.coverage_units)
    assert result.candidate_coverage_complete
    assert not result.has_known_blocking_finding


def test_actual_flow_continues_after_a_candidate_preparation_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, _, _ = _candidate_flow(monkeypatch, count=2)
    first = flow.graph.candidates[0]
    degraded = ProductCandidateFlow(
        flow.discovery,
        flow.graph,
        (
            ProductCandidatePreparationFailure(first, flow.graph.tenant_id, flow.graph.head_sha),
            flow.investigations[1],
        ),
        flow.deterministic_failed,
        AuditRunOutcome.INDETERMINATE,
    )
    skeptic = _ScriptedSkeptic(
        SkepticInvocation(
            "skeptic-scripted",
            ModelCallStatus.SUCCEEDED,
            SkepticOutput(FindingVerdict.CONFIRMED),
        )
    )

    result = run_product_candidate_review(
        degraded,
        auditor_identity_for=_identity,
        severity_for=_high,
        skeptic=skeptic,
    )

    first_outcome, second_outcome = result.outcomes
    assert first_outcome.failure_code is ProductReviewFailureCode.AUDITOR_PREPARATION_FAILED
    assert first_outcome.finding_gate is None
    assert second_outcome.finding_gate is not None
    assert second_outcome.finding_gate.route is FindingRoute.CONFIRMED
    assert result.has_known_blocking_finding
    assert not result.candidate_coverage_complete
    assert len(skeptic.snapshots) == 1


def test_host_identity_fault_is_candidate_local_and_does_not_stop_later_review(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, _, _ = _candidate_flow(monkeypatch, count=2)
    failed_candidate_id = flow.graph.candidates[0].candidate_id
    skeptic = _ScriptedSkeptic(
        SkepticInvocation(
            "skeptic-scripted",
            ModelCallStatus.SUCCEEDED,
            SkepticOutput(FindingVerdict.CONFIRMED),
        )
    )

    def faulting_identity(
        candidate: DiscoveryCandidate, _receipt: AuditorInvestigationReceipt
    ) -> str:
        if candidate.candidate_id == failed_candidate_id:
            raise RuntimeError("host-only failure")
        return "auditor-scripted"

    result = run_product_candidate_review(
        flow,
        auditor_identity_for=faulting_identity,
        severity_for=_high,
        skeptic=skeptic,
    )

    first_outcome, second_outcome = result.outcomes
    assert first_outcome.failure_code is ProductReviewFailureCode.AUDITOR_RECEIPT_INVALID
    assert second_outcome.finding_gate is not None
    assert second_outcome.finding_gate.route is FindingRoute.CONFIRMED
    assert len(skeptic.snapshots) == 1


@pytest.mark.parametrize("failed_index", [0, 1])
def test_severity_fault_is_local_and_preserves_the_other_confirmed_block(
    monkeypatch: pytest.MonkeyPatch, failed_index: int
) -> None:
    flow, _, _ = _candidate_flow(monkeypatch, count=2)
    failed_candidate_id = flow.graph.candidates[failed_index].candidate_id
    skeptic = _ScriptedSkeptic(
        SkepticInvocation(
            "skeptic-scripted",
            ModelCallStatus.SUCCEEDED,
            SkepticOutput(FindingVerdict.CONFIRMED),
        )
    )

    def faulting_severity(candidate: DiscoveryCandidate) -> FindingSeverity:
        if candidate.candidate_id == failed_candidate_id:
            raise RuntimeError("severity-canary: confidential host detail")
        return FindingSeverity.HIGH

    result = run_product_candidate_review(
        flow,
        auditor_identity_for=_identity,
        severity_for=faulting_severity,
        skeptic=skeptic,
    )

    failed = result.outcomes[failed_index]
    confirmed = result.outcomes[1 - failed_index]
    assert failed.failure_code is ProductReviewFailureCode.FINDING_GATE_INVALID
    assert failed.finding_gate is None
    assert confirmed.finding_gate is not None
    assert confirmed.finding_gate.route is FindingRoute.CONFIRMED
    assert result.has_known_blocking_finding
    assert not result.candidate_coverage_complete
    assert len(skeptic.snapshots) == 2
    assert "severity-canary" not in repr(result)
    assert "confidential host detail" not in repr(result)


def test_completed_zero_flow_never_invokes_skeptic_or_claims_candidate_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, _, _ = _candidate_flow(monkeypatch, count=0)
    skeptic = _ScriptedSkeptic(
        SkepticInvocation(
            "skeptic-scripted", ModelCallStatus.SUCCEEDED, SkepticOutput(FindingVerdict.CONFIRMED)
        )
    )

    result = run_product_candidate_review(
        flow,
        auditor_identity_for=_identity,
        severity_for=_high,
        skeptic=skeptic,
    )

    assert result.outcomes == ()
    assert result.coverage_units == ()
    assert skeptic.snapshots == []
    assert not result.candidate_coverage_complete
    assert not result.has_known_blocking_finding


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tenant_id", "tenant-other"),
        ("head_sha", "b" * 40),
        ("candidate_version", 2),
    ],
)
def test_foreign_tenant_head_or_version_receipt_is_failed_without_skeptic(
    monkeypatch: pytest.MonkeyPatch, field: str, value: str | int
) -> None:
    flow, _, _ = _candidate_flow(monkeypatch, count=1)
    receipt = flow.investigations[0]
    object.__setattr__(receipt, field, value)
    skeptic = _ScriptedSkeptic(
        SkepticInvocation(
            "skeptic-scripted", ModelCallStatus.SUCCEEDED, SkepticOutput(FindingVerdict.CONFIRMED)
        )
    )

    result = run_product_candidate_review(
        flow,
        auditor_identity_for=_identity,
        severity_for=_high,
        skeptic=skeptic,
    )

    outcome = result.outcomes[0]
    assert outcome.failure_code is ProductReviewFailureCode.AUDITOR_RECEIPT_INVALID
    assert outcome.finding_gate is None
    assert outcome.coverage_units[0].coverage_status is CoverageStatus.FAILED
    assert outcome.coverage_units[1].coverage_status is CoverageStatus.SKIPPED
    assert skeptic.snapshots == []
