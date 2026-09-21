"""Negative and privacy contracts for bounded product review composition."""

from __future__ import annotations

import pytest
from securecode_ai.adapters.product_review import (
    ProductReviewFailureCode,
    SkepticInvocation,
    run_product_candidate_review,
)
from securecode_ai.contracts import (
    CoverageStatus,
    DiscoveryCandidate,
    FindingGateState,
    FindingVerdict,
    ModelCallStatus,
)
from securecode_ai.core.classification import FindingSeverity
from securecode_ai.core.finding_gate import FindingRoute
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

    def review(self, _snapshot: AuditorSnapshot) -> SkepticInvocation:
        return self.invocation


def _identity(_candidate: DiscoveryCandidate, _receipt: AuditorInvestigationReceipt) -> str:
    return "auditor-scripted"


def _high(_candidate: DiscoveryCandidate) -> FindingSeverity:
    return FindingSeverity.HIGH


@pytest.mark.parametrize("status", [ModelCallStatus.REFUSED, ModelCallStatus.TIMEOUT])
def test_refused_or_timed_out_skeptic_is_indeterminate_and_never_clean(
    monkeypatch: pytest.MonkeyPatch, status: ModelCallStatus
) -> None:
    flow, _, _ = _candidate_flow(monkeypatch, count=1)
    result = run_product_candidate_review(
        flow,
        auditor_identity_for=_identity,
        severity_for=_high,
        skeptic=_ScriptedSkeptic(
            SkepticInvocation("skeptic-scripted", status, SkepticOutput(FindingVerdict.CONFIRMED))
        ),
    )

    outcome = result.outcomes[0]
    assert outcome.skeptic_review is not None
    assert outcome.skeptic_review.model_call_status is status
    assert outcome.finding_gate is not None
    assert outcome.finding_gate.route is FindingRoute.INDETERMINATE
    assert outcome.finding_gate.finding_gate_state is FindingGateState.INCONCLUSIVE
    assert outcome.coverage_units[1].coverage_status is CoverageStatus.FAILED
    assert not result.candidate_coverage_complete


def test_same_identity_or_missing_port_never_reaches_clean_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, _, _ = _candidate_flow(monkeypatch, count=1)
    same_identity = _ScriptedSkeptic(
        SkepticInvocation(
            "auditor-scripted", ModelCallStatus.SUCCEEDED, SkepticOutput(FindingVerdict.CONFIRMED)
        )
    )
    same_result = run_product_candidate_review(
        flow,
        auditor_identity_for=_identity,
        severity_for=_high,
        skeptic=same_identity,
    )
    missing_result = run_product_candidate_review(
        flow,
        auditor_identity_for=_identity,
        severity_for=_high,
        skeptic=object(),
    )

    for result, expected in (
        (same_result, ProductReviewFailureCode.SKEPTIC_REVIEW_INVALID),
        (missing_result, ProductReviewFailureCode.SKEPTIC_PORT_INVALID),
    ):
        outcome = result.outcomes[0]
        assert outcome.failure_code is expected
        assert outcome.finding_gate is None
        assert outcome.coverage_units[2].coverage_status is CoverageStatus.SKIPPED
        assert not result.candidate_coverage_complete


def test_foreign_evidence_is_reduced_to_non_success_before_the_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, _, _ = _candidate_flow(monkeypatch, count=1)
    result = run_product_candidate_review(
        flow,
        auditor_identity_for=_identity,
        severity_for=_high,
        skeptic=_ScriptedSkeptic(
            SkepticInvocation(
                "skeptic-scripted",
                ModelCallStatus.SUCCEEDED,
                SkepticOutput(
                    FindingVerdict.REJECTED_WITH_EVIDENCE,
                    (SkepticObjection(SkepticObjectionKind.EVIDENCE_INTEGRITY, ("foreign",)),),
                ),
            )
        ),
    )

    outcome = result.outcomes[0]
    assert outcome.skeptic_review is not None
    assert outcome.skeptic_review.model_call_status is ModelCallStatus.INVALID_SCHEMA
    assert outcome.finding_gate is not None
    assert outcome.finding_gate.route is FindingRoute.INDETERMINATE
    assert outcome.coverage_units[1].coverage_status is CoverageStatus.FAILED
    assert not result.candidate_coverage_complete


def test_gate_coverage_output_hash_binds_safe_severity_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, _, _ = _candidate_flow(monkeypatch, count=1)
    skeptic = _ScriptedSkeptic(
        SkepticInvocation(
            "skeptic-scripted",
            ModelCallStatus.SUCCEEDED,
            SkepticOutput(FindingVerdict.CONFIRMED),
        )
    )
    low = run_product_candidate_review(
        flow,
        auditor_identity_for=_identity,
        severity_for=lambda _candidate: FindingSeverity.LOW,
        skeptic=skeptic,
    )
    critical = run_product_candidate_review(
        flow,
        auditor_identity_for=_identity,
        severity_for=lambda _candidate: FindingSeverity.CRITICAL,
        skeptic=skeptic,
    )

    low_gate = low.outcomes[0].finding_gate
    critical_gate = critical.outcomes[0].finding_gate
    assert low_gate is not None and critical_gate is not None
    assert low_gate.route is critical_gate.route is FindingRoute.CONFIRMED
    assert low.outcomes[0].coverage_units[2].output_hashes != (
        critical.outcomes[0].coverage_units[2].output_hashes
    )


def test_review_result_excludes_a_skeptic_port_source_canary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, _, _ = _candidate_flow(monkeypatch, count=1)

    class CanarySkeptic:
        raw_provider_content = "source-canary: SELECT secret FROM protected_table"

        def review(self, _snapshot: AuditorSnapshot) -> SkepticInvocation:
            return SkepticInvocation(
                "skeptic-scripted",
                ModelCallStatus.SUCCEEDED,
                SkepticOutput(FindingVerdict.CONFIRMED),
            )

    result = run_product_candidate_review(
        flow,
        auditor_identity_for=_identity,
        severity_for=_high,
        skeptic=CanarySkeptic(),
    )

    assert "source-canary" not in repr(result)
    assert "protected_table" not in repr(result)
