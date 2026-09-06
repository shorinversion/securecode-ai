"""Unit contracts for P3.4's isolated, read-only Skeptic reducer."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from securecode_ai.contracts import FindingVerdict, ModelCallStatus
from securecode_ai.core.skeptic import (
    AuditorSnapshot,
    SkepticContractError,
    SkepticErrorCode,
    SkepticObjection,
    SkepticObjectionKind,
    SkepticOutput,
    review_auditor_snapshot,
)

HEAD = "a" * 40
OUTPUT_SHA = "b" * 64


def _snapshot(*, verdict: FindingVerdict = FindingVerdict.CONFIRMED) -> AuditorSnapshot:
    return AuditorSnapshot(
        candidate_id="candidate-1",
        candidate_version=1,
        head_sha=HEAD,
        auditor_identity="auditor-1",
        auditor_output_sha256=OUTPUT_SHA,
        model_call_status=ModelCallStatus.SUCCEEDED,
        finding_verdict=verdict,
        evidence_ids=("evidence-1", "evidence-2"),
    )


def test_matching_skeptic_verdict_preserves_the_immutable_auditor_snapshot() -> None:
    snapshot = _snapshot()
    result = review_auditor_snapshot(
        snapshot,
        skeptic_identity="skeptic-1",
        model_call_status=ModelCallStatus.SUCCEEDED,
        output=SkepticOutput(FindingVerdict.CONFIRMED),
    )

    assert result.auditor_verdict is FindingVerdict.CONFIRMED
    assert result.skeptic_verdict is FindingVerdict.CONFIRMED
    assert result.effective_verdict is FindingVerdict.CONFIRMED
    assert result.objections == ()
    assert snapshot.evidence_ids == ("evidence-1", "evidence-2")
    with pytest.raises(FrozenInstanceError):
        snapshot.finding_verdict = FindingVerdict.REJECTED_WITH_EVIDENCE  # type: ignore[misc]


def test_typed_objection_preserves_explicit_conflict_and_only_references_audited_evidence() -> None:
    objection = SkepticObjection(
        SkepticObjectionKind.CONTRADICTORY_EVIDENCE,
        ("evidence-2", "evidence-1"),
    )
    result = review_auditor_snapshot(
        _snapshot(),
        skeptic_identity="skeptic-1",
        model_call_status=ModelCallStatus.SUCCEEDED,
        output=SkepticOutput(FindingVerdict.REJECTED_WITH_EVIDENCE, (objection,)),
    )

    assert result.has_conflict
    assert result.effective_verdict is FindingVerdict.CONFLICTING
    assert result.auditor_verdict is FindingVerdict.CONFIRMED
    assert result.skeptic_verdict is FindingVerdict.REJECTED_WITH_EVIDENCE
    assert result.cited_evidence_ids == ("evidence-1", "evidence-2")


@pytest.mark.parametrize(
    "status",
    [
        ModelCallStatus.REFUSED,
        ModelCallStatus.CONTENT_FILTERED,
        ModelCallStatus.EMPTY_OUTPUT,
        ModelCallStatus.INVALID_SCHEMA,
        ModelCallStatus.TIMEOUT,
        ModelCallStatus.PROVIDER_ERROR,
        ModelCallStatus.BUDGET_EXHAUSTED,
        ModelCallStatus.CANCELLED,
    ],
)
def test_non_success_never_becomes_clean_or_an_auditor_verdict(status: ModelCallStatus) -> None:
    result = review_auditor_snapshot(
        _snapshot(),
        skeptic_identity="skeptic-1",
        model_call_status=status,
        output=SkepticOutput(FindingVerdict.CONFIRMED),
    )

    assert result.is_indeterminate
    assert result.model_call_status is status
    assert result.skeptic_verdict is FindingVerdict.NOT_EVALUATED
    assert result.effective_verdict is FindingVerdict.NOT_EVALUATED
    assert result.objections == ()


def test_unknown_or_unexplained_model_output_fails_closed_as_invalid_schema() -> None:
    unexplained = review_auditor_snapshot(
        _snapshot(),
        skeptic_identity="skeptic-1",
        model_call_status=ModelCallStatus.SUCCEEDED,
        output=object(),
    )
    foreign_evidence = review_auditor_snapshot(
        _snapshot(),
        skeptic_identity="skeptic-1",
        model_call_status=ModelCallStatus.SUCCEEDED,
        output=SkepticOutput(
            FindingVerdict.REJECTED_WITH_EVIDENCE,
            (SkepticObjection(SkepticObjectionKind.EVIDENCE_INTEGRITY, ("foreign",)),),
        ),
    )

    assert unexplained.model_call_status is ModelCallStatus.INVALID_SCHEMA
    assert unexplained.effective_verdict is FindingVerdict.NOT_EVALUATED
    assert foreign_evidence.model_call_status is ModelCallStatus.INVALID_SCHEMA
    assert foreign_evidence.effective_verdict is FindingVerdict.NOT_EVALUATED


def test_skeptic_cannot_review_its_own_auditor_output() -> None:
    with pytest.raises(SkepticContractError) as error:
        review_auditor_snapshot(
            _snapshot(),
            skeptic_identity="auditor-1",
            model_call_status=ModelCallStatus.SUCCEEDED,
            output=SkepticOutput(FindingVerdict.CONFIRMED),
        )

    assert error.value.code is SkepticErrorCode.IDENTITY_MISMATCH
    assert str(error.value) == "skeptic contract validation failed"


def test_unexplained_verdict_change_is_not_an_independent_decision() -> None:
    result = review_auditor_snapshot(
        _snapshot(),
        skeptic_identity="skeptic-1",
        model_call_status=ModelCallStatus.SUCCEEDED,
        output=SkepticOutput(FindingVerdict.REJECTED_WITH_EVIDENCE),
    )

    assert result.model_call_status is ModelCallStatus.INVALID_SCHEMA
    assert result.effective_verdict is FindingVerdict.NOT_EVALUATED
