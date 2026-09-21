"""Candidate coverage units and canonical safe receipt digests."""

from __future__ import annotations

import hashlib
import json

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CoverageStatus,
    CoverageUnit,
    DiscoveryCandidate,
    ModelCallStatus,
)
from securecode_ai.core.finding_gate import FindingGateDecision
from securecode_ai.core.investigation import AuditorAttemptReceipt, AuditorInvestigationReceipt
from securecode_ai.core.skeptic import SkepticReview

from .product_review_contracts import ProductReviewFailureCode


def _coverage_unit(
    *,
    stage_id: str,
    candidate: DiscoveryCandidate,
    status: CoverageStatus,
    reason_code: str | None,
    input_hashes: tuple[str, ...],
    output_hashes: tuple[str, ...],
    model_status: ModelCallStatus | None = None,
    schema_valid: bool | None = None,
    receipt_id: str | None = None,
) -> CoverageUnit:
    return CoverageUnit(
        schema_version=CONTRACT_SCHEMA_VERSION,
        coverage_unit_id=_coverage_unit_id(stage_id, candidate),
        stage_id=stage_id,
        subject_id=candidate.candidate_id,
        required=True,
        applicable=True,
        coverage_status=status,
        reason_code=reason_code,
        producer_version="0.1.0" if status is CoverageStatus.COMPLETED else None,
        input_hashes=input_hashes if status is CoverageStatus.COMPLETED else (),
        output_hashes=output_hashes if status is CoverageStatus.COMPLETED else (),
        model_call_status=model_status,
        schema_valid_result=schema_valid,
        receipt_id=receipt_id,
    )


def _coverage_unit_id(stage_id: str, candidate: DiscoveryCandidate) -> str:
    return f"review-{stage_id[:8]}-{_candidate_digest(candidate)[:32]}"


def _receipt_id(stage: str, candidate: DiscoveryCandidate) -> str:
    return f"{stage}-review-{_candidate_digest(candidate)[:32]}"


def _candidate_failure_sha256(
    candidate: DiscoveryCandidate, failure: ProductReviewFailureCode | None
) -> str:
    return _sha256(
        {
            "candidate_id": candidate.candidate_id,
            "candidate_version": candidate.candidate_version,
            "failure": None if failure is None else failure.value,
            "head_sha": candidate.head_sha,
        }
    )


def _candidate_digest(candidate: DiscoveryCandidate) -> str:
    return _sha256(
        {
            "candidate_id": candidate.candidate_id,
            "candidate_version": candidate.candidate_version,
            "head_sha": candidate.head_sha,
        }
    )


def _auditor_receipt_sha256(receipt: AuditorInvestigationReceipt) -> str:
    return _sha256(
        {
            "attempts": [
                {
                    "attempt": item.attempt,
                    "cited_evidence_ids": item.cited_evidence_ids,
                    "finding_verdict": None
                    if item.finding_verdict is None
                    else item.finding_verdict.value,
                    "model_call_status": item.model_call_status.value,
                    "rationale_sha256": item.rationale_sha256,
                    "schema_valid_result": item.schema_valid_result,
                    "selection_sha256": item.selection_sha256,
                }
                for item in receipt.attempts
            ],
            "candidate_id": receipt.candidate_id,
            "candidate_version": receipt.candidate_version,
            "final_model_call_status": receipt.final_model_call_status.value,
            "final_selection_sha256": receipt.final_selection_sha256,
            "finding_verdict": receipt.finding_verdict.value,
            "head_sha": receipt.head_sha,
            "tenant_id": receipt.tenant_id,
        }
    )


def _accepted_terminal_output_sha256(attempt: AuditorAttemptReceipt) -> str:
    """Bind the final verdict and citations to its safe rationale digest.

    ``rationale_sha256`` alone is not an Auditor output digest. The Skeptic
    snapshot receives this canonical digest of all retained terminal-output
    metadata, without retaining the rationale or other provider content.
    """

    return _sha256(
        {
            "cited_evidence_ids": attempt.cited_evidence_ids,
            "finding_verdict": None
            if attempt.finding_verdict is None
            else attempt.finding_verdict.value,
            "rationale_sha256": attempt.rationale_sha256,
            "schema_valid_result": attempt.schema_valid_result,
            "selection_sha256": attempt.selection_sha256,
        }
    )


def _skeptic_receipt_sha256(review: SkepticReview) -> str:
    return _sha256(
        {
            "auditor_identity": review.auditor_identity,
            "auditor_verdict": review.auditor_verdict.value,
            "candidate_id": review.candidate_id,
            "candidate_version": review.candidate_version,
            "cited_evidence_ids": review.cited_evidence_ids,
            "effective_verdict": review.effective_verdict.value,
            "head_sha": review.head_sha,
            "model_call_status": review.model_call_status.value,
            "objections": [
                {"evidence_ids": item.evidence_ids, "kind": item.kind.value}
                for item in review.objections
            ],
            "skeptic_identity": review.skeptic_identity,
            "skeptic_verdict": review.skeptic_verdict.value,
        }
    )


def _finding_gate_sha256(decision: FindingGateDecision) -> str:
    """Canonical safe digest of the complete immutable Finding Gate decision."""

    return _sha256(
        {
            "auditor_cited_evidence_ids": decision.auditor_cited_evidence_ids,
            "auditor_identity": decision.auditor_identity,
            "auditor_model_call_status": decision.auditor_model_call_status.value,
            "auditor_receipt_sha256": decision.auditor_receipt_sha256,
            "auditor_verdict": decision.auditor_verdict.value,
            "candidate_id": decision.candidate_id,
            "candidate_version": decision.candidate_version,
            "finding_gate_state": decision.finding_gate_state.value,
            "head_sha": decision.head_sha,
            "investigation_terminal_status": decision.investigation_terminal_status.value,
            "known_evidence_ids": decision.known_evidence_ids,
            "reason": decision.reason.value,
            "route": decision.route.value,
            "severity": decision.severity.value,
            "skeptic_cited_evidence_ids": decision.skeptic_cited_evidence_ids,
            "skeptic_effective_verdict": decision.skeptic_effective_verdict.value,
            "skeptic_identity": decision.skeptic_identity,
            "skeptic_model_call_status": decision.skeptic_model_call_status.value,
            "skeptic_objections": [
                {"evidence_ids": item.evidence_ids, "kind": item.kind.value}
                for item in decision.skeptic_objections
            ],
            "skeptic_receipt_sha256": decision.skeptic_receipt_sha256,
            "skeptic_verdict": decision.skeptic_verdict.value,
        }
    )


def _sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    ).hexdigest()
