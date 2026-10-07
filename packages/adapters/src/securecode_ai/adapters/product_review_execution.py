"""Candidate-local Auditor, Skeptic, and Finding Gate composition."""

from __future__ import annotations

from collections.abc import Callable

from securecode_ai.contracts import (
    CandidateOrigin,
    CoverageStatus,
    DiscoveryCandidate,
    ModelCallStatus,
)
from securecode_ai.core.classification import (
    ClassificationError,
    ClassificationErrorCode,
    FindingSeverity,
)
from securecode_ai.core.finding_gate import (
    FindingAuthority,
    FindingGateDecision,
    FindingGateInput,
    InvestigationTerminalStatus,
    route_finding,
)
from securecode_ai.core.investigation import (
    AuditorAttemptReceipt,
    AuditorInvestigationReceipt,
    InvestigationDisposition,
)
from securecode_ai.core.skeptic import AuditorSnapshot, SkepticReview, review_auditor_snapshot

from .local_product_runner_execution_family import _candidate_family
from .product_review_contracts import (
    ProductCandidateReviewOutcome,
    ProductReviewFailureCode,
    ProductReviewResult,
    SkepticInvocation,
    SkepticReviewPort,
)
from .product_review_hashes import (
    _accepted_terminal_output_sha256,
    _auditor_receipt_sha256,
    _candidate_failure_sha256,
    _coverage_unit,
    _finding_gate_sha256,
    _receipt_id,
    _skeptic_receipt_sha256,
)
from .product_rule_catalogue import ProductRuleMappingError
from .product_scan import ProductCandidateFlow, ProductCandidatePreparationFailure


def run_product_candidate_review(
    flow: ProductCandidateFlow,
    *,
    auditor_identity_for: Callable[[DiscoveryCandidate, AuditorInvestigationReceipt], str],
    severity_for: Callable[[DiscoveryCandidate], FindingSeverity],
    skeptic: SkepticReviewPort | object,
) -> ProductReviewResult:
    """Bridge each actual Auditor receipt through Skeptic and Finding Gate.

    The supplied identities and severity are host-owned policy metadata.  A
    failed Auditor receipt is never passed to ``FindingGateInput.from_skeptic_review``:
    that Core helper correctly assumes a successful Auditor review.  Each
    candidate remains represented after a fault so later candidates continue.
    """

    if (
        type(flow) is not ProductCandidateFlow
        or not callable(auditor_identity_for)
        or not callable(severity_for)
    ):
        raise ValueError("product review dependencies are invalid")
    if (
        flow.discovery.receipt.tenant_id != flow.graph.tenant_id
        or flow.discovery.receipt.head_sha != flow.graph.head_sha
    ):
        raise ValueError("product discovery receipt identity is invalid")
    outcomes = tuple(
        _review_candidate(
            candidate,
            investigation,
            flow=flow,
            auditor_identity_for=auditor_identity_for,
            severity_for=severity_for,
            skeptic=skeptic,
        )
        for candidate, investigation in zip(flow.graph.candidates, flow.investigations, strict=True)
    )
    return ProductReviewResult(
        tenant_id=flow.graph.tenant_id,
        head_sha=flow.graph.head_sha,
        discovery=flow.discovery,
        upstream_incomplete=flow.required_terminal_outcome is not None,
        outcomes=outcomes,
    )


def _review_candidate(
    candidate: DiscoveryCandidate,
    investigation: AuditorInvestigationReceipt | ProductCandidatePreparationFailure,
    *,
    flow: ProductCandidateFlow,
    auditor_identity_for: Callable[[DiscoveryCandidate, AuditorInvestigationReceipt], str],
    severity_for: Callable[[DiscoveryCandidate], FindingSeverity],
    skeptic: SkepticReviewPort | object,
) -> ProductCandidateReviewOutcome:
    if type(investigation) is ProductCandidatePreparationFailure:
        return _failed_outcome(
            candidate,
            status=ModelCallStatus.INVALID_SCHEMA,
            failure=ProductReviewFailureCode.AUDITOR_PREPARATION_FAILED,
        )
    if type(investigation) is not AuditorInvestigationReceipt or not _same_candidate(
        candidate, investigation, flow
    ):
        return _failed_outcome(
            candidate,
            status=ModelCallStatus.INVALID_SCHEMA,
            failure=ProductReviewFailureCode.AUDITOR_RECEIPT_INVALID,
        )
    if investigation.final_model_call_status is not ModelCallStatus.SUCCEEDED:
        return _failed_outcome(
            candidate,
            status=investigation.final_model_call_status,
            failure=ProductReviewFailureCode.AUDITOR_NON_SUCCESS,
        )
    final_attempt = _accepted_final_attempt(candidate, investigation)
    if final_attempt is None:
        return _failed_outcome(
            candidate,
            status=ModelCallStatus.INVALID_SCHEMA,
            failure=ProductReviewFailureCode.AUDITOR_RECEIPT_INVALID,
        )
    try:
        auditor_identity = auditor_identity_for(candidate, investigation)
        snapshot = AuditorSnapshot(
            candidate_id=candidate.candidate_id,
            candidate_version=candidate.candidate_version,
            head_sha=candidate.head_sha,
            auditor_identity=auditor_identity,
            auditor_output_sha256=_accepted_terminal_output_sha256(final_attempt),
            model_call_status=investigation.final_model_call_status,
            finding_verdict=investigation.finding_verdict,
            evidence_ids=candidate.evidence_ids,
        )
    except Exception:
        return _failed_outcome(
            candidate,
            status=ModelCallStatus.INVALID_SCHEMA,
            failure=ProductReviewFailureCode.AUDITOR_RECEIPT_INVALID,
        )
    auditor_receipt_sha256 = _auditor_receipt_sha256(investigation)
    try:
        review_port = getattr(skeptic, "review", None)
        if not callable(review_port):
            raise ValueError
        invocation = review_port(snapshot)
        if type(invocation) is not SkepticInvocation:
            raise ValueError
    except Exception:
        return _failed_outcome(
            candidate,
            status=ModelCallStatus.INVALID_SCHEMA,
            failure=ProductReviewFailureCode.SKEPTIC_PORT_INVALID,
            auditor_receipt_sha256=auditor_receipt_sha256,
            auditor_status=ModelCallStatus.SUCCEEDED,
        )
    try:
        review = review_auditor_snapshot(
            snapshot,
            skeptic_identity=invocation.skeptic_identity,
            model_call_status=invocation.model_call_status,
            output=invocation.output,
        )
    except Exception:
        return _failed_outcome(
            candidate,
            status=ModelCallStatus.INVALID_SCHEMA,
            failure=ProductReviewFailureCode.SKEPTIC_REVIEW_INVALID,
            auditor_receipt_sha256=auditor_receipt_sha256,
            auditor_status=ModelCallStatus.SUCCEEDED,
        )
    skeptic_receipt_sha256 = _skeptic_receipt_sha256(review)
    failure: ProductReviewFailureCode | None = None
    try:
        severity = severity_for(candidate)
        gate_input = FindingGateInput.from_skeptic_review(
            review,
            severity=severity,
            known_evidence_ids=candidate.evidence_ids,
            auditor_receipt_sha256=auditor_receipt_sha256,
            auditor_cited_evidence_ids=final_attempt.cited_evidence_ids,
            skeptic_receipt_sha256=skeptic_receipt_sha256,
            investigation_terminal_status=InvestigationTerminalStatus.COMPLETED,
            authority=_authority(candidate, flow),
        )
        decision = route_finding(gate_input)
    except ProductRuleMappingError:
        failure = ProductReviewFailureCode.RULE_MAPPING_UNSUPPORTED
    except ClassificationError as exc:
        failure = (
            ProductReviewFailureCode.CLASSIFICATION_UNSUPPORTED
            if exc.code is ClassificationErrorCode.UNSUPPORTED_CWE
            else ProductReviewFailureCode.FINDING_GATE_INVALID
        )
    except Exception:
        failure = ProductReviewFailureCode.FINDING_GATE_INVALID
    if failure is not None:
        return _outcome(
            candidate,
            skeptic_review=review,
            finding_gate=None,
            failure=failure,
            auditor_receipt_sha256=auditor_receipt_sha256,
            skeptic_receipt_sha256=skeptic_receipt_sha256,
        )
    return _outcome(
        candidate,
        skeptic_review=review,
        finding_gate=decision,
        failure=None,
        auditor_receipt_sha256=auditor_receipt_sha256,
        skeptic_receipt_sha256=skeptic_receipt_sha256,
    )


def _authority(candidate: DiscoveryCandidate, flow: ProductCandidateFlow) -> FindingAuthority:
    """A verified secret-detector fact is confirmed by the detector (D-117).

    The detector matched the literal value; models review the masked line only and may
    disagree about it. Every other candidate needs the Auditor and the Skeptic.
    """

    if candidate.candidate_origin is not CandidateOrigin.DETERMINISTIC:
        return FindingAuthority.MODEL_REVIEW
    try:
        rule = _candidate_family(candidate, flow.graph)[0]
    except Exception:
        return FindingAuthority.MODEL_REVIEW
    return (
        FindingAuthority.DETERMINISTIC_DETECTOR
        if rule.startswith("secret-")
        else FindingAuthority.MODEL_REVIEW
    )


def _same_candidate(
    candidate: DiscoveryCandidate, receipt: AuditorInvestigationReceipt, flow: ProductCandidateFlow
) -> bool:
    return (
        candidate.tenant_id == flow.graph.tenant_id
        and candidate.head_sha == flow.graph.head_sha
        and receipt.candidate_id == candidate.candidate_id
        and receipt.candidate_version == candidate.candidate_version
        and receipt.tenant_id == flow.graph.tenant_id
        and receipt.head_sha == candidate.head_sha == flow.graph.head_sha
    )


def _accepted_final_attempt(
    candidate: DiscoveryCandidate, receipt: AuditorInvestigationReceipt
) -> AuditorAttemptReceipt | None:
    if (
        receipt.disposition
        not in {
            InvestigationDisposition.CONFIRMED,
            InvestigationDisposition.REJECTED_WITH_EVIDENCE,
        }
        or not receipt.attempts
    ):
        return None
    attempt = receipt.attempts[-1]
    if (
        attempt.model_call_status is not ModelCallStatus.SUCCEEDED
        or not attempt.schema_valid_result
        or attempt.finding_verdict is not receipt.finding_verdict
        or attempt.rationale_sha256 is None
        or receipt.final_selection_sha256 != attempt.selection_sha256
        or not attempt.cited_evidence_ids
        or not set(attempt.cited_evidence_ids).issubset(candidate.evidence_ids)
    ):
        return None
    return attempt


def _failed_outcome(
    candidate: DiscoveryCandidate,
    *,
    status: ModelCallStatus,
    failure: ProductReviewFailureCode,
    auditor_receipt_sha256: str | None = None,
    auditor_status: ModelCallStatus | None = None,
) -> ProductCandidateReviewOutcome:
    return _outcome(
        candidate,
        skeptic_review=None,
        finding_gate=None,
        failure=failure,
        auditor_receipt_sha256=auditor_receipt_sha256,
        auditor_status=status if auditor_status is None else auditor_status,
    )


def _outcome(
    candidate: DiscoveryCandidate,
    *,
    skeptic_review: SkepticReview | None,
    finding_gate: FindingGateDecision | None,
    failure: ProductReviewFailureCode | None,
    auditor_receipt_sha256: str | None,
    skeptic_receipt_sha256: str | None = None,
    auditor_status: ModelCallStatus = ModelCallStatus.SUCCEEDED,
) -> ProductCandidateReviewOutcome:
    auditor_complete = failure not in {
        ProductReviewFailureCode.AUDITOR_PREPARATION_FAILED,
        ProductReviewFailureCode.AUDITOR_RECEIPT_INVALID,
        ProductReviewFailureCode.AUDITOR_NON_SUCCESS,
    }
    skeptic_complete = (
        skeptic_review is not None and skeptic_review.model_call_status is ModelCallStatus.SUCCEEDED
    )
    gate_complete = finding_gate is not None
    reason = None if failure is None else failure.value
    input_hash = candidate.root_cause_fingerprint
    auditor_output = auditor_receipt_sha256 or _candidate_failure_sha256(candidate, failure)
    units = (
        _coverage_unit(
            stage_id="auditor_investigation",
            candidate=candidate,
            status=CoverageStatus.COMPLETED if auditor_complete else CoverageStatus.FAILED,
            reason_code=None if auditor_complete else reason,
            input_hashes=(input_hash,),
            output_hashes=(auditor_output,),
            model_status=auditor_status,
            schema_valid=auditor_complete,
            receipt_id=_receipt_id("auditor", candidate),
        ),
        _coverage_unit(
            stage_id="skeptic_review",
            candidate=candidate,
            status=(
                CoverageStatus.COMPLETED
                if skeptic_complete
                else CoverageStatus.FAILED
                if skeptic_review is not None
                else CoverageStatus.SKIPPED
            ),
            reason_code=None if skeptic_complete else reason or "SKEPTIC_NON_SUCCESS",
            input_hashes=(auditor_output,),
            output_hashes=(
                skeptic_receipt_sha256 or _candidate_failure_sha256(candidate, failure),
            ),
            model_status=(
                skeptic_review.model_call_status
                if skeptic_review is not None
                else ModelCallStatus.INVALID_SCHEMA
            ),
            schema_valid=skeptic_complete,
            receipt_id=_receipt_id("skeptic", candidate),
        ),
        _coverage_unit(
            stage_id="finding_gate",
            candidate=candidate,
            status=CoverageStatus.COMPLETED if gate_complete else CoverageStatus.SKIPPED,
            reason_code=None if gate_complete else reason or "FINDING_GATE_SKIPPED",
            input_hashes=(auditor_output, skeptic_receipt_sha256 or auditor_output),
            output_hashes=(
                (_finding_gate_sha256(finding_gate),)
                if finding_gate is not None
                else (_candidate_failure_sha256(candidate, failure),)
            ),
        ),
    )
    return ProductCandidateReviewOutcome(
        candidate_id=candidate.candidate_id,
        candidate_version=candidate.candidate_version,
        tenant_id=candidate.tenant_id,
        head_sha=candidate.head_sha,
        skeptic_review=skeptic_review,
        finding_gate=finding_gate,
        coverage_units=units,
        failure_code=failure,
    )
