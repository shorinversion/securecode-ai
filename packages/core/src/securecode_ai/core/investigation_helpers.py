"""Bounded, fail-closed Auditor investigation orchestration.

This module consumes the metadata-only P3.1 context and P3.2 parsed Auditor
contract.  It deliberately has no model transport, repository handle, route
selector, filesystem access, or raw output retention.  The host owns all
budgets; a provider can supply only a typed invocation result and a read-only
context port can supply only a next :class:`EvidencePackage`.
"""

from __future__ import annotations

from securecode_ai.contracts import FindingVerdict, ModelCallStatus

from .auditor import AuditorResponse
from .evidence_package import EvidenceContextRef, EvidencePackage
from .investigation_models import (
    AuditorAttemptReceipt,
    AuditorInvestigationReceipt,
    AuditorInvocation,
    AuditorInvoker,
    InvestigationDisposition,
    InvestigationError,
    InvestigationErrorCode,
    InvestigationStopReason,
    ReadOnlyEvidenceContext,
)


def _invoke(
    auditor: AuditorInvoker, package: EvidencePackage, *, attempt: int
) -> AuditorInvocation:
    """Contain an untrusted provider exception as a source-free non-success."""

    try:
        invocation = auditor.invoke(package, attempt=attempt)
    except Exception:
        return AuditorInvocation(
            response=AuditorResponse(
                model_call_status=ModelCallStatus.PROVIDER_ERROR,
                schema_valid_result=False,
                verdict=None,
            ),
            tokens_used=0,
            tool_calls=0,
            elapsed_ms=0,
        )
    try:
        return AuditorInvocation(
            response=invocation.response,
            tokens_used=invocation.tokens_used,
            tool_calls=invocation.tool_calls,
            elapsed_ms=invocation.elapsed_ms,
        )
    except Exception:
        return AuditorInvocation(
            response=AuditorResponse(
                model_call_status=ModelCallStatus.PROVIDER_ERROR,
                schema_valid_result=False,
                verdict=None,
            ),
            tokens_used=0,
            tool_calls=0,
            elapsed_ms=0,
        )


def _next_package(
    context: ReadOnlyEvidenceContext,
    package: EvidencePackage,
    *,
    attempt: int,
) -> tuple[bool, EvidencePackage | None]:
    """Contain a context-port fault without retaining its exception text."""

    try:
        return True, context.next_package(package, attempt=attempt)
    except Exception:
        return False, None


def _attempt_receipt(
    *,
    attempt: int,
    package: EvidencePackage,
    invocation: AuditorInvocation,
) -> AuditorAttemptReceipt:
    response = invocation.response
    verdict = response.verdict
    return AuditorAttemptReceipt(
        attempt=attempt,
        selection_sha256=package.selection_sha256,
        model_call_status=response.model_call_status,
        schema_valid_result=response.schema_valid_result,
        verdict_id=None if verdict is None else verdict.verdict_id,
        finding_verdict=None if verdict is None else verdict.finding_verdict,
        cited_evidence_ids=() if verdict is None else verdict.cited_evidence_ids,
        rationale_sha256=None if verdict is None else verdict.rationale_sha256,
        tokens_used=invocation.tokens_used,
        tool_calls=invocation.tool_calls,
        elapsed_ms=invocation.elapsed_ms,
    )


def _evidence_terminal_receipt(
    package: EvidencePackage,
    *,
    initial_selection_sha256: str,
    attempts: tuple[AuditorAttemptReceipt, ...],
    context_rounds: int,
    tokens_used: int,
    tool_calls: int,
    elapsed_ms: int,
    disposition: InvestigationDisposition,
) -> AuditorInvestigationReceipt:
    finding_verdict = (
        FindingVerdict.CONFIRMED
        if disposition is InvestigationDisposition.CONFIRMED
        else FindingVerdict.REJECTED_WITH_EVIDENCE
    )
    stop_reason = (
        InvestigationStopReason.CONFIRMED
        if disposition is InvestigationDisposition.CONFIRMED
        else InvestigationStopReason.REJECTED_WITH_EVIDENCE
    )
    return AuditorInvestigationReceipt(
        candidate_id=package.candidate_id,
        candidate_version=package.candidate_version,
        tenant_id=package.tenant_id,
        head_sha=package.head_sha,
        initial_selection_sha256=initial_selection_sha256,
        final_selection_sha256=package.selection_sha256,
        attempts=attempts,
        context_rounds=context_rounds,
        tokens_used=tokens_used,
        tool_calls=tool_calls,
        elapsed_ms=elapsed_ms,
        no_progress_count=0,
        final_model_call_status=ModelCallStatus.SUCCEEDED,
        finding_verdict=finding_verdict,
        disposition=disposition,
        stop_reason=stop_reason,
    )


def _indeterminate_receipt(
    package: EvidencePackage,
    *,
    initial_selection_sha256: str,
    attempts: tuple[AuditorAttemptReceipt, ...],
    context_rounds: int,
    tokens_used: int,
    tool_calls: int,
    elapsed_ms: int,
    no_progress_count: int,
    model_call_status: ModelCallStatus,
    stop_reason: InvestigationStopReason,
) -> AuditorInvestigationReceipt:
    return AuditorInvestigationReceipt(
        candidate_id=package.candidate_id,
        candidate_version=package.candidate_version,
        tenant_id=package.tenant_id,
        head_sha=package.head_sha,
        initial_selection_sha256=initial_selection_sha256,
        final_selection_sha256=package.selection_sha256,
        attempts=attempts,
        context_rounds=context_rounds,
        tokens_used=tokens_used,
        tool_calls=tool_calls,
        elapsed_ms=elapsed_ms,
        no_progress_count=no_progress_count,
        final_model_call_status=model_call_status,
        finding_verdict=FindingVerdict.NOT_EVALUATED,
        disposition=InvestigationDisposition.INDETERMINATE,
        stop_reason=stop_reason,
    )


def _same_candidate(left: EvidencePackage, right: EvidencePackage) -> bool:
    return (
        left.candidate_id == right.candidate_id
        and left.candidate_version == right.candidate_version
        and left.tenant_id == right.tenant_id
        and left.head_sha == right.head_sha
        and left.graph_id == right.graph_id
        and left.graph_sha256 == right.graph_sha256
    )


def _is_strict_evidence_superset(
    previous: EvidencePackage, package: EvidencePackage
) -> bool:
    """Require additive context without replacing an existing evidence binding."""

    previous_by_id = {item.evidence_id: item for item in previous.selected}
    next_by_id = {item.evidence_id: item for item in package.selected}
    previous_ids = set(previous_by_id)
    next_ids = set(next_by_id)
    return previous_ids < next_ids and all(
        next_by_id[evidence_id] == evidence
        for evidence_id, evidence in previous_by_id.items()
    )


def _validated_package(package: EvidencePackage) -> EvidencePackage:
    """Copy through validation before retaining caller-owned immutable-looking data."""

    try:
        selected = tuple(
            EvidenceContextRef(
                evidence_id=item.evidence_id,
                content_id=item.content_id,
                data_class=item.data_class,
                evidence_sha256=item.evidence_sha256,
                producer_id=item.producer_id,
                producer_version=item.producer_version,
                producer_sha256=item.producer_sha256,
                context_bytes=item.context_bytes,
                estimated_tokens=item.estimated_tokens,
            )
            for item in package.selected
        )
        return EvidencePackage(
            candidate_id=package.candidate_id,
            candidate_version=package.candidate_version,
            tenant_id=package.tenant_id,
            head_sha=package.head_sha,
            graph_id=package.graph_id,
            graph_sha256=package.graph_sha256,
            selection_sha256=package.selection_sha256,
            selected=selected,
            omitted_evidence_ids=package.omitted_evidence_ids,
            total_context_bytes=package.total_context_bytes,
            total_input_tokens=package.total_input_tokens,
            truncated=package.truncated,
        )
    except (AttributeError, TypeError, ValueError):
        raise InvestigationError(InvestigationErrorCode.INTEGRITY_FAILURE) from None
