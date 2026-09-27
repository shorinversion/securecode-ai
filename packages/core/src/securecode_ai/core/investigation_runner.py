"""Bounded, fail-closed Auditor investigation orchestration.

This module consumes the metadata-only P3.1 context and P3.2 parsed Auditor
contract.  It deliberately has no model transport, repository handle, route
selector, filesystem access, or raw output retention.  The host owns all
budgets; a provider can supply only a typed invocation result and a read-only
context port can supply only a next :class:`EvidencePackage`.
"""

from __future__ import annotations

from securecode_ai.contracts import FindingVerdict, ModelCallStatus

from .evidence_package import EvidencePackage
from .investigation_helpers import (
    _attempt_receipt,
    _evidence_terminal_receipt,
    _indeterminate_receipt,
    _invoke,
    _is_strict_evidence_superset,
    _next_package,
    _same_candidate,
    _validated_package,
)
from .investigation_models import (
    AuditorAttemptReceipt,
    AuditorInvestigationReceipt,
    AuditorInvoker,
    InvestigationBudget,
    InvestigationDisposition,
    InvestigationError,
    InvestigationErrorCode,
    InvestigationStopReason,
    ReadOnlyEvidenceContext,
)


def run_auditor_investigation(
    package: EvidencePackage,
    *,
    budget: InvestigationBudget,
    auditor: AuditorInvoker,
    context: ReadOnlyEvidenceContext,
) -> AuditorInvestigationReceipt:
    """Run at most two evidence contexts under host-owned cumulative budgets.

    Only a P3.2 ``NEEDS_MORE_EVIDENCE`` verdict attempts a new context.  That
    attempt is admitted solely when its selected evidence IDs preserve every
    prior selected ID and add at least one new ID.  Provider or context-port
    failures produce typed indeterminate receipts; no failure and no model
    value selects a downstream workflow route.
    """

    if (
        type(package) is not EvidencePackage
        or type(budget) is not InvestigationBudget
        or not hasattr(auditor, "invoke")
        or not hasattr(context, "next_package")
    ):
        raise InvestigationError(InvestigationErrorCode.INVALID_INPUT)
    current = _validated_package(package)
    initial_selection_sha256 = current.selection_sha256
    attempts: list[AuditorAttemptReceipt] = []
    context_rounds = 1
    tokens_used = 0
    tool_calls = 0
    elapsed_ms = 0

    while True:
        if len(attempts) >= budget.max_attempts:
            return _indeterminate_receipt(
                current,
                initial_selection_sha256=initial_selection_sha256,
                attempts=tuple(attempts),
                context_rounds=context_rounds,
                tokens_used=tokens_used,
                tool_calls=tool_calls,
                elapsed_ms=elapsed_ms,
                no_progress_count=0,
                model_call_status=ModelCallStatus.BUDGET_EXHAUSTED,
                stop_reason=InvestigationStopReason.BUDGET_EXHAUSTED,
            )
        invocation = _invoke(auditor, current, attempt=len(attempts) + 1)
        attempt_receipt = _attempt_receipt(
            attempt=len(attempts) + 1,
            package=current,
            invocation=invocation,
        )
        attempts.append(attempt_receipt)
        tokens_used += invocation.tokens_used
        tool_calls += invocation.tool_calls
        elapsed_ms += invocation.elapsed_ms

        if (
            tokens_used >= budget.max_tokens
            or tool_calls >= budget.max_tool_calls
            or elapsed_ms >= budget.max_elapsed_ms
        ):
            return _indeterminate_receipt(
                current,
                initial_selection_sha256=initial_selection_sha256,
                attempts=tuple(attempts),
                context_rounds=context_rounds,
                tokens_used=tokens_used,
                tool_calls=tool_calls,
                elapsed_ms=elapsed_ms,
                no_progress_count=0,
                model_call_status=ModelCallStatus.BUDGET_EXHAUSTED,
                stop_reason=InvestigationStopReason.BUDGET_EXHAUSTED,
            )
        response = invocation.response
        if response.model_call_status is not ModelCallStatus.SUCCEEDED or response.verdict is None:
            return _indeterminate_receipt(
                current,
                initial_selection_sha256=initial_selection_sha256,
                attempts=tuple(attempts),
                context_rounds=context_rounds,
                tokens_used=tokens_used,
                tool_calls=tool_calls,
                elapsed_ms=elapsed_ms,
                no_progress_count=0,
                model_call_status=response.model_call_status,
                stop_reason=(
                    InvestigationStopReason.BUDGET_EXHAUSTED
                    if response.model_call_status is ModelCallStatus.BUDGET_EXHAUSTED
                    else InvestigationStopReason.MODEL_NON_SUCCESS
                ),
            )
        if response.verdict.finding_verdict is FindingVerdict.CONFIRMED:
            return _evidence_terminal_receipt(
                current,
                initial_selection_sha256=initial_selection_sha256,
                attempts=tuple(attempts),
                context_rounds=context_rounds,
                tokens_used=tokens_used,
                tool_calls=tool_calls,
                elapsed_ms=elapsed_ms,
                disposition=InvestigationDisposition.CONFIRMED,
            )
        if response.verdict.finding_verdict is FindingVerdict.REJECTED_WITH_EVIDENCE:
            return _evidence_terminal_receipt(
                current,
                initial_selection_sha256=initial_selection_sha256,
                attempts=tuple(attempts),
                context_rounds=context_rounds,
                tokens_used=tokens_used,
                tool_calls=tool_calls,
                elapsed_ms=elapsed_ms,
                disposition=InvestigationDisposition.REJECTED_WITH_EVIDENCE,
            )
        if response.verdict.finding_verdict is not FindingVerdict.NEEDS_MORE_EVIDENCE:
            return _indeterminate_receipt(
                current,
                initial_selection_sha256=initial_selection_sha256,
                attempts=tuple(attempts),
                context_rounds=context_rounds,
                tokens_used=tokens_used,
                tool_calls=tool_calls,
                elapsed_ms=elapsed_ms,
                no_progress_count=0,
                model_call_status=ModelCallStatus.INVALID_SCHEMA,
                stop_reason=InvestigationStopReason.MODEL_NON_SUCCESS,
            )
        if len(attempts) >= budget.max_attempts:
            return _indeterminate_receipt(
                current,
                initial_selection_sha256=initial_selection_sha256,
                attempts=tuple(attempts),
                context_rounds=context_rounds,
                tokens_used=tokens_used,
                tool_calls=tool_calls,
                elapsed_ms=elapsed_ms,
                no_progress_count=0,
                model_call_status=ModelCallStatus.BUDGET_EXHAUSTED,
                stop_reason=InvestigationStopReason.BUDGET_EXHAUSTED,
            )
        if (
            tokens_used >= budget.max_tokens
            or tool_calls >= budget.max_tool_calls
            or elapsed_ms >= budget.max_elapsed_ms
        ):
            return _indeterminate_receipt(
                current,
                initial_selection_sha256=initial_selection_sha256,
                attempts=tuple(attempts),
                context_rounds=context_rounds,
                tokens_used=tokens_used,
                tool_calls=tool_calls,
                elapsed_ms=elapsed_ms,
                no_progress_count=0,
                model_call_status=ModelCallStatus.BUDGET_EXHAUSTED,
                stop_reason=InvestigationStopReason.BUDGET_EXHAUSTED,
            )
        if context_rounds >= budget.max_context_rounds:
            return _indeterminate_receipt(
                current,
                initial_selection_sha256=initial_selection_sha256,
                attempts=tuple(attempts),
                context_rounds=context_rounds,
                tokens_used=tokens_used,
                tool_calls=tool_calls,
                elapsed_ms=elapsed_ms,
                no_progress_count=0,
                model_call_status=ModelCallStatus.BUDGET_EXHAUSTED,
                stop_reason=InvestigationStopReason.CONTEXT_ROUNDS_EXHAUSTED,
            )
        context_ok, next_package = _next_package(context, current, attempt=len(attempts))
        if not context_ok:
            return _indeterminate_receipt(
                current,
                initial_selection_sha256=initial_selection_sha256,
                attempts=tuple(attempts),
                context_rounds=context_rounds,
                tokens_used=tokens_used,
                tool_calls=tool_calls,
                elapsed_ms=elapsed_ms,
                no_progress_count=1,
                model_call_status=ModelCallStatus.PROVIDER_ERROR,
                stop_reason=InvestigationStopReason.CONTEXT_PORT_FAILURE,
            )
        if next_package is None:
            return _indeterminate_receipt(
                current,
                initial_selection_sha256=initial_selection_sha256,
                attempts=tuple(attempts),
                context_rounds=context_rounds,
                tokens_used=tokens_used,
                tool_calls=tool_calls,
                elapsed_ms=elapsed_ms,
                no_progress_count=1,
                model_call_status=ModelCallStatus.INCOMPLETE,
                stop_reason=InvestigationStopReason.NO_NEW_EVIDENCE,
            )
        try:
            next_package = _validated_package(next_package)
        except InvestigationError:
            return _indeterminate_receipt(
                current,
                initial_selection_sha256=initial_selection_sha256,
                attempts=tuple(attempts),
                context_rounds=context_rounds,
                tokens_used=tokens_used,
                tool_calls=tool_calls,
                elapsed_ms=elapsed_ms,
                no_progress_count=1,
                model_call_status=ModelCallStatus.PROVIDER_ERROR,
                stop_reason=InvestigationStopReason.CONTEXT_PORT_FAILURE,
            )
        if not _same_candidate(current, next_package) or not _is_strict_evidence_superset(
            current, next_package
        ):
            return _indeterminate_receipt(
                current,
                initial_selection_sha256=initial_selection_sha256,
                attempts=tuple(attempts),
                context_rounds=context_rounds,
                tokens_used=tokens_used,
                tool_calls=tool_calls,
                elapsed_ms=elapsed_ms,
                no_progress_count=1,
                model_call_status=ModelCallStatus.INCOMPLETE,
                stop_reason=InvestigationStopReason.NO_NEW_EVIDENCE,
            )
        current = next_package
        context_rounds += 1
