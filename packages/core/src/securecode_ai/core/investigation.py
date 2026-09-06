"""Bounded, fail-closed Auditor investigation orchestration.

This module consumes the metadata-only P3.1 context and P3.2 parsed Auditor
contract.  It deliberately has no model transport, repository handle, route
selector, filesystem access, or raw output retention.  The host owns all
budgets; a provider can supply only a typed invocation result and a read-only
context port can supply only a next :class:`EvidencePackage`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from securecode_ai.contracts import FindingVerdict, ModelCallStatus

from .auditor import AuditorResponse
from .evidence_package import EvidenceContextRef, EvidencePackage

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_MAX_ATTEMPTS: Final = 64
_MAX_TOKENS: Final = 4_000_000
_MAX_TOOL_CALLS: Final = 4_096
_MAX_ELAPSED_MS: Final = 86_400_000


class InvestigationErrorCode(StrEnum):
    """Closed caller-side errors which never echo source or model content."""

    INVALID_INPUT = "INVALID_INPUT"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class InvestigationError(ValueError):
    """Safe construction or port-contract failure."""

    __slots__ = ("code",)

    def __init__(self, code: InvestigationErrorCode) -> None:
        if type(code) is not InvestigationErrorCode:
            raise TypeError("investigation error code is invalid")
        self.code = code
        super().__init__("auditor investigation validation failed")
        self.__cause__ = None
        self.__context__ = None


class InvestigationStopReason(StrEnum):
    """Host-owned terminal outcomes; none is a workflow route."""

    CONFIRMED = "CONFIRMED"
    REJECTED_WITH_EVIDENCE = "REJECTED_WITH_EVIDENCE"
    MODEL_NON_SUCCESS = "MODEL_NON_SUCCESS"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    CONTEXT_ROUNDS_EXHAUSTED = "CONTEXT_ROUNDS_EXHAUSTED"
    NO_NEW_EVIDENCE = "NO_NEW_EVIDENCE"
    CONTEXT_PORT_FAILURE = "CONTEXT_PORT_FAILURE"


class InvestigationDisposition(StrEnum):
    """A candidate-local result, intentionally distinct from product PASS/FAIL."""

    CONFIRMED = "CONFIRMED"
    REJECTED_WITH_EVIDENCE = "REJECTED_WITH_EVIDENCE"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True, slots=True)
class InvestigationBudget:
    """Host-selected immutable cumulative limits for one Auditor loop.

    Two is the hard maximum for context rounds.  The initial package counts as
    round one, so a ``NEEDS_MORE_EVIDENCE`` response can consume at most one
    later package carrying genuinely new selected evidence.
    """

    max_attempts: int
    max_tokens: int
    max_tool_calls: int
    max_elapsed_ms: int
    max_no_progress: int = 1
    max_context_rounds: int = 2

    def __post_init__(self) -> None:
        values = (
            self.max_attempts,
            self.max_tokens,
            self.max_tool_calls,
            self.max_elapsed_ms,
            self.max_no_progress,
            self.max_context_rounds,
        )
        ceilings = (
            _MAX_ATTEMPTS,
            _MAX_TOKENS,
            _MAX_TOOL_CALLS,
            _MAX_ELAPSED_MS,
            _MAX_ATTEMPTS,
            2,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, ceilings, strict=True)
        ):
            raise InvestigationError(InvestigationErrorCode.INVALID_INPUT)


@dataclass(frozen=True, slots=True)
class AuditorInvocation:
    """One typed provider result and bounded resource deltas.

    The value carries an already parsed ``AuditorResponse``.  It cannot carry
    provider prose, a next workflow node, a tool result, or a repository view.
    """

    response: AuditorResponse
    tokens_used: int
    tool_calls: int
    elapsed_ms: int

    def __post_init__(self) -> None:
        if (
            type(self.response) is not AuditorResponse
            or any(
                type(value) is not int or value < 0
                for value in (self.tokens_used, self.tool_calls, self.elapsed_ms)
            )
            or self.tokens_used > _MAX_TOKENS
            or self.tool_calls > _MAX_TOOL_CALLS
            or self.elapsed_ms > _MAX_ELAPSED_MS
        ):
            raise InvestigationError(InvestigationErrorCode.INVALID_INPUT)


class AuditorInvoker(Protocol):
    """Typed provider dependency; it cannot select a route or mutate context."""

    def invoke(self, package: EvidencePackage, *, attempt: int) -> AuditorInvocation: ...


class ReadOnlyEvidenceContext(Protocol):
    """Typed read-only context dependency used only after a need-evidence result."""

    def next_package(
        self,
        package: EvidencePackage,
        *,
        attempt: int,
    ) -> EvidencePackage | None: ...


@dataclass(frozen=True, slots=True)
class AuditorAttemptReceipt:
    """Durable-safe record of one model call, excluding all raw model output."""

    attempt: int
    selection_sha256: str
    model_call_status: ModelCallStatus
    schema_valid_result: bool
    verdict_id: str | None
    finding_verdict: FindingVerdict | None
    cited_evidence_ids: tuple[str, ...]
    rationale_sha256: str | None
    tokens_used: int
    tool_calls: int
    elapsed_ms: int

    def __post_init__(self) -> None:
        has_verdict = self.model_call_status is ModelCallStatus.SUCCEEDED
        if (
            type(self.attempt) is not int
            or self.attempt < 1
            or type(self.selection_sha256) is not str
            or _SHA256.fullmatch(self.selection_sha256) is None
            or type(self.model_call_status) is not ModelCallStatus
            or type(self.schema_valid_result) is not bool
            or any(
                type(value) is not int or value < 0
                for value in (self.tokens_used, self.tool_calls, self.elapsed_ms)
            )
            or type(self.cited_evidence_ids) is not tuple
            or any(
                type(item) is not str or _ID.fullmatch(item) is None
                for item in self.cited_evidence_ids
            )
            or self.cited_evidence_ids != tuple(sorted(self.cited_evidence_ids))
            or len(self.cited_evidence_ids) != len(set(self.cited_evidence_ids))
        ):
            raise InvestigationError(InvestigationErrorCode.INVALID_INPUT)
        if has_verdict:
            if (
                not self.schema_valid_result
                or type(self.verdict_id) is not str
                or _ID.fullmatch(self.verdict_id) is None
                or type(self.finding_verdict) is not FindingVerdict
                or self.finding_verdict is FindingVerdict.NOT_EVALUATED
                or not self.cited_evidence_ids
                or type(self.rationale_sha256) is not str
                or _SHA256.fullmatch(self.rationale_sha256) is None
            ):
                raise InvestigationError(InvestigationErrorCode.INTEGRITY_FAILURE)
        elif (
            self.schema_valid_result
            or self.verdict_id is not None
            or self.finding_verdict is not None
            or self.cited_evidence_ids
            or self.rationale_sha256 is not None
        ):
            raise InvestigationError(InvestigationErrorCode.INTEGRITY_FAILURE)


@dataclass(frozen=True, slots=True)
class AuditorInvestigationReceipt:
    """Typed terminal receipt.  It has no route field and can never be PASS."""

    candidate_id: str
    candidate_version: int
    tenant_id: str
    head_sha: str
    initial_selection_sha256: str
    final_selection_sha256: str
    attempts: tuple[AuditorAttemptReceipt, ...]
    context_rounds: int
    tokens_used: int
    tool_calls: int
    elapsed_ms: int
    no_progress_count: int
    final_model_call_status: ModelCallStatus
    finding_verdict: FindingVerdict
    disposition: InvestigationDisposition
    stop_reason: InvestigationStopReason

    def __post_init__(self) -> None:
        if (
            type(self.candidate_id) is not str
            or _ID.fullmatch(self.candidate_id) is None
            or type(self.candidate_version) is not int
            or self.candidate_version < 1
            or type(self.tenant_id) is not str
            or _ID.fullmatch(self.tenant_id) is None
            or type(self.head_sha) is not str
            or _COMMIT_SHA.fullmatch(self.head_sha) is None
            or any(
                type(value) is not str or _SHA256.fullmatch(value) is None
                for value in (self.initial_selection_sha256, self.final_selection_sha256)
            )
            or type(self.attempts) is not tuple
            or any(type(item) is not AuditorAttemptReceipt for item in self.attempts)
            or tuple(item.attempt for item in self.attempts)
            != tuple(range(1, len(self.attempts) + 1))
            or type(self.context_rounds) is not int
            or not 1 <= self.context_rounds <= 2
            or any(
                type(value) is not int or value < 0
                for value in (
                    self.tokens_used,
                    self.tool_calls,
                    self.elapsed_ms,
                    self.no_progress_count,
                )
            )
            or type(self.final_model_call_status) is not ModelCallStatus
            or type(self.finding_verdict) is not FindingVerdict
            or type(self.disposition) is not InvestigationDisposition
            or type(self.stop_reason) is not InvestigationStopReason
        ):
            raise InvestigationError(InvestigationErrorCode.INVALID_INPUT)
        if (
            self.tokens_used != sum(item.tokens_used for item in self.attempts)
            or self.tool_calls != sum(item.tool_calls for item in self.attempts)
            or self.elapsed_ms != sum(item.elapsed_ms for item in self.attempts)
        ):
            raise InvestigationError(InvestigationErrorCode.INTEGRITY_FAILURE)
        if self.disposition is InvestigationDisposition.CONFIRMED:
            expected: tuple[FindingVerdict, InvestigationStopReason | None] = (
                FindingVerdict.CONFIRMED,
                InvestigationStopReason.CONFIRMED,
            )
        elif self.disposition is InvestigationDisposition.REJECTED_WITH_EVIDENCE:
            expected = (
                FindingVerdict.REJECTED_WITH_EVIDENCE,
                InvestigationStopReason.REJECTED_WITH_EVIDENCE,
            )
        else:
            expected = (FindingVerdict.NOT_EVALUATED, None)
        if self.finding_verdict is not expected[0] or (
            expected[1] is not None and self.stop_reason is not expected[1]
        ):
            raise InvestigationError(InvestigationErrorCode.INTEGRITY_FAILURE)
        if self.disposition is InvestigationDisposition.INDETERMINATE and self.stop_reason in {
            InvestigationStopReason.CONFIRMED,
            InvestigationStopReason.REJECTED_WITH_EVIDENCE,
        }:
            raise InvestigationError(InvestigationErrorCode.INTEGRITY_FAILURE)

    @property
    def is_indeterminate(self) -> bool:
        """Return true for every non-terminal-evidence outcome."""

        return self.disposition is InvestigationDisposition.INDETERMINATE


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
    selected_evidence_ids = {item.evidence_id for item in current.selected}
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
            selected_evidence_ids, next_package
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
        selected_evidence_ids.update(item.evidence_id for item in next_package.selected)
        current = next_package
        context_rounds += 1


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
    except (AttributeError, TypeError, ValueError):
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
    )


def _is_strict_evidence_superset(selected_evidence_ids: set[str], package: EvidencePackage) -> bool:
    next_ids = {item.evidence_id for item in package.selected}
    return selected_evidence_ids < next_ids


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


__all__ = [
    "AuditorAttemptReceipt",
    "AuditorInvestigationReceipt",
    "AuditorInvocation",
    "AuditorInvoker",
    "InvestigationBudget",
    "InvestigationDisposition",
    "InvestigationError",
    "InvestigationErrorCode",
    "InvestigationStopReason",
    "ReadOnlyEvidenceContext",
    "run_auditor_investigation",
]
