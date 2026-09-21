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
from .evidence_package import EvidencePackage

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
