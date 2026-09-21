"""Bounded, policy-selected repair orchestration over the validation ladder."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from securecode_ai.contracts import ValidationGateOutcome, ValidationOutcome

from .architect import ArchitectPatchResult
from .validation import ValidationLadderResult

_SCHEMA_VERSION: Final = "1.0.0"
_HASH_DOMAIN: Final = b"securecode-ai/repair-loop/v1\x00"


class RepairState(StrEnum):
    ROOT_CAUSE = "ROOT_CAUSE"
    PATCH_AND_SECURITY_TEST = "PATCH_AND_SECURITY_TEST"
    SANDBOX_VALIDATION = "SANDBOX_VALIDATION"
    VALIDATED_CANDIDATE = "VALIDATED_CANDIDATE"
    RETRY = "RETRY"
    HUMAN_ESCALATION = "HUMAN_ESCALATION"
    REJECTED = "REJECTED"


class RepairStopReason(StrEnum):
    VALIDATED = "VALIDATED"
    MAX_ATTEMPTS = "MAX_ATTEMPTS"
    NO_PROGRESS = "NO_PROGRESS"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    INDETERMINATE = "INDETERMINATE"
    POLICY_DENIED = "POLICY_DENIED"
    REQUEST_INVALID = "REQUEST_INVALID"


@dataclass(frozen=True, slots=True)
class RepairLoopError(ValueError):
    """Non-echoing request error."""

    message: str = "repair loop contract validation failed"

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True, slots=True)
class RepairBudget:
    max_attempts: int = 3
    max_tokens: int = 1_000_000
    max_tool_calls: int = 128
    max_elapsed_ms: int = 600_000
    max_no_progress: int = 1

    def __post_init__(self) -> None:
        values = (
            self.max_attempts,
            self.max_tokens,
            self.max_tool_calls,
            self.max_elapsed_ms,
            self.max_no_progress,
        )
        if any(type(value) is not int or value < 1 for value in values) or self.max_attempts > 3:
            raise RepairLoopError()


_DEFAULT_REPAIR_BUDGET: Final = RepairBudget()


@dataclass(frozen=True, slots=True)
class AttemptUsage:
    tokens_used: int = 0
    tool_calls: int = 0
    elapsed_ms: int = 0

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value < 0
            for value in (self.tokens_used, self.tool_calls, self.elapsed_ms)
        ):
            raise RepairLoopError()


@dataclass(frozen=True, slots=True)
class RetryFeedback:
    """Closed failed-gate evidence; no free-form output is retained."""

    patch_id: str
    validation_id: str
    validation_result_sha256: str
    failed_gates: tuple[tuple[int, str, str], ...]
    retryable: bool
    feedback_sha256: str
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or not self.patch_id
            or not self.validation_id
            or len(self.failed_gates) > 128
            or any(type(item) is not tuple or len(item) != 3 for item in self.failed_gates)
            or any(type(value) is not bool for value in (self.retryable,))
            or len(self.feedback_sha256) != 64
            or self.feedback_sha256 != _feedback_hash(self)
        ):
            raise RepairLoopError()


@dataclass(frozen=True, slots=True)
class RepairAttemptReceipt:
    attempt: int
    state: RepairState
    patch_id: str
    validation_id: str
    validation_result_sha256: str
    progress_sha256: str
    feedback: RetryFeedback | None
    usage: AttemptUsage
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or type(self.attempt) is not int
            or self.attempt < 1
            or type(self.state) is not RepairState
            or not self.patch_id
            or not self.validation_id
            or len(self.validation_result_sha256) != 64
            or len(self.progress_sha256) != 64
            or (self.feedback is not None and type(self.feedback) is not RetryFeedback)
            or type(self.usage) is not AttemptUsage
        ):
            raise RepairLoopError()


@dataclass(frozen=True, slots=True)
class RepairLoopReceipt:
    attempts: tuple[RepairAttemptReceipt, ...]
    final_state: RepairState
    stop_reason: RepairStopReason
    usage: AttemptUsage
    receipt_sha256: str
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or type(self.attempts) is not tuple
            or not self.attempts
            or tuple(item.attempt for item in self.attempts)
            != tuple(range(1, len(self.attempts) + 1))
            or type(self.final_state) is not RepairState
            or type(self.stop_reason) is not RepairStopReason
            or type(self.usage) is not AttemptUsage
            or len(self.receipt_sha256) != 64
            or self.receipt_sha256 != _receipt_hash(self)
        ):
            raise RepairLoopError()


class RepairProposer(Protocol):
    def __call__(
        self, feedback: RetryFeedback, attempt: int
    ) -> tuple[ArchitectPatchResult, AttemptUsage]: ...


class RepairValidator(Protocol):
    def __call__(
        self, patch: ArchitectPatchResult, attempt: int
    ) -> tuple[ValidationLadderResult, AttemptUsage]: ...


def run_repair_loop(
    initial_patch: ArchitectPatchResult,
    validate: RepairValidator,
    propose: RepairProposer,
    *,
    initial_usage: AttemptUsage,
    budget: RepairBudget | None = None,
) -> RepairLoopReceipt:
    """Run at most three policy-controlled attempts; never widens capabilities."""

    effective_budget = _DEFAULT_REPAIR_BUDGET if budget is None else budget
    if (
        type(initial_patch) is not ArchitectPatchResult
        or type(effective_budget) is not RepairBudget
        or type(initial_usage) is not AttemptUsage
        or _budget_exhausted(initial_usage, effective_budget)
    ):
        raise RepairLoopError()
    attempts: list[RepairAttemptReceipt] = []
    total = initial_usage
    patch = initial_patch
    seen_progress: set[str] = set()
    final_state = RepairState.HUMAN_ESCALATION
    stop = RepairStopReason.REQUEST_INVALID
    for number in range(1, effective_budget.max_attempts + 1):
        validated = validate(patch, number)
        if (
            type(validated) is not tuple
            or len(validated) != 2
            or type(validated[0]) is not ValidationLadderResult
            or type(validated[1]) is not AttemptUsage
        ):
            raise RepairLoopError()
        result, reported_usage = validated
        usage = _sum_usage(_validation_usage(result), reported_usage)
        total = _sum_usage(total, usage)
        progress = _progress_hash(patch, result)
        feedback = _feedback(result, patch)
        if _budget_exhausted(total, effective_budget):
            state, stop = RepairState.HUMAN_ESCALATION, RepairStopReason.BUDGET_EXHAUSTED
        elif result.validation.validation_outcome is ValidationOutcome.VALIDATED:
            state, stop = RepairState.VALIDATED_CANDIDATE, RepairStopReason.VALIDATED
        elif progress in seen_progress:
            state, stop = RepairState.HUMAN_ESCALATION, RepairStopReason.NO_PROGRESS
        elif number >= effective_budget.max_attempts:
            state, stop = RepairState.HUMAN_ESCALATION, RepairStopReason.MAX_ATTEMPTS
        elif feedback is None:
            state, stop = RepairState.REJECTED, RepairStopReason.VALIDATION_FAILED
        else:
            state, stop = RepairState.RETRY, RepairStopReason.VALIDATION_FAILED
        seen_progress.add(progress)
        attempts.append(
            RepairAttemptReceipt(
                number,
                state,
                patch.patch_candidate.patch_id,
                result.validation.validation_id,
                result.validation.result_sha256,
                progress,
                feedback,
                total,
            )
        )
        final_state = state
        if state is not RepairState.RETRY:
            break
        if feedback is None:
            raise RepairLoopError()
        proposed = propose(feedback, number + 1)
        if (
            type(proposed) is not tuple
            or len(proposed) != 2
            or type(proposed[0]) is not ArchitectPatchResult
            or type(proposed[1]) is not AttemptUsage
        ):
            raise RepairLoopError()
        patch, proposal_usage = proposed
        total = _sum_usage(total, proposal_usage)
        if _budget_exhausted(total, effective_budget):
            previous = attempts[-1]
            attempts[-1] = RepairAttemptReceipt(
                previous.attempt,
                RepairState.HUMAN_ESCALATION,
                previous.patch_id,
                previous.validation_id,
                previous.validation_result_sha256,
                previous.progress_sha256,
                previous.feedback,
                total,
            )
            final_state = RepairState.HUMAN_ESCALATION
            stop = RepairStopReason.BUDGET_EXHAUSTED
            break
    return _make_receipt(tuple(attempts), final_state, stop, total)


def _feedback(result: ValidationLadderResult, patch: ArchitectPatchResult) -> RetryFeedback | None:
    failed: list[tuple[int, str, str]] = []
    for stage in result.stages:
        gate = stage.gate
        if stage.authoritative and gate.gate_outcome is not ValidationGateOutcome.PASSED:
            if gate.reason_code is None:
                return None
            failed.append((gate.ordinal, gate.gate_id, gate.reason_code))
    if not failed:
        return None
    value = object.__new__(RetryFeedback)
    fields = {
        "patch_id": patch.patch_candidate.patch_id,
        "validation_id": result.validation.validation_id,
        "validation_result_sha256": result.validation.result_sha256,
        "failed_gates": tuple(failed),
        "retryable": True,
        "schema_version": _SCHEMA_VERSION,
        "feedback_sha256": "0" * 64,
    }
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    return RetryFeedback(
        patch_id=patch.patch_candidate.patch_id,
        validation_id=result.validation.validation_id,
        validation_result_sha256=result.validation.result_sha256,
        failed_gates=tuple(failed),
        retryable=True,
        feedback_sha256=_feedback_hash(value),
        schema_version=_SCHEMA_VERSION,
    )


def _validation_usage(result: ValidationLadderResult) -> AttemptUsage:
    return AttemptUsage(
        tool_calls=len(result.stages),
        elapsed_ms=sum(item.gate.resource_usage.elapsed_ms for item in result.stages),
    )


def _budget_exhausted(usage: AttemptUsage, budget: RepairBudget) -> bool:
    return (
        usage.tokens_used > budget.max_tokens
        or usage.tool_calls > budget.max_tool_calls
        or usage.elapsed_ms > budget.max_elapsed_ms
    )


def _progress_hash(patch: ArchitectPatchResult, result: ValidationLadderResult) -> str:
    return _hash(
        {
            "patch_id": patch.patch_candidate.patch_id,
            "diff": patch.patch_candidate.unified_diff_sha256,
            "validation": result.validation.result_sha256,
        }
    )


def _feedback_hash(value: RetryFeedback) -> str:
    return _hash(
        {
            "failed_gates": [list(item) for item in value.failed_gates],
            "patch_id": value.patch_id,
            "retryable": value.retryable,
            "schema_version": value.schema_version,
            "validation_id": value.validation_id,
            "validation_result_sha256": value.validation_result_sha256,
        }
    )


def _receipt_hash(value: RepairLoopReceipt) -> str:
    return _hash(
        {
            "attempts": [
                {
                    "attempt": item.attempt,
                    "patch_id": item.patch_id,
                    "progress_sha256": item.progress_sha256,
                    "state": item.state.value,
                    "feedback_sha256": (
                        None if item.feedback is None else item.feedback.feedback_sha256
                    ),
                    "usage": {
                        "elapsed_ms": item.usage.elapsed_ms,
                        "tool_calls": item.usage.tool_calls,
                        "tokens_used": item.usage.tokens_used,
                    },
                    "validation_id": item.validation_id,
                    "validation_result_sha256": item.validation_result_sha256,
                }
                for item in value.attempts
            ],
            "final_state": value.final_state.value,
            "schema_version": value.schema_version,
            "stop_reason": value.stop_reason.value,
            "usage": {
                "elapsed_ms": value.usage.elapsed_ms,
                "tool_calls": value.usage.tool_calls,
                "tokens_used": value.usage.tokens_used,
            },
        }
    )


def _make_receipt(
    attempts: tuple[RepairAttemptReceipt, ...],
    state: RepairState,
    reason: RepairStopReason,
    usage: AttemptUsage,
) -> RepairLoopReceipt:
    value = object.__new__(RepairLoopReceipt)
    fields = {
        "attempts": attempts,
        "final_state": state,
        "stop_reason": reason,
        "usage": usage,
        "schema_version": _SCHEMA_VERSION,
        "receipt_sha256": "0" * 64,
    }
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    return RepairLoopReceipt(
        attempts=attempts,
        final_state=state,
        stop_reason=reason,
        usage=usage,
        receipt_sha256=_receipt_hash(value),
        schema_version=_SCHEMA_VERSION,
    )


def _sum_usage(left: AttemptUsage, right: AttemptUsage) -> AttemptUsage:
    return AttemptUsage(
        left.tokens_used + right.tokens_used,
        left.tool_calls + right.tool_calls,
        left.elapsed_ms + right.elapsed_ms,
    )


def _hash(value: object) -> str:
    return hashlib.sha256(
        _HASH_DOMAIN
        + json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
            "ascii"
        )
    ).hexdigest()


__all__ = [
    "AttemptUsage",
    "RepairBudget",
    "RepairLoopError",
    "RepairLoopReceipt",
    "RepairProposer",
    "RepairState",
    "RepairStopReason",
    "RetryFeedback",
    "run_repair_loop",
]
