"""Fail-closed local patch status transitions without apply or SCM authority."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from itertools import pairwise
from typing import Final

from securecode_ai.contracts import (
    ComponentPin,
    PatchCandidate,
    PatchStatus,
    ValidationGateOutcome,
    ValidationOutcome,
    ValidationResult,
)

from .diff_review import DiffReviewDisposition, DiffReviewReceipt

_SCHEMA_VERSION: Final = "1.0.0"
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/patch-status/v1\x00"


class PatchStatusErrorCode(StrEnum):
    """Bounded reasons for rejecting a local transition request."""

    REQUEST_INVALID = "REQUEST_INVALID"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    TRANSITION_FORBIDDEN = "TRANSITION_FORBIDDEN"
    VALIDATION_REQUIRED = "VALIDATION_REQUIRED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    APPROVAL_INVALID = "APPROVAL_INVALID"


class PatchStatusError(ValueError):
    """Non-echoing error; no patch/source content can cross this boundary."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PatchStatusErrorCode) -> None:
        if type(code) is not PatchStatusErrorCode:
            raise TypeError("patch status error code is invalid")
        self.code = code
        self.safe_message = "patch status transition validation failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class LocalHumanApprovalReceipt:
    """An explicit local human decision bound to one immutable repair candidate."""

    approval_id: str
    approver_id: str
    policy: ComponentPin
    approved_at: datetime
    patch_id: str
    tenant_id: str
    parent_head_sha: str
    validated_head_sha: str
    unified_diff_sha256: str
    validation_result_sha256: str
    semantic_review_sha256: str
    receipt_sha256: str
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (
                    self.approval_id,
                    self.approver_id,
                    self.patch_id,
                    self.tenant_id,
                )
            )
            or type(self.policy) is not ComponentPin
            or type(self.approved_at) is not datetime
            or self.approved_at.tzinfo is not UTC
            or any(
                type(value) is not str or _COMMIT_SHA.fullmatch(value) is None
                for value in (self.parent_head_sha, self.validated_head_sha)
            )
            or self.parent_head_sha == self.validated_head_sha
            or any(
                type(value) is not str or _SHA256.fullmatch(value) is None
                for value in (
                    self.unified_diff_sha256,
                    self.validation_result_sha256,
                    self.semantic_review_sha256,
                    self.receipt_sha256,
                )
            )
            or self.receipt_sha256 != _approval_hash(self)
        ):
            raise PatchStatusError(PatchStatusErrorCode.APPROVAL_INVALID)


@dataclass(frozen=True, slots=True)
class PatchStatusTransition:
    """One hash-linked monotonic state transition with metadata-only evidence."""

    previous_status: PatchStatus | None
    status: PatchStatus
    previous_receipt_sha256: str | None
    validation_result_sha256: str | None
    semantic_review_sha256: str | None
    approval_receipt_sha256: str | None
    reason_code: str | None
    receipt_sha256: str
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        initial = self.previous_status is None
        if (
            self.schema_version != _SCHEMA_VERSION
            or (self.previous_status is not None and type(self.previous_status) is not PatchStatus)
            or type(self.status) is not PatchStatus
            or (initial != (self.previous_receipt_sha256 is None))
            or any(
                value is not None and (type(value) is not str or _SHA256.fullmatch(value) is None)
                for value in (
                    self.previous_receipt_sha256,
                    self.validation_result_sha256,
                    self.semantic_review_sha256,
                    self.approval_receipt_sha256,
                )
            )
            or (
                self.reason_code is not None
                and (type(self.reason_code) is not str or _ID.fullmatch(self.reason_code) is None)
            )
            or type(self.receipt_sha256) is not str
            or _SHA256.fullmatch(self.receipt_sha256) is None
            or self.receipt_sha256 != _transition_hash(self)
        ):
            raise PatchStatusError(PatchStatusErrorCode.INTEGRITY_FAILURE)
        if initial:
            if self.status is not PatchStatus.SUGGESTED or any(
                value is not None
                for value in (
                    self.validation_result_sha256,
                    self.semantic_review_sha256,
                    self.approval_receipt_sha256,
                    self.reason_code,
                )
            ):
                raise PatchStatusError(PatchStatusErrorCode.INTEGRITY_FAILURE)
        elif self.previous_status is None or not _allowed_transition(
            self.previous_status, self.status
        ):
            raise PatchStatusError(PatchStatusErrorCode.TRANSITION_FORBIDDEN)
        elif (
            (
                self.status is PatchStatus.CANDIDATE
                and any(
                    value is not None
                    for value in (
                        self.validation_result_sha256,
                        self.semantic_review_sha256,
                        self.approval_receipt_sha256,
                        self.reason_code,
                    )
                )
            )
            or (
                self.status is PatchStatus.VALIDATED
                and (
                    self.validation_result_sha256 is None
                    or self.semantic_review_sha256 is not None
                    or self.approval_receipt_sha256 is not None
                    or self.reason_code is not None
                )
            )
            or (
                self.status is PatchStatus.APPROVED
                and (
                    self.validation_result_sha256 is None
                    or self.semantic_review_sha256 is None
                    or self.approval_receipt_sha256 is None
                    or self.reason_code is not None
                )
            )
            or (
                self.status in {PatchStatus.REJECTED, PatchStatus.SUPERSEDED}
                and self.reason_code is None
            )
        ):
            raise PatchStatusError(PatchStatusErrorCode.INTEGRITY_FAILURE)


@dataclass(frozen=True, slots=True)
class PatchStatusState:
    """Current patch plus complete locally auditable, immutable status lineage."""

    patch: PatchCandidate
    effective_head_sha: str
    transitions: tuple[PatchStatusTransition, ...]
    validation: ValidationResult | None
    semantic_review: DiffReviewReceipt | None
    approval: LocalHumanApprovalReceipt | None
    state_sha256: str
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or type(self.patch) is not PatchCandidate
            or type(self.effective_head_sha) is not str
            or _COMMIT_SHA.fullmatch(self.effective_head_sha) is None
            or type(self.transitions) is not tuple
            or not self.transitions
            or any(type(item) is not PatchStatusTransition for item in self.transitions)
            or type(self.validation) not in {ValidationResult, type(None)}
            or type(self.semantic_review) not in {DiffReviewReceipt, type(None)}
            or type(self.approval) not in {LocalHumanApprovalReceipt, type(None)}
            or type(self.state_sha256) is not str
            or _SHA256.fullmatch(self.state_sha256) is None
            or self.state_sha256 != _state_hash(self)
        ):
            raise PatchStatusError(PatchStatusErrorCode.INTEGRITY_FAILURE)
        _assert_state_lineage(self)


def start_patch_status(patch: PatchCandidate) -> PatchStatusState:
    """Register a suggested patch locally; this does not apply it anywhere."""

    checked = _copy_patch(patch)
    if checked.patch_status is not PatchStatus.SUGGESTED:
        raise PatchStatusError(PatchStatusErrorCode.TRANSITION_FORBIDDEN)
    transition = _make_transition(None, PatchStatus.SUGGESTED, None, None, None, None)
    return _make_state(
        checked,
        checked.repository_revision.head_sha,
        (transition,),
        None,
        None,
        None,
    )


def promote_patch_candidate(state: PatchStatusState) -> PatchStatusState:
    """Advance exactly once from SUGGESTED to CANDIDATE without external effects."""

    checked = _copy_state(state)
    _require_status(checked, PatchStatus.SUGGESTED)
    return _append_state(checked, PatchStatus.CANDIDATE, None, None, None, None)


def mark_patch_validated(
    state: PatchStatusState,
    validation: ValidationResult,
) -> PatchStatusState:
    """Bind a candidate to an exact successful validation of its new HEAD."""

    checked = _copy_state(state)
    _require_status(checked, PatchStatus.CANDIDATE)
    checked_validation = _copy_validation(validation)
    if not _matches_validation(checked.patch, checked_validation):
        raise PatchStatusError(PatchStatusErrorCode.VALIDATION_REQUIRED)
    return _append_state(
        checked,
        PatchStatus.VALIDATED,
        checked_validation,
        None,
        None,
        None,
    )


def approve_patch_locally(
    state: PatchStatusState,
    review: DiffReviewReceipt,
    *,
    approval_id: str,
    approver_id: str,
    policy: ComponentPin,
    approved_at: datetime,
) -> PatchStatusState:
    """Record deliberate human approval; it grants no apply or SCM capability."""

    checked = _copy_state(state)
    _require_status(checked, PatchStatus.VALIDATED)
    if checked.validation is None:
        raise PatchStatusError(PatchStatusErrorCode.VALIDATION_REQUIRED)
    checked_review = _copy_review(review)
    if not _matches_review(checked.patch, checked.validation, checked_review):
        raise PatchStatusError(PatchStatusErrorCode.REVIEW_REQUIRED)
    checked_policy = _copy_pin(policy)
    approval = _make_approval(
        approval_id,
        approver_id,
        checked_policy,
        approved_at,
        checked.patch,
        checked.validation,
        checked_review,
    )
    return _append_state(
        checked,
        PatchStatus.APPROVED,
        checked.validation,
        checked_review,
        approval,
        None,
    )


def close_patch_status(
    state: PatchStatusState,
    status: PatchStatus,
    *,
    reason_code: str,
) -> PatchStatusState:
    """Reject or supersede an open local candidate without applying it."""

    checked = _copy_state(state)
    if type(status) is not PatchStatus or status not in {
        PatchStatus.REJECTED,
        PatchStatus.SUPERSEDED,
    }:
        raise PatchStatusError(PatchStatusErrorCode.TRANSITION_FORBIDDEN)
    if type(reason_code) is not str or _ID.fullmatch(reason_code) is None:
        raise PatchStatusError(PatchStatusErrorCode.REQUEST_INVALID)
    return _append_state(
        checked,
        status,
        checked.validation,
        checked.semantic_review,
        checked.approval,
        reason_code,
    )


def _append_state(
    state: PatchStatusState,
    target: PatchStatus,
    validation: ValidationResult | None,
    review: DiffReviewReceipt | None,
    approval: LocalHumanApprovalReceipt | None,
    reason_code: str | None,
) -> PatchStatusState:
    current = state.transitions[-1]
    transition = _make_transition(
        current.status,
        target,
        current.receipt_sha256,
        validation.result_sha256 if validation is not None else None,
        review.review_sha256 if review is not None else None,
        approval.receipt_sha256 if approval is not None else None,
        reason_code,
    )
    patch = state.patch.model_copy(update={"patch_status": target})
    head = validation.head_sha if validation is not None else state.effective_head_sha
    return _make_state(patch, head, (*state.transitions, transition), validation, review, approval)


def _require_status(state: PatchStatusState, expected: PatchStatus) -> None:
    if state.patch.patch_status is not expected:
        raise PatchStatusError(PatchStatusErrorCode.TRANSITION_FORBIDDEN)


def _allowed_transition(previous: PatchStatus, target: PatchStatus) -> bool:
    return (
        (previous is PatchStatus.SUGGESTED and target is PatchStatus.CANDIDATE)
        or (previous is PatchStatus.CANDIDATE and target is PatchStatus.VALIDATED)
        or (previous is PatchStatus.VALIDATED and target is PatchStatus.APPROVED)
        or (
            previous in {PatchStatus.SUGGESTED, PatchStatus.CANDIDATE, PatchStatus.VALIDATED}
            and target in {PatchStatus.REJECTED, PatchStatus.SUPERSEDED}
        )
    )


def _matches_validation(patch: PatchCandidate, validation: ValidationResult) -> bool:
    return (
        validation.patch_id == patch.patch_id
        and validation.tenant_id == patch.repository_revision.tenant_id
        and validation.head_sha != patch.repository_revision.head_sha
        and validation.validation_outcome is ValidationOutcome.VALIDATED
        and all(gate.gate_outcome is ValidationGateOutcome.PASSED for gate in validation.gates)
    )


def _matches_review(
    patch: PatchCandidate,
    validation: ValidationResult,
    review: DiffReviewReceipt,
) -> bool:
    return (
        review.patch_id == patch.patch_id
        and review.tenant_id == patch.repository_revision.tenant_id
        and review.repository_id == patch.repository_revision.repository_id
        and review.parent_head_sha == patch.repository_revision.head_sha
        and review.validated_head_sha == validation.head_sha
        and review.unified_diff_sha256 == patch.unified_diff_sha256
        and review.validation_id == validation.validation_id
        and review.validation_result_sha256 == validation.result_sha256
        and review.disposition
        not in {DiffReviewDisposition.REJECTED, DiffReviewDisposition.INDETERMINATE}
    )


def _assert_state_lineage(state: PatchStatusState) -> None:
    transitions = state.transitions
    if (
        transitions[0].previous_status is not None
        or transitions[0].status is not PatchStatus.SUGGESTED
        or transitions[-1].status is not state.patch.patch_status
        or any(
            transition.previous_status is not previous.status
            or transition.previous_receipt_sha256 != previous.receipt_sha256
            for previous, transition in pairwise(transitions)
        )
    ):
        raise PatchStatusError(PatchStatusErrorCode.INTEGRITY_FAILURE)
    current = transitions[-1]
    if (
        (state.validation is None) != (current.validation_result_sha256 is None)
        or (
            state.validation is not None
            and current.validation_result_sha256 != state.validation.result_sha256
        )
        or (state.semantic_review is None) != (current.semantic_review_sha256 is None)
        or (
            state.semantic_review is not None
            and current.semantic_review_sha256 != state.semantic_review.review_sha256
        )
        or (state.approval is None) != (current.approval_receipt_sha256 is None)
        or (
            state.approval is not None
            and current.approval_receipt_sha256 != state.approval.receipt_sha256
        )
    ):
        raise PatchStatusError(PatchStatusErrorCode.INTEGRITY_FAILURE)
    if current.status in {PatchStatus.VALIDATED, PatchStatus.APPROVED} and (
        state.validation is None or not _matches_validation(state.patch, state.validation)
    ):
        raise PatchStatusError(PatchStatusErrorCode.INTEGRITY_FAILURE)
    if current.status is PatchStatus.APPROVED and (
        state.validation is None
        or state.semantic_review is None
        or state.approval is None
        or not _matches_review(state.patch, state.validation, state.semantic_review)
        or not _approval_matches(
            state.approval,
            state.patch,
            state.validation,
            state.semantic_review,
        )
    ):
        raise PatchStatusError(PatchStatusErrorCode.INTEGRITY_FAILURE)
    if (
        current.status in {PatchStatus.REJECTED, PatchStatus.SUPERSEDED}
        and current.reason_code is None
    ):
        raise PatchStatusError(PatchStatusErrorCode.INTEGRITY_FAILURE)
    expected_head = (
        state.validation.head_sha
        if state.validation is not None
        else state.patch.repository_revision.head_sha
    )
    if state.effective_head_sha != expected_head:
        raise PatchStatusError(PatchStatusErrorCode.INTEGRITY_FAILURE)


def _approval_matches(
    approval: LocalHumanApprovalReceipt,
    patch: PatchCandidate,
    validation: ValidationResult,
    review: DiffReviewReceipt,
) -> bool:
    return (
        approval.patch_id == patch.patch_id
        and approval.tenant_id == patch.repository_revision.tenant_id
        and approval.parent_head_sha == patch.repository_revision.head_sha
        and approval.validated_head_sha == validation.head_sha
        and approval.unified_diff_sha256 == patch.unified_diff_sha256
        and approval.validation_result_sha256 == validation.result_sha256
        and approval.semantic_review_sha256 == review.review_sha256
    )


def _copy_patch(value: PatchCandidate) -> PatchCandidate:
    if type(value) is not PatchCandidate:
        raise PatchStatusError(PatchStatusErrorCode.REQUEST_INVALID)
    try:
        return PatchCandidate.model_validate(value.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError):
        raise PatchStatusError(PatchStatusErrorCode.INTEGRITY_FAILURE) from None


def _copy_validation(value: ValidationResult) -> ValidationResult:
    if type(value) is not ValidationResult:
        raise PatchStatusError(PatchStatusErrorCode.REQUEST_INVALID)
    try:
        return ValidationResult.model_validate(value.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError):
        raise PatchStatusError(PatchStatusErrorCode.INTEGRITY_FAILURE) from None


def _copy_review(value: DiffReviewReceipt) -> DiffReviewReceipt:
    if type(value) is not DiffReviewReceipt:
        raise PatchStatusError(PatchStatusErrorCode.REQUEST_INVALID)
    try:
        return DiffReviewReceipt(
            **{name: getattr(value, name) for name in DiffReviewReceipt.__dataclass_fields__}
        )
    except (AttributeError, TypeError, ValueError):
        raise PatchStatusError(PatchStatusErrorCode.INTEGRITY_FAILURE) from None


def _copy_pin(value: ComponentPin) -> ComponentPin:
    if type(value) is not ComponentPin:
        raise PatchStatusError(PatchStatusErrorCode.REQUEST_INVALID)
    try:
        return ComponentPin.model_validate(value.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError):
        raise PatchStatusError(PatchStatusErrorCode.APPROVAL_INVALID) from None


def _copy_state(value: PatchStatusState) -> PatchStatusState:
    if type(value) is not PatchStatusState:
        raise PatchStatusError(PatchStatusErrorCode.REQUEST_INVALID)
    try:
        patch = _copy_patch(value.patch)
        validation = _copy_validation(value.validation) if value.validation is not None else None
        review = _copy_review(value.semantic_review) if value.semantic_review is not None else None
        approval = (
            LocalHumanApprovalReceipt(
                **{
                    name: getattr(value.approval, name)
                    for name in LocalHumanApprovalReceipt.__dataclass_fields__
                }
            )
            if value.approval is not None
            else None
        )
        transitions = tuple(
            PatchStatusTransition(
                **{name: getattr(item, name) for name in PatchStatusTransition.__dataclass_fields__}
            )
            for item in value.transitions
        )
        return PatchStatusState(
            patch,
            value.effective_head_sha,
            transitions,
            validation,
            review,
            approval,
            value.state_sha256,
            value.schema_version,
        )
    except (AttributeError, TypeError, ValueError):
        raise PatchStatusError(PatchStatusErrorCode.INTEGRITY_FAILURE) from None


def _make_transition(
    previous_status: PatchStatus | None,
    status: PatchStatus,
    previous_receipt_sha256: str | None,
    validation_result_sha256: str | None,
    semantic_review_sha256: str | None,
    approval_receipt_sha256: str | None,
    reason_code: str | None = None,
) -> PatchStatusTransition:
    seed = object.__new__(PatchStatusTransition)
    values = {
        "previous_status": previous_status,
        "status": status,
        "previous_receipt_sha256": previous_receipt_sha256,
        "validation_result_sha256": validation_result_sha256,
        "semantic_review_sha256": semantic_review_sha256,
        "approval_receipt_sha256": approval_receipt_sha256,
        "reason_code": reason_code,
        "receipt_sha256": "0" * 64,
        "schema_version": _SCHEMA_VERSION,
    }
    for name, item in values.items():
        object.__setattr__(seed, name, item)
    return PatchStatusTransition(
        previous_status=previous_status,
        status=status,
        previous_receipt_sha256=previous_receipt_sha256,
        validation_result_sha256=validation_result_sha256,
        semantic_review_sha256=semantic_review_sha256,
        approval_receipt_sha256=approval_receipt_sha256,
        reason_code=reason_code,
        receipt_sha256=_transition_hash(seed),
        schema_version=_SCHEMA_VERSION,
    )


def _make_state(
    patch: PatchCandidate,
    effective_head_sha: str,
    transitions: tuple[PatchStatusTransition, ...],
    validation: ValidationResult | None,
    review: DiffReviewReceipt | None,
    approval: LocalHumanApprovalReceipt | None,
) -> PatchStatusState:
    seed = object.__new__(PatchStatusState)
    values = {
        "patch": patch,
        "effective_head_sha": effective_head_sha,
        "transitions": transitions,
        "validation": validation,
        "semantic_review": review,
        "approval": approval,
        "state_sha256": "0" * 64,
        "schema_version": _SCHEMA_VERSION,
    }
    for name, item in values.items():
        object.__setattr__(seed, name, item)
    return PatchStatusState(
        patch=patch,
        effective_head_sha=effective_head_sha,
        transitions=transitions,
        validation=validation,
        semantic_review=review,
        approval=approval,
        state_sha256=_state_hash(seed),
        schema_version=_SCHEMA_VERSION,
    )


def _make_approval(
    approval_id: str,
    approver_id: str,
    policy: ComponentPin,
    approved_at: datetime,
    patch: PatchCandidate,
    validation: ValidationResult,
    review: DiffReviewReceipt,
) -> LocalHumanApprovalReceipt:
    seed = object.__new__(LocalHumanApprovalReceipt)
    values = {
        "approval_id": approval_id,
        "approver_id": approver_id,
        "policy": policy,
        "approved_at": approved_at,
        "patch_id": patch.patch_id,
        "tenant_id": patch.repository_revision.tenant_id,
        "parent_head_sha": patch.repository_revision.head_sha,
        "validated_head_sha": validation.head_sha,
        "unified_diff_sha256": patch.unified_diff_sha256,
        "validation_result_sha256": validation.result_sha256,
        "semantic_review_sha256": review.review_sha256,
        "receipt_sha256": "0" * 64,
        "schema_version": _SCHEMA_VERSION,
    }
    for name, item in values.items():
        object.__setattr__(seed, name, item)
    return LocalHumanApprovalReceipt(
        approval_id=approval_id,
        approver_id=approver_id,
        policy=policy,
        approved_at=approved_at,
        patch_id=patch.patch_id,
        tenant_id=patch.repository_revision.tenant_id,
        parent_head_sha=patch.repository_revision.head_sha,
        validated_head_sha=validation.head_sha,
        unified_diff_sha256=patch.unified_diff_sha256,
        validation_result_sha256=validation.result_sha256,
        semantic_review_sha256=review.review_sha256,
        receipt_sha256=_approval_hash(seed),
        schema_version=_SCHEMA_VERSION,
    )


def _transition_hash(value: PatchStatusTransition) -> str:
    return _hash(
        {
            "approval_receipt_sha256": value.approval_receipt_sha256,
            "previous_receipt_sha256": value.previous_receipt_sha256,
            "previous_status": value.previous_status.value if value.previous_status else None,
            "reason_code": value.reason_code,
            "schema_version": value.schema_version,
            "semantic_review_sha256": value.semantic_review_sha256,
            "status": value.status.value,
            "validation_result_sha256": value.validation_result_sha256,
        }
    )


def _state_hash(value: PatchStatusState) -> str:
    return _hash(
        {
            "approval_receipt_sha256": value.approval.receipt_sha256 if value.approval else None,
            "effective_head_sha": value.effective_head_sha,
            "patch": value.patch.model_dump(mode="json"),
            "schema_version": value.schema_version,
            "semantic_review_sha256": (
                value.semantic_review.review_sha256 if value.semantic_review else None
            ),
            "transitions": [item.receipt_sha256 for item in value.transitions],
            "validation_result_sha256": (
                value.validation.result_sha256 if value.validation else None
            ),
        }
    )


def _approval_hash(value: LocalHumanApprovalReceipt) -> str:
    return _hash(
        {
            "approval_id": value.approval_id,
            "approved_at": value.approved_at.isoformat(),
            "approver_id": value.approver_id,
            "parent_head_sha": value.parent_head_sha,
            "patch_id": value.patch_id,
            "policy": value.policy.model_dump(mode="json"),
            "schema_version": value.schema_version,
            "semantic_review_sha256": value.semantic_review_sha256,
            "tenant_id": value.tenant_id,
            "unified_diff_sha256": value.unified_diff_sha256,
            "validated_head_sha": value.validated_head_sha,
            "validation_result_sha256": value.validation_result_sha256,
        }
    )


def _hash(material: dict[str, object]) -> str:
    return hashlib.sha256(
        _HASH_DOMAIN
        + json.dumps(
            material,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


__all__ = [
    "LocalHumanApprovalReceipt",
    "PatchStatusError",
    "PatchStatusErrorCode",
    "PatchStatusState",
    "PatchStatusTransition",
    "approve_patch_locally",
    "close_patch_status",
    "mark_patch_validated",
    "promote_patch_candidate",
    "start_patch_status",
]
