"""Fail-closed local patch status transitions without apply or SCM authority."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from itertools import pairwise

from securecode_ai.contracts import (
    ComponentPin,
    PatchCandidate,
    PatchStatus,
    ValidationGateOutcome,
    ValidationOutcome,
    ValidationResult,
)

from .diff_review import DiffReviewDisposition, DiffReviewReceipt
from .patch_status_models import (
    _HASH_DOMAIN,
    _SCHEMA_VERSION,
    LocalHumanApprovalReceipt,
    PatchStatusError,
    PatchStatusErrorCode,
    PatchStatusState,
    PatchStatusTransition,
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
