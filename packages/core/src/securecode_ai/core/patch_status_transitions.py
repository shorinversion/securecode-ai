"""Fail-closed local patch status transitions without apply or SCM authority."""

from __future__ import annotations

from datetime import datetime

from securecode_ai.contracts import (
    ComponentPin,
    PatchCandidate,
    PatchStatus,
    ValidationResult,
)

from .diff_review import DiffReviewReceipt
from .patch_status_helpers import (
    _append_state,
    _copy_patch,
    _copy_pin,
    _copy_review,
    _copy_state,
    _copy_validation,
    _make_approval,
    _make_state,
    _make_transition,
    _matches_review,
    _matches_validation,
    _require_status,
)
from .patch_status_models import (
    _ID,
    PatchStatusError,
    PatchStatusErrorCode,
    PatchStatusState,
)


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
