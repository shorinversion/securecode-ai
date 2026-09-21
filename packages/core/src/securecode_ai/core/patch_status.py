"""Fail-closed local patch status transitions without apply or SCM authority."""

from __future__ import annotations

from .patch_status_models import (
    LocalHumanApprovalReceipt,
    PatchStatusError,
    PatchStatusErrorCode,
    PatchStatusState,
    PatchStatusTransition,
)
from .patch_status_transitions import (
    approve_patch_locally,
    close_patch_status,
    mark_patch_validated,
    promote_patch_candidate,
    start_patch_status,
)

for _patch_status_type in (
    PatchStatusError,
    LocalHumanApprovalReceipt,
    PatchStatusTransition,
    PatchStatusState,
):
    _patch_status_type.__module__ = __name__
del _patch_status_type
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
