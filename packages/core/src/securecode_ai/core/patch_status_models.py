"""Fail-closed local patch status transitions without apply or SCM authority."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final

from securecode_ai.contracts import (
    ComponentPin,
    PatchCandidate,
    PatchStatus,
    ValidationResult,
)

from .diff_review import DiffReviewReceipt

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
        from .patch_status_helpers import _approval_hash

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
        from .patch_status_helpers import _allowed_transition, _transition_hash

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
        from .patch_status_helpers import _assert_state_lineage, _state_hash

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
