"""P4.9 local-only patch status and approval contracts."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ArtifactRef,
    ComponentPin,
    DataClass,
    PatchCandidate,
    PatchStatus,
    ProducerRef,
    RepositoryRevision,
    ResourceUsage,
    ValidationGateOutcome,
    ValidationGateResult,
    ValidationOutcome,
    ValidationResult,
)
from securecode_ai.core.architect import ArchitectPatchResult, TouchedSymbol, _make_rationale
from securecode_ai.core.diff_review import review_semantic_diff
from securecode_ai.core.patch_status import (
    PatchStatusError,
    PatchStatusErrorCode,
    PatchStatusState,
    approve_patch_locally,
    close_patch_status,
    mark_patch_validated,
    promote_patch_candidate,
    start_patch_status,
)

HEAD = "a" * 40
FIXED_HEAD = "b" * 40
HASH = "c" * 64
APPROVED_AT = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)


def _producer() -> ProducerRef:
    return ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="patch-status",
        producer_version="1.0.0",
        producer_sha256=HASH,
    )


def _patch() -> PatchCandidate:
    diff_hash = hashlib.sha256(b"bounded-diff").hexdigest()
    revision = RepositoryRevision(
        schema_version=CONTRACT_SCHEMA_VERSION,
        tenant_id="tenant-1",
        scm_provider="git",
        repository_id="repo-1",
        head_sha=HEAD,
    )
    return PatchCandidate(
        schema_version=CONTRACT_SCHEMA_VERSION,
        patch_id=f"patch-{diff_hash}",
        finding_id="finding-1",
        repository_revision=revision,
        unified_diff_sha256=diff_hash,
        diff_ref=ArtifactRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-1",
            content_id=f"patch-{diff_hash}",
            content_sha256=diff_hash,
            size_bytes=12,
            data_class=DataClass.CONFIDENTIAL_SOURCE,
        ),
        author=_producer(),
        patch_status=PatchStatus.SUGGESTED,
    )


def _validation(
    patch: PatchCandidate,
    *,
    outcome: ValidationOutcome = ValidationOutcome.VALIDATED,
    head: str = FIXED_HEAD,
    result_hash: str = HASH,
) -> ValidationResult:
    gate = ValidationGateResult(
        schema_version=CONTRACT_SCHEMA_VERSION,
        ordinal=1,
        gate_id="patch-apply",
        gate_outcome=ValidationGateOutcome.PASSED,
        producer=_producer(),
        input_hashes=(HASH,),
        output_hashes=(HASH,),
        resource_usage=ResourceUsage(
            schema_version=CONTRACT_SCHEMA_VERSION,
            elapsed_ms=1,
            peak_memory_bytes=1,
            cpu_time_ms=1,
        ),
    )
    return ValidationResult(
        schema_version=CONTRACT_SCHEMA_VERSION,
        validation_id="validation-1",
        tenant_id=patch.repository_revision.tenant_id,
        patch_id=patch.patch_id,
        head_sha=head,
        sandbox_profile=ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id="airgap-sandbox",
            component_version="1.0.0",
            content_sha256=HASH,
        ),
        gates=(gate,),
        validation_outcome=outcome,
        result_sha256=result_hash,
    )


def _architect(patch: PatchCandidate) -> ArchitectPatchResult:
    rationale = _make_rationale(
        finding_id=patch.finding_id,
        root_cause_id="root-cause-1",
        invariant_id="CWE-89-PARAMETER-BINDING",
        invariant_version="1.0.0",
        regression_descriptor_id="regression-1",
        touched_symbols=(TouchedSymbol("app.py", "function", "get_user", 1, 8, HASH),),
    )
    return ArchitectPatchResult(patch, rationale)


def _policy() -> ComponentPin:
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id="local-approval-policy",
        component_version="1.0.0",
        content_sha256=HASH,
    )


def _validated_state() -> tuple[PatchCandidate, ValidationResult, PatchStatusState]:
    patch = _patch()
    state = promote_patch_candidate(start_patch_status(patch))
    validation = _validation(patch)
    return patch, validation, mark_patch_validated(state, validation)


def test_monotonic_suggestion_candidate_validation_and_local_approval() -> None:
    patch, validation, state = _validated_state()
    review = review_semantic_diff(_architect(patch), validation)
    approved = approve_patch_locally(
        state,
        review,
        approval_id="approval-1",
        approver_id="human-reviewer-1",
        policy=_policy(),
        approved_at=APPROVED_AT,
    )

    assert [item.status for item in approved.transitions] == [
        PatchStatus.SUGGESTED,
        PatchStatus.CANDIDATE,
        PatchStatus.VALIDATED,
        PatchStatus.APPROVED,
    ]
    assert approved.patch.patch_status is PatchStatus.APPROVED
    assert approved.effective_head_sha == FIXED_HEAD
    assert approved.approval is not None
    assert approved.approval.validation_result_sha256 == validation.result_sha256
    assert approved.approval.semantic_review_sha256 == review.review_sha256
    assert not hasattr(approved, "apply") and not hasattr(approved, "scm")


def test_approval_before_exact_validation_is_rejected() -> None:
    patch = _patch()
    candidate = promote_patch_candidate(start_patch_status(patch))
    review = review_semantic_diff(_architect(patch), _validation(patch))

    with pytest.raises(PatchStatusError) as error:
        approve_patch_locally(
            candidate,
            review,
            approval_id="approval-1",
            approver_id="human-reviewer-1",
            policy=_policy(),
            approved_at=APPROVED_AT,
        )
    assert error.value.code is PatchStatusErrorCode.TRANSITION_FORBIDDEN


def test_parent_or_different_patch_validation_cannot_mark_candidate_validated() -> None:
    patch = _patch()
    candidate = promote_patch_candidate(start_patch_status(patch))

    with pytest.raises(PatchStatusError) as error:
        mark_patch_validated(candidate, _validation(patch, head=HEAD))
    assert error.value.code is PatchStatusErrorCode.VALIDATION_REQUIRED

    stale = _validation(patch).model_copy(update={"patch_id": "patch-other"})
    with pytest.raises(PatchStatusError) as error:
        mark_patch_validated(candidate, stale)
    assert error.value.code is PatchStatusErrorCode.VALIDATION_REQUIRED


def test_review_replay_from_different_validation_bytes_is_rejected() -> None:
    patch, validation, state = _validated_state()
    replay_review = review_semantic_diff(
        _architect(patch),
        _validation(patch, result_hash="d" * 64),
    )

    with pytest.raises(PatchStatusError) as error:
        approve_patch_locally(
            state,
            replay_review,
            approval_id="approval-1",
            approver_id="human-reviewer-1",
            policy=_policy(),
            approved_at=APPROVED_AT,
        )
    assert error.value.code is PatchStatusErrorCode.REVIEW_REQUIRED
    assert validation.result_sha256 != replay_review.validation_result_sha256


def test_failed_validation_and_replayed_status_transition_fail_closed() -> None:
    patch = _patch()
    candidate = promote_patch_candidate(start_patch_status(patch))
    with pytest.raises(PatchStatusError) as error:
        mark_patch_validated(candidate, _validation(patch, outcome=ValidationOutcome.FAILED))
    assert error.value.code is PatchStatusErrorCode.VALIDATION_REQUIRED

    with pytest.raises(PatchStatusError) as error:
        promote_patch_candidate(candidate)
    assert error.value.code is PatchStatusErrorCode.TRANSITION_FORBIDDEN


@pytest.mark.parametrize("status", [PatchStatus.REJECTED, PatchStatus.SUPERSEDED])
def test_rejection_and_supersession_are_terminal_and_auditable(status: PatchStatus) -> None:
    closed = close_patch_status(
        start_patch_status(_patch()),
        status,
        reason_code="HUMAN_DECISION",
    )

    assert closed.patch.patch_status is status
    assert closed.transitions[-1].reason_code == "HUMAN_DECISION"
    with pytest.raises(PatchStatusError) as error:
        close_patch_status(closed, PatchStatus.REJECTED, reason_code="REPLAY")
    assert error.value.code is PatchStatusErrorCode.TRANSITION_FORBIDDEN


def test_changed_patch_bytes_invalidate_local_approval_state() -> None:
    patch, validation, state = _validated_state()
    review = review_semantic_diff(_architect(patch), validation)
    approved = approve_patch_locally(
        state,
        review,
        approval_id="approval-1",
        approver_id="human-reviewer-1",
        policy=_policy(),
        approved_at=APPROVED_AT,
    )
    changed = approved.patch.model_copy(update={"unified_diff_sha256": "d" * 64})
    object.__setattr__(approved, "patch", changed)

    with pytest.raises(PatchStatusError) as error:
        promote_patch_candidate(approved)
    assert error.value.code is PatchStatusErrorCode.INTEGRITY_FAILURE
