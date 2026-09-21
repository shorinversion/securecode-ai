"""P7.12 isolated Evaluation Lab contracts."""

from __future__ import annotations

import pytest
from securecode_ai.core.evaluation_access import (
    EvaluationAccessAuthority,
    EvaluationAccessError,
    EvaluationAccessGrant,
    EvaluationCapability,
    EvaluationRole,
)
from securecode_ai.core.evaluation_authority import (
    EvaluationEvidenceAuthority,
    EvaluationObservedExecution,
)
from securecode_ai.core.evaluation_candidate_store import (
    CandidateStoreDisposition,
    EvaluationCandidateStore,
    EvaluationCandidateSubmission,
    evaluation_candidate_key,
)
from securecode_ai.core.evaluation_lab import EvaluationLab
from securecode_ai.core.evaluation_lab_evidence import (
    evaluation_envelope_hash,
    evaluation_run_id,
)
from securecode_ai.core.evaluation_lab_models import (
    EvaluationDatasetRef,
    EvaluationLabError,
    EvaluationLaunchDisposition,
    EvaluationLaunchReceipt,
    EvaluationLaunchRequest,
    EvaluationPartition,
    EvaluationPinSet,
    EvaluationPromotionDisposition,
    EvaluationPromotionRequest,
    EvaluationRunReceipt,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
HASH_E = "e" * 64
HASH_F = "f" * 64
FUTURE_UNIX = 4_102_444_800


def _grant(
    authority: EvaluationAccessAuthority,
    *,
    actor_id: str,
    role: EvaluationRole,
    capability: EvaluationCapability,
    candidate_key: str | None,
    dataset_id: str | None = None,
    dataset_sha256: str | None = None,
    run_id: str | None = None,
    nonce: str,
) -> EvaluationAccessGrant:
    return authority.issue(
        actor_id=actor_id,
        role=role,
        capability=capability,
        candidate_key=candidate_key,
        dataset_id=dataset_id,
        dataset_sha256=dataset_sha256,
        run_id=run_id,
        expires_at_unix=FUTURE_UNIX,
        nonce=nonce,
    )


def _store() -> tuple[
    EvaluationCandidateStore,
    str,
    EvaluationAccessAuthority,
    EvaluationEvidenceAuthority,
]:
    access = EvaluationAccessAuthority(authority_id="access-authority", signing_key=b"a" * 32)
    evidence = EvaluationEvidenceAuthority(authority_id="evidence-authority", signing_key=b"e" * 32)
    store = EvaluationCandidateStore(access)
    submission = EvaluationCandidateSubmission(
        candidate_id="candidate-1",
        submitted_by="trainer-1",
        lineage_sha256=HASH_A,
        content=b"candidate-program-v1",
    )
    candidate_key = evaluation_candidate_key(submission)
    receipt = store.submit(
        submission,
        role=EvaluationRole.TRAINER,
        actor_id="trainer-1",
        access_grant=_grant(
            access,
            actor_id="trainer-1",
            role=EvaluationRole.TRAINER,
            capability=EvaluationCapability.SUBMIT_CANDIDATE,
            candidate_key=candidate_key,
            nonce="submit-candidate",
        ),
    )
    return store, receipt.candidate.candidate_key, access, evidence


def _pins() -> EvaluationPinSet:
    return EvaluationPinSet(HASH_A, HASH_B, HASH_C, HASH_D, HASH_E)


def _dataset(partition: EvaluationPartition, *, name: str, lineage: str) -> EvaluationDatasetRef:
    return EvaluationDatasetRef(
        dataset_id=name,
        partition=partition,
        dataset_sha256=HASH_F,
        lineage_sha256=lineage,
        case_ids=("case-1", "case-2", "case-3", "case-4", "case-5", "case-6"),
    )


def _capability(partition: EvaluationPartition) -> EvaluationCapability:
    return {
        EvaluationPartition.TRAIN: EvaluationCapability.RUN_TRAIN,
        EvaluationPartition.DEV: EvaluationCapability.RUN_DEV,
        EvaluationPartition.CALIBRATION: EvaluationCapability.RUN_CALIBRATION,
        EvaluationPartition.LOCKED_TEST: EvaluationCapability.RUN_LOCKED_TEST,
    }[partition]


def _launch_request(
    access: EvaluationAccessAuthority,
    *,
    role: EvaluationRole,
    actor_id: str,
    candidate_key: str,
    dataset: EvaluationDatasetRef,
    nonce: str,
    request_role: EvaluationRole | None = None,
) -> EvaluationLaunchRequest:
    provisional = _grant(
        access,
        actor_id=actor_id,
        role=role,
        capability=_capability(dataset.partition),
        candidate_key=candidate_key,
        dataset_id=dataset.dataset_id,
        dataset_sha256=dataset.dataset_sha256,
        run_id="pending-run",
        nonce=f"{nonce}-pending",
    )
    actual_request_role = role if request_role is None else request_role
    draft = EvaluationLaunchRequest(
        actual_request_role,
        actor_id,
        candidate_key,
        dataset,
        _pins(),
        provisional,
    )
    run_id = evaluation_run_id(draft)
    grant = _grant(
        access,
        actor_id=actor_id,
        role=role,
        capability=_capability(dataset.partition),
        candidate_key=candidate_key,
        dataset_id=dataset.dataset_id,
        dataset_sha256=dataset.dataset_sha256,
        run_id=run_id,
        nonce=nonce,
    )
    return EvaluationLaunchRequest(
        actual_request_role,
        actor_id,
        candidate_key,
        dataset,
        _pins(),
        grant,
    )


def _record_execution(
    lab: EvaluationLab,
    request: EvaluationLaunchRequest,
    *,
    passed: int,
    failed: int,
    errors: int,
    result_sha256: str,
) -> tuple[EvaluationLaunchReceipt, EvaluationRunReceipt]:
    launch = lab.launch(request)
    observation = EvaluationObservedExecution(
        launch.run_id,
        launch.launch_evidence_sha256,
        evaluation_envelope_hash(launch.envelope),
        passed,
        failed,
        errors,
        100,
        250,
        result_sha256,
        request.dataset.case_ids,
        False,
        False,
        False,
        False,
    )
    result = lab.issue_execution(
        actor_id=request.actor_id,
        access_grant=request.access_grant,
        observation=observation,
    )
    receipt = lab.record_execution(
        role=request.role,
        actor_id=request.actor_id,
        access_grant=request.access_grant,
        result=result,
    )
    return launch, receipt


def test_access_is_deny_by_default_and_candidate_store_is_immutable() -> None:
    store, _, access, _ = _store()
    with pytest.raises(EvaluationAccessError):
        _grant(
            access,
            actor_id="trainer-1",
            role=EvaluationRole.TRAINER,
            capability=EvaluationCapability.READ_LOCKED_EXPECTATIONS,
            candidate_key=None,
            nonce="denied-locked-read",
        )

    same_submission = EvaluationCandidateSubmission(
        "candidate-1", "trainer-1", HASH_A, b"candidate-program-v1"
    )
    same_key = evaluation_candidate_key(same_submission)
    same = store.submit(
        same_submission,
        role=EvaluationRole.TRAINER,
        actor_id="trainer-1",
        access_grant=_grant(
            access,
            actor_id="trainer-1",
            role=EvaluationRole.TRAINER,
            capability=EvaluationCapability.SUBMIT_CANDIDATE,
            candidate_key=same_key,
            nonce="submit-same",
        ),
    )
    conflict_submission = EvaluationCandidateSubmission(
        "candidate-1", "trainer-1", HASH_A, b"candidate-program-v2"
    )
    conflict_key = evaluation_candidate_key(conflict_submission)
    conflict = store.submit(
        conflict_submission,
        role=EvaluationRole.TRAINER,
        actor_id="trainer-1",
        access_grant=_grant(
            access,
            actor_id="trainer-1",
            role=EvaluationRole.TRAINER,
            capability=EvaluationCapability.SUBMIT_CANDIDATE,
            candidate_key=conflict_key,
            nonce="submit-conflict",
        ),
    )

    assert same.disposition is CandidateStoreDisposition.IDEMPOTENT
    assert conflict.disposition is CandidateStoreDisposition.CONFLICT


def test_locked_launch_isolated_and_never_exposes_expectations_to_candidate() -> None:
    store, candidate_key, access, evidence = _store()
    lab = EvaluationLab(store, evidence, access)
    request = _launch_request(
        access,
        role=EvaluationRole.LOCKED_TEST_EXECUTOR,
        actor_id="locked-executor",
        candidate_key=candidate_key,
        dataset=_dataset(EvaluationPartition.LOCKED_TEST, name="locked-set", lineage=HASH_B),
        nonce="launch-locked",
    )

    receipt = lab.launch(request)
    duplicate = lab.launch(request)

    assert receipt.disposition is EvaluationLaunchDisposition.CREATED
    assert duplicate.disposition is EvaluationLaunchDisposition.IDEMPOTENT
    assert receipt.envelope.network_disabled
    assert receipt.envelope.credentials_disabled
    assert receipt.envelope.read_only_candidate
    assert receipt.envelope.isolated_scratch
    assert not receipt.envelope.locked_expectations_exposed_to_candidate
    assert not receipt.locked_expectations_disclosed
    assert not receipt.source_disclosed


def test_partition_lineage_is_separated_and_role_is_bound_to_partition() -> None:
    store, candidate_key, access, evidence = _store()
    lab = EvaluationLab(store, evidence, access)
    lab.launch(
        _launch_request(
            access,
            role=EvaluationRole.TRAINER,
            actor_id="trainer-1",
            candidate_key=candidate_key,
            dataset=_dataset(EvaluationPartition.TRAIN, name="train-set", lineage=HASH_C),
            nonce="launch-train",
        )
    )

    with pytest.raises(EvaluationLabError):
        lab.launch(
            _launch_request(
                access,
                role=EvaluationRole.LOCKED_TEST_EXECUTOR,
                request_role=EvaluationRole.TRAINER,
                actor_id="locked-executor",
                candidate_key=candidate_key,
                dataset=_dataset(
                    EvaluationPartition.LOCKED_TEST, name="locked-set", lineage=HASH_D
                ),
                nonce="launch-role-mismatch",
            )
        )
    with pytest.raises(EvaluationLabError):
        lab.launch(
            _launch_request(
                access,
                role=EvaluationRole.TRAINER,
                actor_id="trainer-1",
                candidate_key=candidate_key,
                dataset=_dataset(EvaluationPartition.DEV, name="dev-set", lineage=HASH_C),
                nonce="launch-lineage-conflict",
            )
        )


def test_execution_denominator_retains_failures_and_divergent_replay_conflicts() -> None:
    store, candidate_key, access, evidence = _store()
    lab = EvaluationLab(store, evidence, access)
    request = _launch_request(
        access,
        role=EvaluationRole.TRAINER,
        actor_id="trainer-1",
        candidate_key=candidate_key,
        dataset=_dataset(EvaluationPartition.TRAIN, name="train-set", lineage=HASH_B),
        nonce="execute-train",
    )
    launch, first = _record_execution(
        lab, request, passed=3, failed=2, errors=1, result_sha256=HASH_C
    )
    _, duplicate = _record_execution(
        lab, request, passed=3, failed=2, errors=1, result_sha256=HASH_C
    )

    assert first.denominator_cases == 6
    assert first.failed_cases == 2
    assert duplicate.disposition.value == "IDEMPOTENT"

    divergent = lab.issue_execution(
        actor_id=request.actor_id,
        access_grant=request.access_grant,
        observation=EvaluationObservedExecution(
            launch.run_id,
            launch.launch_evidence_sha256,
            evaluation_envelope_hash(launch.envelope),
            4,
            1,
            1,
            100,
            250,
            HASH_D,
            request.dataset.case_ids,
            False,
            False,
            False,
            False,
        ),
    )
    with pytest.raises(EvaluationLabError):
        lab.record_execution(
            role=request.role,
            actor_id=request.actor_id,
            access_grant=request.access_grant,
            result=divergent,
        )


def test_promotion_requires_independent_reviewer_clean_held_out_and_security_receipt() -> None:
    store, candidate_key, access, evidence = _store()
    lab = EvaluationLab(store, evidence, access)
    request = _launch_request(
        access,
        role=EvaluationRole.LOCKED_TEST_EXECUTOR,
        actor_id="locked-executor",
        candidate_key=candidate_key,
        dataset=_dataset(EvaluationPartition.LOCKED_TEST, name="locked-set", lineage=HASH_B),
        nonce="execute-locked",
    )
    launch, _ = _record_execution(lab, request, passed=6, failed=0, errors=0, result_sha256=HASH_C)

    with pytest.raises(EvaluationLabError):
        lab.issue_security_approval(
            reviewer_id="trainer-1",
            candidate_key=candidate_key,
            held_out_run_id=launch.run_id,
            approved=True,
            access_grant=_grant(
                access,
                actor_id="trainer-1",
                role=EvaluationRole.REVIEWER,
                capability=EvaluationCapability.REVIEW_PROMOTION,
                candidate_key=candidate_key,
                run_id=launch.run_id,
                nonce="owner-review",
            ),
        )

    security = lab.issue_security_approval(
        reviewer_id="reviewer-1",
        candidate_key=candidate_key,
        held_out_run_id=launch.run_id,
        approved=True,
        access_grant=_grant(
            access,
            actor_id="reviewer-1",
            role=EvaluationRole.REVIEWER,
            capability=EvaluationCapability.REVIEW_PROMOTION,
            candidate_key=candidate_key,
            run_id=launch.run_id,
            nonce="security-review",
        ),
    )
    promotion_grant = _grant(
        access,
        actor_id="reviewer-1",
        role=EvaluationRole.REVIEWER,
        capability=EvaluationCapability.PROMOTE,
        candidate_key=candidate_key,
        run_id=launch.run_id,
        nonce="promote-candidate",
    )
    promotion_request = EvaluationPromotionRequest(
        EvaluationRole.REVIEWER,
        "reviewer-1",
        "reviewer-1",
        candidate_key,
        launch.run_id,
        security,
        promotion_grant,
    )
    promoted = lab.promote(promotion_request)
    duplicate = lab.promote(promotion_request)

    assert promoted.disposition is EvaluationPromotionDisposition.PROMOTED
    assert duplicate.disposition is EvaluationPromotionDisposition.IDEMPOTENT
    assert not promoted.source_disclosed
    assert not promoted.locked_expectations_disclosed
