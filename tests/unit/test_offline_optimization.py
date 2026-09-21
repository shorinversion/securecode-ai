"""P7.14 offline prompt and skill optimization contracts."""

from __future__ import annotations

import hashlib

import pytest
from securecode_ai.core.evaluation_access import (
    EvaluationAccessAuthority,
    EvaluationAccessGrant,
    EvaluationCapability,
    EvaluationRole,
)
from securecode_ai.core.evaluation_authority import (
    EvaluationEvidenceAuthority,
    EvaluationObservedExecution,
    EvaluationSecurityReceipt,
)
from securecode_ai.core.evaluation_candidate_store import (
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
    EvaluationLaunchRequest,
    EvaluationPartition,
    EvaluationPinSet,
)
from securecode_ai.core.offline_optimization import (
    OfflineOptimizationError,
    OfflineOptimizationLab,
    OptimizationMetrics,
    OptimizationPhase,
    OptimizationProvenance,
    OptimizationResultAuthority,
    OptimizationRunReceipt,
    OptimizationRunRequest,
    pareto_front,
)
from securecode_ai.core.offline_optimization_evidence import optimization_envelope_hash
from securecode_ai.core.optimization_candidates import (
    OptimizationActor,
    OptimizationCandidateError,
    OptimizationCandidateKind,
    OptimizationCandidateStore,
    OptimizationCandidateSubmission,
)
from securecode_ai.core.optimization_promotion import (
    OptimizationPromotionDecision,
    OptimizationPromotionDisposition,
    OptimizationPromotionError,
    OptimizationPromotionGovernor,
    OptimizationPromotionRequest,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
CONTENT = b"offline-prompt-candidate"
CONTENT_SHA = hashlib.sha256(CONTENT).hexdigest()
FUTURE_UNIX = 4_102_444_800


def _candidate_store() -> tuple[OptimizationCandidateStore, str]:
    store = OptimizationCandidateStore()
    receipt = store.submit(
        OptimizationCandidateSubmission(
            "prompt-1", 1, "optimizer-owner", OptimizationCandidateKind.PROMPT, CONTENT
        ),
        actor=OptimizationActor.OPTIMIZER,
    )
    return store, receipt.candidate.candidate_key


def _provenance() -> OptimizationProvenance:
    return OptimizationProvenance("optimizer-1", "1.0.0", HASH_A, HASH_B, HASH_C, HASH_D, 11)


def _optimization_lab() -> tuple[
    OptimizationCandidateStore,
    str,
    OfflineOptimizationLab,
    OptimizationResultAuthority,
]:
    store, candidate_key = _candidate_store()
    authority = OptimizationResultAuthority(b"o" * 32, "optimization-authority")
    return store, candidate_key, OfflineOptimizationLab(store, authority), authority


def _record(
    lab: OfflineOptimizationLab,
    authority: OptimizationResultAuthority,
    request: OptimizationRunRequest,
    metrics: OptimizationMetrics,
) -> OptimizationRunReceipt:
    pending = lab.launch(request)
    result = authority.issue(
        pending.run_id,
        metrics,
        envelope_sha256=optimization_envelope_hash(pending.envelope),
        network_accessed=False,
        credentials_accessed=False,
        production_alias_accessed=False,
        locked_expectations_accessed=False,
    )
    return lab.record(request, result)


def _evaluation_grant(
    authority: EvaluationAccessAuthority,
    *,
    actor_id: str,
    role: EvaluationRole,
    capability: EvaluationCapability,
    candidate_key: str,
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


def _held_out_evidence() -> tuple[EvaluationLab, str, str, EvaluationSecurityReceipt]:
    access = EvaluationAccessAuthority(authority_id="access-authority", signing_key=b"a" * 32)
    evidence = EvaluationEvidenceAuthority(authority_id="evidence-authority", signing_key=b"e" * 32)
    store = EvaluationCandidateStore(access)
    submission = EvaluationCandidateSubmission("candidate-1", "trainer-1", HASH_A, CONTENT)
    candidate_key = evaluation_candidate_key(submission)
    store.submit(
        submission,
        role=EvaluationRole.TRAINER,
        actor_id="trainer-1",
        access_grant=_evaluation_grant(
            access,
            actor_id="trainer-1",
            role=EvaluationRole.TRAINER,
            capability=EvaluationCapability.SUBMIT_CANDIDATE,
            candidate_key=candidate_key,
            nonce="submit-held-out",
        ),
    )
    lab = EvaluationLab(store, evidence, access)
    dataset = EvaluationDatasetRef(
        "locked-set",
        EvaluationPartition.LOCKED_TEST,
        HASH_B,
        HASH_C,
        ("case-1", "case-2"),
    )
    pins = EvaluationPinSet(HASH_A, HASH_B, HASH_C, HASH_D, HASH_A)
    provisional = _evaluation_grant(
        access,
        actor_id="locked-executor",
        role=EvaluationRole.LOCKED_TEST_EXECUTOR,
        capability=EvaluationCapability.RUN_LOCKED_TEST,
        candidate_key=candidate_key,
        dataset_id=dataset.dataset_id,
        dataset_sha256=dataset.dataset_sha256,
        run_id="pending-run",
        nonce="launch-held-out-pending",
    )
    draft = EvaluationLaunchRequest(
        EvaluationRole.LOCKED_TEST_EXECUTOR,
        "locked-executor",
        candidate_key,
        dataset,
        pins,
        provisional,
    )
    run_id = evaluation_run_id(draft)
    launch_grant = _evaluation_grant(
        access,
        actor_id="locked-executor",
        role=EvaluationRole.LOCKED_TEST_EXECUTOR,
        capability=EvaluationCapability.RUN_LOCKED_TEST,
        candidate_key=candidate_key,
        dataset_id=dataset.dataset_id,
        dataset_sha256=dataset.dataset_sha256,
        run_id=run_id,
        nonce="launch-held-out",
    )
    launch = lab.launch(
        EvaluationLaunchRequest(
            EvaluationRole.LOCKED_TEST_EXECUTOR,
            "locked-executor",
            candidate_key,
            dataset,
            pins,
            launch_grant,
        )
    )
    observation = EvaluationObservedExecution(
        launch.run_id,
        launch.launch_evidence_sha256,
        evaluation_envelope_hash(launch.envelope),
        2,
        0,
        0,
        100,
        250,
        HASH_D,
        dataset.case_ids,
        False,
        False,
        False,
        False,
    )
    result = lab.issue_execution(
        actor_id="locked-executor", access_grant=launch_grant, observation=observation
    )
    lab.record_execution(
        role=EvaluationRole.LOCKED_TEST_EXECUTOR,
        actor_id="locked-executor",
        access_grant=launch_grant,
        result=result,
    )
    review_grant = _evaluation_grant(
        access,
        actor_id="reviewer-1",
        role=EvaluationRole.REVIEWER,
        capability=EvaluationCapability.REVIEW_PROMOTION,
        candidate_key=candidate_key,
        run_id=launch.run_id,
        nonce="review-held-out",
    )
    approval = lab.issue_security_approval(
        reviewer_id="reviewer-1",
        candidate_key=candidate_key,
        held_out_run_id=launch.run_id,
        approved=True,
        access_grant=review_grant,
    )
    return lab, candidate_key, launch.run_id, approval


def test_candidates_are_optimizer_only_immutable_and_have_no_production_alias() -> None:
    store, candidate_key = _candidate_store()

    assert store.resolve(candidate_key).content_sha256 == CONTENT_SHA
    with pytest.raises(OptimizationCandidateError):
        store.submit(
            OptimizationCandidateSubmission(
                "prompt-2",
                1,
                "production-agent",
                OptimizationCandidateKind.PROMPT,
                b"production-write",
            ),
            actor=OptimizationActor.PRODUCTION_AGENT,
        )


def test_offline_run_has_explicit_phase_no_locked_or_alias_access_and_counts_invalid_outputs() -> (
    None
):
    _, candidate_key, lab, authority = _optimization_lab()
    request = OptimizationRunRequest(
        OptimizationActor.OPTIMIZER,
        candidate_key,
        OptimizationPhase.DEV,
        _provenance(),
    )
    metrics = OptimizationMetrics(0.8, 20, 40, 0, 5, 2, 3, 500)

    receipt = _record(lab, authority, request, metrics)
    duplicate = _record(lab, authority, request, metrics)

    assert receipt.metrics.denominator_cases == 10
    assert receipt.metrics.invalid_outputs == 3
    assert not receipt.envelope.locked_expectations_access
    assert not receipt.envelope.production_alias_access
    assert duplicate.disposition.value == "IDEMPOTENT"
    with pytest.raises(OfflineOptimizationError):
        _record(
            lab,
            authority,
            request,
            OptimizationMetrics(0.7, 20, 40, 0, 6, 2, 2, 500),
        )


def test_pareto_comparison_uses_quality_cost_latency_and_security_regressions() -> None:
    _, candidate_key, lab, authority = _optimization_lab()
    dev = _record(
        lab,
        authority,
        OptimizationRunRequest(
            OptimizationActor.OPTIMIZER, candidate_key, OptimizationPhase.DEV, _provenance()
        ),
        OptimizationMetrics(0.8, 10, 20, 0, 8, 1, 1, 500),
    )
    train = _record(
        lab,
        authority,
        OptimizationRunRequest(
            OptimizationActor.OPTIMIZER, candidate_key, OptimizationPhase.TRAIN, _provenance()
        ),
        OptimizationMetrics(0.7, 15, 30, 1, 7, 2, 1, 500),
    )

    assert pareto_front((dev, train)) == (dev,)


def test_promotion_requires_clean_held_out_appsec_and_independent_reviewer_or_no_promotion() -> (
    None
):
    store, candidate_key, lab, authority = _optimization_lab()
    run = _record(
        lab,
        authority,
        OptimizationRunRequest(
            OptimizationActor.OPTIMIZER, candidate_key, OptimizationPhase.DEV, _provenance()
        ),
        OptimizationMetrics(0.9, 10, 20, 0, 8, 0, 0, 500),
    )
    evaluation_lab, held_out_candidate_key, held_out_run_id, approval = _held_out_evidence()
    governor = OptimizationPromotionGovernor(
        candidate_store=store, lab=lab, evaluation_lab=evaluation_lab
    )

    no_promotion = governor.decide(
        OptimizationPromotionRequest(
            OptimizationActor.PROMOTION_REVIEWER,
            "reviewer-1",
            OptimizationPromotionDecision.NO_PROMOTION,
            candidate_key,
            run.run_id,
            held_out_candidate_key,
            held_out_run_id,
            approval,
        )
    )
    promoted = governor.decide(
        OptimizationPromotionRequest(
            OptimizationActor.PROMOTION_REVIEWER,
            "reviewer-1",
            OptimizationPromotionDecision.PROMOTE,
            candidate_key,
            run.run_id,
            held_out_candidate_key,
            held_out_run_id,
            approval,
        )
    )

    assert no_promotion.disposition is OptimizationPromotionDisposition.NO_PROMOTION
    assert promoted.disposition is OptimizationPromotionDisposition.PROMOTED
    assert not promoted.production_alias_updated
    assert not promoted.locked_expectations_disclosed

    with pytest.raises(OptimizationPromotionError):
        OptimizationPromotionGovernor(
            candidate_store=store, lab=lab, evaluation_lab=evaluation_lab
        ).decide(
            OptimizationPromotionRequest(
                OptimizationActor.PROMOTION_REVIEWER,
                "optimizer-owner",
                OptimizationPromotionDecision.PROMOTE,
                candidate_key,
                run.run_id,
                held_out_candidate_key,
                held_out_run_id,
                approval,
            )
        )
