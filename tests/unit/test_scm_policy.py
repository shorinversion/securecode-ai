"""P5.3 deterministic policy truth-table contracts."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    AnalysisHealth,
    AuditRun,
    AuditRunOutcome,
    CandidateInterpretationReceipt,
    CandidateOrigin,
    ComponentPin,
    CoverageManifest,
    CoverageScenario,
    CoverageStatus,
    CoverageUnit,
    DiscoveryCandidate,
    DiscoveryLane,
    FindingGateState,
    LineageRef,
    ModelBudgetUsage,
    ModelCallStatus,
    ModelDiscoveryReceipt,
    ProducerRef,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.contracts.domain import ACCEPTED_STAGE_CATALOGUE_PIN
from securecode_ai.core.baseline_fingerprints import (
    BASELINE_FINGERPRINT_SCHEMA_VERSION,
    BaselineFingerprintComparison,
)
from securecode_ai.core.scm_policy import (
    SCM_POLICY_SCHEMA_VERSION,
    ScmPolicyDecision,
    ScmPolicyDocument,
    ScmPolicyEnforcement,
    ScmPolicyErrorCode,
    ScmPolicyInputHashes,
    ScmPolicyMode,
    ScmPolicyRequest,
    canonical_scm_policy_decision_json,
    evaluate_scm_policy,
)
from securecode_ai.server.persistence import DevelopmentRepository
from securecode_ai.server.worker_scm_policy import record_run_advisory_policy

HEAD = "a" * 40
BASE = "b" * 40
HASH_A = "a" * 64
HASH_B = "b" * 64
NOW = datetime(2026, 9, 8, tzinfo=UTC)


def _pin(name: str, digest: str = HASH_A, version: str = "1.0.0") -> ComponentPin:
    if name == "catalogue":
        name, version, digest = ACCEPTED_STAGE_CATALOGUE_PIN
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=name,
        component_version=version,
        content_sha256=digest,
    )


def _candidate() -> DiscoveryCandidate:
    producer = ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="deterministic",
        producer_version="1.0.0",
        producer_sha256=HASH_A,
    )
    lineage = LineageRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        lineage_id="lineage-1",
        lane=DiscoveryLane.DETERMINISTIC,
        producer=producer,
        root_cause_fingerprint=HASH_B,
        input_signal_ids=("signal-1",),
        evidence_ids=("evidence-1",),
    )
    return DiscoveryCandidate(
        schema_version=CONTRACT_SCHEMA_VERSION,
        candidate_id="candidate-1",
        tenant_id="tenant-1",
        candidate_version=1,
        head_sha=HEAD,
        root_cause_fingerprint=HASH_B,
        candidate_origin=CandidateOrigin.DETERMINISTIC,
        lineage=(lineage,),
        evidence_ids=("evidence-1",),
    )


def _run(
    outcome: AuditRunOutcome = AuditRunOutcome.PASS,
    *,
    missing_coverage: bool = False,
) -> AuditRun:
    if missing_coverage and outcome is not AuditRunOutcome.INDETERMINATE:
        raise ValueError("missing coverage requires indeterminate outcome")
    identity = RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-1",
            scm_provider="github",
            repository_id="repo-1",
            head_sha=HEAD,
            base_sha=BASE,
        ),
        stage_catalogue=_pin("catalogue"),
        workflow=_pin("workflow", HASH_B),
        policy=_pin("policy", "c" * 64),
        configuration=_pin("configuration", "d" * 64),
        provider_profile=_pin("provider", "e" * 64),
        capability_profile=_pin("capability", "f" * 64),
        egress_profile=_pin("egress", "1" * 64),
    )
    candidate = _candidate() if outcome is AuditRunOutcome.FAIL else None
    stages = [
        "intake",
        "language_discovery",
        "deterministic_analysis",
        "model_native_discovery",
        "normalization",
        "coverage_guard",
        "reporting",
    ]
    if candidate is not None:
        stages.extend(("evidence_graph", "auditor_investigation", "skeptic_review", "finding_gate"))
    units = tuple(
        CoverageUnit(
            schema_version=CONTRACT_SCHEMA_VERSION,
            coverage_unit_id=f"unit-{stage}",
            stage_id=stage,
            subject_id=(
                "candidate-1"
                if stage in {"auditor_investigation", "skeptic_review", "finding_gate"}
                else None
            ),
            required=True,
            applicable=True,
            coverage_status=(
                CoverageStatus.FAILED
                if missing_coverage and stage == "intake"
                else CoverageStatus.COMPLETED
            ),
            reason_code="STAGE_FAILED" if missing_coverage and stage == "intake" else None,
            producer_version=None if missing_coverage and stage == "intake" else "1.0.0",
            input_hashes=() if missing_coverage and stage == "intake" else (HASH_A,),
            output_hashes=() if missing_coverage and stage == "intake" else (HASH_B,),
            model_call_status=(
                ModelCallStatus.SUCCEEDED
                if stage in {"model_native_discovery", "auditor_investigation", "skeptic_review"}
                else None
            ),
            schema_valid_result=(
                True
                if stage in {"model_native_discovery", "auditor_investigation", "skeptic_review"}
                else None
            ),
            receipt_id=(
                "discovery-receipt"
                if stage == "model_native_discovery"
                else "interpretation-receipt"
                if stage == "auditor_investigation"
                else "skeptic-receipt"
                if stage == "skeptic_review"
                else None
            ),
        )
        for stage in stages
    )
    budget = ModelBudgetUsage(
        schema_version=CONTRACT_SCHEMA_VERSION,
        token_limit=100,
        tokens_used=1,
        repository_call_limit=10,
        repository_calls_used=1,
        time_limit_ms=1000,
        elapsed_ms=1,
    )
    manifest = CoverageManifest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        catalogue=_pin("catalogue"),
        execution_identity_hash=identity.execution_identity_hash,
        scenario=(
            CoverageScenario.CONFIRMED_FINDING_WITHOUT_REPAIR
            if candidate is not None
            else CoverageScenario.CLEAN_NO_CANDIDATE
        ),
        required_unit_ids=tuple(unit.coverage_unit_id for unit in units),
        units=units,
        discovery_candidates=() if candidate is None else (candidate,),
        model_discovery_receipts=(
            ModelDiscoveryReceipt(
                schema_version=CONTRACT_SCHEMA_VERSION,
                receipt_id="discovery-receipt",
                tenant_id="tenant-1",
                head_sha=HEAD,
                scope_sha256=HASH_A,
                model_profile=_pin("model"),
                prompt=_pin("prompt"),
                budget_usage=budget,
                model_call_status=ModelCallStatus.SUCCEEDED,
                schema_valid_result=True,
                input_sha256=HASH_A,
                output_sha256=HASH_B,
                candidate_ids=(),
            ),
        ),
        candidate_interpretation_receipts=()
        if candidate is None
        else (
            CandidateInterpretationReceipt(
                schema_version=CONTRACT_SCHEMA_VERSION,
                receipt_id="interpretation-receipt",
                tenant_id="tenant-1",
                candidate_id=candidate.candidate_id,
                candidate_version=candidate.candidate_version,
                head_sha=HEAD,
                auditor=_pin("auditor"),
                model_profile=_pin("model"),
                prompt=_pin("prompt"),
                evidence_sha256=HASH_A,
                model_call_status=ModelCallStatus.SUCCEEDED,
                schema_valid_result=True,
                verdict_ref="verdict-1",
                input_sha256=HASH_A,
                output_sha256=HASH_B,
            ),
        ),
        coverage_complete=not missing_coverage,
    )
    return AuditRun(
        schema_version=CONTRACT_SCHEMA_VERSION,
        run_id="run-1",
        execution_identity=identity,
        current_head_sha=HEAD,
        audit_outcome=outcome,
        analysis_health=AnalysisHealth.HEALTHY,
        finding_gate_state=(
            FindingGateState.BLOCKING if candidate is not None else FindingGateState.CLEAN
        ),
        coverage_manifest=manifest,
        finding_ids=() if candidate is None else ("finding-1",),
        blocking_finding_ids=() if candidate is None else ("finding-1",),
        unresolved_gate_ids=(),
        publication_preconditions_met=outcome is not AuditRunOutcome.INDETERMINATE,
        cancelled=outcome is AuditRunOutcome.CANCELLED,
        created_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
    )


def _policy(*, calibrated: bool) -> ScmPolicyDocument:
    return ScmPolicyDocument(
        policy_id="policy-v1",
        policy_version="1.0.0",
        content_sha256=HASH_A,
        calibration_record_sha256=HASH_B if calibrated else None,
    )


def _comparison(*, new: bool = False) -> BaselineFingerprintComparison:
    return BaselineFingerprintComparison(
        schema_version=BASELINE_FINGERPRINT_SCHEMA_VERSION,
        tenant_id="tenant-1",
        base_sha=BASE,
        head_sha=HEAD,
        baseline_fingerprints=() if new else (HASH_B,),
        head_fingerprints=(HASH_B,),
        new_fingerprints=(HASH_B,) if new else (),
    )


def test_advisory_never_blocks_but_preserves_the_observed_outcome() -> None:
    decision = evaluate_scm_policy(
        ScmPolicyRequest(
            _policy(calibrated=False), ScmPolicyMode.ADVISORY, _run(AuditRunOutcome.FAIL)
        )
    )

    assert decision.enforcement is ScmPolicyEnforcement.ADVISORY
    assert decision.observed_audit_outcome is AuditRunOutcome.FAIL
    assert not decision.is_passing
    assert not decision.blocks_merge
    assert decision.publication_permitted


def test_connected_completion_records_an_idempotent_advisory_event() -> None:
    audit_run = _run(AuditRunOutcome.FAIL)
    repository = DevelopmentRepository(sqlite3.connect(":memory:"))
    repository.create_run(
        tenant_id="tenant-1",
        run_id=audit_run.run_id,
        repository_id="repo-1",
        execution_identity_hash=audit_run.execution_identity.execution_identity_hash,
        base_sha=BASE,
        head_sha=HEAD,
        metadata={},
        idempotency_key="run-create-0001",
        request_sha256=HASH_A,
    )

    with repository.transaction() as cursor:
        first = record_run_advisory_policy(cursor, audit_run=audit_run)
        replay = record_run_advisory_policy(cursor, audit_run=audit_run)

    events = repository.list_events("tenant-1", audit_run.run_id, None, 10)
    items = events["items"]
    assert first == replay == 1
    assert isinstance(items, list) and len(items) == 1
    event = items[0]
    assert event["kind"] == "SCM_POLICY_DECISION"
    assert event["policy_decision"]["mode"] == "advisory"
    assert event["policy_decision"]["observed_audit_outcome"] == "FAIL"
    assert event["policy_decision"]["enforcement"] == "ADVISORY"
    assert event["policy_decision"]["blocks_merge"] is False


def test_advisory_receipt_binds_verified_baseline_comparison() -> None:
    audit_run = _run(AuditRunOutcome.FAIL)
    comparison = BaselineFingerprintComparison(
        schema_version=BASELINE_FINGERPRINT_SCHEMA_VERSION,
        tenant_id="tenant-1",
        base_sha=BASE,
        head_sha=HEAD,
        baseline_fingerprints=(HASH_B,),
        head_fingerprints=(HASH_B,),
        new_fingerprints=(),
    )
    repository = DevelopmentRepository(sqlite3.connect(":memory:"))
    repository.create_run(
        tenant_id="tenant-1",
        run_id=audit_run.run_id,
        repository_id="repo-1",
        execution_identity_hash=audit_run.execution_identity.execution_identity_hash,
        base_sha=BASE,
        head_sha=HEAD,
        metadata={},
        idempotency_key="run-create-0002",
        request_sha256=HASH_A,
    )

    with repository.transaction() as cursor:
        record_run_advisory_policy(
            cursor,
            audit_run=audit_run,
            baseline_comparison=comparison,
        )

    events = repository.list_events("tenant-1", audit_run.run_id, None, 10)
    items = events["items"]
    assert isinstance(items, list) and len(items) == 1
    event = items[0]
    assert isinstance(event, dict)
    policy_decision = event["policy_decision"]
    assert isinstance(policy_decision, dict)
    input_hashes = policy_decision["input_hashes"]
    assert isinstance(input_hashes, dict)
    assert input_hashes["baseline_comparison_sha256"]


def test_precalibration_blocking_request_is_non_passing_and_denied() -> None:
    decision = evaluate_scm_policy(
        ScmPolicyRequest(_policy(calibrated=False), ScmPolicyMode.NEW_CODE, _run())
    )

    assert decision.enforcement is ScmPolicyEnforcement.NON_PASS
    assert decision.error_code is ScmPolicyErrorCode.PRECALIBRATION_BLOCKING
    assert not decision.publication_permitted


def test_calibrated_new_code_allows_legacy_debt_and_blocks_new_finding() -> None:
    legacy = evaluate_scm_policy(
        ScmPolicyRequest(
            _policy(calibrated=True),
            ScmPolicyMode.NEW_CODE,
            _run(AuditRunOutcome.FAIL),
            _comparison(),
        )
    )
    new = evaluate_scm_policy(
        ScmPolicyRequest(
            _policy(calibrated=True),
            ScmPolicyMode.NEW_CODE,
            _run(AuditRunOutcome.FAIL),
            _comparison(new=True),
        )
    )

    assert legacy.enforcement is ScmPolicyEnforcement.ALLOW
    assert not legacy.blocks_merge
    assert legacy.observed_audit_outcome is AuditRunOutcome.FAIL
    assert new.enforcement is ScmPolicyEnforcement.BLOCK
    assert new.blocks_merge


def test_calibrated_strict_blocks_confirmed_finding() -> None:
    decision = evaluate_scm_policy(
        ScmPolicyRequest(
            _policy(calibrated=True),
            ScmPolicyMode.STRICT,
            _run(AuditRunOutcome.FAIL),
            _comparison(),
        )
    )

    assert decision.enforcement is ScmPolicyEnforcement.BLOCK
    assert decision.blocks_merge


def test_strict_policy_cannot_allow_failed_audit_with_valid_receipt_metadata() -> None:
    hashes = ScmPolicyInputHashes(
        policy_document_sha256=HASH_A,
        audit_run_sha256=HASH_B,
        execution_identity_sha256="c" * 64,
        baseline_comparison_sha256="d" * 64,
    )
    metadata = {
        "blocks_merge": False,
        "enforcement": ScmPolicyEnforcement.ALLOW.value,
        "error_code": None,
        "input_hashes": {
            "audit_run_sha256": hashes.audit_run_sha256,
            "baseline_comparison_sha256": hashes.baseline_comparison_sha256,
            "execution_identity_sha256": hashes.execution_identity_sha256,
            "policy_document_sha256": hashes.policy_document_sha256,
        },
        "is_passing": False,
        "matched_rule_ids": ("complete_non_blocking",),
        "mode": ScmPolicyMode.STRICT.value,
        "observed_audit_outcome": AuditRunOutcome.FAIL.value,
        "policy_id": "policy-v1",
        "policy_version": "1.0.0",
        "publication_permitted": True,
        "schema_version": SCM_POLICY_SCHEMA_VERSION,
    }
    digest = hashlib.sha256(
        json.dumps(
            metadata, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    ).hexdigest()

    with pytest.raises(ValueError, match="strict policy cannot allow"):
        ScmPolicyDecision(
            schema_version=SCM_POLICY_SCHEMA_VERSION,
            policy_id="policy-v1",
            policy_version="1.0.0",
            mode=ScmPolicyMode.STRICT,
            observed_audit_outcome=AuditRunOutcome.FAIL,
            enforcement=ScmPolicyEnforcement.ALLOW,
            is_passing=False,
            blocks_merge=False,
            publication_permitted=True,
            input_hashes=hashes,
            matched_rule_ids=("complete_non_blocking",),
            error_code=None,
            decision_sha256=digest,
        )


def test_missing_coverage_is_non_passing_even_when_advisory() -> None:
    decision = evaluate_scm_policy(
        ScmPolicyRequest(
            _policy(calibrated=False),
            ScmPolicyMode.ADVISORY,
            _run(AuditRunOutcome.INDETERMINATE, missing_coverage=True),
        )
    )

    assert decision.observed_audit_outcome is AuditRunOutcome.INDETERMINATE
    assert not decision.is_passing
    assert not decision.blocks_merge


def test_unknown_mode_is_a_typed_non_passing_error_without_permission() -> None:
    decision = evaluate_scm_policy(ScmPolicyRequest(_policy(calibrated=True), "future", _run()))

    assert decision.enforcement is ScmPolicyEnforcement.NON_PASS
    assert decision.error_code is ScmPolicyErrorCode.INVALID_INPUT
    assert decision.input_hashes is None
    assert not decision.publication_permitted


def test_receipt_binds_policy_and_every_input_hash_without_raw_source() -> None:
    request = ScmPolicyRequest(
        _policy(calibrated=True),
        ScmPolicyMode.NEW_CODE,
        _run(AuditRunOutcome.FAIL),
        _comparison(new=True),
    )
    first = evaluate_scm_policy(request)
    second = evaluate_scm_policy(request)

    assert first == second
    assert first.input_hashes is not None
    assert first.input_hashes.policy_document_sha256 == HASH_A
    assert first.input_hashes.baseline_comparison_sha256 is not None
    document = canonical_scm_policy_decision_json(first)
    assert "source" not in document.lower()
    assert "credentials" not in document.lower()
    assert document.endswith("\n")
