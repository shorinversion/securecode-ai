"""P5.11 unit contracts for the offline CI worker adapter."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKER_SOURCE = ROOT / "apps" / "worker" / "src"
if str(WORKER_SOURCE) not in sys.path:
    sys.path.insert(0, str(WORKER_SOURCE))

from securecode_ai.contracts import (  # noqa: E402
    CONTRACT_SCHEMA_VERSION,
    AnalysisHealth,
    AuditRun,
    AuditRunOutcome,
    CandidateInterpretationReceipt,
    CandidateOrigin,
    CliErrorCode,
    CliExitCode,
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
    exit_code_for_audit_outcome,
)
from securecode_ai.contracts.domain import ACCEPTED_STAGE_CATALOGUE_PIN  # noqa: E402
from securecode_ai.worker import (  # noqa: E402
    CiWorkerReceipt,
    CiWorkerRequest,
    canonical_ci_worker_result_json,
    run_ci_worker,
)

HEAD = "a" * 40
BASE = "b" * 40
HASH_A = "a" * 64
HASH_B = "b" * 64
NOW = datetime(2026, 9, 17, 0, 0, tzinfo=UTC)


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


def _admitted_run(
    *,
    outcome: AuditRunOutcome = AuditRunOutcome.PASS,
    missing_coverage: bool = False,
) -> AuditRun:
    if missing_coverage and outcome is not AuditRunOutcome.INDETERMINATE:
        raise ValueError("missing coverage requires an indeterminate outcome")
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
            subject_id="candidate-1"
            if stage in {"auditor_investigation", "skeptic_review", "finding_gate"}
            else None,
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
            model_call_status=ModelCallStatus.SUCCEEDED
            if stage in {"model_native_discovery", "auditor_investigation", "skeptic_review"}
            else None,
            schema_valid_result=True
            if stage in {"model_native_discovery", "auditor_investigation", "skeptic_review"}
            else None,
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
    current_head = "c" * 40 if outcome is AuditRunOutcome.SUPERSEDED else HEAD
    return AuditRun(
        schema_version=CONTRACT_SCHEMA_VERSION,
        run_id="run-1",
        execution_identity=identity,
        current_head_sha=current_head,
        audit_outcome=outcome,
        analysis_health=(
            AnalysisHealth.UNAVAILABLE
            if outcome is AuditRunOutcome.ERROR
            else AnalysisHealth.HEALTHY
        ),
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


@pytest.mark.parametrize("outcome", list(AuditRunOutcome))
def test_worker_preserves_admitted_outcome_and_exact_identity_revision(
    outcome: AuditRunOutcome,
) -> None:
    audit_run = _admitted_run(outcome=outcome)
    result = run_ci_worker(CiWorkerRequest(audit_run=audit_run))

    assert result.audit_outcome is outcome
    assert result.exit_code is exit_code_for_audit_outcome(outcome)
    assert result.receipt is not None
    assert (
        result.receipt.execution_identity_hash
        == audit_run.execution_identity.execution_identity_hash
    )
    assert result.receipt.revision == audit_run.execution_identity.repository_revision.head_sha
    assert result.receipt.network_attempts == 0
    assert result.receipt.scm_write_attempts == 0
    assert (result.exit_code is CliExitCode.COMPLETED) is (outcome is AuditRunOutcome.PASS)


def test_worker_emits_one_canonical_metadata_only_machine_result() -> None:
    result = run_ci_worker(CiWorkerRequest(audit_run=_admitted_run()))
    document = canonical_ci_worker_result_json(result)

    assert document == canonical_ci_worker_result_json(result)
    assert document.endswith("\n")
    assert document == "".join(sorted(document.splitlines())) + "\n"
    assert json.loads(document) == result.document()
    assert all(value not in document for value in ("source", "credentials", "secret", "token"))


def test_invalid_or_forged_input_is_closed_usage_failure_not_pass() -> None:
    invalid = run_ci_worker(object())
    forged_outcome = _admitted_run().model_copy(update={"audit_outcome": AuditRunOutcome.FAIL})
    forged_head = _admitted_run(outcome=AuditRunOutcome.SUPERSEDED).model_copy(
        update={"current_head_sha": HEAD}
    )
    tampered_request = CiWorkerRequest(audit_run=_admitted_run())
    object.__setattr__(tampered_request, "audit_run", object())

    for result in (
        invalid,
        run_ci_worker(CiWorkerRequest(audit_run=forged_outcome)),
        run_ci_worker(CiWorkerRequest(audit_run=forged_head)),
        run_ci_worker(tampered_request),
    ):
        assert result.receipt is None
        assert result.error_code is CliErrorCode.INVALID_USAGE
        assert result.exit_code is CliExitCode.INVALID_USAGE_OR_CONFIG


@pytest.mark.parametrize(
    "outcome",
    (
        AuditRunOutcome.INDETERMINATE,
        AuditRunOutcome.ERROR,
        AuditRunOutcome.CANCELLED,
        AuditRunOutcome.SUPERSEDED,
    ),
)
def test_non_success_outcomes_never_render_pass(outcome: AuditRunOutcome) -> None:
    result = run_ci_worker(CiWorkerRequest(audit_run=_admitted_run(outcome=outcome)))

    assert result.audit_outcome is outcome
    assert result.exit_code is not CliExitCode.COMPLETED


def test_missing_mandatory_coverage_is_indeterminate_not_pass() -> None:
    result = run_ci_worker(
        CiWorkerRequest(
            audit_run=_admitted_run(outcome=AuditRunOutcome.INDETERMINATE, missing_coverage=True)
        )
    )

    assert result.audit_outcome is AuditRunOutcome.INDETERMINATE
    assert result.exit_code is CliExitCode.INDETERMINATE


def test_receipt_rejects_nonzero_network_or_scm_writes_and_bad_digest() -> None:
    baseline = run_ci_worker(CiWorkerRequest(audit_run=_admitted_run()))
    assert baseline.receipt is not None
    receipt = baseline.receipt

    for network_attempts, scm_write_attempts, receipt_sha256 in (
        (1, 0, receipt.receipt_sha256),
        (0, 1, receipt.receipt_sha256),
        (0, 0, "g" * 64),
    ):
        with pytest.raises(ValueError):
            CiWorkerReceipt(
                run_id=receipt.run_id,
                execution_identity_hash=receipt.execution_identity_hash,
                revision=receipt.revision,
                audit_outcome=receipt.audit_outcome,
                exit_code=receipt.exit_code,
                network_attempts=network_attempts,
                scm_write_attempts=scm_write_attempts,
                receipt_sha256=receipt_sha256,
            )
