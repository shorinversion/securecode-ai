"""Contract, round-trip and fail-closed tests for P1.5 domain models."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import TypedDict

import pytest
from pydantic import ValidationError
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    AnalysisHealth,
    ArtifactRef,
    AuditRun,
    AuditRunOutcome,
    CandidateInterpretationReceipt,
    CandidateOrigin,
    ComponentPin,
    ContractExtension,
    CoverageManifest,
    CoverageScenario,
    CoverageStatus,
    CoverageUnit,
    DataClass,
    DiscoveryCandidate,
    DiscoveryLane,
    Evidence,
    EvidenceKind,
    ExtensionDataClass,
    FindingCase,
    FindingGateState,
    FindingVerdict,
    LineageRef,
    ModelBudgetUsage,
    ModelCallStatus,
    ModelDiscoveryReceipt,
    PatchCandidate,
    PatchStatus,
    ProducerRef,
    RawSignal,
    RepositoryRevision,
    ResourceUsage,
    RunExecutionIdentity,
    SourceLocation,
    SourcePosition,
    TrustLabel,
    ValidationGateOutcome,
    ValidationGateResult,
    ValidationOutcome,
    ValidationResult,
)
from securecode_ai.contracts.schema_export import validate_public_document


class WireArguments(TypedDict):
    schema_version: str


WIRE: WireArguments = {"schema_version": CONTRACT_SCHEMA_VERSION}
HEAD_SHA = "a" * 40
BASE_SHA = "b" * 40
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
NOW = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _pin(
    name: str,
    *,
    digest: str | None = None,
    version: str | None = None,
) -> ComponentPin:
    if digest is None:
        digest = (
            "adad2e05fc822485f45ac164299462d360ecb015327b84d09c064a697c193d1d"
            if name == "catalogue"
            else HASH_A
        )
    if version is None:
        version = "0.2.0" if name == "catalogue" else "1.0.0"
    return ComponentPin(
        **WIRE,
        component_id="core-mvp-0.2.0" if name == "catalogue" else name,
        component_version=version,
        content_sha256=digest,
    )


def _revision(*, head_sha: str = HEAD_SHA) -> RepositoryRevision:
    return RepositoryRevision(
        **WIRE,
        tenant_id="tenant-1",
        scm_provider="github",
        repository_id="repo-1",
        base_sha=BASE_SHA,
        head_sha=head_sha,
    )


def _identity(**pin_overrides: ComponentPin) -> RunExecutionIdentity:
    pins = {
        "stage_catalogue": _pin("catalogue"),
        "workflow": _pin("workflow", digest=HASH_B),
        "policy": _pin("policy", digest=HASH_C),
        "configuration": _pin("configuration", digest="d" * 64),
        "provider_profile": _pin("provider", digest="e" * 64),
        "capability_profile": _pin("capability", digest="f" * 64),
        "egress_profile": _pin("egress", digest="1" * 64),
    }
    pins.update(pin_overrides)
    return RunExecutionIdentity.build(
        repository_revision=_revision(),
        stage_catalogue=pins["stage_catalogue"],
        workflow=pins["workflow"],
        policy=pins["policy"],
        configuration=pins["configuration"],
        provider_profile=pins["provider_profile"],
        capability_profile=pins["capability_profile"],
        egress_profile=pins["egress_profile"],
    )


def _position(line: int, column: int) -> SourcePosition:
    return SourcePosition(**WIRE, line=line, column=column)


def _location(*, path: str = "src/app.py") -> SourceLocation:
    return SourceLocation(
        **WIRE,
        path=path,
        start=_position(3, 2),
        end=_position(3, 12),
        content_sha256=HASH_A,
    )


def _producer(name: str = "semgrep") -> ProducerRef:
    return ProducerRef(
        **WIRE,
        producer_id=name,
        producer_version="1.0.0",
        producer_sha256=HASH_B,
    )


def _lineage(lane: DiscoveryLane, *, root_cause_fingerprint: str = HASH_C) -> LineageRef:
    return LineageRef(
        **WIRE,
        lineage_id=f"lineage-{lane.value}",
        lane=lane,
        producer=_producer(lane.value),
        root_cause_fingerprint=root_cause_fingerprint,
        input_signal_ids=(f"signal-{lane.value}",),
        evidence_ids=(f"evidence-{lane.value}",),
    )


def _candidate(
    *,
    origin: CandidateOrigin = CandidateOrigin.HYBRID,
    version: int = 1,
) -> DiscoveryCandidate:
    lanes = {
        CandidateOrigin.DETERMINISTIC: (DiscoveryLane.DETERMINISTIC,),
        CandidateOrigin.MODEL_NATIVE: (DiscoveryLane.MODEL_NATIVE,),
        CandidateOrigin.HYBRID: (
            DiscoveryLane.DETERMINISTIC,
            DiscoveryLane.MODEL_NATIVE,
        ),
    }[origin]
    return DiscoveryCandidate(
        **WIRE,
        candidate_id="candidate-1",
        tenant_id="tenant-1",
        candidate_version=version,
        head_sha=HEAD_SHA,
        root_cause_fingerprint=HASH_C,
        candidate_origin=origin,
        lineage=tuple(_lineage(lane) for lane in lanes),
        evidence_ids=tuple(f"evidence-{lane.value}" for lane in lanes),
    )


def _source_artifact(*, digest: str = HASH_A) -> ArtifactRef:
    return ArtifactRef(
        **WIRE,
        tenant_id="tenant-1",
        content_id="artifact-source",
        content_sha256=digest,
        size_bytes=42,
        data_class=DataClass.CONFIDENTIAL_SOURCE,
        expires_at=NOW + timedelta(hours=1),
    )


def _coverage_unit(
    *,
    stage_id: str = "intake",
    coverage_status: CoverageStatus = CoverageStatus.COMPLETED,
    applicable: bool = True,
    reason_code: str | None = None,
    model_call_status: ModelCallStatus | None = None,
    schema_valid_result: bool | None = None,
    receipt_id: str | None = None,
    subject_id: str | None = None,
) -> CoverageUnit:
    completed = coverage_status is CoverageStatus.COMPLETED
    return CoverageUnit(
        **WIRE,
        coverage_unit_id=f"unit-{stage_id}"
        if subject_id is None
        else f"unit-{stage_id}-{subject_id}",
        stage_id=stage_id,
        subject_id=subject_id,
        required=True,
        applicable=applicable,
        coverage_status=coverage_status,
        reason_code=reason_code,
        producer_version="1.0.0" if completed else None,
        input_hashes=(HASH_A,) if completed else (),
        output_hashes=(HASH_B,) if completed else (),
        model_call_status=model_call_status,
        schema_valid_result=schema_valid_result,
        receipt_id=receipt_id,
    )


def _coverage_manifest(*, complete: bool = True) -> CoverageManifest:
    stages = (
        "intake",
        "language_discovery",
        "deterministic_analysis",
        "model_native_discovery",
        "normalization",
        "coverage_guard",
        "reporting",
    )
    units = tuple(
        _coverage_unit(
            stage_id=stage_id,
            model_call_status=(
                ModelCallStatus.SUCCEEDED if stage_id == "model_native_discovery" else None
            ),
            schema_valid_result=True if stage_id == "model_native_discovery" else None,
            receipt_id="receipt-discovery" if stage_id == "model_native_discovery" else None,
        )
        for stage_id in stages
    )
    if not complete:
        units = (
            _coverage_unit(
                stage_id="intake",
                coverage_status=CoverageStatus.FAILED,
                reason_code="STAGE_FAILED",
            ),
            *units[1:],
        )
    receipt = ModelDiscoveryReceipt(
        **WIRE,
        receipt_id="receipt-discovery",
        tenant_id="tenant-1",
        head_sha=HEAD_SHA,
        scope_sha256=HASH_A,
        model_profile=_pin("model"),
        prompt=_pin("prompt"),
        budget_usage=_budget(),
        model_call_status=ModelCallStatus.SUCCEEDED,
        schema_valid_result=True,
        input_sha256=HASH_B,
        output_sha256=HASH_C,
        candidate_ids=(),
    )
    return CoverageManifest(
        **WIRE,
        catalogue=_pin("catalogue"),
        execution_identity_hash=_identity().execution_identity_hash,
        scenario=CoverageScenario.CLEAN_NO_CANDIDATE,
        required_unit_ids=tuple(unit.coverage_unit_id for unit in units),
        units=units,
        model_discovery_receipts=(receipt,),
        coverage_complete=complete,
    )


def _audit_run(**changes: object) -> AuditRun:
    values: dict[str, object] = {
        **WIRE,
        "run_id": "run-1",
        "execution_identity": _identity(),
        "current_head_sha": HEAD_SHA,
        "audit_outcome": AuditRunOutcome.PASS,
        "analysis_health": AnalysisHealth.HEALTHY,
        "finding_gate_state": FindingGateState.CLEAN,
        "coverage_manifest": _coverage_manifest(),
        "finding_ids": (),
        "blocking_finding_ids": (),
        "unresolved_gate_ids": (),
        "publication_preconditions_met": True,
        "cancelled": False,
        "created_at": NOW,
        "completed_at": NOW + timedelta(seconds=1),
    }
    values.update(changes)
    return AuditRun.model_validate(values)


def _finding_case() -> FindingCase:
    lineages = (
        _lineage(DiscoveryLane.DETERMINISTIC),
        _lineage(DiscoveryLane.MODEL_NATIVE),
    )
    return FindingCase(
        **WIRE,
        finding_id="finding-1",
        candidate_id="candidate-1",
        candidate_version=1,
        repository_revision=_revision(),
        root_cause_fingerprint=HASH_C,
        candidate_origin=CandidateOrigin.HYBRID,
        producer_lineage=lineages,
        locations=(_location(),),
        cwe_id="CWE-89",
        evidence_graph_ref=ArtifactRef(
            **WIRE,
            tenant_id="tenant-1",
            content_id="evidence-graph",
            content_sha256=HASH_B,
            size_bytes=12,
            data_class=DataClass.INTERNAL_METADATA,
        ),
        evidence_ids=("evidence-deterministic", "evidence-model_native"),
        interpretation_receipt_id="receipt-interpretation",
        finding_verdict=FindingVerdict.CONFIRMED,
        verdict_evidence_ids=("evidence-deterministic",),
        blocking=True,
    )


def _evidence() -> Evidence:
    return Evidence(
        **WIRE,
        evidence_id="evidence-1",
        tenant_id="tenant-1",
        head_sha=HEAD_SHA,
        evidence_kind=EvidenceKind.SOURCE_LOCATION,
        producer=_producer(),
        trust_label=TrustLabel.TRUSTED_DETERMINISTIC,
        data_class=DataClass.CONFIDENTIAL_SOURCE,
        evidence_sha256=HASH_A,
        location=_location(),
        artifact_ref=_source_artifact(),
    )


def _patch() -> PatchCandidate:
    return PatchCandidate(
        **WIRE,
        patch_id="patch-1",
        finding_id="finding-1",
        repository_revision=_revision(),
        unified_diff_sha256=HASH_A,
        diff_ref=_source_artifact(),
        author=_producer("architect"),
        patch_status=PatchStatus.CANDIDATE,
    )


def _validation() -> ValidationResult:
    gate = ValidationGateResult(
        **WIRE,
        ordinal=1,
        gate_id="parse",
        gate_outcome=ValidationGateOutcome.PASSED,
        producer=_producer("validator"),
        input_hashes=(HASH_A,),
        output_hashes=(HASH_B,),
        resource_usage=ResourceUsage(
            **WIRE,
            elapsed_ms=10,
            peak_memory_bytes=1024,
            cpu_time_ms=8,
        ),
    )
    return ValidationResult(
        **WIRE,
        validation_id="validation-1",
        tenant_id="tenant-1",
        patch_id="patch-1",
        head_sha=HEAD_SHA,
        sandbox_profile=_pin("sandbox"),
        gates=(gate,),
        validation_outcome=ValidationOutcome.VALIDATED,
        result_sha256=HASH_C,
    )


def test_outcome_enums_are_disjoint_and_no_root_uses_generic_status() -> None:
    enum_types: set[type[StrEnum]] = {ModelCallStatus, FindingVerdict, AuditRunOutcome}
    assert len(enum_types) == 3
    assert type(ModelCallStatus.CANCELLED) is ModelCallStatus
    assert type(AuditRunOutcome.CANCELLED) is AuditRunOutcome
    for model in (AuditRun, FindingCase, Evidence, PatchCandidate, ValidationResult):
        assert "status" not in model.model_fields


@pytest.mark.parametrize("bad_version", ["0.1.9", "1.0.0", "2.0.0"])
def test_unsupported_or_old_wire_version_is_rejected(bad_version: str) -> None:
    with pytest.raises(ValidationError, match="version"):
        ComponentPin(
            schema_version=bad_version,
            component_id="policy",
            component_version="1.0.0",
            content_sha256=HASH_A,
        )


def test_future_minor_requires_explicit_closed_extension_envelope() -> None:
    extension = ContractExtension(
        namespace="future-feature",
        extension_version="1.0.0",
        data_class=ExtensionDataClass.INTERNAL_METADATA,
        tenant_id="tenant-1",
        content_id="extension-content",
        payload_sha256=HASH_A,
        payload_size_bytes=12,
    )
    pin = ComponentPin(
        schema_version="0.3.0",
        extensions=(extension,),
        component_id="policy",
        component_version="1.0.0",
        content_sha256=HASH_A,
    )
    assert pin.extensions == (extension,)
    with pytest.raises(ValidationError, match="Extra inputs"):
        ComponentPin.model_validate({**pin.model_dump(mode="json"), "unknown": True})
    with pytest.raises(ValidationError):
        ContractExtension.model_validate(
            {
                "namespace": "unsafe",
                "extension_version": "1.0.0",
                "data_class": "DC3_CONFIDENTIAL_SOURCE",
                "tenant_id": "tenant-1",
                "content_id": "extension-content",
                "payload_sha256": HASH_A,
                "payload_size_bytes": 12,
            }
        )


def test_schema_version_is_required_and_models_are_frozen() -> None:
    with pytest.raises(ValidationError, match="schema_version"):
        ComponentPin(
            component_id="policy",  # type: ignore[call-arg]
            component_version="1.0.0",
            content_sha256=HASH_A,
        )
    pin = _pin("policy")
    with pytest.raises(ValidationError, match="frozen"):
        pin.component_id = "changed"


def test_python_validation_is_strict_like_emitted_json_schema() -> None:
    with pytest.raises(ValidationError):
        SourcePosition.model_validate(
            {"schema_version": CONTRACT_SCHEMA_VERSION, "line": "1", "column": 2}
        )
    with pytest.raises(ValidationError):
        SourcePosition.model_validate(
            {"schema_version": CONTRACT_SCHEMA_VERSION, "line": True, "column": 2}
        )
    with pytest.raises(ValidationError):
        ComponentPin.model_validate(
            {
                "schema_version": CONTRACT_SCHEMA_VERSION,
                "component_id": " policy ",
                "component_version": "1.0.0",
                "content_sha256": HASH_A,
            }
        )


def test_data_class_values_exactly_match_frozen_classification_contract() -> None:
    assert {item.value for item in DataClass} == {
        "DC0_PUBLIC",
        "DC1_INTERNAL_METADATA",
        "DC2_CONFIDENTIAL_SECURITY",
        "DC3_CONFIDENTIAL_SOURCE",
        "DC4_RESTRICTED",
    }


def test_extension_envelope_is_metadata_only_and_cannot_serialize_a_canary() -> None:
    canary = "never-serialize-this-source-or-secret"
    payload = {
        "namespace": "future-feature",
        "extension_version": "1.0.0",
        "data_class": ExtensionDataClass.INTERNAL_METADATA,
        "tenant_id": "tenant-1",
        "content_id": "extension-content",
        "payload_sha256": HASH_A,
        "payload_size_bytes": len(canary),
        "values": {"raw": canary},
    }
    with pytest.raises(ValidationError, match="Extra inputs"):
        ContractExtension.model_validate(payload)
    payload.pop("values")
    extension = ContractExtension.model_validate(payload)
    assert canary not in extension.model_dump_json()


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "../src/app.py",
        "src/../app.py",
        "src\\app.py",
        "C:/src/app.py",
        "src//app.py",
        " src/app.py",
        ".",
        "src/\x7f.py",
        "src/\u202e.py",
        "src/e\u0301.py",
    ],
)
def test_source_location_rejects_non_normalized_or_host_paths(path: str) -> None:
    with pytest.raises(ValidationError, match="path"):
        _location(path=path)


def test_source_location_uses_one_based_ordered_intervals() -> None:
    with pytest.raises(ValidationError):
        _position(0, 1)
    with pytest.raises(ValidationError, match="precede"):
        SourceLocation(
            **WIRE,
            path="src/app.py",
            start=_position(4, 1),
            end=_position(3, 8),
            content_sha256=HASH_A,
        )


def test_execution_identity_hash_is_stable_and_forgery_is_rejected() -> None:
    first = _identity()
    second = _identity()
    assert first.execution_identity_hash == second.execution_identity_hash
    assert first.execution_identity_hash == (
        "2b9310e39707957735025bc4a1536581148a18f00c7df8a186586fe66b4c0247"
    )
    forged = first.model_dump(mode="python")
    forged["execution_identity_hash"] = HASH_A
    with pytest.raises(ValidationError, match="canonical identity"):
        RunExecutionIdentity.model_validate(forged)


def _extension(namespace: str, digest: str) -> ContractExtension:
    return ContractExtension(
        namespace=namespace,
        extension_version="1.0.0",
        data_class=ExtensionDataClass.INTERNAL_METADATA,
        tenant_id="tenant-1",
        content_id=f"content-{namespace}",
        payload_sha256=digest,
        payload_size_bytes=12,
    )


def test_execution_identity_canonicalizes_extension_order() -> None:
    first = RunExecutionIdentity.build(
        repository_revision=_revision(),
        stage_catalogue=_pin("catalogue"),
        workflow=_pin("workflow", digest=HASH_B),
        policy=_pin("policy", digest=HASH_C),
        configuration=_pin("configuration", digest="d" * 64),
        provider_profile=_pin("provider", digest="e" * 64),
        capability_profile=_pin("capability", digest="f" * 64),
        egress_profile=_pin("egress", digest="1" * 64),
        extensions=(_extension("zeta", HASH_A), _extension("alpha", HASH_B)),
    )
    second = RunExecutionIdentity.build(
        repository_revision=_revision(),
        stage_catalogue=_pin("catalogue"),
        workflow=_pin("workflow", digest=HASH_B),
        policy=_pin("policy", digest=HASH_C),
        configuration=_pin("configuration", digest="d" * 64),
        provider_profile=_pin("provider", digest="e" * 64),
        capability_profile=_pin("capability", digest="f" * 64),
        egress_profile=_pin("egress", digest="1" * 64),
        extensions=(_extension("alpha", HASH_B), _extension("zeta", HASH_A)),
    )
    assert [item.namespace for item in first.extensions] == ["alpha", "zeta"]
    assert first.execution_identity_hash == second.execution_identity_hash


@pytest.mark.parametrize(
    "pin_name",
    [
        "stage_catalogue",
        "workflow",
        "policy",
        "configuration",
        "provider_profile",
        "capability_profile",
        "egress_profile",
    ],
)
def test_each_execution_pin_mutation_changes_identity_hash(pin_name: str) -> None:
    baseline = _identity()
    mutated = _identity(**{pin_name: _pin(pin_name, digest="9" * 64)})
    assert mutated.execution_identity_hash != baseline.execution_identity_hash


def test_revision_mutation_changes_identity_and_stale_base_is_rejected() -> None:
    baseline = _identity()
    changed = RunExecutionIdentity.build(
        repository_revision=_revision(head_sha="c" * 40),
        stage_catalogue=baseline.stage_catalogue,
        workflow=baseline.workflow,
        policy=baseline.policy,
        configuration=baseline.configuration,
        provider_profile=baseline.provider_profile,
        capability_profile=baseline.capability_profile,
        egress_profile=baseline.egress_profile,
    )
    assert changed.execution_identity_hash != baseline.execution_identity_hash
    with pytest.raises(ValidationError, match="different revisions"):
        RepositoryRevision(
            **WIRE,
            tenant_id="tenant-1",
            scm_provider="github",
            repository_id="repo-1",
            base_sha=HEAD_SHA,
            head_sha=HEAD_SHA,
        )


def test_pass_requires_complete_healthy_coverage_and_no_blocking_finding() -> None:
    assert _audit_run().audit_outcome is AuditRunOutcome.PASS
    with pytest.raises(ValidationError, match="INDETERMINATE"):
        _audit_run(coverage_manifest=_coverage_manifest(complete=False))
    with pytest.raises(ValidationError, match="FAIL"):
        _audit_run(
            finding_ids=("finding-1",),
            blocking_finding_ids=("finding-1",),
            finding_gate_state=FindingGateState.BLOCKING,
        )
    with pytest.raises(ValidationError, match="INDETERMINATE"):
        _audit_run(analysis_health=AnalysisHealth.DEGRADED)


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        (
            {
                "finding_ids": ("finding-1",),
                "blocking_finding_ids": ("finding-1",),
                "finding_gate_state": FindingGateState.BLOCKING,
                "analysis_health": AnalysisHealth.DEGRADED,
            },
            AuditRunOutcome.FAIL,
        ),
        ({"analysis_health": AnalysisHealth.DEGRADED}, AuditRunOutcome.INDETERMINATE),
        ({"analysis_health": AnalysisHealth.UNAVAILABLE}, AuditRunOutcome.ERROR),
        ({"current_head_sha": "c" * 40}, AuditRunOutcome.SUPERSEDED),
        ({"unresolved_gate_ids": ("human-approval",)}, AuditRunOutcome.INDETERMINATE),
        ({"publication_preconditions_met": False}, AuditRunOutcome.INDETERMINATE),
        ({"cancelled": True}, AuditRunOutcome.CANCELLED),
        (
            {
                "cancelled": True,
                "finding_ids": ("finding-1",),
                "blocking_finding_ids": ("finding-1",),
                "finding_gate_state": FindingGateState.BLOCKING,
            },
            AuditRunOutcome.CANCELLED,
        ),
    ],
)
def test_audit_outcome_precedence_is_deterministic(
    changes: dict[str, object], expected: AuditRunOutcome
) -> None:
    run = _audit_run(**changes, audit_outcome=expected)
    assert run.audit_outcome is expected


def test_audit_run_rejects_mismatched_coverage_catalogue_pin() -> None:
    mismatched_identity = _identity(stage_catalogue=_pin("catalogue", digest=HASH_B))
    manifest = _coverage_manifest().model_copy(
        update={"execution_identity_hash": mismatched_identity.execution_identity_hash}
    )
    with pytest.raises(ValidationError, match="coverage catalogue"):
        _audit_run(execution_identity=mismatched_identity, coverage_manifest=manifest)


def test_audit_run_rejects_manifest_from_different_execution_identity() -> None:
    other_identity = _identity(provider_profile=_pin("other-provider", digest="2" * 64))
    with pytest.raises(ValidationError, match="exact execution identity hash"):
        _audit_run(execution_identity=other_identity)


def test_terminal_audit_run_requires_completed_at() -> None:
    values = _audit_run().model_dump(mode="python")
    values.pop("completed_at")
    with pytest.raises(ValidationError, match="completed_at"):
        AuditRun.model_validate(values)


def test_manifest_rejects_false_completeness_and_missing_required_unit() -> None:
    values = _coverage_manifest(complete=False).model_dump(mode="python")
    values["coverage_complete"] = True
    with pytest.raises(ValidationError, match="does not match"):
        CoverageManifest.model_validate(values)

    values = _coverage_manifest().model_dump(mode="python")
    values["units"] = tuple(values["units"])[1:]
    with pytest.raises(ValidationError, match="exactly enumerate"):
        CoverageManifest.model_validate(values)

    values = _coverage_manifest().model_dump(mode="python")
    hidden_required_failure = _coverage_unit(
        stage_id="evidence_graph",
        coverage_status=CoverageStatus.FAILED,
        reason_code="STAGE_FAILED",
    )
    values["units"] = (*tuple(values["units"]), hidden_required_failure)
    with pytest.raises(ValidationError, match="exactly enumerate"):
        CoverageManifest.model_validate(values)


@pytest.mark.parametrize("scenario", list(CoverageScenario))
def test_all_frozen_stage_catalogue_scenario_snapshots_validate(
    scenario: CoverageScenario,
) -> None:
    manifest = _scenario_manifest(scenario)
    assert manifest.scenario is scenario
    assert manifest.coverage_complete is (
        scenario is not CoverageScenario.UNSUPPORTED_REQUIRED_LANGUAGE
    )


@pytest.mark.parametrize("omitted_stage", ["evidence_graph", "skeptic_review"])
def test_candidate_scenario_rejects_omitted_mandatory_stage(omitted_stage: str) -> None:
    manifest = _scenario_manifest(CoverageScenario.CONFIRMED_FINDING_WITHOUT_REPAIR)
    values = manifest.model_dump(mode="python")
    retained = tuple(unit for unit in manifest.units if unit.stage_id != omitted_stage)
    values["units"] = retained
    values["required_unit_ids"] = tuple(unit.coverage_unit_id for unit in retained)
    with pytest.raises(ValidationError, match="scenario snapshot"):
        CoverageManifest.model_validate(values)


def test_unknown_or_future_model_stage_is_rejected_by_pinned_catalogue() -> None:
    manifest = _coverage_manifest()
    values = manifest.model_dump(mode="python")
    future = _coverage_unit(stage_id="future_model_review")
    values["units"] = (*manifest.units, future)
    values["required_unit_ids"] = (*manifest.required_unit_ids, future.coverage_unit_id)
    with pytest.raises(ValidationError, match="unknown"):
        CoverageManifest.model_validate(values)


def test_producer_cannot_mark_a_mandatory_scenario_stage_not_applicable() -> None:
    manifest = _coverage_manifest()
    values = manifest.model_dump(mode="python")
    units = list(manifest.units)
    target = units[0].model_dump(mode="python")
    target.update(
        {
            "applicable": False,
            "coverage_status": CoverageStatus.NOT_APPLICABLE,
            "reason_code": "PRODUCER_SELF_SKIP",
            "producer_version": None,
            "input_hashes": (),
            "output_hashes": (),
        }
    )
    units[0] = CoverageUnit.model_validate(target)
    values["units"] = tuple(units)
    with pytest.raises(ValidationError, match="must remain applicable"):
        CoverageManifest.model_validate(values)


def test_wrong_catalogue_id_version_or_hash_is_rejected() -> None:
    manifest = _coverage_manifest()
    for replacement in (
        _pin("other-catalogue"),
        _pin("catalogue", version="0.2.1"),
        _pin("catalogue", digest=HASH_A),
    ):
        values = manifest.model_dump(mode="python")
        values["catalogue"] = replacement
        with pytest.raises(ValidationError, match="exact accepted"):
            CoverageManifest.model_validate(values)


def test_accepted_catalogue_pin_matches_frozen_machine_catalogue_bytes() -> None:
    content = (REPOSITORY_ROOT / "specs/behavior/stage-catalogue.yaml").read_bytes()
    assert hashlib.sha256(content).hexdigest() == (
        "adad2e05fc822485f45ac164299462d360ecb015327b84d09c064a697c193d1d"
    )


def test_model_coverage_requires_succeeded_schema_valid_result() -> None:
    assert (
        _coverage_unit(
            stage_id="model_native_discovery",
            model_call_status=ModelCallStatus.SUCCEEDED,
            schema_valid_result=True,
            receipt_id="receipt-discovery",
        ).coverage_status
        is CoverageStatus.COMPLETED
    )
    with pytest.raises(ValidationError, match="SUCCEEDED"):
        _coverage_unit(
            stage_id="model_native_discovery",
            model_call_status=ModelCallStatus.REFUSED,
            schema_valid_result=False,
            receipt_id="receipt-discovery",
        )
    with pytest.raises(ValidationError, match="model coverage"):
        _coverage_unit(stage_id="model_native_discovery")


def _budget() -> ModelBudgetUsage:
    return ModelBudgetUsage(
        **WIRE,
        token_limit=100,
        tokens_used=10,
        repository_call_limit=10,
        repository_calls_used=2,
        time_limit_ms=1000,
        elapsed_ms=100,
    )


def _interpretation_receipt(*, version: int = 1) -> CandidateInterpretationReceipt:
    return CandidateInterpretationReceipt(
        **WIRE,
        receipt_id="receipt-interpretation",
        tenant_id="tenant-1",
        candidate_id="candidate-1",
        candidate_version=version,
        head_sha=HEAD_SHA,
        auditor=_pin("auditor"),
        model_profile=_pin("model"),
        prompt=_pin("auditor-prompt"),
        evidence_sha256=HASH_A,
        model_call_status=ModelCallStatus.SUCCEEDED,
        schema_valid_result=True,
        verdict_ref="verdict-1",
        input_sha256=HASH_B,
        output_sha256=HASH_C,
    )


def _coverage_manifest_with_candidate() -> CoverageManifest:
    candidate = _candidate()
    base = _coverage_manifest()
    discovery_values = base.model_discovery_receipts[0].model_dump(mode="python")
    discovery_values["candidate_ids"] = (candidate.candidate_id,)
    discovery_receipt = ModelDiscoveryReceipt.model_validate(discovery_values)
    extra_units = (
        _coverage_unit(stage_id="evidence_graph"),
        _coverage_unit(
            stage_id="auditor_investigation",
            subject_id=candidate.candidate_id,
            model_call_status=ModelCallStatus.SUCCEEDED,
            schema_valid_result=True,
            receipt_id="receipt-interpretation",
        ),
        _coverage_unit(
            stage_id="skeptic_review",
            subject_id=candidate.candidate_id,
            model_call_status=ModelCallStatus.SUCCEEDED,
            schema_valid_result=True,
            receipt_id="receipt-skeptic",
        ),
        _coverage_unit(stage_id="finding_gate", subject_id=candidate.candidate_id),
    )
    units = (*base.units, *extra_units)
    return CoverageManifest(
        **WIRE,
        catalogue=base.catalogue,
        execution_identity_hash=base.execution_identity_hash,
        scenario=CoverageScenario.CONFIRMED_FINDING_WITHOUT_REPAIR,
        required_unit_ids=tuple(unit.coverage_unit_id for unit in units),
        units=units,
        discovery_candidates=(candidate,),
        model_discovery_receipts=(discovery_receipt,),
        candidate_interpretation_receipts=(_interpretation_receipt(),),
        coverage_complete=True,
    )


def _scenario_manifest(scenario: CoverageScenario) -> CoverageManifest:
    if scenario is CoverageScenario.CLEAN_NO_CANDIDATE:
        return _coverage_manifest()

    atomic_by_scenario = {
        CoverageScenario.DEMO_CWE89_SCAN: (
            "intake",
            "language_discovery",
            "python_parse_symbols",
            "secret_scan",
            "dependency_scan",
            "cwe89_scan",
            "model_native_discovery",
            "normalization",
            "evidence_graph",
            "coverage_guard",
            "reporting",
        ),
        CoverageScenario.CONFIRMED_FINDING_WITHOUT_REPAIR: (
            "intake",
            "language_discovery",
            "deterministic_analysis",
            "model_native_discovery",
            "normalization",
            "evidence_graph",
            "coverage_guard",
            "reporting",
        ),
        CoverageScenario.REPAIR_REQUESTED: (
            "intake",
            "language_discovery",
            "deterministic_analysis",
            "model_native_discovery",
            "normalization",
            "evidence_graph",
            "coverage_guard",
            "reporting",
        ),
        CoverageScenario.UNSUPPORTED_REQUIRED_LANGUAGE: (
            "intake",
            "language_discovery",
            "deterministic_analysis",
            "coverage_guard",
            "reporting",
        ),
    }
    candidate = None if scenario is CoverageScenario.UNSUPPORTED_REQUIRED_LANGUAGE else _candidate()
    units = tuple(
        _coverage_unit(
            stage_id=stage_id,
            coverage_status=(
                CoverageStatus.UNSUPPORTED
                if scenario is CoverageScenario.UNSUPPORTED_REQUIRED_LANGUAGE
                and stage_id == "deterministic_analysis"
                else CoverageStatus.COMPLETED
            ),
            reason_code=(
                "LANGUAGE_UNSUPPORTED"
                if scenario is CoverageScenario.UNSUPPORTED_REQUIRED_LANGUAGE
                and stage_id == "deterministic_analysis"
                else None
            ),
            model_call_status=(
                ModelCallStatus.SUCCEEDED if stage_id == "model_native_discovery" else None
            ),
            schema_valid_result=True if stage_id == "model_native_discovery" else None,
            receipt_id="receipt-discovery" if stage_id == "model_native_discovery" else None,
        )
        for stage_id in atomic_by_scenario[scenario]
    )
    discovery_receipts: tuple[ModelDiscoveryReceipt, ...] = ()
    interpretation_receipts: tuple[CandidateInterpretationReceipt, ...] = ()
    candidates: tuple[DiscoveryCandidate, ...] = ()
    repair_ids: tuple[str, ...] = ()
    if candidate is not None:
        candidates = (candidate,)
        base_receipt = _coverage_manifest().model_discovery_receipts[0]
        receipt_values = base_receipt.model_dump(mode="python")
        receipt_values["candidate_ids"] = (candidate.candidate_id,)
        discovery_receipts = (ModelDiscoveryReceipt.model_validate(receipt_values),)
        interpretation_receipts = (_interpretation_receipt(),)
        units = (
            *units,
            _coverage_unit(
                stage_id="auditor_investigation",
                subject_id=candidate.candidate_id,
                model_call_status=ModelCallStatus.SUCCEEDED,
                schema_valid_result=True,
                receipt_id="receipt-interpretation",
            ),
            _coverage_unit(
                stage_id="skeptic_review",
                subject_id=candidate.candidate_id,
                model_call_status=ModelCallStatus.SUCCEEDED,
                schema_valid_result=True,
                receipt_id="receipt-skeptic",
            ),
            _coverage_unit(stage_id="finding_gate", subject_id=candidate.candidate_id),
        )
        if scenario is CoverageScenario.REPAIR_REQUESTED:
            repair_ids = (candidate.candidate_id,)
            units = (
                *units,
                _coverage_unit(
                    stage_id="root_cause_localization", subject_id=candidate.candidate_id
                ),
                _coverage_unit(
                    stage_id="security_test_generation",
                    subject_id=candidate.candidate_id,
                    model_call_status=ModelCallStatus.SUCCEEDED,
                    schema_valid_result=True,
                    receipt_id="receipt-security-test",
                ),
                _coverage_unit(
                    stage_id="architect",
                    subject_id=candidate.candidate_id,
                    model_call_status=ModelCallStatus.SUCCEEDED,
                    schema_valid_result=True,
                    receipt_id="receipt-architect",
                ),
                _coverage_unit(stage_id="validation_ladder", subject_id=candidate.candidate_id),
            )
    complete = scenario is not CoverageScenario.UNSUPPORTED_REQUIRED_LANGUAGE
    return CoverageManifest(
        **WIRE,
        catalogue=_pin("catalogue"),
        execution_identity_hash=_identity().execution_identity_hash,
        scenario=scenario,
        required_unit_ids=tuple(unit.coverage_unit_id for unit in units),
        units=units,
        discovery_candidates=candidates,
        model_discovery_receipts=discovery_receipts,
        candidate_interpretation_receipts=interpretation_receipts,
        repair_requested_candidate_ids=repair_ids,
        coverage_complete=complete,
    )


def test_unsupported_language_cannot_be_forged_as_complete_or_pass() -> None:
    manifest = _scenario_manifest(CoverageScenario.UNSUPPORTED_REQUIRED_LANGUAGE)
    values = manifest.model_dump(mode="python")
    values["units"] = tuple(
        _coverage_unit(stage_id=unit.stage_id)
        if unit.stage_id == "deterministic_analysis"
        else unit
        for unit in manifest.units
    )
    values["coverage_complete"] = True
    with pytest.raises(ValidationError, match="requires an UNSUPPORTED analysis unit"):
        CoverageManifest.model_validate(values)


def test_model_discovery_completed_zero_is_explicit_and_fail_closed() -> None:
    receipt = ModelDiscoveryReceipt(
        **WIRE,
        receipt_id="receipt-1",
        tenant_id="tenant-1",
        head_sha=HEAD_SHA,
        scope_sha256=HASH_A,
        model_profile=_pin("model"),
        prompt=_pin("prompt"),
        budget_usage=_budget(),
        model_call_status=ModelCallStatus.SUCCEEDED,
        schema_valid_result=True,
        input_sha256=HASH_B,
        output_sha256=HASH_C,
        candidate_ids=(),
    )
    assert receipt.is_completed_zero
    with pytest.raises(ValidationError, match="non-success"):
        ModelDiscoveryReceipt(
            **WIRE,
            receipt_id="receipt-2",
            tenant_id="tenant-1",
            head_sha=HEAD_SHA,
            scope_sha256=HASH_A,
            model_profile=_pin("model"),
            prompt=_pin("prompt"),
            budget_usage=_budget(),
            model_call_status=ModelCallStatus.REFUSED,
            schema_valid_result=True,
            input_sha256=HASH_B,
            output_sha256=HASH_C,
            candidate_ids=("candidate-1",),
        )


def test_manifest_requires_exactly_one_current_interpretation_per_candidate() -> None:
    manifest = _coverage_manifest_with_candidate()
    assert manifest.coverage_complete

    values = manifest.model_dump(mode="python")
    values["candidate_interpretation_receipts"] = ()
    with pytest.raises(ValidationError, match="exactly cover"):
        CoverageManifest.model_validate(values)

    values = manifest.model_dump(mode="python")
    values["candidate_interpretation_receipts"] = (
        _interpretation_receipt(),
        _interpretation_receipt(),
    )
    with pytest.raises(ValidationError, match="exactly one"):
        CoverageManifest.model_validate(values)

    values = manifest.model_dump(mode="python")
    values["candidate_interpretation_receipts"] = (_interpretation_receipt(version=2),)
    with pytest.raises(ValidationError, match="exactly cover"):
        CoverageManifest.model_validate(values)


def test_manifest_rejects_dropped_model_candidate_lineage() -> None:
    manifest = _coverage_manifest_with_candidate()
    values = manifest.model_dump(mode="python")
    receipt_values = manifest.model_discovery_receipts[0].model_dump(mode="python")
    receipt_values["candidate_ids"] = ()
    values["model_discovery_receipts"] = (ModelDiscoveryReceipt.model_validate(receipt_values),)
    with pytest.raises(ValidationError, match="preserve all"):
        CoverageManifest.model_validate(values)


def test_hybrid_candidate_rejects_distinct_root_cause_lineage() -> None:
    with pytest.raises(ValidationError, match="same root-cause"):
        DiscoveryCandidate(
            **WIRE,
            candidate_id="candidate-1",
            tenant_id="tenant-1",
            candidate_version=1,
            head_sha=HEAD_SHA,
            root_cause_fingerprint=HASH_C,
            candidate_origin=CandidateOrigin.HYBRID,
            lineage=(
                _lineage(DiscoveryLane.DETERMINISTIC, root_cause_fingerprint=HASH_C),
                _lineage(DiscoveryLane.MODEL_NATIVE, root_cause_fingerprint=HASH_B),
            ),
        )


@pytest.mark.parametrize(
    ("origin", "lanes"),
    [
        (CandidateOrigin.DETERMINISTIC, (DiscoveryLane.MODEL_NATIVE,)),
        (CandidateOrigin.MODEL_NATIVE, (DiscoveryLane.DETERMINISTIC,)),
        (CandidateOrigin.HYBRID, (DiscoveryLane.DETERMINISTIC,)),
    ],
)
def test_candidate_origin_must_match_exact_lineage(
    origin: CandidateOrigin,
    lanes: tuple[DiscoveryLane, ...],
) -> None:
    with pytest.raises(ValidationError, match="candidate_origin"):
        DiscoveryCandidate(
            **WIRE,
            candidate_id="candidate-1",
            tenant_id="tenant-1",
            candidate_version=1,
            head_sha=HEAD_SHA,
            root_cause_fingerprint=HASH_A,
            candidate_origin=origin,
            lineage=tuple(_lineage(lane, root_cause_fingerprint=HASH_A) for lane in lanes),
        )


def test_sensitive_evidence_and_raw_signal_require_artifact_references() -> None:
    assert _evidence().artifact_ref is not None
    with pytest.raises(ValidationError, match="ArtifactRef"):
        Evidence(
            **WIRE,
            evidence_id="evidence-1",
            tenant_id="tenant-1",
            head_sha=HEAD_SHA,
            evidence_kind=EvidenceKind.SOURCE_LOCATION,
            producer=_producer(),
            trust_label=TrustLabel.UNTRUSTED_REPOSITORY,
            data_class=DataClass.CONFIDENTIAL_SOURCE,
            evidence_sha256=HASH_A,
            location=_location(),
        )
    with pytest.raises(ValidationError, match="ArtifactRef"):
        RawSignal(
            **WIRE,
            raw_signal_id="signal-1",
            tenant_id="tenant-1",
            head_sha=HEAD_SHA,
            producer=_producer(),
            rule_id="CWE-89",
            location=_location(),
            payload_classification=DataClass.RESTRICTED,
            signal_sha256=HASH_A,
        )


def test_terminal_finding_verdict_requires_cited_evidence() -> None:
    values = _finding_case().model_dump(mode="python")
    values["verdict_evidence_ids"] = ()
    with pytest.raises(ValidationError, match="requires cited evidence"):
        FindingCase.model_validate(values)


def test_patch_reference_hash_and_class_are_enforced() -> None:
    assert _patch().diff_ref.content_sha256 == HASH_A
    values = _patch().model_dump(mode="python")
    values["unified_diff_sha256"] = HASH_B
    with pytest.raises(ValidationError, match="diff_ref hash"):
        PatchCandidate.model_validate(values)
    values = _patch().model_dump(mode="python")
    values["diff_ref"] = ArtifactRef(
        **WIRE,
        tenant_id="tenant-1",
        content_id="metadata",
        content_sha256=HASH_A,
        size_bytes=1,
        data_class=DataClass.INTERNAL_METADATA,
    )
    with pytest.raises(ValidationError, match="DC3_CONFIDENTIAL_SOURCE"):
        PatchCandidate.model_validate(values)


def test_cross_tenant_artifact_references_are_rejected() -> None:
    other_tenant = _source_artifact().model_copy(update={"tenant_id": "tenant-2"})
    evidence_values = _evidence().model_dump(mode="python")
    evidence_values["artifact_ref"] = other_tenant
    with pytest.raises(ValidationError, match="same tenant"):
        Evidence.model_validate(evidence_values)

    finding_values = _finding_case().model_dump(mode="python")
    graph = _finding_case().evidence_graph_ref.model_copy(update={"tenant_id": "tenant-2"})
    finding_values["evidence_graph_ref"] = graph
    with pytest.raises(ValidationError, match="same tenant"):
        FindingCase.model_validate(finding_values)

    patch_values = _patch().model_dump(mode="python")
    patch_values["diff_ref"] = other_tenant
    with pytest.raises(ValidationError, match="same tenant"):
        PatchCandidate.model_validate(patch_values)


def _cross_tenant_extension() -> ContractExtension:
    return ContractExtension(
        namespace="vendor.feature",
        extension_version="0.2.0",
        data_class=ExtensionDataClass.INTERNAL_METADATA,
        tenant_id="tenant-2",
        content_id="extension-content",
        payload_sha256=HASH_A,
        payload_size_bytes=1,
    )


@pytest.mark.parametrize(
    ("model", "instance"),
    [
        (AuditRun, _audit_run()),
        (FindingCase, _finding_case()),
        (Evidence, _evidence()),
        (PatchCandidate, _patch()),
        (ValidationResult, _validation()),
    ],
)
def test_public_roots_reject_cross_tenant_extensions(
    model: type[AuditRun | FindingCase | Evidence | PatchCandidate | ValidationResult],
    instance: AuditRun | FindingCase | Evidence | PatchCandidate | ValidationResult,
) -> None:
    values = instance.model_dump(mode="python")
    values["extensions"] = (_cross_tenant_extension(),)
    with pytest.raises(ValidationError, match="public-root tenant"):
        model.model_validate(values)


def test_nested_pin_and_artifact_extensions_bind_to_root_tenant() -> None:
    bad = (_cross_tenant_extension(),)
    policy = _pin("policy", digest=HASH_C).model_copy(update={"extensions": bad})
    identity = _identity(policy=policy)
    manifest = _coverage_manifest().model_copy(
        update={"execution_identity_hash": identity.execution_identity_hash}
    )
    with pytest.raises(ValidationError, match="public-root tenant"):
        _audit_run(execution_identity=identity, coverage_manifest=manifest)

    evidence = _evidence()
    assert evidence.artifact_ref is not None
    values = evidence.model_dump(mode="python")
    values["artifact_ref"] = evidence.artifact_ref.model_copy(update={"extensions": bad})
    with pytest.raises(ValidationError, match="public-root tenant"):
        Evidence.model_validate(values)


def test_validation_requires_ordered_all_passed_gates() -> None:
    validation = _validation()
    assert validation.validation_outcome is ValidationOutcome.VALIDATED
    values = validation.model_dump(mode="python")
    values["gates"] = (validation.gates[0], validation.gates[0])
    with pytest.raises(ValidationError, match="contiguous"):
        ValidationResult.model_validate(values)


@pytest.mark.parametrize(
    ("model", "instance"),
    [
        (AuditRun, _audit_run()),
        (FindingCase, _finding_case()),
        (Evidence, _evidence()),
        (PatchCandidate, _patch()),
        (ValidationResult, _validation()),
    ],
)
def test_public_roots_round_trip_through_json(
    model: type[AuditRun | FindingCase | Evidence | PatchCandidate | ValidationResult],
    instance: AuditRun | FindingCase | Evidence | PatchCandidate | ValidationResult,
) -> None:
    encoded = instance.model_dump_json()
    decoded = model.model_validate_json(encoded)
    assert decoded == instance
    assert json.loads(encoded)["schema_version"] == CONTRACT_SCHEMA_VERSION


def test_named_public_validator_applies_semantic_not_only_structural_rules() -> None:
    valid = _audit_run()
    assert validate_public_document("audit-run", valid.model_dump_json()) == valid
    invalid = valid.model_dump(mode="json")
    invalid["analysis_health"] = AnalysisHealth.DEGRADED.value
    with pytest.raises(ValidationError, match="INDETERMINATE"):
        validate_public_document("audit-run", json.dumps(invalid))


def test_timestamps_must_be_utc_and_completion_cannot_precede_creation() -> None:
    with pytest.raises(ValidationError, match="UTC"):
        _audit_run(created_at=datetime(2026, 8, 13, 12, 0, tzinfo=None))  # noqa: DTZ001
    with pytest.raises(ValidationError, match="precede"):
        _audit_run(completed_at=NOW - timedelta(seconds=1))


def test_raw_signal_schema_has_no_security_verdict() -> None:
    assert "finding_verdict" not in RawSignal.model_fields
    assert "audit_outcome" not in RawSignal.model_fields
