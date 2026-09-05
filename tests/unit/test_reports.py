"""Contract tests for deterministic multi-format reports (P2.12)."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    AnalysisHealth,
    ArtifactRef,
    AuditRun,
    AuditRunOutcome,
    CandidateInterpretationReceipt,
    CandidateOrigin,
    ComponentPin,
    CoverageManifest,
    CoverageScenario,
    CoverageStatus,
    CoverageUnit,
    DataClass,
    DiscoveryCandidate,
    DiscoveryLane,
    FindingCase,
    FindingGateState,
    FindingVerdict,
    LineageRef,
    ModelBudgetUsage,
    ModelCallStatus,
    ModelDiscoveryReceipt,
    ProducerRef,
    RepositoryRevision,
    RunExecutionIdentity,
    SourceLocation,
    SourcePosition,
)
from securecode_ai.contracts.domain import ACCEPTED_STAGE_CATALOGUE_PIN
from securecode_ai.core import reports as reports_module
from securecode_ai.core.classification import classify_cwe
from securecode_ai.core.reports import (
    SARIF_SCHEMA_SHA256,
    SARIF_SCHEMA_URI,
    DeterministicReport,
    ReportError,
    ReportErrorCode,
    ReportFinding,
    ReportFormat,
    build_deterministic_report,
    render_report,
)

HEAD = "a" * 40
BASE = "b" * 40
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
SarifDocument = dict[str, object]
SarifMutator = Callable[[SarifDocument], None]


def _pin(name: str, digest: str = HASH_A, version: str = "1.0.0") -> ComponentPin:
    if name == "catalogue":
        name, version, digest = ACCEPTED_STAGE_CATALOGUE_PIN
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=name,
        component_version=version,
        content_sha256=digest,
    )


def _revision(head: str = HEAD) -> RepositoryRevision:
    return RepositoryRevision(
        schema_version=CONTRACT_SCHEMA_VERSION,
        tenant_id="tenant-1",
        scm_provider="github",
        repository_id="repo-1",
        head_sha=head,
        base_sha=BASE,
    )


def _identity() -> RunExecutionIdentity:
    return RunExecutionIdentity.build(
        repository_revision=_revision(),
        stage_catalogue=_pin("catalogue"),
        workflow=_pin("workflow", HASH_B),
        policy=_pin("policy", HASH_C),
        configuration=_pin("configuration", "d" * 64),
        provider_profile=_pin("provider", "e" * 64),
        capability_profile=_pin("capability", "f" * 64),
        egress_profile=_pin("egress", "1" * 64),
    )


def _lineage() -> LineageRef:
    producer = ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="cwe89",
        producer_version="1.0.0",
        producer_sha256=HASH_B,
    )
    return LineageRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        lineage_id="lineage-deterministic",
        lane=DiscoveryLane.DETERMINISTIC,
        producer=producer,
        root_cause_fingerprint=HASH_C,
        input_signal_ids=("signal-1",),
        evidence_ids=("evidence-1",),
    )


def _model_native_lineage() -> LineageRef:
    producer = ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="model-native-discovery",
        producer_version="1.0.0",
        producer_sha256="d" * 64,
    )
    return LineageRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        lineage_id="lineage-model-native",
        lane=DiscoveryLane.MODEL_NATIVE,
        producer=producer,
        root_cause_fingerprint=HASH_C,
        input_candidate_ids=("model-source-1",),
        evidence_ids=("evidence-1",),
    )


def _candidate() -> DiscoveryCandidate:
    return DiscoveryCandidate(
        schema_version=CONTRACT_SCHEMA_VERSION,
        candidate_id="candidate-1",
        tenant_id="tenant-1",
        candidate_version=1,
        head_sha=HEAD,
        root_cause_fingerprint=HASH_C,
        candidate_origin=CandidateOrigin.HYBRID,
        lineage=(_lineage(), _model_native_lineage()),
        evidence_ids=("evidence-1",),
    )


def _unit(
    stage: str,
    *,
    status: CoverageStatus = CoverageStatus.COMPLETED,
    subject: str | None = None,
    receipt: str | None = None,
    model_status: ModelCallStatus | None = None,
) -> CoverageUnit:
    complete = status is CoverageStatus.COMPLETED
    return CoverageUnit(
        schema_version=CONTRACT_SCHEMA_VERSION,
        coverage_unit_id=f"unit-{stage}-{subject or 'root'}",
        stage_id=stage,
        subject_id=subject,
        required=True,
        applicable=True,
        coverage_status=status,
        reason_code=None if complete else "STAGE_FAILED",
        producer_version="1.0.0" if complete else None,
        input_hashes=(HASH_A,) if complete else (),
        output_hashes=(HASH_B,) if complete else (),
        model_call_status=model_status,
        schema_valid_result=True if model_status else None,
        receipt_id=receipt,
    )


def _budget() -> ModelBudgetUsage:
    return ModelBudgetUsage(
        schema_version=CONTRACT_SCHEMA_VERSION,
        token_limit=100,
        tokens_used=1,
        repository_call_limit=10,
        repository_calls_used=1,
        time_limit_ms=1000,
        elapsed_ms=1,
    )


def _manifest(*, complete: bool = True, with_candidate: bool = True) -> CoverageManifest:
    identity = _identity()
    candidate = _candidate() if with_candidate else None
    scenario = (
        CoverageScenario.CONFIRMED_FINDING_WITHOUT_REPAIR
        if with_candidate
        else CoverageScenario.CLEAN_NO_CANDIDATE
    )
    stages = [
        "intake",
        "language_discovery",
        "deterministic_analysis",
        "model_native_discovery",
        "normalization",
        "coverage_guard",
        "reporting",
    ]
    if with_candidate:
        stages += ["evidence_graph", "auditor_investigation", "skeptic_review", "finding_gate"]
    units = [
        _unit(
            stage,
            status=CoverageStatus.FAILED
            if not complete and stage == "intake"
            else CoverageStatus.COMPLETED,
            subject="candidate-1"
            if stage in {"auditor_investigation", "skeptic_review", "finding_gate"}
            else None,
            receipt="discovery-receipt"
            if stage == "model_native_discovery"
            else (
                "interpretation-receipt"
                if stage == "auditor_investigation"
                else ("skeptic-receipt" if stage == "skeptic_review" else None)
            ),
            model_status=ModelCallStatus.SUCCEEDED
            if stage in {"model_native_discovery", "auditor_investigation", "skeptic_review"}
            else None,
        )
        for stage in stages
    ]
    discovery = ModelDiscoveryReceipt(
        schema_version=CONTRACT_SCHEMA_VERSION,
        receipt_id="discovery-receipt",
        tenant_id="tenant-1",
        head_sha=HEAD,
        scope_sha256=HASH_A,
        model_profile=_pin("model"),
        prompt=_pin("prompt"),
        budget_usage=_budget(),
        model_call_status=ModelCallStatus.SUCCEEDED,
        schema_valid_result=True,
        input_sha256=HASH_B,
        output_sha256=HASH_C,
        candidate_ids=("candidate-1",) if candidate else (),
    )
    interpretation = CandidateInterpretationReceipt(
        schema_version=CONTRACT_SCHEMA_VERSION,
        receipt_id="interpretation-receipt",
        tenant_id="tenant-1",
        candidate_id="candidate-1",
        candidate_version=1,
        head_sha=HEAD,
        auditor=_pin("auditor"),
        model_profile=_pin("model"),
        prompt=_pin("prompt"),
        evidence_sha256=HASH_A,
        model_call_status=ModelCallStatus.SUCCEEDED,
        schema_valid_result=True,
        verdict_ref="verdict-1",
        input_sha256=HASH_B,
        output_sha256=HASH_C,
    )
    return CoverageManifest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        catalogue=_pin("catalogue"),
        execution_identity_hash=identity.execution_identity_hash,
        scenario=scenario,
        required_unit_ids=tuple(item.coverage_unit_id for item in units),
        units=tuple(units),
        discovery_candidates=(candidate,) if candidate else (),
        model_discovery_receipts=(discovery,),
        candidate_interpretation_receipts=(interpretation,) if candidate else (),
        coverage_complete=complete,
    )


def _run(*, complete: bool = True, with_candidate: bool = True) -> AuditRun:
    identity = _identity()
    manifest = _manifest(complete=complete, with_candidate=with_candidate)
    return AuditRun(
        schema_version=CONTRACT_SCHEMA_VERSION,
        run_id="run-1",
        execution_identity=identity,
        current_head_sha=HEAD,
        audit_outcome=AuditRunOutcome.FAIL
        if with_candidate
        else (AuditRunOutcome.PASS if complete else AuditRunOutcome.INDETERMINATE),
        analysis_health=AnalysisHealth.HEALTHY,
        finding_gate_state=FindingGateState.BLOCKING if with_candidate else FindingGateState.CLEAN,
        coverage_manifest=manifest,
        finding_ids=("finding-1",) if with_candidate else (),
        blocking_finding_ids=("finding-1",) if with_candidate else (),
        unresolved_gate_ids=(),
        publication_preconditions_met=True,
        created_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
    )


def _finding() -> FindingCase:
    return FindingCase(
        schema_version=CONTRACT_SCHEMA_VERSION,
        finding_id="finding-1",
        candidate_id="candidate-1",
        candidate_version=1,
        repository_revision=_revision(),
        root_cause_fingerprint=HASH_C,
        candidate_origin=CandidateOrigin.HYBRID,
        producer_lineage=(_lineage(), _model_native_lineage()),
        locations=(
            SourceLocation(
                schema_version=CONTRACT_SCHEMA_VERSION,
                path="src/<script>.py",
                start=SourcePosition(schema_version=CONTRACT_SCHEMA_VERSION, line=3, column=2),
                end=SourcePosition(schema_version=CONTRACT_SCHEMA_VERSION, line=3, column=12),
                content_sha256=HASH_A,
            ),
        ),
        cwe_id="CWE-89",
        evidence_graph_ref=ArtifactRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-1",
            content_id="graph-1",
            content_sha256=HASH_B,
            size_bytes=12,
            data_class=DataClass.INTERNAL_METADATA,
        ),
        evidence_ids=("evidence-1",),
        interpretation_receipt_id="interpretation-receipt",
        finding_verdict=FindingVerdict.CONFIRMED,
        verdict_evidence_ids=("evidence-1",),
        blocking=True,
    )


@pytest.fixture()
def report() -> DeterministicReport:
    return build_deterministic_report(
        _run(), (ReportFinding(_finding(), classify_cwe("CWE-89")),), (_pin("z-tool"),)
    )


def test_canonical_json_is_stable_and_contains_provenance(report: DeterministicReport) -> None:
    first = render_report(report, ReportFormat.JSON)
    second = render_report(report, ReportFormat.JSON)
    assert first == second
    document = json.loads(first)
    assert (
        document["execution_identity_hash"] == report.run.execution_identity.execution_identity_hash
    )
    assert (
        document["coverage_manifest"]
        and document["findings"][0]["root_cause_fingerprint"] == HASH_C
    )


def test_sarif_uses_21_structure_and_repository_relative_encoded_uri(
    report: DeterministicReport,
) -> None:
    document = json.loads(render_report(report, ReportFormat.SARIF))
    run = document["runs"][0]
    assert document["$schema"] == SARIF_SCHEMA_URI
    assert (
        "".join(
            (
                "c3b4bb2d",
                "60938974",
                "83348925",
                "aaa73af0",
                "3b3e3f4b",
                "d4ca38ce",
                "f26dcb42",
                "12a2682e",
            )
        )
        == SARIF_SCHEMA_SHA256
    )
    assert document["version"] == "2.1.0"
    assert (
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "src/%3Cscript%3E.py"
    )
    assert run["results"][0]["ruleId"] == "CWE-89"


def _sarif_run(document: SarifDocument) -> dict[str, object]:
    return cast(list[dict[str, object]], document["runs"])[0]


def _sarif_driver(document: SarifDocument) -> dict[str, object]:
    return cast(dict[str, object], cast(dict[str, object], _sarif_run(document)["tool"])["driver"])


def _sarif_automation(document: SarifDocument) -> dict[str, object]:
    return cast(dict[str, object], _sarif_run(document)["automationDetails"])


def _sarif_run_properties(document: SarifDocument) -> dict[str, object]:
    return cast(dict[str, object], _sarif_run(document)["properties"])


def _sarif_rule(document: SarifDocument) -> dict[str, object]:
    return cast(list[dict[str, object]], _sarif_driver(document)["rules"])[0]


def _sarif_rule_properties(document: SarifDocument) -> dict[str, object]:
    return cast(dict[str, object], _sarif_rule(document)["properties"])


def _sarif_short_description(document: SarifDocument) -> dict[str, object]:
    return cast(dict[str, object], _sarif_rule(document)["shortDescription"])


def _sarif_result(document: SarifDocument) -> dict[str, object]:
    return cast(list[dict[str, object]], _sarif_run(document)["results"])[0]


def _sarif_fingerprints(document: SarifDocument) -> dict[str, object]:
    return cast(dict[str, object], _sarif_result(document)["fingerprints"])


def _sarif_result_message(document: SarifDocument) -> dict[str, object]:
    return cast(dict[str, object], _sarif_result(document)["message"])


def _sarif_result_properties(document: SarifDocument) -> dict[str, object]:
    return cast(dict[str, object], _sarif_result(document)["properties"])


def _sarif_location(document: SarifDocument) -> dict[str, object]:
    return cast(list[dict[str, object]], _sarif_result(document)["locations"])[0]


def _sarif_physical_location(document: SarifDocument) -> dict[str, object]:
    return cast(dict[str, object], _sarif_location(document)["physicalLocation"])


def _sarif_artifact_location(document: SarifDocument) -> dict[str, object]:
    return cast(dict[str, object], _sarif_physical_location(document)["artifactLocation"])


def _sarif_region(document: SarifDocument) -> dict[str, object]:
    return cast(dict[str, object], _sarif_physical_location(document)["region"])


@pytest.mark.parametrize(
    "mutate",
    [
        lambda document: document.__setitem__("unexpected", True),
        lambda document: _sarif_run(document).__setitem__("unexpected", True),
        lambda document: _sarif_driver(document).__setitem__("unexpected", True),
        lambda document: _sarif_automation(document).__setitem__("unexpected", True),
        lambda document: _sarif_run_properties(document).__setitem__("unexpected", True),
        lambda document: _sarif_rule(document).__setitem__("unexpected", True),
        lambda document: _sarif_rule_properties(document).__setitem__("unexpected", True),
        lambda document: _sarif_short_description(document).__setitem__("unexpected", True),
        lambda document: _sarif_result(document).__setitem__("unexpected", True),
        lambda document: _sarif_fingerprints(document).__setitem__("unexpected", True),
        lambda document: _sarif_result_message(document).__setitem__("unexpected", True),
        lambda document: _sarif_result_properties(document).__setitem__("unexpected", True),
        lambda document: _sarif_location(document).__setitem__("unexpected", True),
        lambda document: _sarif_physical_location(document).__setitem__("unexpected", True),
        lambda document: _sarif_artifact_location(document).__setitem__("unexpected", True),
        lambda document: _sarif_region(document).__setitem__("unexpected", True),
        lambda document: _sarif_artifact_location(document).__setitem__(
            "uri", "C:/disclosed/path.py"
        ),
    ],
    ids=[
        "root",
        "run",
        "driver",
        "automation-details",
        "run-properties",
        "rule",
        "rule-properties",
        "short-description",
        "result",
        "fingerprints",
        "result-message",
        "result-properties",
        "location",
        "physical-location",
        "artifact-location",
        "region",
        "unsafe-uri",
    ],
)
def test_sarif_rejects_every_closed_structural_class_and_unsafe_uri(
    report: DeterministicReport, monkeypatch: pytest.MonkeyPatch, mutate: SarifMutator
) -> None:
    original = reports_module._sarif_document

    def malformed(_: DeterministicReport) -> SarifDocument:
        document = original(report)
        mutate(document)
        return document

    monkeypatch.setattr(reports_module, "_sarif_document", malformed)
    with pytest.raises(ReportError) as error:
        render_report(report, ReportFormat.SARIF)
    assert error.value.code is ReportErrorCode.FORMAT_INVALID


def test_markdown_html_escape_active_content_and_csp(report: DeterministicReport) -> None:
    markdown = render_report(report, ReportFormat.MARKDOWN).decode()
    html = render_report(report, ReportFormat.HTML).decode()
    assert "src/<script>.py" not in markdown and "src/<script>.py" not in html
    assert "<script>" not in html and "default-src 'none'" in html
    assert "src/\\<script\\>.py" in markdown
    assert "src/&lt;script&gt;.py" in html


def test_formats_preserve_semantics_and_incomplete_coverage_is_not_clean(
    report: DeterministicReport,
) -> None:
    outputs = {fmt: render_report(report, fmt).decode() for fmt in ReportFormat}
    assert all("FAIL" in value and "CWE-89" in value for value in outputs.values())
    incomplete = build_deterministic_report(
        _run(complete=False, with_candidate=False), (), (_pin("z-tool"),)
    )
    assert "not a clean" in render_report(incomplete, ReportFormat.MARKDOWN).decode().lower()
    assert "not a clean" in render_report(incomplete, ReportFormat.HTML).decode().lower()


def test_exact_identity_mismatch_is_rejected() -> None:
    material = _finding().model_dump(mode="python")
    material["repository_revision"] = _revision("c" * 40)
    finding = FindingCase.model_validate(material)
    with pytest.raises(ReportError) as error:
        build_deterministic_report(
            _run(), (ReportFinding(finding, classify_cwe("CWE-89")),), (_pin("z-tool"),)
        )
    assert error.value.code is ReportErrorCode.IDENTITY_MISMATCH


def test_tampered_input_and_report_document_are_rejected(report: DeterministicReport) -> None:
    with pytest.raises(ReportError) as error:
        build_deterministic_report(_run(), (), (_pin("z-tool"),))
    assert error.value.code is ReportErrorCode.FINDING_MISMATCH
    with pytest.raises(ValueError, match="deterministic report is invalid"):
        replace(report, document={"tampered": True})

    report.document["outcome"] = "PASS"
    with pytest.raises(ReportError) as error:
        render_report(report, ReportFormat.JSON)
    assert error.value.code is ReportErrorCode.INPUT_INVALID
