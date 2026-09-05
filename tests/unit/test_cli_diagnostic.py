"""P2.13 CLI composition checks; execution is deferred to G2 closure."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path

from securecode_ai.cli.application import main
from securecode_ai.cli.diagnostic import (
    DeterministicDiagnostic,
    DiagnosticFormat,
    UnavailableDeterministicDiagnostic,
    run_deterministic_diagnostic,
)
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
from securecode_ai.core.classification import classify_cwe
from securecode_ai.core.reports import (
    DeterministicReport,
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


def _pin(name: str, digest: str = HASH_A, version: str = "1.0.0") -> ComponentPin:
    if name == "catalogue":
        name, version, digest = ACCEPTED_STAGE_CATALOGUE_PIN
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=name,
        component_version=version,
        content_sha256=digest,
    )


def _revision() -> RepositoryRevision:
    return RepositoryRevision(
        schema_version=CONTRACT_SCHEMA_VERSION,
        tenant_id="tenant-1",
        scm_provider="github",
        repository_id="repo-1",
        head_sha=HEAD,
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


def _candidate() -> DiscoveryCandidate:
    producer = ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="cwe89",
        producer_version="1.0.0",
        producer_sha256=HASH_B,
    )
    lineage = LineageRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        lineage_id="lineage-deterministic",
        lane=DiscoveryLane.DETERMINISTIC,
        producer=producer,
        root_cause_fingerprint=HASH_C,
        input_signal_ids=("signal-1",),
        evidence_ids=("evidence-1",),
    )
    return DiscoveryCandidate(
        schema_version=CONTRACT_SCHEMA_VERSION,
        candidate_id="candidate-1",
        tenant_id="tenant-1",
        candidate_version=1,
        head_sha=HEAD,
        root_cause_fingerprint=HASH_C,
        candidate_origin=CandidateOrigin.DETERMINISTIC,
        lineage=(lineage,),
        evidence_ids=("evidence-1",),
    )


def _unit(
    stage: str,
    *,
    subject: str | None = None,
    receipt: str | None = None,
    model_status: ModelCallStatus | None = None,
) -> CoverageUnit:
    return CoverageUnit(
        schema_version=CONTRACT_SCHEMA_VERSION,
        coverage_unit_id=f"unit-{stage}-{subject or 'root'}",
        stage_id=stage,
        subject_id=subject,
        required=True,
        applicable=True,
        coverage_status=CoverageStatus.COMPLETED,
        reason_code=None,
        producer_version="1.0.0",
        input_hashes=(HASH_A,),
        output_hashes=(HASH_B,),
        model_call_status=model_status,
        schema_valid_result=True if model_status else None,
        receipt_id=receipt,
    )


def _report() -> DeterministicReport:
    identity = _identity()
    candidate = _candidate()
    stages = (
        "intake",
        "language_discovery",
        "deterministic_analysis",
        "model_native_discovery",
        "normalization",
        "coverage_guard",
        "reporting",
        "evidence_graph",
        "auditor_investigation",
        "skeptic_review",
        "finding_gate",
    )
    units = tuple(
        _unit(
            stage,
            subject=(
                "candidate-1"
                if stage in {"auditor_investigation", "skeptic_review", "finding_gate"}
                else None
            ),
            receipt="discovery-receipt"
            if stage == "model_native_discovery"
            else (
                "interpretation-receipt"
                if stage == "auditor_investigation"
                else ("skeptic-receipt" if stage == "skeptic_review" else None)
            ),
            model_status=(
                ModelCallStatus.SUCCEEDED
                if stage
                in {
                    "model_native_discovery",
                    "auditor_investigation",
                    "skeptic_review",
                }
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
        scenario=CoverageScenario.CONFIRMED_FINDING_WITHOUT_REPAIR,
        required_unit_ids=tuple(unit.coverage_unit_id for unit in units),
        units=units,
        discovery_candidates=(candidate,),
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
                input_sha256=HASH_B,
                output_sha256=HASH_C,
                candidate_ids=(),
            ),
        ),
        candidate_interpretation_receipts=(
            CandidateInterpretationReceipt(
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
            ),
        ),
        coverage_complete=True,
    )
    run = AuditRun(
        schema_version=CONTRACT_SCHEMA_VERSION,
        run_id="run-1",
        execution_identity=identity,
        current_head_sha=HEAD,
        audit_outcome=AuditRunOutcome.FAIL,
        analysis_health=AnalysisHealth.HEALTHY,
        finding_gate_state=FindingGateState.BLOCKING,
        coverage_manifest=manifest,
        finding_ids=("finding-1",),
        blocking_finding_ids=("finding-1",),
        unresolved_gate_ids=(),
        publication_preconditions_met=True,
        created_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
    )
    finding = FindingCase(
        schema_version=CONTRACT_SCHEMA_VERSION,
        finding_id="finding-1",
        candidate_id="candidate-1",
        candidate_version=1,
        repository_revision=_revision(),
        root_cause_fingerprint=HASH_C,
        candidate_origin=CandidateOrigin.DETERMINISTIC,
        producer_lineage=candidate.lineage,
        locations=(
            SourceLocation(
                schema_version=CONTRACT_SCHEMA_VERSION,
                path="src/app.py",
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
    return build_deterministic_report(
        run,
        (ReportFinding(finding, classify_cwe("CWE-89")),),
        (_pin("diagnostic-tool"),),
    )


class _Diagnostic:
    def __init__(self, report: DeterministicReport) -> None:
        self.report = report
        self.targets: list[str] = []

    def compose(self, target: str) -> DeterministicReport:
        self.targets.append(target)
        return self.report


def _invoke(
    argv: list[str], diagnostic: DeterministicDiagnostic | None = None
) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    code = main(
        argv,
        stdout=stdout,
        stderr=stderr,
        diagnostic=diagnostic,
        correlation_id_factory=lambda: "correlation",
    )
    return code, stdout.getvalue(), stderr.getvalue()


def test_explicit_machine_diagnostic_composes_report_but_not_product_scan(tmp_path: Path) -> None:
    report = _report()
    diagnostic = _Diagnostic(report)
    destination = tmp_path / "result.sarif"

    code, stdout, stderr = _invoke(
        [
            "--json",
            "scan",
            "fixture",
            "--diagnostic",
            "--format",
            "sarif",
            "--output",
            str(destination),
        ],
        diagnostic,
    )

    payload = json.loads(stdout)
    assert code == 0 and stderr == "" and stdout.count("\n") == 1
    assert payload["diagnostic_scope"] == "DETERMINISTIC_FACTS_AND_REPORTS_ONLY"
    assert payload["product_outcome"] == "NOT_EVALUATED"
    assert payload["scan_readiness"] == "NOT_EVALUATED"
    assert payload["model_native_discovery"] == "NOT_EXECUTED"
    assert payload["format"] == "sarif" and payload["output_written"] is True
    assert "PASS" not in stdout
    assert diagnostic.targets == ["fixture"]
    assert destination.read_bytes() == render_report(report, ReportFormat.SARIF)


def test_every_selected_format_is_rendered_from_the_same_validated_report(tmp_path: Path) -> None:
    report = _report()
    for format in DiagnosticFormat:
        destination = tmp_path / f"result.{format.value}"
        result = run_deterministic_diagnostic(
            _Diagnostic(report),
            target="fixture",
            report_format=format,
            output=destination,
        )
        assert result.report_sha256
        assert destination.read_bytes() == render_report(report, ReportFormat(format.value))
        assert result.document()["product_outcome"] == "NOT_EVALUATED"


def test_product_scan_without_explicit_diagnostic_scope_is_still_unavailable() -> None:
    diagnostic = _Diagnostic(_report())
    code, stdout, stderr = _invoke(["scan", "fixture", "--json"], diagnostic)

    assert code == 5 and stderr == "" and stdout.count("\n") == 1
    assert json.loads(stdout)["error"]["error_code"] == "INVALID_USAGE"
    assert diagnostic.targets == []


def test_unwired_diagnostic_is_indeterminate_without_path_or_source_echo() -> None:
    marker = "SECRET_SOURCE_CANARY"
    code, stdout, stderr = _invoke(
        ["--json", "scan", marker, "--diagnostic"], UnavailableDeterministicDiagnostic()
    )

    assert code == 3 and stderr == "" and stdout.count("\n") == 1
    assert json.loads(stdout)["error"]["error_code"] == "ANALYSIS_INDETERMINATE"
    assert marker not in stdout


def test_local_diagnostic_collects_safe_facts_without_a_model_receipt(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def run(request, cursor):\n    value = request.args.get('id')\n    return cursor.execute(f'SELECT {value}')\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("example-package==1.2.3\n", encoding="utf-8")
    destination = tmp_path.parent / "diagnostic-facts.json"

    code, stdout, stderr = _invoke(
        [
            "--json",
            "scan",
            str(tmp_path),
            "--diagnostic",
            "--format",
            "json",
            "--output",
            str(destination),
        ]
    )

    receipt = json.loads(stdout)
    facts = json.loads(destination.read_text(encoding="ascii"))
    assert code == 0 and stderr == "" and stdout.count("\n") == 1
    assert receipt["product_outcome"] == "NOT_EVALUATED"
    assert receipt["model_native_discovery"] == "NOT_EXECUTED"
    assert facts["product_outcome"] == "NOT_EVALUATED"
    assert facts["model_native_discovery"] == "NOT_EXECUTED"
    assert facts["facts"]["files_total"] == 2
    assert facts["facts"]["dependencies_parsed"] == 1
    assert facts["facts"]["cwe89_signals"] >= 1
    assert "app.py" not in destination.read_text(encoding="ascii")


def test_existing_output_is_never_overwritten_and_human_output_is_safe(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "existing.json"
    original = b"do-not-overwrite"
    destination.write_bytes(original)
    code, stdout, stderr = _invoke(
        ["scan", "fixture", "--diagnostic", "--output", str(destination)],
        _Diagnostic(_report()),
    )

    assert code == 4
    assert stdout == ""
    assert stderr == "operation could not be completed\n"
    assert destination.read_bytes() == original
