"""P4.10 pinned CWE-89 reference scenario over the accepted P4 contracts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from securecode_ai.adapters import (
    analyze_python_ast,
    build_python_symbol_index,
    scan_python_cwe89,
)
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ArtifactRef,
    CandidateOrigin,
    DataClass,
    DiscoveryCandidate,
    DiscoveryLane,
    Evidence,
    EvidenceKind,
    FindingCase,
    FindingVerdict,
    LineageRef,
    PatchStatus,
    ProducerRef,
    RepositoryRevision,
    ResourceUsage,
    SourceLocation,
    SourcePosition,
    TrustLabel,
    ValidationOutcome,
)
from securecode_ai.core.architect import TouchedSymbol, emit_patch_candidate
from securecode_ai.core.diff_review import DiffReviewDisposition, review_semantic_diff
from securecode_ai.core.evidence_graph import (
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceNodeKind,
    EvidenceNodeRef,
)
from securecode_ai.core.patch_status import (
    mark_patch_validated,
    promote_patch_candidate,
    start_patch_status,
)
from securecode_ai.core.regression import (
    RegressionCase,
    RegressionCaseKind,
    RegressionCaseResult,
    RegressionDisposition,
    RegressionExpectedOutcome,
    RegressionObservationStatus,
    RegressionRevisionRole,
    build_security_regression_descriptor,
    evaluate_regression,
)
from securecode_ai.core.repair_loop import RepairState, RepairStopReason, run_repair_loop
from securecode_ai.core.root_cause import (
    RootCauseEvidenceRefs,
    RootCauseLocalizationStatus,
    localize_root_cause,
)
from securecode_ai.core.sandbox import (
    SandboxAttestation,
    SandboxCommand,
    SandboxObservation,
    SandboxOutcome,
    SandboxProfile,
    SandboxTeardownReceipt,
    _attestation_hash,
    _observation_hash,
    _profile_hash,
    _teardown_hash,
)
from securecode_ai.core.security_invariants import (
    InvariantEvaluationReason,
    build_security_invariant,
    evaluate_security_invariant,
)
from securecode_ai.core.validation import (
    ValidationLadderRequest,
    ValidationStage,
    run_validation_ladder,
)

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "p4_10"
MANIFEST_PATH = FIXTURE_ROOT / "manifest.json"
PATCH_BYTES = (
    b"diff --git a/app.py b/app.py\n"
    b"--- a/app.py\n"
    b"+++ b/app.py\n"
    b"@@ -1,3 +1,3 @@\n"
    b" def get_user(request, db):\n"
    b'     user_id = request.args.get("user_id")\n'
    b'-    return db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()\n'
    b'+    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()\n'
)
GUARD_BYTES = b"CWE89-GUARD-001:requires-numeric-coercion-evidence\n"


def _manifest() -> dict[str, object]:
    value = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _digest(parts: object) -> str:
    assert isinstance(parts, list)
    assert len(parts) == 8
    assert all(isinstance(part, str) and len(part) == 8 for part in parts)
    return "".join(parts)


def _producer() -> ProducerRef:
    return ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="p4-10-reference",
        producer_version="1.0.0",
        producer_sha256="c" * 64,
    )


def _location(path: str, line: int, content_sha256: str) -> SourceLocation:
    return SourceLocation(
        schema_version=CONTRACT_SCHEMA_VERSION,
        path=path,
        start=SourcePosition(schema_version=CONTRACT_SCHEMA_VERSION, line=line, column=1),
        end=SourcePosition(schema_version=CONTRACT_SCHEMA_VERSION, line=line, column=9),
        content_sha256=content_sha256,
    )


def _evidence(
    evidence_id: str,
    kind: EvidenceKind,
    *,
    head_sha: str,
    content_sha256: str,
    location: SourceLocation | None,
) -> Evidence:
    return Evidence(
        schema_version=CONTRACT_SCHEMA_VERSION,
        evidence_id=evidence_id,
        tenant_id="p4-10-tenant",
        head_sha=head_sha,
        evidence_kind=kind,
        producer=_producer(),
        trust_label=TrustLabel.TRUSTED_DETERMINISTIC,
        data_class=DataClass.INTERNAL_METADATA,
        evidence_sha256=("d" if evidence_id.endswith("source") else "e") * 64,
        location=location,
    )


def _finding_graph(source_sha256: str, head_sha: str) -> tuple[FindingCase, EvidenceGraph]:
    revision = RepositoryRevision(
        schema_version=CONTRACT_SCHEMA_VERSION,
        tenant_id="p4-10-tenant",
        scm_provider="git",
        repository_id="p4-10-cwe89-reference",
        head_sha=head_sha,
    )
    evidence_ids = ("evidence-source", "evidence-propagation", "evidence-sink")
    candidate = DiscoveryCandidate(
        schema_version=CONTRACT_SCHEMA_VERSION,
        candidate_id="candidate-cwe89-1",
        tenant_id=revision.tenant_id,
        candidate_version=1,
        head_sha=head_sha,
        root_cause_fingerprint="f" * 64,
        candidate_origin=CandidateOrigin.DETERMINISTIC,
        lineage=(
            LineageRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                lineage_id="lineage-cwe89-1",
                lane=DiscoveryLane.DETERMINISTIC,
                producer=_producer(),
                root_cause_fingerprint="f" * 64,
                input_signal_ids=("cwe89-signal-1",),
                evidence_ids=evidence_ids,
            ),
        ),
        evidence_ids=evidence_ids,
    )
    source = _evidence(
        "evidence-source",
        EvidenceKind.SOURCE_LOCATION,
        head_sha=head_sha,
        content_sha256=source_sha256,
        location=_location("app.py", 2, source_sha256),
    )
    propagation = _evidence(
        "evidence-propagation",
        EvidenceKind.DATA_FLOW,
        head_sha=head_sha,
        content_sha256=source_sha256,
        location=None,
    )
    sink = _evidence(
        "evidence-sink",
        EvidenceKind.SOURCE_LOCATION,
        head_sha=head_sha,
        content_sha256=source_sha256,
        location=_location("app.py", 3, source_sha256),
    )
    graph = EvidenceGraph(
        graph_id="graph-cwe89-1",
        tenant_id=revision.tenant_id,
        head_sha=head_sha,
        candidates=(candidate,),
        evidence=(source, propagation, sink),
        edges=tuple(
            EvidenceGraphEdge(
                EvidenceEdgeKind.CANDIDATE_EVIDENCE,
                EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, candidate.candidate_id),
                EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, evidence.evidence_id),
            )
            for evidence in (source, propagation, sink)
        ),
    )
    assert source.location is not None
    assert sink.location is not None
    finding = FindingCase(
        schema_version=CONTRACT_SCHEMA_VERSION,
        finding_id="finding-cwe89-1",
        candidate_id=candidate.candidate_id,
        candidate_version=candidate.candidate_version,
        repository_revision=revision,
        root_cause_fingerprint=candidate.root_cause_fingerprint,
        candidate_origin=candidate.candidate_origin,
        producer_lineage=candidate.lineage,
        locations=(source.location, sink.location),
        cwe_id="CWE-89",
        evidence_graph_ref=ArtifactRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=revision.tenant_id,
            content_id=graph.graph_id,
            content_sha256=graph.graph_sha256,
            size_bytes=0,
            data_class=DataClass.INTERNAL_METADATA,
        ),
        evidence_ids=evidence_ids,
        interpretation_receipt_id="interpretation-cwe89-1",
        finding_verdict=FindingVerdict.CONFIRMED,
        verdict_evidence_ids=(source.evidence_id,),
        blocking=True,
    )
    return finding, graph


def _profile() -> SandboxProfile:
    seed = object.__new__(SandboxProfile)
    for name, value in (
        ("profile_id", "p4-10-airgap"),
        ("profile_version", "1.0.0"),
        ("network_disabled", True),
        ("credentials_disabled", True),
        ("host_access_disabled", True),
        ("rootless", True),
        ("read_only_root", True),
        ("max_cpu_time_ms", 100),
        ("max_memory_bytes", 1_000),
        ("max_processes", 2),
        ("max_disk_bytes", 1_000),
        ("max_output_bytes", 1_000),
        ("max_elapsed_ms", 100),
        ("profile_sha256", "0" * 64),
        ("schema_version", "1.0.0"),
    ):
        object.__setattr__(seed, name, value)
    return SandboxProfile(
        "p4-10-airgap",
        "1.0.0",
        True,
        True,
        True,
        True,
        True,
        100,
        1_000,
        2,
        1_000,
        1_000,
        100,
        _profile_hash(seed),
    )


class _EphemeralDriver:
    """Deterministic sandbox port: records no source and mutates no repository."""

    def __init__(self) -> None:
        self.commands: list[str] = []
        self.teardowns: list[SandboxTeardownReceipt] = []

    def attest(self, profile: SandboxProfile) -> SandboxAttestation:
        seed = object.__new__(SandboxAttestation)
        for name, value in (
            ("profile_id", profile.profile_id),
            ("profile_version", profile.profile_version),
            ("profile_sha256", profile.profile_sha256),
            ("network_disabled", True),
            ("credentials_disabled", True),
            ("host_access_disabled", True),
            ("rootless", True),
            ("read_only_root", True),
            ("attestation_sha256", "0" * 64),
            ("schema_version", "1.0.0"),
        ):
            object.__setattr__(seed, name, value)
        return SandboxAttestation(
            profile.profile_id,
            profile.profile_version,
            profile.profile_sha256,
            True,
            True,
            True,
            True,
            True,
            _attestation_hash(seed),
        )

    def execute(self, command: SandboxCommand, profile: SandboxProfile) -> SandboxObservation:
        del profile
        self.commands.append(command.command_id)
        usage = ResourceUsage(
            schema_version=CONTRACT_SCHEMA_VERSION,
            elapsed_ms=1,
            peak_memory_bytes=1,
            cpu_time_ms=1,
        )
        seed = object.__new__(SandboxObservation)
        for name, value in (
            ("outcome", SandboxOutcome.SUCCEEDED),
            ("output_sha256", "a" * 64),
            ("output_size_bytes", 1),
            ("resource_usage", usage),
            ("observation_sha256", "0" * 64),
            ("schema_version", "1.0.0"),
        ):
            object.__setattr__(seed, name, value)
        return SandboxObservation(
            SandboxOutcome.SUCCEEDED,
            "a" * 64,
            1,
            usage,
            _observation_hash(seed),
        )

    def teardown(self) -> SandboxTeardownReceipt:
        seed = object.__new__(SandboxTeardownReceipt)
        for name, value in (
            ("attempted", True),
            ("completed", True),
            ("live_workloads", 0),
            ("reusable_volumes", 0),
            ("receipt_sha256", "0" * 64),
            ("schema_version", "1.0.0"),
        ):
            object.__setattr__(seed, name, value)
        receipt = SandboxTeardownReceipt(True, True, 0, 0, _teardown_hash(seed))
        self.teardowns.append(receipt)
        return receipt


def _case_result(case: RegressionCase, outcome: RegressionExpectedOutcome) -> RegressionCaseResult:
    return RegressionCaseResult(
        case_id=case.case_id,
        status=RegressionObservationStatus.OBSERVED,
        observed_outcome=outcome,
        output_sha256=hashlib.sha256(case.case_id.encode("ascii")).hexdigest(),
        output_size_bytes=1,
    )


def test_pinned_cwe89_vulnerable_path_reaches_validated_candidate_ephemerally() -> None:
    manifest = _manifest()
    identities = manifest["identities"]
    cases_manifest = manifest["cases"]
    assert isinstance(identities, dict)
    assert isinstance(cases_manifest, list)
    vulnerable_case = cases_manifest[0]
    assert isinstance(vulnerable_case, dict)
    vulnerable = (FIXTURE_ROOT / "vulnerable" / "app.py").read_bytes()
    original_bytes = bytes(vulnerable)
    vulnerable_sha256 = hashlib.sha256(vulnerable).hexdigest()
    assert vulnerable_sha256 == _digest(vulnerable_case["sha256_parts"])
    assert hashlib.sha256(PATCH_BYTES).hexdigest() == _digest(
        identities["reference_patch_sha256_parts"]
    )

    index = build_python_symbol_index(
        repository_id=identities["repository_id"],
        revision=identities["vulnerable_head_sha"],
        path="app.py",
        content_sha256=vulnerable_sha256,
        source=vulnerable,
    )
    scan = scan_python_cwe89(index, analyze_python_ast(index))
    assert len(scan.signals) == 1

    finding, graph = _finding_graph(vulnerable_sha256, identities["vulnerable_head_sha"])
    root_receipt = localize_root_cause(
        finding,
        graph,
        RootCauseEvidenceRefs("evidence-source", "evidence-propagation", "evidence-sink"),
    )
    assert root_receipt.status is RootCauseLocalizationStatus.CONFIRMED
    assert root_receipt.record is not None
    invariant = build_security_invariant(finding, root_receipt.record)
    invariant_evaluation = evaluate_security_invariant(
        invariant,
        root_receipt.record,
        finding,
    )
    assert invariant_evaluation.reason is InvariantEvaluationReason.SATISFIED

    safe = (FIXTURE_ROOT / "safe" / "app.py").read_bytes()
    cases = (
        RegressionCase(
            "CWE89-GUARD-001",
            RegressionCaseKind.POC_PLUS,
            hashlib.sha256(GUARD_BYTES).hexdigest(),
            len(GUARD_BYTES),
            "2" * 64,
        ),
        RegressionCase(
            "CWE89-SAFE-001",
            RegressionCaseKind.SAFE_CONTROL,
            hashlib.sha256(safe).hexdigest(),
            len(safe),
            "3" * 64,
        ),
        RegressionCase(
            "CWE89-VULN-001",
            RegressionCaseKind.POC,
            vulnerable_sha256,
            len(vulnerable),
            "4" * 64,
        ),
    )
    descriptor = build_security_regression_descriptor(root_receipt.record, invariant, cases)
    vulnerable_regression = evaluate_regression(
        descriptor,
        root_receipt.record,
        invariant,
        revision_role=RegressionRevisionRole.VULNERABLE,
        evaluated_head_sha=identities["vulnerable_head_sha"],
        observations=tuple(
            _case_result(
                case,
                (
                    RegressionExpectedOutcome.VIOLATION_OBSERVED
                    if case.kind is RegressionCaseKind.POC
                    else RegressionExpectedOutcome.NO_VIOLATION
                ),
            )
            for case in descriptor.cases
        ),
    )
    assert (
        vulnerable_regression.disposition is RegressionDisposition.VULNERABLE_FAILURE_DEMONSTRATED
    )

    fixed_regression = evaluate_regression(
        descriptor,
        root_receipt.record,
        invariant,
        revision_role=RegressionRevisionRole.FIXED_CANDIDATE,
        evaluated_head_sha=identities["fixed_head_sha"],
        observations=tuple(
            _case_result(case, RegressionExpectedOutcome.NO_VIOLATION) for case in descriptor.cases
        ),
    )
    architect = emit_patch_candidate(
        finding,
        root_receipt.record,
        invariant,
        descriptor,
        unified_diff=PATCH_BYTES.decode("utf-8"),
        rationale="Use database driver parameter binding for the localized SQL construction.",
        touched_symbols=(TouchedSymbol("app.py", "function", "get_user", 1, 3, vulnerable_sha256),),
        author=_producer(),
    )
    profile = _profile()
    usage = ResourceUsage(
        schema_version=CONTRACT_SCHEMA_VERSION,
        elapsed_ms=1,
        peak_memory_bytes=1,
        cpu_time_ms=1,
    )
    driver = _EphemeralDriver()
    validation = run_validation_ladder(
        ValidationLadderRequest(
            validation_id="validation-cwe89-1",
            architect_result=architect,
            fixed_head_sha=identities["fixed_head_sha"],
            sandbox_profile=profile,
            producer=_producer(),
            fixed_regression=fixed_regression,
            stage_resources=(usage,) * len(tuple(ValidationStage)),
        ),
        driver,
    )
    repair = run_repair_loop(
        architect,
        lambda patch, attempt: validation,
        lambda feedback, attempt: architect,
    )
    review = review_semantic_diff(architect, validation.validation)
    state = mark_patch_validated(
        promote_patch_candidate(start_patch_status(architect.patch_candidate)),
        validation.validation,
    )

    assert validation.validation.validation_outcome is ValidationOutcome.VALIDATED
    assert repair.final_state is RepairState.VALIDATED_CANDIDATE
    assert repair.stop_reason is RepairStopReason.VALIDATED
    assert review.disposition is DiffReviewDisposition.REVIEWED_NO_HUMAN_MARKER
    assert not review.approval_eligible
    assert state.patch.patch_status is PatchStatus.VALIDATED
    assert state.approval is None
    assert driver.commands == [stage.value for stage in ValidationStage]
    assert len(driver.teardowns) == len(tuple(ValidationStage))
    assert all(receipt.completed for receipt in driver.teardowns)
    assert (FIXTURE_ROOT / "vulnerable" / "app.py").read_bytes() == original_bytes


def test_safe_control_has_no_scanner_signal_confirmed_finding_or_patch() -> None:
    manifest = _manifest()
    identities = manifest["identities"]
    cases_manifest = manifest["cases"]
    assert isinstance(identities, dict)
    assert isinstance(cases_manifest, list)
    safe_case = cases_manifest[1]
    assert isinstance(safe_case, dict)
    safe = (FIXTURE_ROOT / "safe" / "app.py").read_bytes()
    safe_sha256 = hashlib.sha256(safe).hexdigest()
    index = build_python_symbol_index(
        repository_id=identities["repository_id"],
        revision=identities["fixed_head_sha"],
        path="app.py",
        content_sha256=safe_sha256,
        source=safe,
    )

    assert scan_python_cwe89(index, analyze_python_ast(index)).signals == ()
    assert safe_sha256 == _digest(safe_case["sha256_parts"])


def test_manifest_has_fixed_fixture_provenance_without_product_pass_claim() -> None:
    manifest = _manifest()
    assert manifest["schema_version"] == "securecode.p4_10.reference.v1"
    assert manifest["dataset"] == {
        "dataset_id": "SC-MVP-CWE89",
        "version": "1.1.0",
        "revision": "securecode-spec-0.2.0",
        "sha256_parts": [
            "436843b0",
            "2bee53cc",
            "2997903b",
            "3e61afb9",
            "734ff5fa",
            "2580756e",
            "cba7344e",
            "92c12663",
        ],
    }
    cases = manifest["cases"]
    assert isinstance(cases, list)
    by_id = {item["case_id"]: item for item in cases if isinstance(item, dict)}
    assert set(by_id) == {"CWE89-VULN-001", "CWE89-SAFE-001", "CWE89-GUARD-001"}
    for case_id in ("CWE89-VULN-001", "CWE89-SAFE-001"):
        case = by_id[case_id]
        fixture = FIXTURE_ROOT / case["path"]
        content = fixture.read_bytes()
        assert len(content) == case["size_bytes"]
        assert hashlib.sha256(content).hexdigest() == _digest(case["sha256_parts"])
    assert by_id["CWE89-SAFE-001"]["expected"] == "no_confirmed_finding_or_patch"
    assert by_id["CWE89-GUARD-001"]["expected"] == "needs_more_evidence"
