"""Actual catalogue child execution, including isolated static worker."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import NotRequired, TypedDict, Unpack

import pytest
from securecode_ai.adapters.dependency_scanning import ApprovedOsvScanner
from securecode_ai.adapters.native_sources import NativeSourceCatalogue
from securecode_ai.adapters.product_audit import (
    ProductAuditHostInputs,
    ProductAuditStateObservation,
)
from securecode_ai.adapters.product_execution import (
    ProductDeterministicExecution,
    execute_deterministic_children,
)
from securecode_ai.adapters.product_review import ProductReviewResult
from securecode_ai.adapters.product_runtime import ProductAuditorInvocationObservation
from securecode_ai.adapters.product_scan import (
    ProductCandidateFlow,
    ProductCompositionFailure,
)
from securecode_ai.adapters.product_scanner import ProductDeterministicScanResult
from securecode_ai.adapters.secret_detection import SecretFingerprintKey
from securecode_ai.contracts import Evidence, RunExecutionIdentity, WorkflowSnapshot
from securecode_ai.core.evidence_graph import EvidenceGraph
from securecode_ai.core.investigation import (
    AuditorInvoker,
    InvestigationBudget,
    ReadOnlyEvidenceContext,
)
from securecode_ai.core.model_discovery import ModelNativeDiscoveryBackend, ModelNativeDiscoveryPlan


class _FlowKwargs(TypedDict):
    catalogue: NativeSourceCatalogue
    model_plan: ModelNativeDiscoveryPlan
    model_backend: ModelNativeDiscoveryBackend
    deterministic_scanner: Callable[
        [NativeSourceCatalogue], EvidenceGraph | ProductDeterministicScanResult
    ]
    auditor_factory: Callable[[EvidenceGraph], AuditorInvoker]
    investigation_budget: InvestigationBudget
    context_factory: NotRequired[Callable[[EvidenceGraph], ReadOnlyEvidenceContext] | None]
    deterministic_execution: NotRequired[ProductDeterministicExecution | None]


def _retained_artifact(record: Evidence, retained: dict[str, bytes]) -> bytes:
    assert record.artifact_ref is not None
    return retained[record.artifact_ref.content_id]


class Objects:
    def __init__(self) -> None:
        self.contents: dict[tuple[str, str], bytes] = {}

    def add(self, kind: str, content: bytes) -> str:
        oid = hashlib.sha1(
            f"{kind} {len(content)}\0".encode() + content, usedforsecurity=False
        ).hexdigest()
        self.contents[kind, oid] = content
        return oid

    def read(self, kind: str, oid: str, *, max_bytes: int) -> bytes:
        del max_bytes
        return self.contents[kind, oid]


class StateProbe:
    def observe(
        self,
        *,
        run_id: str,
        execution_identity: RunExecutionIdentity,
    ) -> ProductAuditStateObservation:
        return ProductAuditStateObservation(
            run_id,
            execution_identity.execution_identity_hash,
            execution_identity.repository_revision.head_sha,
            False,
            False,
        )


def execute(
    *,
    manifest: bool = False,
    source: bytes = b"answer = 42\n",
    extra: dict[str, bytes] | None = None,
    scanner: ApprovedOsvScanner | None = None,
    path: str = "a.py",
) -> ProductDeterministicExecution:
    reader = Objects()
    entries = {path: source}
    entries.update(extra or {})
    if manifest:
        entries["requirements.txt"] = b"requests==2.19.0\n"
    tree = reader.add(
        "tree",
        b"".join(
            b"100644 " + name.encode() + b"\0" + bytes.fromhex(reader.add("blob", source))
            for name, source in sorted(entries.items())
        ),
    )
    head = reader.add("commit", f"tree {tree}\n\nfixture".encode())
    return execute_deterministic_children(
        reader=reader,
        head_sha=head,
        tenant_id="tenant-public",
        repository_id="repo-fixture",
        content_key=b"c" * 32,
        fingerprint_key=SecretFingerprintKey("fixture", b"k" * 32),
        scanner=scanner,
    )


def test_python_without_manifest_executes_all_selected_children() -> None:
    result = execute()
    assert result.selected_child_ids == ("python_parse_symbols", "secret_scan", "cwe89_scan")
    assert result.is_complete
    assert result.secrets is not None
    assert result.secrets.results
    assert result.scan.receipts
    assert not result.scan.graph.candidates


def test_missing_dependency_port_blocks_composite_but_retains_successful_facts() -> None:
    result = execute(manifest=True)
    assert "dependency_scan" in result.selected_child_ids
    assert not result.is_complete
    assert "PRODUCT_DEPENDENCY_EXECUTION_FAILED" in result.obstacles
    assert result.secrets is not None
    assert result.secrets.results
    assert result.scan.receipts


def test_secret_failure_blocks_composite(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(**kwargs: object) -> None:
        raise RuntimeError("private-source-marker")

    monkeypatch.setattr("securecode_ai.adapters.product_execution.execute_secret_stage", fail)
    result = execute()
    assert not result.is_complete
    assert result.obstacles == ("PRODUCT_SECRET_EXECUTION_FAILED",)
    assert "private-source-marker" not in repr(result.obstacles)


@pytest.mark.parametrize(
    "mutation", ["missing-secret", "wrong-head", "wrong-inventory", "omit-child", "substitute-hash"]
)
def test_substituted_execution_cannot_claim_complete(mutation: str) -> None:
    from dataclasses import replace

    result = execute()
    if mutation == "missing-secret":
        changed = replace(result, secrets=None)
    elif mutation == "wrong-head":
        assert result.secrets is not None
        changed = replace(result, secrets=replace(result.secrets, head_sha="0" * 40))
    elif mutation == "wrong-inventory":
        changed = replace(result, inventory_sha256="0" * 64)
    elif mutation == "omit-child":
        changed = replace(
            result,
            selected_child_ids=result.selected_child_ids[:-1],
            child_output_hashes=result.child_output_hashes[:-1],
        )
    else:
        changed = replace(
            result,
            child_output_hashes=tuple(
                (stage, ("0" * 64,)) for stage, hashes in result.child_output_hashes
            ),
        )
    assert not changed.is_complete


def test_secret_child_fact_is_retained_and_dc4_cannot_reach_model() -> None:
    from securecode_ai.adapters.product_execution import child_fact_graph
    from securecode_ai.contracts import DataClass
    from securecode_ai.core.evidence_package import build_evidence_package

    canary = b"development-" + b"credential-example"
    execution = execute(source=b'password = "' + canary + b'"\n')
    assert execution.secrets is not None
    graph = child_fact_graph(execution, tenant_id="tenant-public")
    assert graph.candidates
    expected_candidates = sum((len(result.candidates) for result in execution.secrets.results), 0)
    assert len(graph.candidates) == expected_candidates
    # Secret facts are value-free metadata (D-114 review of de6eabe): the model
    # may learn that a credential exists at a location, never its value.
    assert all(r.data_class is DataClass.INTERNAL_METADATA for r in graph.evidence)
    assert canary.decode() not in repr(graph)
    package = build_evidence_package(graph, graph.candidates[0].candidate_id)
    assert canary.decode() not in repr(package)


def test_union_preserves_restricted_child_candidate_lineage() -> None:
    from securecode_ai.adapters.product_execution import child_fact_graph, execution_fact_graph

    canary = b"development-" + b"credential-example"
    execution = execute(source=b'password = "' + canary + b'"\n')
    child = child_fact_graph(execution, tenant_id="tenant-public")
    union = execution_fact_graph(execution, tenant_id="tenant-public")
    assert {c.candidate_id for c in child.candidates} <= {c.candidate_id for c in union.candidates}
    assert {e.evidence_id for e in child.evidence} <= {e.evidence_id for e in union.evidence}
    assert len(union.candidates) == len(child.candidates) + len(execution.scan.graph.candidates)
    assert canary.decode() not in repr(union)


def test_actual_guarded_discovery_accounts_for_restricted_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securecode_ai.adapters import product_scan
    from securecode_ai.adapters.product_scan import ProductCandidatePreparationFailure
    from securecode_ai.contracts import AuditRunOutcome, ModelCallStatus

    from tests.unit import test_product_audit
    from tests.unit.test_native_sources import repository

    canary = b"development-" + b"credential-example"
    source = b'password = "' + canary + b'"\nexecute(value)\n'
    captured: list[ProductCandidateFlow | ProductCompositionFailure] = []
    original = product_scan.run_product_candidate_flow

    class Captured(Exception):
        pass

    def run(**kwargs: Unpack[_FlowKwargs]) -> ProductCandidateFlow | ProductCompositionFailure:
        catalogue = kwargs["catalogue"]
        reader, head, _ = repository("a.py", source)
        execution = execute_deterministic_children(
            reader=reader,
            head_sha=head,
            tenant_id=kwargs["model_plan"].request.tenant_id,
            repository_id="repo-a",
            content_key=b"p" * 32,
            fingerprint_key=SecretFingerprintKey("fixture", b"k" * 32),
            scanner=None,
        )
        assert catalogue.snapshot == execution.catalogue.snapshot
        flow = original(
            catalogue=kwargs["catalogue"],
            model_plan=kwargs["model_plan"],
            model_backend=kwargs["model_backend"],
            deterministic_scanner=kwargs["deterministic_scanner"],
            auditor_factory=kwargs["auditor_factory"],
            investigation_budget=kwargs["investigation_budget"],
            context_factory=kwargs.get("context_factory"),
            deterministic_execution=execution,
        )
        captured.append(flow)
        raise Captured

    monkeypatch.setattr(test_product_audit, "run_product_candidate_flow", run)
    with pytest.raises(Captured):
        test_product_audit._actual_flow(monkeypatch, source=source)
    flow = captured[0]
    assert isinstance(flow, ProductCandidateFlow)
    assert flow.discovery.receipt.model_call_status is ModelCallStatus.GUARDRAIL_BLOCKED
    assert len(flow.graph.candidates) == len(flow.investigations)
    assert not any(
        type(receipt) is ProductCandidatePreparationFailure for receipt in flow.investigations
    )
    assert canary.decode() not in repr(flow)
    assert flow.required_terminal_outcome is AuditRunOutcome.INDETERMINATE


def test_dc4_child_admission_denies_raw_source_and_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securecode_ai.adapters.product_execution import child_fact_catalogue, execution_fact_graph
    from securecode_ai.adapters.product_scanner import build_product_auditor_tools
    from securecode_ai.core.tool_policy import (
        ReadEvidenceArguments,
        ReadRangeArguments,
        RepositoryTool,
        RepositoryToolBudget,
        RepositoryToolRequest,
        ToolOutcome,
    )

    canary = b"development-" + b"credential-example"
    execution = execute(source=b'password = "' + canary + b'"\n')
    child = child_fact_catalogue(execution, tenant_id="tenant-public")
    retained = dict(child.artifacts)
    graph = execution_fact_graph(execution, tenant_id="tenant-public")
    tools = build_product_auditor_tools(
        execution.catalogue,
        graph,
        budget=RepositoryToolBudget(16, 65536, 65536),
        deterministic=execution.scan,
        child_artifacts=tuple(
            (record, _retained_artifact(record, retained)) for record in child.graph.evidence
        ),
    )
    head = execution.catalogue.snapshot.head_sha
    # The file holding the secret is never readable raw by model tools ...
    raw = tools.dispatch(
        RepositoryToolRequest(
            RepositoryTool.READ_RANGE, ReadRangeArguments("0.1.0", head, "a.py", 1, 1)
        )
    )
    assert raw.output is None
    assert raw.receipt.outcome is ToolOutcome.NON_SUCCESS
    # ... while the value-free secret fact stays readable for the Auditor.
    fact = tools.dispatch(
        RepositoryToolRequest(
            RepositoryTool.READ_EVIDENCE,
            ReadEvidenceArguments("0.1.0", head, graph.evidence[0].evidence_id),
        )
    )
    assert fact.output is not None
    assert '"rule_id":"secret-' in fact.output.content
    assert canary.decode() not in fact.output.content
    assert canary.decode() not in repr(child)


def test_tampered_child_payload_not_admitted() -> None:
    from securecode_ai.adapters.product_execution import child_fact_catalogue, execution_fact_graph
    from securecode_ai.adapters.product_scanner import build_product_auditor_tools
    from securecode_ai.core.tool_policy import RepositoryToolBudget

    execution = execute(source=b'password = "development-credential-example"\n')
    child = child_fact_catalogue(execution, tenant_id="tenant-public")
    graph = execution_fact_graph(execution, tenant_id="tenant-public")
    with pytest.raises(ValueError, match="Auditor child artifact is invalid"):
        build_product_auditor_tools(
            execution.catalogue,
            graph,
            budget=RepositoryToolBudget(16, 65536, 65536),
            deterministic=execution.scan,
            child_artifacts=((child.graph.evidence[0], b"private-source-marker"),),
        )


def test_restricted_child_does_not_disable_other_file_reads() -> None:
    from securecode_ai.adapters.product_execution import child_fact_catalogue, execution_fact_graph
    from securecode_ai.adapters.product_scanner import build_product_auditor_tools
    from securecode_ai.core.tool_policy import (
        ReadRangeArguments,
        RepositoryTool,
        RepositoryToolBudget,
        RepositoryToolRequest,
        ToolOutcome,
    )

    safe_source = b'def get_user(request, db):\n user_id = request.args.get("user_id")\n return db.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
    execution = execute(
        source=b'password = "' + b"development-" + b"credential-example" + b'"\n',
        extra={"b.py": safe_source},
    )
    child = child_fact_catalogue(execution, tenant_id="tenant-public")
    retained = dict(child.artifacts)
    graph = execution_fact_graph(execution, tenant_id="tenant-public")
    tools = build_product_auditor_tools(
        execution.catalogue,
        graph,
        budget=RepositoryToolBudget(16, 65536, 65536),
        deterministic=execution.scan,
        child_artifacts=tuple(
            (record, _retained_artifact(record, retained)) for record in child.graph.evidence
        ),
    )
    request = RepositoryToolRequest(
        RepositoryTool.READ_RANGE,
        ReadRangeArguments("0.1.0", execution.catalogue.snapshot.head_sha, "b.py", 1, 1),
    )
    result = tools.dispatch(request)
    assert result.receipt.outcome is ToolOutcome.SUCCEEDED
    assert result.output is not None


@pytest.mark.parametrize("invalid_inventory", [False, True])
def test_actual_audit_uses_bound_intake_and_language_observations(
    monkeypatch: pytest.MonkeyPatch, invalid_inventory: bool
) -> None:
    from dataclasses import replace

    from securecode_ai.adapters.product_audit import ProductAuditComposition, compose_product_audit
    from securecode_ai.contracts import CoverageStatus

    from tests.unit.test_native_sources import repository
    from tests.unit.test_product_audit import _actual_flow

    source = b'def get_user(request, db):\n user_id = request.args.get("user_id")\n return db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()\n'
    flow, review, host, _, _ = _actual_flow(monkeypatch, hybrid=True, source=source)
    reader, head, _ = repository("a.py", source)
    execution = execute_deterministic_children(
        reader=reader,
        head_sha=head,
        tenant_id=flow.graph.tenant_id,
        repository_id="repo-a",
        content_key=b"p" * 32,
        fingerprint_key=SecretFingerprintKey("fixture", b"k" * 32),
        scanner=None,
    )
    if invalid_inventory:
        execution = replace(execution, inventory_sha256="0" * 64)
    result = compose_product_audit(
        flow,
        review,
        host=replace(
            host,
            deterministic_execution=execution,
            deterministic_scan=execution.scan,
            state_probe=StateProbe(),
        ),
    )
    assert type(result) is ProductAuditComposition
    units = {unit.stage_id: unit for unit in result.run.coverage_manifest.units}
    expected = CoverageStatus.SKIPPED if invalid_inventory else CoverageStatus.COMPLETED
    assert units["intake"].coverage_status is expected
    assert units["language_discovery"].coverage_status is expected
    assert units["deterministic_analysis"].coverage_status is expected
    for stage in ("python_parse_symbols", "secret_scan", "cwe89_scan"):
        assert units[stage].coverage_status is expected
        assert not units[stage].required
        assert units[stage].coverage_unit_id not in result.run.coverage_manifest.required_unit_ids
    assert result.run.audit_outcome.value == "FAIL"
    assert units["reporting"].coverage_status is CoverageStatus.COMPLETED
    assert units["coverage_guard"].coverage_status is CoverageStatus.COMPLETED
    assert result.preliminary_json_report is not None
    assert result.preliminary_html_report is not None
    assert units["reporting"].output_hashes == (
        hashlib.sha256(result.preliminary_json_report).hexdigest(),
        hashlib.sha256(result.preliminary_html_report).hexdigest(),
    )
    assert result.json_report != result.preliminary_json_report
    assert hashlib.sha256(result.json_report).hexdigest() not in units["reporting"].output_hashes


@pytest.mark.parametrize("fail_at", [1, 3])
def test_preliminary_or_final_render_failure_returns_closed_obstacle(
    monkeypatch: pytest.MonkeyPatch, fail_at: int
) -> None:
    from dataclasses import replace

    from securecode_ai.adapters import product_audit
    from securecode_ai.core.reports import DeterministicReport, ReportFormat, render_report

    from tests.unit.test_native_sources import repository
    from tests.unit.test_product_audit import _actual_flow

    source = b'def get_user(request, db):\n user_id = request.args.get("user_id")\n return db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()\n'
    flow, review, host, _, _ = _actual_flow(monkeypatch, hybrid=True, source=source)
    reader, head, _ = repository("a.py", source)
    execution = execute_deterministic_children(
        reader=reader,
        head_sha=head,
        tenant_id=flow.graph.tenant_id,
        repository_id="repo-a",
        content_key=b"p" * 32,
        fingerprint_key=SecretFingerprintKey("fixture", b"k" * 32),
        scanner=None,
    )
    render = render_report
    calls: list[ReportFormat] = []

    def failing_render(report: DeterministicReport, format: ReportFormat) -> bytes:
        calls.append(format)
        if len(calls) == fail_at:
            raise OSError("private-source-marker")
        return render(report, format)

    monkeypatch.setattr(product_audit, "render_report", failing_render)
    result = product_audit.compose_product_audit(
        flow,
        review,
        host=replace(
            host,
            deterministic_execution=execution,
            deterministic_scan=execution.scan,
            state_probe=StateProbe(),
        ),
    )
    assert type(result) is product_audit.ProductAuditObstacle
    assert "private-source-marker" not in repr(result)
    assert len(calls) == fail_at


@pytest.mark.parametrize(
    "kind,change_at", [("missing", 0), ("stale", 1), ("cancelled", 3), ("stale", 4)]
)
def test_host_state_failure_at_output_boundaries_returns_no_composition(
    monkeypatch: pytest.MonkeyPatch, kind: str, change_at: int
) -> None:
    from dataclasses import replace

    from securecode_ai.adapters.product_audit import (
        ProductAuditObstacle,
        ProductAuditStateObservation,
        compose_product_audit,
    )

    from tests.unit.test_native_sources import repository
    from tests.unit.test_product_audit import _actual_flow

    source = b"answer = 42\n"
    flow, review, host, _, _ = _actual_flow(monkeypatch, count=0, source=source)
    reader, head, _ = repository("a.py", source)
    execution = execute_deterministic_children(
        reader=reader,
        head_sha=head,
        tenant_id=flow.graph.tenant_id,
        repository_id="repo-a",
        content_key=b"p" * 32,
        fingerprint_key=SecretFingerprintKey("fixture", b"k" * 32),
        scanner=None,
    )

    class ChangingState:
        def __init__(self) -> None:
            self.calls = 0

        def observe(
            self,
            *,
            run_id: str,
            execution_identity: RunExecutionIdentity,
        ) -> ProductAuditStateObservation:
            self.calls += 1
            changed = self.calls >= change_at
            return ProductAuditStateObservation(
                run_id,
                execution_identity.execution_identity_hash,
                "0" * 40 if changed and kind == "stale" else head,
                changed and kind == "cancelled",
                True,
            )

    probe = ChangingState()
    result = compose_product_audit(
        flow,
        review,
        host=replace(
            host,
            deterministic_execution=execution,
            deterministic_scan=execution.scan,
            state_probe=None if kind == "missing" else probe,
        ),
    )
    assert type(result) is ProductAuditObstacle
    assert (
        result.code
        == {
            "missing": "PRODUCT_AUDIT_STATE_UNAVAILABLE",
            "stale": "PRODUCT_AUDIT_SUPERSEDED",
            "cancelled": "PRODUCT_AUDIT_CANCELLED",
        }[kind]
    )
    if kind != "missing":
        assert probe.calls == change_at


def test_git_host_probe_reads_actual_head_and_runtime_cancellation() -> None:
    import shutil
    import subprocess
    from pathlib import Path

    from securecode_ai.adapters.product_audit import GitProductAuditStateProbe
    from securecode_ai.adapters.runtime import LocalWorkflowRuntime

    from tests.unit.test_workflow_runtime import _cancel_request, _identity, _read_snapshot, _start

    root = Path(__file__).resolve().parents[2]
    executable_text = shutil.which("git")
    assert executable_text is not None
    executable = Path(executable_text)
    runtime = LocalWorkflowRuntime()
    identity = _identity()
    initial = _start(runtime, identity).snapshot
    assert initial is not None
    latest = [initial]

    def snapshot_for(
        run_id: str,
        expected_identity: RunExecutionIdentity,
    ) -> WorkflowSnapshot:
        result = _read_snapshot(runtime, latest[0], request_id="product-state-read")
        snapshot = result.snapshot
        assert snapshot is not None
        assert snapshot.run_id == run_id
        assert snapshot.execution_identity == expected_identity
        return snapshot

    probe = GitProductAuditStateProbe(
        checkout=root,
        git_executable=executable,
        snapshot_for=snapshot_for,
        reporting_policy=lambda snapshot: False,
    )
    observed = probe.observe(run_id="run", execution_identity=identity)
    actual = (
        subprocess.check_output([str(executable), "-C", str(root), "rev-parse", "HEAD"])
        .decode()
        .strip()
    )
    assert observed.current_head_sha == actual
    assert observed.current_head_sha != identity.repository_revision.head_sha
    assert not observed.cancelled
    assert not observed.reporting_allowed
    cancelled = runtime.cancel(_cancel_request(latest[0])).snapshot
    assert cancelled is not None
    latest[0] = cancelled
    assert probe.observe(run_id="run", execution_identity=identity).cancelled


def test_git_host_probe_closes_invalid_worker_snapshot_and_policy() -> None:
    import shutil
    from pathlib import Path

    from securecode_ai.adapters.product_audit import GitProductAuditStateProbe
    from securecode_ai.adapters.runtime import LocalWorkflowRuntime

    from tests.unit.test_workflow_runtime import _identity, _start

    root = Path(__file__).resolve().parents[2]
    executable_text = shutil.which("git")
    assert executable_text is not None
    executable = Path(executable_text)
    identity = _identity()
    snapshot = _start(LocalWorkflowRuntime(), identity).snapshot
    assert snapshot is not None

    def invalid_snapshot(
        run_id: str,
        execution_identity: RunExecutionIdentity,
    ) -> WorkflowSnapshot:
        del run_id, execution_identity
        return object.__new__(WorkflowSnapshot)

    def invalid_policy(value: WorkflowSnapshot) -> bool:
        del value
        raise TypeError("invalid reporting policy")

    def valid_snapshot(
        run_id: str,
        execution_identity: RunExecutionIdentity,
    ) -> WorkflowSnapshot:
        del run_id, execution_identity
        return snapshot

    cases: tuple[
        tuple[
            Callable[[str, RunExecutionIdentity], WorkflowSnapshot],
            Callable[[WorkflowSnapshot], bool],
        ],
        ...,
    ] = (
        (invalid_snapshot, lambda value: True),
        (valid_snapshot, invalid_policy),
    )
    for reader, policy in cases:
        probe = GitProductAuditStateProbe(
            checkout=root, git_executable=executable, snapshot_for=reader, reporting_policy=policy
        )
        with pytest.raises(ValueError, match="PRODUCT_HOST_STATE_READ_FAILED"):
            probe.observe(run_id="run", execution_identity=identity)


def test_unified_execution_runs_real_safe_pipeline_to_reports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    from securecode_ai.adapters import product_scan
    from securecode_ai.adapters.product_audit import ProductAuditComposition, execute_product_audit
    from securecode_ai.adapters.product_review import run_product_candidate_review
    from securecode_ai.contracts import CoverageStatus
    from securecode_ai.core.classification import FindingSeverity

    from tests.unit import test_product_audit
    from tests.unit.test_native_sources import repository

    source = b"answer = 42\n"
    captured: list[_FlowKwargs] = []
    original = product_scan.run_product_candidate_flow

    def capture(**kwargs: Unpack[_FlowKwargs]) -> ProductCandidateFlow | ProductCompositionFailure:
        captured.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(test_product_audit, "run_product_candidate_flow", capture)
    _flow, _review, host, _endpoint, _ = test_product_audit._actual_flow(
        monkeypatch, count=0, source=source
    )

    class Prepared(Exception):
        pass

    def capture_fresh(**kwargs: Unpack[_FlowKwargs]) -> None:
        captured.append(kwargs)
        raise Prepared

    monkeypatch.setattr(test_product_audit, "run_product_candidate_flow", capture_fresh)
    with pytest.raises(Prepared):
        test_product_audit._actual_flow(monkeypatch, count=0, source=source)
    kwargs = captured[-1]
    reader, _, _ = repository("a.py", source)
    observed_flows: list[ProductCandidateFlow] = []

    def finalize(
        flow: ProductCandidateFlow,
        review: ProductReviewResult,
        bound: ProductAuditHostInputs,
    ) -> ProductAuditHostInputs:
        del review
        observed_flows.append(flow)
        return bound

    result = execute_product_audit(
        reader=reader,
        host=replace(host, state_probe=StateProbe()),
        content_key=b"p" * 32,
        fingerprint_key=SecretFingerprintKey("fixture", b"k" * 32),
        dependency_scanner=None,
        model_plan=kwargs["model_plan"],
        model_backend=kwargs["model_backend"],
        auditor_factory=lambda graph, tools: kwargs["auditor_factory"](graph),
        review_factory=lambda flow, tools: run_product_candidate_review(
            flow,
            auditor_identity_for=lambda candidate, receipt: "auditor",
            severity_for=lambda candidate: FindingSeverity.HIGH,
            skeptic=object(),
        ),
        finalize_host=finalize,
        investigation_budget=kwargs["investigation_budget"],
        tool_budget=kwargs["model_plan"].tool_budget,
    )
    assert type(result) is ProductAuditComposition
    assert result.preliminary_json_report
    assert result.json_report
    assert result.run.audit_outcome.value == "INDETERMINATE"
    assert result.run.coverage_manifest.coverage_complete, (
        observed_flows[0].discovery.receipt.model_call_status,
        observed_flows[0].discovery.tool_receipts,
        [
            (u.stage_id, u.coverage_status.value, u.reason_code)
            for u in result.run.coverage_manifest.units
            if u.coverage_status is not CoverageStatus.COMPLETED
        ],
    )
    assert all(
        unit.coverage_status is CoverageStatus.COMPLETED
        for unit in result.run.coverage_manifest.units
    )


def test_advisory_evidence_reads_only_retained_metadata() -> None:
    import json

    from securecode_ai.adapters.dependency_scanning import (
        OsvAdvisoryRecord,
        OsvBatchRequest,
        OsvBatchResponse,
        OsvPackageResult,
    )
    from securecode_ai.adapters.product_execution import child_fact_catalogue, execution_fact_graph
    from securecode_ai.adapters.product_scanner import build_product_auditor_tools
    from securecode_ai.core.evidence_package import build_evidence_package
    from securecode_ai.core.tool_policy import (
        ReadEvidenceArguments,
        ReadRangeArguments,
        RepositoryTool,
        RepositoryToolBudget,
        RepositoryToolRequest,
        ToolOutcome,
    )

    class Osv:
        scanner_id = "osv.dev"
        scanner_version = "v1"

        def query_batch(self, request: OsvBatchRequest) -> OsvBatchResponse:
            return OsvBatchResponse(
                tuple(
                    OsvPackageResult(purl, (OsvAdvisoryRecord("GHSA-FIXTURE-TEST", ()),))
                    for purl in request.purls
                )
            )

    execution = execute(manifest=True, scanner=Osv())
    assert execution.is_complete
    child = child_fact_catalogue(execution, tenant_id="tenant-public")
    retained = dict(child.artifacts)
    record = child.graph.evidence[0]
    payload = _retained_artifact(record, retained)
    assert json.loads(payload)["detail"]["advisory_id"] == "GHSA-FIXTURE-TEST"
    assert json.loads(payload)["detail"]["purl"] == "pkg:pypi/requests@2.19.0"
    graph = execution_fact_graph(execution, tenant_id="tenant-public")
    package = build_evidence_package(graph, graph.candidates[0].candidate_id)
    assert package
    tools = build_product_auditor_tools(
        execution.catalogue,
        graph,
        budget=RepositoryToolBudget(16, 65536, 65536),
        deterministic=execution.scan,
        child_artifacts=((record, payload),),
    )
    head = execution.catalogue.snapshot.head_sha
    result = tools.dispatch(
        RepositoryToolRequest(
            RepositoryTool.READ_EVIDENCE, ReadEvidenceArguments("0.1.0", head, record.evidence_id)
        )
    )
    assert result.receipt.outcome is ToolOutcome.SUCCEEDED
    assert result.output is not None
    denied = tools.dispatch(
        RepositoryToolRequest(
            RepositoryTool.READ_RANGE, ReadRangeArguments("0.1.0", head, "requirements.txt", 1, 1)
        )
    )
    assert denied.output is None
    assert denied.receipt.outcome is ToolOutcome.NON_SUCCESS


@pytest.mark.parametrize("cwe", ["CWE-89", "CWE-918"])
def test_unified_vulnerable_path_has_guarded_auditor_skeptic_and_fail(
    monkeypatch: pytest.MonkeyPatch, cwe: str
) -> None:
    import json
    from dataclasses import replace

    from securecode_ai.adapters.product_audit import ProductAuditComposition, execute_product_audit
    from securecode_ai.adapters.product_review import run_product_candidate_review
    from securecode_ai.adapters.product_runtime import (
        GuardedEvidenceResolver,
        ProductAuditorInvoker,
    )
    from securecode_ai.adapters.product_skeptic import (
        PRODUCT_SKEPTIC_PROMPT_PIN,
        ProductSkepticReviewPort,
    )
    from securecode_ai.contracts import (
        CandidateOrigin,
        ComponentPin,
        ModelCallStatus,
        ModelPurpose,
        ModelRequest,
        ModelRole,
    )
    from securecode_ai.core.classification import FindingSeverity
    from securecode_ai.core.evidence_package import EvidencePackage, build_evidence_package
    from securecode_ai.core.model_discovery import RepositoryToolSession
    from securecode_ai.core.skeptic import AuditorSnapshot

    from tests.unit import test_product_audit
    from tests.unit.test_native_sources import repository
    from tests.unit.test_openai_compatible_local import _LocalEndpoint

    source = b'def get_user(request, db):\n user_id = request.args.get("user_id")\n return db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()\n'
    if cwe == "CWE-918":
        source = b"import requests\ndef check(request):\n requests.get(request.args.get('url'))\n"
    _flow, _review, host, _endpoint, _ = test_product_audit._actual_flow(
        monkeypatch, hybrid=True, ssrf=cwe == "CWE-918", source=source
    )
    prepared: list[_FlowKwargs] = []
    endpoints: list[_LocalEndpoint] = []
    install = _LocalEndpoint.install

    def install_capture(endpoint: _LocalEndpoint, patcher: pytest.MonkeyPatch) -> None:
        endpoints.append(endpoint)
        install(endpoint, patcher)

    monkeypatch.setattr(_LocalEndpoint, "install", install_capture)

    class Prepared(Exception):
        pass

    def capture(**kwargs: Unpack[_FlowKwargs]) -> None:
        prepared.append(kwargs)
        raise Prepared

    monkeypatch.setattr(test_product_audit, "run_product_candidate_flow", capture)
    with pytest.raises(Prepared):
        test_product_audit._actual_flow(
            monkeypatch, hybrid=True, ssrf=cwe == "CWE-918", source=source
        )
    kwargs = prepared[0]
    endpoint = endpoints[-1]
    invokers: list[ProductAuditorInvoker] = []
    observations: list[ProductAuditorInvocationObservation] = []

    def auditor_factory(
        graph: EvidenceGraph,
        tools: RepositoryToolSession,
    ) -> AuditorInvoker:
        template = kwargs["auditor_factory"](graph)
        assert isinstance(template, ProductAuditorInvoker)
        invoker = ProductAuditorInvoker(
            executor=template._executor,
            resolver=GuardedEvidenceResolver(tools=tools, evidence=graph.evidence),
            evidence_catalogue=graph.evidence,
            content_key=b"a" * 32,
            request_factory=template._request_factory,
            observer=observations.append,
        )
        invokers.append(invoker)
        return invoker

    def review_factory(
        flow: ProductCandidateFlow,
        tools: RepositoryToolSession,
    ) -> ProductReviewResult:
        invoker = invokers[0]

        def request_factory(
            snapshot: AuditorSnapshot,
            package: EvidencePackage,
            attempt: int,
            pin: ComponentPin,
        ) -> ModelRequest:
            base = invoker._request_factory(package, attempt, pin)
            values = base.model_dump(mode="json")
            identifier = "skeptic-" + package.candidate_id + "-" + str(attempt)
            values.update(
                request_id=identifier,
                idempotency_key=identifier,
                role=ModelRole.SKEPTIC.value,
                mode=ModelPurpose.SKEPTIC_REVIEW.value,
                prompt=PRODUCT_SKEPTIC_PROMPT_PIN.model_dump(mode="json"),
            )
            test_product_audit._reply(endpoint, {"finding_verdict": "CONFIRMED", "objections": []})
            return ModelRequest.model_validate_json(json.dumps(values))

        skeptic = ProductSkepticReviewPort(
            executor=invoker._executor,
            resolver=GuardedEvidenceResolver(tools=tools, evidence=flow.graph.evidence),
            evidence_catalogue=flow.graph.evidence,
            content_key=b"s" * 32,
            skeptic_identity="skeptic-product-audit",
            tenant_id=flow.graph.tenant_id,
            package_for=lambda snapshot: build_evidence_package(flow.graph, snapshot.candidate_id),
            request_factory=request_factory,
        )
        return run_product_candidate_review(
            flow,
            auditor_identity_for=lambda candidate, receipt: "auditor-product-audit",
            severity_for=lambda candidate: FindingSeverity.HIGH,
            skeptic=skeptic,
        )

    reader, _, _ = repository("a.py", source)
    result = execute_product_audit(
        reader=reader,
        host=replace(host, state_probe=StateProbe()),
        content_key=b"p" * 32,
        fingerprint_key=SecretFingerprintKey("fixture", b"k" * 32),
        dependency_scanner=None,
        model_plan=kwargs["model_plan"],
        model_backend=kwargs["model_backend"],
        auditor_factory=auditor_factory,
        review_factory=review_factory,
        finalize_host=lambda flow, review, bound: replace(
            bound, auditor_observations=tuple(observations)
        ),
        investigation_budget=kwargs["investigation_budget"],
        tool_budget=kwargs["model_plan"].tool_budget,
    )
    assert type(result) is ProductAuditComposition
    assert result.run.audit_outcome.value == "FAIL"
    assert result.report.findings[0].classification.cwe_id == cwe
    assert result.run.coverage_manifest.coverage_complete
    assert result.report.findings[0].finding.candidate_origin is CandidateOrigin.HYBRID
    assert all(
        receipt.model_call_status is ModelCallStatus.SUCCEEDED
        for receipt in result.run.coverage_manifest.candidate_interpretation_receipts
    )
    assert len(endpoint.requests) == 3
    assert result.preliminary_json_report != result.json_report


@pytest.mark.parametrize("mutation", ["drop", "duplicate", "wrong-request", "wrong-producer"])
def test_zero_signal_receipt_substitution_blocks_completion(mutation: str) -> None:
    from dataclasses import replace

    from securecode_ai.contracts import ProducerRef
    from securecode_ai.core.scanning import ScannerIdentity

    execution = execute(extra={"b.py": b"other = 42\n"})
    assert execution.is_complete
    receipts = execution.scan.receipts
    if mutation == "drop":
        changed = receipts[:-1]
    elif mutation == "duplicate":
        changed = (receipts[0], receipts[0])
    elif mutation == "wrong-request":
        changed = (replace(receipts[0], request_id="foreign-request"), receipts[1])
    else:
        producer = ProducerRef(
            schema_version="0.2.0",
            producer_id="foreign-scanner",
            producer_version="1.0.0",
            producer_sha256="0" * 64,
        )
        changed = (replace(receipts[0], scanner=ScannerIdentity(producer)), receipts[1])
    assert not replace(execution, scan=replace(execution.scan, receipts=changed)).is_complete


@pytest.mark.parametrize(
    "field,value",
    [
        ("head_sha", "0" * 40),
        ("content_sha256", "0" * 64),
        ("tenant_id", "foreign"),
        ("size_bytes", 0),
    ],
)
def test_source_binding_mutations_cannot_complete(field: str, value: str | int) -> None:
    from dataclasses import replace

    execution = execute()
    bindings = execution.scan.source_bindings
    if field == "head_sha":
        assert isinstance(value, str)
        changed = replace(bindings[0], head_sha=value)
    elif field == "content_sha256":
        assert isinstance(value, str)
        changed = replace(bindings[0], content_sha256=value)
    elif field == "tenant_id":
        assert isinstance(value, str)
        changed = replace(bindings[0], tenant_id=value)
    else:
        assert isinstance(value, int)
        changed = replace(bindings[0], size_bytes=value)
    assert not replace(
        execution, scan=replace(execution.scan, source_bindings=(changed,))
    ).is_complete


@pytest.mark.parametrize("operation", ["repair", "propose", "fix"])
def test_scan_executor_does_not_accept_repair_operation(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    from dataclasses import replace

    from securecode_ai.adapters.product_audit import (
        ProductAuditObstacle,
        compose_product_audit,
        execute_product_audit,
    )

    from tests.unit import test_product_audit
    from tests.unit.test_native_sources import repository

    captured: list[_FlowKwargs] = []

    class Captured(Exception):
        pass

    def capture(**kwargs: Unpack[_FlowKwargs]) -> None:
        captured.append(kwargs)
        raise Captured

    monkeypatch.setattr(test_product_audit, "run_product_candidate_flow", capture)
    with pytest.raises(Captured):
        test_product_audit._actual_flow(monkeypatch, count=0, source=b"answer = 42\n")
    kwargs = captured[0]
    monkeypatch.undo()
    flow, review, host, _, _ = test_product_audit._actual_flow(
        monkeypatch, count=0, source=b"answer = 42\n"
    )
    host = replace(host, operation=operation)
    composition = compose_product_audit(flow, review, host=host)
    assert type(composition) is ProductAuditObstacle
    # "repair" is a real operation, so without repair receipts it fails on its
    # inputs; unknown operations fail as unsupported. Neither is accepted.
    expected = (
        "PRODUCT_REPAIR_INPUT_INVALID" if operation == "repair" else "PRODUCT_OPERATION_UNSUPPORTED"
    )
    assert composition.code == expected
    reader, _, _ = repository("a.py", b"answer = 42\n")
    result = execute_product_audit(
        reader=reader,
        host=host,
        content_key=b"p" * 32,
        fingerprint_key=SecretFingerprintKey("fixture", b"k" * 32),
        dependency_scanner=None,
        model_plan=kwargs["model_plan"],
        model_backend=kwargs["model_backend"],
        auditor_factory=lambda graph, tools: kwargs["auditor_factory"](graph),
        review_factory=lambda candidate_flow, tools: review,
        finalize_host=lambda candidate_flow, candidate_review, bound: bound,
        investigation_budget=kwargs["investigation_budget"],
        tool_budget=kwargs["model_plan"].tool_budget,
    )
    assert type(result) is ProductAuditObstacle
    assert type(result) is ProductAuditObstacle
    if operation != "repair":
        assert result.code == expected


@pytest.mark.parametrize("mutation", ["failed", "wrong-head", "missing-result", "wrong-digest"])
def test_unverified_secret_stage_denies_discovery_auditor_and_skeptic_source(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    from dataclasses import replace

    from securecode_ai.adapters.product_execution import (
        RestrictedProductDiscoveryView,
        execution_fact_graph,
        restricted_product_source_paths,
    )
    from securecode_ai.adapters.product_scanner import build_product_auditor_tools
    from securecode_ai.core.tool_policy import (
        ReadEvidenceArguments,
        ReadRangeArguments,
        RepositoryTool,
        RepositoryToolBudget,
        RepositoryToolRequest,
        RepositoryToolWindow,
        ToolOutcome,
    )

    canary = b"development-" + b"credential-example"
    source = (
        b'password = "'
        + canary
        + b'"\n'
        + b'def lookup(request, db):\n id = request.args.get("id")\n db.execute(f"SELECT * FROM users WHERE id = {id}")\n'
    )
    if mutation == "failed":

        def fail(**kwargs: object) -> None:
            raise RuntimeError("secret stage unavailable")

        monkeypatch.setattr("securecode_ai.adapters.product_execution.execute_secret_stage", fail)
    execution = execute(source=source)
    if mutation == "wrong-head":
        assert execution.secrets is not None
        execution = replace(execution, secrets=replace(execution.secrets, head_sha="f" * 40))
    elif mutation == "missing-result":
        assert execution.secrets is not None
        execution = replace(execution, secrets=replace(execution.secrets, results=()))
    elif mutation == "wrong-digest":
        assert execution.secrets is not None
        execution = replace(execution, secrets=replace(execution.secrets, output_sha256="0" * 64))
    assert not execution.is_complete
    assert restricted_product_source_paths(execution) == ("a.py",)
    arguments = ReadRangeArguments("0.1.0", execution.catalogue.snapshot.head_sha, "a.py", 1, 4)
    with pytest.raises(ValueError, match="PRODUCT_DISCOVERY_RESTRICTED_SOURCE"):
        RestrictedProductDiscoveryView(execution).read_range(
            arguments, window=RepositoryToolWindow(65536, 65536)
        )
    graph = execution_fact_graph(execution, tenant_id="tenant-public")
    assert execution.scan.graph.candidates
    for role in ("auditor", "skeptic"):
        tools = build_product_auditor_tools(
            execution.catalogue,
            execution.scan.graph,
            budget=RepositoryToolBudget(16, 65536, 65536),
            deterministic=execution.scan,
            denied_source_paths=restricted_product_source_paths(execution),
        )
        for request in (
            RepositoryToolRequest(RepositoryTool.READ_RANGE, arguments),
            RepositoryToolRequest(
                RepositoryTool.READ_EVIDENCE,
                ReadEvidenceArguments(
                    "0.1.0",
                    execution.catalogue.snapshot.head_sha,
                    execution.scan.graph.evidence[0].evidence_id,
                ),
            ),
        ):
            result = tools.dispatch(request)
            assert result.receipt.outcome is ToolOutcome.NON_SUCCESS, role
            assert result.output is None
    assert graph.candidates  # Failed coverage never erases retained vulnerability facts.


def test_scanner_graph_cannot_drop_retained_receipt_signals() -> None:
    from dataclasses import replace

    source = b'def lookup(request, db):\n id = request.args.get("id")\n db.execute(f"SELECT * FROM users WHERE id = {id}")\n'
    execution = execute(source=source, extra={"b.py": source})
    assert execution.is_complete
    assert sum(len(receipt.signals) for receipt in execution.scan.receipts) == 2
    reduced_graph = replace(execution.scan.graph, candidates=(), evidence=(), edges=())
    reduced_scan = replace(execution.scan, graph=reduced_graph, source_aliases=())
    reduced_execution = replace(
        execution,
        scan=reduced_scan,
        child_output_hashes=tuple(
            (stage, (reduced_graph.graph_sha256,) if stage == "cwe89_scan" else hashes)
            for stage, hashes in execution.child_output_hashes
        ),
    )
    assert not reduced_execution.is_complete


@pytest.mark.parametrize(
    "path,source",
    [
        ("a.js", b"const answer = 42;\n"),
        ("a.ts", b"const answer: number = 42;\n"),
        ("a.go", b"package main\nfunc answer() int { return 42 }\n"),
    ],
)
def test_non_python_execution_selects_actual_secret_only_child(path: str, source: bytes) -> None:
    execution = execute(path=path, source=source)
    assert execution.is_complete
    assert execution.selected_child_ids == ("secret_scan",)
    assert execution.secrets is not None
    assert execution.secrets.results[0].path == path
    assert len(execution.scan.receipts) == 1
    assert not execution.scan.graph.candidates
