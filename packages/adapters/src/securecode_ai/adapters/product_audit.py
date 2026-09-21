"""Compose actual product-flow receipts into a conservative Core audit run.

The adapter deliberately does not fill gaps in the accepted stage catalogue.
It returns a typed obstacle when immutable upstream receipts cannot be represented
by the frozen public ``CoverageManifest`` contract.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import replace

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    AnalysisHealth,
    AuditRun,
    AuditRunOutcome,
    CoverageManifest,
    CoverageScenario,
    FindingGateState,
)
from securecode_ai.core.classification import (
    ClassificationError,
    ClassificationErrorCode,
)
from securecode_ai.core.evidence_graph import EvidenceGraph
from securecode_ai.core.investigation import (
    AuditorInvoker,
    InvestigationBudget,
)
from securecode_ai.core.model_discovery import (
    ModelNativeDiscoveryBackend,
    ModelNativeDiscoveryPlan,
    RepositoryToolSession,
)
from securecode_ai.core.reports import (
    ReportFormat,
    build_deterministic_report,
    render_report,
)
from securecode_ai.core.tool_policy import RepositoryToolBudget

from .dependency_scanning import ApprovedOsvScanner
from .git_snapshot import GitObjectReader
from .product_audit_common import (
    _completed_unit,
    _pin_key,
    _sha256,
)
from .product_audit_coverage import (
    _coverage_units,
)
from .product_audit_findings import (
    _findings,
    _gate_state,
    _unresolved_units,
)
from .product_audit_types import (
    GitProductAuditStateProbe as GitProductAuditStateProbe,
)
from .product_audit_types import (
    ProductAuditComposition,
    ProductAuditFindingMetadata,
    ProductAuditHostInputs,
    ProductAuditObstacle,
    ProductDiscoveryCandidateMapping,
    _AuditObstacle,
)
from .product_audit_types import (
    ProductAuditStateObservation as ProductAuditStateObservation,
)
from .product_audit_types import (
    ProductAuditStateProbe as ProductAuditStateProbe,
)
from .product_audit_validation import (
    _interpretations,
    _model_candidate_mismatch,
    _probe_current_state,
    _require_scan_operation,
    _validate_host,
    _validate_review,
    model_discovery_candidate_mappings,
)
from .product_execution import (
    child_fact_catalogue,
    execute_deterministic_children,
    restricted_product_source_paths,
)
from .product_review import ProductReviewResult
from .product_scan import (
    ProductCandidateFlow,
    run_product_candidate_flow,
)
from .product_scanner import build_product_auditor_tools
from .secret_detection import SecretFingerprintKey

for _product_audit_type in (
    GitProductAuditStateProbe,
    ProductAuditComposition,
    ProductAuditFindingMetadata,
    ProductAuditHostInputs,
    ProductAuditObstacle,
    ProductAuditStateObservation,
    ProductAuditStateProbe,
    ProductDiscoveryCandidateMapping,
):
    _product_audit_type.__module__ = __name__
del _product_audit_type


def compose_product_audit(
    flow: ProductCandidateFlow,
    review: ProductReviewResult,
    *,
    host: ProductAuditHostInputs,
) -> ProductAuditComposition | ProductAuditObstacle:
    """Build a conservative audit from the actual product flow and review.

    Callers cannot select the run verdict.  The Core ``AuditRun`` reducer derives
    it from verified coverage, Finding Gate decisions, and immutable execution
    identity.  A generated JSON or HTML report is deliberately not reused as a
    reporting-stage receipt, which avoids a circular manifest/report hash.
    """

    try:
        _require_scan_operation(host)
        _validate_host(flow, review, host)
        state = _probe_current_state(host) if host.deterministic_execution is not None else None
        mismatch = _model_candidate_mismatch(flow)
        if mismatch is not None:
            return mismatch
        _validate_review(flow, review)
        interpretations = _interpretations(flow, host)
        units = _coverage_units(flow, review, host, interpretations)
        scenario = (
            CoverageScenario.CLEAN_NO_CANDIDATE
            if not flow.graph.candidates
            else CoverageScenario.CONFIRMED_FINDING_WITHOUT_REPAIR
        )
        manifest = CoverageManifest(
            schema_version=CONTRACT_SCHEMA_VERSION,
            catalogue=host.execution_identity.stage_catalogue,
            execution_identity_hash=host.execution_identity.execution_identity_hash,
            scenario=scenario,
            required_unit_ids=tuple(unit.coverage_unit_id for unit in units if unit.required),
            units=tuple(units),
            discovery_candidates=flow.graph.candidates,
            model_discovery_receipts=(flow.discovery.receipt,),
            candidate_interpretation_receipts=interpretations,
            coverage_complete=False,
        )
        findings = _findings(flow, review, host, interpretations)
        blocking_ids = tuple(
            finding.finding.finding_id for finding in findings if finding.finding.blocking
        )
        health = (
            AnalysisHealth.HEALTHY
            if manifest.coverage_complete
            and not flow.required_terminal_outcome
            and all(unit.satisfies_required_coverage for unit in units)
            else AnalysisHealth.DEGRADED
        )
        gate_state = _gate_state(review)
        unresolved = _unresolved_units(units)
        run = AuditRun(
            schema_version=CONTRACT_SCHEMA_VERSION,
            run_id=host.run_id,
            execution_identity=host.execution_identity,
            current_head_sha=state.current_head_sha
            if state is not None
            else host.execution_identity.repository_revision.head_sha,
            audit_outcome=(AuditRunOutcome.FAIL if blocking_ids else AuditRunOutcome.INDETERMINATE),
            analysis_health=health,
            finding_gate_state=gate_state,
            coverage_manifest=manifest,
            finding_ids=tuple(finding.finding.finding_id for finding in findings),
            blocking_finding_ids=blocking_ids,
            unresolved_gate_ids=unresolved,
            publication_preconditions_met=False,
            cancelled=state.cancelled if state is not None else False,
            created_at=host.created_at,
            completed_at=host.completed_at,
        )
        report = build_deterministic_report(
            run, findings, tuple(sorted(host.report_tools, key=_pin_key))
        )
        preliminary_json = render_report(report, ReportFormat.JSON)
        preliminary_html = render_report(report, ReportFormat.HTML)
        if host.deterministic_execution is None:
            return ProductAuditComposition(run, report, preliminary_json, preliminary_html)
        # These are actual retained preliminary bytes, never the final report's
        # self-hash. Only successful final rendering can return a composition.
        reporting = _completed_unit(
            "reporting",
            input_hashes=(report.report_sha256,),
            output_hashes=(
                hashlib.sha256(preliminary_json).hexdigest(),
                hashlib.sha256(preliminary_html).hexdigest(),
            ),
        )
        guarded_units = [reporting if unit.stage_id == "reporting" else unit for unit in units]
        guard_input = _sha256(
            [
                unit.model_dump(mode="json")
                for unit in guarded_units
                if unit.stage_id != "coverage_guard"
            ]
        )
        guard_failures = tuple(
            unit.coverage_unit_id
            for unit in guarded_units
            if unit.stage_id != "coverage_guard"
            and unit.required
            and not unit.satisfies_required_coverage
        )
        guard_output = _sha256(
            {
                "missing_required": guard_failures,
                "model_flow_incomplete": flow.required_terminal_outcome is not None,
            }
        )
        guard = _completed_unit(
            "coverage_guard", input_hashes=(guard_input,), output_hashes=(guard_output,)
        )
        final_units = [
            guard if unit.stage_id == "coverage_guard" else unit for unit in guarded_units
        ]
        manifest_data = manifest.model_dump(mode="json")
        manifest_data["units"] = [unit.model_dump(mode="json") for unit in final_units]
        manifest_data["coverage_complete"] = all(
            unit.satisfies_required_coverage for unit in final_units if unit.required
        )
        final_manifest = CoverageManifest.model_validate_json(json.dumps(manifest_data))
        run_data = run.model_dump(mode="json")
        run_data["coverage_manifest"] = final_manifest.model_dump(mode="json")
        run_data["unresolved_gate_ids"] = list(_unresolved_units(final_units))
        run_data["analysis_health"] = (
            AnalysisHealth.HEALTHY
            if final_manifest.coverage_complete and flow.required_terminal_outcome is None
            else AnalysisHealth.DEGRADED
        ).value
        state = _probe_current_state(host)
        run_data["current_head_sha"] = state.current_head_sha
        run_data["cancelled"] = state.cancelled
        run_data["publication_preconditions_met"] = state.reporting_allowed
        if (
            not blocking_ids
            and final_manifest.coverage_complete
            and run_data["analysis_health"] == AnalysisHealth.HEALTHY.value
            and gate_state is not FindingGateState.INCONCLUSIVE
            and not run_data["unresolved_gate_ids"]
            and state.reporting_allowed
        ):
            run_data["audit_outcome"] = AuditRunOutcome.PASS.value
        final_run = AuditRun.model_validate_json(json.dumps(run_data))
        final_report = build_deterministic_report(
            final_run, findings, tuple(sorted(host.report_tools, key=_pin_key))
        )
        final_json = render_report(final_report, ReportFormat.JSON)
        if _probe_current_state(host) != state:
            raise _AuditObstacle(
                "PRODUCT_AUDIT_STATE_CHANGED", "host state changed during reporting"
            )
        final_html = render_report(final_report, ReportFormat.HTML)
        if _probe_current_state(host) != state:
            raise _AuditObstacle(
                "PRODUCT_AUDIT_STATE_CHANGED", "host state changed during reporting"
            )
        return ProductAuditComposition(
            final_run,
            final_report,
            final_json,
            final_html,
            preliminary_json,
            preliminary_html,
        )
    except _AuditObstacle as error:
        return ProductAuditObstacle(error.code, error.detail)
    except ClassificationError as error:
        if error.code is ClassificationErrorCode.UNSUPPORTED_CWE:
            return ProductAuditObstacle(
                "FINDING_CLASSIFICATION_UNSUPPORTED",
                "Core classification does not support the finding",
            )
        return ProductAuditObstacle("PRODUCT_AUDIT_INPUT_INVALID", "input bindings are invalid")
    except (AttributeError, TypeError, ValueError, RuntimeError, OSError):
        return ProductAuditObstacle("PRODUCT_AUDIT_INPUT_INVALID", "input bindings are invalid")


__all__ = [
    "ProductAuditComposition",
    "ProductAuditFindingMetadata",
    "ProductAuditHostInputs",
    "ProductAuditObstacle",
    "ProductDiscoveryCandidateMapping",
    "compose_product_audit",
    "model_discovery_candidate_mappings",
]


def execute_product_audit(
    *,
    reader: GitObjectReader,
    host: ProductAuditHostInputs,
    content_key: bytes,
    fingerprint_key: SecretFingerprintKey,
    dependency_scanner: ApprovedOsvScanner | None,
    model_plan: ModelNativeDiscoveryPlan,
    model_backend: ModelNativeDiscoveryBackend,
    auditor_factory: Callable[[EvidenceGraph, RepositoryToolSession], AuditorInvoker],
    review_factory: Callable[[ProductCandidateFlow, RepositoryToolSession], ProductReviewResult],
    finalize_host: Callable[
        [ProductCandidateFlow, ProductReviewResult, ProductAuditHostInputs], ProductAuditHostInputs
    ],
    investigation_budget: InvestigationBudget,
    tool_budget: RepositoryToolBudget,
) -> ProductAuditComposition | ProductAuditObstacle:
    """Execute immutable child scans, both lanes, review and causal reports.

    All factories and state/policy ports are installed host capabilities.
    Finalized observations remain subject to composition binding checks.
    No repository source is executed and no external artifact is published.
    """
    try:
        _require_scan_operation(host)
        _probe_current_state(host)
        request = model_plan.request
        if request.execution_identity != host.execution_identity or request.run_id != host.run_id:
            raise ValueError("product execution identity invalid")
        execution = execute_deterministic_children(
            reader=reader,
            head_sha=request.head_sha,
            tenant_id=request.tenant_id,
            repository_id=request.execution_identity.repository_revision.repository_id,
            content_key=content_key,
            fingerprint_key=fingerprint_key,
            scanner=dependency_scanner,
        )
        bound = replace(
            host,
            source_catalogue=execution.catalogue,
            deterministic_scan=execution.scan,
            deterministic_execution=execution,
        )
        children = child_fact_catalogue(execution, tenant_id=request.tenant_id)
        artifacts = dict(children.artifacts)
        retained = tuple(
            (record, artifacts[record.artifact_ref.content_id])
            for record in children.graph.evidence
            if record.artifact_ref is not None
        )
        sessions = []

        def tools_for(graph: EvidenceGraph) -> RepositoryToolSession:
            return build_product_auditor_tools(
                execution.catalogue,
                graph,
                budget=tool_budget,
                deterministic=execution.scan,
                child_artifacts=retained,
                denied_source_paths=restricted_product_source_paths(execution),
            )

        def auditor_for(graph: EvidenceGraph) -> AuditorInvoker:
            tools = tools_for(graph)
            sessions.append(tools)
            return auditor_factory(graph, tools)

        flow = run_product_candidate_flow(
            catalogue=execution.catalogue,
            model_plan=model_plan,
            model_backend=model_backend,
            deterministic_scanner=lambda catalogue: execution.scan,
            auditor_factory=auditor_for,
            investigation_budget=investigation_budget,
            deterministic_execution=execution,
        )
        if not isinstance(flow, ProductCandidateFlow):
            raise _AuditObstacle(
                "PRODUCT_EXECUTION_COMPOSITION_FAILED", "candidate union unavailable"
            )
        tools = sessions[0] if sessions else tools_for(flow.graph)
        review = review_factory(flow, tools)
        finalized = finalize_host(flow, review, bound)
        if (
            finalized.state_probe is not host.state_probe
            or finalized.execution_identity != host.execution_identity
            or finalized.run_id != host.run_id
            or finalized.operation != host.operation
            or finalized.deterministic_execution is not execution
        ):
            raise ValueError("product finalized host binding invalid")
        return compose_product_audit(flow, review, host=finalized)
    except _AuditObstacle as error:
        return ProductAuditObstacle(error.code, error.detail)
    except Exception:
        return ProductAuditObstacle("PRODUCT_EXECUTION_FAILED", "product execution failed")
