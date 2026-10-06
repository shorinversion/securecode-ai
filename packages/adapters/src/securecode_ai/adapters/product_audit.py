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
    CoverageStatus,
    CoverageUnit,
    FindingGateState,
    ModelCallStatus,
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
    ProductRepairReceipt,
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
    model_facing_execution,
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
    ProductRepairReceipt,
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
        repair_requested_candidate_ids = _validate_host(flow, review, host)
        state = _probe_current_state(host) if host.deterministic_execution is not None else None
        mismatch = _model_candidate_mismatch(flow)
        if mismatch is not None:
            return mismatch
        _validate_review(flow, review)
        interpretations = _interpretations(flow, host)
        units = _coverage_units(flow, review, host, interpretations)
        scenario = (
            CoverageScenario.REPAIR_REQUESTED
            if repair_requested_candidate_ids
            else CoverageScenario.CLEAN_NO_CANDIDATE
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
            repair_requested_candidate_ids=repair_requested_candidate_ids,
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
            return ProductAuditComposition(
                run,
                report,
                preliminary_json,
                preliminary_html,
                flow=flow,
                review=review,
                host_inputs=host,
            )
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
        final_gate_state = _gate_state(
            review,
            flow=flow,
            host=host,
            coverage_units=tuple(final_units),
        )
        run_data = run.model_dump(mode="json")
        run_data["coverage_manifest"] = final_manifest.model_dump(mode="json")
        run_data["finding_gate_state"] = final_gate_state.value
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
            and final_gate_state is not FindingGateState.INCONCLUSIVE
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
            flow,
            review,
            host,
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


def compose_product_repair_audit(
    composition: ProductAuditComposition,
    receipts: tuple[ProductRepairReceipt, ...],
) -> ProductAuditComposition | ProductAuditObstacle:
    """Bind local repair receipts to the exact product-flow audit.

    The scan flow and its Finding Gate remain immutable.  This function creates
    a second source-free composition in the ``repair`` operation, carrying the
    real root-cause, regression, Architect and validation receipts.  It never
    applies the patch and it refuses to infer a security-test completion from a
    deterministic descriptor when no independent test receipt exists.
    """

    try:
        if (
            type(composition) is not ProductAuditComposition
            or type(receipts) is not tuple
            or not receipts
            or any(type(item) is not ProductRepairReceipt for item in receipts)
            or composition.flow is None
            or composition.review is None
            or composition.host_inputs is None
        ):
            return ProductAuditObstacle(
                "PRODUCT_REPAIR_CONTEXT_UNAVAILABLE",
                "product repair context is unavailable",
            )
        host = composition.host_inputs
        if (
            host.operation != "scan"
            or host.run_id != composition.run.run_id
            or host.execution_identity != composition.run.execution_identity
            or composition.run.current_head_sha
            != composition.run.execution_identity.repository_revision.head_sha
        ):
            return ProductAuditObstacle(
                "PRODUCT_REPAIR_CONTEXT_INVALID",
                "repair context is not bound to the scan run",
            )
        finding_by_id = {
            item.finding.finding_id: item.finding for item in composition.report.findings
        }
        requested: list[str] = []
        for receipt in receipts:
            if (
                receipt.run_id != composition.run.run_id
                or receipt.execution_identity_hash
                != composition.run.execution_identity.execution_identity_hash
                or receipt.finding_id not in finding_by_id
            ):
                return ProductAuditObstacle(
                    "PRODUCT_REPAIR_RECEIPT_IDENTITY_MISMATCH",
                    "repair receipt is not bound to the scan run",
                )
            finding = finding_by_id[receipt.finding_id]
            if (
                not finding.blocking
                or finding.candidate_id != receipt.candidate_id
                or finding.candidate_version != receipt.candidate_version
                or finding.repository_revision
                != composition.run.execution_identity.repository_revision
            ):
                return ProductAuditObstacle(
                    "PRODUCT_REPAIR_RECEIPT_FINDING_MISMATCH",
                    "repair receipt does not match the confirmed finding",
                )
            requested.append(receipt.candidate_id)
        requested_ids = tuple(sorted(requested))
        if len(set(requested_ids)) != len(requested_ids):
            return ProductAuditObstacle(
                "PRODUCT_REPAIR_RECEIPT_DUPLICATE",
                "repair receipts contain duplicate candidates",
            )
        units = _product_repair_coverage_units(receipts)
        repair_host = replace(
            host,
            operation="repair",
            repair_requested_candidate_ids=requested_ids,
            repair_coverage_units=units,
        )
        result = compose_product_audit(composition.flow, composition.review, host=repair_host)
        if isinstance(result, ProductAuditComposition):
            if result.run.execution_identity != composition.run.execution_identity:
                return ProductAuditObstacle(
                    "PRODUCT_REPAIR_IDENTITY_DRIFT",
                    "repair composition changed execution identity",
                )
            return result
        return result
    except (AttributeError, TypeError, ValueError, RuntimeError, OSError):
        return ProductAuditObstacle(
            "PRODUCT_REPAIR_RECEIPT_INVALID",
            "repair receipts are invalid",
        )


def _product_repair_coverage_units(
    receipts: tuple[ProductRepairReceipt, ...],
) -> tuple[CoverageUnit, ...]:
    units: list[CoverageUnit] = []
    for receipt in sorted(receipts, key=lambda item: item.candidate_id):
        candidate_id = receipt.candidate_id
        root_hash = _sha256(
            {
                "record_id": receipt.root_cause.record_id,
                "finding_id": receipt.root_cause.finding_id,
                "head_sha": receipt.root_cause.head_sha,
                "evidence_graph_id": receipt.root_cause.evidence_graph_id,
                "evidence_graph_sha256": receipt.root_cause.evidence_graph_sha256,
                "root_cause_fingerprint": receipt.root_cause.root_cause_fingerprint,
            }
        )
        units.append(
            _repair_unit(
                "root_cause_localization",
                candidate_id,
                receipt_id=receipt.root_cause.record_id,
                input_hashes=(receipt.root_cause.evidence_graph_sha256,),
                output_hashes=(root_hash, receipt.root_cause.root_cause_fingerprint),
            )
        )
        if (
            receipt.security_test_model_call_status is ModelCallStatus.SUCCEEDED
            and receipt.security_test_schema_valid_result is True
            and receipt.security_test_receipt_id is not None
            and receipt.security_test_output_sha256 is not None
        ):
            units.append(
                _repair_unit(
                    "security_test_generation",
                    candidate_id,
                    receipt_id=receipt.security_test_receipt_id,
                    input_hashes=(receipt.root_cause.root_cause_fingerprint,),
                    output_hashes=(receipt.security_test_output_sha256,),
                    model_call_status=receipt.security_test_model_call_status,
                    schema_valid_result=receipt.security_test_schema_valid_result,
                )
            )
        else:
            units.append(
                _repair_unit(
                    "security_test_generation",
                    candidate_id,
                    status=CoverageStatus.FAILED,
                    reason_code="SECURITY_TEST_RECEIPT_MISSING",
                )
            )
        units.append(
            _repair_unit(
                "architect",
                candidate_id,
                receipt_id=receipt.architect_receipt_id,
                input_hashes=(
                    receipt.regression.descriptor_sha256,
                    receipt.root_cause.root_cause_fingerprint,
                ),
                output_hashes=(
                    receipt.architect.patch_candidate.unified_diff_sha256,
                    receipt.architect.rationale.rationale_sha256,
                    receipt.architect_model_result_sha256,
                ),
                model_call_status=receipt.architect_model_call_status,
                schema_valid_result=receipt.architect_schema_valid_result,
            )
        )
        validation_status = (
            CoverageStatus.COMPLETED
            if receipt.validation.validation.validation_outcome.value == "VALIDATED"
            else CoverageStatus.FAILED
        )
        units.append(
            _repair_unit(
                "validation_ladder",
                candidate_id,
                status=validation_status,
                reason_code=None
                if validation_status is CoverageStatus.COMPLETED
                else "VALIDATION_LADDER_NON_SUCCESS",
                receipt_id=receipt.validation.validation.validation_id,
                input_hashes=(receipt.architect.patch_candidate.unified_diff_sha256,),
                output_hashes=(receipt.validation.validation.result_sha256,),
            )
        )
    return tuple(units)


def _repair_unit(
    stage_id: str,
    candidate_id: str,
    *,
    status: CoverageStatus = CoverageStatus.COMPLETED,
    reason_code: str | None = None,
    receipt_id: str | None = None,
    input_hashes: tuple[str, ...] = (),
    output_hashes: tuple[str, ...] = (),
    model_call_status: ModelCallStatus | None = None,
    schema_valid_result: bool | None = None,
) -> CoverageUnit:
    return CoverageUnit(
        schema_version=CONTRACT_SCHEMA_VERSION,
        coverage_unit_id=f"product-repair-{stage_id}-{_sha256({'candidate_id': candidate_id})[:32]}",
        stage_id=stage_id,
        subject_id=candidate_id,
        required=True,
        applicable=True,
        coverage_status=status,
        reason_code=reason_code,
        producer_version="1.0.0" if status is CoverageStatus.COMPLETED else None,
        input_hashes=input_hashes if status is CoverageStatus.COMPLETED else (),
        output_hashes=output_hashes if status is CoverageStatus.COMPLETED else (),
        model_call_status=model_call_status,
        schema_valid_result=schema_valid_result,
        receipt_id=receipt_id,
    )


__all__ = [
    "ProductAuditComposition",
    "ProductAuditFindingMetadata",
    "ProductAuditHostInputs",
    "ProductAuditObstacle",
    "ProductDiscoveryCandidateMapping",
    "ProductRepairReceipt",
    "compose_product_audit",
    "compose_product_repair_audit",
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
        # Every model-facing step reads files with detected secrets masked (D-116).
        execution = model_facing_execution(execution, content_key=content_key)
        model_catalogue = execution.catalogue
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

        def tools_for(graph: EvidenceGraph) -> RepositoryToolSession:
            return build_product_auditor_tools(
                model_catalogue,
                graph,
                budget=tool_budget,
                deterministic=execution.scan,
                child_artifacts=retained,
                denied_source_paths=restricted_product_source_paths(execution),
                masked_sources=dict(model_catalogue.masked_sources),
            )

        def auditor_for(graph: EvidenceGraph) -> AuditorInvoker:
            return auditor_factory(graph, tools_for(graph))

        flow = run_product_candidate_flow(
            catalogue=model_catalogue,
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
        discovery_receipt = flow.discovery.receipt
        if (
            discovery_receipt.receipt_id != model_plan.receipt_id
            or discovery_receipt.scope_sha256 != model_plan.scope_sha256
            or discovery_receipt.input_sha256 != model_plan.input_sha256
            or discovery_receipt.tenant_id != model_plan.request.tenant_id
            or discovery_receipt.head_sha != model_plan.request.head_sha
            or discovery_receipt.model_profile != model_plan.request.provider_profile
            or discovery_receipt.prompt != model_plan.request.prompt
        ):
            raise _AuditObstacle(
                "PRODUCT_DISCOVERY_RECEIPT_BINDING_INVALID",
                "model discovery receipt is not bound to the admitted plan",
            )
        # The Skeptic is an independent second review: it gets its own tool
        # session and budget instead of whatever the Auditor left unused.
        review = review_factory(flow, tools_for(flow.graph))
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
