"""Compose actual product-flow receipts into a conservative Core audit run.

The adapter deliberately does not fill gaps in the accepted stage catalogue.
It returns a typed obstacle when immutable upstream receipts cannot be represented
by the frozen public ``CoverageManifest`` contract.
"""

from __future__ import annotations

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CandidateInterpretationReceipt,
    CandidateOrigin,
    CoverageStatus,
    CoverageUnit,
    ModelCallStatus,
)

from .product_audit_common import _completed_unit, _sha256, _skipped_unit
from .product_audit_types import ProductAuditHostInputs
from .product_execution import (
    ProductDeterministicExecution,
    child_fact_graph,
)
from .product_review import ProductReviewResult
from .product_scan import (
    ProductCandidateFlow,
)
from .product_scanner import ProductDeterministicScanResult


def _coverage_units(
    flow: ProductCandidateFlow,
    review: ProductReviewResult,
    host: ProductAuditHostInputs,
    interpretations: tuple[CandidateInterpretationReceipt, ...],
) -> list[CoverageUnit]:
    receipt = flow.discovery.receipt
    scenario = bool(flow.graph.candidates)
    units = [
        *_upstream_execution_units(host),
        _deterministic_unit(flow, host),
        *_child_execution_units(host),
        CoverageUnit(
            schema_version=CONTRACT_SCHEMA_VERSION,
            coverage_unit_id="product-model-native-discovery",
            stage_id="model_native_discovery",
            required=True,
            applicable=True,
            coverage_status=(
                CoverageStatus.COMPLETED
                if receipt.model_call_status is ModelCallStatus.SUCCEEDED
                else CoverageStatus.FAILED
            ),
            reason_code=None
            if receipt.model_call_status is ModelCallStatus.SUCCEEDED
            else "MODEL_DISCOVERY_NON_SUCCESS",
            producer_version="1.0.0"
            if receipt.model_call_status is ModelCallStatus.SUCCEEDED
            else None,
            input_hashes=(receipt.input_sha256,)
            if receipt.model_call_status is ModelCallStatus.SUCCEEDED
            else (),
            output_hashes=(receipt.output_sha256,)
            if receipt.model_call_status is ModelCallStatus.SUCCEEDED and receipt.output_sha256
            else (),
            model_call_status=receipt.model_call_status,
            schema_valid_result=receipt.schema_valid_result,
            receipt_id=receipt.receipt_id,
        ),
        _graph_unit("normalization", flow, host),
        *([_graph_unit("evidence_graph", flow, host)] if scenario else []),
    ]
    units.extend(unit for outcome in review.outcomes for unit in outcome.coverage_units)
    if host.operation == "repair":
        units.extend(host.repair_coverage_units)
    units.extend(
        [
            _skipped_unit("coverage_guard", "COVERAGE_GUARD_RECEIPT_MISSING"),
            _skipped_unit("reporting", "REPORTING_RECEIPT_MISSING"),
        ]
    )
    _bind_auditor_coverage(units, interpretations)
    return units


def _child_execution_units(host: ProductAuditHostInputs) -> list[CoverageUnit]:
    """Expose inherited obligations without changing pinned required keys."""
    execution = host.deterministic_execution
    if execution is None:
        return []
    from securecode_ai.core.discovery import (
        DependencyEcosystem,
        IgnorePolicy,
        LanguageId,
        discover_repository,
    )
    from securecode_ai.core.repository import (
        RepositoryFile,
        RepositoryInventory,
        repository_tree_sha256,
    )

    files = tuple(
        RepositoryFile(f.path, len(f.content), f.content_sha256)
        for f in host.source_catalogue.snapshot.files
    )
    inventory = RepositoryInventory(
        files, sum(f.size_bytes for f in files), repository_tree_sha256(files)
    )
    discovery = discover_repository(inventory, IgnorePolicy("product-execution", "1.0.0"))
    python = any(entry.language is LanguageId.PYTHON for entry in discovery.languages)
    manifests = any(
        entry.ecosystem is DependencyEcosystem.PYTHON for entry in discovery.dependency_manifests
    )
    selected = tuple(
        stage
        for stage, applies in (
            ("python_parse_symbols", python),
            ("secret_scan", bool(discovery.languages)),
            ("dependency_scan", manifests),
            ("cwe89_scan", python),
        )
        if applies
    )
    verified = (
        execution.is_complete and execution.catalogue.snapshot == host.source_catalogue.snapshot
    )
    outputs = dict(execution.child_output_hashes)
    units = []
    for stage in selected:
        if verified:
            units.append(
                CoverageUnit(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    coverage_unit_id=f"product-child-{stage}",
                    stage_id=stage,
                    required=False,
                    applicable=True,
                    coverage_status=CoverageStatus.COMPLETED,
                    producer_version="1.0.0",
                    input_hashes=(inventory.tree_sha256,),
                    output_hashes=outputs[stage],
                )
            )
        else:
            units.append(
                CoverageUnit(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    coverage_unit_id=f"product-child-{stage}",
                    stage_id=stage,
                    required=False,
                    applicable=True,
                    coverage_status=CoverageStatus.SKIPPED,
                    reason_code="CHILD_EXECUTION_NOT_VERIFIED",
                )
            )
    return units


def _upstream_execution_units(host: ProductAuditHostInputs) -> list[CoverageUnit]:
    execution = host.deterministic_execution
    if execution is None or execution.catalogue.snapshot != host.source_catalogue.snapshot:
        return [
            _skipped_unit("intake", "INTAKE_RECEIPT_MISSING"),
            _skipped_unit("language_discovery", "LANGUAGE_DISCOVERY_RECEIPT_MISSING"),
        ]
    # Derive observations from retained immutable inputs, not caller flags.
    from securecode_ai.core.discovery import IgnorePolicy, discover_repository
    from securecode_ai.core.repository import (
        RepositoryFile,
        RepositoryInventory,
        repository_tree_sha256,
    )

    execution.catalogue.repository_view()
    files = tuple(
        RepositoryFile(f.path, len(f.content), f.content_sha256)
        for f in execution.catalogue.snapshot.files
    )
    inventory = RepositoryInventory(
        files, sum(f.size_bytes for f in files), repository_tree_sha256(files)
    )
    discovery = discover_repository(inventory, IgnorePolicy("product-execution", "1.0.0"))
    if (
        execution.inventory_sha256 != inventory.tree_sha256
        or execution.discovery_sha256 != discovery.manifest_sha256
    ):
        return [
            _skipped_unit("intake", "INTAKE_OBSERVATION_INVALID"),
            _skipped_unit("language_discovery", "LANGUAGE_DISCOVERY_OBSERVATION_INVALID"),
        ]
    return [
        _completed_unit(
            "intake",
            input_hashes=tuple(f.content_sha256 for f in files),
            output_hashes=(inventory.tree_sha256,),
        ),
        _completed_unit(
            "language_discovery",
            input_hashes=(inventory.tree_sha256,),
            output_hashes=(discovery.manifest_sha256,),
        ),
    ]


def _deterministic_unit(flow: ProductCandidateFlow, host: ProductAuditHostInputs) -> CoverageUnit:
    scan = host.deterministic_scan
    if not _valid_scan_for_flow(scan, flow):
        return _skipped_unit("deterministic_analysis", "DETERMINISTIC_RECEIPT_MISSING")
    assert type(scan) is ProductDeterministicScanResult
    execution = host.deterministic_execution
    if execution is not None:
        if (
            type(execution) is not ProductDeterministicExecution
            or not execution.is_complete
            or execution.catalogue.snapshot != host.source_catalogue.snapshot
            or execution.scan != scan
        ):
            return _skipped_unit(
                "deterministic_analysis", "DETERMINISTIC_CHILD_EXECUTION_INCOMPLETE"
            )
        child = child_fact_graph(execution, tenant_id=flow.graph.tenant_id)
        current_records = {record.evidence_id: record for record in flow.graph.evidence}
        if not all(current_records.get(record.evidence_id) == record for record in child.evidence):
            return _skipped_unit("deterministic_analysis", "DETERMINISTIC_CHILD_FACTS_MISSING")
        for candidate in child.candidates:
            matches = [
                current
                for current in flow.graph.candidates
                if current.root_cause_fingerprint == candidate.root_cause_fingerprint
                and set(candidate.evidence_ids).issubset(current.evidence_ids)
            ]
            if len(matches) != 1:
                return _skipped_unit("deterministic_analysis", "DETERMINISTIC_CHILD_FACTS_MISSING")
    output = _sha256(
        {
            "graph": scan.graph.graph_sha256,
            "receipts": [item.signal_digest for item in scan.receipts],
            "child_outputs": execution.child_output_hashes if execution is not None else (),
        }
    )
    return _completed_unit(
        "deterministic_analysis",
        input_hashes=tuple(item.content_sha256 for item in host.source_catalogue.snapshot.files),
        output_hashes=(output,),
    )


def _scan_contributes_to_flow(
    scan: ProductDeterministicScanResult, flow: ProductCandidateFlow
) -> bool:
    flow_evidence = {item.evidence_id: item for item in flow.graph.evidence}
    if not all(flow_evidence.get(item.evidence_id) == item for item in scan.graph.evidence):
        return False
    if not scan.graph.candidates:
        return not scan.graph.evidence and all(not receipt.signals for receipt in scan.receipts)
    for scanned in scan.graph.candidates:
        matches = [
            current
            for current in flow.graph.candidates
            if current.candidate_origin in {CandidateOrigin.DETERMINISTIC, CandidateOrigin.HYBRID}
            and current.candidate_version == scanned.candidate_version
            and current.root_cause_fingerprint == scanned.root_cause_fingerprint
            and set(scanned.evidence_ids).issubset(current.evidence_ids)
            and any(
                lineage.lane.value == "deterministic"
                and lineage.root_cause_fingerprint == scanned.root_cause_fingerprint
                and set(lineage.evidence_ids).issubset(current.evidence_ids)
                for lineage in current.lineage
            )
        ]
        if len(matches) != 1:
            return False
    return True


def _valid_scan_for_flow(scan: object, flow: ProductCandidateFlow) -> bool:
    return (
        not flow.deterministic_failed
        and type(scan) is ProductDeterministicScanResult
        and scan.graph.tenant_id == flow.graph.tenant_id
        and scan.graph.head_sha == flow.graph.head_sha
        and scan.is_complete
        and bool(scan.receipts)
        and all(item.status.value == "SUCCEEDED" for item in scan.receipts)
        and _scan_contributes_to_flow(scan, flow)
    )


def _graph_unit(
    stage: str, flow: ProductCandidateFlow, host: ProductAuditHostInputs
) -> CoverageUnit:
    scan = host.deterministic_scan
    if (
        not _valid_scan_for_flow(scan, flow)
        or flow.discovery.receipt.model_call_status is not ModelCallStatus.SUCCEEDED
        or not flow.discovery.receipt.schema_valid_result
        or flow.discovery.receipt.output_sha256 is None
    ):
        return _skipped_unit(stage, "GRAPH_INPUT_RECEIPT_MISSING")
    assert type(scan) is ProductDeterministicScanResult
    deterministic = _deterministic_unit(flow, host)
    return _completed_unit(
        stage,
        input_hashes=(
            flow.discovery.receipt.input_sha256,
            flow.discovery.receipt.output_sha256,
            *deterministic.input_hashes,
            *deterministic.output_hashes,
        ),
        output_hashes=(flow.graph.graph_sha256,),
    )


def _bind_auditor_coverage(
    units: list[CoverageUnit], interpretations: tuple[CandidateInterpretationReceipt, ...]
) -> None:
    for index, unit in enumerate(units):
        if unit.stage_id != "auditor_investigation" or unit.subject_id is None:
            continue
        receipt = next(
            (item for item in interpretations if item.candidate_id == unit.subject_id), None
        )
        if receipt is None:
            raise ValueError
        units[index] = unit.model_copy(
            update={
                "model_call_status": receipt.model_call_status,
                "schema_valid_result": receipt.schema_valid_result,
                "receipt_id": receipt.receipt_id,
            }
        )
