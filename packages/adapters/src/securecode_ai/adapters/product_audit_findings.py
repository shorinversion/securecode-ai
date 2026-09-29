"""Compose actual product-flow receipts into a conservative Core audit run.

The adapter deliberately does not fill gaps in the accepted stage catalogue.
It returns a typed obstacle when immutable upstream receipts cannot be represented
by the frozen public ``CoverageManifest`` contract.
"""

from __future__ import annotations

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CandidateInterpretationReceipt,
    CommandOperationEvidence,
    CoverageUnit,
    DiscoveryCandidate,
    Evidence,
    EvidenceKind,
    FindingCase,
    FindingGateState,
)
from securecode_ai.core.classification import (
    classify_product_cwe,
)
from securecode_ai.core.evidence_graph import EvidenceEdgeKind, EvidenceGraph, EvidenceNodeKind
from securecode_ai.core.finding_gate import FindingGateDecision
from securecode_ai.core.normalization import root_cause_location_fingerprint
from securecode_ai.core.reports import (
    ReportFinding,
)

from .product_audit_common import _sha256
from .product_audit_types import (
    _PRODUCT_CWE_RULES,
    ProductAuditFindingMetadata,
    ProductAuditHostInputs,
)
from .product_execution import ProductDeterministicExecution
from .product_review import ProductReviewResult
from .product_scan import (
    ProductCandidateFlow,
)


def _findings(
    flow: ProductCandidateFlow,
    review: ProductReviewResult,
    host: ProductAuditHostInputs,
    interpretations: tuple[CandidateInterpretationReceipt, ...],
) -> tuple[ReportFinding, ...]:
    blocking = [outcome for outcome in review.outcomes if outcome.has_known_blocking_finding]
    metadata = {(item.candidate_id, item.candidate_version): item for item in host.finding_metadata}
    if len(metadata) != len(host.finding_metadata) or set(metadata) != {
        (outcome.candidate_id, outcome.candidate_version) for outcome in blocking
    }:
        raise ValueError
    receipt_by_candidate = {
        (item.candidate_id, item.candidate_version): item for item in interpretations
    }
    candidates = {
        (item.candidate_id, item.candidate_version): item for item in flow.graph.candidates
    }
    records = {item.evidence_id: item for item in flow.graph.evidence}
    output: list[ReportFinding] = []
    for outcome in blocking:
        metadata_item = metadata[(outcome.candidate_id, outcome.candidate_version)]
        candidate = candidates[(outcome.candidate_id, outcome.candidate_version)]
        receipt = receipt_by_candidate[(outcome.candidate_id, outcome.candidate_version)]
        decision = outcome.finding_gate
        if (
            type(decision) is not FindingGateDecision
            or decision.finding_gate_state is not FindingGateState.BLOCKING
            or metadata_item.evidence_graph_ref.tenant_id != candidate.tenant_id
            or metadata_item.evidence_graph_ref.content_id != flow.graph.graph_id
            or metadata_item.evidence_graph_ref.content_sha256 != flow.graph.graph_sha256
        ):
            raise ValueError
        locations = tuple(
            sorted(
                {
                    record.location
                    for evidence_id in candidate.evidence_ids
                    if (record := records.get(evidence_id)) is not None
                    and record.location is not None
                },
                key=lambda item: (item.path, item.start.line, item.start.column),
            )
        )
        if not locations:
            raise ValueError
        command_evidence = _bind_command_operation_evidence(candidate, flow.graph)
        finding = FindingCase(
            schema_version=CONTRACT_SCHEMA_VERSION,
            finding_id=metadata_item.finding_id,
            candidate_id=candidate.candidate_id,
            candidate_version=candidate.candidate_version,
            repository_revision=host.execution_identity.repository_revision,
            root_cause_fingerprint=candidate.root_cause_fingerprint,
            candidate_origin=candidate.candidate_origin,
            producer_lineage=candidate.lineage,
            locations=locations,
            cwe_id=metadata_item.cwe_id,
            evidence_graph_ref=metadata_item.evidence_graph_ref,
            evidence_ids=candidate.evidence_ids,
            interpretation_receipt_id=receipt.receipt_id,
            finding_verdict=decision.auditor_verdict,
            verdict_evidence_ids=decision.auditor_cited_evidence_ids,
            blocking=True,
            command_operation_evidence=command_evidence,
        )
        classification = classify_product_cwe(metadata_item.cwe_id)
        _validate_product_finding_metadata(metadata_item, candidate, records)
        if (
            metadata_item.cwe_id in _PRODUCT_CWE_RULES
            and decision.severity is not classification.severity
        ):
            raise ValueError
        output.append(ReportFinding(finding, classification))
    return tuple(sorted(output, key=lambda item: item.finding.finding_id))


def _validate_product_finding_metadata(
    metadata: ProductAuditFindingMetadata,
    candidate: DiscoveryCandidate,
    records: dict[str, Evidence],
) -> None:
    """Bind the additive portfolio metadata to an existing host candidate.

    The historical CWE-89 host path predates this additive binding and remains
    byte-compatible only when its candidate does not resolve to a product
    portfolio root. Every extended root is derived from the host candidate's
    current evidence locations and the closed rule catalogue before supplied
    metadata is considered.
    """

    recognized = _recognized_product_root(candidate, records)
    if recognized is None:
        if metadata.cwe_id in _PRODUCT_CWE_RULES:
            raise ValueError
        return
    expected_cwe, expected_rule = recognized
    if (
        metadata.cwe_id != expected_cwe
        or metadata.rule_id != expected_rule
        or metadata.root_cause_fingerprint != candidate.root_cause_fingerprint
    ):
        raise ValueError


def _bind_command_operation_evidence(
    candidate: DiscoveryCandidate, graph: EvidenceGraph
) -> tuple[CommandOperationEvidence, ...]:
    """Bind scanner operation facts to one exact graph flow and its endpoints."""

    if not candidate.command_operation_evidence:
        return ()
    records = {item.evidence_id: item for item in graph.evidence}
    graph_edges = tuple(graph.edges)
    output: list[CommandOperationEvidence] = []
    for command in candidate.command_operation_evidence:
        matches: list[tuple[str, str, str]] = []
        for flow in graph.evidence:
            if flow.evidence_kind is not EvidenceKind.DATA_FLOW:
                continue
            targets = {
                edge.target.node_id
                for edge in graph_edges
                if edge.kind is EvidenceEdgeKind.EVIDENCE_DERIVED_FROM
                and edge.source.node_id == flow.evidence_id
                and edge.source.kind is EvidenceNodeKind.EVIDENCE
                and edge.target.kind is EvidenceNodeKind.EVIDENCE
            }
            if command.scanner_signal_id not in targets:
                continue
            source_ids = tuple(
                item_id
                for item_id in targets
                if (item := records.get(item_id)) is not None
                and item.evidence_kind is EvidenceKind.SOURCE_LOCATION
                and item.location == command.source
            )
            sink_ids = tuple(
                item_id
                for item_id in targets
                if (item := records.get(item_id)) is not None
                and item.evidence_kind is EvidenceKind.SOURCE_LOCATION
                and item.location == command.sink
            )
            for source_id in source_ids:
                for sink_id in sink_ids:
                    matches.append((source_id, sink_id, flow.evidence_id))
        if len(matches) != 1:
            raise ValueError("CWE-78 command operation binding is missing or ambiguous")
        source_id, sink_id, flow_id = matches[0]
        output.append(
            command.model_copy(
                update={
                    "source_evidence_id": source_id,
                    "sink_evidence_id": sink_id,
                    "flow_evidence_id": flow_id,
                }
            )
        )
    return tuple(sorted(output, key=lambda item: item.scanner_signal_id))


def _recognized_product_root(
    candidate: DiscoveryCandidate, records: dict[str, Evidence]
) -> tuple[str, str] | None:
    """Resolve only fixed product rule families from host-owned candidate bytes."""

    matches: set[tuple[str, str]] = set()
    for evidence_id in candidate.evidence_ids:
        record = records.get(evidence_id)
        location = getattr(record, "location", None)
        if location is None:
            continue
        for cwe_id, rule_ids in _PRODUCT_CWE_RULES.items():
            for rule_id in rule_ids:
                if (
                    root_cause_location_fingerprint(
                        tenant_id=candidate.tenant_id,
                        rule_id=rule_id,
                        location=location,
                    )
                    == candidate.root_cause_fingerprint
                ):
                    matches.add((cwe_id, rule_id))
    if len(matches) > 1:
        raise ValueError
    return next(iter(matches), None)


def _gate_state(
    review: ProductReviewResult,
    *,
    flow: ProductCandidateFlow | None = None,
    host: ProductAuditHostInputs | None = None,
    coverage_units: tuple[CoverageUnit, ...] | list[CoverageUnit] | None = None,
) -> FindingGateState:
    if review.has_known_blocking_finding:
        return FindingGateState.BLOCKING
    if review.outcomes and all(
        outcome.finding_gate is not None
        and outcome.finding_gate.finding_gate_state is FindingGateState.CLEAN
        for outcome in review.outcomes
    ):
        return FindingGateState.CLEAN
    if (
        not review.outcomes
        and flow is not None
        and host is not None
        and coverage_units is not None
        and _zero_candidate_clean(review, flow, host, tuple(coverage_units))
    ):
        return FindingGateState.CLEAN
    return FindingGateState.INCONCLUSIVE


def _zero_candidate_clean(
    review: ProductReviewResult,
    flow: ProductCandidateFlow,
    host: ProductAuditHostInputs,
    coverage_units: tuple[CoverageUnit, ...],
) -> bool:
    """Require independent proof before routing a completed-zero run as clean."""

    revision = host.execution_identity.repository_revision
    receipt = flow.discovery.receipt
    deterministic_execution = host.deterministic_execution
    if type(deterministic_execution) is not ProductDeterministicExecution:
        return False
    if not deterministic_execution.is_complete:
        return False
    if (
        host.operation != "scan"
        or flow.required_terminal_outcome is not None
        or flow.deterministic_failed
        or review.upstream_incomplete
        or review.discovery != flow.discovery
        or review.outcomes
        or flow.graph.candidates
        or flow.graph.evidence
        or flow.graph.edges
        or not flow.discovery.is_completed_zero
        or receipt.tenant_id != revision.tenant_id
        or receipt.head_sha != revision.head_sha
        or flow.graph.tenant_id != revision.tenant_id
        or flow.graph.head_sha != revision.head_sha
        or host.source_catalogue.snapshot.head_sha != revision.head_sha
        or any(
            index.repository_id != revision.repository_id or index.revision != revision.head_sha
            for index in host.source_catalogue.indexes
        )
        or any(
            anchor.tenant_id != revision.tenant_id or anchor.head_sha != revision.head_sha
            for anchor in host.source_catalogue.anchors
        )
    ):
        return False

    required_units = tuple(unit for unit in coverage_units if unit.required)
    expected_units = frozenset(
        (stage_id, None)
        for stage_id in (
            "intake",
            "language_discovery",
            "deterministic_analysis",
            "model_native_discovery",
            "normalization",
            "coverage_guard",
            "reporting",
        )
    )
    return {(unit.stage_id, unit.subject_id) for unit in required_units} == expected_units and all(
        unit.satisfies_required_coverage for unit in required_units
    )


def _unresolved_units(units: list[CoverageUnit]) -> tuple[str, ...]:
    return tuple(
        f"unresolved-{_sha256({'stage': unit.stage_id, 'subject': unit.subject_id})[:32]}"
        for unit in units
        if unit.required and not unit.satisfies_required_coverage
    )
