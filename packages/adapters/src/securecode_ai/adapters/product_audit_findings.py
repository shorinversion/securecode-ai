"""Compose actual product-flow receipts into a conservative Core audit run.

The adapter deliberately does not fill gaps in the accepted stage catalogue.
It returns a typed obstacle when immutable upstream receipts cannot be represented
by the frozen public ``CoverageManifest`` contract.
"""

from __future__ import annotations

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CandidateInterpretationReceipt,
    CoverageUnit,
    DiscoveryCandidate,
    Evidence,
    FindingCase,
    FindingGateState,
)
from securecode_ai.core.classification import (
    classify_product_cwe,
)
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
        for cwe_id, rule_id in _PRODUCT_CWE_RULES.items():
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


def _gate_state(review: ProductReviewResult) -> FindingGateState:
    if review.has_known_blocking_finding:
        return FindingGateState.BLOCKING
    if review.outcomes and all(
        outcome.finding_gate is not None
        and outcome.finding_gate.finding_gate_state is FindingGateState.CLEAN
        for outcome in review.outcomes
    ):
        return FindingGateState.CLEAN
    return FindingGateState.INCONCLUSIVE


def _unresolved_units(units: list[CoverageUnit]) -> tuple[str, ...]:
    return tuple(
        f"unresolved-{_sha256({'stage': unit.stage_id, 'subject': unit.subject_id})[:32]}"
        for unit in units
        if unit.required and not unit.satisfies_required_coverage
    )
