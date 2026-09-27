"""Candidate rule-family binding for installed product execution."""

from __future__ import annotations

from securecode_ai.contracts import DiscoveryCandidate
from securecode_ai.core.evidence_graph import EvidenceGraph
from securecode_ai.core.normalization import root_cause_location_fingerprint

from .local_product_runner_config import _RULES
from .product_rule_catalogue import ProductRuleMappingError


def _candidate_family(candidate: DiscoveryCandidate, graph: EvidenceGraph) -> tuple[str, str]:
    records = {item.evidence_id: item for item in graph.evidence}
    matches = [
        (rule, cwe)
        for rule, cwe in _RULES.items()
        for evidence_id in candidate.evidence_ids
        if (record := records.get(evidence_id)) is not None
        and record.location is not None
        and root_cause_location_fingerprint(
            tenant_id=candidate.tenant_id, rule_id=rule, location=record.location
        )
        == candidate.root_cause_fingerprint
    ]
    if not matches or len(set(matches)) != 1:
        raise ProductRuleMappingError()
    return matches[0]
