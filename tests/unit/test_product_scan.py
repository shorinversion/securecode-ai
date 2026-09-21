"""Exact graph merge and lane provenance negative oracles."""

import json

import pytest
from securecode_ai.adapters.product_scan import merge_product_lane_graphs
from securecode_ai.contracts import CandidateOrigin, DiscoveryCandidate, Evidence
from securecode_ai.core.evidence_graph import (
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceNodeKind,
    EvidenceNodeRef,
)

from tests.unit.test_evidence_package import _evidence, _graph


def lane(
    origin: CandidateOrigin,
    *,
    fingerprint: str = "a" * 64,
    evidence_id: str = "evidence-a",
    head: str = "1" * 40,
) -> EvidenceGraph:
    graph = _graph(_evidence(evidence_id))
    material = graph.candidates[0].model_dump(mode="json")
    material.update(
        candidate_id=f"candidate-{origin.value.lower()}-{evidence_id}",
        candidate_origin=origin.value,
        root_cause_fingerprint=fingerprint,
        head_sha=head,
    )
    lineage = material["lineage"][0]
    lineage.update(
        lineage_id=f"lineage-{origin.value.lower()}-{evidence_id}",
        lane=origin.value,
        root_cause_fingerprint=fingerprint,
    )
    if origin is CandidateOrigin.MODEL_NATIVE:
        lineage.update(input_signal_ids=[], input_candidate_ids=["source-native"])
    candidate = DiscoveryCandidate.model_validate_json(json.dumps(material))
    record = graph.evidence[0].model_dump(mode="json")
    record["head_sha"] = head
    evidence = Evidence.model_validate_json(json.dumps(record))
    return EvidenceGraph(
        graph_id=f"graph-{origin.value.lower()}",
        tenant_id=graph.tenant_id,
        head_sha=head,
        candidates=(candidate,),
        evidence=(evidence,),
        edges=(
            EvidenceGraphEdge(
                EvidenceEdgeKind.CANDIDATE_EVIDENCE,
                EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, candidate.candidate_id),
                EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, evidence_id),
            ),
        ),
    )


def test_exact_root_merges_all_source_candidates_producers_and_evidence() -> None:
    deterministic = lane(CandidateOrigin.DETERMINISTIC)
    native = lane(CandidateOrigin.MODEL_NATIVE, evidence_id="evidence-b")
    merged = merge_product_lane_graphs(
        graph_id="merged", deterministic=deterministic, native=native
    )
    assert len(merged.candidates) == 1
    candidate = merged.candidates[0]
    assert candidate.candidate_origin is CandidateOrigin.HYBRID
    assert candidate.evidence_ids == ("evidence-a", "evidence-b")
    assert len(candidate.lineage) == 2
    assert {c.candidate_id for c in (*deterministic.candidates, *native.candidates)}.issubset(
        {source for lineage in candidate.lineage for source in lineage.input_candidate_ids}
    )
    assert len(merged.evidence) == len(merged.edges) == 2


def test_nearby_but_different_roots_remain_two_candidates() -> None:
    merged = merge_product_lane_graphs(
        graph_id="merged",
        deterministic=lane(CandidateOrigin.DETERMINISTIC),
        native=lane(CandidateOrigin.MODEL_NATIVE, fingerprint="b" * 64, evidence_id="evidence-b"),
    )
    assert len(merged.candidates) == 2


def test_stale_lane_is_rejected_before_merge() -> None:
    with pytest.raises(ValueError, match="identity"):
        merge_product_lane_graphs(
            graph_id="merged",
            deterministic=lane(CandidateOrigin.DETERMINISTIC),
            native=lane(CandidateOrigin.MODEL_NATIVE, evidence_id="evidence-b", head="2" * 40),
        )


def test_conflicting_evidence_id_cannot_borrow_provenance() -> None:
    native = lane(CandidateOrigin.MODEL_NATIVE)
    record = native.evidence[0].model_dump(mode="json")
    record["evidence_sha256"] = "f" * 64
    native = EvidenceGraph(
        graph_id=native.graph_id,
        tenant_id=native.tenant_id,
        head_sha=native.head_sha,
        candidates=native.candidates,
        evidence=(Evidence.model_validate_json(json.dumps(record)),),
        edges=native.edges,
    )
    with pytest.raises(ValueError, match="collision"):
        merge_product_lane_graphs(
            graph_id="merged", deterministic=lane(CandidateOrigin.DETERMINISTIC), native=native
        )
