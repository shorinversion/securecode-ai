"""Unit contracts for the internal, source-free EvidenceGraph v1."""

from __future__ import annotations

import pytest
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CandidateOrigin,
    DataClass,
    DiscoveryCandidate,
    DiscoveryLane,
    Evidence,
    EvidenceKind,
    LineageRef,
    ProducerRef,
    SourceLocation,
    SourcePosition,
    TrustLabel,
)
from securecode_ai.core.evidence_graph import (
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceGraphError,
    EvidenceGraphErrorCode,
    EvidenceNodeKind,
    EvidenceNodeRef,
)

TENANT = "tenant-1"
HEAD = "a" * 40
ROOT_CAUSE = "b" * 64
HASH_A = "a" * 64


def _producer(identifier: str = "scanner") -> ProducerRef:
    return ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id=identifier,
        producer_version="1.0.0",
        producer_sha256="c" * 64,
    )


def _evidence(
    evidence_id: str,
    *,
    producer: ProducerRef | None = None,
    tenant_id: str = TENANT,
    head_sha: str = HEAD,
) -> Evidence:
    return Evidence(
        schema_version=CONTRACT_SCHEMA_VERSION,
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        head_sha=head_sha,
        evidence_kind=EvidenceKind.SCANNER_SIGNAL,
        producer=_producer() if producer is None else producer,
        trust_label=TrustLabel.TRUSTED_DETERMINISTIC,
        data_class=DataClass.INTERNAL_METADATA,
        evidence_sha256=("d" if evidence_id.endswith("1") else "e") * 64,
        location=SourceLocation(
            schema_version=CONTRACT_SCHEMA_VERSION,
            path="src/app.py",
            start=SourcePosition(schema_version=CONTRACT_SCHEMA_VERSION, line=1, column=1),
            end=SourcePosition(schema_version=CONTRACT_SCHEMA_VERSION, line=1, column=2),
            content_sha256="f" * 64,
        ),
    )


def _candidate(
    evidence_ids: tuple[str, ...] = ("evidence-1",),
    *,
    tenant_id: str = TENANT,
    head_sha: str = HEAD,
    producer: ProducerRef | None = None,
) -> DiscoveryCandidate:
    actual_producer = _producer() if producer is None else producer
    return DiscoveryCandidate(
        schema_version=CONTRACT_SCHEMA_VERSION,
        candidate_id="candidate-1",
        tenant_id=tenant_id,
        candidate_version=1,
        head_sha=head_sha,
        root_cause_fingerprint=ROOT_CAUSE,
        candidate_origin=CandidateOrigin.DETERMINISTIC,
        lineage=(
            LineageRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                lineage_id="lineage-1",
                lane=DiscoveryLane.DETERMINISTIC,
                producer=actual_producer,
                root_cause_fingerprint=ROOT_CAUSE,
                input_signal_ids=("signal-1",),
                evidence_ids=(evidence_ids[0],),
            ),
        ),
        evidence_ids=evidence_ids,
    )


def _candidate_ref() -> EvidenceNodeRef:
    return EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, "candidate-1")


def _evidence_ref(identifier: str) -> EvidenceNodeRef:
    return EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, identifier)


def _candidate_edge(identifier: str) -> EvidenceGraphEdge:
    return EvidenceGraphEdge(
        EvidenceEdgeKind.CANDIDATE_EVIDENCE,
        _candidate_ref(),
        _evidence_ref(identifier),
    )


def _graph(
    *,
    graph_id: str = "graph-1",
    candidates: tuple[DiscoveryCandidate, ...] | None = None,
    evidence: tuple[Evidence, ...] | None = None,
    edges: tuple[EvidenceGraphEdge, ...] | None = None,
) -> EvidenceGraph:
    actual_evidence = (_evidence("evidence-1"),) if evidence is None else evidence
    actual_candidates = (_candidate(),) if candidates is None else candidates
    actual_edges = (_candidate_edge("evidence-1"),) if edges is None else edges
    return EvidenceGraph(
        graph_id=graph_id,
        tenant_id=TENANT,
        head_sha=HEAD,
        candidates=actual_candidates,
        evidence=actual_evidence,
        edges=actual_edges,
    )


def test_graph_canonicalizes_input_order_and_hash_ignores_graph_label() -> None:
    evidence_one = _evidence("evidence-1")
    evidence_two = _evidence("evidence-2")
    candidate = _candidate(("evidence-2", "evidence-1"))
    edges = (_candidate_edge("evidence-2"), _candidate_edge("evidence-1"))

    left = _graph(
        graph_id="graph-left",
        candidates=(candidate,),
        evidence=(evidence_two, evidence_one),
        edges=edges,
    )
    right = _graph(
        graph_id="graph-right",
        candidates=(candidate,),
        evidence=(evidence_one, evidence_two),
        edges=tuple(reversed(edges)),
    )

    assert tuple(item.ref.node_id for item in left.nodes) == (
        "candidate-1",
        "evidence-1",
        "evidence-2",
    )
    assert left.edges == right.edges
    assert left.graph_sha256 == right.graph_sha256
    assert "source" not in left.canonical_payload
    assert "payload" not in left.canonical_payload


@pytest.mark.parametrize(
    ("candidates", "evidence", "code"),
    [
        (
            (_candidate(tenant_id="tenant-2"),),
            (_evidence("evidence-1"),),
            EvidenceGraphErrorCode.IDENTITY_MISMATCH,
        ),
        (
            (_candidate(head_sha="b" * 40),),
            (_evidence("evidence-1"),),
            EvidenceGraphErrorCode.IDENTITY_MISMATCH,
        ),
        (
            (_candidate(("missing",)),),
            (_evidence("evidence-1"),),
            EvidenceGraphErrorCode.DANGLING_REFERENCE,
        ),
        (
            (_candidate(producer=_producer("other")),),
            (_evidence("evidence-1"),),
            EvidenceGraphErrorCode.PROVENANCE_MISMATCH,
        ),
    ],
)
def test_graph_rejects_mismatched_identity_and_provenance(
    candidates: tuple[DiscoveryCandidate, ...],
    evidence: tuple[Evidence, ...],
    code: EvidenceGraphErrorCode,
) -> None:
    with pytest.raises(EvidenceGraphError) as error:
        _graph(candidates=candidates, evidence=evidence)

    assert error.value.code is code
    assert str(error.value) == "evidence graph validation failed"


def test_graph_rejects_missing_candidate_link_duplicate_and_invalid_flow() -> None:
    invalid_flow = EvidenceGraphEdge(
        EvidenceEdgeKind.CANDIDATE_EVIDENCE,
        _evidence_ref("evidence-1"),
        _candidate_ref(),
    )
    for edges, code in (
        ((), EvidenceGraphErrorCode.DANGLING_REFERENCE),
        (
            (_candidate_edge("evidence-1"), _candidate_edge("evidence-1")),
            EvidenceGraphErrorCode.DUPLICATE_NODE,
        ),
        ((invalid_flow,), EvidenceGraphErrorCode.INVALID_FLOW),
    ):
        with pytest.raises(EvidenceGraphError) as error:
            _graph(edges=edges)
        assert error.value.code is code


def test_graph_rejects_orphan_evidence_and_evidence_cycle() -> None:
    evidence_one = _evidence("evidence-1")
    evidence_two = _evidence("evidence-2")
    orphan_candidate = _candidate(("evidence-1",))
    with pytest.raises(EvidenceGraphError) as orphan:
        _graph(candidates=(orphan_candidate,), evidence=(evidence_one, evidence_two))
    assert orphan.value.code is EvidenceGraphErrorCode.DANGLING_REFERENCE

    cycle_edges = (
        _candidate_edge("evidence-1"),
        EvidenceGraphEdge(
            EvidenceEdgeKind.EVIDENCE_DERIVED_FROM,
            _evidence_ref("evidence-1"),
            _evidence_ref("evidence-2"),
        ),
        EvidenceGraphEdge(
            EvidenceEdgeKind.EVIDENCE_DERIVED_FROM,
            _evidence_ref("evidence-2"),
            _evidence_ref("evidence-1"),
        ),
    )
    with pytest.raises(EvidenceGraphError) as cycle:
        _graph(
            candidates=(orphan_candidate,),
            evidence=(evidence_one, evidence_two),
            edges=cycle_edges,
        )
    assert cycle.value.code is EvidenceGraphErrorCode.CYCLE


def test_graph_rejects_unvalidated_retained_contract_state() -> None:
    forged = Evidence.model_construct(
        evidence_id="evidence-1",
        tenant_id="tenant-1",
        head_sha="not-a-commit",
        evidence_kind=EvidenceKind.SCANNER_SIGNAL,
        producer=_producer(),
        trust_label=TrustLabel.TRUSTED_DETERMINISTIC,
        data_class=DataClass.INTERNAL_METADATA,
        evidence_sha256=HASH_A,
        location=None,
        artifact_ref=None,
        schema_version="0.2.0",
        extensions=(),
    )
    with pytest.raises(EvidenceGraphError) as error:
        _graph(evidence=(forged,))

    assert error.value.code is EvidenceGraphErrorCode.INVALID_GRAPH
