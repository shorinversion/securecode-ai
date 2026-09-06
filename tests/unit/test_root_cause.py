"""P4.1 contracts for source-free causal root-cause localization."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

import pytest
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
    ProducerRef,
    RepositoryRevision,
    SourceLocation,
    SourcePosition,
    TrustLabel,
)
from securecode_ai.core.evidence_graph import (
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceNodeKind,
    EvidenceNodeRef,
)
from securecode_ai.core.root_cause import (
    RootCauseContractError,
    RootCauseEvidenceRefs,
    RootCauseLocalizationReason,
    RootCauseLocalizationStatus,
    RootCauseRecord,
    localize_root_cause,
)

TENANT = "tenant-1"
HEAD = "a" * 40
ROOT_CAUSE = "b" * 64
GRAPH_HASH = "c" * 64


def _producer() -> ProducerRef:
    return ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="cwe89-adapter",
        producer_version="1.0.0",
        producer_sha256="d" * 64,
    )


def _location(path: str, line: int) -> SourceLocation:
    return SourceLocation(
        schema_version=CONTRACT_SCHEMA_VERSION,
        path=path,
        start=SourcePosition(schema_version=CONTRACT_SCHEMA_VERSION, line=line, column=1),
        end=SourcePosition(schema_version=CONTRACT_SCHEMA_VERSION, line=line, column=9),
        content_sha256="e" * 64,
    )


def _evidence(
    evidence_id: str,
    kind: EvidenceKind,
    *,
    location: SourceLocation | None,
) -> Evidence:
    return Evidence(
        schema_version=CONTRACT_SCHEMA_VERSION,
        evidence_id=evidence_id,
        tenant_id=TENANT,
        head_sha=HEAD,
        evidence_kind=kind,
        producer=_producer(),
        trust_label=TrustLabel.TRUSTED_DETERMINISTIC,
        data_class=DataClass.INTERNAL_METADATA,
        evidence_sha256=("f" if evidence_id.endswith("source") else "1") * 64,
        location=location,
    )


def _candidate(candidate_id: str = "candidate-1") -> DiscoveryCandidate:
    evidence_ids = ("evidence-source", "evidence-propagation", "evidence-sink")
    return DiscoveryCandidate(
        schema_version=CONTRACT_SCHEMA_VERSION,
        candidate_id=candidate_id,
        tenant_id=TENANT,
        candidate_version=1,
        head_sha=HEAD,
        root_cause_fingerprint=ROOT_CAUSE,
        candidate_origin=CandidateOrigin.DETERMINISTIC,
        lineage=(
            LineageRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                lineage_id=f"lineage-{candidate_id}",
                lane=DiscoveryLane.DETERMINISTIC,
                producer=_producer(),
                root_cause_fingerprint=ROOT_CAUSE,
                input_signal_ids=("signal-1",),
                evidence_ids=evidence_ids,
            ),
        ),
        evidence_ids=evidence_ids,
    )


def _edge(evidence_id: str, candidate_id: str) -> EvidenceGraphEdge:
    return EvidenceGraphEdge(
        EvidenceEdgeKind.CANDIDATE_EVIDENCE,
        EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, candidate_id),
        EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, evidence_id),
    )


def _graph(candidate_id: str = "candidate-1", graph_id: str = "graph-1") -> EvidenceGraph:
    evidence = (
        _evidence(
            "evidence-source",
            EvidenceKind.SOURCE_LOCATION,
            location=_location("src/in.py", 2),
        ),
        _evidence("evidence-propagation", EvidenceKind.DATA_FLOW, location=None),
        _evidence(
            "evidence-sink",
            EvidenceKind.SOURCE_LOCATION,
            location=_location("src/db.py", 8),
        ),
    )
    return EvidenceGraph(
        graph_id=graph_id,
        tenant_id=TENANT,
        head_sha=HEAD,
        candidates=(_candidate(candidate_id),),
        evidence=evidence,
        edges=tuple(_edge(item.evidence_id, candidate_id) for item in evidence),
    )


def _finding(
    graph: EvidenceGraph,
    *,
    finding_id: str = "finding-1",
    candidate_id: str = "candidate-1",
    verdict: FindingVerdict = FindingVerdict.CONFIRMED,
) -> FindingCase:
    return FindingCase(
        schema_version=CONTRACT_SCHEMA_VERSION,
        finding_id=finding_id,
        candidate_id=candidate_id,
        candidate_version=1,
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=TENANT,
            scm_provider="git",
            repository_id="repo-1",
            head_sha=HEAD,
        ),
        root_cause_fingerprint=ROOT_CAUSE,
        candidate_origin=CandidateOrigin.DETERMINISTIC,
        producer_lineage=_candidate(candidate_id).lineage,
        locations=(_location("src/in.py", 2), _location("src/db.py", 8)),
        cwe_id="CWE-89",
        evidence_graph_ref=ArtifactRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=TENANT,
            content_id=graph.graph_id,
            content_sha256=graph.graph_sha256,
            size_bytes=0,
            data_class=DataClass.INTERNAL_METADATA,
        ),
        evidence_ids=("evidence-source", "evidence-propagation", "evidence-sink"),
        interpretation_receipt_id="receipt-1",
        finding_verdict=verdict,
        verdict_evidence_ids=("evidence-source",),
        blocking=True,
    )


def _refs() -> RootCauseEvidenceRefs:
    return RootCauseEvidenceRefs(
        source_evidence_id="evidence-source",
        propagation_evidence_id="evidence-propagation",
        sink_evidence_id="evidence-sink",
    )


def test_localizes_confirmed_cwe89_source_propagation_and_sink_chain() -> None:
    graph = _graph()
    receipt = localize_root_cause(_finding(graph), graph, _refs())

    assert receipt.status is RootCauseLocalizationStatus.CONFIRMED
    assert receipt.reason is RootCauseLocalizationReason.CONFIRMED
    assert receipt.record is not None
    assert receipt.record.finding_id == "finding-1"
    assert receipt.record.repository_id == "repo-1"
    assert receipt.record.evidence == _refs()
    assert "src/" not in receipt.record.record_id


def test_equivalent_surface_locations_preserve_the_same_root_cause_fingerprint() -> None:
    first_graph = _graph()
    second_graph = _graph(candidate_id="candidate-2", graph_id="graph-2")
    first = localize_root_cause(_finding(first_graph), first_graph, _refs())
    second = localize_root_cause(
        _finding(second_graph, finding_id="finding-2", candidate_id="candidate-2"),
        second_graph,
        _refs(),
    )

    assert first.record is not None
    assert second.record is not None
    assert first.record.root_cause_fingerprint == second.record.root_cause_fingerprint
    assert first.record.record_id != second.record.record_id


@pytest.mark.parametrize(
    ("finding", "graph", "reason"),
    [
        (
            lambda graph: _finding(graph, verdict=FindingVerdict.NEEDS_MORE_EVIDENCE),
            lambda graph: graph,
            RootCauseLocalizationReason.FINDING_NOT_CONFIRMED,
        ),
        (
            lambda graph: _finding(graph).model_copy(
                update={
                    "evidence_graph_ref": _finding(graph).evidence_graph_ref.model_copy(
                        update={"content_id": "other-graph"}
                    )
                }
            ),
            lambda graph: graph,
            RootCauseLocalizationReason.GRAPH_MISMATCH,
        ),
        (
            lambda graph: _finding_with_head_drift(graph),
            lambda graph: graph,
            RootCauseLocalizationReason.GRAPH_MISMATCH,
        ),
    ],
)
def test_non_confirming_finding_and_identity_drift_cannot_create_a_record(
    finding: Callable[[EvidenceGraph], FindingCase],
    graph: Callable[[EvidenceGraph], EvidenceGraph],
    reason: RootCauseLocalizationReason,
) -> None:
    baseline = _graph()
    receipt = localize_root_cause(finding(baseline), graph(baseline), _refs())

    assert receipt.status is RootCauseLocalizationStatus.NON_CONFIRMING
    assert receipt.reason is reason
    assert receipt.record is None


def _finding_with_head_drift(graph: EvidenceGraph) -> FindingCase:
    finding = _finding(graph)
    revision = finding.repository_revision.model_copy(update={"head_sha": "9" * 40})
    return finding.model_copy(update={"repository_revision": revision})


@pytest.mark.parametrize(
    ("refs", "reason"),
    [
        (
            RootCauseEvidenceRefs("missing", "evidence-propagation", "evidence-sink"),
            RootCauseLocalizationReason.EVIDENCE_MISSING,
        ),
        (
            RootCauseEvidenceRefs("evidence-source", "evidence-sink", "evidence-propagation"),
            RootCauseLocalizationReason.EVIDENCE_KIND_MISMATCH,
        ),
    ],
)
def test_missing_or_wrong_kind_evidence_is_non_confirming(
    refs: RootCauseEvidenceRefs,
    reason: RootCauseLocalizationReason,
) -> None:
    graph = _graph()
    receipt = localize_root_cause(_finding(graph), graph, refs)

    assert receipt.status is RootCauseLocalizationStatus.NON_CONFIRMING
    assert receipt.reason is reason
    assert receipt.record is None


def test_finding_scope_omission_and_same_surface_role_conflict_are_non_confirming() -> None:
    graph = _graph()
    scoped_finding = _finding(graph).model_copy(
        update={"evidence_ids": ("evidence-source", "evidence-sink")}
    )
    scoped = localize_root_cause(scoped_finding, graph, _refs())

    assert scoped.reason is RootCauseLocalizationReason.EVIDENCE_OUT_OF_SCOPE
    assert scoped.record is None

    source = _evidence(
        "evidence-source",
        EvidenceKind.SOURCE_LOCATION,
        location=_location("src/in.py", 2),
    )
    same_surface_sink = _evidence(
        "evidence-sink", EvidenceKind.SOURCE_LOCATION, location=_location("src/in.py", 2)
    )
    propagation = _evidence("evidence-propagation", EvidenceKind.DATA_FLOW, location=None)
    conflict_graph = EvidenceGraph(
        graph_id="graph-conflict",
        tenant_id=TENANT,
        head_sha=HEAD,
        candidates=(_candidate(),),
        evidence=(source, propagation, same_surface_sink),
        edges=(
            _edge("evidence-source", "candidate-1"),
            _edge("evidence-propagation", "candidate-1"),
            _edge("evidence-sink", "candidate-1"),
        ),
    )
    conflict = localize_root_cause(_finding(conflict_graph), conflict_graph, _refs())

    assert conflict.reason is RootCauseLocalizationReason.CAUSAL_ROLE_CONFLICT
    assert conflict.record is None


def test_tampered_retained_contracts_and_forged_records_are_rejected() -> None:
    graph = _graph()
    finding = _finding(graph)
    object.__setattr__(finding, "candidate_version", 0)

    with pytest.raises(RootCauseContractError):
        localize_root_cause(finding, graph, _refs())

    receipt = localize_root_cause(_finding(graph), graph, _refs())
    assert receipt.record is not None
    with pytest.raises(RootCauseContractError):
        replace(receipt.record, repository_id="other-repo")
    with pytest.raises(RootCauseContractError):
        RootCauseRecord(
            record_id="root-cause-forged",
            schema_version="1.0.0",
            finding_id=receipt.record.finding_id,
            candidate_id=receipt.record.candidate_id,
            candidate_version=receipt.record.candidate_version,
            tenant_id=receipt.record.tenant_id,
            repository_id=receipt.record.repository_id,
            head_sha=receipt.record.head_sha,
            root_cause_fingerprint=receipt.record.root_cause_fingerprint,
            evidence_graph_id=receipt.record.evidence_graph_id,
            evidence_graph_sha256=receipt.record.evidence_graph_sha256,
            evidence=receipt.record.evidence,
        )
