"""Focused P3.1 contracts for metadata-only Auditor context selection."""

from __future__ import annotations

import pytest
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ArtifactRef,
    CandidateOrigin,
    DataClass,
    DiscoveryCandidate,
    DiscoveryLane,
    Evidence,
    EvidenceInputRef,
    EvidenceKind,
    LineageRef,
    ProducerRef,
    TrustLabel,
)
from securecode_ai.core.evidence_graph import (
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceNodeKind,
    EvidenceNodeRef,
)
from securecode_ai.core.evidence_package import (
    EvidencePackageError,
    EvidencePackageErrorCode,
    EvidencePackageLimits,
    build_evidence_package,
)

HEAD = "1" * 40
SHA = "a" * 64


def _producer() -> ProducerRef:
    return ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="scanner",
        producer_version="1.0.0",
        producer_sha256=SHA,
    )


def _evidence(
    evidence_id: str,
    *,
    size_bytes: int = 4,
    data_class: DataClass = DataClass.CONFIDENTIAL_SECURITY,
    with_artifact: bool = True,
) -> Evidence:
    artifact = (
        ArtifactRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-a",
            content_id=f"content-{evidence_id}",
            content_sha256=SHA,
            size_bytes=size_bytes,
            data_class=data_class,
        )
        if with_artifact
        else None
    )
    return Evidence(
        schema_version=CONTRACT_SCHEMA_VERSION,
        evidence_id=evidence_id,
        tenant_id="tenant-a",
        head_sha=HEAD,
        evidence_kind=EvidenceKind.SCANNER_SIGNAL,
        producer=_producer(),
        trust_label=TrustLabel.TRUSTED_DETERMINISTIC,
        data_class=data_class,
        evidence_sha256=SHA,
        artifact_ref=artifact,
    )


def _graph(*evidence: Evidence) -> EvidenceGraph:
    evidence_ids = tuple(item.evidence_id for item in evidence)
    candidate = DiscoveryCandidate(
        schema_version=CONTRACT_SCHEMA_VERSION,
        candidate_id="candidate-a",
        tenant_id="tenant-a",
        candidate_version=1,
        head_sha=HEAD,
        root_cause_fingerprint=SHA,
        candidate_origin=CandidateOrigin.DETERMINISTIC,
        lineage=(
            LineageRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                lineage_id="lineage-a",
                lane=DiscoveryLane.DETERMINISTIC,
                producer=_producer(),
                root_cause_fingerprint=SHA,
                input_signal_ids=("signal-a",),
                evidence_ids=evidence_ids,
            ),
        ),
        evidence_ids=evidence_ids,
    )
    candidate_ref = EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, candidate.candidate_id)
    return EvidenceGraph(
        graph_id="graph-a",
        tenant_id="tenant-a",
        head_sha=HEAD,
        candidates=(candidate,),
        evidence=evidence,
        edges=tuple(
            EvidenceGraphEdge(
                EvidenceEdgeKind.CANDIDATE_EVIDENCE,
                candidate_ref,
                EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, item.evidence_id),
            )
            for item in evidence
        ),
    )


def test_context_selection_is_canonical_and_metadata_only() -> None:
    package = build_evidence_package(
        _graph(_evidence("evidence-b"), _evidence("evidence-a")), "candidate-a"
    )

    assert tuple(item.evidence_id for item in package.selected) == ("evidence-a", "evidence-b")
    assert tuple(item.content_id for item in package.model_evidence) == (
        "content-evidence-a",
        "content-evidence-b",
    )
    assert package.total_context_bytes == 8
    assert package.total_input_tokens == 2
    assert not package.truncated
    assert len(package.selection_sha256) == 64
    assert all(
        EvidenceInputRef.model_validate(item.model_dump(mode="python")) == item
        for item in package.model_evidence
    )


def test_context_selection_records_deterministic_truncation() -> None:
    package = build_evidence_package(
        _graph(_evidence("evidence-b"), _evidence("evidence-a")),
        "candidate-a",
        limits=EvidencePackageLimits(max_context_bytes=4, max_input_tokens=1, max_evidence_items=1),
    )

    assert tuple(item.evidence_id for item in package.selected) == ("evidence-a",)
    assert package.omitted_evidence_ids == ("evidence-b",)
    assert package.truncated


@pytest.mark.parametrize(
    ("evidence", "expected"),
    [
        (
            _evidence("evidence-a", data_class=DataClass.RESTRICTED),
            EvidencePackageErrorCode.FORBIDDEN_DATA_CLASS,
        ),
        (
            _evidence("evidence-a", with_artifact=False),
            EvidencePackageErrorCode.EVIDENCE_UNAVAILABLE,
        ),
    ],
)
def test_context_selection_refuses_unavailable_or_restricted_evidence(
    evidence: Evidence, expected: EvidencePackageErrorCode
) -> None:
    with pytest.raises(EvidencePackageError) as raised:
        build_evidence_package(_graph(evidence), "candidate-a")

    assert raised.value.code is expected


def test_context_selection_never_issues_an_empty_auditor_context() -> None:
    with pytest.raises(EvidencePackageError) as raised:
        build_evidence_package(
            _graph(_evidence("evidence-a", size_bytes=8)),
            "candidate-a",
            limits=EvidencePackageLimits(
                max_context_bytes=4, max_input_tokens=1, max_evidence_items=1
            ),
        )

    assert raised.value.code is EvidencePackageErrorCode.BUDGET_EXHAUSTED
