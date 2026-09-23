"""Verified, tenant-scoped finding evidence projection tests."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

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
    LineageRef,
    ProducerRef,
    SourceLocation,
    SourcePosition,
    TrustLabel,
)
from securecode_ai.server.finding_evidence import FindingEvidenceReader
from securecode_ai.server.persistence import NotFoundError, RepositoryError
from securecode_ai.server.ports import ServiceRequest, VerifiedIdentity
from securecode_ai.server.service import DurableControlPlaneService

TENANT = "tenant-1"
HEAD = "a" * 40
FINGERPRINT = "b" * 64


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _graph_payload() -> dict[str, object]:
    producer = ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="scanner",
        producer_version="1.0.0",
        producer_sha256="c" * 64,
    )
    evidence = Evidence(
        schema_version=CONTRACT_SCHEMA_VERSION,
        evidence_id="evidence-1",
        tenant_id=TENANT,
        head_sha=HEAD,
        evidence_kind=EvidenceKind.SCANNER_SIGNAL,
        producer=producer,
        trust_label=TrustLabel.TRUSTED_DETERMINISTIC,
        data_class=DataClass.INTERNAL_METADATA,
        evidence_sha256="d" * 64,
        location=SourceLocation(
            schema_version=CONTRACT_SCHEMA_VERSION,
            path="src/app.py",
            start=SourcePosition(schema_version=CONTRACT_SCHEMA_VERSION, line=1, column=1),
            end=SourcePosition(schema_version=CONTRACT_SCHEMA_VERSION, line=1, column=2),
            content_sha256="e" * 64,
        ),
    )
    lineage = LineageRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        lineage_id="lineage-1",
        lane=DiscoveryLane.DETERMINISTIC,
        producer=producer,
        root_cause_fingerprint=FINGERPRINT,
        input_signal_ids=("signal-1",),
        evidence_ids=("evidence-1",),
    )
    candidate = DiscoveryCandidate(
        schema_version=CONTRACT_SCHEMA_VERSION,
        candidate_id="candidate-1",
        tenant_id=TENANT,
        candidate_version=1,
        head_sha=HEAD,
        root_cause_fingerprint=FINGERPRINT,
        candidate_origin=CandidateOrigin.DETERMINISTIC,
        lineage=(lineage,),
        evidence_ids=("evidence-1",),
    )
    from securecode_ai.core.evidence_graph import (
        EvidenceEdgeKind,
        EvidenceGraph,
        EvidenceGraphEdge,
        EvidenceNodeKind,
        EvidenceNodeRef,
    )

    graph = EvidenceGraph(
        graph_id="graph-fixture",
        tenant_id=TENANT,
        head_sha=HEAD,
        candidates=(candidate,),
        evidence=(evidence,),
        edges=(
            EvidenceGraphEdge(
                EvidenceEdgeKind.CANDIDATE_EVIDENCE,
                EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, "candidate-1"),
                EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, "evidence-1"),
            ),
        ),
    )
    return graph.canonical_payload


@dataclass
class _Repository:
    finding: dict[str, object]
    run: dict[str, object]
    artifact: dict[str, object]

    def get_finding(self, tenant_id: str, finding_id: str) -> dict[str, object]:
        assert tenant_id == TENANT
        assert finding_id == "finding-1"
        return self.finding

    def get_run(self, tenant_id: str, run_id: str) -> dict[str, object]:
        assert tenant_id == TENANT
        assert run_id == "run-1"
        return self.run

    def list_artifacts(self, tenant_id: str, run_id: str) -> dict[str, object]:
        assert tenant_id == TENANT
        assert run_id == "run-1"
        return {"items": [self.artifact]}


def _fixture(tmp_path: Path) -> tuple[FindingEvidenceReader, Path, _Repository]:
    document = _graph_payload()
    payload = _canonical(document)
    digest = hashlib.sha256(payload).hexdigest()
    artifact_root = tmp_path / "artifacts"
    artifact_path = artifact_root / TENANT / digest[:2] / digest / "payload"
    artifact_path.parent.mkdir(parents=True)
    artifact_path.write_bytes(payload)
    artifact = {
        "content_id": "evidence-graph-1",
        "content_sha256": digest,
        "size_bytes": len(payload),
        "data_class": DataClass.CONFIDENTIAL_SECURITY.value,
        "purpose": "evidence-graph",
    }
    finding = {
        "finding_id": "finding-1",
        "run_id": "run-1",
        "revision_sha": HEAD,
        "blocking": False,
        "confidence": "UNSCORED",
        "cwe_id": "CWE-89",
        "evidence_graph_ref": ArtifactRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=TENANT,
            content_id="evidence-graph-1",
            content_sha256=digest,
            size_bytes=len(payload),
            data_class=DataClass.CONFIDENTIAL_SECURITY,
        ).model_dump(mode="json"),
        "locations": [{"path": "src/app.py", "start_line": 1, "end_line": 1}],
        "root_cause_fingerprint": FINGERPRINT,
        "severity": "HIGH",
        "verdict": "CONFIRMED",
    }
    repository = _Repository(
        finding,
        {"head_sha": HEAD, "repository_id": "repo-1"},
        artifact,
    )
    return (
        FindingEvidenceReader(repository=repository, artifact_root=artifact_root),
        artifact_path,
        repository,
    )


def test_reads_only_verified_nodes_linked_to_finding(tmp_path: Path) -> None:
    reader, _, _ = _fixture(tmp_path)

    result = reader.read(tenant_id=TENANT, finding_id="finding-1")

    assert result["finding_id"] == "finding-1"
    candidates = result["candidates"]
    evidence = result["evidence"]
    assert isinstance(candidates, list)
    assert isinstance(evidence, list)
    assert [item["candidate_id"] for item in candidates] == ["candidate-1"]
    assert [item["evidence_id"] for item in evidence] == ["evidence-1"]
    assert result["evidence_graph_sha256"]
    assert "source" not in result


def test_rejects_modified_content_addressed_payload(tmp_path: Path) -> None:
    reader, artifact_path, _ = _fixture(tmp_path)
    artifact_path.write_bytes(b"{}")

    with pytest.raises(RepositoryError):
        reader.read(tenant_id=TENANT, finding_id="finding-1")


def test_rejects_finding_bound_to_another_revision(tmp_path: Path) -> None:
    reader, _, repository = _fixture(tmp_path)
    repository.run["head_sha"] = "f" * 40

    with pytest.raises(RepositoryError):
        reader.read(tenant_id=TENANT, finding_id="finding-1")


def test_rejects_missing_matching_artifact(tmp_path: Path) -> None:
    reader, _, repository = _fixture(tmp_path)
    repository.artifact["content_sha256"] = "f" * 64

    with pytest.raises(NotFoundError):
        reader.read(tenant_id=TENANT, finding_id="finding-1")


def test_service_exposes_evidence_only_to_authorized_repository(tmp_path: Path) -> None:
    reader, _, repository = _fixture(tmp_path)
    service = DurableControlPlaneService(repository, finding_evidence=reader)  # type: ignore[arg-type]
    request = ServiceRequest(
        method="GET",
        route="/api/v1/findings/{finding_id}/evidence",
        action="findings.evidence.read",
        identity=VerifiedIdentity("user-1", TENANT, frozenset({"admin"})),
        idempotency_key=None,
        precondition=None,
        path_params={"finding_id": "finding-1"},
        query={},
        document=None,
        raw_body=b"",
    )

    response = asyncio.run(service.dispatch(request))

    assert response.status == 200
    assert response.document["finding_id"] == "finding-1"


def test_service_denies_evidence_for_ungranted_repository(tmp_path: Path) -> None:
    reader, _, repository = _fixture(tmp_path)
    service = DurableControlPlaneService(repository, finding_evidence=reader)  # type: ignore[arg-type]
    request = ServiceRequest(
        method="GET",
        route="/api/v1/findings/{finding_id}/evidence",
        action="findings.evidence.read",
        identity=VerifiedIdentity("user-1", TENANT, frozenset({"viewer"})),
        idempotency_key=None,
        precondition=None,
        path_params={"finding_id": "finding-1"},
        query={},
        document=None,
        raw_body=b"",
    )

    response = asyncio.run(service.dispatch(request))

    assert response.status == 403
