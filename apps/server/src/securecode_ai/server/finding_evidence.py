"""Read one finding's verified source-free evidence graph projection."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from securecode_ai.core.evidence_graph import (
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceNodeKind,
)

from .persistence import NotFoundError, RepositoryError
from .worker_completion_evidence import load_verified_evidence_graph
from .worker_findings import WorkerFindingRecord, parse_worker_findings
from .worker_queue_models import WorkerQueueConflict


class FindingEvidenceRepository(Protocol):
    def get_finding(self, tenant_id: str, finding_id: str) -> dict[str, object]: ...

    def get_run(self, tenant_id: str, run_id: str) -> dict[str, object]: ...

    def list_artifacts(self, tenant_id: str, run_id: str) -> dict[str, object]: ...


class FindingEvidenceReader:
    """Verify stored evidence and project only nodes tied to one finding."""

    __slots__ = ("_artifact_root", "_repository")

    def __init__(self, *, repository: FindingEvidenceRepository, artifact_root: Path) -> None:
        if (
            not callable(getattr(repository, "get_finding", None))
            or not callable(getattr(repository, "get_run", None))
            or not callable(getattr(repository, "list_artifacts", None))
            or not isinstance(artifact_root, Path)
        ):
            raise TypeError("finding evidence dependencies are invalid")
        self._repository = repository
        self._artifact_root = artifact_root

    def read(self, *, tenant_id: str, finding_id: str) -> dict[str, object]:
        finding = self._repository.get_finding(tenant_id, finding_id)
        record_document = {
            key: finding[key]
            for key in (
                "blocking",
                "confidence",
                "cwe_id",
                "evidence_graph_ref",
                "finding_id",
                "locations",
                "revision_sha",
                "root_cause_fingerprint",
                "severity",
                "verdict",
            )
            if key in finding
        }
        try:
            records = parse_worker_findings([record_document], required=True, supplied=True)
        except (TypeError, ValueError):
            raise RepositoryError("finding evidence record is invalid") from None
        if len(records) != 1:
            raise RepositoryError("finding evidence record is invalid")
        record = records[0]
        if record.evidence_graph_ref.tenant_id != tenant_id:
            raise RepositoryError("finding evidence identity is invalid")
        run_id = finding.get("run_id")
        if type(run_id) is not str or not run_id:
            raise RepositoryError("finding run binding is invalid")
        run = self._repository.get_run(tenant_id, run_id)
        if run.get("head_sha") != record.revision_sha:
            raise RepositoryError("finding evidence binding is invalid")

        artifacts = self._repository.list_artifacts(tenant_id, run_id)
        items = artifacts.get("items")
        if not isinstance(items, list):
            raise RepositoryError("finding artifact inventory is invalid")
        artifact = next(
            (
                item
                for item in items
                if isinstance(item, dict)
                and item.get("content_id") == record.evidence_graph_ref.content_id
                and item.get("content_sha256") == record.evidence_graph_ref.content_sha256
                and item.get("size_bytes") == record.evidence_graph_ref.size_bytes
                and item.get("data_class") == record.evidence_graph_ref.data_class.value
                and item.get("purpose") == "evidence-graph"
            ),
            None,
        )
        if not isinstance(artifact, dict):
            raise NotFoundError()
        try:
            graph = load_verified_evidence_graph(
                artifact_root=self._artifact_root,
                tenant_id=tenant_id,
                metadata=artifact,
            )
        except (KeyError, TypeError, ValueError, OSError, WorkerQueueConflict):
            raise RepositoryError("finding evidence artifact is invalid") from None
        if graph.tenant_id != tenant_id or graph.head_sha != record.revision_sha:
            raise RepositoryError("finding evidence identity is invalid")
        return _finding_projection(record, graph)


def _finding_projection(record: WorkerFindingRecord, graph: EvidenceGraph) -> dict[str, object]:
    candidates = tuple(
        item
        for item in graph.candidates
        if item.root_cause_fingerprint == record.root_cause_fingerprint
    )
    if not candidates:
        raise RepositoryError("finding evidence candidate is missing")

    candidate_ids = {item.candidate_id for item in candidates}
    evidence_ids = {identifier for item in candidates for identifier in item.evidence_ids}
    while True:
        derived_sources = {
            edge.target.node_id
            for edge in graph.edges
            if edge.kind is EvidenceEdgeKind.EVIDENCE_DERIVED_FROM
            and edge.source.node_id in evidence_ids
        }
        expanded = evidence_ids | derived_sources
        if expanded == evidence_ids:
            break
        evidence_ids = expanded

    evidence = tuple(item for item in graph.evidence if item.evidence_id in evidence_ids)
    edges = tuple(
        edge
        for edge in graph.edges
        if (
            edge.kind is EvidenceEdgeKind.CANDIDATE_EVIDENCE
            and edge.source.kind is EvidenceNodeKind.CANDIDATE
            and edge.source.node_id in candidate_ids
            and edge.target.node_id in evidence_ids
        )
        or (
            edge.kind is EvidenceEdgeKind.EVIDENCE_DERIVED_FROM
            and edge.source.node_id in evidence_ids
            and edge.target.node_id in evidence_ids
        )
    )
    return {
        "finding_id": record.finding_id,
        "revision_sha": record.revision_sha,
        "root_cause_fingerprint": record.root_cause_fingerprint,
        "evidence_graph_sha256": graph.graph_sha256,
        "candidates": [item.model_dump(mode="json") for item in candidates],
        "evidence": [item.model_dump(mode="json") for item in evidence],
        "edges": [
            {
                "kind": edge.kind.value,
                "source": {"kind": edge.source.kind.value, "node_id": edge.source.node_id},
                "target": {"kind": edge.target.kind.value, "node_id": edge.target.node_id},
            }
            for edge in edges
        ],
    }


__all__ = ["FindingEvidenceReader"]
