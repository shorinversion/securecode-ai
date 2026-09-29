"""Read one finding's verified source-free evidence graph projection."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, TypeGuard

from securecode_ai.contracts import DataClass
from securecode_ai.core.evidence_graph import (
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceNodeKind,
)

from .persistence import NotFoundError, RepositoryError
from .residency_registry import ResidencyConflict, ResidencyDecision, ResidencyGuard
from .worker_completion_evidence import load_verified_evidence_graph
from .worker_findings import WorkerFindingRecord, parse_worker_findings
from .worker_queue_models import WorkerQueueConflict

_MAX_ARTIFACT_INVENTORY = 10_000
_ARTIFACT_PAGE_SIZE = 50
_MAX_ARTIFACT_PAGES = 256


class FindingEvidenceRepository(Protocol):
    def get_finding(self, tenant_id: str, finding_id: str) -> dict[str, object]: ...

    def get_run(self, tenant_id: str, run_id: str) -> dict[str, object]: ...

    def list_artifacts(
        self,
        tenant_id: str,
        run_id: str,
        cursor_token: str | None = None,
        limit: int = 50,
    ) -> dict[str, object]: ...


class FindingEvidenceReader:
    """Verify stored evidence and project only nodes tied to one finding."""

    __slots__ = ("_artifact_root", "_repository", "_residency_guard", "_residency_region")

    def __init__(
        self,
        *,
        repository: FindingEvidenceRepository,
        artifact_root: Path,
        residency_guard: ResidencyGuard | None = None,
        residency_region: str | None = None,
    ) -> None:
        if (
            not callable(getattr(repository, "get_finding", None))
            or not callable(getattr(repository, "get_run", None))
            or not callable(getattr(repository, "list_artifacts", None))
            or not isinstance(artifact_root, Path)
            or (residency_guard is None) != (residency_region is None)
            or (
                residency_guard is not None
                and not callable(getattr(residency_guard, "require_region", None))
            )
        ):
            raise TypeError("finding evidence dependencies are invalid")
        self._repository = repository
        self._artifact_root = artifact_root
        self._residency_guard = residency_guard
        self._residency_region = residency_region

    def read(self, *, tenant_id: str, finding_id: str) -> dict[str, object]:
        self._require_residency(tenant_id)
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
        if record.finding_id != finding_id or record.evidence_graph_ref.tenant_id != tenant_id:
            raise RepositoryError("finding evidence identity is invalid")
        run_id = finding.get("run_id")
        if type(run_id) is not str or not run_id:
            raise RepositoryError("finding run binding is invalid")
        run = self._repository.get_run(tenant_id, run_id)
        if not isinstance(run, Mapping) or run.get("head_sha") != record.revision_sha:
            raise RepositoryError("finding evidence binding is invalid")

        artifact = self._find_evidence_artifact(
            tenant_id=tenant_id,
            run_id=run_id,
            content_id=record.evidence_graph_ref.content_id,
            content_sha256=record.evidence_graph_ref.content_sha256,
            size_bytes=record.evidence_graph_ref.size_bytes,
            data_class=record.evidence_graph_ref.data_class.value,
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

    def _find_evidence_artifact(
        self,
        *,
        tenant_id: str,
        run_id: str,
        content_id: str,
        content_sha256: str,
        size_bytes: int,
        data_class: str,
    ) -> dict[str, object] | None:
        """Find the exact graph reference across bounded artifact pages."""

        cursor: str | None = None
        seen_cursors: set[str] = set()
        scanned = 0
        for _ in range(_MAX_ARTIFACT_PAGES):
            if cursor is None:
                page = self._repository.list_artifacts(tenant_id, run_id)
            else:
                page = self._repository.list_artifacts(
                    tenant_id,
                    run_id,
                    cursor,
                    _ARTIFACT_PAGE_SIZE,
                )
            if not isinstance(page, Mapping):
                raise RepositoryError("finding artifact inventory is invalid")
            keys = frozenset(page)
            if keys not in {frozenset({"items"}), frozenset({"items", "next_cursor"})}:
                raise RepositoryError("finding artifact inventory is invalid")
            items = page.get("items")
            if (
                not isinstance(items, list)
                or len(items) > _ARTIFACT_PAGE_SIZE
                or any(not isinstance(item, dict) for item in items)
            ):
                raise RepositoryError("finding artifact inventory is invalid")
            scanned += len(items)
            if scanned > _MAX_ARTIFACT_INVENTORY:
                raise RepositoryError("finding artifact inventory is too large")
            artifact: dict[str, object] | None = next(
                (
                    item
                    for item in items
                    if (
                        (item.get("tenant_id") is None or item.get("tenant_id") == tenant_id)
                        and (item.get("run_id") is None or item.get("run_id") == run_id)
                        and item.get("content_id") == content_id
                        and item.get("content_sha256") == content_sha256
                        and item.get("size_bytes") == size_bytes
                        and item.get("data_class") == data_class
                        and item.get("purpose") == "evidence-graph"
                    )
                ),
                None,
            )
            if artifact is not None:
                return artifact
            if "next_cursor" not in page:
                if cursor is not None:
                    raise RepositoryError("finding artifact cursor is invalid")
                return None
            next_cursor = page["next_cursor"]
            if next_cursor is None:
                return None
            if (
                not _valid_artifact_cursor(next_cursor)
                or next_cursor == cursor
                or next_cursor in seen_cursors
                or not items
            ):
                raise RepositoryError("finding artifact cursor is invalid")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise RepositoryError("finding artifact inventory is too large")

    def _require_residency(self, tenant_id: str) -> None:
        guard = self._residency_guard
        if guard is None:
            return
        region = self._residency_region
        if type(region) is not str or not region:
            raise RepositoryError("finding evidence residency configuration is invalid")
        try:
            decision = guard.require_region(tenant_id=tenant_id, region=region)
        except ResidencyConflict:
            raise NotFoundError() from None
        except Exception:
            raise RepositoryError("finding evidence residency check failed") from None
        if (
            type(decision) is not ResidencyDecision
            or decision.tenant_id != tenant_id
            or decision.source_region != region
            or decision.destination_region != region
            or not decision.same_region
        ):
            raise RepositoryError("finding evidence residency decision is invalid")


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
    if any(
        item.data_class in {DataClass.CONFIDENTIAL_SOURCE, DataClass.RESTRICTED}
        for item in evidence
    ):
        raise RepositoryError("finding evidence is not source-free")
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


def _valid_artifact_cursor(value: object) -> TypeGuard[str]:
    return (
        type(value) is str
        and 1 <= len(value) <= 512
        and all(
            "A" <= character <= "Z"
            or "a" <= character <= "z"
            or "0" <= character <= "9"
            or character in {"_", "-"}
            for character in value
        )
    )


__all__ = ["FindingEvidenceReader"]
