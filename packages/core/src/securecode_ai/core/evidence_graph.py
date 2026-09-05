"""Immutable, graph-runtime-independent evidence graph values.

The graph deliberately carries only typed contract metadata and content hashes.
It never carries source bytes, scanner payloads, or secret-bearing content.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from securecode_ai.contracts import DiscoveryCandidate, Evidence

_GRAPH_SCHEMA_VERSION: Final = "1.0.0"
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_MAX_CANDIDATES: Final = 4_096
_MAX_EVIDENCE: Final = 16_384
_MAX_EDGES: Final = 65_536


class EvidenceGraphErrorCode(StrEnum):
    """Closed, non-echoing graph-validation outcomes."""

    INVALID_GRAPH = "INVALID_GRAPH"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    DUPLICATE_NODE = "DUPLICATE_NODE"
    DANGLING_REFERENCE = "DANGLING_REFERENCE"
    INVALID_FLOW = "INVALID_FLOW"
    PROVENANCE_MISMATCH = "PROVENANCE_MISMATCH"
    CYCLE = "CYCLE"


class EvidenceGraphError(ValueError):
    """Safe validation error that never includes graph or repository content."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EvidenceGraphErrorCode) -> None:
        if type(code) is not EvidenceGraphErrorCode:
            raise TypeError("evidence graph error code is invalid")
        self.code = code
        self.safe_message = "evidence graph validation failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class EvidenceNodeKind(StrEnum):
    """The complete node vocabulary for EvidenceGraph v1."""

    CANDIDATE = "candidate"
    EVIDENCE = "evidence"


class EvidenceEdgeKind(StrEnum):
    """The complete directed edge vocabulary for EvidenceGraph v1."""

    CANDIDATE_EVIDENCE = "candidate_evidence"
    EVIDENCE_DERIVED_FROM = "evidence_derived_from"


@dataclass(frozen=True, slots=True, order=True)
class EvidenceNodeRef:
    """A typed graph-local reference; identifiers are never untyped edge endpoints."""

    kind: EvidenceNodeKind
    node_id: str

    def __post_init__(self) -> None:
        if (
            type(self.kind) is not EvidenceNodeKind
            or type(self.node_id) is not str
            or _ID.fullmatch(self.node_id) is None
        ):
            raise EvidenceGraphError(EvidenceGraphErrorCode.INVALID_GRAPH)


@dataclass(frozen=True, slots=True)
class EvidenceGraphNode:
    """A closed typed node retaining immutable contract metadata only."""

    ref: EvidenceNodeRef
    value: DiscoveryCandidate | Evidence

    def __post_init__(self) -> None:
        if type(self.ref) is not EvidenceNodeRef:
            raise EvidenceGraphError(EvidenceGraphErrorCode.INVALID_GRAPH)
        if self.ref.kind is EvidenceNodeKind.CANDIDATE:
            if (
                type(self.value) is not DiscoveryCandidate
                or self.ref.node_id != self.value.candidate_id
            ):
                raise EvidenceGraphError(EvidenceGraphErrorCode.INVALID_GRAPH)
        elif self.ref.kind is EvidenceNodeKind.EVIDENCE:
            if type(self.value) is not Evidence or self.ref.node_id != self.value.evidence_id:
                raise EvidenceGraphError(EvidenceGraphErrorCode.INVALID_GRAPH)
        else:
            raise EvidenceGraphError(EvidenceGraphErrorCode.INVALID_GRAPH)


@dataclass(frozen=True, slots=True)
class EvidenceGraphEdge:
    """A typed, runtime-independent relationship between EvidenceGraph nodes."""

    kind: EvidenceEdgeKind
    source: EvidenceNodeRef
    target: EvidenceNodeRef

    def __post_init__(self) -> None:
        if (
            type(self.kind) is not EvidenceEdgeKind
            or type(self.source) is not EvidenceNodeRef
            or type(self.target) is not EvidenceNodeRef
        ):
            raise EvidenceGraphError(EvidenceGraphErrorCode.INVALID_GRAPH)

    @property
    def canonical_key(self) -> tuple[str, str, str, str, str]:
        return (
            self.kind.value,
            self.source.kind.value,
            self.source.node_id,
            self.target.kind.value,
            self.target.node_id,
        )


@dataclass(frozen=True, slots=True)
class EvidenceGraph:
    """Validated evidence DAG for one tenant and immutable repository head.

    Candidate-to-evidence edges are exact mirrors of ``DiscoveryCandidate.evidence_ids``.
    ``EVIDENCE_DERIVED_FROM`` points from derived evidence to its source evidence;
    the whole directed graph must be acyclic and every evidence node must be
    reachable from a candidate.  This intentionally has no WorkflowGraph or
    graph-runtime dependency.
    """

    graph_id: str
    tenant_id: str
    head_sha: str
    candidates: tuple[DiscoveryCandidate, ...]
    evidence: tuple[Evidence, ...]
    edges: tuple[EvidenceGraphEdge, ...]
    schema_version: str = _GRAPH_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.graph_id) is not str
            or _ID.fullmatch(self.graph_id) is None
            or type(self.tenant_id) is not str
            or _ID.fullmatch(self.tenant_id) is None
            or type(self.head_sha) is not str
            or _COMMIT_SHA.fullmatch(self.head_sha) is None
            or self.schema_version != _GRAPH_SCHEMA_VERSION
            or type(self.candidates) is not tuple
            or type(self.evidence) is not tuple
            or type(self.edges) is not tuple
        ):
            raise EvidenceGraphError(EvidenceGraphErrorCode.INVALID_GRAPH)
        if (
            len(self.candidates) > _MAX_CANDIDATES
            or len(self.evidence) > _MAX_EVIDENCE
            or len(self.edges) > _MAX_EDGES
        ):
            raise EvidenceGraphError(EvidenceGraphErrorCode.LIMIT_EXCEEDED)
        if (
            any(type(item) is not DiscoveryCandidate for item in self.candidates)
            or any(type(item) is not Evidence for item in self.evidence)
            or any(type(item) is not EvidenceGraphEdge for item in self.edges)
        ):
            raise EvidenceGraphError(EvidenceGraphErrorCode.INVALID_GRAPH)

        try:
            candidates = tuple(
                sorted(
                    (_canonical_candidate(_validated_candidate(item)) for item in self.candidates),
                    key=lambda item: item.candidate_id,
                )
            )
            evidence = tuple(
                sorted(
                    (_validated_evidence(item) for item in self.evidence),
                    key=lambda item: item.evidence_id,
                )
            )
        except (TypeError, ValueError):
            raise EvidenceGraphError(EvidenceGraphErrorCode.INVALID_GRAPH) from None
        edges = tuple(sorted(self.edges, key=lambda item: item.canonical_key))
        object.__setattr__(self, "candidates", candidates)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "edges", edges)

        candidate_by_id = {item.candidate_id: item for item in candidates}
        evidence_by_id = {item.evidence_id: item for item in evidence}
        if len(candidate_by_id) != len(candidates) or len(evidence_by_id) != len(evidence):
            raise EvidenceGraphError(EvidenceGraphErrorCode.DUPLICATE_NODE)
        candidate_identity_mismatch = any(
            candidate.tenant_id != self.tenant_id or candidate.head_sha != self.head_sha
            for candidate in candidates
        )
        evidence_identity_mismatch = any(
            item.tenant_id != self.tenant_id or item.head_sha != self.head_sha for item in evidence
        )
        if candidate_identity_mismatch or evidence_identity_mismatch:
            raise EvidenceGraphError(EvidenceGraphErrorCode.IDENTITY_MISMATCH)

        self._validate_candidate_provenance(candidates, evidence_by_id)
        self._validate_edges(candidate_by_id, evidence_by_id, edges)

    @property
    def nodes(self) -> tuple[EvidenceGraphNode, ...]:
        """Canonical node order: candidates first, then evidence, each by ID."""

        return (
            *(
                EvidenceGraphNode(
                    EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, item.candidate_id), item
                )
                for item in self.candidates
            ),
            *(
                EvidenceGraphNode(
                    EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, item.evidence_id), item
                )
                for item in self.evidence
            ),
        )

    @property
    def canonical_payload(self) -> dict[str, object]:
        """Return a source-free canonical representation used for the graph hash."""

        return {
            "schema_version": self.schema_version,
            "tenant_id": self.tenant_id,
            "head_sha": self.head_sha,
            "candidates": [item.model_dump(mode="json") for item in self.candidates],
            "evidence": [item.model_dump(mode="json") for item in self.evidence],
            "edges": [
                {
                    "kind": item.kind.value,
                    "source": {"kind": item.source.kind.value, "node_id": item.source.node_id},
                    "target": {"kind": item.target.kind.value, "node_id": item.target.node_id},
                }
                for item in self.edges
            ],
        }

    @property
    def graph_sha256(self) -> str:
        """Stable hash of the canonical, source-free graph payload."""

        return _canonical_hash(self.canonical_payload)

    def _validate_candidate_provenance(
        self,
        candidates: Iterable[DiscoveryCandidate],
        evidence_by_id: dict[str, Evidence],
    ) -> None:
        for candidate in candidates:
            if not candidate.evidence_ids:
                raise EvidenceGraphError(EvidenceGraphErrorCode.DANGLING_REFERENCE)
            for evidence_id in candidate.evidence_ids:
                if evidence_id not in evidence_by_id:
                    raise EvidenceGraphError(EvidenceGraphErrorCode.DANGLING_REFERENCE)
            for lineage in candidate.lineage:
                for evidence_id in lineage.evidence_ids:
                    evidence = evidence_by_id.get(evidence_id)
                    if evidence is None:
                        raise EvidenceGraphError(EvidenceGraphErrorCode.DANGLING_REFERENCE)
                    if evidence.producer != lineage.producer:
                        raise EvidenceGraphError(EvidenceGraphErrorCode.PROVENANCE_MISMATCH)

    def _validate_edges(
        self,
        candidate_by_id: dict[str, DiscoveryCandidate],
        evidence_by_id: dict[str, Evidence],
        edges: tuple[EvidenceGraphEdge, ...],
    ) -> None:
        node_refs = {
            *(EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, item_id) for item_id in candidate_by_id),
            *(EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, item_id) for item_id in evidence_by_id),
        }
        if any(edge.source not in node_refs or edge.target not in node_refs for edge in edges):
            raise EvidenceGraphError(EvidenceGraphErrorCode.DANGLING_REFERENCE)
        edge_keys = tuple(edge.canonical_key for edge in edges)
        if len(edge_keys) != len(set(edge_keys)):
            raise EvidenceGraphError(EvidenceGraphErrorCode.DUPLICATE_NODE)

        expected_links = {
            (candidate.candidate_id, evidence_id)
            for candidate in candidate_by_id.values()
            for evidence_id in candidate.evidence_ids
        }
        actual_links: set[tuple[str, str]] = set()
        adjacency: dict[EvidenceNodeRef, set[EvidenceNodeRef]] = {
            node_ref: set() for node_ref in node_refs
        }
        for edge in edges:
            if edge.kind is EvidenceEdgeKind.CANDIDATE_EVIDENCE:
                if (
                    edge.source.kind is not EvidenceNodeKind.CANDIDATE
                    or edge.target.kind is not EvidenceNodeKind.EVIDENCE
                ):
                    raise EvidenceGraphError(EvidenceGraphErrorCode.INVALID_FLOW)
                actual_links.add((edge.source.node_id, edge.target.node_id))
            elif edge.kind is EvidenceEdgeKind.EVIDENCE_DERIVED_FROM:
                if (
                    edge.source.kind is not EvidenceNodeKind.EVIDENCE
                    or edge.target.kind is not EvidenceNodeKind.EVIDENCE
                    or edge.source == edge.target
                ):
                    raise EvidenceGraphError(EvidenceGraphErrorCode.INVALID_FLOW)
            else:  # pragma: no cover - closed enum and exact type are checked above
                raise EvidenceGraphError(EvidenceGraphErrorCode.INVALID_FLOW)
            adjacency[edge.source].add(edge.target)
        if actual_links != expected_links:
            raise EvidenceGraphError(EvidenceGraphErrorCode.DANGLING_REFERENCE)
        self._reject_cycles(adjacency)

        reachable: set[EvidenceNodeRef] = set()
        pending = [
            EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, candidate_id)
            for candidate_id in candidate_by_id
        ]
        while pending:
            current = pending.pop()
            if current in reachable:
                continue
            reachable.add(current)
            pending.extend(adjacency[current] - reachable)
        if any(
            EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, evidence_id) not in reachable
            for evidence_id in evidence_by_id
        ):
            raise EvidenceGraphError(EvidenceGraphErrorCode.DANGLING_REFERENCE)

    @staticmethod
    def _reject_cycles(adjacency: dict[EvidenceNodeRef, set[EvidenceNodeRef]]) -> None:
        """Use iterative topological elimination so bounded deep DAGs cannot recurse."""

        incoming = dict.fromkeys(adjacency, 0)
        for targets in adjacency.values():
            for target in targets:
                incoming[target] += 1
        pending = sorted(node for node, count in incoming.items() if count == 0)
        eliminated = 0
        while pending:
            node = pending.pop()
            eliminated += 1
            for target in sorted(adjacency[node], reverse=True):
                incoming[target] -= 1
                if incoming[target] == 0:
                    pending.append(target)
        if eliminated != len(adjacency):
            raise EvidenceGraphError(EvidenceGraphErrorCode.CYCLE)


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


def _canonical_candidate(candidate: DiscoveryCandidate) -> DiscoveryCandidate:
    """Canonicalize set-like lineage references before they enter the graph hash."""

    lineage = tuple(
        sorted(
            (
                item.model_copy(
                    update={
                        "input_signal_ids": tuple(sorted(item.input_signal_ids)),
                        "input_candidate_ids": tuple(sorted(item.input_candidate_ids)),
                        "evidence_ids": tuple(sorted(item.evidence_ids)),
                    }
                )
                for item in candidate.lineage
            ),
            key=lambda item: item.lineage_id,
        )
    )
    material = candidate.model_dump(mode="python")
    material["lineage"] = lineage
    material["evidence_ids"] = tuple(sorted(candidate.evidence_ids))
    return DiscoveryCandidate.model_validate(material)


def _validated_candidate(candidate: DiscoveryCandidate) -> DiscoveryCandidate:
    return DiscoveryCandidate.model_validate(candidate.model_dump(mode="python"))


def _validated_evidence(evidence: Evidence) -> Evidence:
    return Evidence.model_validate(evidence.model_dump(mode="python"))


__all__ = [
    "EvidenceEdgeKind",
    "EvidenceGraph",
    "EvidenceGraphEdge",
    "EvidenceGraphError",
    "EvidenceGraphErrorCode",
    "EvidenceGraphNode",
    "EvidenceNodeKind",
    "EvidenceNodeRef",
]
