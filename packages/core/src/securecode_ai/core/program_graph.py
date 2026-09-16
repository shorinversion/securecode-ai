"""Sealed, source-free language-neutral program-graph contracts.

``ProgramGraph`` deliberately models only structural containment and bounded
scanner-proven data-flow facts.  It is not an ``EvidenceGraph`` replacement and
does not claim call-target or interprocedural precision.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from .symbols import SourceRange

_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_REVISION: Final = re.compile(r"[0-9a-f]{40}\Z")
_REPOSITORY_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\Z")
_PATH_PART: Final = re.compile(r"[^\\/\x00-\x1f\x7f]{1,255}\Z")
_MAX_NODES: Final = 50_000
_MAX_EDGES: Final = 100_000
_GRAPH_AUTHORITY_KEY: Final = secrets.token_bytes(32)


class ProgramGraphErrorCode(StrEnum):
    """Closed, source-free validation outcomes for the internal graph."""

    INVALID_GRAPH = "INVALID_GRAPH"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    DUPLICATE_NODE = "DUPLICATE_NODE"
    DUPLICATE_EDGE = "DUPLICATE_EDGE"
    DANGLING_ENDPOINT = "DANGLING_ENDPOINT"
    INVALID_FLOW = "INVALID_FLOW"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class ProgramGraphError(ValueError):
    """Fixed, non-echoing graph validation failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: ProgramGraphErrorCode) -> None:
        if type(code) is not ProgramGraphErrorCode:
            raise TypeError("program graph error code is invalid")
        self.code = code
        self.safe_message = "program graph validation failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class ProgramGraphNodeKind(StrEnum):
    """Closed structural vocabulary shared by all admitted languages."""

    MODULE = "module"
    TYPE = "type"
    CALLABLE = "callable"
    HTTP_SOURCE = "http_source"
    INTERPOLATION = "interpolation"
    SQL_SINK = "sql_sink"


class ProgramGraphEdgeKind(StrEnum):
    """Closed relationship vocabulary; CALL is intentionally conservative."""

    CONTAINS = "contains"
    CALL = "call"
    DATA_FLOW = "data_flow"


def _valid_path(path: str) -> bool:
    parts = path.split("/")
    return bool(
        path
        and len(path.encode("utf-8")) <= 4096
        and not path.startswith("/")
        and "\\" not in path
        and all(part not in {"", ".", ".."} and _PATH_PART.fullmatch(part) for part in parts)
    )


def _range_payload(location: SourceRange | None) -> dict[str, object] | None:
    if location is None:
        return None
    return {
        "start_byte": location.start_byte,
        "end_byte": location.end_byte,
        "start_point": [location.start_point.row, location.start_point.column],
        "end_point": [location.end_point.row, location.end_point.column],
    }


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    ).hexdigest()


def _node_digest(
    *,
    kind: ProgramGraphNodeKind,
    language: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    location: SourceRange | None,
    symbol_id: str | None,
) -> str:
    return _canonical_hash(
        {
            "kind": kind.value,
            "language": language,
            "path": path,
            "content_sha256": content_sha256,
            "source_size_bytes": source_size_bytes,
            "location": _range_payload(location),
            "symbol_id": symbol_id,
        }
    )


@dataclass(frozen=True, slots=True)
class ProgramGraphNode:
    """One canonical structural node without retained source bytes or text."""

    node_id: str
    kind: ProgramGraphNodeKind
    language: str
    path: str
    content_sha256: str
    source_size_bytes: int
    location: SourceRange | None
    symbol_id: str | None = None

    def __post_init__(self) -> None:
        valid = (
            type(self.node_id) is str
            and _SHA256.fullmatch(self.node_id) is not None
            and type(self.kind) is ProgramGraphNodeKind
            and type(self.language) is str
            and self.language in {"python", "javascript", "typescript", "go"}
            and type(self.path) is str
            and _valid_path(self.path)
            and type(self.content_sha256) is str
            and _SHA256.fullmatch(self.content_sha256) is not None
            and type(self.source_size_bytes) is int
            and self.source_size_bytes >= 0
            and (self.location is None or type(self.location) is SourceRange)
            and (
                self.symbol_id is None
                or (type(self.symbol_id) is str and _SHA256.fullmatch(self.symbol_id))
            )
        )
        structural = self.kind in {
            ProgramGraphNodeKind.MODULE,
            ProgramGraphNodeKind.TYPE,
            ProgramGraphNodeKind.CALLABLE,
        }
        if (
            not valid
            or (self.location is not None and self.location.end_byte > self.source_size_bytes)
            or (structural and self.symbol_id is None)
            or (self.kind is ProgramGraphNodeKind.MODULE and self.location is not None)
            or (not structural and (self.location is None or self.symbol_id is not None))
            or self.node_id
            != _node_digest(
                kind=self.kind,
                language=self.language,
                path=self.path,
                content_sha256=self.content_sha256,
                source_size_bytes=self.source_size_bytes,
                location=self.location,
                symbol_id=self.symbol_id,
            )
        ):
            raise ProgramGraphError(ProgramGraphErrorCode.INVALID_GRAPH)

    @property
    def canonical_key(self) -> tuple[str, str, str]:
        return (self.path, self.kind.value, self.node_id)


@dataclass(frozen=True, slots=True)
class ProgramGraphEdge:
    """One typed directed relation between node IDs in the same graph."""

    kind: ProgramGraphEdgeKind
    source_node_id: str
    target_node_id: str

    def __post_init__(self) -> None:
        if (
            type(self.kind) is not ProgramGraphEdgeKind
            or type(self.source_node_id) is not str
            or _SHA256.fullmatch(self.source_node_id) is None
            or type(self.target_node_id) is not str
            or _SHA256.fullmatch(self.target_node_id) is None
            or self.source_node_id == self.target_node_id
        ):
            raise ProgramGraphError(ProgramGraphErrorCode.INVALID_GRAPH)

    @property
    def canonical_key(self) -> tuple[str, str, str]:
        return (self.kind.value, self.source_node_id, self.target_node_id)


@dataclass(frozen=True, slots=True)
class ProgramGraph:
    """Authority-sealed, canonical program graph for one immutable repository revision."""

    repository_id: str
    revision: str
    nodes: tuple[ProgramGraphNode, ...]
    edges: tuple[ProgramGraphEdge, ...]
    graph_sha256: str
    _authority_seal: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        valid = (
            type(self.repository_id) is str
            and _REPOSITORY_ID.fullmatch(self.repository_id) is not None
            and type(self.revision) is str
            and _REVISION.fullmatch(self.revision) is not None
            and type(self.nodes) is tuple
            and type(self.edges) is tuple
            and type(self.graph_sha256) is str
            and _SHA256.fullmatch(self.graph_sha256) is not None
            and type(self._authority_seal) is bytes
        )
        if not valid or len(self.nodes) > _MAX_NODES or len(self.edges) > _MAX_EDGES:
            raise ProgramGraphError(
                ProgramGraphErrorCode.LIMIT_EXCEEDED
                if valid
                else ProgramGraphErrorCode.INVALID_GRAPH
            )
        if any(type(item) is not ProgramGraphNode for item in self.nodes) or any(
            type(item) is not ProgramGraphEdge for item in self.edges
        ):
            raise ProgramGraphError(ProgramGraphErrorCode.INVALID_GRAPH)
        nodes = tuple(sorted(self.nodes, key=lambda item: item.canonical_key))
        edges = tuple(sorted(self.edges, key=lambda item: item.canonical_key))
        object.__setattr__(self, "nodes", nodes)
        object.__setattr__(self, "edges", edges)
        node_by_id = {item.node_id: item for item in nodes}
        if len(node_by_id) != len(nodes):
            raise ProgramGraphError(ProgramGraphErrorCode.DUPLICATE_NODE)
        edge_keys = tuple(item.canonical_key for item in edges)
        if len(edge_keys) != len(set(edge_keys)):
            raise ProgramGraphError(ProgramGraphErrorCode.DUPLICATE_EDGE)
        if any(
            edge.source_node_id not in node_by_id or edge.target_node_id not in node_by_id
            for edge in edges
        ):
            raise ProgramGraphError(ProgramGraphErrorCode.DANGLING_ENDPOINT)
        if any(node.language not in {"python", "javascript", "typescript", "go"} for node in nodes):
            raise ProgramGraphError(ProgramGraphErrorCode.IDENTITY_MISMATCH)
        self._validate_edges(node_by_id, edges)
        if self.graph_sha256 != _canonical_hash(self.canonical_payload) or not hmac.compare_digest(
            self._authority_seal, _authority_seal(self.graph_sha256)
        ):
            raise ProgramGraphError(ProgramGraphErrorCode.INTEGRITY_FAILURE)

    @property
    def canonical_payload(self) -> dict[str, object]:
        """Source-free exact payload covered by ``graph_sha256``."""

        return {
            "repository_id": self.repository_id,
            "revision": self.revision,
            "nodes": [
                {
                    "node_id": item.node_id,
                    "kind": item.kind.value,
                    "language": item.language,
                    "path": item.path,
                    "content_sha256": item.content_sha256,
                    "source_size_bytes": item.source_size_bytes,
                    "location": _range_payload(item.location),
                    "symbol_id": item.symbol_id,
                }
                for item in self.nodes
            ],
            "edges": [
                {
                    "kind": item.kind.value,
                    "source_node_id": item.source_node_id,
                    "target_node_id": item.target_node_id,
                }
                for item in self.edges
            ],
        }

    @staticmethod
    def _validate_edges(
        nodes: dict[str, ProgramGraphNode], edges: tuple[ProgramGraphEdge, ...]
    ) -> None:
        for edge in edges:
            source = nodes[edge.source_node_id]
            target = nodes[edge.target_node_id]
            same_file = (
                source.language == target.language
                and source.path == target.path
                and source.content_sha256 == target.content_sha256
                and source.source_size_bytes == target.source_size_bytes
            )
            if edge.kind is ProgramGraphEdgeKind.CONTAINS:
                if (
                    not same_file
                    or source.kind
                    not in {
                        ProgramGraphNodeKind.MODULE,
                        ProgramGraphNodeKind.TYPE,
                        ProgramGraphNodeKind.CALLABLE,
                    }
                    or target.kind not in {ProgramGraphNodeKind.TYPE, ProgramGraphNodeKind.CALLABLE}
                ):
                    raise ProgramGraphError(ProgramGraphErrorCode.INVALID_FLOW)
            elif edge.kind is ProgramGraphEdgeKind.CALL:
                if (
                    source.language != target.language
                    or (source.path == target.path and not same_file)
                    or source.kind is not ProgramGraphNodeKind.CALLABLE
                    or target.kind is not ProgramGraphNodeKind.CALLABLE
                ):
                    raise ProgramGraphError(ProgramGraphErrorCode.INVALID_FLOW)
            elif edge.kind is ProgramGraphEdgeKind.DATA_FLOW:
                allowed = {
                    (ProgramGraphNodeKind.HTTP_SOURCE, ProgramGraphNodeKind.INTERPOLATION),
                    (ProgramGraphNodeKind.INTERPOLATION, ProgramGraphNodeKind.SQL_SINK),
                }
                if not same_file or (source.kind, target.kind) not in allowed:
                    raise ProgramGraphError(ProgramGraphErrorCode.INVALID_FLOW)
            else:  # pragma: no cover - exact enum checked by ProgramGraphEdge
                raise ProgramGraphError(ProgramGraphErrorCode.INVALID_FLOW)


def _authority_seal(graph_sha256: str) -> bytes:
    return hmac.digest(_GRAPH_AUTHORITY_KEY, graph_sha256.encode("ascii"), "sha256")


def _build_program_graph(
    *,
    repository_id: str,
    revision: str,
    nodes: tuple[ProgramGraphNode, ...],
    edges: tuple[ProgramGraphEdge, ...],
) -> ProgramGraph:
    """Create a validated authority-sealed graph; intentionally not a Core export."""

    provisional = object.__new__(ProgramGraph)
    object.__setattr__(provisional, "repository_id", repository_id)
    object.__setattr__(provisional, "revision", revision)
    object.__setattr__(
        provisional, "nodes", tuple(sorted(nodes, key=lambda item: item.canonical_key))
    )
    object.__setattr__(
        provisional, "edges", tuple(sorted(edges, key=lambda item: item.canonical_key))
    )
    object.__setattr__(provisional, "graph_sha256", "0" * 64)
    object.__setattr__(provisional, "_authority_seal", b"")
    graph_sha256 = _canonical_hash(provisional.canonical_payload)
    return ProgramGraph(
        repository_id=repository_id,
        revision=revision,
        nodes=nodes,
        edges=edges,
        graph_sha256=graph_sha256,
        _authority_seal=_authority_seal(graph_sha256),
    )


__all__ = [
    "ProgramGraph",
    "ProgramGraphEdge",
    "ProgramGraphEdgeKind",
    "ProgramGraphError",
    "ProgramGraphErrorCode",
    "ProgramGraphNode",
    "ProgramGraphNodeKind",
]
