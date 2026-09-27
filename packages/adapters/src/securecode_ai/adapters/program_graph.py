"""Bounded conversion of sealed indexes and scanner facts into ProgramGraph."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core.program_graph import (
    _MAX_EDGES,
    _MAX_NODES,
    ProgramGraph,
    ProgramGraphEdge,
    ProgramGraphEdgeKind,
    ProgramGraphNode,
    ProgramGraphNodeKind,
    _build_program_graph,
    _node_digest,
)
from securecode_ai.core.symbols import SourceRange, SymbolIndex, SymbolKind

from .cwe89 import Cwe89ScanError, Cwe89ScanResult, scan_python_cwe89
from .cwe89_multilanguage import (
    MultilanguageCwe89ScanError,
    MultilanguageCwe89ScanResult,
    scan_go_cwe89,
    scan_javascript_cwe89,
    scan_typescript_cwe89,
)
from .python_ast import PythonAstError, analyze_python_ast

_SUPPORTED_LANGUAGES = frozenset({"python", "javascript", "typescript", "go"})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_LIMITS = (4_096, 20_000, 20_000, _MAX_NODES, _MAX_EDGES)


class ProgramGraphAdapterErrorCode(StrEnum):
    """Closed, source-free adapter failures."""

    REQUEST_INVALID = "REQUEST_INVALID"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    FACT_MISMATCH = "FACT_MISMATCH"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"


class ProgramGraphAdapterError(RuntimeError):
    """Fixed failure for graph conversion; never echoes program text."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: ProgramGraphAdapterErrorCode) -> None:
        if type(code) is not ProgramGraphAdapterErrorCode:
            raise TypeError("program graph adapter error code is invalid")
        self.code = code
        self.safe_message = "program graph conversion failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class ProgramCallFact:
    """Source-free, caller-supplied relation between sealed callable symbols."""

    repository_id: str
    revision: str
    caller_symbol_id: str
    callee_symbol_id: str

    def __post_init__(self) -> None:
        if (
            type(self.repository_id) is not str
            or not self.repository_id
            or type(self.revision) is not str
            or re.fullmatch(r"[0-9a-f]{40}", self.revision) is None
            or type(self.caller_symbol_id) is not str
            or _SHA256.fullmatch(self.caller_symbol_id) is None
            or type(self.callee_symbol_id) is not str
            or _SHA256.fullmatch(self.callee_symbol_id) is None
            or self.caller_symbol_id == self.callee_symbol_id
        ):
            raise ValueError("program call fact is invalid")


@dataclass(frozen=True, slots=True)
class ProgramGraphAdapterLimits:
    """Upper-bounded conversion inputs before Core graph construction."""

    max_symbol_indexes: int = _MAX_LIMITS[0]
    max_scanner_results: int = _MAX_LIMITS[1]
    max_call_facts: int = _MAX_LIMITS[2]
    max_nodes: int = _MAX_LIMITS[3]
    max_edges: int = _MAX_LIMITS[4]

    def __post_init__(self) -> None:
        values = (
            self.max_symbol_indexes,
            self.max_scanner_results,
            self.max_call_facts,
            self.max_nodes,
            self.max_edges,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("program graph adapter limits are invalid")


DEFAULT_PROGRAM_GRAPH_ADAPTER_LIMITS = ProgramGraphAdapterLimits()
_ScannerResult = Cwe89ScanResult | MultilanguageCwe89ScanResult


def build_program_graph(
    symbol_indexes: tuple[SymbolIndex, ...],
    scanner_results: tuple[_ScannerResult, ...],
    call_facts: tuple[ProgramCallFact, ...] = (),
    *,
    limits: ProgramGraphAdapterLimits = DEFAULT_PROGRAM_GRAPH_ADAPTER_LIMITS,
) -> ProgramGraph:
    """Build a source-free graph after independently revalidating every fact.

    CALL relationships are part of the shared Core contract but are not inferred
    here: the currently admitted scanners provide only bounded local
    source-to-interpolation-to-sink facts. This prevents a false claim of
    interprocedural precision.
    """

    if (
        type(symbol_indexes) is not tuple
        or type(scanner_results) is not tuple
        or type(call_facts) is not tuple
        or type(limits) is not ProgramGraphAdapterLimits
        or any(type(item) is not SymbolIndex for item in symbol_indexes)
        or any(
            type(item) not in {Cwe89ScanResult, MultilanguageCwe89ScanResult}
            for item in scanner_results
        )
        or any(type(item) is not ProgramCallFact for item in call_facts)
    ):
        raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.REQUEST_INVALID)
    if (
        len(symbol_indexes) > limits.max_symbol_indexes
        or len(scanner_results) > limits.max_scanner_results
        or len(call_facts) > limits.max_call_facts
    ):
        raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.LIMIT_EXCEEDED)
    if not symbol_indexes or len(scanner_results) != len(symbol_indexes):
        raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.REQUEST_INVALID)

    # Structural nodes and validated call facts are unique across admitted
    # paths. Reject a lower-bound overflow before rescanning, constructing
    # nodes, or sorting aggregates.
    structural_nodes = 0
    structural_edges = len(call_facts)
    for index in symbol_indexes:
        structural_nodes += len(index.symbols)
        structural_edges += max(0, len(index.symbols) - 1)
        if structural_nodes > limits.max_nodes or structural_edges > limits.max_edges:
            raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.LIMIT_EXCEEDED)

    indexes = tuple(sorted(symbol_indexes, key=lambda item: (item.path, item.content_sha256)))
    repository_id = indexes[0].repository_id
    revision = indexes[0].revision
    index_keys = {(item.path, item.content_sha256) for item in indexes}
    index_paths = {item.path for item in indexes}
    if (
        len(index_keys) != len(indexes)
        or any(
            item.repository_id != repository_id
            or item.revision != revision
            or item.language not in _SUPPORTED_LANGUAGES
            for item in indexes
        )
        or len(index_paths) != len(indexes)
    ):
        raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.IDENTITY_MISMATCH)

    facts_by_key: dict[tuple[str, str], _ScannerResult] = {}
    for result in scanner_results:
        key = (result.path, result.content_sha256)
        if (
            key in facts_by_key
            or result.repository_id != repository_id
            or result.revision != revision
            or key not in index_keys
        ):
            raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.IDENTITY_MISMATCH)
        facts_by_key[key] = result
    if set(facts_by_key) != index_keys:
        raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.IDENTITY_MISMATCH)

    nodes: dict[str, ProgramGraphNode] = {}
    edges: set[ProgramGraphEdge] = set()
    callable_nodes: dict[str, ProgramGraphNode] = {}
    for index in indexes:
        result = facts_by_key[(index.path, index.content_sha256)]
        _validate_scanner_result(index, result)
        symbol_nodes = _symbol_nodes(index, nodes, limits)
        callable_nodes.update(
            {
                symbol.symbol_id: symbol_nodes[symbol.symbol_id]
                for symbol in index.symbols
                if symbol_nodes[symbol.symbol_id].kind is ProgramGraphNodeKind.CALLABLE
            }
        )
        for symbol in index.symbols[1:]:
            parent = symbol_nodes.get(symbol.parent_symbol_id or "")
            child = symbol_nodes[symbol.symbol_id]
            if parent is None:
                raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.FACT_MISMATCH)
            _admit_edge(
                edges,
                ProgramGraphEdge(ProgramGraphEdgeKind.CONTAINS, parent.node_id, child.node_id),
                limits,
            )
        for signal in result.signals:
            source = _fact_node(index, ProgramGraphNodeKind.HTTP_SOURCE, signal.source)
            _admit_node(nodes, source, limits)
            interpolation = _fact_node(
                index, ProgramGraphNodeKind.INTERPOLATION, signal.interpolation
            )
            _admit_node(nodes, interpolation, limits)
            sink = _fact_node(index, ProgramGraphNodeKind.SQL_SINK, signal.sink)
            _admit_node(nodes, sink, limits)
            for edge in (
                ProgramGraphEdge(
                    ProgramGraphEdgeKind.DATA_FLOW, source.node_id, interpolation.node_id
                ),
                ProgramGraphEdge(
                    ProgramGraphEdgeKind.DATA_FLOW, interpolation.node_id, sink.node_id
                ),
            ):
                _admit_edge(edges, edge, limits)
    _add_call_edges(
        repository_id=repository_id,
        revision=revision,
        call_facts=call_facts,
        callable_nodes=callable_nodes,
        edges=edges,
        limits=limits,
    )
    return _build_program_graph(
        repository_id=repository_id,
        revision=revision,
        nodes=tuple(nodes.values()),
        edges=tuple(edges),
    )


def _admit_node(
    nodes: dict[str, ProgramGraphNode],
    node: ProgramGraphNode,
    limits: ProgramGraphAdapterLimits,
) -> None:
    if node.node_id not in nodes:
        if len(nodes) >= limits.max_nodes:
            raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.LIMIT_EXCEEDED)
        nodes[node.node_id] = node


def _admit_edge(
    edges: set[ProgramGraphEdge],
    edge: ProgramGraphEdge,
    limits: ProgramGraphAdapterLimits,
) -> None:
    if edge not in edges:
        if len(edges) >= limits.max_edges:
            raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.LIMIT_EXCEEDED)
        edges.add(edge)


def _add_call_edges(
    *,
    repository_id: str,
    revision: str,
    call_facts: tuple[ProgramCallFact, ...],
    callable_nodes: dict[str, ProgramGraphNode],
    edges: set[ProgramGraphEdge],
    limits: ProgramGraphAdapterLimits,
) -> None:
    if len(set(call_facts)) != len(call_facts):
        raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.FACT_MISMATCH)
    for fact in call_facts:
        if fact.repository_id != repository_id or fact.revision != revision:
            raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.IDENTITY_MISMATCH)
        caller = callable_nodes.get(fact.caller_symbol_id)
        callee = callable_nodes.get(fact.callee_symbol_id)
        if caller is None or callee is None:
            raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.FACT_MISMATCH)
        if caller.language != callee.language:
            raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.IDENTITY_MISMATCH)
        _admit_edge(
            edges,
            ProgramGraphEdge(ProgramGraphEdgeKind.CALL, caller.node_id, callee.node_id),
            limits,
        )


def _symbol_nodes(
    index: SymbolIndex,
    aggregate: dict[str, ProgramGraphNode],
    limits: ProgramGraphAdapterLimits,
) -> dict[str, ProgramGraphNode]:
    nodes: dict[str, ProgramGraphNode] = {}
    for symbol in index.symbols:
        kind = (
            ProgramGraphNodeKind.MODULE
            if symbol.kind is SymbolKind.MODULE
            else ProgramGraphNodeKind.TYPE
            if symbol.kind is SymbolKind.CLASS
            else ProgramGraphNodeKind.CALLABLE
        )
        location = None if kind is ProgramGraphNodeKind.MODULE else symbol.declaration
        node = _node(index, kind, location, symbol.symbol_id)
        _admit_node(aggregate, node, limits)
        nodes[symbol.symbol_id] = node
    return nodes


def _fact_node(
    index: SymbolIndex, kind: ProgramGraphNodeKind, location: SourceRange
) -> ProgramGraphNode:
    return _node(index, kind, location, None)


def _node(
    index: SymbolIndex,
    kind: ProgramGraphNodeKind,
    location: SourceRange | None,
    symbol_id: str | None,
) -> ProgramGraphNode:
    node_id = _node_digest(
        kind=kind,
        language=index.language,
        path=index.path,
        content_sha256=index.content_sha256,
        source_size_bytes=index.source_byte_length,
        location=location,
        symbol_id=symbol_id,
    )
    return ProgramGraphNode(
        node_id=node_id,
        kind=kind,
        language=index.language,
        path=index.path,
        content_sha256=index.content_sha256,
        source_size_bytes=index.source_byte_length,
        location=location,
        symbol_id=symbol_id,
    )


def _validate_scanner_result(index: SymbolIndex, result: _ScannerResult) -> None:
    expected_language = "python" if isinstance(result, Cwe89ScanResult) else result.language
    if (
        expected_language != index.language
        or result.path != index.path
        or result.content_sha256 != index.content_sha256
        or result.source_size_bytes != index.source_byte_length
    ):
        raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.IDENTITY_MISMATCH)
    try:
        expected = _rescan(index)
    except (
        Cwe89ScanError,
        MultilanguageCwe89ScanError,
        PythonAstError,
        TypeError,
        ValueError,
    ):
        raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.ANALYSIS_UNAVAILABLE) from None
    if result != expected:
        raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.FACT_MISMATCH)


def _rescan(index: SymbolIndex) -> _ScannerResult:
    if index.language == "python":
        return scan_python_cwe89(index, analyze_python_ast(index))
    if index.language == "javascript":
        return scan_javascript_cwe89(index)
    if index.language == "typescript":
        return scan_typescript_cwe89(index)
    if index.language == "go":
        return scan_go_cwe89(index)
    raise ProgramGraphAdapterError(ProgramGraphAdapterErrorCode.REQUEST_INVALID)


__all__ = [
    "DEFAULT_PROGRAM_GRAPH_ADAPTER_LIMITS",
    "ProgramCallFact",
    "ProgramGraphAdapterError",
    "ProgramGraphAdapterErrorCode",
    "ProgramGraphAdapterLimits",
    "build_program_graph",
]
