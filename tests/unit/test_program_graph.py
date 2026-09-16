"""Shared P7.3 language-neutral ProgramGraph contract tests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import replace

import pytest
from securecode_ai.adapters import (
    Cwe89ScanResult,
    MultilanguageCwe89ScanResult,
    ProgramCallFact,
    ProgramGraphAdapterError,
    ProgramGraphAdapterErrorCode,
    ProgramGraphAdapterLimits,
    build_go_symbol_index,
    build_javascript_symbol_index,
    build_program_graph,
    build_python_symbol_index,
    scan_go_cwe89,
    scan_javascript_cwe89,
    scan_python_cwe89,
)
from securecode_ai.adapters.python_ast import analyze_python_ast
from securecode_ai.core import (
    ProgramGraph,
    ProgramGraphEdge,
    ProgramGraphEdgeKind,
    ProgramGraphError,
    ProgramGraphErrorCode,
    ProgramGraphNodeKind,
    SymbolIndex,
)
from securecode_ai.core.program_graph import _build_program_graph

REPOSITORY_ID = "example/p7-graph"
REVISION = "c" * 40
PYTHON = b"""def lookup(request, db):
    value = request.args.get("id")
    return db.execute(f"SELECT {value}")
"""
JAVASCRIPT = b"""function lookup(req, db) {
  const id = req.query.id;
  const sql = "SELECT " + id;
  db.query(sql);
}
"""
GO = b"""package api
import "fmt"
func lookup(r *Request, db DB) {
 id := r.URL.Query().Get("id")
 sql := fmt.Sprintf("SELECT %s", id)
 db.Query(sql)
}
"""
PYTHON_CALLER = b"""def caller():
    return worker()
"""
PYTHON_CALLEE = b"""def worker():
    return 1
"""


_ScannerResult = Cwe89ScanResult | MultilanguageCwe89ScanResult
_IndexBuilder = Callable[..., SymbolIndex]


def _index(builder: _IndexBuilder, path: str, source: bytes) -> SymbolIndex:
    return builder(
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        path=path,
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )


def _inputs() -> tuple[tuple[SymbolIndex, ...], tuple[_ScannerResult, ...]]:
    python = _index(build_python_symbol_index, "api/python_lookup.py", PYTHON)
    javascript = _index(build_javascript_symbol_index, "api/javascript_lookup.js", JAVASCRIPT)
    go = _index(build_go_symbol_index, "api/go_lookup.go", GO)
    return (
        (python, javascript, go),
        (
            scan_python_cwe89(python, analyze_python_ast(python)),
            scan_javascript_cwe89(javascript),
            scan_go_cwe89(go),
        ),
    )


def test_three_language_graph_has_one_canonical_source_free_contract() -> None:
    indexes, results = _inputs()
    first = build_program_graph(indexes, results)
    second = build_program_graph(tuple(reversed(indexes)), tuple(reversed(results)))

    assert isinstance(first, ProgramGraph)
    assert first == second
    assert first.graph_sha256 == second.graph_sha256
    assert {node.language for node in first.nodes} == {"python", "javascript", "go"}
    assert tuple(node.canonical_key for node in first.nodes) == tuple(
        sorted(node.canonical_key for node in first.nodes)
    )
    assert tuple(edge.canonical_key for edge in first.edges) == tuple(
        sorted(edge.canonical_key for edge in first.edges)
    )
    assert {edge.kind for edge in first.edges} == {
        ProgramGraphEdgeKind.CONTAINS,
        ProgramGraphEdgeKind.DATA_FLOW,
    }
    assert sum(node.kind is ProgramGraphNodeKind.HTTP_SOURCE for node in first.nodes) == 3
    assert sum(node.kind is ProgramGraphNodeKind.INTERPOLATION for node in first.nodes) == 3
    assert sum(node.kind is ProgramGraphNodeKind.SQL_SINK for node in first.nodes) == 3
    payload = json.dumps(first.canonical_payload, sort_keys=True)
    assert PYTHON.decode() not in payload
    assert JAVASCRIPT.decode() not in payload
    assert GO.decode() not in payload


def test_cross_revision_and_recomputed_fact_mismatches_fail_closed() -> None:
    indexes, results = _inputs()
    changed = _index(
        build_javascript_symbol_index,
        "api/javascript_lookup.js",
        JAVASCRIPT,
    )
    object.__setattr__(changed, "revision", "d" * 40)
    with pytest.raises(ProgramGraphAdapterError) as revision:
        build_program_graph((indexes[0], changed, indexes[2]), results)
    assert revision.value.code is ProgramGraphAdapterErrorCode.IDENTITY_MISMATCH

    forged = results[1]
    object.__setattr__(forged, "scan_sha256", "0" * 64)
    with pytest.raises(ProgramGraphAdapterError) as fact:
        build_program_graph(indexes, results)
    assert fact.value.code is ProgramGraphAdapterErrorCode.FACT_MISMATCH


def test_data_flow_cannot_cross_file_identity() -> None:
    indexes, results = _inputs()
    graph = build_program_graph(indexes, results)
    source = next(
        node
        for node in graph.nodes
        if node.kind is ProgramGraphNodeKind.HTTP_SOURCE and node.path == "api/python_lookup.py"
    )
    interpolation = next(
        node
        for node in graph.nodes
        if node.kind is ProgramGraphNodeKind.INTERPOLATION
        and node.path == "api/javascript_lookup.js"
    )
    cross_file = ProgramGraphEdge(
        ProgramGraphEdgeKind.DATA_FLOW,
        source.node_id,
        interpolation.node_id,
    )
    with pytest.raises(ProgramGraphError) as caught:
        _build_program_graph(
            repository_id=graph.repository_id,
            revision=graph.revision,
            nodes=graph.nodes,
            edges=(*graph.edges, cross_file),
        )
    assert caught.value.code is ProgramGraphErrorCode.INVALID_FLOW


def test_cross_file_call_facts_are_bounded_and_identity_checked() -> None:
    indexes, results = _inputs()
    caller = _index(build_python_symbol_index, "api/caller.py", PYTHON_CALLER)
    callee = _index(build_python_symbol_index, "api/callee.py", PYTHON_CALLEE)
    caller_result = scan_python_cwe89(caller, analyze_python_ast(caller))
    callee_result = scan_python_cwe89(callee, analyze_python_ast(callee))
    call_fact = ProgramCallFact(
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        caller_symbol_id=caller.symbols[1].symbol_id,
        callee_symbol_id=callee.symbols[1].symbol_id,
    )
    graph = build_program_graph(
        (*indexes, caller, callee),
        (*results, caller_result, callee_result),
        call_facts=(call_fact,),
    )
    call_edge = next(edge for edge in graph.edges if edge.kind is ProgramGraphEdgeKind.CALL)
    nodes = {node.node_id: node for node in graph.nodes}
    assert nodes[call_edge.source_node_id].path == "api/caller.py"
    assert nodes[call_edge.target_node_id].path == "api/callee.py"
    assert nodes[call_edge.source_node_id].language == nodes[call_edge.target_node_id].language

    with pytest.raises(ProgramGraphAdapterError) as dangling:
        build_program_graph(
            (*indexes, caller, callee),
            (*results, caller_result, callee_result),
            call_facts=(replace(call_fact, caller_symbol_id="0" * 64),),
        )
    assert dangling.value.code is ProgramGraphAdapterErrorCode.FACT_MISMATCH

    with pytest.raises(ProgramGraphAdapterError) as revision:
        build_program_graph(
            (*indexes, caller, callee),
            (*results, caller_result, callee_result),
            call_facts=(replace(call_fact, revision="d" * 40),),
        )
    assert revision.value.code is ProgramGraphAdapterErrorCode.IDENTITY_MISMATCH

    with pytest.raises(ProgramGraphAdapterError) as language:
        build_program_graph(
            (*indexes, caller, callee),
            (*results, caller_result, callee_result),
            call_facts=(replace(call_fact, callee_symbol_id=indexes[1].symbols[1].symbol_id),),
        )
    assert language.value.code is ProgramGraphAdapterErrorCode.IDENTITY_MISMATCH

    with pytest.raises(ProgramGraphAdapterError) as overflow:
        build_program_graph(
            (*indexes, caller, callee),
            (*results, caller_result, callee_result),
            call_facts=(
                call_fact,
                replace(
                    call_fact,
                    caller_symbol_id=callee.symbols[1].symbol_id,
                    callee_symbol_id=caller.symbols[1].symbol_id,
                ),
            ),
            limits=ProgramGraphAdapterLimits(max_call_facts=1),
        )
    assert overflow.value.code is ProgramGraphAdapterErrorCode.LIMIT_EXCEEDED


def test_overflow_and_public_resealing_are_rejected() -> None:
    indexes, results = _inputs()
    with pytest.raises(ProgramGraphAdapterError) as overflow:
        build_program_graph(
            indexes,
            results,
            limits=ProgramGraphAdapterLimits(max_symbol_indexes=1),
        )
    assert overflow.value.code is ProgramGraphAdapterErrorCode.LIMIT_EXCEEDED

    graph = build_program_graph(indexes, _inputs()[1])
    with pytest.raises(ProgramGraphError):
        replace(graph, graph_sha256="0" * 64)
    with pytest.raises(ProgramGraphError):
        replace(graph, nodes=graph.nodes[:-1])


def test_adapter_rejects_unknown_language_before_scanner_execution() -> None:
    indexes, results = _inputs()
    unsupported = indexes[1]
    object.__setattr__(unsupported, "language", "rust")
    with pytest.raises(ProgramGraphAdapterError) as caught:
        build_program_graph(indexes, results)
    assert caught.value.code is ProgramGraphAdapterErrorCode.IDENTITY_MISMATCH


@pytest.mark.parametrize(
    "limits",
    [
        ProgramGraphAdapterLimits(max_nodes=5),
        ProgramGraphAdapterLimits(max_edges=2),
    ],
)
def test_aggregate_structural_overflow_precedes_scanning_and_allocation(
    monkeypatch: pytest.MonkeyPatch,
    limits: ProgramGraphAdapterLimits,
) -> None:
    import securecode_ai.adapters.program_graph as adapter

    indexes, results = _inputs()

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("overflow must be rejected before rescanning or node construction")

    monkeypatch.setattr(adapter, "_validate_scanner_result", forbidden)
    monkeypatch.setattr(adapter, "_symbol_nodes", forbidden)
    monkeypatch.setattr(adapter, "_build_program_graph", forbidden)
    with pytest.raises(ProgramGraphAdapterError) as caught:
        build_program_graph(indexes, results, limits=limits)
    assert caught.value.code is ProgramGraphAdapterErrorCode.LIMIT_EXCEEDED


@pytest.mark.parametrize(
    "limits",
    [
        ProgramGraphAdapterLimits(max_nodes=12),
        ProgramGraphAdapterLimits(max_edges=7),
    ],
)
def test_aggregate_flow_overflow_precedes_core_sorting(
    monkeypatch: pytest.MonkeyPatch,
    limits: ProgramGraphAdapterLimits,
) -> None:
    import securecode_ai.adapters.program_graph as adapter

    indexes, results = _inputs()

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("overflow must be rejected before Core sorting/validation")

    monkeypatch.setattr(adapter, "_build_program_graph", forbidden)
    with pytest.raises(ProgramGraphAdapterError) as caught:
        build_program_graph(indexes, results, limits=limits)
    assert caught.value.code is ProgramGraphAdapterErrorCode.LIMIT_EXCEEDED


def test_aggregate_admission_counts_unique_flow_nodes_and_edges() -> None:
    source = b"function f(req, db) { const id = req.query.id; const sql = `SELECT ${id}`; db.query(sql); db.query(sql); }"
    index = _index(build_javascript_symbol_index, "api/reuse.js", source)
    result = scan_javascript_cwe89(index)
    graph = build_program_graph(
        (index,), (result,), limits=ProgramGraphAdapterLimits(max_nodes=6, max_edges=4)
    )
    assert len(graph.nodes) == 6
    assert len(graph.edges) == 4


def test_call_edge_counts_against_aggregate_budget() -> None:
    caller = _index(build_python_symbol_index, "api/caller.py", PYTHON_CALLER)
    callee = _index(build_python_symbol_index, "api/callee.py", PYTHON_CALLEE)
    results = tuple(
        scan_python_cwe89(index, analyze_python_ast(index)) for index in (caller, callee)
    )
    fact = ProgramCallFact(
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        caller_symbol_id=caller.symbols[1].symbol_id,
        callee_symbol_id=callee.symbols[1].symbol_id,
    )
    with pytest.raises(ProgramGraphAdapterError) as caught:
        build_program_graph(
            (caller, callee), results, (fact,), limits=ProgramGraphAdapterLimits(max_edges=2)
        )
    assert caught.value.code is ProgramGraphAdapterErrorCode.LIMIT_EXCEEDED
