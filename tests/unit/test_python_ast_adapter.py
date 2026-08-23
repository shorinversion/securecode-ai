"""Acceptance and adversarial tests for the bounded CPython AST adapter."""

from __future__ import annotations

import ast
import copy
import hashlib
from dataclasses import replace

import pytest
from securecode_ai.adapters import (
    PythonAstError,
    PythonAstErrorCode,
    PythonAstLimits,
    PythonAstStatus,
    analyze_python_ast,
    build_python_symbol_index,
    open_python_ast,
)
from securecode_ai.core import SymbolIndex

REPOSITORY_ID = "example/secure-repository"
REVISION = "2" * 40
PATH = "src/example.py"


def _symbols(source: bytes) -> SymbolIndex:
    return build_python_symbol_index(
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        path=PATH,
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )


def test_valid_python_produces_deterministic_isolated_ast() -> None:
    source = """\
def decorated(function):
    return function

@decorated
async def outer(café: int) -> int:
    def nested(value: int) -> int:
        return value + 1
    return nested(café)
""".encode()
    first = analyze_python_ast(_symbols(source))
    second = analyze_python_ast(_symbols(source))

    assert first == second
    assert first.status is PythonAstStatus.PARSED
    assert first.node_count > 1
    assert first.tree_sha256 == second.tree_sha256
    assert "value" not in repr(first)
    opened = open_python_ast(first)
    assert isinstance(opened, ast.Module)
    assert any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(opened))
    assert sum(isinstance(node, ast.FunctionDef) for node in ast.walk(opened)) == 2
    opened.body.clear()
    assert open_python_ast(first).body


def test_empty_python_is_a_valid_parsed_module() -> None:
    result = analyze_python_ast(_symbols(b""))
    assert result.status is PythonAstStatus.PARSED
    assert result.node_count == 1
    assert open_python_ast(result).body == []


def test_syntax_error_is_a_typed_non_echoing_result() -> None:
    marker = b"PRIVATE_CANARY = (\n"
    result = analyze_python_ast(_symbols(marker))
    assert result.status is PythonAstStatus.SYNTAX_ERROR
    assert result.diagnostic is not None
    assert result.node_count == 0
    assert result.tree_sha256 is None
    assert "PRIVATE_CANARY" not in repr(result)
    with pytest.raises(PythonAstError) as caught:
        open_python_ast(result)
    assert caught.value.code is PythonAstErrorCode.REQUEST_INVALID


def test_unicode_syntax_location_uses_utf8_byte_columns() -> None:
    result = analyze_python_ast(_symbols("é = 1; (\n".encode()))
    assert result.status is PythonAstStatus.SYNTAX_ERROR
    assert result.diagnostic is not None
    assert result.diagnostic.start_point.column >= 2


@pytest.mark.parametrize(
    ("limits", "source", "code"),
    [
        (PythonAstLimits(max_source_bytes=1), b"pass", PythonAstErrorCode.SOURCE_LIMIT),
        (PythonAstLimits(max_nodes=1), b"x = 1", PythonAstErrorCode.NODE_LIMIT),
        (PythonAstLimits(max_depth=1), b"x = 1", PythonAstErrorCode.DEPTH_LIMIT),
    ],
)
def test_every_runtime_budget_fails_closed(
    limits: PythonAstLimits, source: bytes, code: PythonAstErrorCode
) -> None:
    with pytest.raises(PythonAstError) as caught:
        analyze_python_ast(_symbols(source), limits=limits)
    assert caught.value.code is code


def test_limit_configuration_rejects_over_ceiling_values() -> None:
    for name, ceiling in (
        ("max_source_bytes", 2_000_000),
        ("max_nodes", 250_000),
        ("max_depth", 512),
    ):
        with pytest.raises(ValueError, match="Python AST limits are invalid"):
            PythonAstLimits(**{name: ceiling + 1})


def test_public_copy_cannot_reseal_changed_analysis() -> None:
    result = analyze_python_ast(_symbols(b"x = 1\n"))
    with pytest.raises(ValueError, match="Python AST analysis is invalid"):
        replace(result, node_count=result.node_count + 1)
    opened = open_python_ast(result)
    opened.body.clear()
    assert open_python_ast(result).body


def test_mutated_source_index_is_rejected_before_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    index = _symbols(b"pass\n")
    object.__setattr__(index, "source", b"PRIVATE_CANARY = 1\n")
    parse_called = False

    def observe_parse(*args: object, **kwargs: object) -> None:
        nonlocal parse_called
        del args, kwargs
        parse_called = True

    monkeypatch.setattr(ast, "parse", observe_parse)
    with pytest.raises(PythonAstError) as caught:
        analyze_python_ast(index)
    assert caught.value.code is PythonAstErrorCode.INTEGRITY_FAILURE
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert not parse_called


def test_retained_tree_mutation_is_detected() -> None:
    result = analyze_python_ast(_symbols(b"x = 1\n"))
    assert result._tree is not None
    result._tree.body.clear()
    with pytest.raises(PythonAstError) as caught:
        open_python_ast(result)
    assert caught.value.code is PythonAstErrorCode.INTEGRITY_FAILURE
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_cyclic_retained_tree_is_a_typed_non_echoing_integrity_failure() -> None:
    result = analyze_python_ast(_symbols(b"x = 1\n"))
    assert result._tree is not None
    result._tree.body[:] = [result._tree]  # type: ignore[list-item]
    with pytest.raises(PythonAstError) as caught:
        open_python_ast(result)
    assert caught.value.code is PythonAstErrorCode.INTEGRITY_FAILURE
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_open_validates_the_exact_copied_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    result = analyze_python_ast(_symbols(b"x = 1\n"))
    real_deepcopy = copy.deepcopy

    def mutate_snapshot(value: object) -> object:
        snapshot = real_deepcopy(value)
        assert isinstance(snapshot, ast.Module)
        snapshot.body.clear()
        return snapshot

    monkeypatch.setattr("securecode_ai.adapters.python_ast.copy.deepcopy", mutate_snapshot)
    with pytest.raises(PythonAstError) as caught:
        open_python_ast(result)
    assert caught.value.code is PythonAstErrorCode.INTEGRITY_FAILURE


def test_parser_failure_drops_raw_exception_context(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_parse(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("PRIVATE_CANARY")

    monkeypatch.setattr(ast, "parse", fail_parse)
    with pytest.raises(PythonAstError) as caught:
        analyze_python_ast(_symbols(b"pass\n"))
    assert caught.value.code is PythonAstErrorCode.PARSER_FAILURE
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "PRIVATE_CANARY" not in repr(caught.value)


def test_adapter_has_no_filesystem_execution_or_network_inputs() -> None:
    parameters = analyze_python_ast.__annotations__
    assert not ({"path", "filesystem", "shell", "network", "command"} & set(parameters))
