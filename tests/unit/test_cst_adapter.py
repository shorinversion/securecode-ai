"""Acceptance and adversarial tests for the bounded Python CST adapter."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest
import securecode_ai.adapters.cst as cst_module
from securecode_ai.adapters import (
    CstAdapterError,
    CstAdapterErrorCode,
    CstLimits,
    build_python_symbol_index,
)
from securecode_ai.core import (
    ParseDiagnostic,
    ParseDiagnosticCode,
    ParseHealth,
    SourcePoint,
    SourceRange,
    SymbolIndex,
    SymbolKind,
    stable_symbol_id,
)

REPOSITORY_ID = "example/secure-repository"
REVISION = "1" * 40
PATH = "src/example.py"


def _build(source: bytes, **overrides: object) -> SymbolIndex:
    arguments: dict[str, object] = {
        "repository_id": REPOSITORY_ID,
        "revision": REVISION,
        "path": PATH,
        "content_sha256": hashlib.sha256(source).hexdigest(),
        "source": source,
    }
    arguments.update(overrides)
    return build_python_symbol_index(**arguments)  # type: ignore[arg-type]


def test_nested_symbols_are_deterministic_and_exactly_located() -> None:
    source = (
        b"@decorator\nclass Service:\n"
        b"    async def fetch(self):\n        return 1\n\n"
        b"def helper():\n    def nested():\n        pass\n    return nested\n"
    )
    first = _build(source)
    second = _build(source)

    assert first == second
    assert first.parse_health is ParseHealth.HEALTHY
    assert first.diagnostics == ()
    assert [(item.kind, item.qualified_name) for item in first.symbols] == [
        (SymbolKind.MODULE, "src.example"),
        (SymbolKind.CLASS, "src.example.Service"),
        (SymbolKind.ASYNC_METHOD, "src.example.Service.fetch"),
        (SymbolKind.FUNCTION, "src.example.helper"),
        (SymbolKind.FUNCTION, "src.example.helper.nested"),
    ]
    service = first.symbols[1]
    assert source[service.name_location.start_byte : service.name_location.end_byte] == b"Service"
    assert service.declaration.start_byte == 0
    assert service.parent_symbol_id == first.symbols[0].symbol_id


def test_unicode_multiline_and_leading_shift_preserve_semantic_ids() -> None:
    source = "class Café(\n    object,\n):\n    def méthode(self):\n        pass\n".encode()
    shifted = b"# harmless prefix\n\n" + source
    before = _build(source)
    after = _build(shifted)

    assert [item.symbol_id for item in before.symbols] == [item.symbol_id for item in after.symbols]
    assert [item.declaration.start_byte for item in before.symbols[1:]] != [
        item.declaration.start_byte for item in after.symbols[1:]
    ]
    assert before.index_sha256 != after.index_sha256


def test_empty_python_is_a_healthy_module_index() -> None:
    index = _build(b"")
    assert index.parse_health is ParseHealth.HEALTHY
    assert len(index.symbols) == 1
    assert index.symbols[0].kind is SymbolKind.MODULE


def test_malformed_python_is_explicitly_recovered_with_bounded_diagnostics() -> None:
    index = _build(b"def broken(:\n  return 1\n")
    assert index.parse_health is ParseHealth.RECOVERED_WITH_ERRORS
    assert index.diagnostics


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"language": "javascript"}, CstAdapterErrorCode.LANGUAGE_UNSUPPORTED),
        ({"path": "src/example.js"}, CstAdapterErrorCode.LANGUAGE_UNSUPPORTED),
        ({"content_sha256": "0" * 64}, CstAdapterErrorCode.CONTENT_MISMATCH),
        ({"path": "../escape.py"}, CstAdapterErrorCode.REQUEST_INVALID),
        ({"revision": "main"}, CstAdapterErrorCode.REQUEST_INVALID),
    ],
)
def test_invalid_request_metadata_fails_without_echo(
    overrides: dict[str, object], code: CstAdapterErrorCode
) -> None:
    marker = b"PRIVATE_MARKER"
    with pytest.raises(CstAdapterError) as caught:
        _build(marker, **overrides)
    assert caught.value.code is code
    assert str(caught.value) == "CST analysis failed"
    assert "PRIVATE_MARKER" not in repr(caught.value)


def test_invalid_utf8_fails_without_echo() -> None:
    with pytest.raises(CstAdapterError) as caught:
        _build(b"\xff")
    assert caught.value.code is CstAdapterErrorCode.SOURCE_ENCODING_INVALID
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_parser_failure_drops_raw_exception_context(monkeypatch: pytest.MonkeyPatch) -> None:
    class FailingParser:
        def parse(self, source: bytes) -> None:
            del source
            raise RuntimeError("PRIVATE_SOURCE_CANARY")

    monkeypatch.setattr(cst_module, "Parser", lambda language: FailingParser())
    with pytest.raises(CstAdapterError) as caught:
        _build(b"pass\n")
    assert caught.value.code is CstAdapterErrorCode.PARSER_FAILURE
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "PRIVATE_SOURCE_CANARY" not in repr(caught.value)


def test_core_validation_failure_drops_raw_exception_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_validation(**values: object) -> None:
        del values
        raise ValueError("PRIVATE_SOURCE_CANARY")

    monkeypatch.setattr(cst_module, "_build_symbol_index", fail_validation)
    with pytest.raises(CstAdapterError) as caught:
        _build(b"pass\n")
    assert caught.value.code is CstAdapterErrorCode.REQUEST_INVALID
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "PRIVATE_SOURCE_CANARY" not in repr(caught.value)


@pytest.mark.parametrize(
    ("limits", "source", "code"),
    [
        (CstLimits(max_source_bytes=1), b"pass", CstAdapterErrorCode.SOURCE_LIMIT),
        (CstLimits(max_nodes=1), b"pass", CstAdapterErrorCode.NODE_LIMIT),
        (CstLimits(max_symbols=1), b"def f(): pass", CstAdapterErrorCode.SYMBOL_LIMIT),
        (CstLimits(max_depth=1), b"def f(): pass", CstAdapterErrorCode.DEPTH_LIMIT),
        (
            CstLimits(max_diagnostics=1),
            b"def a(:\ndef b(:\n",
            CstAdapterErrorCode.DIAGNOSTIC_LIMIT,
        ),
    ],
)
def test_each_budget_fails_closed(
    limits: CstLimits, source: bytes, code: CstAdapterErrorCode
) -> None:
    with pytest.raises(CstAdapterError) as caught:
        _build(source, limits=limits)
    assert caught.value.code is code


def test_limit_configuration_has_immutable_upper_ceilings() -> None:
    assert CstLimits() == CstLimits(
        max_source_bytes=2_000_000,
        max_nodes=250_000,
        max_symbols=25_000,
        max_depth=512,
        max_diagnostics=1_000,
    )
    field_names = (
        "max_source_bytes",
        "max_nodes",
        "max_symbols",
        "max_depth",
        "max_diagnostics",
    )
    ceilings = (2_000_000, 250_000, 25_000, 512, 1_000)
    for field_name, ceiling in zip(field_names, ceilings, strict=True):
        with pytest.raises(ValueError, match="CST limits are invalid"):
            CstLimits(**{field_name: ceiling + 1})


def test_duplicate_symbols_receive_deterministic_occurrences() -> None:
    index = _build(b"def same(): pass\ndef same(): pass\n")
    duplicates = index.symbols[1:]
    assert [item.occurrence for item in duplicates] == [0, 1]
    assert duplicates[0].symbol_id != duplicates[1].symbol_id


def test_forged_index_digest_and_reordered_symbols_are_rejected() -> None:
    index = _build(b"class A: pass\ndef f(): pass\n")
    with pytest.raises(ValueError, match="symbol index is invalid"):
        replace(index, index_sha256="0" * 64)
    with pytest.raises(ValueError, match="symbol index is invalid"):
        replace(index, symbols=tuple(reversed(index.symbols)))


def test_recomputed_index_rejects_copied_ids_and_overlapping_siblings() -> None:
    index = _build(b"def first(): pass\ndef second(): pass\n")
    first, second = index.symbols[1:]
    copied_id = replace(second, symbol_id=first.symbol_id)
    with pytest.raises(ValueError, match="symbol index is invalid"):
        replace(index, symbols=(index.symbols[0], first, copied_id))

    overlapping = replace(
        second,
        declaration=SourceRange(
            first.declaration.end_byte - 1,
            second.declaration.end_byte,
            first.declaration.end_point,
            second.declaration.end_point,
        ),
    )
    with pytest.raises(ValueError, match="symbol index is invalid"):
        replace(index, symbols=(index.symbols[0], first, overlapping))


def test_recomputed_index_rejects_out_of_bounds_source_geometry() -> None:
    index = _build(b"def first(): pass\n")
    oversized_module = replace(
        index.symbols[0],
        declaration=SourceRange(
            0,
            index.source_byte_length + 1,
            SourcePoint(0, 0),
            SourcePoint(index.source_end_point.row + 1, 0),
        ),
    )
    with pytest.raises(ValueError, match="symbol index is invalid"):
        replace(index, symbols=(oversized_module, *index.symbols[1:]))


def test_recomputed_index_rejects_in_bounds_false_name_and_point_geometry() -> None:
    index = _build(b"def first(): pass\n")
    function = index.symbols[1]
    false_name = replace(
        function,
        name_location=SourceRange(0, 3, SourcePoint(0, 0), SourcePoint(0, 3)),
    )
    with pytest.raises(ValueError, match="symbol index is invalid"):
        replace(index, symbols=(index.symbols[0], false_name))

    false_point = replace(
        function,
        declaration=SourceRange(
            function.declaration.start_byte,
            function.declaration.end_byte,
            SourcePoint(0, 1),
            function.declaration.end_point,
        ),
    )
    with pytest.raises(ValueError, match="symbol index is invalid"):
        replace(index, symbols=(index.symbols[0], false_point))


def test_public_core_cannot_reseal_semantically_fabricated_indexes() -> None:
    import securecode_ai.core as core

    index = _build(b"# x\n")
    forged_module = replace(
        index.symbols[0],
        name="forged",
        qualified_name="forged",
        symbol_id="0" * 64,
    )
    with pytest.raises(ValueError, match="symbol index is invalid"):
        replace(index, symbols=(forged_module,))
    assert not hasattr(core, "build_symbol_index")


def test_public_mutation_cannot_reseal_parser_semantics_or_metrics() -> None:
    index = _build(b"# x\n")
    module = index.symbols[0]
    fake_function = replace(
        module,
        symbol_id=stable_symbol_id(
            index.repository_id,
            index.path,
            SymbolKind.FUNCTION,
            f"{module.qualified_name}.x",
            0,
        ),
        kind=SymbolKind.FUNCTION,
        name="x",
        qualified_name=f"{module.qualified_name}.x",
        declaration=SourceRange(0, 3, SourcePoint(0, 0), SourcePoint(0, 3)),
        name_location=SourceRange(2, 3, SourcePoint(0, 2), SourcePoint(0, 3)),
        parent_symbol_id=module.symbol_id,
    )
    fake_diagnostic = ParseDiagnostic(
        code=ParseDiagnosticCode.ERROR_NODE,
        location=SourceRange(0, 1, SourcePoint(0, 0), SourcePoint(0, 1)),
    )
    mutations = (
        {"symbols": (module, fake_function)},
        {"diagnostics": (fake_diagnostic,), "parse_health": ParseHealth.RECOVERED_WITH_ERRORS},
        {"node_count": index.node_count + 1},
        {"max_depth": index.max_depth + 1},
    )
    for mutation in mutations:
        with pytest.raises(ValueError, match="symbol index is invalid"):
            replace(index, **mutation)


def test_public_mutation_rejects_wrong_kind_and_parent() -> None:
    index = _build(b"def first(): pass\n")
    function = index.symbols[1]
    wrong_kind = replace(
        function,
        kind=SymbolKind.CLASS,
        symbol_id=stable_symbol_id(
            index.repository_id,
            index.path,
            SymbolKind.CLASS,
            function.qualified_name,
            function.occurrence,
        ),
    )
    wrong_parent = replace(function, parent_symbol_id="f" * 64)
    for forged in (wrong_kind, wrong_parent):
        with pytest.raises(ValueError, match="symbol index is invalid"):
            replace(index, symbols=(index.symbols[0], forged))


def test_adapter_exposes_no_filesystem_or_execution_inputs() -> None:
    parameters = build_python_symbol_index.__annotations__
    assert not ({"filesystem", "shell", "network", "command"} & set(parameters))
