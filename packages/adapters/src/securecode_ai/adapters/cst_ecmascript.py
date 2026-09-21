"""Bounded Python Tree-sitter adapter over caller-admitted source bytes."""

from __future__ import annotations

import hashlib
from typing import Protocol, cast

import tree_sitter_javascript
import tree_sitter_typescript
from securecode_ai.core import (
    ParseDiagnostic,
    ParseDiagnosticCode,
    ParseHealth,
    SourcePoint,
    SourceRange,
    Symbol,
    SymbolIndex,
    SymbolKind,
    stable_symbol_id,
)
from securecode_ai.core.symbols import _build_symbol_index
from tree_sitter import Language, Node, Parser

from .cst_models import (
    DEFAULT_CST_LIMITS,
    CstAdapterErrorCode,
    CstLimits,
    _decode_name,
    _fail,
    _point,
    _range,
)


class _JavaScriptLanguageModule(Protocol):
    def language(self) -> object: ...


class _TypeScriptLanguageModule(Protocol):
    def language_tsx(self) -> object: ...

    def language_typescript(self) -> object: ...


_JAVASCRIPT_LANGUAGE_MODULE = cast(
    _JavaScriptLanguageModule,
    tree_sitter_javascript,
)
_TYPESCRIPT_LANGUAGE_MODULE = cast(
    _TypeScriptLanguageModule,
    tree_sitter_typescript,
)


def _javascript_language() -> object:
    return _JAVASCRIPT_LANGUAGE_MODULE.language()


def _typescript_language(*, tsx: bool) -> object:
    if tsx:
        return _TYPESCRIPT_LANGUAGE_MODULE.language_tsx()
    return _TYPESCRIPT_LANGUAGE_MODULE.language_typescript()


def build_javascript_symbol_index(
    *,
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source: bytes,
    language: str = "javascript",
    limits: CstLimits = DEFAULT_CST_LIMITS,
) -> SymbolIndex:
    """Parse exact admitted JavaScript bytes into a sealed symbol index."""

    return _build_ecmascript_symbol_index(
        repository_id=repository_id,
        revision=revision,
        path=path,
        content_sha256=content_sha256,
        source=source,
        language=language,
        expected_language="javascript",
        suffixes=(".js", ".mjs", ".cjs", ".jsx"),
        parser_id="tree-sitter-javascript@0.25",
        grammar=_javascript_language(),
        limits=limits,
    )


def build_typescript_symbol_index(
    *,
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source: bytes,
    language: str = "typescript",
    limits: CstLimits = DEFAULT_CST_LIMITS,
) -> SymbolIndex:
    """Parse exact admitted TypeScript bytes into a sealed symbol index."""

    return _build_ecmascript_symbol_index(
        repository_id=repository_id,
        revision=revision,
        path=path,
        content_sha256=content_sha256,
        source=source,
        language=language,
        expected_language="typescript",
        suffixes=(".ts", ".mts", ".cts", ".tsx"),
        parser_id="tree-sitter-typescript@0.23",
        grammar=_typescript_language(tsx=path.endswith(".tsx")),
        limits=limits,
    )


def _build_ecmascript_symbol_index(
    *,
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source: bytes,
    language: str,
    expected_language: str,
    suffixes: tuple[str, ...],
    parser_id: str,
    grammar: object,
    limits: CstLimits,
) -> SymbolIndex:
    if type(source) is not bytes or type(limits) is not CstLimits:
        raise _fail(CstAdapterErrorCode.REQUEST_INVALID)
    if language != expected_language or not path.endswith(suffixes):
        raise _fail(CstAdapterErrorCode.LANGUAGE_UNSUPPORTED)
    if len(source) > limits.max_source_bytes:
        raise _fail(CstAdapterErrorCode.SOURCE_LIMIT)
    if hashlib.sha256(source).hexdigest() != content_sha256:
        raise _fail(CstAdapterErrorCode.CONTENT_MISMATCH)
    try:
        source.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise _fail(CstAdapterErrorCode.SOURCE_ENCODING_INVALID) from None
    try:
        parser = Parser(Language(grammar))
        tree = parser.parse(source)
    except Exception:
        raise _fail(CstAdapterErrorCode.PARSER_FAILURE) from None

    root = tree.root_node
    stack: list[tuple[Node, int]] = [(root, 0)]
    diagnostics: list[ParseDiagnostic] = []
    node_count = 0
    max_depth = 0
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise _fail(CstAdapterErrorCode.DEPTH_LIMIT)
        node_count += 1
        if node_count > limits.max_nodes:
            raise _fail(CstAdapterErrorCode.NODE_LIMIT)
        max_depth = max(max_depth, depth)
        if node.type == "ERROR" or node.is_missing:
            diagnostics.append(
                ParseDiagnostic(
                    ParseDiagnosticCode.MISSING_NODE
                    if node.is_missing
                    else ParseDiagnosticCode.ERROR_NODE,
                    _range(node),
                )
            )
            if len(diagnostics) > limits.max_diagnostics:
                raise _fail(CstAdapterErrorCode.DIAGNOSTIC_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.children))

    module_name = _ecmascript_module_name(path, suffixes)
    module = Symbol(
        symbol_id=stable_symbol_id(repository_id, path, SymbolKind.MODULE, module_name, 0),
        kind=SymbolKind.MODULE,
        name=module_name.rsplit(".", 1)[-1],
        qualified_name=module_name,
        occurrence=0,
        declaration=_range(root),
        name_location=SourceRange(0, 0, SourcePoint(0, 0), SourcePoint(0, 0)),
        parent_symbol_id=None,
    )
    symbols = [module]
    occurrences: dict[tuple[SymbolKind, str], int] = {}

    def visit(node: Node, parents: tuple[Symbol, ...]) -> None:
        if node.type in {
            "class_declaration",
            "function_declaration",
            "method_definition",
            "arrow_function",
            "function_expression",
            "generator_function",
            "generator_function_declaration",
        }:
            visit_definition(node, parents)
            return
        for child in node.named_children:
            visit(child, parents)

    def visit_definition(node: Node, parents: tuple[Symbol, ...]) -> None:
        name_node = node.child_by_field_name("name")
        declaration = node
        if node.type in {"arrow_function", "function_expression", "generator_function"}:
            owner = node.parent
            if owner is not None and owner.type in {
                "variable_declarator",
                "pair",
                "field_definition",
                "public_field_definition",
                "assignment_expression",
            }:
                bound_name = (
                    owner.child_by_field_name("name")
                    or owner.child_by_field_name("key")
                    or owner.child_by_field_name("property")
                    or owner.child_by_field_name("left")
                )
                if bound_name is not None and bound_name.type in {
                    "identifier",
                    "property_identifier",
                    "private_property_identifier",
                    "member_expression",
                    "string",
                }:
                    name_node = bound_name
                    declaration = owner
            if name_node is None:
                # Anonymous callable names are exact syntax tokens, not invented
                # source spans. Occurrences disambiguate siblings in one scope.
                name_node = next(
                    (child for child in node.children if child.type in {"=>", "function"}),
                    None,
                )
        if name_node is None:
            return
        name = _decode_name(source, name_node.start_byte, name_node.end_byte)
        parent = parents[-1] if parents else module
        if node.type == "class_declaration":
            kind = SymbolKind.CLASS
        elif parent.kind is SymbolKind.CLASS:
            kind = SymbolKind.ASYNC_METHOD if _is_async(node, source) else SymbolKind.METHOD
        else:
            kind = SymbolKind.ASYNC_FUNCTION if _is_async(node, source) else SymbolKind.FUNCTION
        qualified_name = f"{parent.qualified_name}.{name}"
        occurrence_key = (kind, qualified_name)
        occurrence = occurrences.get(occurrence_key, 0)
        occurrences[occurrence_key] = occurrence + 1
        symbol = Symbol(
            symbol_id=stable_symbol_id(repository_id, path, kind, qualified_name, occurrence),
            kind=kind,
            name=name,
            qualified_name=qualified_name,
            occurrence=occurrence,
            declaration=_range(declaration),
            name_location=_range(name_node),
            parent_symbol_id=parent.symbol_id,
        )
        symbols.append(symbol)
        if len(symbols) > limits.max_symbols:
            raise _fail(CstAdapterErrorCode.SYMBOL_LIMIT)
        for child in node.named_children:
            visit(child, (*parents, symbol))

    for child in root.named_children:
        visit(child, ())
    health = ParseHealth.RECOVERED_WITH_ERRORS if diagnostics else ParseHealth.HEALTHY
    try:
        return _build_symbol_index(
            repository_id=repository_id,
            revision=revision,
            path=path,
            content_sha256=content_sha256,
            source=source,
            source_byte_length=len(source),
            source_end_point=_point(root.end_point),
            language=language,
            parser_id=parser_id,
            parse_health=health,
            symbols=tuple(symbols),
            diagnostics=tuple(diagnostics),
            node_count=node_count,
            max_depth=max_depth,
        )
    except ValueError:
        raise _fail(CstAdapterErrorCode.REQUEST_INVALID) from None


def _ecmascript_module_name(path: str, suffixes: tuple[str, ...]) -> str:
    suffix = next(item for item in suffixes if path.endswith(item))
    return path[: -len(suffix)].replace("/", ".")


def _is_async(node: Node, source: bytes) -> bool:
    return (
        source[node.start_byte : min(node.end_byte, node.start_byte + 8)]
        .lstrip()
        .startswith(b"async")
    )
