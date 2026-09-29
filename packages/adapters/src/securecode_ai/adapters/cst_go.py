"""Bounded Python Tree-sitter adapter over caller-admitted source bytes."""

from __future__ import annotations

import hashlib
from typing import Protocol, cast

import tree_sitter_go
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


class _GoLanguageModule(Protocol):
    def language(self) -> object: ...


_GO_LANGUAGE_MODULE = cast(
    _GoLanguageModule,
    tree_sitter_go,
)


def _go_language() -> object:
    return _GO_LANGUAGE_MODULE.language()


def build_go_symbol_index(
    *,
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source: bytes,
    language: str = "go",
    limits: CstLimits = DEFAULT_CST_LIMITS,
) -> SymbolIndex:
    """Parse exact admitted Go bytes into a sealed symbol index."""

    if type(source) is not bytes or type(limits) is not CstLimits:
        raise _fail(CstAdapterErrorCode.REQUEST_INVALID)
    if language != "go" or not path.lower().endswith(".go"):
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
        parser = Parser(Language(_go_language()))
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

    module_name = path[:-3].replace("/", ".")
    module = Symbol(
        symbol_id=stable_symbol_id(repository_id, path, SymbolKind.MODULE, module_name, 0),
        kind=SymbolKind.MODULE,
        name=module_name.rsplit(".", 1)[-1],
        qualified_name=module_name,
        occurrence=0,
        declaration=SourceRange(0, root.end_byte, SourcePoint(0, 0), _range(root).end_point),
        name_location=SourceRange(0, 0, SourcePoint(0, 0), SourcePoint(0, 0)),
        parent_symbol_id=None,
    )
    symbols = [module]
    occurrences: dict[tuple[SymbolKind, str], int] = {}
    for node in _go_declarations(root):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        name = _decode_name(source, name_node.start_byte, name_node.end_byte)
        kind = (
            SymbolKind.CLASS
            if node.type == "type_spec"
            else SymbolKind.METHOD
            if node.type == "method_declaration"
            else SymbolKind.FUNCTION
        )
        receiver = _go_receiver_type(node) if node.type == "method_declaration" else None
        receiver_name = (
            _decode_name(source, receiver.start_byte, receiver.end_byte)
            if receiver is not None
            else None
        )
        qualifier = f"{receiver_name}." if receiver_name is not None else ""
        qualified_name = f"{module.qualified_name}.{qualifier}{name}"
        occurrence_key = (kind, qualified_name)
        occurrence = occurrences.get(occurrence_key, 0)
        occurrences[occurrence_key] = occurrence + 1
        symbols.append(
            Symbol(
                symbol_id=stable_symbol_id(repository_id, path, kind, qualified_name, occurrence),
                kind=kind,
                name=name,
                qualified_name=qualified_name,
                occurrence=occurrence,
                declaration=_range(node),
                name_location=_range(name_node),
                parent_symbol_id=module.symbol_id,
                receiver_name=receiver_name,
                receiver_location=_range(receiver) if receiver is not None else None,
            )
        )
        if len(symbols) > limits.max_symbols:
            raise _fail(CstAdapterErrorCode.SYMBOL_LIMIT)
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
            parser_id="tree-sitter-go@0.25",
            parse_health=health,
            symbols=tuple(symbols),
            diagnostics=tuple(diagnostics),
            node_count=node_count,
            max_depth=max_depth,
        )
    except ValueError:
        raise _fail(CstAdapterErrorCode.REQUEST_INVALID) from None


def _go_receiver_type(node: Node) -> Node | None:
    receiver = node.child_by_field_name("receiver")
    if receiver is None or not receiver.named_children:
        return None
    type_node = receiver.named_children[0].child_by_field_name("type")
    while type_node is not None:
        if type_node.type == "type_identifier":
            return type_node
        if type_node.type == "generic_type":
            type_node = type_node.child_by_field_name("type")
        elif type_node.type == "pointer_type" and type_node.named_children:
            type_node = type_node.named_children[0]
        else:
            return None
    return None


def _go_declarations(root: Node) -> tuple[Node, ...]:
    declarations: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in {"function_declaration", "method_declaration", "type_spec"}:
            declarations.append(node)
            continue
        stack.extend(reversed(node.named_children))
    return tuple(declarations)
