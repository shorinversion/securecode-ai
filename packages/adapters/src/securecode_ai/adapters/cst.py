"""Bounded Python Tree-sitter adapter over caller-admitted source bytes."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum

import tree_sitter_python
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
from tree_sitter import Language, Node, Parser, Point

_PARSER_ID = "tree-sitter-python@0.25"
_MAX_CST_LIMIT_VALUES = (2_000_000, 250_000, 25_000, 512, 1_000)


class CstAdapterErrorCode(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    LANGUAGE_UNSUPPORTED = "LANGUAGE_UNSUPPORTED"
    CONTENT_MISMATCH = "CONTENT_MISMATCH"
    SOURCE_ENCODING_INVALID = "SOURCE_ENCODING_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    SYMBOL_LIMIT = "SYMBOL_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    DIAGNOSTIC_LIMIT = "DIAGNOSTIC_LIMIT"
    PARSER_FAILURE = "PARSER_FAILURE"


class CstAdapterError(RuntimeError):
    """Fixed, non-echoing CST boundary failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: CstAdapterErrorCode) -> None:
        if type(code) is not CstAdapterErrorCode:
            raise TypeError("CST adapter error code is invalid")
        self.code = code
        self.safe_message = "CST analysis failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class CstLimits:
    max_source_bytes: int = _MAX_CST_LIMIT_VALUES[0]
    max_nodes: int = _MAX_CST_LIMIT_VALUES[1]
    max_symbols: int = _MAX_CST_LIMIT_VALUES[2]
    max_depth: int = _MAX_CST_LIMIT_VALUES[3]
    max_diagnostics: int = _MAX_CST_LIMIT_VALUES[4]

    def __post_init__(self) -> None:
        values = (
            self.max_source_bytes,
            self.max_nodes,
            self.max_symbols,
            self.max_depth,
            self.max_diagnostics,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_CST_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("CST limits are invalid")


DEFAULT_CST_LIMITS = CstLimits()


def _range(node: Node) -> SourceRange:
    return SourceRange(
        start_byte=node.start_byte,
        end_byte=node.end_byte,
        start_point=_point(node.start_point),
        end_point=_point(node.end_point),
    )


def _point(point: Point) -> SourcePoint:
    return SourcePoint(row=point.row, column=point.column)


def _module_name(path: str) -> str:
    value = path[:-4] if path.endswith(".pyi") else path[:-3]
    parts = value.split("/")
    if parts[-1] == "__init__" and len(parts) > 1:
        parts.pop()
    return ".".join(parts)


def _fail(code: CstAdapterErrorCode) -> CstAdapterError:
    return CstAdapterError(code)


def _decode_name(source: bytes, start_byte: int, end_byte: int) -> str:
    invalid = False
    try:
        name = source[start_byte:end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        invalid = True
        name = ""
    if invalid:
        raise _fail(CstAdapterErrorCode.SOURCE_ENCODING_INVALID) from None
    return name


def build_python_symbol_index(
    *,
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source: bytes,
    language: str = "python",
    limits: CstLimits = DEFAULT_CST_LIMITS,
) -> SymbolIndex:
    """Parse exact admitted Python bytes into a bounded immutable symbol index."""

    if type(source) is not bytes or type(limits) is not CstLimits:
        raise _fail(CstAdapterErrorCode.REQUEST_INVALID)
    if language != "python":
        raise _fail(CstAdapterErrorCode.LANGUAGE_UNSUPPORTED)
    if not (path.endswith(".py") or path.endswith(".pyi")):
        raise _fail(CstAdapterErrorCode.LANGUAGE_UNSUPPORTED)
    if len(source) > limits.max_source_bytes:
        raise _fail(CstAdapterErrorCode.SOURCE_LIMIT)
    if hashlib.sha256(source).hexdigest() != content_sha256:
        raise _fail(CstAdapterErrorCode.CONTENT_MISMATCH)
    encoding_invalid = False
    try:
        source.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        encoding_invalid = True
    if encoding_invalid:
        raise _fail(CstAdapterErrorCode.SOURCE_ENCODING_INVALID) from None
    parser_failed = False
    try:
        tree = Parser(Language(tree_sitter_python.language())).parse(source)
    except Exception:
        parser_failed = True
        tree = None
    if parser_failed or tree is None:
        raise _fail(CstAdapterErrorCode.PARSER_FAILURE) from None

    root = tree.root_node
    stack: list[tuple[Node, int]] = [(root, 0)]
    ordered_nodes: list[tuple[Node, int]] = []
    diagnostics: list[ParseDiagnostic] = []
    max_depth = 0
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise _fail(CstAdapterErrorCode.DEPTH_LIMIT)
        ordered_nodes.append((node, depth))
        if len(ordered_nodes) > limits.max_nodes:
            raise _fail(CstAdapterErrorCode.NODE_LIMIT)
        max_depth = max(max_depth, depth)
        if node.type == "ERROR" or node.is_missing:
            code = (
                ParseDiagnosticCode.MISSING_NODE
                if node.is_missing
                else ParseDiagnosticCode.ERROR_NODE
            )
            diagnostics.append(ParseDiagnostic(code=code, location=_range(node)))
            if len(diagnostics) > limits.max_diagnostics:
                raise _fail(CstAdapterErrorCode.DIAGNOSTIC_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.children))

    symbols: list[Symbol] = []
    occurrences: dict[tuple[SymbolKind, str], int] = {}
    module_name = _module_name(path)
    module_id = stable_symbol_id(repository_id, path, SymbolKind.MODULE, module_name, 0)
    symbols.append(
        Symbol(
            symbol_id=module_id,
            kind=SymbolKind.MODULE,
            name=module_name.rsplit(".", 1)[-1],
            qualified_name=module_name,
            occurrence=0,
            declaration=_range(root),
            name_location=SourceRange(0, 0, SourcePoint(0, 0), SourcePoint(0, 0)),
            parent_symbol_id=None,
        )
    )

    def visit(node: Node, parents: tuple[Symbol, ...]) -> None:
        if node.type == "decorated_definition":
            definition = next(
                (child for child in node.named_children if child.type.endswith("_definition")),
                None,
            )
            if definition is not None:
                visit_definition(definition, parents, declaration_node=node)
            return
        if node.type in {"class_definition", "function_definition"}:
            visit_definition(node, parents, declaration_node=node)
            return
        for child in node.named_children:
            visit(child, parents)

    def visit_definition(
        node: Node, parents: tuple[Symbol, ...], *, declaration_node: Node
    ) -> None:
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return
        name = _decode_name(source, name_node.start_byte, name_node.end_byte)
        parent = parents[-1] if parents else symbols[0]
        qualified_name = f"{parent.qualified_name}.{name}"
        if node.type == "class_definition":
            kind = SymbolKind.CLASS
        else:
            is_async = any(child.type == "async" for child in node.children)
            in_class = parent.kind is SymbolKind.CLASS
            kind = (
                SymbolKind.ASYNC_METHOD
                if is_async and in_class
                else SymbolKind.METHOD
                if in_class
                else SymbolKind.ASYNC_FUNCTION
                if is_async
                else SymbolKind.FUNCTION
            )
        occurrence_key = (kind, qualified_name)
        occurrence = occurrences.get(occurrence_key, 0)
        occurrences[occurrence_key] = occurrence + 1
        symbol = Symbol(
            symbol_id=stable_symbol_id(repository_id, path, kind, qualified_name, occurrence),
            kind=kind,
            name=name,
            qualified_name=qualified_name,
            occurrence=occurrence,
            declaration=_range(declaration_node),
            name_location=_range(name_node),
            parent_symbol_id=parent.symbol_id,
        )
        symbols.append(symbol)
        if len(symbols) > limits.max_symbols:
            raise _fail(CstAdapterErrorCode.SYMBOL_LIMIT)
        body = node.child_by_field_name("body")
        if body is not None:
            for child in body.named_children:
                visit(child, (*parents, symbol))

    for child in root.named_children:
        visit(child, ())

    health = ParseHealth.RECOVERED_WITH_ERRORS if diagnostics else ParseHealth.HEALTHY
    validation_failed = False
    try:
        index = _build_symbol_index(
            repository_id=repository_id,
            revision=revision,
            path=path,
            content_sha256=content_sha256,
            source=source,
            source_byte_length=len(source),
            source_end_point=_point(root.end_point),
            language="python",
            parser_id=_PARSER_ID,
            parse_health=health,
            symbols=tuple(symbols),
            diagnostics=tuple(diagnostics),
            node_count=len(ordered_nodes),
            max_depth=max_depth,
        )
    except ValueError:
        validation_failed = True
        index = None
    if validation_failed or index is None:
        raise _fail(CstAdapterErrorCode.REQUEST_INVALID) from None
    return index


__all__ = [
    "DEFAULT_CST_LIMITS",
    "CstAdapterError",
    "CstAdapterErrorCode",
    "CstLimits",
    "build_python_symbol_index",
]
