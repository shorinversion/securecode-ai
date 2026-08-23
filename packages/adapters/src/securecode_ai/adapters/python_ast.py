"""Bounded CPython AST analysis over an accepted source-bound symbol index."""

from __future__ import annotations

import ast
import copy
import hashlib
import hmac
import json
import secrets
import sys
from dataclasses import dataclass, field
from enum import StrEnum

from securecode_ai.core import SourcePoint, SymbolIndex

_MAX_AST_LIMIT_VALUES = (2_000_000, 250_000, 512)
_AST_AUTHORITY_KEY = secrets.token_bytes(32)
_PARSER_ID = f"cpython-ast@{sys.version_info.major}.{sys.version_info.minor}"


class PythonAstStatus(StrEnum):
    PARSED = "parsed"
    SYNTAX_ERROR = "syntax_error"


class PythonAstDiagnosticCode(StrEnum):
    SYNTAX_ERROR = "SYNTAX_ERROR"


class PythonAstErrorCode(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    PARSER_FAILURE = "PARSER_FAILURE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonAstError(RuntimeError):
    """Fixed, non-echoing CPython AST boundary failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonAstErrorCode) -> None:
        if type(code) is not PythonAstErrorCode:
            raise TypeError("Python AST error code is invalid")
        self.code = code
        self.safe_message = "Python AST analysis failed"
        super().__init__(self.safe_message)


@dataclass(frozen=True, slots=True)
class PythonAstLimits:
    max_source_bytes: int = _MAX_AST_LIMIT_VALUES[0]
    max_nodes: int = _MAX_AST_LIMIT_VALUES[1]
    max_depth: int = _MAX_AST_LIMIT_VALUES[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_nodes, self.max_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_AST_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("Python AST limits are invalid")


DEFAULT_PYTHON_AST_LIMITS = PythonAstLimits()


@dataclass(frozen=True, slots=True)
class PythonAstDiagnostic:
    code: PythonAstDiagnosticCode
    start_point: SourcePoint
    end_point: SourcePoint

    def __post_init__(self) -> None:
        if (
            type(self.code) is not PythonAstDiagnosticCode
            or type(self.start_point) is not SourcePoint
            or type(self.end_point) is not SourcePoint
            or self.end_point < self.start_point
        ):
            raise ValueError("Python AST diagnostic is invalid")


@dataclass(frozen=True, slots=True)
class PythonAstAnalysis:
    symbol_index_sha256: str
    parser_id: str
    status: PythonAstStatus
    node_count: int
    max_depth: int
    tree_sha256: str | None
    diagnostic: PythonAstDiagnostic | None
    _tree: ast.Module | None = field(repr=False, compare=False)
    _authority_seal: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        valid = (
            type(self.symbol_index_sha256) is str
            and len(self.symbol_index_sha256) == 64
            and all(character in "0123456789abcdef" for character in self.symbol_index_sha256)
            and self.parser_id == _PARSER_ID
            and type(self.status) is PythonAstStatus
            and type(self.node_count) is int
            and self.node_count >= 0
            and type(self.max_depth) is int
            and self.max_depth >= 0
            and (self.tree_sha256 is None or _is_sha256(self.tree_sha256))
            and (self.diagnostic is None or type(self.diagnostic) is PythonAstDiagnostic)
            and (self._tree is None or type(self._tree) is ast.Module)
        )
        if not valid:
            raise ValueError("Python AST analysis is invalid")
        if self.status is PythonAstStatus.PARSED:
            if (
                self._tree is None
                or self.tree_sha256 is None
                or self.diagnostic is not None
                or self.node_count < 1
                or _tree_sha256(self._tree) != self.tree_sha256
            ):
                raise ValueError("Python AST analysis is invalid")
        elif (
            self._tree is not None
            or self.tree_sha256 is not None
            or self.diagnostic is None
            or self.node_count != 0
            or self.max_depth != 0
        ):
            raise ValueError("Python AST analysis is invalid")
        if type(self._authority_seal) is not bytes or not hmac.compare_digest(
            self._authority_seal, _analysis_seal(self)
        ):
            raise ValueError("Python AST analysis is invalid")


def analyze_python_ast(
    symbol_index: SymbolIndex,
    *,
    limits: PythonAstLimits = DEFAULT_PYTHON_AST_LIMITS,
) -> PythonAstAnalysis:
    """Parse exact P2.3-admitted Python bytes without filesystem or execution access."""

    if type(symbol_index) is not SymbolIndex or type(limits) is not PythonAstLimits:
        raise PythonAstError(PythonAstErrorCode.REQUEST_INVALID)
    admitted_index = _validated_symbol_index(symbol_index)
    if len(admitted_index.source) > limits.max_source_bytes:
        raise PythonAstError(PythonAstErrorCode.SOURCE_LIMIT)

    syntax_values: tuple[int | None, int | None, int | None, int | None] | None = None
    parser_failed = False
    try:
        tree = ast.parse(
            admitted_index.source,
            filename="<admitted-python>",
            mode="exec",
            type_comments=True,
        )
    except SyntaxError as error:
        syntax_values = (error.lineno, error.offset, error.end_lineno, error.end_offset)
        tree = None
    except Exception:
        parser_failed = True
        tree = None
    if parser_failed:
        raise PythonAstError(PythonAstErrorCode.PARSER_FAILURE) from None
    if tree is None:
        diagnostic = _syntax_diagnostic(admitted_index.source, syntax_values)
        return _make_analysis(
            symbol_index_sha256=admitted_index.index_sha256,
            status=PythonAstStatus.SYNTAX_ERROR,
            node_count=0,
            max_depth=0,
            tree_sha256=None,
            diagnostic=diagnostic,
            tree=None,
        )

    stack: list[tuple[ast.AST, int]] = [(tree, 0)]
    node_count = 0
    max_depth = 0
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise PythonAstError(PythonAstErrorCode.DEPTH_LIMIT)
        node_count += 1
        if node_count > limits.max_nodes:
            raise PythonAstError(PythonAstErrorCode.NODE_LIMIT)
        max_depth = max(max_depth, depth)
        children = tuple(ast.iter_child_nodes(node))
        stack.extend((child, depth + 1) for child in reversed(children))
    return _make_analysis(
        symbol_index_sha256=admitted_index.index_sha256,
        status=PythonAstStatus.PARSED,
        node_count=node_count,
        max_depth=max_depth,
        tree_sha256=_tree_sha256(tree),
        diagnostic=None,
        tree=tree,
    )


def open_python_ast(analysis: PythonAstAnalysis) -> ast.Module:
    """Return an isolated copy after revalidating process-local provenance and integrity."""

    invalid = False
    try:
        snapshot = copy.deepcopy(analysis._tree)
        PythonAstAnalysis(
            symbol_index_sha256=analysis.symbol_index_sha256,
            parser_id=analysis.parser_id,
            status=analysis.status,
            node_count=analysis.node_count,
            max_depth=analysis.max_depth,
            tree_sha256=analysis.tree_sha256,
            diagnostic=analysis.diagnostic,
            _tree=snapshot,
            _authority_seal=analysis._authority_seal,
        )
    except MemoryError:
        raise
    except Exception:
        invalid = True
    if invalid:
        raise PythonAstError(PythonAstErrorCode.INTEGRITY_FAILURE) from None
    if analysis.status is not PythonAstStatus.PARSED or snapshot is None:
        raise PythonAstError(PythonAstErrorCode.REQUEST_INVALID)
    return snapshot


def _validated_symbol_index(symbol_index: SymbolIndex) -> SymbolIndex:
    invalid = False
    try:
        validated = SymbolIndex(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source=symbol_index.source,
            source_byte_length=symbol_index.source_byte_length,
            source_end_point=symbol_index.source_end_point,
            language=symbol_index.language,
            parser_id=symbol_index.parser_id,
            parse_health=symbol_index.parse_health,
            symbols=symbol_index.symbols,
            diagnostics=symbol_index.diagnostics,
            node_count=symbol_index.node_count,
            max_depth=symbol_index.max_depth,
            index_sha256=symbol_index.index_sha256,
            _authority_seal=symbol_index._authority_seal,
        )
    except (AttributeError, TypeError, ValueError):
        invalid = True
        validated = None
    if invalid or validated is None:
        raise PythonAstError(PythonAstErrorCode.INTEGRITY_FAILURE) from None
    return validated


def _make_analysis(
    *,
    symbol_index_sha256: str,
    status: PythonAstStatus,
    node_count: int,
    max_depth: int,
    tree_sha256: str | None,
    diagnostic: PythonAstDiagnostic | None,
    tree: ast.Module | None,
) -> PythonAstAnalysis:
    provisional = object.__new__(PythonAstAnalysis)
    values = {
        "symbol_index_sha256": symbol_index_sha256,
        "parser_id": _PARSER_ID,
        "status": status,
        "node_count": node_count,
        "max_depth": max_depth,
        "tree_sha256": tree_sha256,
        "diagnostic": diagnostic,
        "_tree": tree,
    }
    for name, value in values.items():
        object.__setattr__(provisional, name, value)
    object.__setattr__(provisional, "_authority_seal", b"")
    return PythonAstAnalysis(
        symbol_index_sha256=symbol_index_sha256,
        parser_id=_PARSER_ID,
        status=status,
        node_count=node_count,
        max_depth=max_depth,
        tree_sha256=tree_sha256,
        diagnostic=diagnostic,
        _tree=tree,
        _authority_seal=_analysis_seal(provisional),
    )


def _analysis_seal(analysis: PythonAstAnalysis) -> bytes:
    diagnostic = analysis.diagnostic
    value = {
        "diagnostic": (
            None
            if diagnostic is None
            else {
                "code": diagnostic.code.value,
                "end": [diagnostic.end_point.row, diagnostic.end_point.column],
                "start": [diagnostic.start_point.row, diagnostic.start_point.column],
            }
        ),
        "max_depth": analysis.max_depth,
        "node_count": analysis.node_count,
        "parser_id": analysis.parser_id,
        "status": analysis.status.value,
        "symbol_index_sha256": analysis.symbol_index_sha256,
        "tree_sha256": analysis.tree_sha256,
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hmac.digest(_AST_AUTHORITY_KEY, encoded, "sha256")


def _syntax_diagnostic(
    source: bytes,
    values: tuple[int | None, int | None, int | None, int | None] | None,
) -> PythonAstDiagnostic:
    text = source.decode("utf-8", errors="strict")
    lines = text.splitlines(keepends=True) or [""]
    lineno, offset, end_lineno, end_offset = values or (None, None, None, None)
    start = _syntax_point(lines, lineno, offset)
    end = _syntax_point(lines, end_lineno or lineno, end_offset or offset)
    if end < start:
        end = start
    return PythonAstDiagnostic(
        code=PythonAstDiagnosticCode.SYNTAX_ERROR,
        start_point=start,
        end_point=end,
    )


def _syntax_point(lines: list[str], lineno: int | None, offset: int | None) -> SourcePoint:
    row = min(max((lineno or 1) - 1, 0), len(lines) - 1)
    line = lines[row]
    character_column = min(max((offset or 1) - 1, 0), len(line))
    return SourcePoint(row=row, column=len(line[:character_column].encode("utf-8")))


def _tree_sha256(tree: ast.Module) -> str:
    dumped = ast.dump(tree, annotate_fields=True, include_attributes=True, indent=None)
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


__all__ = [
    "DEFAULT_PYTHON_AST_LIMITS",
    "PythonAstAnalysis",
    "PythonAstDiagnostic",
    "PythonAstDiagnosticCode",
    "PythonAstError",
    "PythonAstErrorCode",
    "PythonAstLimits",
    "PythonAstStatus",
    "analyze_python_ast",
    "open_python_ast",
]
