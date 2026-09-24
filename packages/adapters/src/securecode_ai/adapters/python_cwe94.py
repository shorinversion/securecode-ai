"""Bounded Python dynamic-code-execution facts for CWE-94.

The scanner consumes an admitted :class:`SymbolIndex` and its matching sealed
CPython AST analysis.  It recognizes a deliberately small, auditable set of
dynamic execution APIs, resolves only local aliases, and emits source ranges
and hashes.  It never imports, executes, or retains repository source text in
its result.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import RepositoryFile, SourcePoint, SourceRange, SymbolIndex

from .python_ast import (
    PythonAstAnalysis,
    PythonAstError,
    PythonAstStatus,
    analyze_python_ast,
    open_python_ast,
)

_MAX_LIMIT_VALUES = (2_000_000, 10_000, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class PythonCwe94ScanErrorCode(StrEnum):
    """Closed reasons a dynamic-code scan cannot produce a result."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe94ScanError(RuntimeError):
    """Fixed, non-echoing Python CWE-94 scanner failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe94ScanErrorCode) -> None:
        if type(code) is not PythonCwe94ScanErrorCode:
            raise TypeError("Python CWE-94 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-94 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe94Operation(StrEnum):
    """Recognized dynamic-code execution operations."""

    EVAL = "eval"
    EXEC = "exec"
    COMPILE = "compile"
    EXECFILE = "execfile"
    RUNSOURCE = "runsource"
    RUNPATH = "run_path"
    RUNMODULE = "run_module"


@dataclass(frozen=True, slots=True)
class PythonCwe94ScanLimits:
    """Hard ceilings for source, output, and alias resolution."""

    max_source_bytes: int = _MAX_LIMIT_VALUES[0]
    max_signals: int = _MAX_LIMIT_VALUES[1]
    max_resolution_depth: int = _MAX_LIMIT_VALUES[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("Python CWE-94 scan limits are invalid")


DEFAULT_PYTHON_CWE94_SCAN_LIMITS = PythonCwe94ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe94Signal:
    """One bounded input-to-dynamic-execution fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe94Operation
    detector: str = "securecode-python-cwe94@1.0"
    cwe: str = "CWE-94"

    def __post_init__(self) -> None:
        valid_identity = (
            type(self.repository_id) is str
            and bool(self.repository_id)
            and len(self.repository_id.encode("utf-8")) <= 1024
            and type(self.revision) is str
            and _SHA1.fullmatch(self.revision) is not None
            and type(self.path) is str
            and type(self.content_sha256) is str
            and _SHA256.fullmatch(self.content_sha256) is not None
            and type(self.source_size_bytes) is int
            and self.source_size_bytes >= 0
        )
        if valid_identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid_identity = False
        valid_ranges = (
            type(self.source) is SourceRange
            and type(self.sink) is SourceRange
            and self.sink.contains(self.source)
            and self.source.end_byte <= self.source_size_bytes
            and self.sink.end_byte <= self.source_size_bytes
        )
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not PythonCwe94Operation
            or self.detector != "securecode-python-cwe94@1.0"
            or self.cwe != "CWE-94"
        ):
            raise ValueError("Python CWE-94 signal is invalid")


@dataclass(frozen=True, slots=True)
class PythonCwe94ScanResult:
    """Source-free, deterministic CWE-94 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe94Signal, ...]
    scan_sha256: str

    def __post_init__(self) -> None:
        valid_identity = (
            type(self.repository_id) is str
            and bool(self.repository_id)
            and type(self.revision) is str
            and _SHA1.fullmatch(self.revision) is not None
            and type(self.path) is str
            and type(self.content_sha256) is str
            and _SHA256.fullmatch(self.content_sha256) is not None
            and type(self.source_size_bytes) is int
            and self.source_size_bytes >= 0
        )
        if valid_identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid_identity = False
        order = tuple(
            (
                item.sink.start_byte,
                item.sink.end_byte,
                item.source.start_byte,
                item.operation.value,
            )
            for item in self.signals
        )
        same_identity = all(
            item.repository_id == self.repository_id
            and item.revision == self.revision
            and item.path == self.path
            and item.content_sha256 == self.content_sha256
            and item.source_size_bytes == self.source_size_bytes
            for item in self.signals
        )
        if (
            not valid_identity
            or type(self.signals) is not tuple
            or any(type(item) is not PythonCwe94Signal for item in self.signals)
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
            or not same_identity
            or _SHA256.fullmatch(self.scan_sha256) is None
            or self.scan_sha256
            != _scan_sha256(
                self.repository_id,
                self.revision,
                self.path,
                self.content_sha256,
                self.source_size_bytes,
                self.signals,
            )
        ):
            raise ValueError("Python CWE-94 scan result is invalid")


_DIRECT_OPERATIONS: dict[str, PythonCwe94Operation] = {
    "eval": PythonCwe94Operation.EVAL,
    "exec": PythonCwe94Operation.EXEC,
    "compile": PythonCwe94Operation.COMPILE,
    "execfile": PythonCwe94Operation.EXECFILE,
    "builtins.eval": PythonCwe94Operation.EVAL,
    "builtins.exec": PythonCwe94Operation.EXEC,
    "builtins.compile": PythonCwe94Operation.COMPILE,
    "builtins.execfile": PythonCwe94Operation.EXECFILE,
    "__builtins__.eval": PythonCwe94Operation.EVAL,
    "__builtins__.exec": PythonCwe94Operation.EXEC,
    "__builtins__.compile": PythonCwe94Operation.COMPILE,
    "__builtins__.execfile": PythonCwe94Operation.EXECFILE,
    "code.InteractiveInterpreter.runsource": PythonCwe94Operation.RUNSOURCE,
    "code.InteractiveConsole.push": PythonCwe94Operation.RUNSOURCE,
    "runpy.run_path": PythonCwe94Operation.RUNPATH,
    "runpy.run_module": PythonCwe94Operation.RUNMODULE,
}
_BUILTIN_MODULES = frozenset({"builtins", "__builtins__"})
_BUILTIN_OPERATIONS = frozenset(
    {"eval", "exec", "compile", "execfile"}
)
_CODE_MODULES = frozenset({"code", "runpy"})


def scan_python_cwe94(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe94ScanLimits = DEFAULT_PYTHON_CWE94_SCAN_LIMITS,
) -> PythonCwe94ScanResult:
    """Return bounded facts for local Python dynamic-code execution calls.

    The supplied AST analysis must be produced for the exact sealed symbol
    index.  Unknown imports, indirect reflection, and unresolved aliases are
    ignored.  A malformed or mismatched analysis fails closed with a typed,
    source-free error.
    """

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe94ScanLimits
    ):
        raise PythonCwe94ScanError(PythonCwe94ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe94ScanError(PythonCwe94ScanErrorCode.SOURCE_LIMIT)

    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe94ScanError(PythonCwe94ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe94ScanError(PythonCwe94ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe94ScanError(PythonCwe94ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases: dict[str, str | None] = {}
    raw: list[tuple[SourceRange, SourceRange, PythonCwe94Operation]] = []
    _scan_statements(tree.body, aliases, source, line_starts, limits, raw)
    unique = sorted(
        set(raw),
        key=lambda item: (
            item[1].start_byte,
            item[1].end_byte,
            item[0].start_byte,
            item[2].value,
        ),
    )
    if len(unique) > limits.max_signals:
        raise PythonCwe94ScanError(PythonCwe94ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe94Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
        )
        for source_range, sink_range, operation in unique
    )
    return PythonCwe94ScanResult(
        repository_id=symbol_index.repository_id,
        revision=symbol_index.revision,
        path=symbol_index.path,
        content_sha256=symbol_index.content_sha256,
        source_size_bytes=symbol_index.source_byte_length,
        signals=signals,
        scan_sha256=_scan_sha256(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            signals,
        ),
    )


def _scan_statements(
    statements: list[ast.stmt],
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe94ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe94Operation]],
) -> None:
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _scan_function(statement, aliases, source, line_starts, limits, output)
            aliases[statement.name] = None
            continue
        if isinstance(statement, ast.ClassDef):
            _scan_decorators(statement.decorator_list, aliases, source, line_starts, limits, output)
            child_aliases = dict(aliases)
            _scan_statements(statement.body, child_aliases, source, line_starts, limits, output)
            aliases[statement.name] = None
            continue

        if isinstance(statement, ast.Import):
            _record_imports(statement, aliases)
        elif isinstance(statement, ast.ImportFrom):
            _record_import_from(statement, aliases)

        _scan_statement_calls(statement, aliases, source, line_starts, limits, output)
        _record_assignment_aliases(statement, aliases, limits.max_resolution_depth)
        _record_scope_bindings(statement, aliases)

        if isinstance(statement, ast.If):
            left = dict(aliases)
            right = dict(aliases)
            _scan_statements(statement.body, left, source, line_starts, limits, output)
            _scan_statements(statement.orelse, right, source, line_starts, limits, output)
            _merge_aliases(aliases, left, right)
        else:
            for child in _nested_statement_lists(statement):
                child_aliases = dict(aliases)
                _scan_statements(child, child_aliases, source, line_starts, limits, output)


def _scan_function(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe94ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe94Operation]],
) -> None:
    _scan_decorators(function.decorator_list, aliases, source, line_starts, limits, output)
    child_aliases = dict(aliases)
    parameters = (
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    )
    for parameter in parameters:
        child_aliases[parameter.arg] = None
    if function.args.vararg is not None:
        child_aliases[function.args.vararg.arg] = None
    if function.args.kwarg is not None:
        child_aliases[function.args.kwarg.arg] = None
    _scan_statements(function.body, child_aliases, source, line_starts, limits, output)


def _scan_decorators(
    decorators: list[ast.expr],
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe94ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe94Operation]],
) -> None:
    for decorator in decorators:
        for node in _expression_nodes(decorator):
            if isinstance(node, ast.Call):
                _record_call(node, aliases, source, line_starts, limits, output)


def _scan_statement_calls(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe94ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe94Operation]],
) -> None:
    for node in _statement_nodes(statement):
        if isinstance(node, ast.Call):
            _record_call(node, aliases, source, line_starts, limits, output)


def _record_call(
    call: ast.Call,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe94ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe94Operation]],
) -> None:
    operation = _operation_for_callable(call.func, aliases, limits.max_resolution_depth)
    if operation is None:
        return
    sink = _node_range(call, source, line_starts)
    input_node = _input_node(call, operation)
    input_range = _node_range(input_node, source, line_starts) if input_node is not None else sink
    if not sink.contains(input_range):
        raise PythonCwe94ScanError(PythonCwe94ScanErrorCode.INTEGRITY_FAILURE)
    output.append((input_range, sink, operation))
    if len(output) > limits.max_signals:
        raise PythonCwe94ScanError(PythonCwe94ScanErrorCode.SIGNAL_LIMIT)


def _operation_for_callable(
    callable_node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
) -> PythonCwe94Operation | None:
    if isinstance(callable_node, ast.Call):
        if _dotted_name(callable_node.func) not in {"getattr", "builtins.getattr"}:
            return None
        if len(callable_node.args) < 2 or callable_node.keywords:
            return None
        base = _canonical_reference(callable_node.args[0], aliases, max_depth)
        member = _literal_string(callable_node.args[1])
        if base is None or member is None:
            return None
        return _DIRECT_OPERATIONS.get(f"{base}.{member}")
    canonical = _canonical_reference(callable_node, aliases, max_depth)
    if canonical is None:
        return None
    return _DIRECT_OPERATIONS.get(canonical)


def _canonical_reference(
    node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe94ScanError(PythonCwe94ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        if node.id in aliases:
            return aliases[node.id]
        if node.id in _BUILTIN_MODULES or node.id in _BUILTIN_OPERATIONS:
            return node.id
        return None
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Subscript):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        member = _literal_string(node.slice)
        return None if base is None or member is None else f"{base}.{member}"
    if isinstance(node, ast.Call):
        if _dotted_name(node.func) not in {"getattr", "builtins.getattr"}:
            return None
        if len(node.args) < 2 or node.keywords:
            return None
        base = _canonical_reference(node.args[0], aliases, max_depth, depth + 1)
        member = _literal_string(node.args[1])
        return None if base is None or member is None else f"{base}.{member}"
    return None


def _input_node(call: ast.Call, operation: PythonCwe94Operation) -> ast.expr | None:
    keyword_names = {
        PythonCwe94Operation.EVAL: frozenset({"source", "object"}),
        PythonCwe94Operation.EXEC: frozenset({"source", "object"}),
        PythonCwe94Operation.COMPILE: frozenset({"source"}),
        PythonCwe94Operation.EXECFILE: frozenset({"filename"}),
        PythonCwe94Operation.RUNSOURCE: frozenset({"source"}),
        PythonCwe94Operation.RUNPATH: frozenset({"path_name"}),
        PythonCwe94Operation.RUNMODULE: frozenset({"mod_name"}),
    }[operation]
    for keyword in call.keywords:
        if keyword.arg in keyword_names:
            return keyword.value
    return call.args[0] if call.args else None


def _record_imports(statement: ast.Import, aliases: dict[str, str | None]) -> None:
    for imported in statement.names:
        if imported.name in _CODE_MODULES:
            aliases[imported.asname or imported.name.split(".", 1)[0]] = imported.name
        elif imported.name == "builtins":
            aliases[imported.asname or "builtins"] = "builtins"
        else:
            aliases[imported.asname or imported.name.split(".", 1)[0]] = None


def _record_import_from(statement: ast.ImportFrom, aliases: dict[str, str | None]) -> None:
    module = statement.module or ""
    if statement.level or module not in {"builtins", "__builtins__", "code", "runpy"}:
        for imported in statement.names:
            aliases[imported.asname or imported.name] = None
        return
    for imported in statement.names:
        name = imported.asname or imported.name
        canonical = f"{module}.{imported.name}"
        if imported.name == "*":
            continue
        aliases[name] = canonical if canonical in _DIRECT_OPERATIONS else None


def _record_assignment_aliases(
    statement: ast.stmt, aliases: dict[str, str | None], max_depth: int
) -> None:
    values: list[tuple[ast.expr, ast.expr]] = []
    if isinstance(statement, ast.Assign) and statement.targets:
        values.extend((target, statement.value) for target in statement.targets)
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        values.append((statement.target, statement.value))
    for target, value in values:
        if not isinstance(target, ast.Name):
            continue
        resolved = _canonical_reference(value, aliases, max_depth)
        aliases[target.id] = resolved


def _record_scope_bindings(statement: ast.stmt, aliases: dict[str, str | None]) -> None:
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        for name in _target_names(statement.target):
            aliases[name] = None
    elif isinstance(statement, (ast.With, ast.AsyncWith)):
        for item in statement.items:
            if item.optional_vars is not None:
                for name in _target_names(item.optional_vars):
                    aliases[name] = None
    elif isinstance(statement, ast.Try):
        for handler in statement.handlers:
            if handler.name is not None:
                aliases[handler.name] = None
    elif isinstance(statement, ast.Delete):
        for target in statement.targets:
            for name in _target_names(target):
                aliases.pop(name, None)


def _merge_aliases(
    target: dict[str, str | None], left: dict[str, str | None], right: dict[str, str | None]
) -> None:
    target.clear()
    for name in left.keys() | right.keys():
        left_value = left.get(name)
        right_value = right.get(name)
        target[name] = left_value if left_value == right_value else None


def _target_names(node: ast.AST) -> tuple[str, ...]:
    return tuple(item.id for item in ast.walk(node) if isinstance(item, ast.Name))


def _statement_nodes(statement: ast.stmt) -> tuple[ast.AST, ...]:
    output: list[ast.AST] = []
    stack: list[ast.AST] = [statement]
    while stack:
        node = stack.pop()
        if node is not statement and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            continue
        output.append(node)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(output)


def _expression_nodes(expression: ast.expr) -> tuple[ast.AST, ...]:
    output: list[ast.AST] = []
    stack: list[ast.AST] = [expression]
    while stack:
        node = stack.pop()
        if node is not expression and isinstance(node, (ast.Lambda, ast.FunctionDef, ast.ClassDef)):
            continue
        output.append(node)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(output)


def _nested_statement_lists(statement: ast.stmt) -> tuple[list[ast.stmt], ...]:
    if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
        return statement.body, statement.orelse
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        return (statement.body,)
    if isinstance(statement, ast.Try):
        return (
            statement.body,
            statement.orelse,
            statement.finalbody,
            *(handler.body for handler in statement.handlers),
        )
    return ()


def _literal_string(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None


def _dotted_name(node: ast.AST) -> str:
    parts: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _line_starts(source: bytes) -> tuple[int, ...]:
    starts = [0]
    starts.extend(index + 1 for index, value in enumerate(source) if value == 10)
    if starts[-1] != len(source):
        starts.append(len(source))
    return tuple(starts)


def _node_range(node: ast.AST, source: bytes, line_starts: tuple[int, ...]) -> SourceRange:
    try:
        start_line = node.lineno - 1  # type: ignore[attr-defined]
        end_line = node.end_lineno - 1  # type: ignore[attr-defined]
        start_column = node.col_offset  # type: ignore[attr-defined]
        end_column = node.end_col_offset  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        raise PythonCwe94ScanError(PythonCwe94ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe94ScanError(PythonCwe94ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe94ScanError(PythonCwe94ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start,
        end,
        SourcePoint(start_line, start_column),
        SourcePoint(end_line, end_column),
    )


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[PythonCwe94Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "detector": signal.detector,
                "operation": signal.operation.value,
                "sink": _range_value(signal.sink),
                "source": _range_value(signal.source),
            }
            for signal in signals
        ],
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


def _range_value(location: SourceRange) -> dict[str, int]:
    return {
        "end_byte": location.end_byte,
        "end_column": location.end_point.column,
        "end_row": location.end_point.row,
        "start_byte": location.start_byte,
        "start_column": location.start_point.column,
        "start_row": location.start_point.row,
    }


# Compatibility aliases make the module usable beside the existing Cwe89 and
# Python-prefixed portfolio adapters while keeping one implementation.
Cwe94ScanErrorCode = PythonCwe94ScanErrorCode
Cwe94ScanError = PythonCwe94ScanError
Cwe94ScanLimits = PythonCwe94ScanLimits
Cwe94Signal = PythonCwe94Signal
Cwe94ScanResult = PythonCwe94ScanResult


__all__ = [
    "DEFAULT_PYTHON_CWE94_SCAN_LIMITS",
    "Cwe94ScanError",
    "Cwe94ScanErrorCode",
    "Cwe94ScanLimits",
    "Cwe94ScanResult",
    "Cwe94Signal",
    "PythonCwe94Operation",
    "PythonCwe94ScanError",
    "PythonCwe94ScanErrorCode",
    "PythonCwe94ScanLimits",
    "PythonCwe94ScanResult",
    "PythonCwe94Signal",
    "scan_python_cwe94",
]
