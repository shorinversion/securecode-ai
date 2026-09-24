"""Bounded Python regular-expression denial-of-service facts for CWE-1333.

The scanner consumes an admitted :class:`~securecode_ai.core.SymbolIndex` and
its matching sealed CPython AST analysis.  It recognises only known regular
expression APIs, follows local callable and pattern aliases, and reports
catastrophic backtracking shapes in literal patterns.  Results contain ranges
and content-addressed metadata only; the pattern text is never retained in a
result or error.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from securecode_ai.core import RepositoryFile, SourcePoint, SourceRange, SymbolIndex

from .python_ast import (
    PythonAstAnalysis,
    PythonAstError,
    PythonAstStatus,
    analyze_python_ast,
    open_python_ast,
)

_MAX_LIMIT_VALUES = (2_000_000, 10_000, 64)
_MAX_PATTERN_BYTES = 65_536
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-python-cwe1333"
_DETECTOR = "securecode-python-cwe1333@1.0"

# ``re._parser`` is the parser used by the standard library implementation.
# It is read dynamically so unsupported runtimes fail closed in the scanner,
# instead of making this adapter import an implementation detail directly.
_REGEX_PARSER: Any = getattr(re, "_parser", None)
_REGEX_CONSTANTS: Any = getattr(re, "_constants", None)
_MAX_REPEAT: Any = getattr(_REGEX_CONSTANTS, "MAXREPEAT", object())


class PythonCwe1333ScanErrorCode(StrEnum):
    """Closed reasons a CWE-1333 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe1333ScanError(RuntimeError):
    """Fixed, non-echoing Python CWE-1333 scanner failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe1333ScanErrorCode) -> None:
        if type(code) is not PythonCwe1333ScanErrorCode:
            raise TypeError("Python CWE-1333 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-1333 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe1333Operation(StrEnum):
    """Recognised standard-library regular-expression operations."""

    COMPILE = "re.compile"
    MATCH = "re.match"
    FULLMATCH = "re.fullmatch"
    SEARCH = "re.search"
    FINDALL = "re.findall"
    FINDITER = "re.finditer"
    SPLIT = "re.split"
    SUB = "re.sub"
    SUBN = "re.subn"

    # ``regex`` exposes the same call shape.  It is an explicit known API,
    # rather than an arbitrary function whose name happens to be ``compile``.
    REGEX_COMPILE = "regex.compile"
    REGEX_MATCH = "regex.match"
    REGEX_FULLMATCH = "regex.fullmatch"
    REGEX_SEARCH = "regex.search"
    REGEX_FINDALL = "regex.findall"
    REGEX_FINDITER = "regex.finditer"
    REGEX_SPLIT = "regex.split"
    REGEX_SUB = "regex.sub"
    REGEX_SUBN = "regex.subn"


class PythonCwe1333Hazard(StrEnum):
    """Backtracking shape which makes a regex vulnerable to CWE-1333."""

    NESTED_QUANTIFIER = "nested_quantifier"
    AMBIGUOUS_ALTERNATION = "ambiguous_alternation"
    OVERLAPPING_QUANTIFIERS = "overlapping_quantifiers"


@dataclass(frozen=True, slots=True)
class PythonCwe1333ScanLimits:
    """Hard ceilings for source, output, aliases, and regex traversal."""

    max_source_bytes: int = _MAX_LIMIT_VALUES[0]
    max_signals: int = _MAX_LIMIT_VALUES[1]
    max_resolution_depth: int = _MAX_LIMIT_VALUES[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("Python CWE-1333 scan limits are invalid")


DEFAULT_PYTHON_CWE1333_SCAN_LIMITS = PythonCwe1333ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe1333Signal:
    """One immutable, source-free catastrophic-regex fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe1333Operation
    hazard: PythonCwe1333Hazard
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-1333"
    detector: str = _DETECTOR

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
        expected_id = (
            _signal_id(
                self.repository_id,
                self.revision,
                self.path,
                self.content_sha256,
                self.source_size_bytes,
                self.source,
                self.sink,
                self.operation,
                self.hazard,
            )
            if valid_identity
            and valid_ranges
            and type(self.operation) is PythonCwe1333Operation
            and type(self.hazard) is PythonCwe1333Hazard
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not PythonCwe1333Operation
            or type(self.hazard) is not PythonCwe1333Hazard
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-1333"
            or self.detector != _DETECTOR
        ):
            raise ValueError("Python CWE-1333 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete regular-expression call location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class PythonCwe1333ScanResult:
    """Source-free, deterministic CWE-1333 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe1333Signal, ...]
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
        valid_signals = type(self.signals) is tuple and all(
            type(item) is PythonCwe1333Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    item.sink.start_byte,
                    item.sink.end_byte,
                    item.source.start_byte,
                    item.source.end_byte,
                    item.operation.value,
                    item.hazard.value,
                )
                for item in self.signals
            )
            if valid_signals
            else ()
        )
        same_identity = (
            all(
                item.repository_id == self.repository_id
                and item.revision == self.revision
                and item.path == self.path
                and item.content_sha256 == self.content_sha256
                and item.source_size_bytes == self.source_size_bytes
                for item in self.signals
            )
            if valid_signals
            else False
        )
        if (
            not valid_identity
            or not valid_signals
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
            or not same_identity
            or type(self.scan_sha256) is not str
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
            raise ValueError("Python CWE-1333 scan result is invalid")


_DIRECT_OPERATIONS: dict[str, PythonCwe1333Operation] = {
    "re.compile": PythonCwe1333Operation.COMPILE,
    "re.match": PythonCwe1333Operation.MATCH,
    "re.fullmatch": PythonCwe1333Operation.FULLMATCH,
    "re.search": PythonCwe1333Operation.SEARCH,
    "re.findall": PythonCwe1333Operation.FINDALL,
    "re.finditer": PythonCwe1333Operation.FINDITER,
    "re.split": PythonCwe1333Operation.SPLIT,
    "re.sub": PythonCwe1333Operation.SUB,
    "re.subn": PythonCwe1333Operation.SUBN,
    "regex.compile": PythonCwe1333Operation.REGEX_COMPILE,
    "regex.match": PythonCwe1333Operation.REGEX_MATCH,
    "regex.fullmatch": PythonCwe1333Operation.REGEX_FULLMATCH,
    "regex.search": PythonCwe1333Operation.REGEX_SEARCH,
    "regex.findall": PythonCwe1333Operation.REGEX_FINDALL,
    "regex.finditer": PythonCwe1333Operation.REGEX_FINDITER,
    "regex.split": PythonCwe1333Operation.REGEX_SPLIT,
    "regex.sub": PythonCwe1333Operation.REGEX_SUB,
    "regex.subn": PythonCwe1333Operation.REGEX_SUBN,
}
_REGEX_MODULES = frozenset({"re", "regex"})


def scan_python_cwe1333(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe1333ScanLimits = DEFAULT_PYTHON_CWE1333_SCAN_LIMITS,
) -> PythonCwe1333ScanResult:
    """Return bounded facts for catastrophic Python regex calls.

    Only literal patterns and aliases assigned from literals are analysed.
    Unknown imports, dynamic pattern construction, arbitrary callables, and
    unresolved aliases are ignored.  Invalid or mismatched sealed inputs fail
    closed with a typed, source-free error.
    """

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe1333ScanLimits
    ):
        raise PythonCwe1333ScanError(PythonCwe1333ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe1333ScanError(PythonCwe1333ScanErrorCode.SOURCE_LIMIT)

    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe1333ScanError(PythonCwe1333ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe1333ScanError(PythonCwe1333ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe1333ScanError(PythonCwe1333ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases: dict[str, str | None] = {}
    patterns: dict[str, str | None] = {}
    raw: list[
        tuple[
            SourceRange,
            SourceRange,
            PythonCwe1333Operation,
            PythonCwe1333Hazard,
        ]
    ] = []
    try:
        _scan_statements(
            tree.body,
            aliases,
            patterns,
            source,
            line_starts,
            limits,
            raw,
        )
    except PythonCwe1333ScanError:
        raise
    except (MemoryError, RecursionError, TypeError, ValueError):
        raise PythonCwe1333ScanError(PythonCwe1333ScanErrorCode.INTEGRITY_FAILURE) from None

    unique = sorted(
        set(raw),
        key=lambda item: (
            item[1].start_byte,
            item[1].end_byte,
            item[0].start_byte,
            item[0].end_byte,
            item[2].value,
            item[3].value,
        ),
    )
    if len(unique) > limits.max_signals:
        raise PythonCwe1333ScanError(PythonCwe1333ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe1333Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
            hazard=hazard,
        )
        for source_range, sink_range, operation, hazard in unique
    )
    return PythonCwe1333ScanResult(
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
    patterns: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe1333ScanLimits,
    output: list[
        tuple[SourceRange, SourceRange, PythonCwe1333Operation, PythonCwe1333Hazard]
    ],
) -> None:
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            child_aliases = dict(aliases)
            child_patterns = dict(patterns)
            for parameter in (
                *statement.args.posonlyargs,
                *statement.args.args,
                *statement.args.kwonlyargs,
            ):
                child_aliases[parameter.arg] = None
                child_patterns[parameter.arg] = None
            if statement.args.vararg is not None:
                child_aliases[statement.args.vararg.arg] = None
                child_patterns[statement.args.vararg.arg] = None
            if statement.args.kwarg is not None:
                child_aliases[statement.args.kwarg.arg] = None
                child_patterns[statement.args.kwarg.arg] = None
            _scan_statements(
                statement.body,
                child_aliases,
                child_patterns,
                source,
                line_starts,
                limits,
                output,
            )
            aliases[statement.name] = None
            patterns[statement.name] = None
            continue
        if isinstance(statement, ast.ClassDef):
            child_aliases = dict(aliases)
            child_patterns = dict(patterns)
            _scan_statements(
                statement.body,
                child_aliases,
                child_patterns,
                source,
                line_starts,
                limits,
                output,
            )
            aliases[statement.name] = None
            patterns[statement.name] = None
            continue

        if isinstance(statement, ast.Import):
            _record_imports(statement, aliases)
        elif isinstance(statement, ast.ImportFrom):
            _record_import_from(statement, aliases)

        _scan_statement_calls(statement, aliases, patterns, source, line_starts, limits, output)
        _record_assignments(statement, aliases, patterns, limits.max_resolution_depth)
        _record_scope_bindings(statement, aliases, patterns)

        if isinstance(statement, ast.If):
            left_aliases = dict(aliases)
            right_aliases = dict(aliases)
            left_patterns = dict(patterns)
            right_patterns = dict(patterns)
            _scan_statements(
                statement.body,
                left_aliases,
                left_patterns,
                source,
                line_starts,
                limits,
                output,
            )
            _scan_statements(
                statement.orelse,
                right_aliases,
                right_patterns,
                source,
                line_starts,
                limits,
                output,
            )
            _merge_bindings(aliases, left_aliases, right_aliases)
            _merge_bindings(patterns, left_patterns, right_patterns)
        else:
            for child_statements in _nested_statement_lists(statement):
                child_aliases = dict(aliases)
                child_patterns = dict(patterns)
                _scan_statements(
                    child_statements,
                    child_aliases,
                    child_patterns,
                    source,
                    line_starts,
                    limits,
                    output,
                )


def _scan_statement_calls(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    patterns: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe1333ScanLimits,
    output: list[
        tuple[SourceRange, SourceRange, PythonCwe1333Operation, PythonCwe1333Hazard]
    ],
) -> None:
    for node in _statement_nodes(statement):
        if isinstance(node, ast.Call):
            _record_call(node, aliases, patterns, source, line_starts, limits, output)


def _record_call(
    call: ast.Call,
    aliases: dict[str, str | None],
    patterns: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe1333ScanLimits,
    output: list[
        tuple[SourceRange, SourceRange, PythonCwe1333Operation, PythonCwe1333Hazard]
    ],
) -> None:
    operation = _operation_for_callable(call.func, aliases, limits.max_resolution_depth)
    if operation is None:
        return
    pattern_node = _pattern_argument(call)
    if pattern_node is None:
        return
    pattern = _literal_pattern(pattern_node, patterns, limits.max_resolution_depth)
    if pattern is None:
        return
    hazard = _regex_hazard(pattern)
    if hazard is None:
        return
    sink = _node_range(call, source, line_starts)
    source_range = _node_range(pattern_node, source, line_starts)
    if not sink.contains(source_range):
        raise PythonCwe1333ScanError(PythonCwe1333ScanErrorCode.INTEGRITY_FAILURE)
    output.append((source_range, sink, operation, hazard))
    if len(output) > limits.max_signals:
        raise PythonCwe1333ScanError(PythonCwe1333ScanErrorCode.SIGNAL_LIMIT)


def _operation_for_callable(
    callable_node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
) -> PythonCwe1333Operation | None:
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
    return None if canonical is None else _DIRECT_OPERATIONS.get(canonical)


def _pattern_argument(call: ast.Call) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg in {"pattern", "regex", "expression"}:
            return keyword.value
    return call.args[0] if call.args else None


def _canonical_reference(
    node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe1333ScanError(PythonCwe1333ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        return aliases.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Subscript):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        member = _literal_string(node.slice)
        return None if base is None or member is None else f"{base}.{member}"
    return None


def _literal_pattern(
    node: ast.AST,
    patterns: dict[str, str | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe1333ScanError(PythonCwe1333ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Constant) and type(node.value) is str:
        return node.value if len(node.value.encode("utf-8")) <= _MAX_PATTERN_BYTES else None
    if isinstance(node, ast.Name):
        return patterns.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal_pattern(node.left, patterns, max_depth, depth + 1)
        right = _literal_pattern(node.right, patterns, max_depth, depth + 1)
        if left is None or right is None:
            return None
        value = left + right
        return value if len(value.encode("utf-8")) <= _MAX_PATTERN_BYTES else None
    return None


def _record_imports(statement: ast.Import, aliases: dict[str, str | None]) -> None:
    for imported in statement.names:
        root = imported.name.split(".", 1)[0]
        aliases[imported.asname or root] = (
            imported.name if imported.name in _REGEX_MODULES else None
        )


def _record_import_from(statement: ast.ImportFrom, aliases: dict[str, str | None]) -> None:
    module = statement.module or ""
    if statement.level or module not in _REGEX_MODULES:
        for imported in statement.names:
            aliases[imported.asname or imported.name] = None
        return
    for imported in statement.names:
        if imported.name == "*":
            continue
        name = imported.asname or imported.name
        canonical = f"{module}.{imported.name}"
        aliases[name] = canonical if canonical in _DIRECT_OPERATIONS else None


def _record_assignments(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    patterns: dict[str, str | None],
    max_depth: int,
) -> None:
    values: list[tuple[ast.expr, ast.expr]] = []
    if isinstance(statement, ast.Assign):
        values.extend((target, statement.value) for target in statement.targets)
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        values.append((statement.target, statement.value))
    for target, value in values:
        if not isinstance(target, ast.Name):
            continue
        aliases[target.id] = _canonical_reference(value, aliases, max_depth)
        patterns[target.id] = _literal_pattern(value, patterns, max_depth)


def _record_scope_bindings(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    patterns: dict[str, str | None],
) -> None:
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        for name in _target_names(statement.target):
            aliases[name] = None
            patterns[name] = None
    elif isinstance(statement, (ast.With, ast.AsyncWith)):
        for item in statement.items:
            if item.optional_vars is not None:
                for name in _target_names(item.optional_vars):
                    aliases[name] = None
                    patterns[name] = None
    elif isinstance(statement, ast.Try):
        for handler in statement.handlers:
            if handler.name is not None:
                aliases[handler.name] = None
                patterns[handler.name] = None
    elif isinstance(statement, ast.Delete):
        for target in statement.targets:
            for name in _target_names(target):
                aliases.pop(name, None)
                patterns.pop(name, None)


def _merge_bindings(
    target: dict[str, str | None],
    left: dict[str, str | None],
    right: dict[str, str | None],
) -> None:
    target.clear()
    for name in left.keys() | right.keys():
        left_value = left.get(name)
        right_value = right.get(name)
        target[name] = left_value if left_value == right_value else None


def _regex_hazard(pattern: str) -> PythonCwe1333Hazard | None:
    if _REGEX_PARSER is None or len(pattern.encode("utf-8")) > _MAX_PATTERN_BYTES:
        return None
    try:
        parsed = _REGEX_PARSER.parse(pattern, 0)
        return _sequence_hazard(tuple(parsed), 0)
    except (MemoryError, RecursionError):
        return None
    except Exception:
        # Invalid patterns and parser-specific constructs are not findings.
        return None


def _sequence_hazard(
    sequence: tuple[tuple[Any, Any], ...],
    depth: int,
    enclosing_unbounded: bool = False,
) -> PythonCwe1333Hazard | None:
    if depth > 64:
        return None
    repeat_summaries: list[tuple[int, _FirstInfo, bool]] = []
    for index, token in enumerate(sequence):
        if not isinstance(token, tuple) or len(token) != 2:
            continue
        operator, argument = token
        if _is_operator(operator, "BRANCH"):
            branches = argument[1] if isinstance(argument, tuple) and len(argument) > 1 else ()
            if enclosing_unbounded and _ambiguous_alternation(branches, depth + 1):
                return PythonCwe1333Hazard.AMBIGUOUS_ALTERNATION
            for branch in branches:
                hazard = _sequence_hazard(tuple(branch), depth + 1, enclosing_unbounded)
                if hazard is not None:
                    return hazard
            continue
        if _is_repeat(operator):
            minimum, maximum, body = _repeat_parts(argument)
            if body is None:
                continue
            unbounded = maximum == _MAX_REPEAT
            if unbounded and _has_variable_repeat(tuple(body), depth + 1):
                return PythonCwe1333Hazard.NESTED_QUANTIFIER
            hazard = _sequence_hazard(tuple(body), depth + 1, unbounded)
            if hazard is not None:
                return hazard
            if _is_backtracking_repeat(operator, minimum, maximum):
                repeat_summaries.append(
                    (index, _first_sequence(tuple(body), depth + 1), unbounded)
                )
            continue
        for child in _child_sequences(operator, argument):
            hazard = _sequence_hazard(tuple(child), depth + 1, enclosing_unbounded)
            if hazard is not None:
                return hazard

    for left, right in zip(repeat_summaries, repeat_summaries[1:]):
        if (left[2] or right[2]) and _first_overlap(left[1], right[1]):
            return PythonCwe1333Hazard.OVERLAPPING_QUANTIFIERS
    return None


def _has_variable_repeat(sequence: tuple[tuple[Any, Any], ...], depth: int) -> bool:
    if depth > 64:
        return False
    for token in sequence:
        if not isinstance(token, tuple) or len(token) != 2:
            continue
        operator, argument = token
        if _is_repeat(operator):
            minimum, maximum, body = _repeat_parts(argument)
            if body is not None and _is_backtracking_repeat(operator, minimum, maximum):
                return True
            if body is not None and _has_variable_repeat(tuple(body), depth + 1):
                return True
        elif any(
            _has_variable_repeat(tuple(child), depth + 1)
            for child in _child_sequences(operator, argument)
        ):
            return True
    return False


def _ambiguous_alternation(branches: Any, depth: int) -> bool:
    if depth > 64 or not isinstance(branches, (list, tuple)):
        return False
    infos = [_first_sequence(tuple(branch), depth + 1) for branch in branches]
    for index, left in enumerate(infos):
        for right in infos[index + 1 :]:
            if (left.nullable and right.nullable) or _first_overlap(left, right):
                return True
    return False


def _repeat_parts(argument: Any) -> tuple[int, Any, Any]:
    if not isinstance(argument, tuple) or len(argument) != 3:
        return 0, None, None
    minimum, maximum, body = argument
    if type(minimum) is not int or not isinstance(body, (list, tuple)):
        return 0, None, None
    return minimum, maximum, body


def _is_repeat(operator: Any) -> bool:
    return any(
        operator is getattr(_REGEX_CONSTANTS, name, object())
        for name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT")
    )


def _is_backtracking_repeat(operator: Any, minimum: int, maximum: Any) -> bool:
    possessive = getattr(_REGEX_CONSTANTS, "POSSESSIVE_REPEAT", object())
    return operator is not possessive and type(minimum) is int and maximum != minimum


def _is_operator(operator: Any, name: str) -> bool:
    return operator is getattr(_REGEX_CONSTANTS, name, object())


def _child_sequences(operator: Any, argument: Any) -> tuple[tuple[Any, ...], ...]:
    if _is_operator(operator, "SUBPATTERN") and isinstance(argument, tuple) and len(argument) == 4:
        return (tuple(argument[3]),)
    if _is_operator(operator, "ATOMIC_GROUP") and isinstance(argument, (list, tuple)):
        return (tuple(argument),)
    if _is_operator(operator, "BRANCH") and isinstance(argument, tuple) and len(argument) > 1:
        return tuple(tuple(branch) for branch in argument[1])
    if _is_operator(operator, "ASSERT") or _is_operator(operator, "ASSERT_NOT"):
        if (
            isinstance(argument, tuple)
            and len(argument) > 1
            and isinstance(argument[1], (list, tuple))
        ):
            return (tuple(argument[1]),)
    if _is_operator(operator, "GROUPREF_EXISTS") and isinstance(argument, tuple):
        return tuple(tuple(item) for item in argument[1:] if isinstance(item, (list, tuple)))
    return ()


@dataclass(frozen=True, slots=True)
class _FirstInfo:
    literals: frozenset[int] = frozenset()
    ranges: tuple[tuple[int, int], ...] = ()
    categories: frozenset[str] = frozenset()
    wildcard: bool = False
    nullable: bool = False


def _first_sequence(sequence: tuple[tuple[Any, Any], ...], depth: int) -> _FirstInfo:
    if depth > 64:
        return _FirstInfo(wildcard=True)
    result = _FirstInfo(nullable=True)
    for token in sequence:
        info = _first_token(token, depth + 1)
        result = _first_union(result, info)
        if not info.nullable:
            return _FirstInfo(
                result.literals,
                result.ranges,
                result.categories,
                result.wildcard,
                False,
            )
    return result


def _first_token(token: tuple[Any, Any], depth: int) -> _FirstInfo:
    if depth > 64 or not isinstance(token, tuple) or len(token) != 2:
        return _FirstInfo(wildcard=True)
    operator, argument = token
    if _is_operator(operator, "LITERAL") and type(argument) is int:
        return _FirstInfo(literals=frozenset({argument}))
    if _is_operator(operator, "RANGE") and isinstance(argument, tuple) and len(argument) == 2:
        return _FirstInfo(ranges=((argument[0], argument[1]),))
    if _is_operator(operator, "ANY") or _is_operator(operator, "NOT_LITERAL"):
        return _FirstInfo(wildcard=True)
    if _is_operator(operator, "CATEGORY"):
        return _FirstInfo(categories=frozenset({_category_name(argument)}))
    if _is_operator(operator, "IN") and isinstance(argument, (list, tuple)):
        result = _FirstInfo()
        for child in argument:
            if isinstance(child, tuple) and len(child) == 2:
                result = _first_union(result, _first_token(child, depth + 1))
        return result
    if _is_operator(operator, "BRANCH") and isinstance(argument, tuple) and len(argument) > 1:
        result = _FirstInfo(nullable=False)
        for branch in argument[1]:
            result = _first_union(result, _first_sequence(tuple(branch), depth + 1))
        return result
    if _is_repeat(operator):
        minimum, _maximum, body = _repeat_parts(argument)
        if body is None:
            return _FirstInfo(wildcard=True)
        info = _first_sequence(tuple(body), depth + 1)
        return _FirstInfo(
            info.literals,
            info.ranges,
            info.categories,
            info.wildcard,
            minimum == 0 or info.nullable,
        )
    if _is_operator(operator, "SUBPATTERN") and isinstance(argument, tuple) and len(argument) == 4:
        return _first_sequence(tuple(argument[3]), depth + 1)
    if _is_operator(operator, "ATOMIC_GROUP") and isinstance(argument, (list, tuple)):
        return _first_sequence(tuple(argument), depth + 1)
    if _is_operator(operator, "ASSERT") or _is_operator(operator, "ASSERT_NOT"):
        return _FirstInfo(nullable=True)
    if _is_operator(operator, "AT") or _is_operator(operator, "INFO"):
        return _FirstInfo(nullable=True)
    if _is_operator(operator, "SUCCESS"):
        return _FirstInfo(nullable=True)
    if _is_operator(operator, "FAILURE"):
        return _FirstInfo()
    if _is_operator(operator, "GROUPREF") or _is_operator(operator, "GROUPREF_EXISTS"):
        return _FirstInfo(wildcard=True)
    return _FirstInfo(wildcard=True)


def _first_union(left: _FirstInfo, right: _FirstInfo) -> _FirstInfo:
    return _FirstInfo(
        left.literals | right.literals,
        (*left.ranges, *right.ranges),
        left.categories | right.categories,
        left.wildcard or right.wildcard,
        left.nullable or right.nullable,
    )


def _first_overlap(left: _FirstInfo, right: _FirstInfo) -> bool:
    if left.wildcard or right.wildcard:
        return True
    if left.literals & right.literals:
        return True
    if any(_ranges_overlap(a, b) for a in left.ranges for b in right.ranges):
        return True
    if any(_literal_in_range(value, span) for value in left.literals for span in right.ranges):
        return True
    if any(_literal_in_range(value, span) for value in right.literals for span in left.ranges):
        return True
    if any(
        _category_matches_literal(category, value)
        for category in left.categories
        for value in right.literals
    ):
        return True
    if any(
        _category_matches_literal(category, value)
        for category in right.categories
        for value in left.literals
    ):
        return True
    return any(
        _categories_overlap(left_category, right_category)
        for left_category in left.categories
        for right_category in right.categories
    )


def _ranges_overlap(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return max(left[0], right[0]) <= min(left[1], right[1])


def _literal_in_range(value: int, span: tuple[int, int]) -> bool:
    return span[0] <= value <= span[1]


def _category_name(value: Any) -> str:
    text = str(value).lower()
    for name in ("not_digit", "not_word", "not_space", "digit", "word", "space"):
        if name in text:
            return name
    return "other"


def _category_matches_literal(category: str, value: int) -> bool:
    try:
        character = chr(value)
    except (ValueError, TypeError):
        return True
    if category == "digit":
        return character.isdigit()
    if category == "word":
        return character.isalnum() or character == "_"
    if category == "space":
        return character.isspace()
    if category.startswith("not_"):
        return not _category_matches_literal(category[4:], value)
    return True


def _categories_overlap(left: str, right: str) -> bool:
    if left == right or "other" in {left, right}:
        return True
    if left.startswith("not_"):
        return right != left[4:]
    if right.startswith("not_"):
        return left != right[4:]
    if {left, right} == {"digit", "word"}:
        return True
    return False


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
        raise PythonCwe1333ScanError(PythonCwe1333ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe1333ScanError(PythonCwe1333ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe1333ScanError(PythonCwe1333ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start,
        end,
        SourcePoint(start_line, start_column),
        SourcePoint(end_line, end_column),
    )


def _signal_id(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    source: SourceRange,
    sink: SourceRange,
    operation: PythonCwe1333Operation,
    hazard: PythonCwe1333Hazard,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
        "hazard": hazard.value,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "sink": _range_value(sink),
        "source": _range_value(source),
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[PythonCwe1333Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "detector": signal.detector,
                "hazard": signal.hazard.value,
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


# Compatibility aliases make the module usable beside the existing portfolio
# adapters while keeping one Python-specific implementation.
Cwe1333ScanErrorCode = PythonCwe1333ScanErrorCode
Cwe1333ScanError = PythonCwe1333ScanError
Cwe1333ScanLimits = PythonCwe1333ScanLimits
Cwe1333Signal = PythonCwe1333Signal
Cwe1333ScanResult = PythonCwe1333ScanResult


__all__ = [
    "DEFAULT_PYTHON_CWE1333_SCAN_LIMITS",
    "Cwe1333ScanError",
    "Cwe1333ScanErrorCode",
    "Cwe1333ScanLimits",
    "Cwe1333ScanResult",
    "Cwe1333Signal",
    "PythonCwe1333Hazard",
    "PythonCwe1333Operation",
    "PythonCwe1333ScanError",
    "PythonCwe1333ScanErrorCode",
    "PythonCwe1333ScanLimits",
    "PythonCwe1333ScanResult",
    "PythonCwe1333Signal",
    "scan_python_cwe1333",
]
