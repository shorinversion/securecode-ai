"""Bounded Python CWE-476 (``None`` dereference) facts.

This adapter reports only local dereferences whose receiver has a statically
provable nullable value.  The analysis is deliberately small and flow aware:
explicit ``None`` assignments, nullable annotations and parameters, nullable
function summaries, and APIs with a documented nullable result are followed
through local assignments.  Unknown values are ignored.  ``if value is not
None`` and equivalent bounded guards narrow the value for the guarded path.

The scanner consumes an admitted :class:`SymbolIndex` and the matching sealed
CPython AST analysis.  It never imports or executes repository code and emits
only immutable, source-free ranges and content-addressed metadata.
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
_RULE_ID = "securecode-python-cwe476"
_DETECTOR = "securecode-python-cwe476@1.0"
_DETAIL = "nullable_value_dereferenced_without_guard"


class PythonCwe476ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-476 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe476ScanError(RuntimeError):
    """Fixed scanner failure which never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe476ScanErrorCode) -> None:
        if type(code) is not PythonCwe476ScanErrorCode:
            raise TypeError("Python CWE-476 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-476 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe476Operation(StrEnum):
    """Kinds of local Python dereference represented by a signal."""

    ATTRIBUTE_DEREFERENCE = "attribute_dereference"
    SUBSCRIPT_DEREFERENCE = "subscript_dereference"

    # Compatibility names used by generic scanner consumers.
    ATTRIBUTE = "attribute_dereference"
    SUBSCRIPT = "subscript_dereference"


@dataclass(frozen=True, slots=True)
class PythonCwe476ScanLimits:
    """Hard ceilings for source, output, and local flow resolution."""

    max_source_bytes: int = _MAX_LIMIT_VALUES[0]
    max_signals: int = _MAX_LIMIT_VALUES[1]
    max_resolution_depth: int = _MAX_LIMIT_VALUES[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("Python CWE-476 scan limits are invalid")


DEFAULT_PYTHON_CWE476_SCAN_LIMITS = PythonCwe476ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe476Signal:
    """One immutable local nullable-source dereference fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe476Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-476"
    detector: str = _DETECTOR
    detail: str = _DETAIL

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
            )
            if valid_identity and valid_ranges and type(self.operation) is PythonCwe476Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not PythonCwe476Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-476"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-476 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete dereference location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class PythonCwe476ScanResult:
    """Source-free, deterministic CWE-476 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe476Signal, ...]
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
            type(item) is PythonCwe476Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    item.sink.start_byte,
                    item.sink.end_byte,
                    item.source.start_byte,
                    item.source.end_byte,
                    item.operation.value,
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
            raise ValueError("Python CWE-476 scan result is invalid")


class _Nullability(StrEnum):
    UNKNOWN = "unknown"
    NONNULL = "nonnull"
    NULL = "null"
    MAYBE_NULL = "maybe_null"


@dataclass(frozen=True, slots=True)
class _Flow:
    values: dict[str, _Nullability]
    nonnull: frozenset[str]
    fallthrough: bool = True


@dataclass(frozen=True, slots=True)
class _Fact:
    source: ast.expr
    sink: ast.Attribute | ast.Subscript
    operation: PythonCwe476Operation


def scan_python_cwe476(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe476ScanLimits = DEFAULT_PYTHON_CWE476_SCAN_LIMITS,
) -> PythonCwe476ScanResult:
    """Find bounded dereferences of locally proven nullable Python values."""

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe476ScanLimits
    ):
        raise PythonCwe476ScanError(PythonCwe476ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe476ScanError(PythonCwe476ScanErrorCode.SOURCE_LIMIT)

    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe476ScanError(PythonCwe476ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe476ScanError(PythonCwe476ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe476ScanError(PythonCwe476ScanErrorCode.ANALYSIS_UNAVAILABLE)

    _bounded_nodes(tree, limits.max_resolution_depth * 10_000)
    source = symbol_index.source
    line_starts = _line_starts(source)
    nullable_functions = _collect_nullable_functions(tree)
    facts: set[tuple[SourceRange, SourceRange, PythonCwe476Operation]] = set()
    try:
        _analyze_block(
            tree.body,
            _Flow({}, frozenset()),
            nullable_functions,
            limits,
            source,
            line_starts,
            facts,
        )
    except RecursionError:
        raise PythonCwe476ScanError(PythonCwe476ScanErrorCode.SIGNAL_LIMIT) from None
    if len(facts) > limits.max_signals:
        raise PythonCwe476ScanError(PythonCwe476ScanErrorCode.SIGNAL_LIMIT)

    ordered = tuple(
        sorted(
            facts,
            key=lambda item: (
                item[1].start_byte,
                item[1].end_byte,
                item[0].start_byte,
                item[0].end_byte,
                item[2].value,
            ),
        )
    )
    signals = tuple(
        PythonCwe476Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
        )
        for source_range, sink_range, operation in ordered
    )
    return PythonCwe476ScanResult(
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


def _analyze_block(
    statements: list[ast.stmt],
    flow: _Flow,
    nullable_functions: frozenset[str],
    limits: PythonCwe476ScanLimits,
    source: bytes,
    line_starts: tuple[int, ...],
    facts: set[tuple[SourceRange, SourceRange, PythonCwe476Operation]],
) -> _Flow:
    current = flow
    for statement in statements:
        if not current.fallthrough:
            break
        current = _analyze_statement(
            statement,
            current,
            nullable_functions,
            limits,
            source,
            line_starts,
            facts,
        )
    return current


def _analyze_statement(
    statement: ast.stmt,
    flow: _Flow,
    nullable_functions: frozenset[str],
    limits: PythonCwe476ScanLimits,
    source: bytes,
    line_starts: tuple[int, ...],
    facts: set[tuple[SourceRange, SourceRange, PythonCwe476Operation]],
) -> _Flow:
    values = dict(flow.values)
    nonnull = set(flow.nonnull)

    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
        initial = _function_flow(statement)
        _analyze_block(
            statement.body,
            initial,
            nullable_functions,
            limits,
            source,
            line_starts,
            facts,
        )
        return flow
    if isinstance(statement, ast.ClassDef):
        _analyze_block(
            statement.body,
            flow,
            nullable_functions,
            limits,
            source,
            line_starts,
            facts,
        )
        return flow
    if isinstance(statement, ast.If):
        _scan_expr(statement.test, flow, nullable_functions, limits, source, line_starts, facts)
        true_names, false_names = _guard_names(statement.test)
        true_flow = _with_guard(flow, true_names)
        false_flow = _with_guard(flow, false_names)
        body = _analyze_block(
            statement.body,
            true_flow,
            nullable_functions,
            limits,
            source,
            line_starts,
            facts,
        )
        orelse = (
            _analyze_block(
                statement.orelse,
                false_flow,
                nullable_functions,
                limits,
                source,
                line_starts,
                facts,
            )
            if statement.orelse
            else false_flow
        )
        return _merge_flows(body, orelse)
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        _scan_expr(statement.iter, flow, nullable_functions, limits, source, line_starts, facts)
        loop_values = dict(values)
        loop_nonnull = set(nonnull)
        _assign_target(statement.target, _Nullability.UNKNOWN, loop_values, loop_nonnull)
        body = _analyze_block(
            statement.body,
            _Flow(loop_values, frozenset(loop_nonnull)),
            nullable_functions,
            limits,
            source,
            line_starts,
            facts,
        )
        orelse = (
            _analyze_block(
                statement.orelse,
                flow,
                nullable_functions,
                limits,
                source,
                line_starts,
                facts,
            )
            if statement.orelse
            else flow
        )
        return _merge_flows(flow, _merge_flows(body, orelse))
    if isinstance(statement, (ast.While,)):
        _scan_expr(statement.test, flow, nullable_functions, limits, source, line_starts, facts)
        body = _analyze_block(
            statement.body,
            _Flow(values, frozenset(nonnull)),
            nullable_functions,
            limits,
            source,
            line_starts,
            facts,
        )
        orelse = (
            _analyze_block(
                statement.orelse,
                flow,
                nullable_functions,
                limits,
                source,
                line_starts,
                facts,
            )
            if statement.orelse
            else flow
        )
        return _merge_flows(flow, _merge_flows(body, orelse))
    if isinstance(statement, ast.Try):
        body = _analyze_block(
            statement.body,
            flow,
            nullable_functions,
            limits,
            source,
            line_starts,
            facts,
        )
        branches = [body]
        for handler in statement.handlers:
            branches.append(
                _analyze_block(
                    handler.body,
                    flow,
                    nullable_functions,
                    limits,
                    source,
                    line_starts,
                    facts,
                )
            )
        merged = branches[0]
        for branch in branches[1:]:
            merged = _merge_flows(merged, branch)
        if statement.finalbody:
            merged = _analyze_block(
                statement.finalbody,
                merged,
                nullable_functions,
                limits,
                source,
                line_starts,
                facts,
            )
        return _merge_flows(
            merged,
            _analyze_block(
                statement.orelse,
                body,
                nullable_functions,
                limits,
                source,
                line_starts,
                facts,
            )
            if statement.orelse
            else merged,
        )
    if isinstance(statement, (ast.Return, ast.Raise)):
        value = statement.value if isinstance(statement, ast.Return) else statement.exc
        if value is not None:
            _scan_expr(value, flow, nullable_functions, limits, source, line_starts, facts)
        return _Flow(values, frozenset(nonnull), False)
    if isinstance(statement, (ast.Break, ast.Continue)):
        return _Flow(values, frozenset(nonnull), False)
    if isinstance(statement, ast.Delete):
        for target in statement.targets:
            if isinstance(target, ast.Name):
                values.pop(target.id, None)
                nonnull.discard(target.id)
        return _Flow(values, frozenset(nonnull))
    if isinstance(statement, (ast.Assign, ast.AnnAssign)):
        value = statement.value
        annotation = statement.annotation if isinstance(statement, ast.AnnAssign) else None
        if value is None:
            status = (
                _Nullability.MAYBE_NULL
                if _annotation_nullable(annotation)
                else _Nullability.UNKNOWN
            )
        else:
            _scan_expr(value, flow, nullable_functions, limits, source, line_starts, facts)
            status = _expr_nullability(value, flow, nullable_functions, limits)
            if _annotation_nullable(annotation) and status in {
                _Nullability.UNKNOWN,
                _Nullability.MAYBE_NULL,
            }:
                status = _join_nullability(status, _Nullability.MAYBE_NULL)
        targets = (
            tuple(statement.targets) if isinstance(statement, ast.Assign) else (statement.target,)
        )
        for target in targets:
            _assign_target(target, status, values, nonnull)
        return _Flow(values, frozenset(nonnull))
    if isinstance(statement, ast.AugAssign):
        _scan_expr(statement.value, flow, nullable_functions, limits, source, line_starts, facts)
        _scan_expr(statement.target, flow, nullable_functions, limits, source, line_starts, facts)
        _assign_target(statement.target, _Nullability.UNKNOWN, values, nonnull)
        return _Flow(values, frozenset(nonnull))
    if isinstance(statement, ast.With):
        for item in statement.items:
            _scan_expr(
                item.context_expr, flow, nullable_functions, limits, source, line_starts, facts
            )
            if item.optional_vars is not None:
                status = _expr_nullability(item.context_expr, flow, nullable_functions, limits)
                _assign_target(item.optional_vars, status, values, nonnull)
        body = _analyze_block(
            statement.body,
            _Flow(values, frozenset(nonnull)),
            nullable_functions,
            limits,
            source,
            line_starts,
            facts,
        )
        return _merge_flows(flow, body)
    if isinstance(statement, ast.Match):
        _scan_expr(statement.subject, flow, nullable_functions, limits, source, line_starts, facts)
        branches = []
        for case in statement.cases:
            _scan_expr(
                case.guard, flow, nullable_functions, limits, source, line_starts, facts
            ) if case.guard else None
            branches.append(
                _analyze_block(
                    case.body,
                    flow,
                    nullable_functions,
                    limits,
                    source,
                    line_starts,
                    facts,
                )
            )
        merged = flow
        for branch in branches:
            merged = _merge_flows(merged, branch)
        return merged

    _scan_expr(statement, flow, nullable_functions, limits, source, line_starts, facts)
    return _Flow(values, frozenset(nonnull))


def _scan_expr(
    node: ast.AST | None,
    flow: _Flow,
    nullable_functions: frozenset[str],
    limits: PythonCwe476ScanLimits,
    source: bytes,
    line_starts: tuple[int, ...],
    facts: set[tuple[SourceRange, SourceRange, PythonCwe476Operation]],
) -> None:
    if node is None:
        return
    if isinstance(node, ast.Attribute):
        _scan_expr(node.value, flow, nullable_functions, limits, source, line_starts, facts)
        status = _expr_nullability(node.value, flow, nullable_functions, limits)
        if _is_nullable(status, node.value, flow):
            _add_fact(
                node.value,
                node,
                PythonCwe476Operation.ATTRIBUTE_DEREFERENCE,
                source,
                line_starts,
                facts,
            )
        return
    if isinstance(node, ast.Subscript):
        _scan_expr(node.value, flow, nullable_functions, limits, source, line_starts, facts)
        _scan_expr(node.slice, flow, nullable_functions, limits, source, line_starts, facts)
        status = _expr_nullability(node.value, flow, nullable_functions, limits)
        if _is_nullable(status, node.value, flow):
            _add_fact(
                node.value,
                node,
                PythonCwe476Operation.SUBSCRIPT_DEREFERENCE,
                source,
                line_starts,
                facts,
            )
        return
    for child in ast.iter_child_nodes(node):
        _scan_expr(child, flow, nullable_functions, limits, source, line_starts, facts)


def _add_fact(
    source_node: ast.expr,
    sink_node: ast.Attribute | ast.Subscript,
    operation: PythonCwe476Operation,
    source: bytes,
    line_starts: tuple[int, ...],
    facts: set[tuple[SourceRange, SourceRange, PythonCwe476Operation]],
) -> None:
    source_range = _node_range(source_node, source, line_starts)
    sink_range = _node_range(sink_node, source, line_starts)
    if not sink_range.contains(source_range):
        raise PythonCwe476ScanError(PythonCwe476ScanErrorCode.INTEGRITY_FAILURE)
    facts.add((source_range, sink_range, operation))


def _expr_nullability(
    node: ast.AST,
    flow: _Flow,
    nullable_functions: frozenset[str],
    limits: PythonCwe476ScanLimits,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> _Nullability:
    if depth > limits.max_resolution_depth:
        raise PythonCwe476ScanError(PythonCwe476ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        if node.id in flow.nonnull:
            return _Nullability.NONNULL
        return flow.values.get(node.id, _Nullability.UNKNOWN)
    if isinstance(node, ast.Constant):
        return _Nullability.NULL if node.value is None else _Nullability.NONNULL
    if isinstance(node, ast.JoinedStr | ast.List | ast.Tuple | ast.Set | ast.Dict | ast.Lambda):
        return _Nullability.NONNULL
    if isinstance(node, ast.Await | ast.UnaryOp):
        child = node.value if isinstance(node, ast.Await) else node.operand
        return _expr_nullability(child, flow, nullable_functions, limits, depth + 1, seen)
    if isinstance(node, ast.IfExp):
        return _join_nullability(
            _expr_nullability(node.body, flow, nullable_functions, limits, depth + 1, seen),
            _expr_nullability(node.orelse, flow, nullable_functions, limits, depth + 1, seen),
        )
    if isinstance(node, ast.BoolOp):
        statuses = tuple(
            _expr_nullability(value, flow, nullable_functions, limits, depth + 1, seen)
            for value in node.values
        )
        if isinstance(node.op, ast.Or) and _Nullability.NONNULL in statuses:
            return _Nullability.NONNULL
        if isinstance(node.op, ast.And) and _Nullability.UNKNOWN in statuses:
            return _Nullability.UNKNOWN
        if _Nullability.NULL in statuses:
            return _Nullability.MAYBE_NULL
        if _Nullability.MAYBE_NULL in statuses:
            return _Nullability.MAYBE_NULL
        return _Nullability.UNKNOWN if _Nullability.UNKNOWN in statuses else _Nullability.NONNULL
    if isinstance(node, ast.NamedExpr):
        return _expr_nullability(node.value, flow, nullable_functions, limits, depth + 1, seen)
    if isinstance(node, ast.Call):
        name = _canonical_name(node.func)
        if name in nullable_functions:
            return _Nullability.MAYBE_NULL
        if name in {
            "dict.get",
            "Mapping.get",
            "collections.abc.Mapping.get",
            "request.args.get",
            "request.form.get",
            "request.values.get",
            "request.headers.get",
            "request.json.get",
            "query_params.get",
            "params.get",
        }:
            # get(key, default) returns the default for a missing key, so only a
            # possibly-None default keeps the result nullable.
            default = node.args[1] if len(node.args) >= 2 else None
            for keyword in node.keywords:
                if keyword.arg == "default":
                    default = keyword.value
            if default is not None:
                return _join_nullability(
                    _Nullability.NONNULL,
                    _expr_nullability(default, flow, nullable_functions, limits, depth + 1, seen),
                )
            return _Nullability.MAYBE_NULL
        if name is not None and name.endswith(".pop") and len(node.args) < 2:
            return _Nullability.MAYBE_NULL
        if (
            name in {"getattr", "builtins.getattr"}
            and len(node.args) >= 3
            and _is_none_literal(node.args[2])
        ):
            return _Nullability.MAYBE_NULL
        if (
            name in {"next", "builtins.next"}
            and len(node.args) >= 2
            and _is_none_literal(node.args[1])
        ):
            return _Nullability.MAYBE_NULL
        if name in {"typing.cast", "cast"} and len(node.args) >= 2:
            return (
                _Nullability.MAYBE_NULL
                if _annotation_nullable(node.args[0])
                else _expr_nullability(
                    node.args[1], flow, nullable_functions, limits, depth + 1, seen
                )
            )
        return _Nullability.UNKNOWN
    if isinstance(node, ast.BinOp):
        return _Nullability.UNKNOWN
    if isinstance(node, ast.Compare):
        return _Nullability.NONNULL
    return _Nullability.UNKNOWN


def _is_nullable(status: _Nullability, node: ast.expr, flow: _Flow) -> bool:
    return status in {_Nullability.NULL, _Nullability.MAYBE_NULL} and not (
        isinstance(node, ast.Name) and node.id in flow.nonnull
    )


def _join_nullability(first: _Nullability, *rest: _Nullability) -> _Nullability:
    status = first
    for item in rest:
        if status is item:
            continue
        if _Nullability.UNKNOWN in {status, item}:
            status = _Nullability.UNKNOWN
        elif _Nullability.NULL in {status, item} or _Nullability.MAYBE_NULL in {status, item}:
            status = _Nullability.MAYBE_NULL
        else:
            status = _Nullability.NONNULL
    return status


def _assign_target(
    target: ast.AST,
    status: _Nullability,
    values: dict[str, _Nullability],
    nonnull: set[str],
) -> None:
    if isinstance(target, ast.Name):
        values[target.id] = status
        nonnull.discard(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            _assign_target(element, _Nullability.UNKNOWN, values, nonnull)


def _function_flow(function: ast.FunctionDef | ast.AsyncFunctionDef) -> _Flow:
    values: dict[str, _Nullability] = {}
    positional = [*function.args.posonlyargs, *function.args.args]
    defaults = [None] * (len(positional) - len(function.args.defaults)) + list(
        function.args.defaults
    )
    for argument, default in zip(positional, defaults, strict=True):
        if _annotation_nullable(argument.annotation) or _is_none_literal(default):
            values[argument.arg] = _Nullability.MAYBE_NULL
    for argument, default in zip(
        function.args.kwonlyargs,
        function.args.kw_defaults,
        strict=True,
    ):
        if _annotation_nullable(argument.annotation) or _is_none_literal(default):
            values[argument.arg] = _Nullability.MAYBE_NULL
    if function.args.vararg and _annotation_nullable(function.args.vararg.annotation):
        values[function.args.vararg.arg] = _Nullability.MAYBE_NULL
    if function.args.kwarg and _annotation_nullable(function.args.kwarg.annotation):
        values[function.args.kwarg.arg] = _Nullability.MAYBE_NULL
    return _Flow(values, frozenset())


def _collect_nullable_functions(tree: ast.AST) -> frozenset[str]:
    result: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if _annotation_nullable(node.returns) or _function_returns_none(node):
            result.add(node.name)
    return frozenset(result)


def _function_returns_none(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return whether this function directly returns the ``None`` literal."""

    stack: list[ast.AST] = list(function.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Return) and _is_none_literal(node.value):
            return True
        stack.extend(ast.iter_child_nodes(node))
    return False


def _guard_names(node: ast.expr | None) -> tuple[frozenset[str], frozenset[str]]:
    if node is None:
        return frozenset(), frozenset()
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        false_names, true_names = _guard_names(node.operand)
        return true_names, false_names
    if isinstance(node, ast.Name):
        return frozenset({node.id}), frozenset()
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        true: set[str] = set()
        for value in node.values:
            names, _ = _guard_names(value)
            true.update(names)
        return frozenset(true), frozenset()
    if (
        isinstance(node, ast.Call)
        and _canonical_name(node.func) in {"isinstance", "issubclass"}
        and node.args
    ) and isinstance(node.args[0], ast.Name):
        return frozenset({node.args[0].id}), frozenset()
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
        left, right = node.left, node.comparators[0]
        left_name = left.id if isinstance(left, ast.Name) else None
        right_name = right.id if isinstance(right, ast.Name) else None
        if _is_none_literal(right) and left_name is not None:
            names = frozenset({left_name})
        elif _is_none_literal(left) and right_name is not None:
            names = frozenset({right_name})
        else:
            return frozenset(), frozenset()
        operation = node.ops[0]
        if isinstance(operation, (ast.IsNot, ast.NotEq)):
            return names, frozenset()
        if isinstance(operation, (ast.Is, ast.Eq)):
            return frozenset(), names
    return frozenset(), frozenset()


def _with_guard(flow: _Flow, names: frozenset[str]) -> _Flow:
    return _Flow(dict(flow.values), flow.nonnull | names, flow.fallthrough)


def _merge_flows(left: _Flow, right: _Flow) -> _Flow:
    branches = [branch for branch in (left, right) if branch.fallthrough]
    if not branches:
        return _Flow(dict(left.values), frozenset(), False)
    names = set().union(*(branch.values.keys() for branch in branches))
    values = {
        name: _join_nullability(
            *(
                _Nullability.NONNULL
                if name in branch.nonnull
                else branch.values.get(name, _Nullability.UNKNOWN)
                for branch in branches
            )
        )
        for name in names
    }
    common_nonnull = set(branches[0].nonnull)
    for branch in branches[1:]:
        common_nonnull.intersection_update(branch.nonnull)
    return _Flow(values, frozenset(common_nonnull))


def _annotation_nullable(node: ast.AST | None) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        text = node.value.replace(" ", "")
        return "Optional[" in text or text.endswith("|None") or text.startswith("None|")
    if isinstance(node, ast.Name):
        return node.id in {"Optional", "None", "Any"}
    if isinstance(node, ast.Attribute):
        return node.attr in {"Optional", "Union"}
    if isinstance(node, ast.Subscript):
        base = _canonical_name(node.value)
        if base in {"Optional", "typing.Optional", "Union", "typing.Union"}:
            return True
        if base in {"Annotated", "typing.Annotated"}:
            return _annotation_nullable(node.slice)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return (
            _annotation_nullable(node.left)
            or _annotation_nullable(node.right)
            or _is_none_literal(node.left)
            or _is_none_literal(node.right)
        )
    return _is_none_literal(node)


def _canonical_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _canonical_name(node.value)
        return None if base is None else f"{base}.{node.attr}"
    return None


def _is_none_literal(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _bounded_nodes(tree: ast.AST, limit: int) -> tuple[ast.AST, ...]:
    if type(limit) is not int or limit < 1:
        raise PythonCwe476ScanError(PythonCwe476ScanErrorCode.REQUEST_INVALID)
    result: list[ast.AST] = []
    stack = [tree]
    while stack:
        node = stack.pop()
        result.append(node)
        if len(result) > limit:
            raise PythonCwe476ScanError(PythonCwe476ScanErrorCode.SIGNAL_LIMIT)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(result)


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
        raise PythonCwe476ScanError(PythonCwe476ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe476ScanError(PythonCwe476ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe476ScanError(PythonCwe476ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start, end, SourcePoint(start_line, start_column), SourcePoint(end_line, end_column)
    )


def _range_value(location: SourceRange) -> dict[str, int]:
    return {
        "end_byte": location.end_byte,
        "end_column": location.end_point.column,
        "end_row": location.end_point.row,
        "start_byte": location.start_byte,
        "start_column": location.start_point.column,
        "start_row": location.start_point.row,
    }


def _signal_id(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    source: SourceRange,
    sink: SourceRange,
    operation: PythonCwe476Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "sink": _range_value(sink),
        "source": _range_value(source),
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[PythonCwe476Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "detector": signal.detector,
                "operation": signal.operation.value,
                "rule_id": signal.rule_id,
                "signal_id": signal.signal_id,
                "sink": _range_value(signal.sink),
                "source": _range_value(signal.source),
            }
            for signal in signals
        ],
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


# Compatibility aliases keep this adapter usable beside existing CWE scanners.
Cwe476ScanError = PythonCwe476ScanError
Cwe476ScanErrorCode = PythonCwe476ScanErrorCode
Cwe476ScanLimits = PythonCwe476ScanLimits
Cwe476ScanResult = PythonCwe476ScanResult
Cwe476Signal = PythonCwe476Signal


__all__ = [
    "DEFAULT_PYTHON_CWE476_SCAN_LIMITS",
    "Cwe476ScanError",
    "Cwe476ScanErrorCode",
    "Cwe476ScanLimits",
    "Cwe476ScanResult",
    "Cwe476Signal",
    "PythonCwe476Operation",
    "PythonCwe476ScanError",
    "PythonCwe476ScanErrorCode",
    "PythonCwe476ScanLimits",
    "PythonCwe476ScanResult",
    "PythonCwe476Signal",
    "scan_python_cwe476",
]
