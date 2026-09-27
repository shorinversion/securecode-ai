"""Bounded Python LDAP-injection facts for CWE-90.

The scanner consumes an admitted :class:`~securecode_ai.core.SymbolIndex` and
its matching sealed CPython AST analysis.  It recognises a small, explicit set
of python-ldap and ldap3 operations, follows local aliases, and reports only
source ranges and content-addressed metadata.  Repository code is never
imported or executed and source text is not retained in a result or error.
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
_RULE_ID = "securecode-python-cwe90"
_DETECTOR = "securecode-python-cwe90@1.0"


class PythonCwe90ScanErrorCode(StrEnum):
    """Closed reasons an LDAP-injection scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe90ScanError(RuntimeError):
    """Fixed, non-echoing Python CWE-90 scanner failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe90ScanErrorCode) -> None:
        if type(code) is not PythonCwe90ScanErrorCode:
            raise TypeError("Python CWE-90 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-90 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe90Operation(StrEnum):
    """Recognised LDAP operations that consume a filter, DN, or value."""

    LDAP_SEARCH = "ldap.search"
    LDAP_SEARCH_S = "ldap.search_s"
    LDAP_SEARCH_EXT = "ldap.search_ext"
    LDAP_SEARCH_EXT_S = "ldap.search_ext_s"
    LDAP_COMPARE = "ldap.compare"
    LDAP_ADD = "ldap.add"
    LDAP_MODIFY = "ldap.modify"
    LDAP_DELETE = "ldap.delete"
    LDAP_MODIFY_DN = "ldap.modrdn"
    LDAP_INITIALIZED_SEARCH = "ldap.initialize.search"
    LDAP_INITIALIZED_SEARCH_S = "ldap.initialize.search_s"
    LDAP_INITIALIZED_SEARCH_EXT = "ldap.initialize.search_ext"
    LDAP_INITIALIZED_SEARCH_EXT_S = "ldap.initialize.search_ext_s"
    LDAP_INITIALIZED_COMPARE = "ldap.initialize.compare"
    LDAP_INITIALIZED_ADD = "ldap.initialize.add"
    LDAP_INITIALIZED_MODIFY = "ldap.initialize.modify"
    LDAP_INITIALIZED_DELETE = "ldap.initialize.delete"
    LDAP_INITIALIZED_MODIFY_DN = "ldap.initialize.modrdn"
    LDAP3_SEARCH = "ldap3.Connection.search"
    LDAP3_SEARCH_S = "ldap3.Connection.search_s"
    LDAP3_COMPARE = "ldap3.Connection.compare"
    LDAP3_ADD = "ldap3.Connection.add"
    LDAP3_MODIFY = "ldap3.Connection.modify"
    LDAP3_DELETE = "ldap3.Connection.delete"
    LDAP3_MODIFY_DN = "ldap3.Connection.modify_dn"

    # Short names are convenient to callers while the canonical values above
    # keep hashes stable across adapters.
    SEARCH = "ldap.search"
    SEARCH_S = "ldap.search_s"
    SEARCH_EXT = "ldap.search_ext"
    SEARCH_EXT_S = "ldap.search_ext_s"


@dataclass(frozen=True, slots=True)
class PythonCwe90ScanLimits:
    """Hard ceilings for source, output, and alias/data-flow resolution."""

    max_source_bytes: int = _MAX_LIMIT_VALUES[0]
    max_signals: int = _MAX_LIMIT_VALUES[1]
    max_resolution_depth: int = _MAX_LIMIT_VALUES[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("Python CWE-90 scan limits are invalid")


DEFAULT_PYTHON_CWE90_SCAN_LIMITS = PythonCwe90ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe90Signal:
    """One bounded untrusted-input-to-LDAP-operation fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe90Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-90"
    detector: str = _DETECTOR

    def __post_init__(self) -> None:
        identity_valid = (
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
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity_valid = False
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
            if identity_valid and valid_ranges and type(self.operation) is PythonCwe90Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not valid_ranges
            or type(self.operation) is not PythonCwe90Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-90"
            or self.detector != _DETECTOR
        ):
            raise ValueError("Python CWE-90 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete LDAP operation location."""

        return self.sink


@dataclass(frozen=True, slots=True)
class PythonCwe90ScanResult:
    """Source-free, deterministic CWE-90 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe90Signal, ...]
    scan_sha256: str

    def __post_init__(self) -> None:
        identity_valid = (
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
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity_valid = False
        valid_signals = type(self.signals) is tuple and all(
            type(item) is PythonCwe90Signal for item in self.signals
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
            not identity_valid
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
            raise ValueError("Python CWE-90 scan result is invalid")


_DIRECT_OPERATIONS: dict[str, PythonCwe90Operation] = {
    "ldap.search": PythonCwe90Operation.LDAP_SEARCH,
    "ldap.search_s": PythonCwe90Operation.LDAP_SEARCH_S,
    "ldap.search_ext": PythonCwe90Operation.LDAP_SEARCH_EXT,
    "ldap.search_ext_s": PythonCwe90Operation.LDAP_SEARCH_EXT_S,
    "ldap.compare": PythonCwe90Operation.LDAP_COMPARE,
    "ldap.add": PythonCwe90Operation.LDAP_ADD,
    "ldap.modify": PythonCwe90Operation.LDAP_MODIFY,
    "ldap.delete": PythonCwe90Operation.LDAP_DELETE,
    "ldap.modrdn": PythonCwe90Operation.LDAP_MODIFY_DN,
    "ldap.initialize.search": PythonCwe90Operation.LDAP_INITIALIZED_SEARCH,
    "ldap.initialize.search_s": PythonCwe90Operation.LDAP_INITIALIZED_SEARCH_S,
    "ldap.initialize.search_ext": PythonCwe90Operation.LDAP_INITIALIZED_SEARCH_EXT,
    "ldap.initialize.search_ext_s": PythonCwe90Operation.LDAP_INITIALIZED_SEARCH_EXT_S,
    "ldap.initialize.compare": PythonCwe90Operation.LDAP_INITIALIZED_COMPARE,
    "ldap.initialize.add": PythonCwe90Operation.LDAP_INITIALIZED_ADD,
    "ldap.initialize.modify": PythonCwe90Operation.LDAP_INITIALIZED_MODIFY,
    "ldap.initialize.delete": PythonCwe90Operation.LDAP_INITIALIZED_DELETE,
    "ldap.initialize.modrdn": PythonCwe90Operation.LDAP_INITIALIZED_MODIFY_DN,
    "ldap3.Connection.search": PythonCwe90Operation.LDAP3_SEARCH,
    "ldap3.Connection.search_s": PythonCwe90Operation.LDAP3_SEARCH_S,
    "ldap3.Connection.compare": PythonCwe90Operation.LDAP3_COMPARE,
    "ldap3.Connection.add": PythonCwe90Operation.LDAP3_ADD,
    "ldap3.Connection.modify": PythonCwe90Operation.LDAP3_MODIFY,
    "ldap3.Connection.delete": PythonCwe90Operation.LDAP3_DELETE,
    "ldap3.Connection.modify_dn": PythonCwe90Operation.LDAP3_MODIFY_DN,
}
_MODULES = frozenset({"ldap", "ldap3"})
_LDAP_IMPORT_MODULES = frozenset({"ldap", "ldap.filter", "ldap3", "ldap3.utils", "ldap3.utils.conv"})
_SANITIZERS = frozenset(
    {
        "ldap.filter.escape_filter_chars",
        "ldap.filter.escape_bytes",
        "ldap.filter.filter_format",
        "ldap3.utils.conv.escape_filter_chars",
        "ldap3.utils.dn.escape_rdn",
        "escape_filter_chars",
        "escape_bytes",
        "filter_format",
        "escape_rdn",
    }
)
_SOURCE_NAMES = frozenset(
    {
        "body",
        "cookies",
        "data",
        "form",
        "get_json",
        "headers",
        "args",
        "json",
        "params",
        "path",
        "query",
        "query_params",
        "query_string",
        "values",
        "GET",
        "POST",
    }
)
_SOURCE_ROOTS = frozenset({"request", "req", "http_request", "flask_request"})
_PARAMETER_NAMES = frozenset(
    {
        "arg",
        "attribute",
        "cn",
        "data",
        "dn",
        "email",
        "filter",
        "filter_str",
        "filterstr",
        "input",
        "ldap_filter",
        "name",
        "payload",
        "query",
        "search",
        "search_filter",
        "uid",
        "user",
        "username",
        "value",
    }
)


def scan_python_cwe90(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe90ScanLimits = DEFAULT_PYTHON_CWE90_SCAN_LIMITS,
) -> PythonCwe90ScanResult:
    """Return bounded facts for local Python LDAP calls fed by untrusted input.

    The analysis must be sealed for the exact supplied symbol index.  Unknown
    imports, reflection, and unresolved aliases are ignored.  Explicit LDAP
    escaping helpers are treated as sanitizers and do not produce a fact.
    """

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe90ScanLimits
    ):
        raise PythonCwe90ScanError(PythonCwe90ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe90ScanError(PythonCwe90ScanErrorCode.SOURCE_LIMIT)

    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe90ScanError(PythonCwe90ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe90ScanError(PythonCwe90ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe90ScanError(PythonCwe90ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases: dict[str, str | None] = {}
    raw: list[tuple[SourceRange, SourceRange, PythonCwe90Operation]] = []
    _scan_statements(tree.body, aliases, tree, source, line_starts, limits, raw)
    unique = sorted(
        set(raw),
        key=lambda item: (
            item[1].start_byte,
            item[1].end_byte,
            item[0].start_byte,
            item[0].end_byte,
            item[2].value,
        ),
    )
    if len(unique) > limits.max_signals:
        raise PythonCwe90ScanError(PythonCwe90ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe90Signal(
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
    return PythonCwe90ScanResult(
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
    tree: ast.AST,
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe90ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe90Operation]],
) -> None:
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _scan_function(statement, aliases, tree, source, line_starts, limits, output)
            aliases[statement.name] = None
            continue
        if isinstance(statement, ast.ClassDef):
            _scan_decorators(statement.decorator_list, aliases, tree, source, line_starts, limits, output)
            child_aliases = dict(aliases)
            _scan_statements(statement.body, child_aliases, tree, source, line_starts, limits, output)
            aliases[statement.name] = None
            continue

        if isinstance(statement, ast.Import):
            _record_imports(statement, aliases)
        elif isinstance(statement, ast.ImportFrom):
            _record_import_from(statement, aliases)

        _scan_expression_calls(statement, aliases, tree, source, line_starts, limits, output)
        _record_assignment_aliases(statement, aliases, limits.max_resolution_depth)
        _record_scope_bindings(statement, aliases, limits.max_resolution_depth)

        if isinstance(statement, ast.If):
            left = dict(aliases)
            right = dict(aliases)
            _scan_statements(statement.body, left, tree, source, line_starts, limits, output)
            _scan_statements(statement.orelse, right, tree, source, line_starts, limits, output)
            _merge_aliases(aliases, left, right)
        elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            body_aliases = dict(aliases)
            _scan_statements(statement.body, body_aliases, tree, source, line_starts, limits, output)
            else_aliases = dict(aliases)
            _scan_statements(statement.orelse, else_aliases, tree, source, line_starts, limits, output)
            _merge_aliases(aliases, body_aliases, else_aliases)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            parent_aliases = dict(aliases)
            child_aliases = dict(aliases)
            _scan_statements(statement.body, child_aliases, tree, source, line_starts, limits, output)
            _merge_aliases(aliases, parent_aliases, child_aliases)
        elif isinstance(statement, ast.Try):
            branches: list[dict[str, str | None]] = []
            body_aliases = dict(aliases)
            _scan_statements(statement.body, body_aliases, tree, source, line_starts, limits, output)
            branches.append(body_aliases)
            for handler in statement.handlers:
                handler_aliases = dict(aliases)
                if handler.name is not None:
                    handler_aliases[handler.name] = None
                _scan_statements(handler.body, handler_aliases, tree, source, line_starts, limits, output)
                branches.append(handler_aliases)
            else_aliases = dict(aliases)
            _scan_statements(statement.orelse, else_aliases, tree, source, line_starts, limits, output)
            branches.append(else_aliases)
            final_aliases = dict(aliases)
            _scan_statements(statement.finalbody, final_aliases, tree, source, line_starts, limits, output)
            branches.append(final_aliases)
            _merge_many_aliases(aliases, branches)
        else:
            for child in _nested_statement_lists(statement):
                parent_aliases = dict(aliases)
                child_aliases = dict(aliases)
                _scan_statements(child, child_aliases, tree, source, line_starts, limits, output)
                _merge_aliases(aliases, parent_aliases, child_aliases)


def _scan_function(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    tree: ast.AST,
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe90ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe90Operation]],
) -> None:
    _scan_decorators(function.decorator_list, aliases, tree, source, line_starts, limits, output)
    for default in (*function.args.defaults, *(item for item in function.args.kw_defaults if item)):
        _scan_expression(default, aliases, tree, source, line_starts, limits, output)
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
    _scan_statements(function.body, child_aliases, tree, source, line_starts, limits, output)


def _scan_decorators(
    decorators: list[ast.expr],
    aliases: dict[str, str | None],
    tree: ast.AST,
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe90ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe90Operation]],
) -> None:
    for decorator in decorators:
        _scan_expression(decorator, aliases, tree, source, line_starts, limits, output)


def _scan_expression_calls(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    tree: ast.AST,
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe90ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe90Operation]],
) -> None:
    _scan_expression(statement, aliases, tree, source, line_starts, limits, output)


def _scan_expression(
    root: ast.AST,
    aliases: dict[str, str | None],
    tree: ast.AST,
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe90ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe90Operation]],
) -> None:
    stack: list[ast.AST] = [root]
    while stack:
        node = stack.pop()
        if node is not root and isinstance(node, ast.stmt):
            continue
        if node is not root and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, ast.Call):
            _record_call(node, aliases, tree, source, line_starts, limits, output)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))


def _record_call(
    call: ast.Call,
    aliases: dict[str, str | None],
    tree: ast.AST,
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe90ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe90Operation]],
) -> None:
    operation = _operation_for_callable(call.func, aliases, limits.max_resolution_depth)
    if operation is None:
        return
    sink = _node_range(call, source, line_starts)
    for input_node in _input_nodes(call, operation):
        source_node = _resolve_source(
            input_node,
            call=call,
            tree=tree,
            source=source,
            aliases=aliases,
            max_depth=limits.max_resolution_depth,
            seen=frozenset(),
        )
        if source_node is None:
            continue
        # The tainted origin can be an earlier assignment outside the call.
        # Keep the reported source range on the sink expression so the
        # immutable fact remains a nested, source-free call projection.
        input_range = _node_range(input_node, source, line_starts)
        if not sink.contains(input_range):
            raise PythonCwe90ScanError(PythonCwe90ScanErrorCode.INTEGRITY_FAILURE)
        output.append((input_range, sink, operation))
        if len(output) > limits.max_signals:
            raise PythonCwe90ScanError(PythonCwe90ScanErrorCode.SIGNAL_LIMIT)


def _operation_for_callable(
    callable_node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
) -> PythonCwe90Operation | None:
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
    return _DIRECT_OPERATIONS.get(canonical or "")


def _canonical_reference(
    node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe90ScanError(PythonCwe90ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        return aliases.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Subscript):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        member = _literal_string(node.slice)
        return None if base is None or member is None else f"{base}.{member}"
    if isinstance(node, ast.Call):
        if _dotted_name(node.func) in {"getattr", "builtins.getattr"}:
            if len(node.args) < 2 or node.keywords:
                return None
            base = _canonical_reference(node.args[0], aliases, max_depth, depth + 1)
            member = _literal_string(node.args[1])
            return None if base is None or member is None else f"{base}.{member}"
        return _canonical_reference(node.func, aliases, max_depth, depth + 1)
    return None


def _input_nodes(call: ast.Call, operation: PythonCwe90Operation) -> tuple[ast.expr, ...]:
    """Return only arguments carrying an LDAP filter, DN, or compare value."""

    if operation in {
        PythonCwe90Operation.LDAP_SEARCH,
        PythonCwe90Operation.LDAP_SEARCH_S,
        PythonCwe90Operation.LDAP_SEARCH_EXT,
        PythonCwe90Operation.LDAP_SEARCH_EXT_S,
    }:
        indexes = (1, 3)
        keyword_names = ("base", "base_dn", "filter", "filterstr", "search_base", "search_filter")
        nodes = [call.args[index] for index in indexes if index < len(call.args)]
    elif operation in {
        PythonCwe90Operation.LDAP_INITIALIZED_SEARCH,
        PythonCwe90Operation.LDAP_INITIALIZED_SEARCH_S,
        PythonCwe90Operation.LDAP_INITIALIZED_SEARCH_EXT,
        PythonCwe90Operation.LDAP_INITIALIZED_SEARCH_EXT_S,
    }:
        indexes = (0, 2)
        keyword_names = ("base", "base_dn", "filter", "filterstr", "search_base", "search_filter")
        nodes = [call.args[index] for index in indexes if index < len(call.args)]
    elif operation in {
        PythonCwe90Operation.LDAP3_SEARCH,
        PythonCwe90Operation.LDAP3_SEARCH_S,
    }:
        keyword_names = ("search_base", "search_filter", "filter", "base")
        nodes = list(call.args[:2])
    elif operation in {
        PythonCwe90Operation.LDAP_COMPARE,
        PythonCwe90Operation.LDAP3_COMPARE,
        PythonCwe90Operation.LDAP_INITIALIZED_COMPARE,
    }:
        keyword_names = ("dn", "entry", "attr", "attribute", "value")
        nodes = list(call.args[:3])
    elif operation in {
        PythonCwe90Operation.LDAP_ADD,
        PythonCwe90Operation.LDAP_MODIFY,
        PythonCwe90Operation.LDAP_DELETE,
        PythonCwe90Operation.LDAP_MODIFY_DN,
        PythonCwe90Operation.LDAP3_ADD,
        PythonCwe90Operation.LDAP3_MODIFY,
        PythonCwe90Operation.LDAP3_DELETE,
        PythonCwe90Operation.LDAP3_MODIFY_DN,
        PythonCwe90Operation.LDAP_INITIALIZED_ADD,
        PythonCwe90Operation.LDAP_INITIALIZED_MODIFY,
        PythonCwe90Operation.LDAP_INITIALIZED_DELETE,
        PythonCwe90Operation.LDAP_INITIALIZED_MODIFY_DN,
    }:
        keyword_names = ("dn", "entry", "relative_dn", "attributes", "changes", "value")
        nodes = list(call.args[:2])
    else:
        keyword_names = ()
        nodes = []
    for keyword in call.keywords:
        if keyword.arg in keyword_names:
            nodes.append(keyword.value)
    return tuple(nodes)


def _resolve_source(
    subject: ast.expr,
    *,
    call: ast.Call,
    tree: ast.AST,
    source: bytes,
    aliases: dict[str, str | None],
    max_depth: int,
    seen: frozenset[str],
    before: tuple[int, int] | None = None,
    depth: int = 0,
) -> ast.expr | None:
    if depth > max_depth:
        raise PythonCwe90ScanError(PythonCwe90ScanErrorCode.SIGNAL_LIMIT)
    if _is_sanitizer_expression(subject, aliases, max_depth):
        return None
    direct = _direct_source_node(subject, source)
    if direct is not None:
        return direct
    if isinstance(subject, ast.Name):
        if subject.id in seen:
            return None
        assignment = _latest_assignment(tree, call, subject.id, before)
        if assignment is not None and assignment.value is not None:
            return _resolve_source(
                assignment.value,
                call=call,
                tree=tree,
                source=source,
                aliases=aliases,
                max_depth=max_depth,
                seen=seen | {subject.id},
                before=(assignment.lineno, assignment.col_offset),
                depth=depth + 1,
            )
        if _is_parameter_source(subject.id, call, tree):
            return subject
    for child in ast.iter_child_nodes(subject):
        if isinstance(child, ast.expr):
            resolved = _resolve_source(
                child,
                call=call,
                tree=tree,
                source=source,
                aliases=aliases,
                max_depth=max_depth,
                seen=seen,
                before=before,
                depth=depth + 1,
            )
            if resolved is not None:
                return resolved
    return None


def _direct_source_node(subject: ast.expr, source: bytes) -> ast.expr | None:
    stack: list[ast.AST] = [subject]
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Call) and _source_call(node, source):
            return node
        if isinstance(node, ast.Attribute) and _source_attribute(node):
            return node
        if isinstance(node, ast.Subscript) and _source_subscript(node):
            return node
        if isinstance(node, ast.Call) and _input_call(node):
            return node
        if isinstance(node, ast.Call) and _is_sanitizer_name(node.func, source):
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return None


def _source_call(node: ast.Call, source: bytes) -> bool:
    name = _source_name(node.func, source)
    if name in {"input", "builtins.input", "os.getenv", "os.environ.get"}:
        return True
    compact = _compact(source, node)
    return bool(
        re.match(
            r"(?:request|req|http_request|flask_request)(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])*\.(?:get|pop|setdefault)\(",
            compact,
        )
        or re.match(
            r"(?:event|context)\.get\(",
            compact,
        )
    )


def _source_attribute(node: ast.Attribute) -> bool:
    if node.attr not in _SOURCE_NAMES:
        return False
    root: ast.expr = node.value
    while isinstance(root, ast.Attribute):
        root = root.value
    return isinstance(root, ast.Name) and root.id in _SOURCE_ROOTS


def _source_subscript(node: ast.Subscript) -> bool:
    value = node.value
    if isinstance(value, ast.Attribute):
        if _source_attribute(value):
            return True
        return (
            isinstance(value.value, ast.Name)
            and value.value.id == "os"
            and value.attr == "environ"
        )
    return isinstance(value, ast.Name) and value.id in {"argv", "environ"}


def _input_call(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Name) and node.func.id == "input"


def _source_name(node: ast.AST, source: bytes) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _compact(source, node)
    return ""


def _is_sanitizer_expression(
    node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    return isinstance(node, ast.Call) and (
        _canonical_reference(node.func, aliases, max_depth) in _SANITIZERS
        or _canonical_reference(node.func, aliases, max_depth) in {
            "ldap.filter.filter_format",
            "ldap3.utils.conv.escape_filter_chars",
        }
    )


def _is_sanitizer_name(node: ast.AST, source: bytes) -> bool:
    return _compact(source, node) in _SANITIZERS


def _is_parameter_source(name: str, call: ast.Call, tree: ast.AST) -> bool:
    if name.lower() not in _PARAMETER_NAMES:
        return False
    scope = _enclosing_function(call, tree)
    if scope is None:
        return False
    parameters = (
        *scope.args.posonlyargs,
        *scope.args.args,
        *scope.args.kwonlyargs,
    )
    return any(parameter.arg == name for parameter in parameters) or (
        scope.args.vararg is not None and scope.args.vararg.arg == name
    ) or (scope.args.kwarg is not None and scope.args.kwarg.arg == name)


def _enclosing_function(
    call: ast.Call, tree: ast.AST
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    candidates: list[tuple[int, int, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    call_line = getattr(call, "lineno", -1)
    for item in ast.walk(tree):
        if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end_line = getattr(item, "end_lineno", None)
        if type(end_line) is int and item.lineno <= call_line <= end_line:
            candidates.append((end_line - item.lineno, item.col_offset, item))
    return min(candidates, default=(0, 0, None))[2]


def _latest_assignment(
    tree: ast.AST,
    call: ast.Call,
    name: str,
    before: tuple[int, int] | None,
) -> ast.Assign | ast.AnnAssign | None:
    scope = _enclosing_function(call, tree)
    root: ast.AST = scope if scope is not None else tree
    boundary = before or (getattr(call, "lineno", 0), getattr(call, "col_offset", 0))
    candidates: list[ast.Assign | ast.AnnAssign] = []
    stack: list[ast.AST] = [root]
    while stack:
        node = stack.pop()
        if node is not root and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            position = (node.lineno, node.col_offset)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if position < boundary and any(_target_has_name(target, name) for target in targets):
                candidates.append(node)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return max(candidates, key=lambda item: (item.lineno, item.col_offset), default=None)


def _record_imports(statement: ast.Import, aliases: dict[str, str | None]) -> None:
    for imported in statement.names:
        root = imported.name.split(".", 1)[0]
        if root not in _MODULES:
            aliases[imported.asname or root] = None
        elif imported.asname is None:
            # ``import ldap.filter`` binds the package name ``ldap``.
            aliases[root] = root
        elif imported.name in _LDAP_IMPORT_MODULES:
            aliases[imported.asname or root] = imported.name
        else:
            aliases[imported.asname or root] = root


def _record_import_from(statement: ast.ImportFrom, aliases: dict[str, str | None]) -> None:
    module = statement.module or ""
    if statement.level or not (module == "ldap" or module.startswith("ldap.") or module == "ldap3" or module.startswith("ldap3.")):
        for imported in statement.names:
            aliases[imported.asname or imported.name] = None
        return
    for imported in statement.names:
        if imported.name == "*":
            continue
        name = imported.asname or imported.name
        canonical = f"{module}.{imported.name}"
        if canonical in _DIRECT_OPERATIONS or canonical in _SANITIZERS:
            aliases[name] = canonical
        elif module in {"ldap3", "ldap3.core.connection"} and imported.name == "Connection":
            aliases[name] = "ldap3.Connection"
        else:
            aliases[name] = None


def _record_assignment_aliases(
    statement: ast.stmt, aliases: dict[str, str | None], max_depth: int
) -> None:
    values: list[tuple[ast.expr, ast.expr]] = []
    if isinstance(statement, ast.Assign) and statement.targets:
        values.extend((target, statement.value) for target in statement.targets)
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        values.append((statement.target, statement.value))
    for target, value in values:
        if isinstance(target, ast.Name):
            aliases[target.id] = _canonical_reference(value, aliases, max_depth)


def _record_scope_bindings(
    statement: ast.stmt, aliases: dict[str, str | None], max_depth: int
) -> None:
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        _invalidate_target_aliases(statement.target, aliases)
    elif isinstance(statement, (ast.With, ast.AsyncWith)):
        for item in statement.items:
            if item.optional_vars is not None:
                reference = _canonical_reference(item.context_expr, aliases, max_depth)
                for name in _target_names(item.optional_vars):
                    aliases[name] = reference
    elif isinstance(statement, ast.Try):
        for handler in statement.handlers:
            if handler.name is not None:
                aliases[handler.name] = None
    elif isinstance(statement, ast.Delete):
        _invalidate_target_aliases(statement, aliases)


def _invalidate_target_aliases(node: ast.AST, aliases: dict[str, str | None]) -> None:
    for name in _target_names(node):
        aliases[name] = None


def _merge_aliases(
    target: dict[str, str | None], left: dict[str, str | None], right: dict[str, str | None]
) -> None:
    target.clear()
    for name in left.keys() | right.keys():
        left_value = left.get(name)
        right_value = right.get(name)
        target[name] = left_value if left_value == right_value else None


def _merge_many_aliases(
    target: dict[str, str | None], branches: list[dict[str, str | None]]
) -> None:
    if not branches:
        return
    merged = dict(branches[0])
    for branch in branches[1:]:
        _merge_aliases(merged, merged, branch)
    target.clear()
    target.update(merged)


def _target_names(node: ast.AST) -> tuple[str, ...]:
    return tuple(item.id for item in ast.walk(node) if isinstance(item, ast.Name))


def _target_has_name(target: ast.expr, name: str) -> bool:
    return any(item.id == name for item in ast.walk(target) if isinstance(item, ast.Name))


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
    if isinstance(statement, ast.Match):
        return tuple(case.body for case in statement.cases)
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
        raise PythonCwe90ScanError(PythonCwe90ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe90ScanError(PythonCwe90ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe90ScanError(PythonCwe90ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start,
        end,
        SourcePoint(start_line, start_column),
        SourcePoint(end_line, end_column),
    )


def _compact(source: bytes, node: ast.AST) -> str:
    location = _node_range(node, source, _line_starts(source))
    return b"".join(source[location.start_byte : location.end_byte].split()).decode(
        "ascii", "ignore"
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
    operation: PythonCwe90Operation,
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
    signals: tuple[PythonCwe90Signal, ...],
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


# Compatibility aliases keep this adapter usable beside the existing CWE
# scanners while retaining the Python-specific implementation names.
Cwe90ScanErrorCode = PythonCwe90ScanErrorCode
Cwe90ScanError = PythonCwe90ScanError
Cwe90ScanLimits = PythonCwe90ScanLimits
Cwe90ScanResult = PythonCwe90ScanResult
Cwe90Signal = PythonCwe90Signal


__all__ = [
    "DEFAULT_PYTHON_CWE90_SCAN_LIMITS",
    "Cwe90ScanError",
    "Cwe90ScanErrorCode",
    "Cwe90ScanLimits",
    "Cwe90ScanResult",
    "Cwe90Signal",
    "PythonCwe90Operation",
    "PythonCwe90ScanError",
    "PythonCwe90ScanErrorCode",
    "PythonCwe90ScanLimits",
    "PythonCwe90ScanResult",
    "PythonCwe90Signal",
    "scan_python_cwe90",
]
