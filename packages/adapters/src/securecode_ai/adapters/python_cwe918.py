"""Bounded Python source-to-sink facts for CWE-918 SSRF.

The scanner consumes a sealed :class:`~securecode_ai.core.SymbolIndex` and
its matching sealed CPython AST analysis.  It recognizes explicit request
data sources from common Flask, Django, and ASGI shapes and a small allow-list
of outbound HTTP clients.  Only local aliases and bounded value propagation
are followed.  Results contain immutable locations and content-addressed
metadata; source bytes are never retained in a signal or an error message.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Iterable
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

_MAX_LIMITS = (2_000_000, 10_000, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-python-cwe918"
_DETECTOR = "securecode-python-cwe918@1.0"
_DETAIL = "untrusted_url_to_http_client"

_HTTP_METHODS = frozenset({"delete", "get", "head", "options", "patch", "post", "put", "request"})
_REQUEST_MODULES = frozenset({"requests", "requests.api"})
_HTTPX_MODULES = frozenset({"httpx"})
_AIOHTTP_MODULES = frozenset({"aiohttp"})
_REQUEST_CLIENTS = frozenset(
    {
        "requests.Session",
        "requests.sessions.Session",
        "httpx.Client",
        "httpx.AsyncClient",
        "aiohttp.ClientSession",
    }
)
_REQUEST_SOURCE_ROOTS = frozenset(
    {
        "environ",
        "http_request",
        "request",
        "req",
        "scope",
        "websocket",
        "websocket_scope",
    }
)
_REQUEST_SOURCE_ATTRIBUTES = frozenset(
    {
        "args",
        "body",
        "COOKIES",
        "cookies",
        "data",
        "FILES",
        "form",
        "GET",
        "headers",
        "json",
        "META",
        "POST",
        "path_params",
        "query",
        "query_params",
        "query_string",
        "url",
        "values",
    }
)
_REQUEST_ACCESS_METHODS = frozenset(
    {
        "body",
        "get_data",
        "get_json",
        "json",
        "form",
        "read",
        "stream",
    }
)
_REQUEST_CONTAINER_METHODS = frozenset({"get", "getall", "getlist", "pop"})
_SCOPE_SOURCE_KEYS = frozenset(
    {
        "body",
        "headers",
        "path_params",
        "query_params",
        "query_string",
    }
)
_ENVIRONMENT_SOURCE_KEYS = frozenset(
    {"QUERY_STRING", "PATH_INFO", "RAW_URI", "REQUEST_URI", "wsgi.input"}
)
_FLOW_PRESERVING_METHODS = frozenset(
    {
        "decode",
        "format",
        "join",
        "replace",
        "strip",
        "lstrip",
        "rstrip",
        "removeprefix",
        "removesuffix",
        "lower",
        "upper",
        "casefold",
    }
)
_FLOW_PRESERVING_CALLS = frozenset(
    {
        "bytes",
        "str",
        "urllib.parse.urljoin",
        "urllib.parse.urlencode",
        "urllib.parse.quote",
        "urllib.parse.quote_plus",
        "urllib.parse.unquote",
        "urllib.parse.unquote_plus",
        "urljoin",
        "urlencode",
    }
)


class PythonCwe918ScanErrorCode(StrEnum):
    """Closed, source-free reasons an SSRF scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe918ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser text."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe918ScanErrorCode) -> None:
        if type(code) is not PythonCwe918ScanErrorCode:
            raise TypeError("Python CWE-918 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-918 SSRF scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class PythonCwe918ScanLimits:
    """Hard ceilings for source, output, and local flow resolution."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_resolution_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Python CWE-918 scan limits are invalid")


DEFAULT_PYTHON_CWE918_SCAN_LIMITS = PythonCwe918ScanLimits()


class PythonCwe918Operation(StrEnum):
    """Recognized outbound HTTP client operations."""

    REQUESTS_REQUEST = "requests.request"
    REQUESTS_METHOD = "requests.method"
    HTTPX_REQUEST = "httpx.request"
    HTTPX_METHOD = "httpx.method"
    AIOHTTP_REQUEST = "aiohttp.request"
    AIOHTTP_METHOD = "aiohttp.method"
    URLLIB_URLOPEN = "urllib.request.urlopen"
    URLLIB_REQUEST = "urllib.request.Request"


@dataclass(frozen=True, slots=True)
class PythonCwe918Signal:
    """One immutable untrusted-request-data to HTTP-client fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe918Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-918"
    detector: str = _DETECTOR
    detail: str = _DETAIL

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
        ranges_valid = (
            type(self.source) is SourceRange
            and type(self.sink) is SourceRange
            and self.source.start_byte <= self.sink.end_byte
            and self.source.end_byte <= self.sink.end_byte
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
            if identity_valid and ranges_valid and type(self.operation) is PythonCwe918Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not PythonCwe918Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-918"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-918 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete outbound call location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class PythonCwe918ScanResult:
    """Deterministic, source-free CWE-918 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe918Signal, ...]
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
            type(item) is PythonCwe918Signal for item in self.signals
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
            raise ValueError("Python CWE-918 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange


def scan_python_cwe918(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe918ScanLimits = DEFAULT_PYTHON_CWE918_SCAN_LIMITS,
) -> PythonCwe918ScanResult:
    """Find bounded request-data flows into Python outbound HTTP clients.

    The AST analysis must be produced for the exact sealed symbol index.
    Unknown imports, arbitrary calls, and unresolved aliases are ignored.
    Invalid or mismatched inputs fail closed with a typed source-free error.
    """

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe918ScanLimits
    ):
        raise PythonCwe918ScanError(PythonCwe918ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe918ScanError(PythonCwe918ScanErrorCode.SOURCE_LIMIT)

    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe918ScanError(PythonCwe918ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe918ScanError(PythonCwe918ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe918ScanError(PythonCwe918ScanErrorCode.ANALYSIS_UNAVAILABLE)

    line_starts = _line_starts(symbol_index.source)
    aliases: dict[str, str | None] = {}
    flows: dict[str, tuple[_Flow, ...]] = {}
    raw: list[tuple[SourceRange, SourceRange, PythonCwe918Operation]] = []
    _scan_statements(
        tree.body,
        aliases,
        flows,
        symbol_index.source,
        line_starts,
        limits,
        raw,
    )
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
        raise PythonCwe918ScanError(PythonCwe918ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe918Signal(
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
    return PythonCwe918ScanResult(
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


def scan_python_cwe918_ssrf(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe918ScanLimits = DEFAULT_PYTHON_CWE918_SCAN_LIMITS,
) -> PythonCwe918ScanResult:
    """Descriptive alias for :func:`scan_python_cwe918`."""

    return scan_python_cwe918(symbol_index, ast_analysis, limits=limits)


def scan_python_ssrf(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe918ScanLimits = DEFAULT_PYTHON_CWE918_SCAN_LIMITS,
) -> PythonCwe918ScanResult:
    """Compatibility alias for callers grouping language SSRF scanners."""

    return scan_python_cwe918(symbol_index, ast_analysis, limits=limits)


def _scan_statements(
    statements: list[ast.stmt],
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe918ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe918Operation]],
) -> None:
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _scan_function(statement, aliases, flows, source, line_starts, limits, output)
            aliases[statement.name] = None
            flows.pop(statement.name, None)
            continue
        if isinstance(statement, ast.ClassDef):
            _scan_decorators(
                statement.decorator_list, aliases, flows, source, line_starts, limits, output
            )
            child_aliases = dict(aliases)
            child_flows = dict(flows)
            _scan_statements(
                statement.body,
                child_aliases,
                child_flows,
                source,
                line_starts,
                limits,
                output,
            )
            aliases[statement.name] = None
            flows.pop(statement.name, None)
            continue

        if isinstance(statement, ast.Import):
            _record_imports(statement, aliases)
        elif isinstance(statement, ast.ImportFrom):
            _record_import_from(statement, aliases)

        _scan_statement_calls(statement, aliases, flows, source, line_starts, limits, output)
        _record_assignment(statement, aliases, flows, source, line_starts, limits)
        _record_scope_bindings(statement, aliases, flows)

        if isinstance(statement, ast.If):
            left_aliases = dict(aliases)
            left_flows = dict(flows)
            right_aliases = dict(aliases)
            right_flows = dict(flows)
            _scan_statements(
                statement.body,
                left_aliases,
                left_flows,
                source,
                line_starts,
                limits,
                output,
            )
            _scan_statements(
                statement.orelse,
                right_aliases,
                right_flows,
                source,
                line_starts,
                limits,
                output,
            )
            _merge_bindings(aliases, flows, left_aliases, left_flows, right_aliases, right_flows)
        elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            body_aliases = dict(aliases)
            body_flows = dict(flows)
            if isinstance(statement, (ast.For, ast.AsyncFor)):
                _invalidate_target(statement.target, body_aliases, body_flows)
            _scan_statements(
                statement.body,
                body_aliases,
                body_flows,
                source,
                line_starts,
                limits,
                output,
            )
            else_aliases = dict(aliases)
            else_flows = dict(flows)
            _scan_statements(
                statement.orelse,
                else_aliases,
                else_flows,
                source,
                line_starts,
                limits,
                output,
            )
            _merge_bindings(aliases, flows, body_aliases, body_flows, else_aliases, else_flows)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            child_aliases = dict(aliases)
            child_flows = dict(flows)
            for item in statement.items:
                if item.optional_vars is not None:
                    _invalidate_target(item.optional_vars, child_aliases, child_flows)
            _scan_statements(
                statement.body,
                child_aliases,
                child_flows,
                source,
                line_starts,
                limits,
                output,
            )
            _merge_bindings(aliases, flows, aliases, flows, child_aliases, child_flows)
        elif isinstance(statement, ast.Try):
            branches: list[tuple[dict[str, str | None], dict[str, tuple[_Flow, ...]]]] = []
            body_aliases = dict(aliases)
            body_flows = dict(flows)
            _scan_statements(
                statement.body,
                body_aliases,
                body_flows,
                source,
                line_starts,
                limits,
                output,
            )
            branches.append((body_aliases, body_flows))
            for handler in statement.handlers:
                handler_aliases = dict(aliases)
                handler_flows = dict(flows)
                if handler.name is not None:
                    handler_aliases[handler.name] = None
                    handler_flows.pop(handler.name, None)
                _scan_statements(
                    handler.body,
                    handler_aliases,
                    handler_flows,
                    source,
                    line_starts,
                    limits,
                    output,
                )
                branches.append((handler_aliases, handler_flows))
            else_aliases = dict(aliases)
            else_flows = dict(flows)
            _scan_statements(
                statement.orelse,
                else_aliases,
                else_flows,
                source,
                line_starts,
                limits,
                output,
            )
            branches.append((else_aliases, else_flows))
            final_aliases = dict(aliases)
            final_flows = dict(flows)
            _scan_statements(
                statement.finalbody,
                final_aliases,
                final_flows,
                source,
                line_starts,
                limits,
                output,
            )
            branches.append((final_aliases, final_flows))
            _merge_many_bindings(aliases, flows, branches)
        else:
            for child in _nested_statement_lists(statement):
                child_aliases = dict(aliases)
                child_flows = dict(flows)
                _scan_statements(
                    child,
                    child_aliases,
                    child_flows,
                    source,
                    line_starts,
                    limits,
                    output,
                )
                _merge_bindings(
                    aliases,
                    flows,
                    aliases,
                    flows,
                    child_aliases,
                    child_flows,
                )


def _scan_function(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe918ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe918Operation]],
) -> None:
    _scan_decorators(function.decorator_list, aliases, flows, source, line_starts, limits, output)
    child_aliases = dict(aliases)
    child_flows = dict(flows)
    parameters = (
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    )
    for parameter in parameters:
        if parameter.arg in _REQUEST_SOURCE_ROOTS:
            child_aliases.pop(parameter.arg, None)
        else:
            child_aliases[parameter.arg] = None
        child_flows.pop(parameter.arg, None)
    if function.args.vararg is not None:
        if function.args.vararg.arg in _REQUEST_SOURCE_ROOTS:
            child_aliases.pop(function.args.vararg.arg, None)
        else:
            child_aliases[function.args.vararg.arg] = None
        child_flows.pop(function.args.vararg.arg, None)
    if function.args.kwarg is not None:
        if function.args.kwarg.arg in _REQUEST_SOURCE_ROOTS:
            child_aliases.pop(function.args.kwarg.arg, None)
        else:
            child_aliases[function.args.kwarg.arg] = None
        child_flows.pop(function.args.kwarg.arg, None)
    _scan_statements(
        function.body,
        child_aliases,
        child_flows,
        source,
        line_starts,
        limits,
        output,
    )


def _scan_decorators(
    decorators: list[ast.expr],
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe918ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe918Operation]],
) -> None:
    for decorator in decorators:
        _scan_expression_calls(decorator, aliases, flows, source, line_starts, limits, output)


def _scan_statement_calls(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe918ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe918Operation]],
) -> None:
    stack: list[ast.AST] = [statement]
    while stack:
        node = stack.pop()
        for child in reversed(tuple(ast.iter_child_nodes(node))):
            if isinstance(child, ast.stmt):
                continue
            stack.append(child)
        if isinstance(node, ast.Call):
            _record_call(node, aliases, flows, source, line_starts, limits, output)


def _scan_expression_calls(
    expression: ast.expr,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe918ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe918Operation]],
) -> None:
    stack: list[ast.AST] = [expression]
    while stack:
        node = stack.pop()
        for child in reversed(tuple(ast.iter_child_nodes(node))):
            if isinstance(child, (ast.stmt, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            stack.append(child)
        if isinstance(node, ast.Call):
            _record_call(node, aliases, flows, source, line_starts, limits, output)


def _record_call(
    call: ast.Call,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe918ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe918Operation]],
) -> None:
    sink = _sink_for_callable(call.func, aliases)
    if sink is None:
        return
    operation, url_index, keyword_names = sink
    argument = _call_argument(call, url_index, keyword_names)
    if argument is None:
        return
    source_flows = _resolve_flows(argument, aliases, flows, source, line_starts, limits, 0)
    sink_range = _node_range(call, source, line_starts)
    for flow in source_flows:
        output.append((flow.source, sink_range, operation))
        if len(output) > limits.max_signals:
            raise PythonCwe918ScanError(PythonCwe918ScanErrorCode.SIGNAL_LIMIT)


def _sink_for_callable(
    callable_node: ast.expr,
    aliases: dict[str, str | None],
) -> tuple[PythonCwe918Operation, int, frozenset[str]] | None:
    canonical = _canonical_reference(callable_node, aliases, 0)
    if canonical is None:
        return None
    parts = canonical.rsplit(".", 1)
    receiver = parts[0] if len(parts) == 2 else ""
    method = parts[-1]
    if canonical in {"requests.request", "requests.api.request"}:
        return PythonCwe918Operation.REQUESTS_REQUEST, 1, frozenset({"url"})
    if receiver in _REQUEST_MODULES and method in _HTTP_METHODS and method != "request":
        return PythonCwe918Operation.REQUESTS_METHOD, 0, frozenset({"url"})
    if canonical == "httpx.request":
        return PythonCwe918Operation.HTTPX_REQUEST, 1, frozenset({"url"})
    if receiver in _HTTPX_MODULES and method in _HTTP_METHODS and method != "request":
        return PythonCwe918Operation.HTTPX_METHOD, 0, frozenset({"url"})
    if canonical == "aiohttp.request":
        return PythonCwe918Operation.AIOHTTP_REQUEST, 1, frozenset({"url"})
    if receiver in _AIOHTTP_MODULES and method in _HTTP_METHODS and method != "request":
        return PythonCwe918Operation.AIOHTTP_METHOD, 0, frozenset({"url"})
    if canonical in {"urllib.request.urlopen", "urllib.urlopen", "urlopen"}:
        return PythonCwe918Operation.URLLIB_URLOPEN, 0, frozenset({"url"})
    if canonical in {"urllib.request.Request", "Request"}:
        return PythonCwe918Operation.URLLIB_REQUEST, 0, frozenset({"url"})
    if receiver in _REQUEST_CLIENTS and method in _HTTP_METHODS:
        if method == "request":
            return _client_operation(receiver), 1, frozenset({"url"})
        return _client_operation(receiver), 0, frozenset({"url"})
    if receiver in _REQUEST_CLIENTS and method == "send":
        return _client_operation(receiver), 0, frozenset()
    return None


def _client_operation(receiver: str) -> PythonCwe918Operation:
    if receiver.startswith("requests"):
        return PythonCwe918Operation.REQUESTS_METHOD
    if receiver.startswith("httpx"):
        return PythonCwe918Operation.HTTPX_METHOD
    return PythonCwe918Operation.AIOHTTP_METHOD


def _call_argument(
    call: ast.Call,
    index: int,
    keyword_names: frozenset[str],
) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg in keyword_names:
            return keyword.value
    return call.args[index] if len(call.args) > index else None


def _resolve_flows(
    node: ast.expr,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe918ScanLimits,
    depth: int,
) -> tuple[_Flow, ...]:
    if depth > limits.max_resolution_depth:
        raise PythonCwe918ScanError(PythonCwe918ScanErrorCode.SIGNAL_LIMIT)
    direct = _source_range(node, aliases, source, line_starts)
    if direct is not None:
        return (_Flow(direct),)
    if isinstance(node, ast.Name):
        return flows.get(node.id, ())
    if isinstance(node, ast.Await):
        return _resolve_flows(node.value, aliases, flows, source, line_starts, limits, depth + 1)
    if isinstance(node, ast.NamedExpr):
        return _resolve_flows(node.value, aliases, flows, source, line_starts, limits, depth + 1)
    if isinstance(node, ast.Call):
        canonical = _canonical_reference(node.func, aliases, depth + 1)
        if canonical in _FLOW_PRESERVING_CALLS or _is_request_builder(canonical):
            return _dedupe_flows(
                (
                    flow
                    for argument in _flow_arguments(node)
                    for flow in _resolve_flows(
                        argument, aliases, flows, source, line_starts, limits, depth + 1
                    )
                ),
                limits,
            )
        if canonical is not None and canonical.rsplit(".", 1)[-1] in _FLOW_PRESERVING_METHODS:
            return _dedupe_flows(
                (
                    flow
                    for argument in _flow_arguments(node)
                    for flow in _resolve_flows(
                        argument, aliases, flows, source, line_starts, limits, depth + 1
                    )
                ),
                limits,
            )
        return ()
    if isinstance(node, ast.Attribute):
        return _resolve_flows(node.value, aliases, flows, source, line_starts, limits, depth + 1)
    if isinstance(node, ast.Subscript):
        return _resolve_flows(node.value, aliases, flows, source, line_starts, limits, depth + 1)
    if isinstance(node, ast.BinOp | ast.BoolOp | ast.Compare | ast.IfExp | ast.JoinedStr):
        return _dedupe_flows(
            (
                flow
                for child in ast.iter_child_nodes(node)
                if isinstance(child, ast.expr)
                for flow in _resolve_flows(
                    child, aliases, flows, source, line_starts, limits, depth + 1
                )
            ),
            limits,
        )
    if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
        return _dedupe_flows(
            (
                flow
                for child in ast.iter_child_nodes(node)
                if isinstance(child, ast.expr)
                for flow in _resolve_flows(
                    child, aliases, flows, source, line_starts, limits, depth + 1
                )
            ),
            limits,
        )
    return ()


def _flow_arguments(call: ast.Call) -> tuple[ast.expr, ...]:
    receiver = (
        (call.func.value,)
        if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.expr)
        else ()
    )
    return (*receiver, *call.args, *(item.value for item in call.keywords))


def _is_request_builder(canonical: str | None) -> bool:
    return canonical in {
        "urllib.request.Request",
        "requests.Request",
        "httpx.Request",
    }


def _canonical_source(node: ast.AST, aliases: dict[str, str | None], depth: int = 0) -> str | None:
    if depth > 64:
        return None
    return _canonical_reference(node, aliases, depth)


def _source_range(
    node: ast.expr,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
) -> SourceRange | None:
    """Return a range for one explicit Flask, Django, or ASGI source node."""

    canonical = _canonical_source(node, aliases)
    if isinstance(node, ast.Subscript):
        base = _canonical_source(node.value, aliases)
        key = _literal_string(node.slice)
        if _is_source_container(base) or (
            _is_request_root(base) and key in _SCOPE_SOURCE_KEYS | _ENVIRONMENT_SOURCE_KEYS
        ):
            return _node_range(node, source, line_starts)
    if canonical is not None:
        if _is_source_attribute(canonical):
            return _node_range(node, source, line_starts)
        if _is_source_access_call(canonical, node):
            return _node_range(node, source, line_starts)
    return None


def _is_request_root(canonical: str | None) -> bool:
    if canonical is None:
        return False
    if canonical in _REQUEST_SOURCE_ROOTS:
        return True
    return canonical.endswith(".request") or canonical.endswith(".Request")


def _is_source_container(canonical: str | None) -> bool:
    if canonical is None:
        return False
    base, _, attribute = canonical.rpartition(".")
    return _is_request_root(base) and attribute in _REQUEST_SOURCE_ATTRIBUTES


def _is_source_attribute(canonical: str) -> bool:
    base, _, attribute = canonical.rpartition(".")
    if _is_source_container(canonical):
        return True
    return _is_request_root(base) and attribute in _REQUEST_SOURCE_ATTRIBUTES


def _is_source_access_call(canonical: str, node: ast.AST) -> bool:
    base, _, method = canonical.rpartition(".")
    if _is_request_root(base) and method in _REQUEST_ACCESS_METHODS:
        return True
    if (
        _is_request_root(base)
        and method in _REQUEST_CONTAINER_METHODS
        and isinstance(node, ast.Call)
    ):
        key = _literal_string(node.args[0]) if node.args else None
        if key in _SCOPE_SOURCE_KEYS | _ENVIRONMENT_SOURCE_KEYS:
            return True
    container, _, accessor = base.rpartition(".")
    return (
        _is_request_root(container)
        and accessor in _REQUEST_SOURCE_ATTRIBUTES
        and method in (_REQUEST_CONTAINER_METHODS | _FLOW_PRESERVING_METHODS)
    )


def _canonical_reference(
    node: ast.AST,
    aliases: dict[str, str | None],
    depth: int = 0,
) -> str | None:
    if depth > 64:
        return None
    if isinstance(node, ast.Name):
        if node.id in aliases:
            return aliases[node.id]
        if node.id in _REQUEST_SOURCE_ROOTS or node.id in {"flask", "django", "urllib"}:
            return node.id
        return None
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Subscript):
        return _canonical_reference(node.value, aliases, depth + 1)
    if isinstance(node, ast.Call):
        if _dotted_name(node.func) in {"getattr", "builtins.getattr"}:
            if len(node.args) < 2 or node.keywords:
                return None
            base = _canonical_reference(node.args[0], aliases, depth + 1)
            member = _literal_string(node.args[1])
            return None if base is None or member is None else f"{base}.{member}"
        return _canonical_reference(node.func, aliases, depth + 1)
    return None


def _record_imports(statement: ast.Import, aliases: dict[str, str | None]) -> None:
    for imported in statement.names:
        root = imported.name.split(".", 1)[0]
        if imported.name in {
            "requests",
            "requests.api",
            "httpx",
            "aiohttp",
            "flask",
            "urllib",
            "urllib.request",
            "urllib.parse",
        }:
            aliases[imported.asname or root] = imported.name if imported.asname else root
        else:
            aliases[imported.asname or root] = None


def _record_import_from(statement: ast.ImportFrom, aliases: dict[str, str | None]) -> None:
    module = statement.module or ""
    if statement.level:
        for imported in statement.names:
            aliases[imported.asname or imported.name] = None
        return
    known = {
        "requests": _HTTP_METHODS | {"Session", "Request"},
        "httpx": _HTTP_METHODS | {"Client", "AsyncClient", "Request"},
        "aiohttp": _HTTP_METHODS | {"ClientSession"},
        "urllib.request": {"Request", "urlopen"},
        "urllib": {"request", "parse"},
        "urllib.parse": {"urljoin", "urlencode", "quote", "quote_plus", "unquote", "unquote_plus"},
        "flask": {"request"},
        "starlette.requests": {"Request"},
        "fastapi": {"Request"},
    }
    for imported in statement.names:
        name = imported.asname or imported.name
        aliases[name] = (
            f"{module}.{imported.name}" if imported.name in known.get(module, ()) else None
        )


def _record_assignment(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe918ScanLimits,
) -> None:
    values: list[tuple[ast.expr, ast.expr]] = []
    if isinstance(statement, ast.Assign):
        values.extend((target, statement.value) for target in statement.targets)
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        values.append((statement.target, statement.value))
    for target, value in values:
        names = _target_names(target)
        resolved = _resolve_flows(value, aliases, flows, source, line_starts, limits, 0)
        canonical = _canonical_reference(value, aliases)
        for name in names:
            aliases[name] = canonical
            if resolved:
                flows[name] = resolved
            else:
                flows.pop(name, None)


def _record_scope_bindings(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
) -> None:
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        _invalidate_target(statement.target, aliases, flows)
    elif isinstance(statement, (ast.With, ast.AsyncWith)):
        for item in statement.items:
            if item.optional_vars is not None:
                _invalidate_target(item.optional_vars, aliases, flows)
    elif isinstance(statement, ast.Try):
        for handler in statement.handlers:
            if handler.name is not None:
                aliases[handler.name] = None
                flows.pop(handler.name, None)
    elif isinstance(statement, ast.Delete):
        for target in statement.targets:
            _invalidate_target(target, aliases, flows)


def _invalidate_target(
    target: ast.AST,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
) -> None:
    for name in _target_names(target):
        aliases[name] = None
        flows.pop(name, None)


def _merge_bindings(
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    left_aliases: dict[str, str | None],
    left_flows: dict[str, tuple[_Flow, ...]],
    right_aliases: dict[str, str | None],
    right_flows: dict[str, tuple[_Flow, ...]],
) -> None:
    merged_aliases: dict[str, str | None] = {}
    merged_flows: dict[str, tuple[_Flow, ...]] = {}
    for name in left_aliases.keys() | right_aliases.keys():
        left_value = left_aliases.get(name)
        right_value = right_aliases.get(name)
        merged_aliases[name] = left_value if left_value == right_value else None
        left_flow = left_flows.get(name, ())
        right_flow = right_flows.get(name, ())
        if left_flow == right_flow and left_flow:
            merged_flows[name] = left_flow
    aliases.clear()
    aliases.update(merged_aliases)
    flows.clear()
    flows.update(merged_flows)


def _merge_many_bindings(
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    branches: list[tuple[dict[str, str | None], dict[str, tuple[_Flow, ...]]]],
) -> None:
    if not branches:
        return
    aliases.clear()
    flows.clear()
    names = set().union(*(branch_aliases.keys() for branch_aliases, _ in branches))
    for name in names:
        values = {branch_aliases.get(name) for branch_aliases, _ in branches}
        aliases[name] = values.pop() if len(values) == 1 else None
        branch_flows = [branch_flows.get(name, ()) for _, branch_flows in branches]
        if (
            branch_flows
            and all(value == branch_flows[0] for value in branch_flows)
            and branch_flows[0]
        ):
            flows[name] = branch_flows[0]


def _target_names(node: ast.AST) -> tuple[str, ...]:
    return tuple(item.id for item in ast.walk(node) if isinstance(item, ast.Name))


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


def _dedupe_flows(flows: Iterable[_Flow], limits: PythonCwe918ScanLimits) -> tuple[_Flow, ...]:
    unique: dict[tuple[int, int], _Flow] = {}
    for flow in flows:
        unique[(flow.source.start_byte, flow.source.end_byte)] = flow
        if len(unique) > limits.max_signals:
            raise PythonCwe918ScanError(PythonCwe918ScanErrorCode.SIGNAL_LIMIT)
    return tuple(unique[key] for key in sorted(unique))


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
        raise PythonCwe918ScanError(PythonCwe918ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe918ScanError(PythonCwe918ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe918ScanError(PythonCwe918ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start,
        end,
        SourcePoint(start_line, start_column),
        SourcePoint(end_line, end_column),
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
    operation: PythonCwe918Operation,
) -> str:
    material = {
        "content_sha256": content_sha256,
        "cwe": "CWE-918",
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
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[PythonCwe918Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "cwe": item.cwe,
                "detail": item.detail,
                "detector": item.detector,
                "operation": item.operation.value,
                "signal_id": item.signal_id,
                "sink": _range_value(item.sink),
                "source": _range_value(item.source),
            }
            for item in signals
        ],
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


# Compatibility aliases keep the Python adapter aligned with the generic CWE
# naming used by the other language-specific scanners.
Cwe918ScanError = PythonCwe918ScanError
Cwe918ScanErrorCode = PythonCwe918ScanErrorCode
Cwe918ScanLimits = PythonCwe918ScanLimits
Cwe918ScanResult = PythonCwe918ScanResult
Cwe918Signal = PythonCwe918Signal
DEFAULT_CWE918_SCAN_LIMITS = DEFAULT_PYTHON_CWE918_SCAN_LIMITS


__all__ = [
    "DEFAULT_CWE918_SCAN_LIMITS",
    "DEFAULT_PYTHON_CWE918_SCAN_LIMITS",
    "Cwe918ScanError",
    "Cwe918ScanErrorCode",
    "Cwe918ScanLimits",
    "Cwe918ScanResult",
    "Cwe918Signal",
    "PythonCwe918Operation",
    "PythonCwe918ScanError",
    "PythonCwe918ScanErrorCode",
    "PythonCwe918ScanLimits",
    "PythonCwe918ScanResult",
    "PythonCwe918Signal",
    "scan_python_cwe918",
    "scan_python_cwe918_ssrf",
    "scan_python_ssrf",
]
