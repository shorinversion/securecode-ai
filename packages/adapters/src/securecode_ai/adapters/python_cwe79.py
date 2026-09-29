"""Bounded Python cross-site-scripting facts for CWE-79.

The scanner consumes an admitted :class:`~securecode_ai.core.SymbolIndex` and
the matching sealed CPython AST analysis.  It follows a small set of explicit
web request sources through local aliases into HTML-producing response and
template APIs.  Known escaping helpers terminate a flow.  Results contain
immutable source ranges and content-addressed metadata only; repository source
is never retained in a result or an error.
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

_MAX_LIMIT_VALUES = (2_000_000, 10_000, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-python-cwe79"
_DETECTOR = "securecode-python-cwe79@1.0"
_DETAIL_HTML = "untrusted_input_to_html"
_DETAIL_TEMPLATE = "untrusted_input_to_template"


class PythonCwe79ScanErrorCode(StrEnum):
    """Closed reasons a cross-site-scripting scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe79ScanError(RuntimeError):
    """Fixed, non-echoing Python CWE-79 scanner failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe79ScanErrorCode) -> None:
        if type(code) is not PythonCwe79ScanErrorCode:
            raise TypeError("Python CWE-79 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-79 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe79Operation(StrEnum):
    """Recognized HTML and template construction operations."""

    RENDER_TEMPLATE = "render_template"
    RENDER_TEMPLATE_STRING = "render_template_string"
    TEMPLATE_RENDER = "template.render"
    DJANGO_RENDER = "django.render"
    HTML_RESPONSE = "html_response"
    HTTP_RESPONSE = "http_response"
    MAKE_RESPONSE = "make_response"
    MARK_SAFE = "mark_safe"
    MARKUP = "markupsafe.Markup"
    TEMPLATE_CONSTRUCTOR = "template_constructor"
    HTML_STRING = "html_string"
    RENDER_HTML = "html_response"
    RESPONSE_BODY = "http_response"

    # These aliases keep the operation surface convenient for generic
    # consumers while preserving one canonical value per finding.
    FLASK_RENDER_TEMPLATE = "render_template"
    FLASK_RENDER_TEMPLATE_STRING = "render_template_string"
    RESPONSE = "html_response"
    HTML = "html_string"


@dataclass(frozen=True, slots=True)
class PythonCwe79ScanLimits:
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
            raise ValueError("Python CWE-79 scan limits are invalid")


DEFAULT_PYTHON_CWE79_SCAN_LIMITS = PythonCwe79ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe79Signal:
    """One immutable request-to-HTML sink fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe79Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-79"
    detector: str = _DETECTOR
    detail: str = _DETAIL_HTML

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
        ranges_valid = (
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
                self.detail,
            )
            if valid_identity and ranges_valid and type(self.operation) is PythonCwe79Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not ranges_valid
            or type(self.operation) is not PythonCwe79Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-79"
            or self.detector != _DETECTOR
            or self.detail not in {_DETAIL_HTML, _DETAIL_TEMPLATE}
        ):
            raise ValueError("Python CWE-79 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete HTML sink location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class PythonCwe79ScanResult:
    """Source-free, deterministic CWE-79 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe79Signal, ...]
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
            type(item) is PythonCwe79Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    item.sink.start_byte,
                    item.sink.end_byte,
                    item.source.start_byte,
                    item.source.end_byte,
                    item.operation.value,
                    item.detail,
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
            raise ValueError("Python CWE-79 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange


@dataclass(frozen=True, slots=True)
class _Sink:
    operation: PythonCwe79Operation
    argument_indices: tuple[int, ...] = ()
    argument_names: frozenset[str] = frozenset()
    all_arguments: bool = False
    detail: str = _DETAIL_HTML


_KNOWN_MODULES = frozenset(
    {
        "bleach",
        "cgi",
        "django",
        "fastapi",
        "flask",
        "html",
        "jinja2",
        "markupsafe",
        "starlette",
    }
)
_REQUEST_ROOTS = frozenset(
    {
        "request",
        "req",
        "http_request",
        "scope",
        "websocket",
        "websocket_scope",
        "ctx",
    }
)
_REQUEST_ATTRIBUTES = frozenset(
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
        "path",
        "path_params",
        "query",
        "query_params",
        "query_string",
        "url",
        "values",
    }
)
_REQUEST_ACCESS_METHODS = frozenset(
    {"body", "get_data", "get_json", "json", "read", "readline", "readlines"}
)
_CONTAINER_ACCESS_METHODS = frozenset({"get", "getall", "getlist", "pop", "setdefault"})
_FLOW_PRESERVING_METHODS = frozenset(
    {
        "decode",
        "encode",
        "format",
        "join",
        "lower",
        "lstrip",
        "replace",
        "removeprefix",
        "removesuffix",
        "rstrip",
        "strip",
        "swapcase",
        "title",
        "upper",
    }
)
_FLOW_PRESERVING_CALLS = frozenset(
    {
        "bytes",
        "str",
        "os.fspath",
        "urllib.parse.unquote",
        "urllib.parse.unquote_plus",
    }
)
_TRUSTED_ESCAPERS = frozenset(
    {
        "bleach.clean",
        "bleach.linkify",
        "cgi.escape",
        "django.utils.html.escape",
        "django.utils.html.format_html",
        "django.utils.html.format_html_join",
        "flask.escape",
        "html.escape",
        "markupsafe.escape",
        "markupsafe.Markup.escape",
    }
)
_SINKS: dict[str, _Sink] = {
    "flask.render_template": _Sink(
        PythonCwe79Operation.RENDER_TEMPLATE,
        all_arguments=True,
        detail=_DETAIL_TEMPLATE,
    ),
    "flask.render_template_string": _Sink(
        PythonCwe79Operation.RENDER_TEMPLATE_STRING,
        all_arguments=True,
        detail=_DETAIL_TEMPLATE,
    ),
    "django.shortcuts.render": _Sink(
        PythonCwe79Operation.DJANGO_RENDER,
        all_arguments=True,
        detail=_DETAIL_TEMPLATE,
    ),
    "django.template.loader.render_to_string": _Sink(
        PythonCwe79Operation.RENDER_TEMPLATE,
        all_arguments=True,
        detail=_DETAIL_TEMPLATE,
    ),
    "jinja2.Template": _Sink(
        PythonCwe79Operation.TEMPLATE_CONSTRUCTOR,
        argument_indices=(0,),
        detail=_DETAIL_TEMPLATE,
    ),
    "flask.make_response": _Sink(PythonCwe79Operation.MAKE_RESPONSE, argument_indices=(0,)),
    "flask.Response": _Sink(PythonCwe79Operation.HTML_RESPONSE, argument_indices=(0,)),
    "starlette.responses.Response": _Sink(
        PythonCwe79Operation.HTTP_RESPONSE,
        argument_indices=(0,),
        argument_names=frozenset({"content"}),
    ),
    "starlette.responses.HTMLResponse": _Sink(
        PythonCwe79Operation.HTML_RESPONSE,
        argument_indices=(0,),
        argument_names=frozenset({"content"}),
    ),
    "fastapi.responses.Response": _Sink(
        PythonCwe79Operation.HTTP_RESPONSE,
        argument_indices=(0,),
        argument_names=frozenset({"content"}),
    ),
    "fastapi.responses.HTMLResponse": _Sink(
        PythonCwe79Operation.HTML_RESPONSE,
        argument_indices=(0,),
        argument_names=frozenset({"content"}),
    ),
    "django.http.HttpResponse": _Sink(
        PythonCwe79Operation.HTTP_RESPONSE,
        argument_indices=(0,),
        argument_names=frozenset({"content"}),
    ),
    "markupsafe.Markup": _Sink(
        PythonCwe79Operation.MARKUP,
        argument_indices=(0,),
    ),
    "django.utils.safestring.mark_safe": _Sink(
        PythonCwe79Operation.MARK_SAFE,
        argument_indices=(0,),
    ),
}


def scan_python_cwe79(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe79ScanLimits = DEFAULT_PYTHON_CWE79_SCAN_LIMITS,
) -> PythonCwe79ScanResult:
    """Return bounded facts for request data reaching HTML-producing APIs.

    The supplied AST analysis must be produced for the exact sealed symbol
    index.  Unknown imports, reflection, and unresolved aliases are ignored.
    Malformed or mismatched analysis fails closed with a typed source-free
    error.  The scanner performs no imports or repository I/O.
    """

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe79ScanLimits
    ):
        raise PythonCwe79ScanError(PythonCwe79ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe79ScanError(PythonCwe79ScanErrorCode.SOURCE_LIMIT)

    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe79ScanError(PythonCwe79ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe79ScanError(PythonCwe79ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe79ScanError(PythonCwe79ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases: dict[str, str | None] = {}
    flows: dict[str, tuple[_Flow, ...]] = {}
    raw: list[tuple[SourceRange, SourceRange, PythonCwe79Operation, str]] = []
    _scan_statements(tree.body, aliases, flows, source, line_starts, limits, raw)
    unique = sorted(
        set(raw),
        key=lambda item: (
            item[1].start_byte,
            item[1].end_byte,
            item[0].start_byte,
            item[0].end_byte,
            item[2].value,
            item[3],
        ),
    )
    if len(unique) > limits.max_signals:
        raise PythonCwe79ScanError(PythonCwe79ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe79Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
            detail=detail,
        )
        for source_range, sink_range, operation, detail in unique
    )
    return PythonCwe79ScanResult(
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
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe79ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe79Operation, str]],
) -> None:
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _scan_function(statement, aliases, flows, source, line_starts, limits, output)
            aliases[statement.name] = None
            flows.pop(statement.name, None)
            continue
        if isinstance(statement, ast.ClassDef):
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
        if isinstance(statement, ast.Return) and statement.value is not None:
            _record_html_return(
                statement.value, aliases, flows, source, line_starts, limits, output
            )
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
    limits: PythonCwe79ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe79Operation, str]],
) -> None:
    child_aliases = dict(aliases)
    child_flows = dict(flows)
    parameters = (
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    )
    for parameter in parameters:
        if parameter.arg in _REQUEST_ROOTS:
            child_aliases.pop(parameter.arg, None)
        else:
            child_aliases[parameter.arg] = None
        child_flows.pop(parameter.arg, None)
    if function.args.vararg is not None:
        child_aliases[function.args.vararg.arg] = None
        child_flows.pop(function.args.vararg.arg, None)
    if function.args.kwarg is not None:
        child_aliases[function.args.kwarg.arg] = None
        child_flows.pop(function.args.kwarg.arg, None)
    _scan_statements(function.body, child_aliases, child_flows, source, line_starts, limits, output)


def _scan_statement_calls(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe79ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe79Operation, str]],
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


def _record_call(
    call: ast.Call,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe79ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe79Operation, str]],
) -> None:
    sink = _sink_for_callable(call.func, aliases, limits.max_resolution_depth)
    if sink is None:
        return
    sink_range = _node_range(call, source, line_starts)
    for argument in _sink_arguments(call, sink):
        source_flows = _resolve_flows(argument, aliases, flows, source, line_starts, limits, 0)
        for flow in source_flows:
            if not sink_range.contains(flow.source):
                raise PythonCwe79ScanError(PythonCwe79ScanErrorCode.INTEGRITY_FAILURE)
            output.append((flow.source, sink_range, sink.operation, sink.detail))
            if len(output) > limits.max_signals:
                raise PythonCwe79ScanError(PythonCwe79ScanErrorCode.SIGNAL_LIMIT)


def _record_html_return(
    value: ast.expr,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe79ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe79Operation, str]],
) -> None:
    if not _contains_html_literal(value):
        return
    sink_range = _node_range(value, source, line_starts)
    for flow in _resolve_flows(value, aliases, flows, source, line_starts, limits, 0):
        if not sink_range.contains(flow.source):
            raise PythonCwe79ScanError(PythonCwe79ScanErrorCode.INTEGRITY_FAILURE)
        output.append((flow.source, sink_range, PythonCwe79Operation.HTML_STRING, _DETAIL_HTML))
        if len(output) > limits.max_signals:
            raise PythonCwe79ScanError(PythonCwe79ScanErrorCode.SIGNAL_LIMIT)


def _sink_for_callable(
    callable_node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
) -> _Sink | None:
    canonical = _canonical_reference(callable_node, aliases, max_depth)
    if canonical is None:
        return None
    direct = _SINKS.get(canonical)
    if direct is not None:
        return direct
    if canonical.endswith(".render") and (
        canonical.startswith("jinja2.") or canonical.startswith("markupsafe.")
    ):
        return _Sink(
            PythonCwe79Operation.TEMPLATE_RENDER, all_arguments=True, detail=_DETAIL_TEMPLATE
        )
    return None


def _sink_arguments(call: ast.Call, sink: _Sink) -> tuple[ast.expr, ...]:
    if sink.all_arguments:
        return (*call.args, *(item.value for item in call.keywords))
    positional = tuple(
        call.args[index] for index in sink.argument_indices if index < len(call.args)
    )
    named = tuple(item.value for item in call.keywords if item.arg in sink.argument_names)
    return (*positional, *named)


def _resolve_flows(
    node: ast.expr,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe79ScanLimits,
    depth: int,
) -> tuple[_Flow, ...]:
    if depth > limits.max_resolution_depth:
        raise PythonCwe79ScanError(PythonCwe79ScanErrorCode.SIGNAL_LIMIT)
    direct = _source_range(node, aliases, source, line_starts, limits.max_resolution_depth)
    if direct is not None:
        return (_Flow(direct),)
    if isinstance(node, ast.Name):
        return flows.get(node.id, ())
    if isinstance(node, (ast.Await, ast.NamedExpr)):
        return _resolve_flows(node.value, aliases, flows, source, line_starts, limits, depth + 1)
    if isinstance(node, ast.Call):
        canonical = _canonical_reference(node.func, aliases, limits.max_resolution_depth)
        if canonical in _TRUSTED_ESCAPERS:
            return ()
        if canonical in _FLOW_PRESERVING_CALLS or (
            canonical is not None and canonical.rsplit(".", 1)[-1] in _FLOW_PRESERVING_METHODS
        ):
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
    if isinstance(node, (ast.BinOp, ast.BoolOp, ast.Compare, ast.IfExp, ast.JoinedStr)):
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
    if isinstance(node, ast.FormattedValue):
        return _resolve_flows(node.value, aliases, flows, source, line_starts, limits, depth + 1)
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


def _dedupe_flows(flows: Iterable[_Flow], limits: PythonCwe79ScanLimits) -> tuple[_Flow, ...]:
    unique: dict[tuple[int, int], _Flow] = {}
    for flow in flows:
        unique[(flow.source.start_byte, flow.source.end_byte)] = flow
        if len(unique) > limits.max_signals:
            raise PythonCwe79ScanError(PythonCwe79ScanErrorCode.SIGNAL_LIMIT)
    return tuple(unique[key] for key in sorted(unique))


def _source_range(
    node: ast.expr,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    max_depth: int,
) -> SourceRange | None:
    canonical = _canonical_reference(node, aliases, max_depth)
    if isinstance(node, ast.Subscript):
        if _source_range(node.value, aliases, source, line_starts, max_depth) is not None:
            return _node_range(node, source, line_starts)
        base = _canonical_reference(node.value, aliases, max_depth)
        if _is_source_container(base):
            return _node_range(node, source, line_starts)
    if canonical is not None:
        if _is_source_container(canonical):
            return _node_range(node, source, line_starts)
        if _is_source_access_call(canonical):
            return _node_range(node, source, line_starts)
    return None


def _is_source_root(canonical: str | None) -> bool:
    if canonical is None:
        return False
    return (
        canonical in _REQUEST_ROOTS
        or canonical.endswith(".request")
        or canonical.endswith(".Request")
    )


def _is_source_container(canonical: str | None) -> bool:
    if canonical is None:
        return False
    base, _, attribute = canonical.rpartition(".")
    return _is_source_root(base) and attribute in _REQUEST_ATTRIBUTES


def _is_source_access_call(canonical: str) -> bool:
    base, _, method = canonical.rpartition(".")
    if _is_source_root(base) and method in _REQUEST_ACCESS_METHODS:
        return True
    return bool(_is_source_container(base) and method in _CONTAINER_ACCESS_METHODS)


def _canonical_reference(
    node: ast.AST,
    aliases: dict[str, str | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe79ScanError(PythonCwe79ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        if node.id in aliases:
            return aliases[node.id]
        if node.id in _REQUEST_ROOTS or node.id in _KNOWN_MODULES:
            return node.id
        return None
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Subscript):
        return _canonical_reference(node.value, aliases, max_depth, depth + 1)
    if isinstance(node, ast.Call):
        if _dotted_name(node.func) in {"getattr", "builtins.getattr"}:
            if len(node.args) < 2 or node.keywords:
                return None
            base = _canonical_reference(node.args[0], aliases, max_depth, depth + 1)
            member = _literal_string(node.args[1])
            return None if base is None or member is None else f"{base}.{member}"
        return _canonical_reference(node.func, aliases, max_depth, depth + 1)
    return None


def _record_imports(statement: ast.Import, aliases: dict[str, str | None]) -> None:
    for imported in statement.names:
        root = imported.name.split(".", 1)[0]
        aliases[imported.asname or root] = imported.name if root in _KNOWN_MODULES else None


def _record_import_from(statement: ast.ImportFrom, aliases: dict[str, str | None]) -> None:
    module = statement.module or ""
    known: dict[str, frozenset[str]] = {
        "flask": frozenset(
            {"request", "render_template", "render_template_string", "make_response", "Response"}
        ),
        "django.shortcuts": frozenset({"render"}),
        "django.http": frozenset({"HttpResponse"}),
        "django.template.loader": frozenset({"render_to_string"}),
        "django.utils.html": frozenset({"escape", "format_html", "format_html_join"}),
        "django.utils.safestring": frozenset({"mark_safe", "SafeString"}),
        "html": frozenset({"escape"}),
        "jinja2": frozenset({"Template"}),
        "markupsafe": frozenset({"Markup", "escape"}),
        "bleach": frozenset({"clean", "linkify"}),
        "starlette.responses": frozenset({"Response", "HTMLResponse"}),
        "fastapi.responses": frozenset({"Response", "HTMLResponse"}),
    }
    if statement.level or module not in known:
        for imported in statement.names:
            aliases[imported.asname or imported.name] = None
        return
    for imported in statement.names:
        if imported.name == "*":
            continue
        name = imported.asname or imported.name
        aliases[name] = f"{module}.{imported.name}" if imported.name in known[module] else None


def _record_assignment(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe79ScanLimits,
) -> None:
    values: list[tuple[ast.expr, ast.expr]] = []
    if isinstance(statement, ast.Assign):
        values.extend((target, statement.value) for target in statement.targets)
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        values.append((statement.target, statement.value))
    for target, value in values:
        names = _target_names(target)
        resolved = _resolve_flows(value, aliases, flows, source, line_starts, limits, 0)
        canonical = _canonical_reference(value, aliases, limits.max_resolution_depth)
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
    target_aliases: dict[str, str | None],
    target_flows: dict[str, tuple[_Flow, ...]],
    left_aliases: dict[str, str | None],
    left_flows: dict[str, tuple[_Flow, ...]],
    right_aliases: dict[str, str | None],
    right_flows: dict[str, tuple[_Flow, ...]],
) -> None:
    merged_aliases: dict[str, str | None] = {}
    merged_flows: dict[str, tuple[_Flow, ...]] = {}
    for name in left_aliases.keys() | right_aliases.keys():
        left_alias = left_aliases.get(name)
        right_alias = right_aliases.get(name)
        merged_aliases[name] = left_alias if left_alias == right_alias else None
        left_flow = left_flows.get(name, ())
        right_flow = right_flows.get(name, ())
        if left_flow == right_flow and left_flow:
            merged_flows[name] = left_flow
    target_aliases.clear()
    target_aliases.update(merged_aliases)
    target_flows.clear()
    target_flows.update(merged_flows)


def _merge_many_bindings(
    target_aliases: dict[str, str | None],
    target_flows: dict[str, tuple[_Flow, ...]],
    branches: list[tuple[dict[str, str | None], dict[str, tuple[_Flow, ...]]]],
) -> None:
    if not branches:
        return
    merged_aliases = dict(branches[0][0])
    merged_flows = dict(branches[0][1])
    for branch_aliases, branch_flows in branches[1:]:
        _merge_bindings(
            merged_aliases,
            merged_flows,
            merged_aliases,
            merged_flows,
            branch_aliases,
            branch_flows,
        )
    target_aliases.clear()
    target_aliases.update(merged_aliases)
    target_flows.clear()
    target_flows.update(merged_flows)


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
    if isinstance(statement, ast.Match):
        return tuple(case.body for case in statement.cases)
    return ()


def _flow_arguments(call: ast.Call) -> tuple[ast.expr, ...]:
    receiver = (
        (call.func.value,)
        if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.expr)
        else ()
    )
    return (*receiver, *call.args, *(item.value for item in call.keywords))


def _contains_html_literal(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and type(child.value) is str:
            value = child.value.lower()
            if "<" in value and ">" in value:
                return True
    return False


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
        raise PythonCwe79ScanError(PythonCwe79ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe79ScanError(PythonCwe79ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe79ScanError(PythonCwe79ScanErrorCode.INTEGRITY_FAILURE)
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
    operation: PythonCwe79Operation,
    detail: str,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detail": detail,
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
    signals: tuple[PythonCwe79Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "detail": signal.detail,
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


def _range_value(location: SourceRange) -> dict[str, int]:
    return {
        "end_byte": location.end_byte,
        "end_column": location.end_point.column,
        "end_row": location.end_point.row,
        "start_byte": location.start_byte,
        "start_column": location.start_point.column,
        "start_row": location.start_point.row,
    }


# Compatibility aliases keep this adapter usable beside the existing CWE
# scanners while retaining the Python-specific implementation names.
Cwe79ScanErrorCode = PythonCwe79ScanErrorCode
Cwe79ScanError = PythonCwe79ScanError
Cwe79ScanLimits = PythonCwe79ScanLimits
Cwe79ScanResult = PythonCwe79ScanResult
Cwe79Signal = PythonCwe79Signal


__all__ = [
    "DEFAULT_PYTHON_CWE79_SCAN_LIMITS",
    "Cwe79ScanError",
    "Cwe79ScanErrorCode",
    "Cwe79ScanLimits",
    "Cwe79ScanResult",
    "Cwe79Signal",
    "PythonCwe79Operation",
    "PythonCwe79ScanError",
    "PythonCwe79ScanErrorCode",
    "PythonCwe79ScanLimits",
    "PythonCwe79ScanResult",
    "PythonCwe79Signal",
    "scan_python_cwe79",
]
