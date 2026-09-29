"""Bounded Python CWE-601 open-redirect facts.

The scanner consumes an admitted, sealed :class:`SymbolIndex` and the matching
sealed CPython AST analysis.  It recognises request-derived redirect targets
at a small set of Flask, Django, Starlette, and response-header sinks.  Only
local aliases and bounded expression resolution are followed.  Results and
failures contain source-free metadata, ranges, and stable hashes; repository
source is never retained or echoed.
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
_RULE_ID = "securecode-python-cwe601"
_DETECTOR = "securecode-python-cwe601@1.0"
_DETAIL = "untrusted_redirect_destination"


class PythonCwe601ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-601 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe601ScanError(RuntimeError):
    """Fixed Python CWE-601 failure which never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe601ScanErrorCode) -> None:
        if type(code) is not PythonCwe601ScanErrorCode:
            raise TypeError("Python CWE-601 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-601 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe601Operation(StrEnum):
    """Recognised redirect and response-location operations."""

    FLASK_REDIRECT = "flask_redirect"
    DJANGO_REDIRECT = "django_redirect"
    DJANGO_HTTP_REDIRECT = "django_http_redirect"
    DJANGO_HTTP_PERMANENT_REDIRECT = "django_http_permanent_redirect"
    STARLETTE_REDIRECT = "starlette_redirect"
    WERKZEUG_REDIRECT = "werkzeug_redirect"
    RESPONSE_LOCATION = "response_location"

    # Compatibility names for generic redirect consumers.
    REDIRECT = "flask_redirect"
    RESPONSE_REDIRECT = "flask_redirect"
    LOCATION_HEADER = "response_location"


@dataclass(frozen=True, slots=True)
class PythonCwe601ScanLimits:
    """Hard ceilings for source, output, and local-flow resolution."""

    max_source_bytes: int = _MAX_LIMIT_VALUES[0]
    max_signals: int = _MAX_LIMIT_VALUES[1]
    max_resolution_depth: int = _MAX_LIMIT_VALUES[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("Python CWE-601 scan limits are invalid")


DEFAULT_PYTHON_CWE601_SCAN_LIMITS = PythonCwe601ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe601Signal:
    """One immutable request-to-redirect destination fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe601Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-601"
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
            if valid_identity and valid_ranges and type(self.operation) is PythonCwe601Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not PythonCwe601Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-601"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-601 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete redirect sink location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class PythonCwe601ScanResult:
    """Source-free, deterministic CWE-601 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe601Signal, ...]
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
            type(item) is PythonCwe601Signal for item in self.signals
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
            raise ValueError("Python CWE-601 scan result is invalid")


_DIRECT_OPERATIONS: dict[str, PythonCwe601Operation] = {
    "flask.redirect": PythonCwe601Operation.FLASK_REDIRECT,
    "flask.helpers.redirect": PythonCwe601Operation.FLASK_REDIRECT,
    "django.shortcuts.redirect": PythonCwe601Operation.DJANGO_REDIRECT,
    "django.http.HttpResponseRedirect": PythonCwe601Operation.DJANGO_HTTP_REDIRECT,
    "django.http.HttpResponsePermanentRedirect": PythonCwe601Operation.DJANGO_HTTP_PERMANENT_REDIRECT,
    "starlette.responses.RedirectResponse": PythonCwe601Operation.STARLETTE_REDIRECT,
    "werkzeug.utils.redirect": PythonCwe601Operation.WERKZEUG_REDIRECT,
}
_FRAMEWORK_MODULES = frozenset(
    {
        "flask",
        "django",
        "starlette",
        "werkzeug",
    }
)
_SOURCE_ROOTS = frozenset(
    {
        "request",
        "req",
        "http_request",
        "flask_request",
        "django_request",
    }
)
_SOURCE_ATTRIBUTES = frozenset(
    {
        "args",
        "query",
        "query_params",
        "query_string",
        "form",
        "headers",
        "GET",
        "POST",
        "data",
        "json",
        "values",
        "params",
    }
)
_REQUEST_METHODS = frozenset({"get", "getlist", "getone", "pop", "setdefault"})
_REQUEST_PARAMETER_NAMES = frozenset(
    {
        "callback",
        "continue",
        "destination",
        "next",
        "next_url",
        "redirect",
        "redirect_to",
        "redirect_url",
        "return_to",
        "return_url",
        "target",
        "url",
    }
)
_RESPONSE_ROOTS = frozenset(
    {
        "reply",
        "res",
        "response",
        "http_response",
        "httpresponse",
        "result",
    }
)
_RESPONSE_HEADER_NAMES = frozenset({"headers", "header", "raw_headers"})
_LOCATION_NAMES = frozenset({"location", "Location"})
_PRESERVING_CALLS = frozenset(
    {
        "str",
        "builtins.str",
        "urllib.parse.unquote",
        "urllib.parse.unquote_plus",
        "urllib.parse.urlunparse",
    }
)
_SAFE_URL_BUILDERS = frozenset(
    {
        "flask.url_for",
        "django.urls.reverse",
        "django.urls.reverse_lazy",
        "starlette.routing.url_path_for",
        "werkzeug.urls.url_encode",
    }
)
_SAFE_PREDICATES = frozenset(
    {
        "django.utils.http.is_safe_url",
        "django.utils.http.url_has_allowed_host_and_scheme",
        "is_safe_url",
        "is_safe_redirect",
        "is_local_url",
        "is_relative_url",
        "validate_redirect",
        "validate_redirect_url",
        "allow_redirect",
        "allowed_redirect",
        "is_allowed_redirect",
    }
)
_SANITIZER_NAMES = frozenset(
    {
        "sanitize_redirect",
        "sanitize_redirect_url",
        "sanitize_url",
        "safe_redirect",
        "safe_redirect_url",
        "safe_url",
        "get_safe_url",
        "get_safe_redirect_url",
        "normalize_safe_url",
    }
)


def scan_python_cwe601(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe601ScanLimits = DEFAULT_PYTHON_CWE601_SCAN_LIMITS,
) -> PythonCwe601ScanResult:
    """Find bounded request-to-redirect facts in one sealed Python file."""

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe601ScanLimits
    ):
        raise PythonCwe601ScanError(PythonCwe601ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe601ScanError(PythonCwe601ScanErrorCode.SOURCE_LIMIT)

    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe601ScanError(PythonCwe601ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe601ScanError(PythonCwe601ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe601ScanError(PythonCwe601ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases = _collect_aliases(tree, limits.max_resolution_depth)
    raw: set[tuple[SourceRange, SourceRange, PythonCwe601Operation]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            _record_redirect_call(
                node,
                tree,
                aliases,
                source,
                line_starts,
                limits,
                raw,
            )
            _record_response_constructor(
                node,
                tree,
                aliases,
                source,
                line_starts,
                limits,
                raw,
            )
            _record_location_update_call(
                node,
                tree,
                aliases,
                source,
                line_starts,
                limits,
                raw,
            )
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            _record_location_assignment(
                node,
                tree,
                aliases,
                source,
                line_starts,
                limits,
                raw,
            )
        if len(raw) > limits.max_signals:
            raise PythonCwe601ScanError(PythonCwe601ScanErrorCode.SIGNAL_LIMIT)

    unique = tuple(
        sorted(
            raw,
            key=lambda item: (
                item[1].start_byte,
                item[1].end_byte,
                item[0].start_byte,
                item[0].end_byte,
                item[2].value,
            ),
        )
    )
    if len(unique) > limits.max_signals:
        raise PythonCwe601ScanError(PythonCwe601ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe601Signal(
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
    return PythonCwe601ScanResult(
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


def _record_redirect_call(
    call: ast.Call,
    tree: ast.AST,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe601ScanLimits,
    output: set[tuple[SourceRange, SourceRange, PythonCwe601Operation]],
) -> None:
    operation = _operation_for_callable(call.func, aliases, limits.max_resolution_depth)
    if operation is None or operation is PythonCwe601Operation.RESPONSE_LOCATION:
        return
    input_node = _redirect_argument(call, operation)
    if input_node is None:
        return
    if _guarded_by_allowlist(call, tree, aliases, limits.max_resolution_depth):
        return
    if (
        _resolve_source(
            input_node,
            call=call,
            tree=tree,
            source=source,
            aliases=aliases,
            max_depth=limits.max_resolution_depth,
            seen=frozenset(),
        )
        is None
    ):
        return
    sink = _node_range(call, source, line_starts)
    source_range = _node_range(input_node, source, line_starts)
    _add_fact(output, source_range, sink, operation)


def _record_location_assignment(
    node: ast.Assign | ast.AnnAssign | ast.AugAssign,
    tree: ast.AST,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe601ScanLimits,
    output: set[tuple[SourceRange, SourceRange, PythonCwe601Operation]],
) -> None:
    value: ast.expr | None
    targets: tuple[ast.expr, ...]
    if isinstance(node, ast.Assign):
        value = node.value
        targets = tuple(node.targets)
    elif isinstance(node, ast.AnnAssign):
        value = node.value
        targets = (node.target,)
    else:
        value = node.value
        targets = (node.target,)
    if value is None:
        return
    for target in targets:
        if not _is_location_target(target, aliases, source):
            continue
        if _guarded_by_allowlist(node, tree, aliases, limits.max_resolution_depth):
            continue
        if (
            _resolve_source(
                value,
                call=node,
                tree=tree,
                source=source,
                aliases=aliases,
                max_depth=limits.max_resolution_depth,
                seen=frozenset(),
            )
            is None
        ):
            continue
        sink = _node_range(node, source, line_starts)
        source_range = _node_range(value, source, line_starts)
        _add_fact(output, source_range, sink, PythonCwe601Operation.RESPONSE_LOCATION)


def _record_location_update_call(
    call: ast.Call,
    tree: ast.AST,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe601ScanLimits,
    output: set[tuple[SourceRange, SourceRange, PythonCwe601Operation]],
) -> None:
    canonical = _canonical_reference(call.func, aliases, limits.max_resolution_depth)
    if canonical is None:
        canonical = _compact(source, call.func)
    if canonical is None or not canonical.endswith(".update"):
        return
    base = canonical[: -len(".update")]
    if not _is_response_headers(base, aliases):
        return
    mapping = call.args[0] if call.args and not call.keywords else None
    if not isinstance(mapping, ast.Dict):
        return
    sink = _node_range(call, source, line_starts)
    for key, value in zip(mapping.keys, mapping.values, strict=False):
        if _literal_string(key) not in _LOCATION_NAMES or value is None:
            continue
        if _guarded_by_allowlist(call, tree, aliases, limits.max_resolution_depth):
            continue
        if (
            _resolve_source(
                value,
                call=call,
                tree=tree,
                source=source,
                aliases=aliases,
                max_depth=limits.max_resolution_depth,
                seen=frozenset(),
            )
            is None
        ):
            continue
        _add_fact(
            output,
            _node_range(value, source, line_starts),
            sink,
            PythonCwe601Operation.RESPONSE_LOCATION,
        )


def _record_response_constructor(
    call: ast.Call,
    tree: ast.AST,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe601ScanLimits,
    output: set[tuple[SourceRange, SourceRange, PythonCwe601Operation]],
) -> None:
    canonical = _canonical_reference(call.func, aliases, limits.max_resolution_depth)
    if canonical is None:
        canonical = _compact(source, call.func)
    if not canonical.endswith(("Response", "HttpResponse")):
        return
    headers = next(
        (keyword.value for keyword in call.keywords if keyword.arg == "headers"),
        None,
    )
    if not isinstance(headers, ast.Dict):
        return
    sink = _node_range(call, source, line_starts)
    for key, value in zip(headers.keys, headers.values, strict=False):
        if _literal_string(key) not in _LOCATION_NAMES or value is None:
            continue
        if _guarded_by_allowlist(call, tree, aliases, limits.max_resolution_depth):
            continue
        if (
            _resolve_source(
                value,
                call=call,
                tree=tree,
                source=source,
                aliases=aliases,
                max_depth=limits.max_resolution_depth,
                seen=frozenset(),
            )
            is None
        ):
            continue
        _add_fact(
            output,
            _node_range(value, source, line_starts),
            sink,
            PythonCwe601Operation.RESPONSE_LOCATION,
        )


def _redirect_argument(call: ast.Call, operation: PythonCwe601Operation) -> ast.expr | None:
    if call.args:
        return call.args[0]
    # Every supported redirect operation shares the same keyword names.
    accepted = ("url", "location", "to")
    for keyword in call.keywords:
        if keyword.arg in accepted:
            return keyword.value
    return None


def _operation_for_callable(
    callable_node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
) -> PythonCwe601Operation | None:
    canonical = _canonical_reference(callable_node, aliases, max_depth)
    if canonical is None:
        return None
    direct = _DIRECT_OPERATIONS.get(canonical)
    if direct is not None:
        return direct
    if canonical.endswith(".redirect"):
        if canonical.startswith("flask."):
            return PythonCwe601Operation.FLASK_REDIRECT
        if canonical.startswith("django.shortcuts."):
            return PythonCwe601Operation.DJANGO_REDIRECT
        if canonical.startswith("werkzeug.utils."):
            return PythonCwe601Operation.WERKZEUG_REDIRECT
    if canonical.endswith(".RedirectResponse") and canonical.startswith("starlette.responses"):
        return PythonCwe601Operation.STARLETTE_REDIRECT
    if canonical.endswith(".HttpResponseRedirect"):
        return PythonCwe601Operation.DJANGO_HTTP_REDIRECT
    if canonical.endswith(".HttpResponsePermanentRedirect"):
        return PythonCwe601Operation.DJANGO_HTTP_PERMANENT_REDIRECT
    return None


def _resolve_source(
    subject: ast.expr,
    *,
    call: ast.AST | None,
    tree: ast.AST,
    source: bytes,
    aliases: dict[str, str | None],
    max_depth: int,
    seen: frozenset[str],
    before: tuple[int, int] | None = None,
    depth: int = 0,
) -> ast.expr | None:
    if depth > max_depth:
        raise PythonCwe601ScanError(PythonCwe601ScanErrorCode.SIGNAL_LIMIT)
    if _is_safe_expression(subject, aliases, max_depth):
        return None
    direct = _direct_source_node(subject, source)
    if direct is not None:
        return direct
    if isinstance(subject, ast.Name):
        if subject.id in seen:
            return None
        if call is not None:
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
    if isinstance(subject, (ast.Constant, ast.Lambda)):
        return None
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
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Call) and _is_safe_callable_text(node.func, source):
            continue
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return None


def _source_call(node: ast.Call, source: bytes) -> bool:
    name = _compact(source, node.func)
    if name in {"input", "builtins.input"}:
        return True
    pieces = name.replace("[", ".[").split(".")
    if not pieces or pieces[0] not in _SOURCE_ROOTS:
        return False
    return bool(
        pieces[-1] in _REQUEST_METHODS
        or pieces[-1] in _SOURCE_ATTRIBUTES
        or (len(pieces) > 1 and pieces[-2] in _SOURCE_ATTRIBUTES)
    )


def _source_attribute(node: ast.Attribute) -> bool:
    if node.attr not in _SOURCE_ATTRIBUTES:
        return False
    root: ast.expr = node.value
    while isinstance(root, ast.Attribute):
        root = root.value
    return isinstance(root, ast.Name) and root.id in _SOURCE_ROOTS


def _source_subscript(node: ast.Subscript) -> bool:
    value = node.value
    if isinstance(value, ast.Attribute):
        return _source_attribute(value)
    return isinstance(value, ast.Name) and value.id in _SOURCE_ROOTS


def _is_parameter_source(name: str, call: ast.AST | None, tree: ast.AST) -> bool:
    if name.lower() not in _REQUEST_PARAMETER_NAMES or call is None:
        return False
    scope = _enclosing_function(call, tree)
    if scope is None:
        return False
    parameters = (
        *scope.args.posonlyargs,
        *scope.args.args,
        *scope.args.kwonlyargs,
    )
    return (
        any(parameter.arg == name for parameter in parameters)
        or (scope.args.vararg is not None and scope.args.vararg.arg == name)
        or (scope.args.kwarg is not None and scope.args.kwarg.arg == name)
    )


def _is_safe_expression(
    node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    canonical = _canonical_reference(node.func, aliases, max_depth)
    if canonical is None:
        return False
    return (
        canonical in _SAFE_URL_BUILDERS
        or canonical in _SAFE_PREDICATES
        or canonical in _SANITIZER_NAMES
        or canonical.rsplit(".", 1)[-1] in _SANITIZER_NAMES
    )


def _is_safe_callable_text(node: ast.AST, source: bytes) -> bool:
    return _compact(source, node).rsplit(".", 1)[-1] in _SANITIZER_NAMES


def _is_location_target(target: ast.expr, aliases: dict[str, str | None], source: bytes) -> bool:
    if isinstance(target, ast.Subscript):
        key = _literal_string(target.slice)
        if key not in _LOCATION_NAMES:
            return False
        return _is_response_object(target.value, aliases, source)
    if isinstance(target, ast.Attribute) and target.attr.lower() == "location":
        return _is_response_object(target.value, aliases, source)
    return False


def _is_response_headers(canonical: str, aliases: dict[str, str | None]) -> bool:
    pieces = canonical.split(".")
    return (
        len(pieces) >= 2
        and pieces[-1] in _RESPONSE_HEADER_NAMES
        and (
            pieces[0] in _RESPONSE_ROOTS
            or pieces[0] in {"headers", "response_headers"}
            or (aliases.get(pieces[0]) or "").endswith("Response")
        )
    )


def _is_response_object(node: ast.expr, aliases: dict[str, str | None], source: bytes) -> bool:
    canonical = _canonical_reference(node, aliases, 8)
    if canonical is not None:
        root = canonical.split(".", 1)[0]
        if root in _RESPONSE_ROOTS:
            return True
        if canonical.endswith(("Response", "HttpResponse", "RedirectResponse")):
            return True
    text = _compact(source, node)
    root = text.split(".", 1)[0]
    return root in _RESPONSE_ROOTS or root in {"headers", "response_headers"}


def _guarded_by_allowlist(
    node: ast.AST,
    tree: ast.AST,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    for candidate in ast.walk(tree):
        if not isinstance(candidate, ast.If):
            continue
        if not _is_descendant(node, candidate.body):
            continue
        if any(
            isinstance(item, ast.Call)
            and _canonical_reference(item.func, aliases, max_depth) in _SAFE_PREDICATES
            for item in ast.walk(candidate.test)
        ):
            return True
    return False


def _is_descendant(node: ast.AST, statements: list[ast.stmt]) -> bool:
    return any(node is candidate for statement in statements for candidate in ast.walk(statement))


def _collect_aliases(tree: ast.AST, max_depth: int) -> dict[str, str | None]:
    aliases: dict[str, str | None] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            _record_imports(node, aliases)
        elif isinstance(node, ast.ImportFrom):
            _record_import_from(node, aliases)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            values: list[tuple[ast.expr, ast.expr]] = []
            if isinstance(node, ast.Assign):
                values.extend((target, node.value) for target in node.targets)
            elif node.value is not None:
                values.append((node.target, node.value))
            for target, value in values:
                if isinstance(target, ast.Name):
                    aliases[target.id] = _canonical_reference(value, aliases, max_depth)
    return aliases


def _record_imports(statement: ast.Import, aliases: dict[str, str | None]) -> None:
    for imported in statement.names:
        root = imported.name.split(".", 1)[0]
        aliases[imported.asname or root] = (
            imported.name if imported.name.split(".", 1)[0] in _FRAMEWORK_MODULES else None
        )


def _record_import_from(statement: ast.ImportFrom, aliases: dict[str, str | None]) -> None:
    module = statement.module or ""
    for imported in statement.names:
        if imported.name == "*" or statement.level:
            continue
        name = imported.asname or imported.name
        canonical = f"{module}.{imported.name}"
        if (
            canonical in _DIRECT_OPERATIONS
            or module in _FRAMEWORK_MODULES
            or module.startswith(tuple(f"{item}." for item in _FRAMEWORK_MODULES))
        ):
            aliases[name] = canonical
        else:
            aliases[name] = None


def _canonical_reference(
    node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe601ScanError(PythonCwe601ScanErrorCode.SIGNAL_LIMIT)
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
        if _dotted_name(node.func) not in {"getattr", "builtins.getattr"}:
            return _canonical_reference(node.func, aliases, max_depth, depth + 1)
        if len(node.args) < 2 or node.keywords:
            return None
        base = _canonical_reference(node.args[0], aliases, max_depth, depth + 1)
        member = _literal_string(node.args[1])
        return None if base is None or member is None else f"{base}.{member}"
    return None


def _latest_assignment(
    tree: ast.AST,
    call: ast.AST,
    name: str,
    before: tuple[int, int] | None,
) -> ast.Assign | ast.AnnAssign | ast.NamedExpr | None:
    scope = _enclosing_function(call, tree)
    root: ast.AST = scope if scope is not None else tree
    boundary = before or (getattr(call, "lineno", 0), getattr(call, "col_offset", 0))
    candidates: list[ast.Assign | ast.AnnAssign | ast.NamedExpr] = []
    stack: list[ast.AST] = [root]
    while stack:
        current = stack.pop()
        if current is not root and isinstance(
            current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            continue
        if isinstance(current, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            position = (current.lineno, current.col_offset)
            if isinstance(current, ast.Assign):
                targets = current.targets
            elif isinstance(current, ast.AnnAssign):
                targets = [current.target]
            else:
                targets = [current.target]
            if position < boundary and any(_target_has_name(target, name) for target in targets):
                candidates.append(current)
        stack.extend(reversed(tuple(ast.iter_child_nodes(current))))
    return max(candidates, key=lambda item: (item.lineno, item.col_offset), default=None)


def _target_has_name(target: ast.AST, name: str) -> bool:
    return any(item.id == name for item in ast.walk(target) if isinstance(item, ast.Name))


def _enclosing_function(
    call: ast.AST, tree: ast.AST
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


def _add_fact(
    output: set[tuple[SourceRange, SourceRange, PythonCwe601Operation]],
    source_range: SourceRange,
    sink_range: SourceRange,
    operation: PythonCwe601Operation,
) -> None:
    if not sink_range.contains(source_range):
        raise PythonCwe601ScanError(PythonCwe601ScanErrorCode.INTEGRITY_FAILURE)
    output.add((source_range, sink_range, operation))


def _literal_string(node: ast.AST | None) -> str | None:
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
        raise PythonCwe601ScanError(PythonCwe601ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe601ScanError(PythonCwe601ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe601ScanError(PythonCwe601ScanErrorCode.INTEGRITY_FAILURE)
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
    operation: PythonCwe601Operation,
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
    signals: tuple[PythonCwe601Signal, ...],
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


# Compatibility aliases keep this adapter usable beside the existing CWE
# scanners while retaining the Python-specific implementation names.
Cwe601ScanErrorCode = PythonCwe601ScanErrorCode
Cwe601ScanError = PythonCwe601ScanError
Cwe601ScanLimits = PythonCwe601ScanLimits
Cwe601ScanResult = PythonCwe601ScanResult
Cwe601Signal = PythonCwe601Signal


__all__ = [
    "DEFAULT_PYTHON_CWE601_SCAN_LIMITS",
    "Cwe601ScanError",
    "Cwe601ScanErrorCode",
    "Cwe601ScanLimits",
    "Cwe601ScanResult",
    "Cwe601Signal",
    "PythonCwe601Operation",
    "PythonCwe601ScanError",
    "PythonCwe601ScanErrorCode",
    "PythonCwe601ScanLimits",
    "PythonCwe601ScanResult",
    "PythonCwe601Signal",
    "scan_python_cwe601",
]
