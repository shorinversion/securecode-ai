"""Bounded Go source-to-sink facts for CWE-601 open redirects.

The scanner consumes one sealed Go :class:`~securecode_ai.core.SymbolIndex` and
emits immutable, source-free facts.  It covers the standard ``net/http``
redirect helpers and ``Location`` response headers, together with a small
bounded data-flow model for request-controlled URL and query values.  URL
parsing is transparent, while explicit allow-list and redirect sanitizers are
treated as validation boundaries.  The module produces scanner facts only;
it does not decide whether a fact is a vulnerability.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import (
    ParseHealth,
    RepositoryFile,
    SourcePoint,
    SourceRange,
    SymbolIndex,
)
from tree_sitter import Language, Node, Parser

from .cst import build_go_symbol_index
from .cst_go import _go_language

_MAX_LIMITS = (2_000_000, 2_048, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-go-cwe601"
_DETECTOR = "securecode-go-cwe601@1.0"

_HTTP_PACKAGE = "net/http"
_URL_PACKAGE = "net/url"
_HTTP_REDIRECT = "Redirect"
_HTTP_REDIRECT_HANDLER = "RedirectHandler"
_LOCATION_METHODS = frozenset({"Set", "Add", "SetCanonical"})
_URL_PARSERS = frozenset(
    {
        "JoinPath",
        "Parse",
        "ParseRequestURI",
        "PathEscape",
        "PathUnescape",
        "QueryEscape",
        "QueryUnescape",
        "ResolveReference",
    }
)
_URL_METHODS = frozenset({"String", "EscapedPath", "RequestURI", "Path", "RawPath"})
_STRING_HELPERS = frozenset(
    {"Join", "Replace", "ReplaceAll", "TrimSpace", "TrimPrefix", "TrimSuffix", "Sprintf"}
)
_REQUEST_METHODS = frozenset({"FormValue", "PostFormValue", "PathValue"})
_QUERY_METHODS = frozenset({"Get", "Has", "Encode"})
_ALLOWLIST_SANITIZERS = frozenset(
    {
        "allowRedirect",
        "allowedRedirect",
        "allowedURL",
        "isAllowedHost",
        "isAllowedRedirect",
        "isAllowedURL",
        "isSafeRedirect",
        "isSafeURL",
        "sanitizeRedirect",
        "sanitizeURL",
        "safeRedirect",
        "safeRedirectURL",
        "safeURL",
        "validateRedirect",
        "validateRedirectTarget",
        "validateURL",
    }
)
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})


class GoCwe601ScanErrorCode(StrEnum):
    """Closed, source-free reasons a Go open-redirect scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe601ScanError(RuntimeError):
    """Fixed scanner failure that never echoes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe601ScanErrorCode) -> None:
        if type(code) is not GoCwe601ScanErrorCode:
            raise TypeError("Go CWE-601 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-601 open redirect scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe601ScanLimits:
    """Hard ceilings applied before and during structural data-flow analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-601 scan limits are invalid")


DEFAULT_GO_CWE601_SCAN_LIMITS = GoCwe601ScanLimits()


class GoCwe601Operation(StrEnum):
    """Recognised Go redirect and response-header operations."""

    HTTP_REDIRECT = "http.redirect"
    HTTP_REDIRECT_HANDLER = "http.redirect_handler"
    LOCATION_HEADER = "http.location_header"

    REDIRECT = "http.redirect"
    REDIRECT_HANDLER = "http.redirect_handler"
    HEADER_SET = "http.location_header"


@dataclass(frozen=True, slots=True)
class GoCwe601Signal:
    """One immutable request-to-redirect destination fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe601Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-601"
    detector: str = _DETECTOR
    detail: str = "untrusted_redirect_destination"

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
            and self.source.start_byte <= self.sink.end_byte
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
            if valid_identity and valid_ranges and type(self.operation) is GoCwe601Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not GoCwe601Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-601"
            or self.detector != _DETECTOR
            or self.detail != "untrusted_redirect_destination"
        ):
            raise ValueError("Go CWE-601 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", expected_id)

    @property
    def deterministic_id(self) -> str:
        return self.signal_id

    @property
    def location(self) -> SourceRange:
        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class GoCwe601ScanResult:
    """Deterministic, source-free result for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe601Signal, ...]
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
            type(item) is GoCwe601Signal for item in self.signals
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
        same_identity = all(
            item.repository_id == self.repository_id
            and item.revision == self.revision
            and item.path == self.path
            and item.content_sha256 == self.content_sha256
            and item.source_size_bytes == self.source_size_bytes
            for item in self.signals
        )
        if (
            not identity_valid
            or not valid_signals
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
            or len({item.signal_id for item in self.signals}) != len(self.signals)
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
            raise ValueError("Go CWE-601 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange
    sanitized: bool = False


@dataclass(frozen=True, slots=True)
class _Guard:
    start_byte: int
    end_byte: int
    names: frozenset[str]


def scan_go_cwe601(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe601ScanLimits = DEFAULT_GO_CWE601_SCAN_LIMITS,
) -> GoCwe601ScanResult:
    """Find bounded request-controlled destinations in Go redirect sinks."""

    _validate_request(symbol_index, limits)
    source = symbol_index.source
    try:
        rebuilt = build_go_symbol_index(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source=source,
        )
        if rebuilt != symbol_index:
            raise ValueError("index mismatch")
        root = Parser(Language(_go_language())).parse(source).root_node
        if root.has_error:
            raise ValueError("parse error")
        source.decode("utf-8", errors="strict")
    except Exception:
        raise GoCwe601ScanError(GoCwe601ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    raw: set[tuple[SourceRange, SourceRange, GoCwe601Operation]] = set()
    try:
        for scope in _scopes(root):
            environment: dict[str, tuple[_Flow, ...]] = {}
            query_aliases: set[str] = set()
            header_aliases: set[str] = set()
            guards = _allowlist_guards(scope, source)
            for node in _scope_preorder(scope):
                if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                    _capture_assignment(
                        node,
                        environment,
                        query_aliases,
                        header_aliases,
                        source,
                        imports,
                        limits,
                    )
                    assignment = _location_header_assignment(node, source, header_aliases)
                    if assignment is not None:
                        value, sink = assignment
                        allowed = _guarded_names(guards, sink)
                        for flow in _resolve(
                            value,
                            environment,
                            query_aliases,
                            source,
                            imports,
                            limits,
                            0,
                            frozenset(),
                            allowed,
                        ):
                            if not flow.sanitized:
                                raw.add(
                                    (flow.source, _range(sink), GoCwe601Operation.LOCATION_HEADER)
                                )
                if node.type != "call_expression":
                    continue
                sink_info = _sink_for_call(node, source, imports, header_aliases)
                if sink_info is None:
                    continue
                operation, arguments = sink_info
                allowed = _guarded_names(guards, node)
                for argument in arguments:
                    for flow in _resolve(
                        argument,
                        environment,
                        query_aliases,
                        source,
                        imports,
                        limits,
                        0,
                        frozenset(),
                        allowed,
                    ):
                        if flow.sanitized:
                            continue
                        raw.add((flow.source, _range(node), operation))
                        if len(raw) > limits.max_signals:
                            raise GoCwe601ScanError(GoCwe601ScanErrorCode.SIGNAL_LIMIT)
    except GoCwe601ScanError:
        raise
    except Exception:
        raise GoCwe601ScanError(GoCwe601ScanErrorCode.INTEGRITY_FAILURE) from None

    ordered = sorted(
        raw,
        key=lambda item: (
            item[1].start_byte,
            item[1].end_byte,
            item[0].start_byte,
            item[0].end_byte,
            item[2].value,
        ),
    )
    if len(ordered) > limits.max_signals:
        raise GoCwe601ScanError(GoCwe601ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe601Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
            signal_id=_signal_id(
                symbol_index.repository_id,
                symbol_index.revision,
                symbol_index.path,
                symbol_index.content_sha256,
                symbol_index.source_byte_length,
                source_range,
                sink_range,
                operation,
            ),
        )
        for source_range, sink_range, operation in ordered
    )
    return GoCwe601ScanResult(
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


def scan_go_cwe601_open_redirect(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe601ScanLimits = DEFAULT_GO_CWE601_SCAN_LIMITS,
) -> GoCwe601ScanResult:
    """Descriptive alias for :func:`scan_go_cwe601`."""

    return scan_go_cwe601(symbol_index, limits=limits)


def scan_go_open_redirect(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe601ScanLimits = DEFAULT_GO_CWE601_SCAN_LIMITS,
) -> GoCwe601ScanResult:
    """Compatibility alias for callers grouping Go redirect scanners."""

    return scan_go_cwe601(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe601ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe601ScanLimits:
        raise GoCwe601ScanError(GoCwe601ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe601ScanError(GoCwe601ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe601ScanError(GoCwe601ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe601ScanError(GoCwe601ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    relevant = {_HTTP_PACKAGE, _URL_PACKAGE, "fmt", "strings"}
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        package = _text(source, path_node).strip('"`')
        if package not in relevant:
            continue
        name_node = node.child_by_field_name("name")
        alias = _text(source, name_node) if name_node is not None else package.rsplit("/", 1)[-1]
        if alias not in {".", "_"}:
            aliases[alias] = package
    return aliases


def _sink_for_call(
    node: Node,
    source: bytes,
    imports: dict[str, str],
    header_aliases: set[str],
) -> tuple[GoCwe601Operation, tuple[Node, ...]] | None:
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None or function.type != "selector_expression":
        return None
    values = tuple(arguments.named_children)
    if not values:
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    package = imports.get(_text(source, operand))
    name = _text(source, field)
    if package == _HTTP_PACKAGE and name == _HTTP_REDIRECT:
        return (
            GoCwe601Operation.HTTP_REDIRECT,
            (values[2],) if len(values) > 2 else (),
        )
    if package == _HTTP_PACKAGE and name == _HTTP_REDIRECT_HANDLER:
        return (
            GoCwe601Operation.HTTP_REDIRECT_HANDLER,
            (values[0],),
        )
    header_name = _literal_text(source, values[0])
    if name not in _LOCATION_METHODS or header_name is None or header_name.lower() != "location":
        return None
    if not _is_header_expression(operand, source, header_aliases):
        return None
    return GoCwe601Operation.LOCATION_HEADER, (values[1],) if len(values) > 1 else ()


def _location_header_assignment(
    node: Node, source: bytes, header_aliases: set[str]
) -> tuple[Node, Node] | None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return None
    left_values = tuple(left.named_children) if left.type == "expression_list" else (left,)
    right_values = tuple(right.named_children) if right.type == "expression_list" else (right,)
    for target, value in zip(left_values, right_values, strict=False):
        if target.type != "index_expression":
            continue
        values = tuple(target.named_children)
        if len(values) < 2:
            continue
        header_name = _literal_text(source, values[-1])
        if header_name is None or header_name.lower() != "location":
            continue
        receiver = values[0]
        if _is_header_expression(receiver, source, header_aliases):
            return value, node
    return None


def _is_header_expression(node: Node, source: bytes, header_aliases: set[str]) -> bool:
    if node.type == "identifier":
        return _text(source, node) in header_aliases
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return False
    field = function.child_by_field_name("field")
    return field is not None and _text(source, field) == "Header"


def _capture_assignment(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    query_aliases: set[str],
    header_aliases: set[str],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe601ScanLimits,
) -> None:
    if node.type == "var_spec":
        names_node = node.child_by_field_name("name")
        values_node = node.child_by_field_name("value")
        if names_node is None or values_node is None:
            return
        names = tuple(names_node.named_children) or (names_node,)
        values = tuple(values_node.named_children) or (values_node,)
    else:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        names = tuple(left.named_children) if left.type == "expression_list" else (left,)
        values = tuple(right.named_children) if right.type == "expression_list" else (right,)
    if len(values) == 1 and len(names) > 1:
        values = values * len(names)
    for name, value in zip(names, values, strict=False):
        if name.type != "identifier":
            continue
        identifier = _text(source, name)
        if _is_query_expression(value, source):
            query_aliases.add(identifier)
        if _is_header_expression(value, source, header_aliases):
            header_aliases.add(identifier)
        environment[identifier] = _resolve(
            value,
            environment,
            query_aliases,
            source,
            imports,
            limits,
            0,
            frozenset({identifier}),
            frozenset(),
        )


def _resolve(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    query_aliases: set[str],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe601ScanLimits,
    depth: int,
    visited: frozenset[str],
    sanitized_names: frozenset[str],
) -> tuple[_Flow, ...]:
    if depth > limits.max_expression_depth:
        raise GoCwe601ScanError(GoCwe601ScanErrorCode.SIGNAL_LIMIT)
    direct = _external_source(node, source, query_aliases)
    if direct is not None:
        return (_Flow(_range(direct)),)
    if node.type == "identifier":
        name = _text(source, node)
        if name in sanitized_names or name in visited:
            return ()
        return environment.get(name, ())
    if node.type in {"parenthesized_expression", "unary_expression", "pointer_expression"}:
        return _dedupe_flows(
            (
                flow
                for child in node.named_children
                for flow in _resolve(
                    child,
                    environment,
                    query_aliases,
                    source,
                    imports,
                    limits,
                    depth + 1,
                    visited,
                    sanitized_names,
                )
            ),
            limits,
        )
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            return ()
        values = tuple(arguments.named_children)
        qualified = _qualified_call(function, source, imports)
        if _is_allowlist_sanitizer(function, source):
            flows = (
                flow
                for argument in values[:1]
                for flow in _resolve(
                    argument,
                    environment,
                    query_aliases,
                    source,
                    imports,
                    limits,
                    depth + 1,
                    visited,
                    sanitized_names,
                )
            )
            return _dedupe_flows((_Flow(flow.source, True) for flow in flows), limits)
        if qualified in {f"url.{item}" for item in _URL_PARSERS}:
            values = (
                values[:1]
                if qualified == "url.Parse" or qualified == "url.ParseRequestURI"
                else values
            )
        elif qualified == "fmt.Sprintf":
            values = values[1:]
        elif qualified not in {f"url.{item}" for item in _URL_PARSERS} and qualified not in {
            f"strings.{item}" for item in _STRING_HELPERS
        }:
            if function is not None and function.type == "selector_expression":
                field = function.child_by_field_name("field")
                operand = function.child_by_field_name("operand")
                if (
                    field is not None
                    and _text(source, field) in _URL_METHODS
                    and operand is not None
                ):
                    return _resolve(
                        operand,
                        environment,
                        query_aliases,
                        source,
                        imports,
                        limits,
                        depth + 1,
                        visited,
                        sanitized_names,
                    )
            return ()
        return _dedupe_flows(
            (
                flow
                for argument in values
                for flow in _resolve(
                    argument,
                    environment,
                    query_aliases,
                    source,
                    imports,
                    limits,
                    depth + 1,
                    visited,
                    sanitized_names,
                )
            ),
            limits,
        )
    if node.type in {
        "binary_expression",
        "composite_literal",
        "element_list",
        "index_expression",
        "keyed_element",
        "literal_value",
        "slice_expression",
    }:
        return _dedupe_flows(
            (
                flow
                for child in node.named_children
                for flow in _resolve(
                    child,
                    environment,
                    query_aliases,
                    source,
                    imports,
                    limits,
                    depth + 1,
                    visited,
                    sanitized_names,
                )
            ),
            limits,
        )
    return ()


def _external_source(node: Node, source: bytes, query_aliases: set[str]) -> Node | None:
    compact = _compact_text(source, node)
    if node.type == "index_expression" and compact.endswith("]"):
        prefix = compact.rsplit("[", 1)[0]
        if prefix.endswith(".URL.Query()") or prefix in query_aliases:
            return node
    if node.type == "selector_expression" and re.search(
        r"(?:^|\.)URL\.(?:Path|RawPath|RawQuery|RequestURI)\Z", compact
    ):
        return node
    if node.type != "call_expression":
        return None
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    name = _text(source, field)
    receiver = _compact_text(source, operand)
    if name in _REQUEST_METHODS:
        return node
    if name == "Get" and (receiver.endswith(".URL.Query()") or receiver in query_aliases):
        return node
    if name == "Get" and receiver.endswith(".Header()"):
        return node
    return None


def _is_query_expression(node: Node, source: bytes) -> bool:
    return _compact_text(source, node).endswith(".URL.Query()")


def _is_allowlist_sanitizer(function: Node | None, source: bytes) -> bool:
    if function is None:
        return False
    compact = _compact_text(source, function)
    name = compact.rsplit(".", 1)[-1]
    return name in _ALLOWLIST_SANITIZERS or any(
        token in name.lower() for token in ("allow", "safe", "trusted", "sanitize", "validate")
    )


def _allowlist_guards(scope: Node, source: bytes) -> tuple[_Guard, ...]:
    guards: list[_Guard] = []
    for node in _scope_preorder(scope):
        if node.type != "if_statement":
            continue
        condition = node.child_by_field_name("condition")
        body = node.child_by_field_name("consequence")
        if condition is None or body is None:
            continue
        compact = _compact_text(source, condition).lower()
        names = frozenset(
            value
            for item in _preorder(condition)
            if item.type == "identifier"
            for value in (_text(source, item),)
            if value not in {"true", "false"}
            and value.lower() not in {name.lower() for name in _ALLOWLIST_SANITIZERS}
        )
        looks_like_allowlist = any(
            token in compact for token in ("allow", "safe", "trusted", "host", "origin", "redirect")
        )
        if not names or not looks_like_allowlist:
            continue
        guards.append(_Guard(body.start_byte, body.end_byte, names))
        if ("!" in compact and _contains_return(body)) or (
            "!=" in compact and _contains_return(body)
        ):
            guards.append(_Guard(node.end_byte, scope.end_byte, names))
    return tuple(guards)


def _guarded_names(guards: tuple[_Guard, ...], node: Node) -> frozenset[str]:
    values: set[str] = set()
    for guard in guards:
        if guard.start_byte <= node.start_byte and node.end_byte <= guard.end_byte:
            values.update(guard.names)
    return frozenset(values)


def _contains_return(node: Node) -> bool:
    return any(item.type == "return_statement" for item in _preorder(node))


def _qualified_call(function: Node | None, source: bytes, imports: dict[str, str]) -> str:
    if function is None or function.type != "selector_expression":
        return ""
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return ""
    package = imports.get(_text(source, operand))
    name = _text(source, field)
    if package in {_HTTP_PACKAGE, _URL_PACKAGE}:
        return f"{package.rsplit('/', 1)[-1]}.{name}"
    if package in {"fmt", "strings"}:
        return f"{package}.{name}"
    return ""


def _scopes(root: Node) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node == root or node.type in _GO_SCOPES)


def _scope_preorder(scope: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    while stack:
        node = stack.pop()
        output.append(node)
        if node != scope and node.type in _GO_SCOPES:
            continue
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _preorder(root: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        output.append(node)
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _dedupe_flows(flows: Iterable[_Flow], limits: GoCwe601ScanLimits) -> tuple[_Flow, ...]:
    unique: dict[tuple[int, int, bool], _Flow] = {}
    for flow in flows:
        unique[(flow.source.start_byte, flow.source.end_byte, flow.sanitized)] = flow
        if len(unique) > limits.max_signals:
            raise GoCwe601ScanError(GoCwe601ScanErrorCode.SIGNAL_LIMIT)
    return tuple(unique[key] for key in sorted(unique))


def _text(source: bytes, node: Node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")


def _compact_text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return "".join(_text(source, node).split())


def _literal_text(source: bytes, node: Node) -> str | None:
    value = _text(source, node)
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return None


def _range(node: Node) -> SourceRange:
    return SourceRange(
        node.start_byte,
        node.end_byte,
        SourcePoint(node.start_point.row, node.start_point.column),
        SourcePoint(node.end_point.row, node.end_point.column),
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
    operation: GoCwe601Operation,
) -> str:
    material = {
        "content_sha256": content_sha256,
        "cwe": "CWE-601",
        "detector": _DETECTOR,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "sink": _range_value(sink),
        "source": _range_value(source),
        "source_size_bytes": source_size_bytes,
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    return digest


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe601Signal, ...],
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


# Compatibility aliases keep the module usable beside the existing portfolio
# adapters while retaining a Go-specific public name.
Cwe601ScanErrorCode = GoCwe601ScanErrorCode
Cwe601ScanError = GoCwe601ScanError
Cwe601ScanLimits = GoCwe601ScanLimits
Cwe601ScanResult = GoCwe601ScanResult
Cwe601Signal = GoCwe601Signal


__all__ = [
    "DEFAULT_GO_CWE601_SCAN_LIMITS",
    "Cwe601ScanError",
    "Cwe601ScanErrorCode",
    "Cwe601ScanLimits",
    "Cwe601ScanResult",
    "Cwe601Signal",
    "GoCwe601Operation",
    "GoCwe601ScanError",
    "GoCwe601ScanErrorCode",
    "GoCwe601ScanLimits",
    "GoCwe601ScanResult",
    "GoCwe601Signal",
    "scan_go_cwe601",
    "scan_go_cwe601_open_redirect",
    "scan_go_open_redirect",
]
