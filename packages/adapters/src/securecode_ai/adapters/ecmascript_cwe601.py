"""Bounded JavaScript and TypeScript CWE-601 open-redirect facts.

This module consumes a sealed ECMAScript ``SymbolIndex`` and reparses the
admitted bytes before inspecting the CST.  It recognizes explicit request
sources, a small allow-list of response redirect and browser navigation
sinks, and local alias propagation.  The output is immutable and contains
only source ranges and content-addressed metadata.  It is a scanner
primitive, not a finding or a verdict.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import ParseHealth, RepositoryFile, SourcePoint, SourceRange, SymbolIndex
from tree_sitter import Language, Node, Parser

from .cst import CstAdapterError, build_javascript_symbol_index, build_typescript_symbol_index
from .cst_ecmascript import _javascript_language, _typescript_language

_MAX_LIMITS = (2_000_000, 250_000, 512, 10_000)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_RULE_ID = "securecode-ecmascript-cwe601"
_DETECTOR = "securecode-ecmascript-cwe601@1.0"

_REQUEST_ROOTS = frozenset({"ctx", "context", "event", "httpRequest", "req", "request"})
_REQUEST_FIELDS = frozenset(
    {
        "body",
        "cookies",
        "headers",
        "params",
        "path",
        "pathParameters",
        "query",
        "queryStringParameters",
    }
)
_RESPONSE_ROOTS = frozenset(
    {
        "ctx",
        "context",
        "h",
        "httpResponse",
        "reply",
        "res",
        "response",
        "serverResponse",
    }
)
_ROUTER_ROOTS = frozenset({"navigate", "navigation", "router"})
_LOCATION_ROOTS = frozenset({"document.location", "location", "window.location"})
_KNOWN_REDIRECT_MODULES = frozenset(
    {
        "@remix-run/node",
        "@remix-run/router",
        "next/navigation",
        "next/server",
        "react-router",
        "react-router-dom",
    }
)
_PRESERVING_FUNCTIONS = frozenset(
    {
        "String",
        "decodeURI",
        "decodeURIComponent",
        "encodeURI",
        "encodeURIComponent",
        "URL",
        "URLSearchParams",
    }
)


class EcmaScriptCwe601ScanErrorCode(StrEnum):
    """Closed, source-free reasons a scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe601ScanError(RuntimeError):
    """Fixed scanner failure that never includes source or parser text."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe601ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe601ScanErrorCode:
            raise TypeError("ECMAScript CWE-601 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-601 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe601ScanLimits:
    """Hard ceilings applied before and during structural analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_nodes: int = _MAX_LIMITS[1]
    max_depth: int = _MAX_LIMITS[2]
    max_signals: int = _MAX_LIMITS[3]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_nodes, self.max_depth, self.max_signals)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("ECMAScript CWE-601 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE601_SCAN_LIMITS = EcmaScriptCwe601ScanLimits()


class EcmaScriptCwe601Operation(StrEnum):
    """Recognized response redirect and browser navigation operations."""

    RESPONSE_REDIRECT = "response_redirect"
    NAVIGATION_REDIRECT = "navigation_redirect"
    LOCATION_ASSIGN = "location_assign"
    LOCATION_REPLACE = "location_replace"
    LOCATION_ASSIGNMENT = "location_assignment"
    LOCATION_HREF_ASSIGNMENT = "location_href_assignment"
    WINDOW_OPEN = "window_open"
    ROUTER_PUSH = "router_push"
    ROUTER_REPLACE = "router_replace"
    ROUTER_NAVIGATE = "router_navigate"
    HISTORY_PUSH_STATE = "history_push_state"
    HISTORY_REPLACE_STATE = "history_replace_state"

    # Descriptive compatibility names for callers that use framework terms.
    EXPRESS_REDIRECT = "response_redirect"
    FASTIFY_REDIRECT = "response_redirect"
    KOA_REDIRECT = "response_redirect"
    NEXT_REDIRECT = "navigation_redirect"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe601Signal:
    """One immutable request-to-redirect destination fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe601Operation
    signal_id: str
    rule_id: str = _RULE_ID
    cwe: str = "CWE-601"
    detector: str = _DETECTOR
    detail: str = "untrusted_redirect_destination"

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
            and self.sink.contains(self.source)
            and self.source.end_byte <= self.source_size_bytes
            and self.sink.end_byte <= self.source_size_bytes
        )
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not EcmaScriptCwe601Operation
            or type(self.signal_id) is not str
            or _SHA256.fullmatch(self.signal_id) is None
            or self.signal_id
            != _signal_id(
                self.repository_id,
                self.revision,
                self.path,
                self.content_sha256,
                self.source_size_bytes,
                self.source,
                self.sink,
                self.operation,
            )
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-601"
            or self.detector != _DETECTOR
            or self.detail != "untrusted_redirect_destination"
        ):
            raise ValueError("ECMAScript CWE-601 signal is invalid")

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the sink range used by generic scanner consumers."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe601ScanResult:
    """Deterministic, source-free result for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe601Signal, ...]
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
            and self.language in {"javascript", "typescript"}
        )
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity_valid = False
        order = tuple(
            (
                item.sink.start_byte,
                item.sink.end_byte,
                item.source.start_byte,
                item.source.end_byte,
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
            not identity_valid
            or type(self.signals) is not tuple
            or any(type(item) is not EcmaScriptCwe601Signal for item in self.signals)
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
                self.language,
                self.signals,
            )
        ):
            raise ValueError("ECMAScript CWE-601 scan result is invalid")


def scan_javascript_cwe601(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe601ScanLimits = DEFAULT_ECMASCRIPT_CWE601_SCAN_LIMITS,
) -> EcmaScriptCwe601ScanResult:
    """Find bounded JavaScript request-to-redirect facts."""

    return _scan_ecmascript_cwe601(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe601(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe601ScanLimits = DEFAULT_ECMASCRIPT_CWE601_SCAN_LIMITS,
) -> EcmaScriptCwe601ScanResult:
    """Find bounded TypeScript request-to-redirect facts."""

    return _scan_ecmascript_cwe601(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe601(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe601ScanLimits = DEFAULT_ECMASCRIPT_CWE601_SCAN_LIMITS,
) -> EcmaScriptCwe601ScanResult:
    """Dispatch a CWE-601 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe601(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe601(symbol_index, limits=limits)
    raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe601(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe601ScanLimits,
) -> EcmaScriptCwe601ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe601ScanLimits:
        raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.ANALYSIS_UNAVAILABLE)

    builder = (
        build_javascript_symbol_index
        if expected_language == "javascript"
        else build_typescript_symbol_index
    )
    try:
        rebuilt = builder(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source=symbol_index.source,
        )
        if rebuilt != symbol_index:
            raise ValueError("symbol index mismatch")
        grammar = (
            _javascript_language()
            if expected_language == "javascript"
            else _typescript_language(tsx=symbol_index.path.endswith(".tsx"))
        )
        source = symbol_index.source
        source.decode("utf-8", errors="strict")
        root = Parser(Language(grammar)).parse(source).root_node
    except (CstAdapterError, TypeError, UnicodeDecodeError, ValueError):
        raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.INTEGRITY_FAILURE) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.ANALYSIS_UNAVAILABLE)
        aliases = _collect_aliases(nodes, source)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe601Operation]] = set()
        for node in nodes:
            if node.type == "call_expression":
                operation = _operation_for_call(node, source, aliases)
                if operation is None:
                    continue
                arguments = node.child_by_field_name("arguments")
                if arguments is None:
                    raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.INTEGRITY_FAILURE)
                scope = _enclosing_scope(node, root)
                for argument in _sink_arguments(arguments, operation):
                    for source_node in _resolve_source(
                        argument,
                        scope=scope,
                        source=source,
                        aliases=aliases,
                        limits=limits,
                        depth=0,
                        visited=frozenset(),
                    ):
                        _add_fact(raw, _range(source_node), _range(node), operation)
                        if len(raw) > limits.max_signals:
                            raise EcmaScriptCwe601ScanError(
                                EcmaScriptCwe601ScanErrorCode.SIGNAL_LIMIT
                            )
            elif node.type in {"assignment_expression", "augmented_assignment_expression"}:
                fact = _assignment_fact(node, source, aliases)
                if fact is not None:
                    raw.add(fact)
            if len(raw) > limits.max_signals:
                raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.SIGNAL_LIMIT)
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
    except EcmaScriptCwe601ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.INTEGRITY_FAILURE) from None

    if len(ordered) > limits.max_signals:
        raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        EcmaScriptCwe601Signal(
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
    return EcmaScriptCwe601ScanResult(
        repository_id=symbol_index.repository_id,
        revision=symbol_index.revision,
        path=symbol_index.path,
        content_sha256=symbol_index.content_sha256,
        source_size_bytes=symbol_index.source_byte_length,
        language=expected_language,
        signals=signals,
        scan_sha256=_scan_sha256(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            expected_language,
            signals,
        ),
    )


def _bounded_nodes(root: Node, limits: EcmaScriptCwe601ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _operation_for_call(
    node: Node, source: bytes, aliases: dict[str, str]
) -> EcmaScriptCwe601Operation | None:
    function = node.child_by_field_name("function")
    if function is None:
        return None
    canonical = _canonical_expression(function, source, aliases)
    if canonical is None:
        return None
    exact = {
        "history.pushState": EcmaScriptCwe601Operation.HISTORY_PUSH_STATE,
        "history.replaceState": EcmaScriptCwe601Operation.HISTORY_REPLACE_STATE,
        "location.assign": EcmaScriptCwe601Operation.LOCATION_ASSIGN,
        "location.replace": EcmaScriptCwe601Operation.LOCATION_REPLACE,
        "window.location.assign": EcmaScriptCwe601Operation.LOCATION_ASSIGN,
        "window.location.replace": EcmaScriptCwe601Operation.LOCATION_REPLACE,
        "document.location.assign": EcmaScriptCwe601Operation.LOCATION_ASSIGN,
        "document.location.replace": EcmaScriptCwe601Operation.LOCATION_REPLACE,
        "window.open": EcmaScriptCwe601Operation.WINDOW_OPEN,
        "open": EcmaScriptCwe601Operation.WINDOW_OPEN,
        "navigate": EcmaScriptCwe601Operation.ROUTER_NAVIGATE,
        "router.navigate": EcmaScriptCwe601Operation.ROUTER_NAVIGATE,
        "router.push": EcmaScriptCwe601Operation.ROUTER_PUSH,
        "router.replace": EcmaScriptCwe601Operation.ROUTER_REPLACE,
        "navigation.navigate": EcmaScriptCwe601Operation.ROUTER_NAVIGATE,
        "navigation.push": EcmaScriptCwe601Operation.ROUTER_PUSH,
        "navigation.replace": EcmaScriptCwe601Operation.ROUTER_REPLACE,
        "Response.redirect": EcmaScriptCwe601Operation.NAVIGATION_REDIRECT,
        "NextResponse.redirect": EcmaScriptCwe601Operation.NAVIGATION_REDIRECT,
    }
    if canonical in exact:
        return exact[canonical]
    if canonical == "redirect" or _known_import_redirect(canonical):
        return EcmaScriptCwe601Operation.RESPONSE_REDIRECT
    parts = canonical.split(".")
    if len(parts) >= 2 and parts[-1] == "redirect" and parts[0] in _RESPONSE_ROOTS:
        return EcmaScriptCwe601Operation.RESPONSE_REDIRECT
    if len(parts) == 2 and parts[0] in _ROUTER_ROOTS:
        return {
            "push": EcmaScriptCwe601Operation.ROUTER_PUSH,
            "replace": EcmaScriptCwe601Operation.ROUTER_REPLACE,
            "navigate": EcmaScriptCwe601Operation.ROUTER_NAVIGATE,
        }.get(parts[1])
    return None


def _known_import_redirect(canonical: str) -> bool:
    parts = canonical.rsplit(".", 1)
    return len(parts) == 2 and parts[1] == "redirect" and parts[0] in _KNOWN_REDIRECT_MODULES


def _sink_arguments(arguments: Node, operation: EcmaScriptCwe601Operation) -> tuple[Node, ...]:
    values = arguments.named_children
    if not values:
        return ()
    if operation in {
        EcmaScriptCwe601Operation.HISTORY_PUSH_STATE,
        EcmaScriptCwe601Operation.HISTORY_REPLACE_STATE,
    }:
        return (values[2],) if len(values) >= 3 else ()
    return (values[0],)


def _assignment_fact(
    node: Node, source: bytes, aliases: dict[str, str]
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe601Operation] | None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return None
    path = _canonical_member_path(left, source, aliases)
    if path is None:
        return None
    canonical = ".".join(path)
    if canonical in {"location", "window.location", "document.location"}:
        operation = EcmaScriptCwe601Operation.LOCATION_ASSIGNMENT
    elif canonical in {
        "location.href",
        "window.location.href",
        "document.location.href",
        "location.pathname",
        "window.location.pathname",
        "document.location.pathname",
    }:
        operation = EcmaScriptCwe601Operation.LOCATION_HREF_ASSIGNMENT
    else:
        return None
    sink = _range(node)
    source_range = _range(right)
    if not sink.contains(source_range):
        raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.INTEGRITY_FAILURE)
    return source_range, sink, operation


def _add_fact(
    output: set[tuple[SourceRange, SourceRange, EcmaScriptCwe601Operation]],
    source: SourceRange,
    sink: SourceRange,
    operation: EcmaScriptCwe601Operation,
) -> None:
    if not sink.contains(source):
        raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.INTEGRITY_FAILURE)
    output.add((source, sink, operation))


def _resolve_source(
    node: Node,
    *,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe601ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[Node, ...]:
    if depth > limits.max_depth:
        raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.DEPTH_LIMIT)
    if _is_request_source(node, source):
        return (node,)
    if node.type == "identifier":
        name = _text(source, node)
        if name in visited:
            return ()
        bound = _latest_binding(scope, name, node.start_byte, source)
        if bound is None:
            return ()
        return _resolve_source(
            bound,
            scope=scope,
            source=source,
            aliases=aliases,
            limits=limits,
            depth=depth + 1,
            visited=visited | {name},
        )
    if node.type in {
        "await_expression",
        "parenthesized_expression",
        "non_null_expression",
        "unary_expression",
        "update_expression",
        "as_expression",
        "satisfies_expression",
    }:
        return _resolve_children(node, scope, source, aliases, limits, depth + 1, visited)
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            return ()
        canonical = _canonical_expression(function, source, aliases)
        if _is_preserving_call(canonical):
            return _resolve_children(arguments, scope, source, aliases, limits, depth + 1, visited)
        return ()
    if node.type == "new_expression":
        return _resolve_children(node, scope, source, aliases, limits, depth + 1, visited)
    if node.type in {
        "binary_expression",
        "conditional_expression",
        "assignment_expression",
        "ternary_expression",
        "template_substitution",
        "template_string",
        "sequence_expression",
        "logical_expression",
        "object",
        "array",
    }:
        return _resolve_children(node, scope, source, aliases, limits, depth + 1, visited)
    if node.type in {"member_expression", "subscript_expression"}:
        return _resolve_children(node, scope, source, aliases, limits, depth + 1, visited)
    return ()


def _is_preserving_call(canonical: str | None) -> bool:
    if canonical is None:
        return False
    if canonical in _PRESERVING_FUNCTIONS:
        return True
    return canonical.endswith((".toString", ".trim", ".toLowerCase", ".toUpperCase"))


def _resolve_children(
    node: Node,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe601ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[Node, ...]:
    values: list[Node] = []
    for child in node.named_children:
        values.extend(
            _resolve_source(
                child,
                scope=scope,
                source=source,
                aliases=aliases,
                limits=limits,
                depth=depth,
                visited=visited,
            )
        )
    unique: dict[tuple[int, int], Node] = {}
    for value in values:
        unique[(value.start_byte, value.end_byte)] = value
    return tuple(unique[key] for key in sorted(unique))


def _is_request_source(node: Node, source: bytes) -> bool:
    compact = _compact_text(source, node).replace("?.", ".")
    if node.type in {"member_expression", "subscript_expression"}:
        return _member_request_source(compact)
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None:
        return False
    return _call_request_source(_compact_text(source, function).replace("?.", "."))


def _member_request_source(value: str) -> bool:
    pieces = value.replace("[", ".[").split(".")
    if len(pieces) < 3 or pieces[0] not in _REQUEST_ROOTS:
        return False
    index = 1
    if pieces[index] == "request":
        index += 1
    if index >= len(pieces) or pieces[index] not in _REQUEST_FIELDS:
        return False
    return len(pieces) > index + 1 and any(part for part in pieces[index + 1 :])


def _call_request_source(callee: str) -> bool:
    pieces = callee.replace("[", ".[").split(".")
    if pieces and pieces[0] in _REQUEST_ROOTS:
        return callee.endswith((".get", ".param", ".header")) and (
            len(pieces) >= 2
            and (pieces[-2] in _REQUEST_FIELDS or pieces[-1] in {"param", "header"})
        )
    return callee.endswith(".searchParams.get") or (callee.endswith(".get") and "query" in pieces)


def _enclosing_scope(node: Node, root: Node) -> Node:
    current = node.parent
    while current is not None:
        if current.type in {
            "function_declaration",
            "function",
            "function_expression",
            "arrow_function",
            "generator_function",
            "generator_function_declaration",
            "method_definition",
        }:
            return current
        current = current.parent
    return root


def _latest_binding(scope: Node, name: str, before: int, source: bytes) -> Node | None:
    bound: Node | None = None
    for node in _scope_preorder(scope):
        if node.start_byte >= before:
            continue
        if node.type == "variable_declarator":
            left = node.child_by_field_name("name")
            right = node.child_by_field_name("value")
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
        else:
            continue
        if (
            left is not None
            and right is not None
            and left.type == "identifier"
            and _text(source, left) == name
        ):
            bound = right
    return bound


def _scope_preorder(scope: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    nested = {
        "function_declaration",
        "function",
        "function_expression",
        "arrow_function",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
    first = True
    while stack:
        node = stack.pop()
        output.append(node)
        if not first and node.type in nested:
            continue
        first = False
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _collect_aliases(nodes: tuple[Node, ...], source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in nodes:
        if node.type == "import_statement":
            _collect_import_aliases(node, source, aliases)
        elif node.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in node.named_children:
                if declarator.type != "variable_declarator":
                    continue
                name = declarator.child_by_field_name("name")
                value = declarator.child_by_field_name("value")
                if name is None or value is None:
                    continue
                canonical = _canonical_expression(value, source, aliases)
                if canonical is None:
                    continue
                if name.type == "identifier":
                    aliases[_text(source, name)] = canonical
                elif name.type in {"object_pattern", "object"}:
                    _collect_pattern_aliases(name, canonical, source, aliases)
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                canonical = _canonical_expression(right, source, aliases)
                if canonical is not None:
                    aliases[_text(source, left)] = canonical
    return aliases


def _collect_import_aliases(node: Node, source: bytes, aliases: dict[str, str]) -> None:
    module_node = node.child_by_field_name("source")
    if module_node is None:
        return
    module = _string_value(module_node, source)
    if module is None:
        return
    module = _normalise_module(module)
    for clause in node.named_children:
        if clause.type != "import_clause":
            continue
        for item in clause.named_children:
            if item.type == "identifier":
                aliases[_text(source, item)] = module
            elif item.type == "namespace_import":
                children = item.named_children
                if children:
                    aliases[_text(source, children[-1])] = module
            elif item.type in {"named_imports", "named_import"}:
                for specifier in item.named_children:
                    if specifier.type != "import_specifier":
                        continue
                    names = list(specifier.named_children)
                    if not names:
                        continue
                    imported = _text(source, names[0])
                    local = _text(source, names[-1])
                    aliases[local] = f"{module}.{imported}"


def _collect_pattern_aliases(
    pattern: Node, module: str, source: bytes, aliases: dict[str, str]
) -> None:
    for child in pattern.named_children:
        if child.type not in {
            "pair",
            "object_pattern_property",
            "shorthand_property_identifier_pattern",
        }:
            continue
        key = child.child_by_field_name("key") or child
        value = child.child_by_field_name("value") or key
        if key.type not in {"identifier", "property_identifier", "string"} or value.type not in {
            "identifier",
            "property_identifier",
            "string",
        }:
            continue
        key_text = _text(source, key).strip("'\"")
        local = _text(source, value).strip("'\"")
        aliases[local] = f"{module}.{key_text}"


def _canonical_expression(node: Node, source: bytes, aliases: dict[str, str]) -> str | None:
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or _compact_text(source, function) != "require":
            return None
        values = arguments.named_children
        if len(values) != 1:
            return None
        module = _string_value(values[0], source)
        return _normalise_module(module) if module is not None else None
    path = _member_path(node, source, aliases)
    if path is not None:
        return _canonical_name(".".join(path), aliases)
    return _canonical_name(_compact_text(source, node), aliases)


def _canonical_member_path(
    node: Node, source: bytes, aliases: dict[str, str]
) -> tuple[str, ...] | None:
    path = _member_path(node, source, aliases)
    if path is None:
        return None
    canonical = _canonical_name(".".join(path), aliases)
    return tuple(canonical.split("."))


def _member_path(node: Node, source: bytes, aliases: dict[str, str]) -> tuple[str, ...] | None:
    if node.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "this",
        "super",
    }:
        value = _text(source, node)
        return (value,) if value and value != "#" else None
    if node.type in {"member_expression", "subscript_expression"}:
        object_node = node.child_by_field_name("object")
        property_node = node.child_by_field_name("property")
        if property_node is None:
            property_node = node.child_by_field_name("index")
        if object_node is None or property_node is None:
            return None
        base = _canonical_expression(object_node, source, aliases)
        property_name = _static_property_name(property_node, source)
        if base is None or property_name is None:
            return None
        return (*base.split("."), property_name)
    return None


def _canonical_name(value: str, aliases: dict[str, str]) -> str:
    parts = value.split(".")
    if not parts or not _IDENTIFIER.fullmatch(parts[0]):
        return value
    base = aliases.get(parts[0], parts[0])
    if len(parts) == 1:
        return base
    return ".".join((base, *parts[1:]))


def _static_property_name(node: Node, source: bytes) -> str | None:
    if node.type == "computed_property_name":
        values = list(node.named_children)
        return _static_property_name(values[0], source) if len(values) == 1 else None
    if node.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        return _text(source, node)
    if node.type in {"string", "string_fragment"}:
        return _string_value(node, source)
    return None


def _normalise_module(value: str) -> str:
    return value[5:] if value.startswith("node:") else value


def _string_value(node: Node, source: bytes) -> str | None:
    if node.type not in {"string", "string_fragment"}:
        return None
    value = source[node.start_byte : node.end_byte]
    if node.type == "string":
        if len(value) < 2 or value[:1] not in {b"'", b'"', b"`"} or value[-1:] != value[:1]:
            return None
        value = value[1:-1]
    if b"\\" in value or b"\n" in value or b"\r" in value:
        return None
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.INTEGRITY_FAILURE) from None


def _text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe601ScanError(EcmaScriptCwe601ScanErrorCode.INTEGRITY_FAILURE) from None


def _compact_text(source: bytes, node: Node) -> str:
    return "".join(_text(source, node).split())


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
    operation: EcmaScriptCwe601Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-601",
        "detector": _DETECTOR,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
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
    language: str,
    signals: tuple[EcmaScriptCwe601Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-601",
        "detector": _DETECTOR,
        "language": language,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
                "operation": signal.operation.value,
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


# Discoverable names for language-neutral callers.
scan_javascript_open_redirect = scan_javascript_cwe601
scan_typescript_open_redirect = scan_typescript_cwe601
scan_ecmascript_open_redirect = scan_ecmascript_cwe601
scan_javascript_cwe601_open_redirect = scan_javascript_cwe601
scan_typescript_cwe601_open_redirect = scan_typescript_cwe601
scan_ecmascript_cwe601_open_redirect = scan_ecmascript_cwe601


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE601_SCAN_LIMITS",
    "EcmaScriptCwe601Operation",
    "EcmaScriptCwe601ScanError",
    "EcmaScriptCwe601ScanErrorCode",
    "EcmaScriptCwe601ScanLimits",
    "EcmaScriptCwe601ScanResult",
    "EcmaScriptCwe601Signal",
    "scan_ecmascript_cwe601",
    "scan_ecmascript_cwe601_open_redirect",
    "scan_ecmascript_open_redirect",
    "scan_javascript_cwe601",
    "scan_javascript_cwe601_open_redirect",
    "scan_javascript_open_redirect",
    "scan_typescript_cwe601",
    "scan_typescript_cwe601_open_redirect",
    "scan_typescript_open_redirect",
]
