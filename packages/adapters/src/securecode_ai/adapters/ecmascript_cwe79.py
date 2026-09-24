"""Bounded JavaScript and TypeScript cross-site-scripting facts.

The scanner operates on an admitted, sealed :class:`SymbolIndex`.  It rebuilds
the index and reparses the exact admitted bytes before inspecting a small CST
allow-list.  Results contain only source ranges and content-addressed
metadata.  Unknown syntax, malformed indexes, and resource exhaustion fail
closed with a source-free error.
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
_RULE_ID = "securecode-ecmascript-cwe79"
_DETECTOR = "securecode-ecmascript-cwe79@1.0"

_REQUEST_ROOTS = frozenset(
    {"ctx", "context", "event", "httpRequest", "message", "req", "request", "http"}
)
_REQUEST_FIELDS = frozenset(
    {
        "body",
        "cookies",
        "data",
        "headers",
        "params",
        "path",
        "pathParameters",
        "query",
        "queryStringParameters",
    }
)
_LOCATION_ROOTS = frozenset({"location", "window.location", "document.location"})
_LOCATION_FIELDS = frozenset({"hash", "href", "search"})
_ENV_ROOTS = frozenset({"env", "environment", "process.env"})
_PRESERVING_FUNCTIONS = frozenset(
    {
        "Boolean",
        "Buffer.from",
        "decodeURI",
        "decodeURIComponent",
        "encodeURI",
        "encodeURIComponent",
        "JSON.stringify",
        "Number",
        "String",
        "String.raw",
        "URL",
        "URLSearchParams",
    }
)
_PRESERVING_METHODS = frozenset({"replace", "replaceAll", "toString", "trim", "valueOf"})
_SANITIZERS = frozenset(
    {
        "DOMPurify.sanitize",
        "escapeHtml",
        "escapeHTML",
        "escape_html",
        "he.encode",
        "htmlEscape",
        "htmlspecialchars",
        "sanitizeHtml",
        "sanitizeHTML",
        "sanitize-html",
        "xss",
    }
)
_SINK_PROPERTIES = frozenset({"innerHTML", "outerHTML"})
_NESTED_FUNCTIONS = frozenset(
    {
        "arrow_function",
        "function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)


class EcmaScriptCwe79ScanErrorCode(StrEnum):
    """Closed, source-free reasons a scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe79ScanError(RuntimeError):
    """Fixed scanner failure that never echoes repository text."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe79ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe79ScanErrorCode:
            raise TypeError("ECMAScript CWE-79 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-79 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class EcmaScriptCwe79Operation(StrEnum):
    """Recognized DOM and framework HTML sinks."""

    INNER_HTML = "innerHTML"
    OUTER_HTML = "outerHTML"
    INSERT_ADJACENT_HTML = "insertAdjacentHTML"
    DOCUMENT_WRITE = "document.write"
    DOCUMENT_WRITELN = "document.writeln"
    REACT_DANGEROUSLY_SET_INNER_HTML = "dangerouslySetInnerHTML"
    VUE_V_HTML = "v-html"
    ANGULAR_BYPASS_SECURITY_TRUST_HTML = "bypassSecurityTrustHtml"
    LIT_UNSAFE_HTML = "unsafeHTML"

    # Descriptive aliases for language-neutral consumers.
    DOM_INNER_HTML = "innerHTML"
    DOM_OUTER_HTML = "outerHTML"
    DOM_INSERT_ADJACENT_HTML = "insertAdjacentHTML"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe79ScanLimits:
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
            raise ValueError("ECMAScript CWE-79 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE79_SCAN_LIMITS = EcmaScriptCwe79ScanLimits()


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe79Signal:
    """One immutable external-input-to-HTML-sink fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe79Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-79"
    detector: str = _DETECTOR
    detail: str = "untrusted_input_to_html_sink"

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
        expected = (
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
            if valid_identity and valid_ranges and type(self.operation) is EcmaScriptCwe79Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not EcmaScriptCwe79Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-79"
            or self.detector != _DETECTOR
            or self.detail != "untrusted_input_to_html_sink"
        ):
            raise ValueError("ECMAScript CWE-79 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete sink location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe79ScanResult:
    """Deterministic, source-free result for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe79Signal, ...]
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
            and self.language in {"javascript", "typescript"}
        )
        if valid_identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid_identity = False
        valid_signals = type(self.signals) is tuple and all(
            type(item) is EcmaScriptCwe79Signal for item in self.signals
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
        same_identity = valid_signals and all(
            item.repository_id == self.repository_id
            and item.revision == self.revision
            and item.path == self.path
            and item.content_sha256 == self.content_sha256
            and item.source_size_bytes == self.source_size_bytes
            for item in self.signals
        )
        if (
            not valid_identity
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
                self.language,
                self.signals,
            )
        ):
            raise ValueError("ECMAScript CWE-79 scan result is invalid")


def scan_javascript_cwe79(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe79ScanLimits = DEFAULT_ECMASCRIPT_CWE79_SCAN_LIMITS,
) -> EcmaScriptCwe79ScanResult:
    """Find bounded JavaScript request-to-HTML sink facts."""

    return _scan_ecmascript_cwe79(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe79(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe79ScanLimits = DEFAULT_ECMASCRIPT_CWE79_SCAN_LIMITS,
) -> EcmaScriptCwe79ScanResult:
    """Find bounded TypeScript request-to-HTML sink facts."""

    return _scan_ecmascript_cwe79(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe79(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe79ScanLimits = DEFAULT_ECMASCRIPT_CWE79_SCAN_LIMITS,
) -> EcmaScriptCwe79ScanResult:
    """Dispatch a CWE-79 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe79ScanError(EcmaScriptCwe79ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe79(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe79(symbol_index, limits=limits)
    raise EcmaScriptCwe79ScanError(EcmaScriptCwe79ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe79(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe79ScanLimits,
) -> EcmaScriptCwe79ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe79ScanLimits:
        raise EcmaScriptCwe79ScanError(EcmaScriptCwe79ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe79ScanError(EcmaScriptCwe79ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe79ScanError(EcmaScriptCwe79ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe79ScanError(EcmaScriptCwe79ScanErrorCode.ANALYSIS_UNAVAILABLE)

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
        raise EcmaScriptCwe79ScanError(EcmaScriptCwe79ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe79ScanError(EcmaScriptCwe79ScanErrorCode.INTEGRITY_FAILURE) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe79ScanError(EcmaScriptCwe79ScanErrorCode.ANALYSIS_UNAVAILABLE)
        aliases = _collect_aliases(nodes, source)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe79Operation]] = set()
        for node in nodes:
            facts = _node_facts(node, root, source, aliases, limits)
            for source_node, sink_node, operation in facts:
                source_range = _range(source_node)
                sink_range = _range(sink_node)
                if not sink_range.contains(source_range):
                    raise EcmaScriptCwe79ScanError(
                        EcmaScriptCwe79ScanErrorCode.INTEGRITY_FAILURE
                    )
                raw.add((source_range, sink_range, operation))
                if len(raw) > limits.max_signals:
                    raise EcmaScriptCwe79ScanError(EcmaScriptCwe79ScanErrorCode.SIGNAL_LIMIT)
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
    except EcmaScriptCwe79ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe79ScanError(EcmaScriptCwe79ScanErrorCode.INTEGRITY_FAILURE) from None

    signals = tuple(
        EcmaScriptCwe79Signal(
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
    return EcmaScriptCwe79ScanResult(
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


def _node_facts(
    node: Node,
    root: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe79ScanLimits,
) -> tuple[tuple[Node, Node, EcmaScriptCwe79Operation], ...]:
    scope = _enclosing_scope(node, root)
    if node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return ()
        operation = _assignment_operation(left, source, aliases)
        if operation is None:
            return ()
        return tuple(
            (candidate, node, operation)
            for candidate in _resolve_source(
                right,
                scope=scope,
                source=source,
                aliases=aliases,
                limits=limits,
                depth=0,
                visited=frozenset(),
            )
        )
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            return ()
        operation = _call_operation(function, source, aliases)
        if operation is None:
            return ()
        values = list(arguments.named_children)
        positions = (1,) if operation is EcmaScriptCwe79Operation.INSERT_ADJACENT_HTML else (0,)
        if operation in {
            EcmaScriptCwe79Operation.DOCUMENT_WRITE,
            EcmaScriptCwe79Operation.DOCUMENT_WRITELN,
        }:
            positions = tuple(range(len(values)))
        return tuple(
            (candidate, node, operation)
            for index in positions
            if index < len(values)
            for candidate in _resolve_source(
                values[index],
                scope=scope,
                source=source,
                aliases=aliases,
                limits=limits,
                depth=0,
                visited=frozenset(),
            )
        )
    if node.type == "pair":
        key = node.child_by_field_name("key")
        value = node.child_by_field_name("value")
        if key is None or value is None or _static_property_name(key, source) != "__html":
            return ()
        if not _has_framework_ancestor(node, source, aliases):
            return ()
        return tuple(
            (candidate, node, EcmaScriptCwe79Operation.REACT_DANGEROUSLY_SET_INNER_HTML)
            for candidate in _resolve_source(
                value,
                scope=scope,
                source=source,
                aliases=aliases,
                limits=limits,
                depth=0,
                visited=frozenset(),
            )
        )
    if node.type == "jsx_attribute" and _compact_text(source, node).startswith("v-html"):
        values = list(node.named_children)
        value = values[-1] if values else None
        if value is None:
            return ()
        if value.type == "jsx_expression":
            children = value.named_children
            value = children[-1] if children else None
        if value is None:
            return ()
        return tuple(
            (candidate, node, EcmaScriptCwe79Operation.VUE_V_HTML)
            for candidate in _resolve_source(
                value,
                scope=scope,
                source=source,
                aliases=aliases,
                limits=limits,
                depth=0,
                visited=frozenset(),
            )
        )
    return ()


def _assignment_operation(
    left: Node, source: bytes, aliases: dict[str, str]
) -> EcmaScriptCwe79Operation | None:
    if left.type not in {"member_expression", "subscript_expression"}:
        return None
    property_node = left.child_by_field_name("property") or left.child_by_field_name("index")
    name = _static_property_name(property_node, source) if property_node is not None else None
    return {
        "innerHTML": EcmaScriptCwe79Operation.INNER_HTML,
        "outerHTML": EcmaScriptCwe79Operation.OUTER_HTML,
    }.get(name)


def _call_operation(
    function: Node, source: bytes, aliases: dict[str, str]
) -> EcmaScriptCwe79Operation | None:
    canonical = _canonical_expression(function, source, aliases)
    if canonical is None:
        return None
    if canonical.endswith(".insertAdjacentHTML") or canonical == "insertAdjacentHTML":
        return EcmaScriptCwe79Operation.INSERT_ADJACENT_HTML
    if canonical in {"document.write", "window.document.write"}:
        return EcmaScriptCwe79Operation.DOCUMENT_WRITE
    if canonical in {"document.writeln", "window.document.writeln"}:
        return EcmaScriptCwe79Operation.DOCUMENT_WRITELN
    if canonical.endswith(".bypassSecurityTrustHtml"):
        return EcmaScriptCwe79Operation.ANGULAR_BYPASS_SECURITY_TRUST_HTML
    if canonical in {"unsafeHTML", "lit.html.unsafeHTML", "lit.unsafeHTML"}:
        return EcmaScriptCwe79Operation.LIT_UNSAFE_HTML
    return None


def _resolve_source(
    node: Node,
    *,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe79ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[Node, ...]:
    if depth > limits.max_depth:
        raise EcmaScriptCwe79ScanError(EcmaScriptCwe79ScanErrorCode.DEPTH_LIMIT)
    if _is_sanitizer_expression(node, source, aliases):
        return ()
    if _is_external_source(node, source):
        return (node,)
    if node.type == "identifier":
        name = _node_text(source, node)
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
        "type_assertion",
    }:
        return _resolve_children(node, scope, source, aliases, limits, depth + 1, visited)
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            return ()
        canonical = _canonical_expression(function, source, aliases)
        if canonical in _PRESERVING_FUNCTIONS or (
            canonical is not None and canonical.rsplit(".", 1)[-1] in _PRESERVING_METHODS
        ):
            return _resolve_children(node, scope, source, aliases, limits, depth + 1, visited)
        return ()
    if node.type in {
        "binary_expression",
        "conditional_expression",
        "ternary_expression",
        "assignment_expression",
        "logical_expression",
        "template_substitution",
        "template_string",
        "sequence_expression",
        "object",
        "array",
        "pair",
        "arguments",
        "member_expression",
        "subscript_expression",
        "spread_element",
    }:
        return _resolve_children(node, scope, source, aliases, limits, depth + 1, visited)
    return ()


def _resolve_children(
    node: Node,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe79ScanLimits,
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


def _is_external_source(node: Node, source: bytes) -> bool:
    compact = _compact_text(source, node).replace("?.", ".").replace("[", ".[", 1)
    if node.type in {"member_expression", "subscript_expression"}:
        return _member_source(compact)
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    if function is None:
        return False
    return _call_source(_compact_text(source, function))


def _member_source(value: str) -> bool:
    pieces = value.split(".")
    if len(pieces) < 2:
        return False
    if pieces[0] == "process" and len(pieces) >= 3 and pieces[1] == "env":
        return bool(pieces[2])
    if pieces[0] in _ENV_ROOTS:
        return len(pieces) > 1 and any(pieces[1:])
    if pieces[0] in _LOCATION_ROOTS and pieces[1] in _LOCATION_FIELDS:
        return True
    if pieces[0] in {"window", "document"} and len(pieces) >= 3:
        if pieces[0] == "window" and pieces[1] == "location":
            return pieces[2] in _LOCATION_FIELDS
        if pieces[0] == "document" and pieces[1] == "location":
            return pieces[2] in _LOCATION_FIELDS
    if pieces[0] not in _REQUEST_ROOTS:
        return False
    return pieces[1] in _REQUEST_FIELDS


def _call_source(callee: str) -> bool:
    compact = callee.replace("?.", ".").replace("[", ".[", 1)
    pieces = compact.split(".")
    if not pieces:
        return False
    if pieces[-1] in {"get", "param", "query", "input", "body", "header"}:
        return len(pieces) >= 2 and (
            any(part in _REQUEST_FIELDS for part in pieces)
            or any(part in {"searchParams", "URLSearchParams", "querystring"} for part in pieces)
        )
    return pieces[-1] in {"getQuery", "getParam", "getInput", "getHeader"}


def _is_sanitizer_expression(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    if node.type not in {"call_expression", "new_expression"}:
        return False
    function = node.child_by_field_name("function") or node.child_by_field_name("constructor")
    if function is None:
        return False
    canonical = _canonical_expression(function, source, aliases)
    return canonical in _SANITIZERS or (
        canonical is not None and canonical.rsplit(".", 1)[-1] in _SANITIZERS
    )


def _has_framework_ancestor(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    current = node.parent
    while current is not None:
        if current.type == "call_expression":
            function = current.child_by_field_name("function")
            canonical = (
                _canonical_expression(function, source, aliases) if function is not None else None
            )
            if canonical is not None and canonical.rsplit(".", 1)[-1] in {
                "createElement",
                "jsx",
                "jsxs",
            }:
                return True
        if current.type in _NESTED_FUNCTIONS:
            return False
        current = current.parent
    return False


def _enclosing_scope(node: Node, root: Node) -> Node:
    current = node.parent
    while current is not None:
        if current.type in _NESTED_FUNCTIONS:
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
        if left is not None and right is not None and left.type == "identifier":
            if _node_text(source, left) == name:
                bound = right
    return bound


def _scope_preorder(scope: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    first = True
    while stack:
        node = stack.pop()
        output.append(node)
        if not first and node.type in _NESTED_FUNCTIONS:
            continue
        first = False
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _collect_aliases(nodes: tuple[Node, ...], source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in nodes:
        if node.type not in {"variable_declarator", "assignment_expression"}:
            continue
        if node.type == "variable_declarator":
            left = node.child_by_field_name("name")
            right = node.child_by_field_name("value")
        else:
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
        if left is None or right is None or left.type != "identifier":
            continue
        canonical = _canonical_expression(right, source, aliases)
        if canonical is not None:
            aliases[_node_text(source, left)] = canonical
    return aliases


def _canonical_expression(node: Node, source: bytes, aliases: dict[str, str]) -> str | None:
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or _compact_text(source, function) != "require":
            return None
        values = list(arguments.named_children)
        if len(values) != 1:
            return None
        return _string_value(values[0], source)
    if node.type in {"member_expression", "subscript_expression"}:
        object_node = node.child_by_field_name("object")
        property_node = node.child_by_field_name("property") or node.child_by_field_name("index")
        if object_node is None or property_node is None:
            return None
        base = _canonical_expression(object_node, source, aliases)
        if base is None:
            base = _canonical_name(_compact_text(source, object_node), aliases)
        name = _static_property_name(property_node, source)
        return f"{base}.{name}" if base and name else None
    return _canonical_name(_compact_text(source, node), aliases)


def _canonical_name(value: str, aliases: dict[str, str]) -> str:
    parts = value.split(".")
    if not parts or not _IDENTIFIER.fullmatch(parts[0]):
        return value
    base = aliases.get(parts[0], parts[0])
    return ".".join((base, *parts[1:])) if len(parts) > 1 else base


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
        return _node_text(source, node)
    if node.type in {"string", "string_fragment"}:
        return _string_value(node, source)
    return None


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
        raise EcmaScriptCwe79ScanError(EcmaScriptCwe79ScanErrorCode.INTEGRITY_FAILURE) from None


def _node_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe79ScanError(EcmaScriptCwe79ScanErrorCode.INTEGRITY_FAILURE) from None


def _compact_text(source: bytes, node: Node | None) -> str:
    return "" if node is None else "".join(_node_text(source, node).split())


def _bounded_nodes(root: Node, limits: EcmaScriptCwe79ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe79ScanError(EcmaScriptCwe79ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe79ScanError(EcmaScriptCwe79ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


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
    operation: EcmaScriptCwe79Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-79",
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
    language: str,
    signals: tuple[EcmaScriptCwe79Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-79",
        "detector": _DETECTOR,
        "language": language,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
                "detail": signal.detail,
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


# Discoverable aliases for language-neutral callers.
scan_javascript_xss = scan_javascript_cwe79
scan_typescript_xss = scan_typescript_cwe79
scan_ecmascript_xss = scan_ecmascript_cwe79


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE79_SCAN_LIMITS",
    "EcmaScriptCwe79Operation",
    "EcmaScriptCwe79ScanError",
    "EcmaScriptCwe79ScanErrorCode",
    "EcmaScriptCwe79ScanLimits",
    "EcmaScriptCwe79ScanResult",
    "EcmaScriptCwe79Signal",
    "scan_ecmascript_cwe79",
    "scan_ecmascript_xss",
    "scan_javascript_cwe79",
    "scan_javascript_xss",
    "scan_typescript_cwe79",
    "scan_typescript_xss",
]
