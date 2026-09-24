"""Bounded ECMAScript CWE-117 log-injection facts.

The scanner consumes a sealed :class:`~securecode_ai.core.SymbolIndex`,
rebuilds that index from the admitted bytes, and then inspects a bounded
tree-sitter CST.  It recognizes request-derived values reaching console,
Winston, Pino, and conventional logger message arguments without a known
CR/LF sanitizer.  Object arguments used as structured logging fields are
treated as serialized fields and are not reported as interpolated messages.

Results contain only immutable ranges and content-addressed metadata.  Source
text is used transiently while scanning and is never retained in a signal or
an error.  Unknown syntax and resource exhaustion fail closed.
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

_MAX_LIMITS = (2_000_000, 250_000, 512, 50_000, 10_000)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_RULE_ID = "securecode-ecmascript-cwe117"
_DETECTOR = "securecode-ecmascript-cwe117@1.0"

_REQUEST_ROOTS = frozenset(
    {
        "ctx",
        "context",
        "event",
        "httpRequest",
        "message",
        "req",
        "request",
    }
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
_LOGGER_METHODS = frozenset(
    {"debug", "error", "fatal", "info", "log", "trace", "warn", "warning"}
)
_LOGGER_ROOTS = frozenset(
    {
        "console",
        "log",
        "logger",
        "logging",
        "pino",
        "pinoLogger",
        "winston",
    }
)
_CRLF_SANITIZER_NAMES = frozenset(
    {
        "escapecrlf",
        "escapeloggingspecials",
        "escapelogvalue",
        "logsafe",
        "normalizelog",
        "removecarriagereturns",
        "removecrlf",
        "removenewlines",
        "sanitizeforlog",
        "sanitizeforlogging",
        "sanitizelog",
        "stripcrlf",
        "stripnewlines",
    }
)
_SAFE_MESSAGE_BUILDERS = frozenset(
    {
        "encodeURIComponent",
        "encodeURI",
        "JSON.stringify",
        "escape",
        "querystring.escape",
    }
)
_MESSAGE_BUILDERS = frozenset({"util.format", "format", "sprintf"})
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


class EcmaScriptCwe117ScanErrorCode(StrEnum):
    """Closed, source-free reasons a scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    ALIAS_LIMIT = "ALIAS_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe117ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe117ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe117ScanErrorCode:
            raise TypeError("ECMAScript CWE-117 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-117 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class EcmaScriptCwe117Operation(StrEnum):
    """Message sink categories that can preserve untrusted CR/LF bytes."""

    UNSAFE_DIRECT_MESSAGE = "unsafe_direct_message"
    UNSAFE_INTERPOLATED_MESSAGE = "unsafe_interpolated_message"
    CONSOLE_MESSAGE = "unsafe_direct_message"
    LOGGER_MESSAGE = "unsafe_interpolated_message"
    WINSTON_MESSAGE = "unsafe_interpolated_message"
    PINO_MESSAGE = "unsafe_interpolated_message"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe117ScanLimits:
    """Hard ceilings applied before and during structural analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_nodes: int = _MAX_LIMITS[1]
    max_depth: int = _MAX_LIMITS[2]
    max_aliases: int = _MAX_LIMITS[3]
    max_signals: int = _MAX_LIMITS[4]

    def __post_init__(self) -> None:
        values = (
            self.max_source_bytes,
            self.max_nodes,
            self.max_depth,
            self.max_aliases,
            self.max_signals,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("ECMAScript CWE-117 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE117_SCAN_LIMITS = EcmaScriptCwe117ScanLimits()


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe117Signal:
    """One immutable request-to-log message fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe117Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-117"
    detector: str = _DETECTOR
    detail: str = "request_derived_unsanitized_crlf"

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
            if valid_identity
            and valid_ranges
            and type(self.operation) is EcmaScriptCwe117Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not EcmaScriptCwe117Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-117"
            or self.detector != _DETECTOR
            or self.detail != "request_derived_unsanitized_crlf"
        ):
            raise ValueError("ECMAScript CWE-117 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete logging call location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe117ScanResult:
    """Deterministic, source-free result for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe117Signal, ...]
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
            type(item) is EcmaScriptCwe117Signal for item in self.signals
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
            raise ValueError("ECMAScript CWE-117 scan result is invalid")


def scan_javascript_cwe117(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe117ScanLimits = DEFAULT_ECMASCRIPT_CWE117_SCAN_LIMITS,
) -> EcmaScriptCwe117ScanResult:
    """Find bounded JavaScript request-to-log injection facts."""

    return _scan_ecmascript_cwe117(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe117(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe117ScanLimits = DEFAULT_ECMASCRIPT_CWE117_SCAN_LIMITS,
) -> EcmaScriptCwe117ScanResult:
    """Find bounded TypeScript request-to-log injection facts."""

    return _scan_ecmascript_cwe117(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe117(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe117ScanLimits = DEFAULT_ECMASCRIPT_CWE117_SCAN_LIMITS,
) -> EcmaScriptCwe117ScanResult:
    """Dispatch a CWE-117 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe117ScanError(EcmaScriptCwe117ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe117(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe117(symbol_index, limits=limits)
    raise EcmaScriptCwe117ScanError(EcmaScriptCwe117ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe117(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe117ScanLimits,
) -> EcmaScriptCwe117ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe117ScanLimits:
        raise EcmaScriptCwe117ScanError(EcmaScriptCwe117ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe117ScanError(EcmaScriptCwe117ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe117ScanError(EcmaScriptCwe117ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe117ScanError(EcmaScriptCwe117ScanErrorCode.ANALYSIS_UNAVAILABLE)

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
        raise EcmaScriptCwe117ScanError(
            EcmaScriptCwe117ScanErrorCode.INTEGRITY_FAILURE
        ) from None
    except Exception:
        raise EcmaScriptCwe117ScanError(
            EcmaScriptCwe117ScanErrorCode.INTEGRITY_FAILURE
        ) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe117ScanError(
                EcmaScriptCwe117ScanErrorCode.ANALYSIS_UNAVAILABLE
            )
        aliases = _collect_aliases(nodes, source, limits)
        logger_names = _collect_logger_names(nodes, source, aliases, limits)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe117Operation]] = set()
        for node in nodes:
            if node.type != "call_expression":
                continue
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if function is None or arguments is None:
                continue
            operation = _logging_operation(function, source, aliases, logger_names)
            if operation is None:
                continue
            values = list(arguments.named_children)
            for message in _message_arguments(values, function, source, operation):
                scope = _enclosing_scope(node, root)
                sources = _resolve_message_sources(
                    message,
                    scope=scope,
                    source=source,
                    aliases=aliases,
                    limits=limits,
                    depth=0,
                    visited=frozenset(),
                )
                sink_range = _range(node)
                for source_node in sources:
                    source_range = _range(source_node)
                    if not sink_range.contains(source_range):
                        raise EcmaScriptCwe117ScanError(
                            EcmaScriptCwe117ScanErrorCode.INTEGRITY_FAILURE
                        )
                    raw.add((source_range, sink_range, operation))
                    if len(raw) > limits.max_signals:
                        raise EcmaScriptCwe117ScanError(
                            EcmaScriptCwe117ScanErrorCode.SIGNAL_LIMIT
                        )
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
    except EcmaScriptCwe117ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe117ScanError(
            EcmaScriptCwe117ScanErrorCode.INTEGRITY_FAILURE
        ) from None

    signals = tuple(
        EcmaScriptCwe117Signal(
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
    return EcmaScriptCwe117ScanResult(
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


def _message_arguments(
    values: list[Node],
    function: Node,
    source: bytes,
    operation: EcmaScriptCwe117Operation,
) -> tuple[Node, ...]:
    """Select message positions while excluding structured logging fields."""

    if not values:
        return ()
    function_text = _compact_text(source, function)
    if operation is EcmaScriptCwe117Operation.UNSAFE_DIRECT_MESSAGE:
        return tuple(value for value in values if value.type not in {"object", "array"})
    if values[0].type == "object":
        return tuple(value for value in values[1:] if value.type not in {"object", "array"})
    if function_text.endswith(".log") and _looks_like_level_literal(values[0], source):
        return tuple(value for value in values[1:] if value.type not in {"object", "array"})
    return tuple(value for value in values if value.type not in {"object", "array"})


def _looks_like_level_literal(node: Node, source: bytes) -> bool:
    value = _string_value(node, source)
    return value in {"debug", "error", "fatal", "info", "trace", "warn", "warning"}


def _logging_operation(
    function: Node,
    source: bytes,
    aliases: dict[str, str],
    logger_names: set[str],
) -> EcmaScriptCwe117Operation | None:
    canonical = _canonical_expression(function, source, aliases)
    text = canonical or _compact_text(source, function)
    if function.type == "identifier" and text in logger_names:
        return EcmaScriptCwe117Operation.UNSAFE_DIRECT_MESSAGE
    method = text.rsplit(".", 1)[-1] if "." in text else text
    if method not in _LOGGER_METHODS:
        return None
    root = text.split(".", 1)[0]
    if root == "console":
        return EcmaScriptCwe117Operation.UNSAFE_DIRECT_MESSAGE
    if _is_logger_receiver(text, root, logger_names):
        return EcmaScriptCwe117Operation.UNSAFE_INTERPOLATED_MESSAGE
    if text.startswith("pino(") or text.startswith("winston("):
        return EcmaScriptCwe117Operation.UNSAFE_INTERPOLATED_MESSAGE
    return None


def _is_logger_receiver(text: str, root: str, logger_names: set[str]) -> bool:
    if root in _LOGGER_ROOTS or root in logger_names:
        return True
    if "." in text:
        receiver = text.rsplit(".", 1)[0]
        return receiver in logger_names or receiver.rsplit(".", 1)[-1] in _LOGGER_ROOTS
    return False


def _resolve_message_sources(
    node: Node,
    *,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe117ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[Node, ...]:
    if depth > limits.max_depth:
        raise EcmaScriptCwe117ScanError(EcmaScriptCwe117ScanErrorCode.DEPTH_LIMIT)
    if _is_crlf_sanitizer(node, source, aliases):
        return ()
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        canonical = (
            _canonical_expression(function, source, aliases) if function is not None else None
        )
        if canonical in _SAFE_MESSAGE_BUILDERS:
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
        return _resolve_message_sources(
            bound,
            scope=scope,
            source=source,
            aliases=aliases,
            limits=limits,
            depth=depth + 1,
            visited=visited | {name},
        )
    if node.type in {"object", "array"}:
        return ()
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        if function is None:
            return ()
        canonical = _canonical_expression(function, source, aliases)
        if canonical not in _MESSAGE_BUILDERS and not _is_safe_method(canonical):
            return ()
        return _resolve_children(node, scope, source, aliases, limits, depth + 1, visited)
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
    if node.type in {
        "binary_expression",
        "conditional_expression",
        "ternary_expression",
        "assignment_expression",
        "logical_expression",
        "template_substitution",
        "template_string",
        "sequence_expression",
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
    limits: EcmaScriptCwe117ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[Node, ...]:
    values: list[Node] = []
    for child in node.named_children:
        values.extend(
            _resolve_message_sources(
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


def _is_safe_method(canonical: str | None) -> bool:
    if canonical is None:
        return False
    return canonical.rsplit(".", 1)[-1] in {
        "encodeURIComponent",
        "encodeURI",
        "replace",
        "replaceAll",
    }


def _is_crlf_sanitizer(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None:
        return False
    canonical = _canonical_expression(function, source, aliases)
    name = (canonical or _compact_text(source, function)).rsplit(".", 1)[-1]
    if name.lower() in _CRLF_SANITIZER_NAMES:
        return True
    if name not in {"replace", "replaceAll"}:
        return False
    values = list(arguments.named_children)
    if not values:
        return False
    pattern = _compact_text(source, values[0]).lower()
    return "\\r" in pattern or "\\n" in pattern or "crlf" in pattern or "newline" in pattern


def _is_external_source(node: Node, source: bytes) -> bool:
    compact = _compact_text(source, node).replace("?.", ".")
    if node.type in {"member_expression", "subscript_expression"}:
        return _member_source(compact)
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    if function is None:
        return False
    return _call_source(_compact_text(source, function))


def _member_source(value: str) -> bool:
    pieces = value.replace("[", ".[", 1).split(".")
    if len(pieces) < 2 or pieces[0] not in _REQUEST_ROOTS:
        return False
    return pieces[1] in _REQUEST_FIELDS


def _call_source(callee: str) -> bool:
    pieces = callee.replace("?.", ".").replace("[", ".[", 1).split(".")
    if not pieces:
        return False
    if pieces[-1] in {
        "body",
        "get",
        "getHeader",
        "getInput",
        "getParam",
        "getQuery",
        "header",
        "input",
        "param",
        "query",
    }:
        return len(pieces) >= 2 and (
            any(part in _REQUEST_FIELDS for part in pieces)
            or pieces[0] in _REQUEST_ROOTS
        )
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


def _collect_aliases(
    nodes: tuple[Node, ...], source: bytes, limits: EcmaScriptCwe117ScanLimits
) -> dict[str, str]:
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
            if len(aliases) > limits.max_aliases:
                raise EcmaScriptCwe117ScanError(EcmaScriptCwe117ScanErrorCode.ALIAS_LIMIT)
    return aliases


def _collect_logger_names(
    nodes: tuple[Node, ...],
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe117ScanLimits,
) -> set[str]:
    names = set(_LOGGER_ROOTS)
    for node in nodes:
        if node.type not in {"variable_declarator", "assignment_expression"}:
            continue
        left = (
            node.child_by_field_name("name")
            if node.type == "variable_declarator"
            else node.child_by_field_name("left")
        )
        right = (
            node.child_by_field_name("value")
            if node.type == "variable_declarator"
            else node.child_by_field_name("right")
        )
        if left is None or right is None or left.type != "identifier":
            continue
        canonical = _canonical_expression(right, source, aliases) or _compact_text(source, right)
        if _looks_like_logger_value(canonical, names):
            names.add(_node_text(source, left))
            if len(names) > limits.max_aliases:
                raise EcmaScriptCwe117ScanError(EcmaScriptCwe117ScanErrorCode.ALIAS_LIMIT)
    return names


def _looks_like_logger_value(value: str, logger_names: set[str]) -> bool:
    compact = value.replace(" ", "")
    return (
        compact.startswith("pino(")
        or compact.startswith("winston.createLogger(")
        or compact.startswith("createLogger(")
        or ".child(" in compact
        or any(compact.startswith(f"{name}.") for name in logger_names)
    )


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
        raise EcmaScriptCwe117ScanError(EcmaScriptCwe117ScanErrorCode.INTEGRITY_FAILURE) from None


def _node_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe117ScanError(EcmaScriptCwe117ScanErrorCode.INTEGRITY_FAILURE) from None


def _compact_text(source: bytes, node: Node | None) -> str:
    return "" if node is None else "".join(_node_text(source, node).split())


def _bounded_nodes(root: Node, limits: EcmaScriptCwe117ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe117ScanError(EcmaScriptCwe117ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe117ScanError(EcmaScriptCwe117ScanErrorCode.NODE_LIMIT)
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
    operation: EcmaScriptCwe117Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-117",
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
    signals: tuple[EcmaScriptCwe117Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-117",
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


scan_javascript_log_injection = scan_javascript_cwe117
scan_typescript_log_injection = scan_typescript_cwe117
scan_ecmascript_log_injection = scan_ecmascript_cwe117


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE117_SCAN_LIMITS",
    "EcmaScriptCwe117Operation",
    "EcmaScriptCwe117ScanError",
    "EcmaScriptCwe117ScanErrorCode",
    "EcmaScriptCwe117ScanLimits",
    "EcmaScriptCwe117ScanResult",
    "EcmaScriptCwe117Signal",
    "scan_ecmascript_cwe117",
    "scan_ecmascript_log_injection",
    "scan_javascript_cwe117",
    "scan_javascript_log_injection",
    "scan_typescript_cwe117",
    "scan_typescript_log_injection",
]
