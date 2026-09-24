"""Bounded Go facts for CWE-209 sensitive data in error messages.

The detector deliberately works on a small, local data-flow projection.  It
recognises values obtained from request or credential-like sources and follows
them through assignments and formatting helpers into standard error sinks.  A
fixed error string, a value that has crossed a recognised redaction or hashing
boundary, and an unresolved helper call are left alone.  Source bytes are
used only while parsing and are never retained in a result or an exception.
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
_RULE_ID = "securecode-go-cwe209"
_DETECTOR = "securecode-go-cwe209@1.0"
_DETAIL = "sensitive_value_in_error_message"
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})

_FMT_PACKAGE = "fmt"
_ERRORS_PACKAGE = "errors"
_HTTP_PACKAGE = "net/http"
_OS_PACKAGE = "os"
_STRING_PACKAGES = frozenset({"fmt", "strings", "path", "path/filepath"})
_REQUEST_METHODS = frozenset(
    {
        "Cookie",
        "FormValue",
        "GetBody",
        "PathValue",
        "PostFormValue",
        "Query",
    }
)
_SENSITIVE_WORDS = frozenset(
    {
        "accesskey",
        "apikey",
        "auth",
        "authorization",
        "bearer",
        "clientsecret",
        "cookie",
        "credential",
        "credentials",
        "jwt",
        "password",
        "passwd",
        "passcode",
        "privatekey",
        "secret",
        "session",
        "sessionid",
        "sessiontoken",
        "token",
    }
)
_SENSITIVE_LITERAL_MARKERS = frozenset(
    {
        "access-key",
        "access_key",
        "api-key",
        "api_key",
        "authorization",
        "bearer",
        "client-secret",
        "client_secret",
        "cookie",
        "credential",
        "jwt",
        "passcode",
        "password",
        "passwd",
        "private-key",
        "private_key",
        "secret",
        "session-token",
        "session_token",
        "token",
        "x-api-key",
        "x-auth-token",
    }
)
_SANITIZER_WORDS = frozenset(
    {
        "base64",
        "encrypt",
        "hash",
        "hmac",
        "mask",
        "obfuscate",
        "redact",
        "sanitize",
        "scrub",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
    }
)


class GoCwe209ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-209 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe209ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe209ScanErrorCode) -> None:
        if type(code) is not GoCwe209ScanErrorCode:
            raise TypeError("Go CWE-209 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-209 error-disclosure scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe209ScanLimits:
    """Hard ceilings applied before and during local flow analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-209 scan limits are invalid")


DEFAULT_GO_CWE209_SCAN_LIMITS = GoCwe209ScanLimits()


class GoCwe209Operation(StrEnum):
    """Recognised error-message sinks."""

    FMT_ERRORF = "fmt.Errorf"
    ERRORS_NEW = "errors.New"
    HTTP_ERROR = "http.Error"
    PANIC = "panic"

    # Compatibility names for generic scanner consumers.
    FORMAT_ERROR = "fmt.Errorf"
    NEW_ERROR = "errors.New"
    ERROR_RESPONSE = "http.Error"


_OPERATION_BY_CALL: dict[tuple[str, str], GoCwe209Operation] = {
    (_FMT_PACKAGE, "Errorf"): GoCwe209Operation.FMT_ERRORF,
    (_ERRORS_PACKAGE, "New"): GoCwe209Operation.ERRORS_NEW,
    (_HTTP_PACKAGE, "Error"): GoCwe209Operation.HTTP_ERROR,
}


@dataclass(frozen=True, slots=True)
class GoCwe209Signal:
    """One immutable source-free sensitive-value-to-error fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe209Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-209"
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
            and 0 <= self.source.start_byte <= self.source.end_byte
            and self.source.end_byte <= self.sink.end_byte
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
            if valid_identity and valid_ranges and type(self.operation) is GoCwe209Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not GoCwe209Operation
            or type(signal_id) is not str
            or expected_id is None
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-209"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-209 signal is invalid")
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
class GoCwe209ScanResult:
    """Deterministic, source-free result for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe209Signal, ...]
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
            type(item) is GoCwe209Signal for item in self.signals
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
            raise ValueError("Go CWE-209 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange


def scan_go_cwe209(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe209ScanLimits = DEFAULT_GO_CWE209_SCAN_LIMITS,
) -> GoCwe209ScanResult:
    """Find sensitive request or credential values in error-message sinks."""

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
        raise GoCwe209ScanError(GoCwe209ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    raw: set[tuple[SourceRange, SourceRange, GoCwe209Operation]] = set()
    try:
        for scope in _scopes(root):
            environment: dict[str, tuple[_Flow, ...]] = {}
            for node in _scope_preorder(scope):
                if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                    _capture_assignment(node, environment, source, imports, limits)
                if node.type != "call_expression":
                    continue
                operation = _operation_for_call(node, source, imports)
                if operation is None:
                    continue
                arguments = node.child_by_field_name("arguments")
                if arguments is None:
                    continue
                values = arguments.named_children
                selected = _sink_arguments(values, operation)
                sink_range = _range(node)
                for value in selected:
                    for flow in _resolve(
                        value, environment, source, imports, limits, 0, frozenset()
                    ):
                        if flow.source.end_byte > sink_range.end_byte:
                            raise GoCwe209ScanError(
                                GoCwe209ScanErrorCode.INTEGRITY_FAILURE
                            )
                        raw.add((flow.source, sink_range, operation))
                        if len(raw) > limits.max_signals:
                            raise GoCwe209ScanError(GoCwe209ScanErrorCode.SIGNAL_LIMIT)
                if operation is GoCwe209Operation.PANIC and not selected:
                    continue
    except GoCwe209ScanError:
        raise
    except Exception:
        raise GoCwe209ScanError(GoCwe209ScanErrorCode.INTEGRITY_FAILURE) from None

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
        raise GoCwe209ScanError(GoCwe209ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe209Signal(
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
    return GoCwe209ScanResult(
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


def scan_go_error_disclosure(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe209ScanLimits = DEFAULT_GO_CWE209_SCAN_LIMITS,
) -> GoCwe209ScanResult:
    """Descriptive alias for :func:`scan_go_cwe209`."""

    return scan_go_cwe209(symbol_index, limits=limits)


def scan_go_sensitive_error_messages(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe209ScanLimits = DEFAULT_GO_CWE209_SCAN_LIMITS,
) -> GoCwe209ScanResult:
    """Compatibility alias for callers grouping error-message scans."""

    return scan_go_cwe209(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe209ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe209ScanLimits:
        raise GoCwe209ScanError(GoCwe209ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe209ScanError(GoCwe209ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe209ScanError(GoCwe209ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe209ScanError(GoCwe209ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    relevant = _STRING_PACKAGES | {_ERRORS_PACKAGE, _HTTP_PACKAGE, _OS_PACKAGE}
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


def _operation_for_call(
    node: Node,
    source: bytes,
    imports: dict[str, str],
) -> GoCwe209Operation | None:
    function = node.child_by_field_name("function")
    if function is None:
        return None
    if function.type == "identifier" and _text(source, function) == "panic":
        return GoCwe209Operation.PANIC
    if function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    return _OPERATION_BY_CALL.get((imports.get(_compact_text(source, operand), ""), _text(source, field)))


def _sink_arguments(
    values: tuple[Node, ...], operation: GoCwe209Operation
) -> tuple[Node, ...]:
    if not values:
        return ()
    if operation is GoCwe209Operation.FMT_ERRORF:
        return values[1:]
    if operation is GoCwe209Operation.HTTP_ERROR:
        return values[1:2]
    return values[:1]


def _capture_assignment(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe209ScanLimits,
) -> None:
    if node.type == "var_spec":
        names_node = node.child_by_field_name("name")
        values_node = node.child_by_field_name("value")
        if names_node is None or values_node is None:
            return
        names = names_node.named_children or (names_node,)
        values = values_node.named_children or (values_node,)
    else:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        names = left.named_children if left.type == "expression_list" else (left,)
        values = right.named_children if right.type == "expression_list" else (right,)
    if len(values) == 1 and len(names) > 1:
        values = values * len(names)
    for name, value in zip(names, values, strict=False):
        if name.type != "identifier":
            continue
        name_text = _text(source, name)
        environment[name_text] = _resolve(
            value, environment, source, imports, limits, 0, frozenset()
        )


def _resolve(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe209ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[_Flow, ...]:
    if depth > limits.max_expression_depth:
        raise GoCwe209ScanError(GoCwe209ScanErrorCode.SIGNAL_LIMIT)
    if _is_sanitizer(node, source, imports):
        return ()
    direct = _external_source(node, source, imports)
    if direct is not None:
        return (_Flow(_range(direct)),)
    if node.type == "identifier":
        name = _text(source, node)
        if name in visited:
            return ()
        values = environment.get(name)
        if values is not None:
            return values
        return (_Flow(_range(node)),) if _is_sensitive_name(name) else ()
    if node.type in {"parenthesized_expression", "unary_expression", "pointer_expression"}:
        return _dedupe_flows(
            (
                flow
                for child in node.named_children
                for flow in _resolve(
                    child,
                    environment,
                    source,
                    imports,
                    limits,
                    depth + 1,
                    visited,
                )
            )
        )
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            return ()
        values = arguments.named_children
        if _is_sanitizer(node, source, imports):
            return ()
        qualified = _qualified_call(function, source, imports)
        if qualified in {
            "fmt.Sprintf",
            "fmt.Sprint",
            "fmt.Sprintln",
            "fmt.Sprint",
            "errors.Join",
            "strings.Join",
            "strings.Builder",
        }:
            args = values[1:] if qualified == "fmt.Sprintf" else values
            return _dedupe_flows(
                (
                    flow
                    for argument in args
                    for flow in _resolve(
                        argument,
                        environment,
                        source,
                        imports,
                        limits,
                        depth + 1,
                        visited,
                    )
                )
            )
        if function is not None and function.type == "selector_expression":
            field = function.child_by_field_name("field")
            operand = function.child_by_field_name("operand")
            if field is not None and operand is not None and _text(source, field) == "Error":
                return _resolve(
                    operand,
                    environment,
                    source,
                    imports,
                    limits,
                    depth + 1,
                    visited | {_compact_text(source, operand)},
                )
        return ()
    if node.type in {
        "binary_expression",
        "composite_literal",
        "index_expression",
        "slice_expression",
        "type_conversion_expression",
    }:
        return _dedupe_flows(
            (
                flow
                for child in node.named_children
                for flow in _resolve(
                    child,
                    environment,
                    source,
                    imports,
                    limits,
                    depth + 1,
                    visited,
                )
            )
        )
    return ()


def _external_source(node: Node, source: bytes, imports: dict[str, str]) -> Node | None:
    compact = _compact_text(source, node)
    if node.type == "index_expression" and compact.endswith("]"):
        prefix = compact.rsplit("[", 1)[0]
        if prefix.endswith(".Args"):
            receiver = prefix[: -len(".Args")]
            if imports.get(receiver) == _OS_PACKAGE:
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
    method = _text(source, field)
    receiver = _compact_text(source, operand)
    if method in {"FormValue", "PostFormValue", "PathValue", "Cookie"}:
        return node
    if method == "Get" and (
        receiver.endswith((".Header", ".URL.Query()", ".Form", ".PostForm"))
        or receiver.rsplit(".", 1)[-1].lower() in {"header", "query", "form"}
    ):
        return node
    package = imports.get(_compact_text(source, operand))
    if package == _OS_PACKAGE and method == "Getenv":
        arguments = node.child_by_field_name("arguments")
        if arguments is not None and arguments.named_children:
            literal = _compact_text(source, arguments.named_children[0]).lower()
            if _mentions_sensitive_literal(literal):
                return node
    return None


def _is_sanitizer(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    function = node.child_by_field_name("function") if node.type == "call_expression" else None
    if function is None or function.type != "selector_expression":
        return False
    field = function.child_by_field_name("field")
    operand = function.child_by_field_name("operand")
    if field is None or operand is None:
        return False
    method = _text(source, field).lower()
    package = imports.get(_compact_text(source, operand), "")
    return method in _SANITIZER_WORDS or (
        package in {"crypto/sha256", "crypto/sha512", "crypto/md5", "encoding/hex"}
        and method not in {"New", "NewEncoder"}
    )


def _qualified_call(function: Node | None, source: bytes, imports: dict[str, str]) -> str:
    if function is None or function.type != "selector_expression":
        return ""
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return ""
    package = imports.get(_compact_text(source, operand))
    method = _text(source, field)
    if package is not None:
        return f"{package}.{method}"
    return ""


def _is_sensitive_name(value: str) -> bool:
    tokens = _name_tokens(value)
    return bool(tokens & _SENSITIVE_WORDS)


def _name_tokens(value: str) -> frozenset[str]:
    return frozenset(
        token.lower()
        for token in re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|\Z)|[A-Z]?[a-z]+|\d+", value)
    ) | frozenset(re.sub(r"[^a-z0-9]", "", value.lower()).split())


def _mentions_sensitive_literal(value: str) -> bool:
    compact = re.sub(r"[^a-z0-9_-]", "", value.lower())
    return any(marker in value.lower() or marker.replace("-", "") in compact for marker in _SENSITIVE_LITERAL_MARKERS)


def _scopes(root: Node) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node is root or node.type in _GO_SCOPES)


def _scope_preorder(scope: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    while stack:
        node = stack.pop()
        output.append(node)
        if node is not scope and node.type in _GO_SCOPES:
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


def _dedupe_flows(flows: Iterable[_Flow]) -> tuple[_Flow, ...]:
    unique: dict[tuple[int, int], _Flow] = {}
    for flow in flows:
        unique[(flow.source.start_byte, flow.source.end_byte)] = flow
    return tuple(unique[key] for key in sorted(unique))


def _text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")


def _compact_text(source: bytes, node: Node | None) -> str:
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
    operation: GoCwe209Operation,
) -> str:
    material = {
        "content_sha256": content_sha256,
        "cwe": "CWE-209",
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
    return "go-cwe209-" + digest


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe209Signal, ...],
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


__all__ = [
    "DEFAULT_GO_CWE209_SCAN_LIMITS",
    "GoCwe209Operation",
    "GoCwe209ScanError",
    "GoCwe209ScanErrorCode",
    "GoCwe209ScanLimits",
    "GoCwe209ScanResult",
    "GoCwe209Signal",
    "scan_go_cwe209",
    "scan_go_error_disclosure",
    "scan_go_sensitive_error_messages",
]
