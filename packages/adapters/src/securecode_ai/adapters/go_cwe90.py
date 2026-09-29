"""Bounded Go source-to-sink facts for CWE-90 LDAP injection.

The scanner accepts one admitted, sealed Go ``SymbolIndex`` and reparses the
same bytes before inspecting the CST.  It recognises the go-ldap/ldap package,
request and environment sources, a small set of string-preserving helpers,
and LDAP filter, search, and compare operations.  LDAP escaping helpers are
treated as sanitizers.  Results contain ranges and content-addressed metadata
only; source text and parser failures never leave this module.
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
_RULE_ID = "securecode-go-cwe90"
_DETECTOR = "securecode-go-cwe90@1.0"

_LDAP_MODULES = frozenset({"github.com/go-ldap/ldap", "github.com/go-ldap/ldap/v3"})
_OS_PACKAGE = "os"
_FMT_PACKAGE = "fmt"
_STRINGS_PACKAGE = "strings"
_REQUEST_METHODS = frozenset({"FormValue", "PostFormValue", "PathValue", "Header"})
_ENV_METHODS = frozenset({"Getenv", "LookupEnv"})
_STRING_HELPERS = frozenset(
    {"Sprintf", "Join", "Replace", "ReplaceAll", "TrimSpace", "TrimPrefix", "TrimSuffix"}
)
_LDAP_SANITIZERS = frozenset(
    {
        "EscapeFilter",
        "EscapeFilterValue",
        "EscapeDN",
        "EscapeDNComponent",
        "FilterEscape",
    }
)
_LDAP_CONNECTION_FACTORIES = frozenset(
    {"Dial", "DialURL", "DialTLS", "DialContext", "DialURLContext", "NewConn"}
)
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})


class GoCwe90ScanErrorCode(StrEnum):
    """Closed, source-free reasons a Go LDAP scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe90ScanError(RuntimeError):
    """Fixed scanner failure that never echoes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe90ScanErrorCode) -> None:
        if type(code) is not GoCwe90ScanErrorCode:
            raise TypeError("Go CWE-90 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-90 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe90ScanLimits:
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
            raise ValueError("Go CWE-90 scan limits are invalid")


DEFAULT_GO_CWE90_SCAN_LIMITS = GoCwe90ScanLimits()


class GoCwe90Operation(StrEnum):
    """Recognised go-ldap/ldap filter, search, and compare operations."""

    NEW_SEARCH_REQUEST = "ldap.new_search_request"
    SEARCH = "ldap.search"
    SEARCH_WITH_PAGING = "ldap.search_with_paging"
    COMPARE = "ldap.compare"

    LDAP_NEW_SEARCH_REQUEST = "ldap.new_search_request"
    LDAP_SEARCH = "ldap.search"
    LDAP_SEARCH_WITH_PAGING = "ldap.search_with_paging"
    LDAP_COMPARE = "ldap.compare"


@dataclass(frozen=True, slots=True)
class GoCwe90Signal:
    """One immutable request or environment to LDAP operation fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe90Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-90"
    detector: str = _DETECTOR
    detail: str = "untrusted_input_to_ldap"

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
            if valid_identity and valid_ranges and type(self.operation) is GoCwe90Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not GoCwe90Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-90"
            or self.detector != _DETECTOR
            or self.detail != "untrusted_input_to_ldap"
        ):
            raise ValueError("Go CWE-90 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

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
class GoCwe90ScanResult:
    """Source-free, deterministic CWE-90 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe90Signal, ...]
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
            type(item) is GoCwe90Signal for item in self.signals
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
                self.signals,
            )
        ):
            raise ValueError("Go CWE-90 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange


def scan_go_cwe90(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe90ScanLimits = DEFAULT_GO_CWE90_SCAN_LIMITS,
) -> GoCwe90ScanResult:
    """Find bounded external-input flows into go-ldap/ldap operations."""

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
        raise GoCwe90ScanError(GoCwe90ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    raw: set[tuple[SourceRange, SourceRange, GoCwe90Operation]] = set()
    for scope in _scopes(root):
        environment: dict[str, tuple[_Flow, ...]] = {}
        connections = _connection_parameters(scope, source, imports)
        for node in _scope_preorder(scope):
            if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                _capture_assignment(node, environment, connections, source, imports, limits)
            if node.type != "call_expression":
                continue
            operation = _operation_for_call(node, source, imports, connections)
            if operation is None:
                continue
            arguments = node.child_by_field_name("arguments")
            if arguments is None:
                raise GoCwe90ScanError(GoCwe90ScanErrorCode.INTEGRITY_FAILURE)
            for argument in _sink_arguments(arguments, operation):
                for flow in _resolve(
                    argument, environment, source, imports, limits, 0, frozenset()
                ):
                    sink_range = _range(node)
                    if flow.source.end_byte > sink_range.end_byte:
                        raise GoCwe90ScanError(GoCwe90ScanErrorCode.INTEGRITY_FAILURE)
                    raw.add((flow.source, sink_range, operation))
                    if len(raw) > limits.max_signals:
                        raise GoCwe90ScanError(GoCwe90ScanErrorCode.SIGNAL_LIMIT)

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
        raise GoCwe90ScanError(GoCwe90ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe90Signal(
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
    return GoCwe90ScanResult(
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


def scan_go_cwe90_ldap_injection(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe90ScanLimits = DEFAULT_GO_CWE90_SCAN_LIMITS,
) -> GoCwe90ScanResult:
    """Descriptive alias for :func:`scan_go_cwe90`."""

    return scan_go_cwe90(symbol_index, limits=limits)


def scan_go_ldap_injection(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe90ScanLimits = DEFAULT_GO_CWE90_SCAN_LIMITS,
) -> GoCwe90ScanResult:
    """Compatibility alias for callers grouping Go LDAP scanners."""

    return scan_go_cwe90(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe90ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe90ScanLimits:
        raise GoCwe90ScanError(GoCwe90ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe90ScanError(GoCwe90ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe90ScanError(GoCwe90ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe90ScanError(GoCwe90ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    relevant = _LDAP_MODULES | {_OS_PACKAGE, _FMT_PACKAGE, _STRINGS_PACKAGE, "net/http"}
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
    connections: set[str],
) -> GoCwe90Operation | None:
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    receiver = _compact_text(source, operand)
    method = _text(source, field)
    package = imports.get(receiver)
    if package in _LDAP_MODULES and method == "NewSearchRequest":
        return GoCwe90Operation.NEW_SEARCH_REQUEST
    if method == "Search" and _is_connection(receiver, connections):
        return GoCwe90Operation.SEARCH
    if method == "SearchWithPaging" and _is_connection(receiver, connections):
        return GoCwe90Operation.SEARCH_WITH_PAGING
    if method == "Compare" and _is_connection(receiver, connections):
        return GoCwe90Operation.COMPARE
    return None


def _is_connection(receiver: str, connections: set[str]) -> bool:
    if receiver in connections:
        return True
    return receiver.rsplit(".", 1)[-1] in {"conn", "connection", "client", "ldapConn"}


def _sink_arguments(arguments: Node, operation: GoCwe90Operation) -> tuple[Node, ...]:
    values = tuple(arguments.named_children)
    if not values:
        return ()
    if operation is GoCwe90Operation.NEW_SEARCH_REQUEST:
        return (values[6],) if len(values) > 6 else ()
    if operation in {GoCwe90Operation.SEARCH, GoCwe90Operation.SEARCH_WITH_PAGING}:
        return values[:1]
    return values[:3]


def _capture_assignment(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    connections: set[str],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe90ScanLimits,
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
        name_text = _text(source, name)
        environment[name_text] = _resolve(
            value, environment, source, imports, limits, 0, frozenset()
        )
        if _is_connection_factory(value, source, imports) or (
            value.type == "identifier" and _text(source, value) in connections
        ):
            connections.add(name_text)
        else:
            connections.discard(name_text)


def _is_connection_factory(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return False
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    return (
        operand is not None
        and field is not None
        and imports.get(_text(source, operand)) in _LDAP_MODULES
        and _text(source, field) in _LDAP_CONNECTION_FACTORIES
    )


def _connection_parameters(scope: Node, source: bytes, imports: dict[str, str]) -> set[str]:
    result: set[str] = set()
    for node in _preorder(scope):
        if node.type != "parameter_declaration":
            continue
        type_node = node.child_by_field_name("type")
        if type_node is None:
            continue
        type_text = _compact_text(source, type_node)
        if not any(
            f"{alias}.Conn" in type_text
            for alias, package in imports.items()
            if package in _LDAP_MODULES
        ):
            continue
        names_node = node.child_by_field_name("name")
        if names_node is not None:
            for child in names_node.named_children or (names_node,):
                if child.type == "identifier":
                    result.add(_text(source, child))
    return result


def _resolve(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe90ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[_Flow, ...]:
    if depth > limits.max_expression_depth:
        raise GoCwe90ScanError(GoCwe90ScanErrorCode.SIGNAL_LIMIT)
    if _is_sanitizer(node, source, imports):
        return ()
    direct = _external_source(node, source, imports)
    if direct is not None:
        return (_Flow(_range(direct)),)
    if node.type == "identifier":
        name = _text(source, node)
        if name in visited:
            return ()
        return environment.get(name, ())
    if node.type in {"parenthesized_expression", "unary_expression", "pointer_expression"}:
        return _dedupe_flows(
            (
                flow
                for child in node.named_children
                for flow in _resolve(
                    child, environment, source, imports, limits, depth + 1, visited
                )
            ),
            limits,
        )
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            return ()
        qualified = _qualified_call(function, source, imports)
        if qualified in {
            "fmt.Sprintf",
            "strings.Join",
            "strings.Replace",
            "strings.ReplaceAll",
            "strings.TrimSpace",
            "strings.TrimPrefix",
            "strings.TrimSuffix",
        }:
            values = tuple(
                arguments.named_children[1:]
                if qualified == "fmt.Sprintf"
                else arguments.named_children
            )
            return _dedupe_flows(
                (
                    flow
                    for argument in values
                    for flow in _resolve(
                        argument, environment, source, imports, limits, depth + 1, visited
                    )
                ),
                limits,
            )
        if qualified == "ldap.NewSearchRequest":
            values = tuple(arguments.named_children)
            return (
                _resolve(values[6], environment, source, imports, limits, depth + 1, visited)
                if len(values) > 6
                else ()
            )
        return ()
    if node.type in {
        "binary_expression",
        "index_expression",
        "slice_expression",
        "composite_literal",
    }:
        return _dedupe_flows(
            (
                flow
                for child in node.named_children
                for flow in _resolve(
                    child, environment, source, imports, limits, depth + 1, visited
                )
            ),
            limits,
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
    name = _text(source, field)
    receiver = _compact_text(source, operand)
    if name in _ENV_METHODS and imports.get(receiver) == _OS_PACKAGE:
        return node
    if name in _REQUEST_METHODS:
        if name in {"FormValue", "PostFormValue", "PathValue"}:
            return node
        if receiver.endswith((".Header", ".URL.Query()", ".Form", ".PostForm")):
            return node
    if name == "Get" and receiver.endswith((".URL.Query()", ".Form", ".PostForm")):
        return node
    return None


def _is_sanitizer(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return False
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return False
    return (
        imports.get(_text(source, operand)) in _LDAP_MODULES
        and _text(source, field) in _LDAP_SANITIZERS
    )


def _qualified_call(function: Node | None, source: bytes, imports: dict[str, str]) -> str:
    if function is None or function.type != "selector_expression":
        return ""
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return ""
    package = imports.get(_text(source, operand))
    name = _text(source, field)
    if package in _LDAP_MODULES and name in {"NewSearchRequest", *_LDAP_SANITIZERS}:
        return f"ldap.{name}"
    if package in {_FMT_PACKAGE, _STRINGS_PACKAGE} and name in _STRING_HELPERS:
        return f"{package}.{name}"
    return ""


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


def _dedupe_flows(flows: Iterable[_Flow], limits: GoCwe90ScanLimits) -> tuple[_Flow, ...]:
    unique: dict[tuple[int, int], _Flow] = {}
    for flow in flows:
        unique[(flow.source.start_byte, flow.source.end_byte)] = flow
        if len(unique) > limits.max_signals:
            raise GoCwe90ScanError(GoCwe90ScanErrorCode.SIGNAL_LIMIT)
    return tuple(unique[key] for key in sorted(unique))


def _text(source: bytes, node: Node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")


def _compact_text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
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
    operation: GoCwe90Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-90",
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
    signals: tuple[GoCwe90Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-90",
        "detector": _DETECTOR,
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


__all__ = [
    "DEFAULT_GO_CWE90_SCAN_LIMITS",
    "GoCwe90Operation",
    "GoCwe90ScanError",
    "GoCwe90ScanErrorCode",
    "GoCwe90ScanLimits",
    "GoCwe90ScanResult",
    "GoCwe90Signal",
    "scan_go_cwe90",
    "scan_go_cwe90_ldap_injection",
    "scan_go_ldap_injection",
]
