"""Bounded Go source-to-sink facts for CWE-918 SSRF.

The scanner consumes one sealed Go :class:`~securecode_ai.core.SymbolIndex` and
emits immutable metadata only.  It recognises a small, explicit set of request
and environment sources and the standard ``net/http`` client boundary.  The
result is a structural fact for the common pipeline, not a vulnerability
verdict.  Source bytes are used while scanning but are never retained in a
signal or an exception message.
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

_HTTP_PACKAGE = "net/http"
_URL_PACKAGE = "net/url"
_OS_PACKAGE = "os"
_HTTP_DIRECT_METHODS = frozenset({"Get", "Head", "Post", "PostForm"})
_HTTP_CLIENT_METHODS = frozenset({"Get", "Head", "Post", "PostForm", "Do"})
_HTTP_REQUEST_BUILDERS = frozenset({"NewRequest", "NewRequestWithContext"})
_URL_BUILDERS = frozenset({"Parse", "JoinPath"})
_URL_TRANSFORMS = frozenset(
    {
        "QueryEscape",
        "PathEscape",
        "JoinPath",
        "ResolveReference",
    }
)
_STRING_TRANSFORMS = frozenset(
    {"Join", "Replace", "ReplaceAll", "TrimSpace", "TrimPrefix", "TrimSuffix"}
)
_SOURCE_METHODS = frozenset({"FormValue", "PostFormValue", "PathValue"})
_URL_ACCESSORS = frozenset({"Path", "RawPath", "RawQuery", "RequestURI"})
_URL_STRING_METHODS = frozenset({"String", "EscapedPath", "RequestURI"})
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})


class GoCwe918ScanErrorCode(StrEnum):
    """Closed, source-free reasons why an SSRF fact cannot be emitted."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe918ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe918ScanErrorCode) -> None:
        if type(code) is not GoCwe918ScanErrorCode:
            raise TypeError("Go CWE-918 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-918 SSRF scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe918ScanLimits:
    """Hard bounds applied before and during structural data-flow analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-918 scan limits are invalid")


DEFAULT_GO_CWE918_SCAN_LIMITS = GoCwe918ScanLimits()


@dataclass(frozen=True, slots=True)
class GoCwe918Signal:
    """One source-free, deterministic untrusted-URL-to-HTTP fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    detector: str = "securecode-go-cwe918@1.0"
    cwe: str = "CWE-918"
    detail: str = "untrusted_url_to_http_client"
    signal_id: str = ""

    def __post_init__(self) -> None:
        valid = (
            type(self.repository_id) is str
            and bool(self.repository_id)
            and type(self.revision) is str
            and _SHA1.fullmatch(self.revision) is not None
            and type(self.path) is str
            and type(self.content_sha256) is str
            and _SHA256.fullmatch(self.content_sha256) is not None
            and type(self.source_size_bytes) is int
            and self.source_size_bytes >= 0
            and type(self.source) is SourceRange
            and type(self.sink) is SourceRange
            and self.source.start_byte <= self.sink.end_byte
            and self.source.end_byte <= self.sink.end_byte
            and self.source.end_byte <= self.source_size_bytes
            and self.sink.end_byte <= self.source_size_bytes
            and self.detector == "securecode-go-cwe918@1.0"
            and self.cwe == "CWE-918"
            and self.detail == "untrusted_url_to_http_client"
        )
        if valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid = False
        if not valid:
            raise ValueError("Go CWE-918 signal is invalid")
        expected_id = _signal_id(
            self.repository_id,
            self.revision,
            self.path,
            self.content_sha256,
            self.source_size_bytes,
            self.source,
            self.sink,
        )
        if self.signal_id not in {"", expected_id}:
            raise ValueError("Go CWE-918 signal is invalid")
        if self.signal_id == "":
            object.__setattr__(self, "signal_id", expected_id)


@dataclass(frozen=True, slots=True)
class GoCwe918ScanResult:
    """Deterministic metadata and facts for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe918Signal, ...]
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
        order = tuple(
            (item.sink.start_byte, item.sink.end_byte, item.source.start_byte, item.source.end_byte)
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
            or any(type(item) is not GoCwe918Signal for item in self.signals)
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
            or not same_identity
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
            raise ValueError("Go CWE-918 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange


def scan_go_cwe918(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe918ScanLimits = DEFAULT_GO_CWE918_SCAN_LIMITS,
) -> GoCwe918ScanResult:
    """Find bounded external URL flows into standard Go HTTP clients."""

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
    except Exception:
        raise GoCwe918ScanError(GoCwe918ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    raw: list[tuple[SourceRange, SourceRange]] = []
    for scope in _scopes(root):
        environment: dict[str, tuple[_Flow, ...]] = {}
        for node in _scope_preorder(scope):
            if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                _capture_assignment(node, environment, source, imports, limits)
            if node.type != "call_expression":
                continue
            sink_kind = _http_sink_kind(node, source, imports)
            if sink_kind is None:
                continue
            arguments = node.child_by_field_name("arguments")
            if arguments is None:
                continue
            sink_arguments = _sink_arguments(sink_kind, arguments)
            for argument in sink_arguments:
                flows = _resolve(argument, environment, source, imports, limits, 0)
                for flow in flows:
                    raw.append((flow.source, _range(node)))
                    if len(raw) > limits.max_signals:
                        raise GoCwe918ScanError(GoCwe918ScanErrorCode.SIGNAL_LIMIT)

    unique = sorted(
        set(raw),
        key=lambda item: (
            item[1].start_byte,
            item[1].end_byte,
            item[0].start_byte,
            item[0].end_byte,
        ),
    )
    if len(unique) > limits.max_signals:
        raise GoCwe918ScanError(GoCwe918ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe918Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
        )
        for source_range, sink_range in unique
    )
    return GoCwe918ScanResult(
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


def scan_go_cwe918_ssrf(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe918ScanLimits = DEFAULT_GO_CWE918_SCAN_LIMITS,
) -> GoCwe918ScanResult:
    """Descriptive alias for :func:`scan_go_cwe918`."""

    return scan_go_cwe918(symbol_index, limits=limits)


def scan_go_ssrf(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe918ScanLimits = DEFAULT_GO_CWE918_SCAN_LIMITS,
) -> GoCwe918ScanResult:
    """Compatibility alias for callers grouping Go SSRF scanners."""

    return scan_go_cwe918(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe918ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe918ScanLimits:
        raise GoCwe918ScanError(GoCwe918ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe918ScanError(GoCwe918ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe918ScanError(GoCwe918ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe918ScanError(GoCwe918ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    relevant = {_HTTP_PACKAGE, _URL_PACKAGE, _OS_PACKAGE, "fmt", "strings"}
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


def _http_sink_kind(node: Node, source: bytes, imports: dict[str, str]) -> str | None:
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    receiver = _text(source, operand)
    method = _text(source, field)
    if imports.get(receiver) == _HTTP_PACKAGE and method in _HTTP_DIRECT_METHODS:
        return method
    if method not in _HTTP_CLIENT_METHODS:
        return None
    if imports.get(receiver) is not None:
        return None
    return method


def _sink_arguments(kind: str, arguments: Node) -> tuple[Node, ...]:
    values = tuple(arguments.named_children)
    if not values:
        return ()
    if kind == "Do":
        return (values[0],)
    return (values[0],)


def _capture_assignment(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe918ScanLimits,
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
        environment[_text(source, name)] = _resolve(value, environment, source, imports, limits, 0)


def _resolve(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe918ScanLimits,
    depth: int,
    visited: frozenset[str] = frozenset(),
) -> tuple[_Flow, ...]:
    if depth > limits.max_expression_depth:
        raise GoCwe918ScanError(GoCwe918ScanErrorCode.SIGNAL_LIMIT)
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
        builder = _qualified_call(function, source, imports)
        if builder in {"http.NewRequest", "http.NewRequestWithContext"}:
            values = tuple(arguments.named_children)
            url_index = 2 if builder.endswith("WithContext") else 1
            if len(values) <= url_index:
                return ()
            return _resolve(
                values[url_index], environment, source, imports, limits, depth + 1, visited
            )
        if builder in {"url.Parse", "url.JoinPath"}:
            values = tuple(arguments.named_children)
            if builder == "url.Parse":
                values = values[:1]
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
        if builder in {
            "fmt.Sprintf",
            "strings.Join",
            "strings.Replace",
            "strings.ReplaceAll",
            "strings.TrimSpace",
            "strings.TrimPrefix",
            "strings.TrimSuffix",
            "url.QueryEscape",
            "url.PathEscape",
        }:
            values = tuple(
                arguments.named_children[1:]
                if builder == "fmt.Sprintf"
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
        if function is not None and function.type == "selector_expression":
            operand = function.child_by_field_name("operand")
            field = function.child_by_field_name("field")
            if (
                operand is not None
                and field is not None
                and _text(source, field) in _URL_STRING_METHODS
            ):
                return _resolve(operand, environment, source, imports, limits, depth + 1, visited)
        return ()
    if node.type in {"binary_expression", "index_expression", "slice_expression"}:
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
    if node.type == "selector_expression":
        if re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*\.(?:URL\.)?(?:Path|RawPath|RawQuery|RequestURI)",
            compact,
        ):
            return node
        return None
    if node.type != "call_expression":
        return None
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return None
    field = function.child_by_field_name("field")
    operand = function.child_by_field_name("operand")
    if field is None or operand is None:
        return None
    name = _text(source, field)
    receiver = _compact_text(source, operand)
    if name in _SOURCE_METHODS:
        return node
    if name in {"Get", "LookupEnv"} and imports.get(receiver) == _OS_PACKAGE:
        return node
    if name == "Getenv" and imports.get(receiver) == _OS_PACKAGE:
        return node
    if name in {"Get", "LookupEnv"} and (
        receiver.endswith(".URL.Query()")
        or receiver.endswith(".Form")
        or receiver.endswith(".PostForm")
    ):
        return node
    if name in _URL_STRING_METHODS and re.search(r"\.URL$", receiver):
        return node
    return None


def _qualified_call(function: Node | None, source: bytes, imports: dict[str, str]) -> str:
    if function is None or function.type != "selector_expression":
        return ""
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return ""
    package = imports.get(_text(source, operand))
    name = _text(source, field)
    if package == _HTTP_PACKAGE and name in _HTTP_REQUEST_BUILDERS:
        return f"http.{name}"
    if package == _URL_PACKAGE and (name in _URL_BUILDERS or name in _URL_TRANSFORMS):
        return f"url.{name}"
    if package in {"fmt", "strings"} and name in _STRING_TRANSFORMS | {"Sprintf"}:
        return f"{package}.{name}"
    return ""


def _is_scope(node: Node) -> bool:
    return node.type in _GO_SCOPES


def _scopes(root: Node) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node is root or _is_scope(node))


def _scope_preorder(scope: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    while stack:
        node = stack.pop()
        output.append(node)
        if node is not scope and _is_scope(node):
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


def _dedupe_flows(flows: Iterable[_Flow], limits: GoCwe918ScanLimits) -> tuple[_Flow, ...]:
    unique: dict[tuple[int, int], _Flow] = {}
    for flow in flows:
        unique[(flow.source.start_byte, flow.source.end_byte)] = flow
        if len(unique) > limits.max_signals:
            raise GoCwe918ScanError(GoCwe918ScanErrorCode.SIGNAL_LIMIT)
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
) -> str:
    material = {
        "content_sha256": content_sha256,
        "cwe": "CWE-918",
        "detector": "securecode-go-cwe918@1.0",
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
    return "go-cwe918-" + digest


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe918Signal, ...],
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
    "DEFAULT_GO_CWE918_SCAN_LIMITS",
    "GoCwe918ScanError",
    "GoCwe918ScanErrorCode",
    "GoCwe918ScanLimits",
    "GoCwe918ScanResult",
    "GoCwe918Signal",
    "scan_go_cwe918",
    "scan_go_cwe918_ssrf",
    "scan_go_ssrf",
]
