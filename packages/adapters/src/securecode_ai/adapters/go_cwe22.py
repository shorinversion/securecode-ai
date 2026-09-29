"""Bounded Go source-to-sink facts for CWE-22 path traversal.

The scanner accepts a sealed :class:`~securecode_ai.core.SymbolIndex` and
returns only source ranges and content-addressed metadata.  It deliberately
recognises a small set of HTTP, environment, and command-line sources and
filesystem sinks.  It does not execute the analysed program, retain source
text in its result, or decide whether a finding is a vulnerability.
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

_FILESYSTEM_PACKAGES = frozenset({"os", "io/ioutil"})
_PATH_PACKAGES = frozenset({"path", "path/filepath"})
_UTILITY_PACKAGES = frozenset({"fmt", "strings"})
_FILESYSTEM_FUNCTIONS = frozenset(
    {
        "Chmod",
        "Chown",
        "Create",
        "CreateTemp",
        "Link",
        "Lstat",
        "Mkdir",
        "MkdirAll",
        "Open",
        "OpenFile",
        "ReadFile",
        "Readlink",
        "Remove",
        "RemoveAll",
        "Rename",
        "Stat",
        "Symlink",
        "Truncate",
        "WriteFile",
    }
)
_HTTP_FUNCTIONS = frozenset({"ServeFile", "ServeFileFS"})
_PATH_BUILDER_FUNCTIONS = frozenset({"Abs", "Clean", "FromSlash", "Join", "Rel", "ToSlash"})
_SOURCE_CALLS = frozenset(
    {
        "FormValue",
        "Get",
        "Getenv",
        "LookupEnv",
        "PathValue",
        "PostFormValue",
    }
)
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})


class GoCwe22ScanErrorCode(StrEnum):
    """Closed, source-free reasons why a Go path scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe22ScanError(RuntimeError):
    """Safe scanner failure that never includes source or parser text."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe22ScanErrorCode) -> None:
        if type(code) is not GoCwe22ScanErrorCode:
            raise TypeError("Go CWE-22 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-22 path scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe22ScanLimits:
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
            raise ValueError("Go CWE-22 scan limits are invalid")


DEFAULT_GO_CWE22_SCAN_LIMITS = GoCwe22ScanLimits()


@dataclass(frozen=True, slots=True)
class GoCwe22Signal:
    """One source-free, deterministic untrusted-path-to-filesystem fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    detector: str = "securecode-go-cwe22@1.0"
    cwe: str = "CWE-22"
    detail: str = "untrusted_path_to_filesystem"
    signal_id: str = ""

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
            and type(self.source) is SourceRange
            and type(self.sink) is SourceRange
            and self.source.end_byte <= self.sink.end_byte
            and self.source.end_byte <= self.source_size_bytes
            and self.sink.end_byte <= self.source_size_bytes
            and self.detector == "securecode-go-cwe22@1.0"
            and self.cwe == "CWE-22"
            and self.detail == "untrusted_path_to_filesystem"
        )
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity_valid = False
        if not identity_valid:
            raise ValueError("Go CWE-22 signal is invalid")
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
            raise ValueError("Go CWE-22 signal is invalid")
        if self.signal_id == "":
            object.__setattr__(self, "signal_id", expected_id)


@dataclass(frozen=True, slots=True)
class GoCwe22ScanResult:
    """Deterministic metadata and facts for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe22Signal, ...]
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
            or any(type(item) is not GoCwe22Signal for item in self.signals)
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
            raise ValueError("Go CWE-22 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange


def scan_go_cwe22(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe22ScanLimits = DEFAULT_GO_CWE22_SCAN_LIMITS,
) -> GoCwe22ScanResult:
    """Find bounded external-input flows into Go filesystem path sinks."""

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
        raise GoCwe22ScanError(GoCwe22ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    raw: list[tuple[SourceRange, SourceRange]] = []
    for scope in _scopes(root):
        environment: dict[str, tuple[_Flow, ...]] = {}
        for node in _scope_preorder(scope):
            if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                _capture_assignment(node, environment, source, imports, limits)
            if node.type != "call_expression" or not _is_sink(node, source, imports):
                continue
            arguments = node.child_by_field_name("arguments")
            if arguments is None:
                continue
            for argument in _sink_path_arguments(node, arguments, source, imports):
                for flow in _resolve(argument, environment, source, imports, limits, 0):
                    raw.append((flow.source, _range(node)))
                    if len(raw) > limits.max_signals:
                        raise GoCwe22ScanError(GoCwe22ScanErrorCode.SIGNAL_LIMIT)

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
        raise GoCwe22ScanError(GoCwe22ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe22Signal(
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
    return GoCwe22ScanResult(
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


def scan_go_cwe22_path_traversal(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe22ScanLimits = DEFAULT_GO_CWE22_SCAN_LIMITS,
) -> GoCwe22ScanResult:
    """Descriptive alias for :func:`scan_go_cwe22`."""

    return scan_go_cwe22(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe22ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe22ScanLimits:
        raise GoCwe22ScanError(GoCwe22ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe22ScanError(GoCwe22ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe22ScanError(GoCwe22ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe22ScanError(GoCwe22ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        package = _text(source, path_node).strip('"`')
        if package not in _FILESYSTEM_PACKAGES | _PATH_PACKAGES | _UTILITY_PACKAGES | {"net/http"}:
            continue
        name_node = node.child_by_field_name("name")
        alias = _text(source, name_node) if name_node is not None else package.rsplit("/", 1)[-1]
        if alias not in {".", "_"}:
            aliases[alias] = package
    return aliases


def _is_sink(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return False
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return False
    package = imports.get(_text(source, operand))
    name = _text(source, field)
    return (package in _FILESYSTEM_PACKAGES and name in _FILESYSTEM_FUNCTIONS) or (
        package == "net/http" and name in _HTTP_FUNCTIONS
    )


def _sink_path_arguments(
    node: Node,
    arguments: Node,
    source: bytes,
    imports: dict[str, str],
) -> tuple[Node, ...]:
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return ()
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return ()
    package = imports.get(_text(source, operand))
    name = _text(source, field)
    values = tuple(arguments.named_children)
    if package == "net/http":
        path_index = 3 if name == "ServeFileFS" else 2
        return (values[path_index],) if len(values) > path_index else ()
    if name in {"Link", "Rename", "Symlink"}:
        return tuple(values[:2])
    return values[:1]


def _capture_assignment(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe22ScanLimits,
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
    for name, value in zip(names, values, strict=False):
        if name.type != "identifier":
            continue
        environment[_text(source, name)] = _resolve(value, environment, source, imports, limits, 0)


def _resolve(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe22ScanLimits,
    depth: int,
    visited: frozenset[str] = frozenset(),
) -> tuple[_Flow, ...]:
    if depth > limits.max_expression_depth:
        raise GoCwe22ScanError(GoCwe22ScanErrorCode.SIGNAL_LIMIT)
    direct = _external_source(node, source, imports)
    if direct is not None:
        return (_Flow(_range(direct)),)
    if node.type == "identifier":
        name = _text(source, node)
        if name in visited:
            return ()
        return environment.get(name, ())
    if node.type in {"parenthesized_expression", "unary_expression", "pointer_expression"}:
        return tuple(
            flow
            for child in node.named_children
            for flow in _resolve(child, environment, source, imports, limits, depth + 1, visited)
        )
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        if _is_path_builder(function, source, imports):
            arguments = node.child_by_field_name("arguments")
            if arguments is None:
                return ()
            return _dedupe_flows(
                (
                    flow
                    for argument in arguments.named_children
                    for flow in _resolve(
                        argument, environment, source, imports, limits, depth + 1, visited
                    )
                ),
                limits,
            )
        # fmt.Sprintf and strings concatenation preserve an untrusted path.
        utility_function = _utility_function(function, source, imports)
        if utility_function is not None:
            arguments = node.child_by_field_name("arguments")
            if arguments is None:
                return ()
            values = (
                arguments.named_children[1:]
                if utility_function == "fmt.Sprintf"
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
            if imports.get(receiver) == "os":
                return node
    if node.type != "call_expression":
        if node.type == "selector_expression" and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*\.URL\.(?:Path|RawPath)", compact
        ):
            return node
        return None
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return None
    field = function.child_by_field_name("field")
    if field is None or _text(source, field) not in _SOURCE_CALLS:
        return None
    operand = function.child_by_field_name("operand")
    if operand is None:
        return None
    receiver = _compact_text(source, operand)
    if (
        receiver.endswith(".URL.Query()")
        or receiver.endswith(".Form")
        or receiver.endswith(".PostForm")
    ):
        return node
    if _text(source, field) in {"FormValue", "PostFormValue", "PathValue"}:
        return node
    if imports.get(receiver) == "os" and _text(source, field) in {
        "Getenv",
        "LookupEnv",
    }:
        return node
    return None


def _is_path_builder(function: Node | None, source: bytes, imports: dict[str, str]) -> bool:
    if function is None or function.type != "selector_expression":
        return False
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    return (
        operand is not None
        and field is not None
        and imports.get(_text(source, operand)) in _PATH_PACKAGES
        and _text(source, field) in _PATH_BUILDER_FUNCTIONS
    )


def _utility_function(function: Node | None, source: bytes, imports: dict[str, str]) -> str | None:
    if function is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    package = imports.get(_text(source, operand))
    name = _text(source, field)
    if package == "fmt" and name == "Sprintf":
        return "fmt.Sprintf"
    if package == "strings" and name in {"TrimSpace", "TrimPrefix"}:
        return f"strings.{name}"
    return None


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


def _dedupe_flows(flows: Iterable[_Flow], limits: GoCwe22ScanLimits) -> tuple[_Flow, ...]:
    unique: dict[tuple[int, int], _Flow] = {}
    for flow in flows:
        unique[(flow.source.start_byte, flow.source.end_byte)] = flow
        if len(unique) > limits.max_signals:
            raise GoCwe22ScanError(GoCwe22ScanErrorCode.SIGNAL_LIMIT)
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
        "cwe": "CWE-22",
        "detector": "securecode-go-cwe22@1.0",
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
    return "go-cwe22-" + digest


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe22Signal, ...],
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
    "DEFAULT_GO_CWE22_SCAN_LIMITS",
    "GoCwe22ScanError",
    "GoCwe22ScanErrorCode",
    "GoCwe22ScanLimits",
    "GoCwe22ScanResult",
    "GoCwe22Signal",
    "scan_go_cwe22",
    "scan_go_cwe22_path_traversal",
]
