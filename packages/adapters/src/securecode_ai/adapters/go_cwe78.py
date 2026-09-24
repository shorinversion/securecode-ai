"""Bounded Go source-to-sink facts for CWE-78 command injection.

The scanner consumes one sealed Go :class:`~securecode_ai.core.SymbolIndex` and
emits immutable source ranges plus content-addressed metadata.  It recognises
request and environment input flowing into the standard ``os/exec`` command
constructors.  Constant-only command calls are ignored.  Source bytes are
used during parsing but are never retained in a signal or an error message.
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

_EXEC_PACKAGE = "os/exec"
_OS_PACKAGE = "os"
_EXEC_FUNCTIONS = frozenset({"Command", "CommandContext"})
_ENV_FUNCTIONS = frozenset({"Getenv", "LookupEnv"})
_REQUEST_FUNCTIONS = frozenset(
    {"FormValue", "Get", "PathValue", "PostFormValue"}
)
_UTILITY_PACKAGES = frozenset({"fmt", "strings"})
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})


class GoCwe78ScanErrorCode(StrEnum):
    """Closed, source-free reasons why a command scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe78ScanError(RuntimeError):
    """Fixed scanner failure that never includes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe78ScanErrorCode) -> None:
        if type(code) is not GoCwe78ScanErrorCode:
            raise TypeError("Go CWE-78 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-78 command scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe78ScanLimits:
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
            raise ValueError("Go CWE-78 scan limits are invalid")


DEFAULT_GO_CWE78_SCAN_LIMITS = GoCwe78ScanLimits()


@dataclass(frozen=True, slots=True)
class GoCwe78Signal:
    """One source-free, deterministic input-to-``os/exec`` fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    detector: str = "securecode-go-cwe78@1.0"
    cwe: str = "CWE-78"
    detail: str = "untrusted_input_to_exec_command"
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
            and self.source.end_byte <= self.sink.end_byte
            and self.source.end_byte <= self.source_size_bytes
            and self.sink.end_byte <= self.source_size_bytes
            and self.detector == "securecode-go-cwe78@1.0"
            and self.cwe == "CWE-78"
            and self.detail == "untrusted_input_to_exec_command"
        )
        if valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid = False
        if not valid:
            raise ValueError("Go CWE-78 signal is invalid")
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
            raise ValueError("Go CWE-78 signal is invalid")
        if self.signal_id == "":
            object.__setattr__(self, "signal_id", expected_id)


@dataclass(frozen=True, slots=True)
class GoCwe78ScanResult:
    """Deterministic metadata and facts for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe78Signal, ...]
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
            or any(type(item) is not GoCwe78Signal for item in self.signals)
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
            raise ValueError("Go CWE-78 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange


def scan_go_cwe78(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe78ScanLimits = DEFAULT_GO_CWE78_SCAN_LIMITS,
) -> GoCwe78ScanResult:
    """Find bounded request or environment flows into Go exec constructors."""

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
        raise GoCwe78ScanError(GoCwe78ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    raw: list[tuple[SourceRange, SourceRange]] = []
    for scope in _scopes(root):
        environment: dict[str, tuple[_Flow, ...]] = {}
        for node in _scope_preorder(scope):
            if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                _capture_assignment(node, environment, source, imports, limits)
            if node.type != "call_expression":
                continue
            arguments = node.child_by_field_name("arguments")
            if arguments is None:
                continue
            for argument in _exec_arguments(node, arguments, source, imports):
                for flow in _resolve(argument, environment, source, imports, limits, 0):
                    raw.append((flow.source, _range(node)))
                    if len(raw) > limits.max_signals:
                        raise GoCwe78ScanError(GoCwe78ScanErrorCode.SIGNAL_LIMIT)

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
        raise GoCwe78ScanError(GoCwe78ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe78Signal(
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
    return GoCwe78ScanResult(
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


def scan_go_cwe78_command_injection(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe78ScanLimits = DEFAULT_GO_CWE78_SCAN_LIMITS,
) -> GoCwe78ScanResult:
    """Descriptive alias for :func:`scan_go_cwe78`."""

    return scan_go_cwe78(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe78ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe78ScanLimits:
        raise GoCwe78ScanError(GoCwe78ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe78ScanError(GoCwe78ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe78ScanError(GoCwe78ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe78ScanError(GoCwe78ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    relevant = {_EXEC_PACKAGE, _OS_PACKAGE} | _UTILITY_PACKAGES
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


def _exec_arguments(
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
    if imports.get(_text(source, operand)) != _EXEC_PACKAGE:
        return ()
    name = _text(source, field)
    if name not in _EXEC_FUNCTIONS:
        return ()
    values = arguments.named_children
    # CommandContext receives context first.  The remaining arguments are the
    # executable and its argv; a constant executable plus dynamic argv is
    # still a source-to-sink flow and is intentionally retained.
    return values[1:] if name == "CommandContext" else values


def _capture_assignment(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe78ScanLimits,
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
        environment[_text(source, name)] = _resolve(
            value, environment, source, imports, limits, 0
        )


def _resolve(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe78ScanLimits,
    depth: int,
    visited: frozenset[str] = frozenset(),
) -> tuple[_Flow, ...]:
    if depth > limits.max_expression_depth:
        raise GoCwe78ScanError(GoCwe78ScanErrorCode.SIGNAL_LIMIT)
    direct = _external_source(node, source, imports)
    if direct is not None:
        return (_Flow(_range(direct)),)
    if node.type == "identifier":
        name = _text(source, node)
        if name in visited:
            return ()
        return environment.get(name, ())
    if node.type in {
        "parenthesized_expression",
        "unary_expression",
        "pointer_expression",
        "type_conversion_expression",
        "variadic_expression",
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
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            return ()
        utility = _utility_function(function, source, imports)
        if utility is None:
            return ()
        values = arguments.named_children[1:] if utility == "fmt.Sprintf" else arguments.named_children
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
    if node.type in {
        "binary_expression",
        "composite_literal",
        "index_expression",
        "keyed_element",
        "slice_expression",
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
    field = function.child_by_field_name("field")
    operand = function.child_by_field_name("operand")
    if field is None or operand is None:
        return None
    name = _text(source, field)
    if name in _ENV_FUNCTIONS and imports.get(_compact_text(source, operand)) == _OS_PACKAGE:
        return node
    if name not in _REQUEST_FUNCTIONS:
        return None
    receiver = _compact_text(source, operand)
    if name in {"FormValue", "PostFormValue", "PathValue"}:
        return node
    if receiver.endswith(".URL.Query()") or receiver.endswith(".Form") or receiver.endswith(
        ".PostForm"
    ):
        return node
    return None


def _utility_function(
    function: Node | None, source: bytes, imports: dict[str, str]
) -> str | None:
    if function is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    package = imports.get(_text(source, operand))
    name = _text(source, field)
    if package == "fmt" and name in {"Sprintf", "Sprint", "Sprintln"}:
        return f"fmt.{name}"
    if package == "strings" and name in {
        "Join",
        "Replace",
        "ReplaceAll",
        "TrimSpace",
        "TrimPrefix",
        "TrimSuffix",
    }:
        return f"strings.{name}"
    return None


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


def _dedupe_flows(
    flows: Iterable[_Flow], limits: GoCwe78ScanLimits
) -> tuple[_Flow, ...]:
    unique: dict[tuple[int, int], _Flow] = {}
    for flow in flows:
        unique[(flow.source.start_byte, flow.source.end_byte)] = flow
        if len(unique) > limits.max_signals:
            raise GoCwe78ScanError(GoCwe78ScanErrorCode.SIGNAL_LIMIT)
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
        "cwe": "CWE-78",
        "detector": "securecode-go-cwe78@1.0",
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
    return "go-cwe78-" + digest


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe78Signal, ...],
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
    "DEFAULT_GO_CWE78_SCAN_LIMITS",
    "GoCwe78ScanError",
    "GoCwe78ScanErrorCode",
    "GoCwe78ScanLimits",
    "GoCwe78ScanResult",
    "GoCwe78Signal",
    "scan_go_cwe78",
    "scan_go_cwe78_command_injection",
]
