"""Bounded Go log-injection facts for CWE-117.

The scanner accepts one sealed Go ``SymbolIndex`` and follows only values
read from a typed ``*http.Request`` parameter into the standard library's
unstructured ``log`` output. It emits source-free, deterministic ranges.
Structured logging APIs and unknown logger wrappers are outside this adapter's
scope.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import ParseHealth, RepositoryFile, SourcePoint, SourceRange, SymbolIndex
from tree_sitter import Language, Node, Parser

from .cst import build_go_symbol_index
from .cst_go import _go_language

_MAX_LIMITS = (2_000_000, 2_048, 64, 100_000)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-go-cwe117"
_DETECTOR = "securecode-go-cwe117@1.0"
_DETAIL = "http_request_data_to_unstructured_log"
_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})
_LOG_METHODS = frozenset({"Print", "Printf", "Println", "Output"})
_SAFE_CALLS = frozenset(
    {
        "encoding/json.Marshal",
        "encoding/json.MarshalIndent",
        "strconv.Quote",
        "strconv.QuoteToASCII",
    }
)


class GoCwe117ScanErrorCode(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe117ScanError(RuntimeError):
    """Fixed scanner failure that does not disclose source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe117ScanErrorCode) -> None:
        if type(code) is not GoCwe117ScanErrorCode:
            raise TypeError("Go CWE-117 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-117 log-injection scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe117ScanLimits:
    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]
    max_nodes: int = _MAX_LIMITS[3]

    def __post_init__(self) -> None:
        values = (
            self.max_source_bytes,
            self.max_signals,
            self.max_expression_depth,
            self.max_nodes,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-117 scan limits are invalid")


DEFAULT_GO_CWE117_SCAN_LIMITS = GoCwe117ScanLimits()


class GoCwe117Operation(StrEnum):
    LOG_PRINT = "log.Print"
    LOG_PRINTF = "log.Printf"
    LOG_PRINTLN = "log.Println"
    LOG_OUTPUT = "log.Output"
    LOGGER_PRINT = "log.Logger.Print"
    LOGGER_PRINTF = "log.Logger.Printf"
    LOGGER_PRINTLN = "log.Logger.Println"
    LOGGER_OUTPUT = "log.Logger.Output"


@dataclass(frozen=True, slots=True)
class GoCwe117Signal:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe117Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-117"
    detector: str = _DETECTOR
    detail: str = _DETAIL

    def __post_init__(self) -> None:
        identity = (
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
        if identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity = False
        ranges = (
            type(self.source) is SourceRange
            and type(self.sink) is SourceRange
            and self.sink.contains(self.source)
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
            if identity and ranges and type(self.operation) is GoCwe117Operation
            else None
        )
        actual = self.signal_id or expected
        if (
            not identity
            or not ranges
            or expected is None
            or type(actual) is not str
            or _SHA256.fullmatch(actual) is None
            or actual != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-117"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-117 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", expected)

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
class GoCwe117ScanResult:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe117Signal, ...]
    scan_sha256: str

    def __post_init__(self) -> None:
        identity = (
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
        if identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity = False
        valid = type(self.signals) is tuple and all(
            type(item) is GoCwe117Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    s.sink.start_byte,
                    s.sink.end_byte,
                    s.source.start_byte,
                    s.source.end_byte,
                    s.operation.value,
                )
                for s in self.signals
            )
            if valid
            else ()
        )
        same = valid and all(
            (s.repository_id, s.revision, s.path, s.content_sha256, s.source_size_bytes)
            == (
                self.repository_id,
                self.revision,
                self.path,
                self.content_sha256,
                self.source_size_bytes,
            )
            for s in self.signals
        )
        if (
            not identity
            or not valid
            or not same
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
            or len({s.signal_id for s in self.signals}) != len(self.signals)
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
            raise ValueError("Go CWE-117 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange
    safe: bool = False


def scan_go_cwe117(
    symbol_index: SymbolIndex, *, limits: GoCwe117ScanLimits = DEFAULT_GO_CWE117_SCAN_LIMITS
) -> GoCwe117ScanResult:
    """Find bounded request-derived values reaching standard unstructured logs."""
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe117ScanLimits:
        raise GoCwe117ScanError(GoCwe117ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe117ScanError(GoCwe117ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe117ScanError(GoCwe117ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe117ScanError(GoCwe117ScanErrorCode.ANALYSIS_UNAVAILABLE)
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
            raise ValueError
        source.decode("utf-8", errors="strict")
        root = Parser(Language(_go_language())).parse(source).root_node
        if root.has_error:
            raise ValueError
        nodes = _walk(root, limits.max_nodes)
    except _TraversalLimit:
        raise GoCwe117ScanError(GoCwe117ScanErrorCode.NODE_LIMIT) from None
    except Exception:
        raise GoCwe117ScanError(GoCwe117ScanErrorCode.INTEGRITY_FAILURE) from None
    imports = _imports(nodes, source)
    raw: set[tuple[SourceRange, SourceRange, GoCwe117Operation]] = set()
    try:
        for scope in (node for node in nodes if node.type in _SCOPES):
            requests = _request_parameters(scope, source, imports)
            if not requests:
                continue
            env: dict[str, tuple[_Flow, ...]] = {}
            logger_names = _logger_names(scope, source, imports, limits)
            for node in _scope_nodes(scope, limits.max_nodes):
                if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                    _assign(node, env, requests, source, imports, limits)
                if node.type != "call_expression":
                    continue
                operation = _sink(node, source, imports, logger_names)
                if operation is None:
                    continue
                args = node.child_by_field_name("arguments")
                if args is None:
                    continue
                values = tuple(args.named_children)
                for arg_index, arg in enumerate(values):
                    flows = _resolve(arg, env, requests, source, imports, limits, 0)
                    for flow in flows:
                        if flow.safe:
                            continue
                        if operation in {
                            GoCwe117Operation.LOG_PRINTF,
                            GoCwe117Operation.LOGGER_PRINTF,
                        } and _printf_argument_safe(values, arg_index, source):
                            continue
                        raw.add((flow.source, _range(node), operation))
                        if len(raw) > limits.max_signals:
                            raise GoCwe117ScanError(GoCwe117ScanErrorCode.SIGNAL_LIMIT)
    except GoCwe117ScanError:
        raise
    except _TraversalLimit:
        raise GoCwe117ScanError(GoCwe117ScanErrorCode.NODE_LIMIT) from None
    except Exception:
        raise GoCwe117ScanError(GoCwe117ScanErrorCode.INTEGRITY_FAILURE) from None
    ordered = sorted(
        raw,
        key=lambda x: (x[1].start_byte, x[1].end_byte, x[0].start_byte, x[0].end_byte, x[2].value),
    )
    signals = tuple(
        GoCwe117Signal(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            src,
            sink,
            op,
        )
        for src, sink, op in ordered
    )
    return GoCwe117ScanResult(
        symbol_index.repository_id,
        symbol_index.revision,
        symbol_index.path,
        symbol_index.content_sha256,
        symbol_index.source_byte_length,
        signals,
        _scan_sha256(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            signals,
        ),
    )


def _imports(nodes: tuple[Node, ...], source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in nodes:
        if node.type != "import_spec":
            continue
        path = node.child_by_field_name("path")
        if path is None:
            continue
        package = _text(source, path).strip('"`')
        alias_node = node.child_by_field_name("name")
        alias = _text(source, alias_node) if alias_node else package.rsplit("/", 1)[-1]
        if package in {
            "net/http",
            "log",
            "encoding/json",
            "strconv",
            "fmt",
            "io",
        } and alias not in {".", "_"}:
            aliases[alias] = package
    return aliases


def _request_parameters(scope: Node, source: bytes, imports: dict[str, str]) -> set[str]:
    params = scope.child_by_field_name("parameters")
    if params is None:
        return set()
    http_aliases = {alias for alias, package in imports.items() if package == "net/http"}
    names: set[str] = set()
    for declaration in params.named_children:
        if declaration.type != "parameter_declaration":
            continue
        type_node = declaration.child_by_field_name("type")
        if type_node is None:
            continue
        type_text = "".join(_text(source, type_node).split())
        if not any(type_text == f"*{alias}.Request" for alias in http_aliases):
            continue
        name_node = declaration.child_by_field_name("name")
        if name_node is not None:
            names.update(
                _text(source, item)
                for item in name_node.named_children
                if item.type == "identifier"
            )
    return names


def _logger_names(
    scope: Node, source: bytes, imports: dict[str, str], limits: GoCwe117ScanLimits
) -> frozenset[str]:
    names: set[str] = set()
    for node in _scope_nodes(scope, limits.max_nodes):
        if node.type not in {"short_var_declaration", "assignment_statement", "var_spec"}:
            continue
        left, right = _assignment_parts(node)
        if left is None or right is None:
            continue
        for name, value in zip(_children_or_self(left), _children_or_self(right), strict=False):
            if name.type == "identifier" and _call_package(value, source, imports) == (
                "log",
                "New",
            ):
                names.add(_text(source, name))
    return frozenset(names)


def _assign(
    node: Node,
    env: dict[str, tuple[_Flow, ...]],
    requests: set[str],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe117ScanLimits,
) -> None:
    left, right = _assignment_parts(node)
    if left is None or right is None:
        return
    names, values = _children_or_self(left), _children_or_self(right)
    if len(names) > limits.max_signals or len(values) > limits.max_signals:
        raise GoCwe117ScanError(GoCwe117ScanErrorCode.SIGNAL_LIMIT)
    for name, value in zip(names, values, strict=False):
        if name.type != "identifier":
            continue
        key = _text(source, name)
        if _request_chain(value, requests, source):
            requests.add(key)
        elif key in requests:
            requests.discard(key)
        resolved = _resolve(value, env, requests, source, imports, limits, 0)
        if resolved:
            env[key] = _dedupe(resolved)
        else:
            env.pop(key, None)


def _resolve(
    node: Node,
    env: dict[str, tuple[_Flow, ...]],
    requests: set[str],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe117ScanLimits,
    depth: int,
) -> tuple[_Flow, ...]:
    if depth > limits.max_expression_depth:
        raise GoCwe117ScanError(GoCwe117ScanErrorCode.SIGNAL_LIMIT)
    if node.type in {"identifier", "field_identifier"}:
        return env.get(_text(source, node), ())
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        arguments = tuple(args.named_children) if args is not None else ()
        package, method = _call_package(function, source, imports) if function else ("", "")
        if (package, method) in {
            ("encoding/json", "Marshal"),
            ("encoding/json", "MarshalIndent"),
            ("strconv", "Quote"),
            ("strconv", "QuoteToASCII"),
        } or (package == "fmt" and method == "Sprintf" and _safe_printf(arguments, source)):
            return tuple(
                _Flow(flow.source, True)
                for arg in arguments
                for flow in _resolve(arg, env, requests, source, imports, limits, depth + 1)
            )
        if _request_source(node, requests, source, imports):
            return (_Flow(_range(node)),)
        if function is not None and _request_chain(function, requests, source):
            return (_Flow(_range(node)),)
        return _combine(
            _resolve(arg, env, requests, source, imports, limits, depth + 1) for arg in arguments
        )
    if _request_chain(node, requests, source):
        return (_Flow(_range(node)),)
    if node.type in {
        "interpreted_string_literal",
        "raw_string_literal",
        "int_literal",
        "rune_literal",
    }:
        return ()
    if node.type in {
        "parenthesized_expression",
        "selector_expression",
        "index_expression",
        "binary_expression",
        "expression_list",
        "composite_literal",
        "keyed_element",
        "unary_expression",
        "pointer_expression",
        "slice_expression",
    }:
        return _combine(
            _resolve(child, env, requests, source, imports, limits, depth + 1)
            for child in node.named_children
        )
    return ()


def _request_source(node: Node, requests: set[str], source: bytes, imports: dict[str, str]) -> bool:
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return False
    field = function.child_by_field_name("field")
    name = _text(source, field) if field else ""
    package, imported_name = _call_package(function, source, imports)
    if (package, imported_name) == ("io", "ReadAll"):
        args = node.child_by_field_name("arguments")
        return args is not None and any(
            _body_chain(arg, requests, source) for arg in args.named_children
        )
    if name not in {"Get", "PostFormValue", "FormValue", "Cookie", "PathValue", "ReadAll"}:
        return False
    return _request_chain(function.child_by_field_name("operand"), requests, source)


def _request_chain(node: Node | None, requests: set[str], source: bytes) -> bool:
    if node is None:
        return False
    if node.type == "identifier":
        return _text(source, node) in requests
    if node.type == "selector_expression":
        field = node.child_by_field_name("field")
        operand = node.child_by_field_name("operand")
        return _text(source, field) in {
            "URL",
            "Header",
            "Form",
            "PostForm",
            "Host",
            "RemoteAddr",
            "Method",
            "Path",
            "RawPath",
            "RawQuery",
            "RequestURI",
            "Fragment",
        } and _request_chain(operand, requests, source)
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        if function is not None and function.type == "selector_expression":
            field = function.child_by_field_name("field")
            operand = function.child_by_field_name("operand")
            return _text(source, field) in {"Query", "Get", "ReadAll"} and _request_chain(
                operand, requests, source
            )
    return False


def _body_chain(node: Node, requests: set[str], source: bytes) -> bool:
    if node.type != "selector_expression":
        return False
    field = node.child_by_field_name("field")
    operand = node.child_by_field_name("operand")
    return (
        field is not None
        and _text(source, field) == "Body"
        and operand is not None
        and operand.type == "identifier"
        and _text(source, operand) in requests
    )


def _sink(
    node: Node, source: bytes, imports: dict[str, str], logger_names: frozenset[str]
) -> GoCwe117Operation | None:
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    method = _text(source, field)
    if method not in _LOG_METHODS:
        return None
    package = imports.get(_text(source, operand)) if operand.type == "identifier" else None
    if package == "log":
        return GoCwe117Operation(f"log.{method}")
    if _text(source, operand) in logger_names:
        return GoCwe117Operation(f"log.Logger.{method}")
    return None


def _call_package(node: Node | None, source: bytes, imports: dict[str, str]) -> tuple[str, str]:
    if node is not None and node.type == "call_expression":
        node = node.child_by_field_name("function")
    if node is None or node.type != "selector_expression":
        return "", ""
    operand, field = node.child_by_field_name("operand"), node.child_by_field_name("field")
    if operand is None or field is None or operand.type != "identifier":
        return "", ""
    return imports.get(_text(source, operand), ""), _text(source, field)


def _printf_argument_safe(args: tuple[Node, ...], index: int, source: bytes) -> bool:
    if index == 0 or not args:
        return False
    fmt_node = args[0]
    if fmt_node.type not in {"interpreted_string_literal", "raw_string_literal"}:
        return False
    literal = _text(source, fmt_node)
    try:
        fmt = literal[1:-1] if literal.startswith("`") else json.loads(literal)
    except (ValueError, TypeError):
        return False
    if not isinstance(fmt, str):
        return False
    if "%[" in fmt or "*" in fmt:
        return False
    conversions = re.findall(r"%(?:%|[-+# 0]*\d*(?:\.\d*)?([a-zA-Z]))", fmt)
    return index <= len(conversions) and conversions[index - 1] == "q"


def _safe_printf(args: tuple[Node, ...], source: bytes) -> bool:
    if not args or args[0].type not in {"interpreted_string_literal", "raw_string_literal"}:
        return False
    literal = _text(source, args[0])
    try:
        fmt = literal[1:-1] if literal.startswith("`") else json.loads(literal)
    except (ValueError, TypeError):
        return False
    if not isinstance(fmt, str) or "%[" in fmt or "*" in fmt:
        return False
    conversions = re.findall(r"%(?:%|[-+# 0]*\d*(?:\.\d*)?([a-zA-Z]))", fmt)
    return (
        bool(conversions)
        and all(verb == "q" for verb in conversions)
        and len(args) - 1 <= len(conversions)
    )


def _assignment_parts(node: Node) -> tuple[Node | None, Node | None]:
    if node.type == "var_spec":
        return node.child_by_field_name("name"), node.child_by_field_name("value")
    return node.child_by_field_name("left"), node.child_by_field_name("right")


def _children_or_self(node: Node) -> tuple[Node, ...]:
    return tuple(node.named_children) or (node,)


def _scope_nodes(scope: Node, ceiling: int) -> tuple[Node, ...]:
    out: list[Node] = []
    stack = [scope]
    while stack:
        node = stack.pop()
        out.append(node)
        if len(out) > ceiling:
            raise _TraversalLimit
        if node is not scope and node.type in _SCOPES:
            continue
        stack.extend(reversed(node.named_children))
    return tuple(out)


def _walk(root: Node, ceiling: int) -> tuple[Node, ...]:
    out: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        out.append(node)
        if len(out) > ceiling:
            raise _TraversalLimit
        stack.extend(reversed(node.named_children))
    return tuple(out)


class _TraversalLimit(Exception):
    pass


def _combine(groups: Iterable[Iterable[_Flow]]) -> tuple[_Flow, ...]:
    return _dedupe(flow for group in groups for flow in group)


def _dedupe(flows: Iterable[_Flow]) -> tuple[_Flow, ...]:
    values: dict[tuple[int, int, bool], _Flow] = {}
    for flow in flows:
        values[(flow.source.start_byte, flow.source.end_byte, flow.safe)] = flow
    return tuple(values[key] for key in sorted(values))


def _text(source: bytes, node: Node | None) -> str:
    return (
        ""
        if node is None
        else source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    )


def _range(node: Node) -> SourceRange:
    return SourceRange(
        node.start_byte,
        node.end_byte,
        SourcePoint(node.start_point.row, node.start_point.column),
        SourcePoint(node.end_point.row, node.end_point.column),
    )


def _range_value(value: SourceRange) -> dict[str, int]:
    return {
        "end_byte": value.end_byte,
        "end_column": value.end_point.column,
        "end_row": value.end_point.row,
        "start_byte": value.start_byte,
        "start_column": value.start_point.column,
        "start_row": value.start_point.row,
    }


def _signal_id(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size: int,
    source: SourceRange,
    sink: SourceRange,
    operation: GoCwe117Operation,
) -> str:
    payload = {
        "content_sha256": content_sha256,
        "cwe": "CWE-117",
        "detector": _DETECTOR,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "sink": _range_value(sink),
        "source": _range_value(source),
        "source_size_bytes": source_size,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size: int,
    signals: tuple[GoCwe117Signal, ...],
) -> str:
    payload = {
        "content_sha256": content_sha256,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "cwe": s.cwe,
                "detail": s.detail,
                "detector": s.detector,
                "operation": s.operation.value,
                "signal_id": s.signal_id,
                "sink": _range_value(s.sink),
                "source": _range_value(s.source),
            }
            for s in signals
        ],
        "source_size_bytes": source_size,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


Cwe117ScanError = GoCwe117ScanError
Cwe117ScanErrorCode = GoCwe117ScanErrorCode
Cwe117ScanLimits = GoCwe117ScanLimits
Cwe117ScanResult = GoCwe117ScanResult
Cwe117Signal = GoCwe117Signal
scan_go_log_injection = scan_go_cwe117

__all__ = [
    "DEFAULT_GO_CWE117_SCAN_LIMITS",
    "Cwe117ScanError",
    "Cwe117ScanErrorCode",
    "Cwe117ScanLimits",
    "Cwe117ScanResult",
    "Cwe117Signal",
    "GoCwe117Operation",
    "GoCwe117ScanError",
    "GoCwe117ScanErrorCode",
    "GoCwe117ScanLimits",
    "GoCwe117ScanResult",
    "GoCwe117Signal",
    "scan_go_cwe117",
    "scan_go_log_injection",
]
