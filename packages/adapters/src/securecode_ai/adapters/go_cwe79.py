"""Bounded Go cross-site-scripting facts for CWE-79.

The scanner consumes one admitted, sealed Go :class:`SymbolIndex` and emits
immutable source ranges with content-addressed metadata.  It follows request
values into explicit unsafe ``html/template`` conversions, response-writer
output, and ``text/template`` execution.  ``html/template`` execution and its
escaping helpers are treated as safe boundaries.  Source bytes are needed for
the CST walk but are never copied into a result or an error message.
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
_RULE_ID = "securecode-go-cwe79"
_DETECTOR = "securecode-go-cwe79@1.0"

_HTML_TEMPLATE = "html/template"
_TEXT_TEMPLATE = "text/template"
_HTML_PACKAGE = "html"
_FMT_PACKAGE = "fmt"
_IO_PACKAGE = "io"
_STRINGS_PACKAGE = "strings"
_HTTP_PACKAGE = "net/http"
_RELEVANT_PACKAGES = frozenset(
    {
        _HTML_TEMPLATE,
        _TEXT_TEMPLATE,
        _HTML_PACKAGE,
        _FMT_PACKAGE,
        _IO_PACKAGE,
        _STRINGS_PACKAGE,
        _HTTP_PACKAGE,
    }
)
_REQUEST_METHODS = frozenset({"FormValue", "PostFormValue", "PathValue"})
_REQUEST_GET_METHODS = frozenset({"Get", "Lookup"})
_ESCAPE_FUNCTIONS = frozenset(
    {
        "EscapeString",
        "HTMLEscape",
        "HTMLEscapeString",
        "JSEscape",
        "JSEscapeString",
        "URLQueryEscaper",
    }
)
_HTML_CONVERSIONS: dict[str, GoCwe79Operation] = {}
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})


class GoCwe79ScanErrorCode(StrEnum):
    """Closed, source-free reasons why an XSS fact cannot be emitted."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe79ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe79ScanErrorCode) -> None:
        if type(code) is not GoCwe79ScanErrorCode:
            raise TypeError("Go CWE-79 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-79 XSS scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class GoCwe79Operation(StrEnum):
    """Recognized unsafe HTML output boundaries."""

    UNSAFE_HTML_CONVERSION = "unsafe_html_conversion"
    UNSAFE_HTML_ATTR_CONVERSION = "unsafe_html_attr_conversion"
    UNSAFE_JS_CONVERSION = "unsafe_js_conversion"
    RAW_RESPONSE_WRITE = "raw_response_write"
    RAW_FORMATTED_RESPONSE_WRITE = "raw_formatted_response_write"
    TEXT_TEMPLATE_EXECUTE = "text_template_execute"
    TEXT_TEMPLATE_EXECUTE_TEMPLATE = "text_template_execute_template"


_HTML_CONVERSIONS.update(
    {
        "HTML": GoCwe79Operation.UNSAFE_HTML_CONVERSION,
        "HTMLAttr": GoCwe79Operation.UNSAFE_HTML_ATTR_CONVERSION,
        "JS": GoCwe79Operation.UNSAFE_JS_CONVERSION,
    }
)


@dataclass(frozen=True, slots=True)
class GoCwe79ScanLimits:
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
            raise ValueError("Go CWE-79 scan limits are invalid")


DEFAULT_GO_CWE79_SCAN_LIMITS = GoCwe79ScanLimits()


@dataclass(frozen=True, slots=True)
class GoCwe79Signal:
    """One immutable request-to-HTML sink fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe79Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-79"
    detector: str = _DETECTOR
    detail: str = "untrusted_input_to_html"

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
        ranges_valid = (
            type(self.source) is SourceRange
            and type(self.sink) is SourceRange
            and self.source.end_byte <= self.sink.end_byte
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
            if valid_identity and ranges_valid and type(self.operation) is GoCwe79Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not ranges_valid
            or type(self.operation) is not GoCwe79Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-79"
            or self.detector != _DETECTOR
            or self.detail != "untrusted_input_to_html"
        ):
            raise ValueError("Go CWE-79 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete HTML sink location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class GoCwe79ScanResult:
    """Deterministic, source-free CWE-79 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe79Signal, ...]
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
            type(item) is GoCwe79Signal for item in self.signals
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
            raise ValueError("Go CWE-79 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange


def scan_go_cwe79(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe79ScanLimits = DEFAULT_GO_CWE79_SCAN_LIMITS,
) -> GoCwe79ScanResult:
    """Find bounded request flows into unsafe Go HTML output boundaries."""

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
        raise GoCwe79ScanError(GoCwe79ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    raw: set[tuple[SourceRange, SourceRange, GoCwe79Operation]] = set()
    for scope in _scopes(root):
        environment: dict[str, tuple[_Flow, ...]] = {}
        templates: dict[str, str] = {}
        response_writers = _response_writer_names(scope, source, imports)
        for node in _scope_preorder(scope):
            if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                _capture_assignment(
                    node,
                    environment,
                    templates,
                    response_writers,
                    source,
                    imports,
                    limits,
                )
            if node.type != "call_expression":
                continue
            operation, arguments = _sink_for_call(
                node, source, imports, templates, response_writers
            )
            if operation is None:
                continue
            for argument in arguments:
                for flow in _resolve(
                    argument, environment, source, imports, limits, 0, frozenset()
                ):
                    sink_range = _range(node)
                    if flow.source.end_byte > sink_range.end_byte:
                        raise GoCwe79ScanError(GoCwe79ScanErrorCode.INTEGRITY_FAILURE)
                    raw.add((flow.source, sink_range, operation))
                    if len(raw) > limits.max_signals:
                        raise GoCwe79ScanError(GoCwe79ScanErrorCode.SIGNAL_LIMIT)

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
        raise GoCwe79ScanError(GoCwe79ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe79Signal(
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
    return GoCwe79ScanResult(
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


def scan_go_cwe79_xss(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe79ScanLimits = DEFAULT_GO_CWE79_SCAN_LIMITS,
) -> GoCwe79ScanResult:
    """Descriptive alias for :func:`scan_go_cwe79`."""

    return scan_go_cwe79(symbol_index, limits=limits)


def scan_go_xss(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe79ScanLimits = DEFAULT_GO_CWE79_SCAN_LIMITS,
) -> GoCwe79ScanResult:
    """Compatibility alias for callers grouping Go XSS scanners."""

    return scan_go_cwe79(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe79ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe79ScanLimits:
        raise GoCwe79ScanError(GoCwe79ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe79ScanError(GoCwe79ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe79ScanError(GoCwe79ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe79ScanError(GoCwe79ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        package = _text(source, path_node).strip('"`')
        if package not in _RELEVANT_PACKAGES:
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
    templates: dict[str, str],
    response_writers: set[str],
) -> tuple[GoCwe79Operation | None, tuple[Node, ...]]:
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None:
        return None, ()
    values = tuple(arguments.named_children)
    qualified = _qualified_call(function, source, imports)
    if qualified.startswith("html/template."):
        conversion_name = qualified.rsplit(".", 1)[-1]
        operation = _HTML_CONVERSIONS.get(conversion_name)
        if operation is not None:
            return operation, values[:1]
    method = _method_name(function, source)
    receiver = _receiver_text(function, source)
    if method == "Write" and _is_response_writer(receiver, response_writers):
        return GoCwe79Operation.RAW_RESPONSE_WRITE, values[:1]
    if (
        qualified in {"fmt.Fprint", "fmt.Fprintln", "io.WriteString"}
        and values
        and _is_response_writer(_compact_text(source, values[0]), response_writers)
    ):
        return GoCwe79Operation.RAW_FORMATTED_RESPONSE_WRITE, values[1:]
    if (
        qualified == "fmt.Fprintf"
        and values
        and _is_response_writer(_compact_text(source, values[0]), response_writers)
    ):
        return GoCwe79Operation.RAW_FORMATTED_RESPONSE_WRITE, values[2:]
    if method in {"Execute", "ExecuteTemplate"}:
        receiver_node = function.child_by_field_name("operand")
        package = (
            _template_kind(receiver_node, source, imports, templates)
            if receiver_node is not None
            else None
        )
        if package == _TEXT_TEMPLATE:
            if method == "Execute":
                return GoCwe79Operation.TEXT_TEMPLATE_EXECUTE, values[1:2]
            return GoCwe79Operation.TEXT_TEMPLATE_EXECUTE_TEMPLATE, values[2:3]
    return None, ()


def _capture_assignment(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    templates: dict[str, str],
    response_writers: set[str],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe79ScanLimits,
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
        template_kind = _template_kind(value, source, imports, templates)
        if template_kind is not None:
            templates[name_text] = template_kind
        else:
            templates.pop(name_text, None)
        if _is_response_writer_value(value, source, response_writers):
            response_writers.add(name_text)
        elif name_text in response_writers:
            response_writers.remove(name_text)


def _response_writer_names(scope: Node, source: bytes, imports: dict[str, str]) -> set[str]:
    names: set[str] = set()
    http_aliases = tuple(alias for alias, package in imports.items() if package == _HTTP_PACKAGE)
    for node in _preorder(scope):
        if node.type != "parameter_declaration":
            continue
        type_node = node.child_by_field_name("type")
        names_node = node.child_by_field_name("name")
        if type_node is None or names_node is None:
            continue
        type_text = _compact_text(source, type_node)
        if not any(f"{alias}.ResponseWriter" in type_text for alias in http_aliases):
            continue
        for name in names_node.named_children or (names_node,):
            if name.type == "identifier":
                names.add(_text(source, name))
    return names


def _is_response_writer_value(node: Node, source: bytes, names: set[str]) -> bool:
    if node.type == "identifier":
        return _text(source, node) in names
    if node.type in {"parenthesized_expression", "pointer_expression"}:
        return any(_is_response_writer_value(child, source, names) for child in node.named_children)
    return False


def _is_response_writer(receiver: str, names: set[str]) -> bool:
    compact = receiver.removeprefix("&")
    return compact in names


def _template_kind(
    node: Node,
    source: bytes,
    imports: dict[str, str],
    templates: dict[str, str],
) -> str | None:
    if node.type == "identifier":
        return templates.get(_text(source, node))
    if node.type == "parenthesized_expression":
        return next(
            (
                kind
                for child in node.named_children
                if (kind := _template_kind(child, source, imports, templates))
            ),
            None,
        )
    if node.type != "call_expression":
        return None
    function = node.child_by_field_name("function")
    if function is None:
        return None
    qualified = _qualified_call(function, source, imports)
    if qualified in {"html/template.New", "text/template.New"}:
        return qualified.split("/", 1)[0] + "/template"
    if qualified in {"html/template.Must", "text/template.Must"}:
        args = node.child_by_field_name("arguments")
        if args is None:
            return None
        return next(
            (
                kind
                for child in args.named_children
                if (kind := _template_kind(child, source, imports, templates))
            ),
            None,
        )
    if function.type == "selector_expression":
        receiver = function.child_by_field_name("operand")
        method = _method_name(function, source)
        if receiver is not None and method in {"Parse", "ParseFiles", "ParseGlob"}:
            return _template_kind(receiver, source, imports, templates)
    return None


def _resolve(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe79ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[_Flow, ...]:
    if depth > limits.max_expression_depth:
        raise GoCwe79ScanError(GoCwe79ScanErrorCode.SIGNAL_LIMIT)
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
    if node.type in {
        "parenthesized_expression",
        "unary_expression",
        "pointer_expression",
        "type_conversion_expression",
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
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            return ()
        if _is_sanitizer(node, source, imports):
            return ()
        qualified = _qualified_call(function, source, imports)
        if qualified in {
            "fmt.Sprintf",
            "fmt.Sprint",
            "fmt.Sprintln",
            "strings.Join",
            "strings.Replace",
            "strings.ReplaceAll",
            "strings.TrimSpace",
            "strings.TrimPrefix",
            "strings.TrimSuffix",
        }:
            values = (
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
        return ()
    if node.type in {
        "binary_expression",
        "index_expression",
        "slice_expression",
        "selector_expression",
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
        if prefix.endswith((".URL.Query()", ".Form", ".PostForm", ".Header")):
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
    if name in _REQUEST_GET_METHODS and receiver.endswith(
        (".URL.Query()", ".Form", ".PostForm", ".Header")
    ):
        return node
    return None


def _is_sanitizer(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    qualified = _qualified_call(node.child_by_field_name("function"), source, imports)
    package, _, name = qualified.rpartition(".")
    return (package == _HTML_PACKAGE and name == "EscapeString") or (
        package == _HTML_TEMPLATE and name in _ESCAPE_FUNCTIONS
    )


def _qualified_call(function: Node | None, source: bytes, imports: dict[str, str]) -> str:
    if function is None or function.type != "selector_expression":
        return ""
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return ""
    package = imports.get(_text(source, operand))
    if package not in _RELEVANT_PACKAGES:
        return ""
    return f"{package}.{_text(source, field)}"


def _method_name(function: Node, source: bytes) -> str:
    if function.type != "selector_expression":
        return ""
    field = function.child_by_field_name("field")
    return _text(source, field) if field is not None else ""


def _receiver_text(function: Node, source: bytes) -> str:
    if function.type != "selector_expression":
        return ""
    operand = function.child_by_field_name("operand")
    return _compact_text(source, operand)


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


def _dedupe_flows(flows: Iterable[_Flow], limits: GoCwe79ScanLimits) -> tuple[_Flow, ...]:
    unique: dict[tuple[int, int], _Flow] = {}
    for flow in flows:
        unique[(flow.source.start_byte, flow.source.end_byte)] = flow
        if len(unique) > limits.max_signals:
            raise GoCwe79ScanError(GoCwe79ScanErrorCode.SIGNAL_LIMIT)
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
    operation: GoCwe79Operation,
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe79Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-79",
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
    "DEFAULT_GO_CWE79_SCAN_LIMITS",
    "GoCwe79Operation",
    "GoCwe79ScanError",
    "GoCwe79ScanErrorCode",
    "GoCwe79ScanLimits",
    "GoCwe79ScanResult",
    "GoCwe79Signal",
    "scan_go_cwe79",
    "scan_go_cwe79_xss",
    "scan_go_xss",
]
