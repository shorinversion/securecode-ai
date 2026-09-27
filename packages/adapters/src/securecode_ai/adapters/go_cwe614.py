"""Bounded Go facts for security-sensitive cookies without ``Secure``.

The detector accepts one caller-admitted, sealed Go :class:`SymbolIndex` and
rebuilds it before walking the same tree-sitter grammar.  It recognises the
standard library ``net/http.SetCookie`` sink and a small, explicit set of
session and authentication cookie names.  A finding is emitted only when the
cookie name is a static sensitive name and the ``Secure`` field is absent or
the literal ``false``.  Unknown expressions are suppressed because their
security state cannot be proved by this bounded analysis.

Returned objects contain immutable ranges and content-addressed metadata only.
The scanner never imports or executes repository code, retains source text, or
places source text in an error.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
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
_RULE_ID = "securecode-go-cwe614"
_DETECTOR = "securecode-go-cwe614@1.0"
_DETAIL = "sensitive_cookie_without_secure_flag"
_HTTP_PACKAGE = "net/http"
_COOKIE_TYPE = "Cookie"
_SET_COOKIE = "SetCookie"
_SENSITIVE_NAME = frozenset(
    {
        "session",
        "sessionid",
        "session_id",
        "sessid",
        "sid",
        "auth",
        "authn",
        "authz",
        "authtoken",
        "access_token",
        "refresh_token",
        "id_token",
        "token",
        "jwt",
        "credential",
        "credentials",
        "identity",
        "login",
        "remember",
        "remember_me",
        "csrf",
        "oauth",
    }
)
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})


class GoCwe614ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-614 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe614ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe614ScanErrorCode) -> None:
        if type(code) is not GoCwe614ScanErrorCode:
            raise TypeError("Go CWE-614 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-614 cookie-security scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe614ScanLimits:
    """Hard ceilings applied before and during structural analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-614 scan limits are invalid")


DEFAULT_GO_CWE614_SCAN_LIMITS = GoCwe614ScanLimits()


class GoCwe614Operation(StrEnum):
    """Recognised standard-library cookie security failures."""

    HTTP_COOKIE_WITHOUT_SECURE = "net/http.Cookie_without_secure"
    HTTP_COOKIE_SECURE_FALSE = "net/http.Cookie.Secure=false"

    # Compatibility names used by generic finding consumers.
    WITHOUT_SECURE = "net/http.Cookie_without_secure"
    SECURE_FALSE = "net/http.Cookie.Secure=false"


class _SecureState(StrEnum):
    MISSING = "missing"
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class GoCwe614Signal:
    """One immutable source-free sensitive-cookie security fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe614Operation
    cookie_name: str
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-614"
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
            and type(self.cookie_name) is str
            and 0 < len(self.cookie_name) <= 256
        )
        if valid_identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid_identity = False
        ranges_valid = (
            type(self.source) is SourceRange
            and type(self.sink) is SourceRange
            and self.sink.contains(self.source)
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
                self.cookie_name,
            )
            if valid_identity
            and ranges_valid
            and type(self.operation) is GoCwe614Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not ranges_valid
            or type(self.operation) is not GoCwe614Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-614"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-614 signal is invalid")
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
class GoCwe614ScanResult:
    """Deterministic, source-free output for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe614Signal, ...]
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
            type(item) is GoCwe614Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    item.sink.start_byte,
                    item.sink.end_byte,
                    item.source.start_byte,
                    item.source.end_byte,
                    item.operation.value,
                    item.cookie_name,
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
            raise ValueError("Go CWE-614 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _CookieInfo:
    literal: SourceRange
    name_location: SourceRange
    cookie_name: str
    secure_state: _SecureState


def scan_go_cwe614(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe614ScanLimits = DEFAULT_GO_CWE614_SCAN_LIMITS,
) -> GoCwe614ScanResult:
    """Find sensitive cookies emitted by ``http.SetCookie`` without Secure."""

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
        _bounded_preorder(root, limits.max_expression_depth)
    except GoCwe614ScanError:
        raise
    except Exception:
        raise GoCwe614ScanError(GoCwe614ScanErrorCode.INTEGRITY_FAILURE) from None

    raw: set[tuple[SourceRange, SourceRange, GoCwe614Operation, str]] = set()
    try:
        for scope in _scopes(root):
            scope_nodes = _scope_preorder(scope)
            imports = _import_aliases(root, source)
            bindings = _cookie_bindings(scope_nodes, source, imports)
            secure_updates = _secure_assignments(scope_nodes, source)
            for node in scope_nodes:
                if node.type != "call_expression":
                    continue
                _collect_set_cookie_call(
                    node,
                    source,
                    imports,
                    bindings,
                    secure_updates,
                    raw,
                )
                if len(raw) > limits.max_signals:
                    raise GoCwe614ScanError(GoCwe614ScanErrorCode.SIGNAL_LIMIT)
    except GoCwe614ScanError:
        raise
    except Exception:
        raise GoCwe614ScanError(GoCwe614ScanErrorCode.INTEGRITY_FAILURE) from None

    ordered = sorted(
        raw,
        key=lambda item: (
            item[1].start_byte,
            item[1].end_byte,
            item[0].start_byte,
            item[0].end_byte,
            item[2].value,
            item[3],
        ),
    )
    if len(ordered) > limits.max_signals:
        raise GoCwe614ScanError(GoCwe614ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe614Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
            cookie_name=cookie_name,
            signal_id=_signal_id(
                symbol_index.repository_id,
                symbol_index.revision,
                symbol_index.path,
                symbol_index.content_sha256,
                symbol_index.source_byte_length,
                source_range,
                sink_range,
                operation,
                cookie_name,
            ),
        )
        for source_range, sink_range, operation, cookie_name in ordered
    )
    return GoCwe614ScanResult(
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


def scan_go_cookie_security(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe614ScanLimits = DEFAULT_GO_CWE614_SCAN_LIMITS,
) -> GoCwe614ScanResult:
    """Descriptive alias for :func:`scan_go_cwe614`."""

    return scan_go_cwe614(symbol_index, limits=limits)


def scan_go_cwe614_cookie_security(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe614ScanLimits = DEFAULT_GO_CWE614_SCAN_LIMITS,
) -> GoCwe614ScanResult:
    """Compatibility alias for callers grouping cookie-security scans."""

    return scan_go_cwe614(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe614ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe614ScanLimits:
        raise GoCwe614ScanError(GoCwe614ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe614ScanError(GoCwe614ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe614ScanError(GoCwe614ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe614ScanError(GoCwe614ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.named_children[-1] if node.named_children else None
        if path_node is None or path_node.type not in {
            "interpreted_string_literal",
            "raw_string_literal",
        }:
            continue
        package = _literal_text(path_node, source)
        if package != _HTTP_PACKAGE:
            continue
        name_node = node.child_by_field_name("name")
        alias = (
            _text(source, name_node)
            if name_node is not None
            else package.rsplit("/", 1)[-1]
        )
        if alias not in {".", "_"}:
            aliases[alias] = package
    return aliases


def _collect_set_cookie_call(
    node: Node,
    source: bytes,
    imports: dict[str, str],
    bindings: dict[str, tuple[tuple[int, _CookieInfo], ...]],
    secure_updates: dict[str, tuple[tuple[int, _SecureState], ...]],
    raw: set[tuple[SourceRange, SourceRange, GoCwe614Operation, str]],
) -> None:
    if _qualified_call(node, source, imports) != (_HTTP_PACKAGE, _SET_COOKIE):
        return
    arguments = node.child_by_field_name("arguments")
    if arguments is None or len(arguments.named_children) < 2:
        return
    cookie_expression = _unwrap_expression(arguments.named_children[1])
    info = _cookie_info(cookie_expression, source, imports)
    if info is None and cookie_expression.type == "identifier":
        name = _text(source, cookie_expression)
        info = _latest_binding(bindings.get(name, ()), node.start_byte)
        if info is not None:
            update = _latest_secure_update(
                secure_updates.get(name, ()), node.start_byte
            )
            if update is not None:
                info = replace(info, secure_state=update)
    if info is None or not _is_sensitive_cookie(info.cookie_name):
        return
    if info.secure_state is _SecureState.TRUE or info.secure_state is _SecureState.UNKNOWN:
        return
    operation = (
        GoCwe614Operation.HTTP_COOKIE_SECURE_FALSE
        if info.secure_state is _SecureState.FALSE
        else GoCwe614Operation.HTTP_COOKIE_WITHOUT_SECURE
    )
    raw.add((info.name_location, _range(node), operation, info.cookie_name))


def _cookie_bindings(
    nodes: tuple[Node, ...], source: bytes, imports: dict[str, str]
) -> dict[str, tuple[tuple[int, _CookieInfo], ...]]:
    output: dict[str, list[tuple[int, _CookieInfo]]] = {}
    for node in nodes:
        if node.type not in {"short_var_declaration", "assignment_statement"}:
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            continue
        names = left.named_children if left.type == "expression_list" else (left,)
        values = right.named_children if right.type == "expression_list" else (right,)
        for name, value in zip(names, values, strict=False):
            if name.type != "identifier":
                continue
            info = _cookie_info(_unwrap_expression(value), source, imports)
            if info is not None:
                output.setdefault(_text(source, name), []).append((node.start_byte, info))
    return {
        name: tuple(sorted(events, key=lambda item: item[0]))
        for name, events in output.items()
    }


def _secure_assignments(
    nodes: tuple[Node, ...], source: bytes
) -> dict[str, tuple[tuple[int, _SecureState], ...]]:
    output: dict[str, list[tuple[int, _SecureState]]] = {}
    for node in nodes:
        if node.type != "assignment_statement":
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            continue
        left_value = left.named_children[0] if left.type == "expression_list" else left
        right_value = right.named_children[0] if right.type == "expression_list" else right
        if left_value.type != "selector_expression":
            continue
        field = left_value.child_by_field_name("field")
        operand = left_value.child_by_field_name("operand")
        if (
            field is None
            or operand is None
            or field.type != "field_identifier"
            or operand.type != "identifier"
            or _text(source, field) != "Secure"
        ):
            continue
        state = _secure_state(right_value)
        output.setdefault(_text(source, operand), []).append((node.start_byte, state))
    return {
        name: tuple(sorted(events, key=lambda item: item[0]))
        for name, events in output.items()
    }


def _latest_binding(
    events: tuple[tuple[int, _CookieInfo], ...], position: int
) -> _CookieInfo | None:
    latest: _CookieInfo | None = None
    for start, info in events:
        if start >= position:
            break
        latest = info
    return latest


def _latest_secure_update(
    events: tuple[tuple[int, _SecureState], ...], position: int
) -> _SecureState | None:
    latest: _SecureState | None = None
    for start, state in events:
        if start >= position:
            break
        latest = state
    return latest


def _cookie_info(
    node: Node | None, source: bytes, imports: dict[str, str]
) -> _CookieInfo | None:
    if node is None:
        return None
    package, name = _composite_type(node, source, imports)
    if package != _HTTP_PACKAGE or name != _COOKIE_TYPE:
        return None
    fields = _fields(node, source)
    name_node = fields.get("name")
    if name_node is None:
        return None
    cookie_name = _literal_text(name_node, source)
    if cookie_name is None or not _is_sensitive_cookie(cookie_name):
        return None
    secure_node = fields.get("secure")
    secure_state = (
        _SecureState.MISSING
        if secure_node is None
        else _secure_state(secure_node)
    )
    return _CookieInfo(
        literal=_range(node),
        name_location=_range(name_node),
        cookie_name=cookie_name,
        secure_state=secure_state,
    )


def _is_sensitive_cookie(name: str) -> bool:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    normalized = re.sub(r"[^a-z0-9]+", "_", normalized).strip("_")
    if normalized in _SENSITIVE_NAME:
        return True
    tokens = frozenset(normalized.split("_"))
    return bool(tokens & {"session", "sessid", "sid", "auth", "token", "jwt"})


def _secure_state(node: Node) -> _SecureState:
    if node.type == "true":
        return _SecureState.TRUE
    if node.type == "false":
        return _SecureState.FALSE
    return _SecureState.UNKNOWN


def _composite_type(node: Node, source: bytes, imports: dict[str, str]) -> tuple[str, str]:
    type_node = node.child_by_field_name("type")
    if type_node is None or type_node.type != "qualified_type":
        return "", ""
    package_node = type_node.named_children[0] if type_node.named_children else None
    name_node = type_node.child_by_field_name("name")
    if package_node is None or name_node is None:
        return "", ""
    return imports.get(_text(source, package_node), ""), _text(source, name_node)


def _fields(node: Node, source: bytes) -> dict[str, Node]:
    body = node.child_by_field_name("body")
    if body is None:
        return {}
    output: dict[str, Node] = {}
    for element in body.named_children:
        if element.type != "keyed_element":
            continue
        key = element.child_by_field_name("key")
        value = element.child_by_field_name("value")
        if key is None or value is None:
            continue
        value_children = value.named_children
        output[_field_key(key, source)] = (
            value_children[0]
            if value.type == "literal_element" and len(value_children) == 1
            else value
        )
    return output


def _field_key(node: Node, source: bytes) -> str:
    return _compact_text(source, node).strip('"`').lower()


def _qualified_call(
    node: Node, source: bytes, imports: dict[str, str]
) -> tuple[str, str] | None:
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None or operand.type != "identifier":
        return None
    package = imports.get(_text(source, operand))
    return None if package is None else (package, _text(source, field))


def _unwrap_expression(node: Node) -> Node:
    current = node
    while current.type in {
        "expression_list",
        "unary_expression",
        "parenthesized_expression",
    }:
        children = current.named_children
        if not children:
            break
        current = children[-1]
    return current


def _bounded_preorder(root: Node, max_depth: int) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise GoCwe614ScanError(GoCwe614ScanErrorCode.ANALYSIS_UNAVAILABLE)
        output.append(node)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _scopes(root: Node) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node.type in _GO_SCOPES)


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


def _text(source: bytes, node: Node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")


def _compact_text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return "".join(_text(source, node).split())


def _literal_text(node: Node, source: bytes) -> str | None:
    if node.type == "literal_element" and len(node.named_children) == 1:
        return _literal_text(node.named_children[0], source)
    if node.type not in {"interpreted_string_literal", "raw_string_literal"}:
        return None
    text = _text(source, node).strip()
    if len(text) < 2:
        return None
    if text.startswith("`") and text.endswith("`"):
        return text[1:-1]
    if text.startswith('"') and text.endswith('"'):
        try:
            value = json.loads(text)
        except (TypeError, ValueError):
            return None
        return value if type(value) is str else None
    return None


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
    operation: GoCwe614Operation,
    cookie_name: str,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cookie_name": cookie_name,
        "cwe": "CWE-614",
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
    signals: tuple[GoCwe614Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-614",
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
                "cookie_name": signal.cookie_name,
                "detail": signal.detail,
                "detector": signal.detector,
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


# Compatibility aliases keep this adapter usable beside the existing CWE
# scanners while retaining the Go-specific implementation names.
Cwe614ScanErrorCode = GoCwe614ScanErrorCode
Cwe614ScanError = GoCwe614ScanError
Cwe614ScanLimits = GoCwe614ScanLimits
Cwe614ScanResult = GoCwe614ScanResult
Cwe614Signal = GoCwe614Signal


__all__ = [
    "Cwe614ScanError",
    "Cwe614ScanErrorCode",
    "Cwe614ScanLimits",
    "Cwe614ScanResult",
    "Cwe614Signal",
    "DEFAULT_GO_CWE614_SCAN_LIMITS",
    "GoCwe614Operation",
    "GoCwe614ScanError",
    "GoCwe614ScanErrorCode",
    "GoCwe614ScanLimits",
    "GoCwe614ScanResult",
    "GoCwe614Signal",
    "scan_go_cookie_security",
    "scan_go_cwe614",
    "scan_go_cwe614_cookie_security",
]
