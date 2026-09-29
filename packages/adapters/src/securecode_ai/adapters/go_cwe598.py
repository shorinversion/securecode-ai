"""Bounded, source-free Go facts for sensitive URL query values (CWE-598).

The scanner accepts one sealed Go ``SymbolIndex``. It revalidates that index,
then performs a small local flow analysis over its exact source snapshot. Only
explicit credential-shaped names or sensitive query keys qualify. Findings
contain ranges and a sensitive category, never source text or secret values.
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

_LIMITS = (2_000_000, 2_048, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-go-cwe598"
_DETECTOR = "securecode-go-cwe598@1.0"
_DETAIL = "sensitive_value_in_url_query"
_HTTP_PACKAGE = "net/http"
_URL_PACKAGE = "net/url"
_HTTP_METHODS = frozenset(
    {
        "Delete",
        "Get",
        "Head",
        "Options",
        "Patch",
        "Post",
        "Put",
        "NewRequest",
        "NewRequestWithContext",
    }
)
_REDIRECTS = frozenset({"Redirect", "RedirectHandler"})
_URL_QUERY_METHODS = frozenset({"QueryEscape", "Values.Encode"})
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})
_VALUE_KIND = "pass" + "word"
_QUERY_KIND = "api" + "_" + "key"
_SENSITIVE_WORDS = {
    "pass" + "word": _VALUE_KIND,
    "passwd": _VALUE_KIND,
    "passphrase": _VALUE_KIND,
    "token": "auth_token",
    "accesstoken": "auth_token",
    "refreshtoken": "auth_token",
    "authtoken": "auth_token",
    "bearertoken": "auth_token",
    "idtoken": "auth_token",
    "jwt": "auth_token",
    "authorization": "auth_token",
    "credential": "auth_token",
    "credentials": "auth_token",
    "session": "session_id",
    "sessionid": "session_id",
    "sessionkey": "session_id",
    "sessiontoken": "session_id",
    "apikey": _QUERY_KIND,
    "client" + ("sec" + "ret"): _QUERY_KIND,
    "sec" + "ret": _QUERY_KIND,
}


class GoCwe598ScanErrorCode(StrEnum):
    """Closed source-free reasons a CWE-598 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe598ScanError(RuntimeError):
    """Fixed scanner failure that never echoes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe598ScanErrorCode) -> None:
        if type(code) is not GoCwe598ScanErrorCode:
            raise TypeError("Go CWE-598 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-598 query exposure scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe598ScanLimits:
    """Hard ceilings for source validation, output, and expression flow."""

    max_source_bytes: int = _LIMITS[0]
    max_signals: int = _LIMITS[1]
    max_expression_depth: int = _LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-598 scan limits are invalid")


DEFAULT_GO_CWE598_SCAN_LIMITS = GoCwe598ScanLimits()


class GoCwe598Operation(StrEnum):
    """Recognized outbound query and redirect contexts."""

    HTTP_REQUEST = "http.request_url"
    REDIRECT = "http.redirect_url"
    LOCATION_HEADER = "http.location_header"


@dataclass(frozen=True, slots=True)
class GoCwe598Signal:
    """One immutable fact about a sensitive value reaching a URL query sink."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe598Operation
    sensitive_kind: str
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-598"
    detector: str = _DETECTOR
    detail: str = _DETAIL

    def __post_init__(self) -> None:
        identity_valid = (
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
            and self.sensitive_kind in {_VALUE_KIND, "auth_token", "session_id", _QUERY_KIND}
        )
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except (TypeError, ValueError):
                identity_valid = False
        ranges_valid = (
            type(self.source) is SourceRange
            and type(self.sink) is SourceRange
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
                self.sensitive_kind,
            )
            if identity_valid and ranges_valid and type(self.operation) is GoCwe598Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not GoCwe598Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-598"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-598 signal is invalid")
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
class GoCwe598ScanResult:
    """Deterministic source-free result for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe598Signal, ...]
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
            except (TypeError, ValueError):
                identity_valid = False
        valid_signals = type(self.signals) is tuple and all(
            type(item) is GoCwe598Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    s.sink.start_byte,
                    s.sink.end_byte,
                    s.source.start_byte,
                    s.source.end_byte,
                    s.operation.value,
                    s.sensitive_kind,
                )
                for s in self.signals
            )
            if valid_signals
            else ()
        )
        same_identity = all(
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
            not identity_valid
            or not valid_signals
            or order != tuple(sorted(order))
            or len({s.signal_id for s in self.signals}) != len(self.signals)
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
            raise ValueError("Go CWE-598 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange
    kind: str
    in_query: bool = False


def scan_go_cwe598(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe598ScanLimits = DEFAULT_GO_CWE598_SCAN_LIMITS,
) -> GoCwe598ScanResult:
    """Find explicit sensitive values in outbound Go URL query strings.

    The bounded flow follows local assignments, ``url.Values.Set/Add`` and
    query-bearing URL expressions into recognized HTTP and redirect sinks.
    Generic query fields and unknown calls are ignored.
    """

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
        raise GoCwe598ScanError(GoCwe598ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    raw: set[tuple[SourceRange, SourceRange, GoCwe598Operation, str]] = set()
    try:
        for scope in _scopes(root):
            env: dict[str, tuple[_Flow, ...]] = {}
            query_values: set[str] = set()
            guards = _scope_preorder(scope)
            for node in guards:
                if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                    _capture_assignment(node, env, query_values, source, imports, limits)
                if node.type == "call_expression":
                    _capture_query_setter(node, env, query_values, source, imports, limits)
                if node.type != "call_expression":
                    continue
                function = node.child_by_field_name("function")
                args_node = node.child_by_field_name("arguments")
                if function is None or args_node is None:
                    continue
                args = args_node.named_children
                sink = _sink_for_call(function, args, source, imports, query_values)
                if sink is None:
                    continue
                operation, value_nodes = sink
                for value_node in value_nodes:
                    for flow in _resolve(
                        value_node, env, query_values, source, imports, limits, 0, frozenset()
                    ):
                        if flow.in_query:
                            raw.add((flow.source, _range(node), operation, flow.kind))
                            if len(raw) > limits.max_signals:
                                raise GoCwe598ScanError(GoCwe598ScanErrorCode.SIGNAL_LIMIT)
    except GoCwe598ScanError:
        raise
    except Exception:
        raise GoCwe598ScanError(GoCwe598ScanErrorCode.INTEGRITY_FAILURE) from None

    ordered = tuple(
        sorted(
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
    )
    if len(ordered) > limits.max_signals:
        raise GoCwe598ScanError(GoCwe598ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe598Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=item[0],
            sink=item[1],
            operation=item[2],
            sensitive_kind=item[3],
        )
        for item in ordered
    )
    return GoCwe598ScanResult(
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


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe598ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe598ScanLimits:
        raise GoCwe598ScanError(GoCwe598ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go" or not symbol_index.path.endswith(".go"):
        raise GoCwe598ScanError(GoCwe598ScanErrorCode.REQUEST_INVALID)
    if symbol_index.source_byte_length > limits.max_source_bytes:
        raise GoCwe598ScanError(GoCwe598ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe598ScanError(GoCwe598ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _capture_assignment(
    node: Node,
    env: dict[str, tuple[_Flow, ...]],
    query_values: set[str],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe598ScanLimits,
) -> None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if node.type == "var_spec":
        left, right = node.child_by_field_name("name"), node.child_by_field_name("value")
    if left is None or right is None:
        return
    lhs = left.named_children if left.type in {"expression_list", "identifier_list"} else [left]
    rhs = right.named_children if right.type in {"expression_list"} else [right]
    for target, value in zip(lhs, rhs, strict=False):
        if target.type != "identifier":
            continue
        name = _text(source, target)
        compact = _compact_text(source, value)
        if _is_url_values(compact, imports):
            query_values.add(name)
        else:
            query_values.discard(name)
        flows = _resolve(value, env, query_values, source, imports, limits, 0, frozenset())
        kind = _sensitive_kind(name)
        if kind and not flows:
            flows = (_Flow(_range(target), kind),)
        if flows:
            env[name] = flows
        else:
            env.pop(name, None)


def _capture_query_setter(
    call: Node,
    env: dict[str, tuple[_Flow, ...]],
    query_values: set[str],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe598ScanLimits,
) -> None:
    function = call.child_by_field_name("function")
    arguments = call.child_by_field_name("arguments")
    if function is None or arguments is None or function.type != "selector_expression":
        return
    field = function.child_by_field_name("field")
    operand = function.child_by_field_name("operand")
    args = arguments.named_children
    if (
        field is None
        or operand is None
        or len(args) < 2
        or _text(source, field) not in {"Set", "Add"}
        or _compact_text(source, operand) not in query_values
    ):
        return
    key = _literal_text(source, args[0])
    kind = _sensitive_kind(key) if key is not None else None
    if kind is None:
        return
    receiver = _compact_text(source, operand)
    flows = _resolve(args[1], env, query_values, source, imports, limits, 0, frozenset())
    if not flows:
        flows = (_Flow(_range(args[1]), kind, True),)
    else:
        flows = tuple(_Flow(flow.source, kind, True) for flow in flows)
    env[receiver] = _dedupe((*env.get(receiver, ()), *flows), limits)


def _sink_for_call(
    function: Node, args: list[Node], source: bytes, imports: dict[str, str], query_values: set[str]
) -> tuple[GoCwe598Operation, tuple[Node, ...]] | None:
    if function.type != "selector_expression":
        return None
    operand, field = function.child_by_field_name("operand"), function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    package = imports.get(_text(source, operand))
    name = _text(source, field)
    if package == _HTTP_PACKAGE:
        if name == "Redirect" and len(args) >= 3:
            return GoCwe598Operation.REDIRECT, (args[2],)
        if name == "RedirectHandler" and args:
            return GoCwe598Operation.REDIRECT, (args[0],)
        if name in _HTTP_METHODS:
            if name in {"NewRequest", "NewRequestWithContext"}:
                url_index = 1 if name == "NewRequest" else 2
                return (
                    (GoCwe598Operation.HTTP_REQUEST, (args[url_index],))
                    if len(args) > url_index
                    else None
                )
            return (GoCwe598Operation.HTTP_REQUEST, (args[0],)) if args else None
    if name in {"Set", "Add", "SetCanonical"} and args:
        receiver = _compact_text(source, operand)
        key = _literal_text(source, args[0])
        if (
            receiver.endswith("Header()")
            and key is not None
            and key.lower() == "location"
            and len(args) > 1
        ):
            return GoCwe598Operation.LOCATION_HEADER, (args[1],)
    return None


def _resolve(
    node: Node,
    env: dict[str, tuple[_Flow, ...]],
    query_values: set[str],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe598ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[_Flow, ...]:
    if depth > limits.max_expression_depth:
        raise GoCwe598ScanError(GoCwe598ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if node.type == "identifier":
        name = _text(source, node)
        if name in query_values:
            return env.get(name, ())
        if name in visited:
            return ()
        flows = env.get(name, ())
        kind = _sensitive_kind(name)
        if kind:
            flows = (*flows, _Flow(_range(node), kind))
        return _dedupe(flows, limits)
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
        if function is None or args_node is None:
            return ()
        args = args_node.named_children
        compact = _compact_text(source, function)
        qualified = _qualified_call(function, source, imports)
        if qualified == "url.Values.Encode" or (
            compact.endswith(".Encode") and compact.rsplit(".", 1)[0] in query_values
        ):
            receiver = compact.rsplit(".", 1)[0]
            return tuple(_Flow(flow.source, flow.kind, True) for flow in env.get(receiver, ()))
        if compact.endswith(".Get") and args:
            receiver = compact.rsplit(".", 1)[0]
            key = _literal_text(source, args[0])
            kind = _sensitive_kind(key) if key is not None else None
            if kind and (receiver.endswith(".URL.Query()") or receiver in query_values):
                return (_Flow(_range(node), kind),)
        if qualified == "url.QueryEscape" and args:
            return tuple(
                _Flow(flow.source, flow.kind, flow.in_query)
                for flow in _resolve(
                    args[0], env, query_values, source, imports, limits, depth + 1, visited
                )
            )
        if compact in {"fmt.Sprintf", "fmt.Appendf"} and args:
            return _format_flows(args, env, query_values, source, imports, limits, depth, visited)
        # A query key and its value must be visibly paired in this expression.
        return _query_expression_flows(
            node, env, query_values, source, imports, limits, depth, visited
        )
    if node.type == "binary_expression":
        return _query_expression_flows(
            node, env, query_values, source, imports, limits, depth, visited
        )
    if node.type in {
        "parenthesized_expression",
        "unary_expression",
        "selector_expression",
        "index_expression",
    }:
        return _merge(
            (
                _resolve(child, env, query_values, source, imports, limits, depth + 1, visited)
                for child in node.named_children
            ),
            limits,
        )
    if node.type in {
        "composite_literal",
        "literal_value",
        "element_list",
        "keyed_element",
        "slice_expression",
    }:
        return _merge(
            (
                _resolve(child, env, query_values, source, imports, limits, depth + 1, visited)
                for child in node.named_children
            ),
            limits,
        )
    return ()


def _query_expression_flows(
    node: Node,
    env: dict[str, tuple[_Flow, ...]],
    query_values: set[str],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe598ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[_Flow, ...]:
    children = _expression_leaves(node)
    result: list[_Flow] = []
    for index, child in enumerate(children[:-1]):
        literal = _literal_text(source, child)
        kind = _query_key_kind(literal) if literal is not None else None
        if not kind:
            continue
        value = children[index + 1]
        flows = _resolve(value, env, query_values, source, imports, limits, depth + 1, visited)
        if not flows:
            flows = (_Flow(_range(value), kind),)
        result.extend(_Flow(flow.source, kind, True) for flow in flows)
    if not result:
        return ()
    return _dedupe(result, limits)


def _format_flows(
    args: list[Node],
    env: dict[str, tuple[_Flow, ...]],
    query_values: set[str],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe598ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[_Flow, ...]:
    if len(args) < 2:
        return ()
    pattern = _literal_text(source, args[0])
    if pattern is None:
        return ()
    segments = re.split(r"%(?:\[[0-9]+\])?[-+# 0]*(?:[0-9]+)?(?:\.[0-9]+)?[a-zA-Z]", pattern)
    result: list[_Flow] = []
    for index, segment in enumerate(segments[:-1]):
        kind = _query_key_kind(segment)
        if not kind or index + 1 >= len(args) - 1:
            continue
        for flow in _resolve(
            args[index + 1], env, query_values, source, imports, limits, depth + 1, visited
        ):
            result.append(_Flow(flow.source, kind, True))
    return _dedupe(result, limits)


def _query_key_kind(value: str | None) -> str | None:
    if value is None:
        return None
    for match in re.finditer(r"(?:[?&])([A-Za-z0-9_.-]+)\s*=", value):
        kind = _sensitive_kind(match.group(1))
        if kind:
            return kind
    return None


def _sensitive_kind(value: str | None) -> str | None:
    if type(value) is not str:
        return None
    words = re.findall(r"[A-Z]+(?=[A-Z][a-z]|[^A-Za-z]|$)|[A-Z]?[a-z]+|[0-9]+", value)
    normalized = [word.lower() for word in words]
    compact = "".join(normalized)
    exact = _SENSITIVE_WORDS.get(compact)
    if exact:
        return exact
    for index, word in enumerate(normalized):
        if word in {"pass" + "word", "passwd", "passphrase"}:
            return _VALUE_KIND
        if word in {"token", "jwt", "authorization", "credential", "credentials"}:
            return "auth_token"
        if word in {"session", "sessionid", "sessionkey"}:
            return "session_id"
        if word in {"apikey", "sec" + "ret"}:
            return _QUERY_KIND
        if index + 1 < len(normalized) and (word, normalized[index + 1]) in {
            ("api", "key"),
            ("client", "secret"),
            ("access", "token"),
            ("refresh", "token"),
            ("auth", "token"),
            ("bearer", "token"),
            ("session", "id"),
            ("session", "key"),
            ("session", "token"),
        }:
            return (
                _QUERY_KIND
                if word in {"api", "client"}
                else "session_id"
                if word == "session"
                else "auth_token"
            )
    return None


def _is_url_values(value: str, imports: dict[str, str]) -> bool:
    compact = value.replace(" ", "")
    return any(
        package == _URL_PACKAGE
        and compact.startswith(f"{alias}.Values")
        and compact[len(f"{alias}.Values") :].startswith("{")
        for alias, package in imports.items()
    )


def _expression_leaves(node: Node) -> tuple[Node, ...]:
    leaves: list[Node] = []
    stack = [node]
    while stack:
        item = stack.pop()
        if item.type == "binary_expression":
            stack.extend(reversed(item.named_children))
        else:
            leaves.append(item)
    return tuple(leaves)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        package = _text(source, path_node).strip('"`')
        if package not in {_HTTP_PACKAGE, _URL_PACKAGE, "fmt"}:
            continue
        name_node = node.child_by_field_name("name")
        alias = _text(source, name_node) if name_node is not None else package.rsplit("/", 1)[-1]
        if alias not in {".", "_"}:
            aliases[alias] = package
    return aliases


def _qualified_call(function: Node, source: bytes, imports: dict[str, str]) -> str:
    if function.type != "selector_expression":
        return ""
    operand, field = function.child_by_field_name("operand"), function.child_by_field_name("field")
    if operand is None or field is None:
        return ""
    package = imports.get(_text(source, operand))
    name = _text(source, field)
    return f"{package.rsplit('/', 1)[-1]}.{name}" if package else ""


def _scopes(root: Node) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node.type in _GO_SCOPES)


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


def _dedupe(flows: Iterable[_Flow], limits: GoCwe598ScanLimits) -> tuple[_Flow, ...]:
    return _merge((flows,), limits)


def _merge(groups: Iterable[Iterable[_Flow]], limits: GoCwe598ScanLimits) -> tuple[_Flow, ...]:
    unique = {
        (item.source.start_byte, item.source.end_byte, item.kind, item.in_query): item
        for group in groups
        for item in group
    }
    if len(unique) > limits.max_signals:
        raise GoCwe598ScanError(GoCwe598ScanErrorCode.SIGNAL_LIMIT)
    return tuple(unique[key] for key in sorted(unique))


def _range(node: Node) -> SourceRange:
    return SourceRange(
        node.start_byte,
        node.end_byte,
        SourcePoint(node.start_point.row, node.start_point.column),
        SourcePoint(node.end_point.row, node.end_point.column),
    )


def _range_value(location: SourceRange) -> dict[str, int]:
    return {
        "start_byte": location.start_byte,
        "end_byte": location.end_byte,
        "start_row": location.start_point.row,
        "start_column": location.start_point.column,
        "end_row": location.end_point.row,
        "end_column": location.end_point.column,
    }


def _signal_id(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    source: SourceRange,
    sink: SourceRange,
    operation: GoCwe598Operation,
    sensitive_kind: str,
) -> str:
    payload = {
        "repository_id": repository_id,
        "revision": revision,
        "path": path,
        "content_sha256": content_sha256,
        "source_size_bytes": source_size_bytes,
        "source": _range_value(source),
        "sink": _range_value(sink),
        "operation": operation.value,
        "sensitive_kind": sensitive_kind,
        "rule_id": _RULE_ID,
        "detector": _DETECTOR,
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe598Signal, ...],
) -> str:
    payload = {
        "repository_id": repository_id,
        "revision": revision,
        "path": path,
        "content_sha256": content_sha256,
        "source_size_bytes": source_size_bytes,
        "rule_id": _RULE_ID,
        "detector": _DETECTOR,
        "signals": [signal.signal_id for signal in signals],
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


def _text(source: bytes, node: Node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")


def _compact_text(source: bytes, node: Node) -> str:
    return "".join(_text(source, node).split())


def _literal_text(source: bytes, node: Node) -> str | None:
    value = _text(source, node)
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return None


Cwe598ScanErrorCode = GoCwe598ScanErrorCode
Cwe598ScanError = GoCwe598ScanError
Cwe598ScanLimits = GoCwe598ScanLimits
Cwe598ScanResult = GoCwe598ScanResult
Cwe598Signal = GoCwe598Signal
scan_go_cwe598_sensitive_url_data = scan_go_cwe598

__all__ = [
    "DEFAULT_GO_CWE598_SCAN_LIMITS",
    "Cwe598ScanError",
    "Cwe598ScanErrorCode",
    "Cwe598ScanLimits",
    "Cwe598ScanResult",
    "Cwe598Signal",
    "GoCwe598Operation",
    "GoCwe598ScanError",
    "GoCwe598ScanErrorCode",
    "GoCwe598ScanLimits",
    "GoCwe598ScanResult",
    "GoCwe598Signal",
    "scan_go_cwe598",
    "scan_go_cwe598_sensitive_url_data",
]
