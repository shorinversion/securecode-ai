"""Bounded Go login-handler facts for CWE-307.

The scanner looks for a deliberately narrow authentication flow in ordinary
``net/http`` handlers.  A finding requires all of the following evidence in
the same bounded handler: an HTTP request/response signature, a login-like
route or function name, and an explicit password or credential verification
call.  A recognised limiter, quota check, or rate-limit middleware suppresses
the finding.  Unknown router and authentication abstractions are left
unresolved instead of producing blanket alerts.

Only an admitted, sealed :class:`~securecode_ai.core.SymbolIndex` is accepted.
Source bytes are parsed transiently.  Results contain immutable identity,
exact source ranges, and content-addressed hashes, but never source text or
parser diagnostics.
"""

from __future__ import annotations

import hashlib
import json
import re
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
_RULE_ID = "securecode-go-cwe307"
_DETECTOR = "securecode-go-cwe307@1.0"
_DETAIL = "login_handler_without_rate_limit"

_HTTP_PACKAGE = "net/http"
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})
_ROUTE_METHODS = frozenset(
    {
        "any",
        "delete",
        "get",
        "handle",
        "handlecontext",
        "handlefunc",
        "patch",
        "path",
        "post",
        "put",
        "route",
        "servehttp",
    }
)
_AUTH_METHODS = frozenset(
    {
        "authenticate",
        "authenticateuser",
        "checkpassword",
        "checkpasswordhash",
        "compare",
        "comparehashandpassword",
        "comparepassword",
        "validatecredentials",
        "validatepassword",
        "verifypassword",
        "verifycredentials",
    }
)
_AUTH_PACKAGES = frozenset(
    {
        "golang.org/x/crypto/bcrypt",
        "golang.org/x/crypto/argon2",
        "crypto/subtle",
    }
)
_LIMITER_PACKAGES = frozenset(
    {
        "github.com/didip/tollbooth",
        "github.com/didip/tollbooth/v7",
        "github.com/go-chi/httprate",
        "github.com/juju/ratelimit",
        "github.com/ululebedev/limiter",
        "github.com/ululebedev/limiter/v3",
        "github.com/veqryn/ratelimit",
        "golang.org/x/time/rate",
    }
)
_LIMITER_CALLS = frozenset(
    {
        "allow",
        "allown",
        "check",
        "checkquota",
        "enforceratelimit",
        "limit",
        "limiter",
        "rate",
        "ratelimit",
        "reserve",
        "reserven",
        "take",
        "wait",
        "waitn",
    }
)
_LIMITER_CONSTRUCTORS = frozenset({"newlimiter", "newrate", "newthrottler"})
_LIMITER_WORDS = frozenset(
    {
        "bucket",
        "limit",
        "limiter",
        "quota",
        "rate",
        "ratelimit",
        "throttle",
        "throttler",
        "tokenbucket",
    }
)
_LOGIN_WORDS = frozenset({"auth", "authenticate", "login", "signin", "signon"})
_PASSWORD_WORDS = frozenset({"credential", "hash", "pass", "password", "secret"})


class GoCwe307ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-307 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe307ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe307ScanErrorCode) -> None:
        if type(code) is not GoCwe307ScanErrorCode:
            raise TypeError("Go CWE-307 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-307 login rate-limit scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe307ScanLimits:
    """Hard bounds applied before and during structural handler analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-307 scan limits are invalid")


DEFAULT_GO_CWE307_SCAN_LIMITS = GoCwe307ScanLimits()


class GoCwe307Operation(StrEnum):
    """The bounded authentication projection reported by this scanner."""

    LOGIN_WITHOUT_RATE_LIMIT = "login_without_rate_limit"
    LOGIN_HANDLER_WITHOUT_RATE_LIMIT = "login_handler_without_rate_limit"


@dataclass(frozen=True, slots=True)
class GoCwe307Signal:
    """One immutable source-free login handler without a proven limiter."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe307Operation = GoCwe307Operation.LOGIN_HANDLER_WITHOUT_RATE_LIMIT
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-307"
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
            if valid_identity and valid_ranges and type(self.operation) is GoCwe307Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not GoCwe307Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-307"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-307 signal is invalid")
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
class GoCwe307ScanResult:
    """Deterministic, source-free CWE-307 output for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe307Signal, ...]
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
            type(item) is GoCwe307Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    item.sink.start_byte,
                    item.sink.end_byte,
                    item.source.start_byte,
                    item.source.end_byte,
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
            raise ValueError("Go CWE-307 scan result is invalid")


def scan_go_cwe307(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe307ScanLimits = DEFAULT_GO_CWE307_SCAN_LIMITS,
) -> GoCwe307ScanResult:
    """Find bounded net/http login handlers without a recognised limiter."""

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
        raise GoCwe307ScanError(GoCwe307ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    login_routes = _login_route_targets(root, source)
    limited_routes = _limited_route_targets(root, source, imports)
    facts: list[tuple[SourceRange, SourceRange, GoCwe307Operation]] = []
    for scope in _function_scopes(root):
        if not _is_http_handler(scope, source, imports):
            continue
        if not _is_login_scope(scope, source, imports, login_routes | limited_routes):
            continue
        if _has_limiter_evidence(scope, source, imports) or _scope_has_limited_route(
            scope, source, imports
        ):
            continue
        auth_call = _authentication_call(scope, source, imports)
        if auth_call is None:
            continue
        facts.append(
            (
                _range(auth_call),
                _range(scope),
                GoCwe307Operation.LOGIN_HANDLER_WITHOUT_RATE_LIMIT,
            )
        )
        if len(facts) > limits.max_signals:
            raise GoCwe307ScanError(GoCwe307ScanErrorCode.SIGNAL_LIMIT)

    unique = tuple(
        sorted(
            set(facts),
            key=lambda item: (
                item[1].start_byte,
                item[1].end_byte,
                item[0].start_byte,
                item[0].end_byte,
                item[2].value,
            ),
        )
    )
    if len(unique) > limits.max_signals:
        raise GoCwe307ScanError(GoCwe307ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe307Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
        )
        for source_range, sink_range, operation in unique
    )
    return GoCwe307ScanResult(
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


def scan_go_login_rate_limit(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe307ScanLimits = DEFAULT_GO_CWE307_SCAN_LIMITS,
) -> GoCwe307ScanResult:
    """Descriptive alias for :func:`scan_go_cwe307`."""

    return scan_go_cwe307(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe307ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe307ScanLimits:
        raise GoCwe307ScanError(GoCwe307ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe307ScanError(GoCwe307ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe307ScanError(GoCwe307ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe307ScanError(GoCwe307ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        path = _text(source, path_node).strip('"`')
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            alias = _text(source, name_node)
            if alias not in {".", "_"}:
                aliases[alias] = path
            continue
        aliases[path.rsplit("/", 1)[-1]] = path
    return aliases


def _function_scopes(root: Node) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node.type in _GO_SCOPES)


def _is_http_handler(scope: Node, source: bytes, imports: dict[str, str]) -> bool:
    parameters = scope.child_by_field_name("parameters")
    if parameters is None:
        return False
    text = _compact_text(source, parameters).lower()
    http_aliases = tuple(alias for alias, path in imports.items() if path == _HTTP_PACKAGE)
    has_writer = "responsewriter" in text and any(
        f"{alias.lower()}.responsewriter" in text for alias in http_aliases
    )
    has_request = "request" in text and any(
        f"{alias.lower()}.request" in text for alias in http_aliases
    )
    return has_writer and has_request


def _is_login_scope(
    scope: Node,
    source: bytes,
    imports: dict[str, str],
    limited_routes: frozenset[str],
) -> bool:
    name_node = scope.child_by_field_name("name")
    if name_node is not None and _is_login_name(_text(source, name_node)):
        return True
    if _literal_route_login(scope, source, imports):
        return True
    return bool(name_node is not None and _compact_text(source, name_node) in limited_routes)


def _authentication_call(scope: Node, source: bytes, imports: dict[str, str]) -> Node | None:
    for node in _scope_preorder(scope):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        if function is None:
            continue
        name = _call_name(function, source)
        if not name:
            continue
        member = name.rsplit(".", 1)[-1].lower()
        package = name.rsplit(".", 1)[0] if "." in name else ""
        canonical_package = imports.get(package, package)
        if member in _AUTH_METHODS and (
            canonical_package in _AUTH_PACKAGES
            or member != "compare"
            or _password_context(node, source)
        ):
            return node
        if _is_password_verifier_name(member) and _password_context(node, source):
            return node
    return None


def _has_limiter_evidence(scope: Node, source: bytes, imports: dict[str, str]) -> bool:
    for node in _scope_preorder(scope):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        if function is None:
            continue
        name = _call_name(function, source)
        if _is_limiter_call(name, imports, source, function):
            return True
    return False


def _limited_route_targets(root: Node, source: bytes, imports: dict[str, str]) -> frozenset[str]:
    targets: set[str] = set()
    for node in _preorder(root):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            continue
        route_name = _call_name(function, source)
        if route_name.rsplit(".", 1)[-1].lower() not in _ROUTE_METHODS:
            continue
        call_text = _compact_text(source, node).lower()
        if not _route_has_login_literal(arguments, source):
            continue
        if not _route_has_limiter_marker(node, source, imports):
            continue
        for candidate in _preorder(arguments):
            if candidate.type in {"identifier", "field_identifier"}:
                value = _text(source, candidate)
                if not _is_route_noise(value, call_text):
                    targets.add(value)
    return frozenset(targets)


def _login_route_targets(root: Node, source: bytes) -> frozenset[str]:
    """Return named handlers directly registered on a login-like route."""

    targets: set[str] = set()
    for node in _preorder(root):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            continue
        route_name = _compact_text(source, function).rsplit(".", 1)[-1].lower()
        if route_name not in _ROUTE_METHODS or not _route_has_login_literal(arguments, source):
            continue
        for candidate in _preorder(arguments):
            if candidate.type in {"identifier", "field_identifier"}:
                value = _text(source, candidate)
                if not _is_route_noise(value, ""):
                    targets.add(value)
    return frozenset(targets)


def _literal_route_login(scope: Node, source: bytes, imports: dict[str, str]) -> bool:
    ancestor = scope.parent
    hops = 0
    while ancestor is not None and hops < 12:
        if ancestor.type == "call_expression":
            function = ancestor.child_by_field_name("function")
            arguments = ancestor.child_by_field_name("arguments")
            if function is not None and arguments is not None:
                name = _call_name(function, source)
                if name.rsplit(".", 1)[-1].lower() in _ROUTE_METHODS and _route_has_login_literal(
                    arguments, source
                ):
                    return True
        ancestor = ancestor.parent
        hops += 1
    del imports
    return False


def _scope_has_limited_route(scope: Node, source: bytes, imports: dict[str, str]) -> bool:
    """Return whether an anonymous handler is wrapped by a limited route."""

    ancestor = scope.parent
    hops = 0
    while ancestor is not None and hops < 12:
        if ancestor.type == "call_expression":
            function = ancestor.child_by_field_name("function")
            arguments = ancestor.child_by_field_name("arguments")
            if function is not None and arguments is not None:
                name = _call_name(function, source)
                if (
                    name.rsplit(".", 1)[-1].lower() in _ROUTE_METHODS
                    and _route_has_login_literal(arguments, source)
                    and _route_has_limiter_marker(ancestor, source, imports)
                ):
                    return True
        ancestor = ancestor.parent
        hops += 1
    return False


def _route_has_login_literal(arguments: Node, source: bytes) -> bool:
    return any(
        node.type in {"interpreted_string_literal", "raw_string_literal"}
        and bool(
            re.search(
                r"(?:login|signin|sign-in|auth|session)",
                _text(source, node),
                re.IGNORECASE,
            )
        )
        for node in _preorder(arguments)
    )


def _route_has_limiter_marker(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    for child in _preorder(node):
        if child.type == "call_expression":
            function = child.child_by_field_name("function")
            if function is not None and _is_limiter_call(
                _call_name(function, source), imports, source, function
            ):
                return True
        if child.type in {"identifier", "field_identifier"} and _contains_limiter_word(
            _text(source, child)
        ):
            return True
    return False


def _is_limiter_call(
    name: str | None,
    imports: dict[str, str],
    source: bytes,
    function: Node,
) -> bool:
    if not name:
        return False
    member = name.rsplit(".", 1)[-1].lower()
    package = name.rsplit(".", 1)[0] if "." in name else ""
    if package in imports and imports[package] in _LIMITER_PACKAGES:
        return member not in _LIMITER_CONSTRUCTORS
    if member in _LIMITER_CALLS:
        operand = function.child_by_field_name("operand")
        return operand is not None and _contains_limiter_word(_text(source, operand))
    return _contains_limiter_word(member) and member not in {"authenticate", "validate"}


def _is_route_noise(value: str, call_text: str) -> bool:
    lower = value.lower()
    del call_text
    return lower in {"router", "mux", "r", "http", "nil"}


def _password_context(node: Node, source: bytes) -> bool:
    text = _compact_text(source, node).lower()
    return any(word in text for word in _PASSWORD_WORDS)


def _is_password_verifier_name(member: str) -> bool:
    return any(marker in member for marker in ("password", "credential")) and any(
        marker in member for marker in ("check", "compare", "validate", "verify", "auth")
    )


def _is_login_name(value: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", value.lower())
    suffixes = (
        "handler",
        "endpoint",
        "route",
        "user",
        "view",
        "action",
        "request",
        "func",
    )
    return compact in _LOGIN_WORDS or any(
        compact.startswith(f"{word}{suffix}") for word in _LOGIN_WORDS for suffix in suffixes
    )


def _contains_limiter_word(value: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", value.lower())
    return compact in _LIMITER_WORDS or any(
        marker in compact for marker in ("ratelimit", "limiter", "quota", "throttle", "tokenbucket")
    )


def _call_name(function: Node, source: bytes) -> str:
    return _compact_text(source, function)


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
    operation: GoCwe307Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-307",
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
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe307Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-307",
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
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
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


Cwe307ScanErrorCode = GoCwe307ScanErrorCode
Cwe307ScanError = GoCwe307ScanError
Cwe307ScanLimits = GoCwe307ScanLimits
Cwe307ScanResult = GoCwe307ScanResult
Cwe307Signal = GoCwe307Signal


__all__ = [
    "DEFAULT_GO_CWE307_SCAN_LIMITS",
    "Cwe307ScanError",
    "Cwe307ScanErrorCode",
    "Cwe307ScanLimits",
    "Cwe307ScanResult",
    "Cwe307Signal",
    "GoCwe307Operation",
    "GoCwe307ScanError",
    "GoCwe307ScanErrorCode",
    "GoCwe307ScanLimits",
    "GoCwe307ScanResult",
    "GoCwe307Signal",
    "scan_go_cwe307",
    "scan_go_login_rate_limit",
]
