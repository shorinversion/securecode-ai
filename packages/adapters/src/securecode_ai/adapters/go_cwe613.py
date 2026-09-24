"""Bounded Go facts for CWE-613 insufficient session expiration.

The detector is intentionally limited to session-shaped HTTP cookies, the
common gorilla/sessions options object, and JWT construction.  It reports an
explicit zero lifetime, an empty expiration, or a token construction for
which no expiration claim is present.  Positive MaxAge values and real time
expiration expressions are treated as validation boundaries.

Only an admitted, healthy :class:`~securecode_ai.core.SymbolIndex` is
accepted.  Source bytes are parsed transiently.  Returned signals contain
immutable repository identity, exact tree-sitter ranges, and deterministic
hashes, but no source text or parser diagnostics.
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
_RULE_ID = "securecode-go-cwe613"
_DETECTOR = "securecode-go-cwe613@1.0"
_DETAIL = "insufficient_session_expiration"
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})
_HTTP_PACKAGE = "net/http"
_TIME_PACKAGE = "time"
_SESSION_PACKAGES = frozenset(
    {
        "github.com/gorilla/sessions",
        "github.com/gorilla/securecookie",
        "github.com/gin-contrib/sessions",
    }
)
_TOKEN_PACKAGES = frozenset({"golang.org/x/oauth2"})
_JWT_PACKAGES = frozenset(
    {
        "github.com/dgrijalva/jwt-go",
        "github.com/golang-jwt/jwt",
        "github.com/golang-jwt/jwt/v4",
        "github.com/golang-jwt/jwt/v5",
    }
)
_COOKIE_TYPES = frozenset({"Cookie"})
_SESSION_OPTIONS_TYPES = frozenset({"Options", "SessionOptions", "CookieStore"})
_TOKEN_TYPES = frozenset({"Token"})
_JWT_CLAIM_TYPES = frozenset({"MapClaims", "RegisteredClaims", "StandardClaims"})
_JWT_NEW_METHODS = frozenset({"New", "NewWithClaims"})
_EXPIRY_KEYS = frozenset(
    {"exp", "expires", "expiresat", "expiration", "expiry", "maxage"}
)
_SESSION_NAME_MARKERS = frozenset(
    {
        "auth",
        "authentication",
        "jwt",
        "login",
        "oauth",
        "refresh",
        "session",
        "sid",
        "token",
    }
)


class GoCwe613ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-613 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe613ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe613ScanErrorCode) -> None:
        if type(code) is not GoCwe613ScanErrorCode:
            raise TypeError("Go CWE-613 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-613 session-expiration scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe613ScanLimits:
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
            raise ValueError("Go CWE-613 scan limits are invalid")


DEFAULT_GO_CWE613_SCAN_LIMITS = GoCwe613ScanLimits()


class GoCwe613Operation(StrEnum):
    """Recognised session and token lifetime failures."""

    COOKIE_MAX_AGE_ZERO = "http.Cookie.MaxAge=0"
    COOKIE_WITHOUT_EXPIRATION = "http.Cookie_without_expiration"
    COOKIE_ZERO_EXPIRATION = "http.Cookie_expiration_zero"
    SESSION_MAX_AGE_ZERO = "sessions.Options.MaxAge=0"
    SESSION_WITHOUT_EXPIRATION = "sessions.Options_without_expiration"
    JWT_WITHOUT_EXPIRATION = "jwt_without_expiration"
    JWT_EXPIRATION_ZERO = "jwt_expiration_zero"
    TOKEN_WITHOUT_EXPIRATION = "session_token_without_expiration"

    # Compatibility names used by generic finding consumers.
    MAX_AGE_ZERO = "http.Cookie.MaxAge=0"
    NO_EXPIRATION = "jwt_without_expiration"


@dataclass(frozen=True, slots=True)
class GoCwe613Signal:
    """One immutable source-free insufficient-expiration fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe613Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-613"
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
        )
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity_valid = False
        ranges_valid = (
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
            if identity_valid and ranges_valid and type(self.operation) is GoCwe613Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not GoCwe613Operation
            or expected_id is None
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-613"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-613 signal is invalid")
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
class GoCwe613ScanResult:
    """Deterministic, source-free output for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe613Signal, ...]
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
            type(item) is GoCwe613Signal for item in self.signals
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
            raise ValueError("Go CWE-613 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _CookieInfo:
    literal: SourceRange
    expiration: SourceRange | None
    expiration_secure: bool
    expiration_zero: bool
    session_shaped: bool


@dataclass(frozen=True, slots=True)
class _ClaimsInfo:
    literal: SourceRange
    expiration: SourceRange | None
    expiration_secure: bool
    expiration_zero: bool


def scan_go_cwe613(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe613ScanLimits = DEFAULT_GO_CWE613_SCAN_LIMITS,
) -> GoCwe613ScanResult:
    """Find explicit zero or missing expiration on Go sessions and tokens."""

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
        nodes = _bounded_preorder(root, limits.max_expression_depth)
    except GoCwe613ScanError:
        raise
    except Exception:
        raise GoCwe613ScanError(GoCwe613ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    raw: set[tuple[SourceRange, SourceRange, GoCwe613Operation]] = set()
    try:
        for scope in _scopes(root):
            scope_nodes = _scope_preorder(scope)
            claims = _claim_bindings(scope_nodes, source, imports)
            cookies = _cookie_bindings(scope_nodes, source, imports)
            for node in scope_nodes:
                if node.type == "call_expression":
                    _collect_cookie_call(node, source, imports, cookies, raw)
                    _collect_jwt_call(node, source, imports, claims, raw)
                elif node.type in {"assignment_statement", "short_var_declaration"}:
                    _collect_max_age_assignment(node, source, imports, raw)
            _collect_session_option_literals(scope_nodes, source, imports, raw)
            if len(raw) > limits.max_signals:
                raise GoCwe613ScanError(GoCwe613ScanErrorCode.SIGNAL_LIMIT)
    except GoCwe613ScanError:
        raise
    except Exception:
        raise GoCwe613ScanError(GoCwe613ScanErrorCode.INTEGRITY_FAILURE) from None

    del nodes
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
        raise GoCwe613ScanError(GoCwe613ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe613Signal(
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
    return GoCwe613ScanResult(
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


def scan_go_session_expiration(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe613ScanLimits = DEFAULT_GO_CWE613_SCAN_LIMITS,
) -> GoCwe613ScanResult:
    """Descriptive alias for :func:`scan_go_cwe613`."""

    return scan_go_cwe613(symbol_index, limits=limits)


def scan_go_cwe613_session_expiration(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe613ScanLimits = DEFAULT_GO_CWE613_SCAN_LIMITS,
) -> GoCwe613ScanResult:
    """Compatibility alias for callers grouping session scans."""

    return scan_go_cwe613(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe613ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe613ScanLimits:
        raise GoCwe613ScanError(GoCwe613ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe613ScanError(GoCwe613ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe613ScanError(GoCwe613ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe613ScanError(GoCwe613ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    relevant = {
        _HTTP_PACKAGE,
        _TIME_PACKAGE,
        *_SESSION_PACKAGES,
        *_JWT_PACKAGES,
        *_TOKEN_PACKAGES,
    }
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.named_children[-1] if node.named_children else None
        if path_node is None or path_node.type not in {
            "interpreted_string_literal",
            "raw_string_literal",
        }:
            continue
        package = _text(source, path_node).strip('"`')
        if package not in relevant:
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


def _claim_bindings(
    nodes: tuple[Node, ...], source: bytes, imports: dict[str, str]
) -> dict[str, _ClaimsInfo]:
    output: dict[str, _ClaimsInfo] = {}
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
            literal = _unwrap_composite(value)
            info = _claims_info(literal, source, imports)
            if info is not None:
                output[_text(source, name)] = info
    return output


def _cookie_bindings(
    nodes: tuple[Node, ...], source: bytes, imports: dict[str, str]
) -> dict[str, _CookieInfo]:
    output: dict[str, _CookieInfo] = {}
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
            literal = _unwrap_composite(value)
            info = _cookie_info(literal, source, imports)
            if info is not None:
                output[_text(source, name)] = info
    return output


def _collect_cookie_call(
    node: Node,
    source: bytes,
    imports: dict[str, str],
    cookies: dict[str, _CookieInfo],
    raw: set[tuple[SourceRange, SourceRange, GoCwe613Operation]],
) -> None:
    call = _qualified_call(node, source, imports)
    if call != (_HTTP_PACKAGE, "SetCookie"):
        return
    arguments = node.child_by_field_name("arguments")
    if arguments is None or len(arguments.named_children) < 2:
        return
    value = arguments.named_children[1]
    info = _cookie_info(_unwrap_composite(value), source, imports)
    if info is None and value.type == "identifier":
        info = cookies.get(_text(source, value))
    if info is None or not info.session_shaped:
        return
    operation = (
        GoCwe613Operation.COOKIE_MAX_AGE_ZERO
        if info.expiration_zero
        else GoCwe613Operation.COOKIE_WITHOUT_EXPIRATION
        if info.expiration is None
        else GoCwe613Operation.COOKIE_ZERO_EXPIRATION
    )
    if info.expiration_secure:
        return
    raw.add((info.expiration or info.literal, _range(node), operation))


def _collect_jwt_call(
    node: Node,
    source: bytes,
    imports: dict[str, str],
    claims: dict[str, _ClaimsInfo],
    raw: set[tuple[SourceRange, SourceRange, GoCwe613Operation]],
) -> None:
    call = _qualified_call(node, source, imports)
    if call is None or call[0] not in _JWT_PACKAGES or call[1] not in _JWT_NEW_METHODS:
        return
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return
    values = arguments.named_children
    if call[1] == "New":
        raw.add((_range(node.child_by_field_name("function") or node), _range(node), GoCwe613Operation.JWT_WITHOUT_EXPIRATION))
        return
    if len(values) < 2:
        return
    literal = _unwrap_composite(values[1])
    info = _claims_info(literal, source, imports)
    if info is None and values[1].type == "identifier":
        info = claims.get(_text(source, values[1]))
    if info is None:
        return
    operation = (
        GoCwe613Operation.JWT_EXPIRATION_ZERO
        if info.expiration_zero
        else GoCwe613Operation.JWT_WITHOUT_EXPIRATION
        if info.expiration is None
        else GoCwe613Operation.JWT_EXPIRATION_ZERO
    )
    if info.expiration_secure:
        return
    raw.add((info.expiration or info.literal, _range(node), operation))


def _collect_session_option_literals(
    nodes: tuple[Node, ...],
    source: bytes,
    imports: dict[str, str],
    raw: set[tuple[SourceRange, SourceRange, GoCwe613Operation]],
) -> None:
    for node in nodes:
        if node.type != "composite_literal":
            continue
        package, name = _composite_type(node, source, imports)
        session_options = package in _SESSION_PACKAGES and name in _SESSION_OPTIONS_TYPES
        oauth_token = package in _TOKEN_PACKAGES and name in _TOKEN_TYPES
        if not session_options and not oauth_token:
            continue
        info = _expiration_info(node, source, imports)
        if info[2]:
            continue
        if oauth_token:
            operation = GoCwe613Operation.TOKEN_WITHOUT_EXPIRATION
        elif info[3]:
            operation = GoCwe613Operation.SESSION_MAX_AGE_ZERO
        else:
            operation = GoCwe613Operation.SESSION_WITHOUT_EXPIRATION
        raw.add((info[0] or _range(node), _range(node), operation))


def _collect_max_age_assignment(
    node: Node,
    source: bytes,
    imports: dict[str, str],
    raw: set[tuple[SourceRange, SourceRange, GoCwe613Operation]],
) -> None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return
    left_value = left.named_children[0] if left.type == "expression_list" else left
    value = right.named_children[0] if right.type == "expression_list" else right
    if not _is_max_age_selector(left_value, source):
        return
    if not _is_zero_value(value, source):
        return
    if not _selector_is_session_like(left_value, source, imports):
        return
    raw.add((_range(value), _range(node), GoCwe613Operation.SESSION_MAX_AGE_ZERO))


def _cookie_info(node: Node | None, source: bytes, imports: dict[str, str]) -> _CookieInfo | None:
    if node is None:
        return None
    package, name = _composite_type(node, source, imports)
    if package != _HTTP_PACKAGE or name not in _COOKIE_TYPES:
        return None
    info = _expiration_info(node, source, imports)
    fields = _fields(node, source)
    name_node = fields.get("name")
    value_node = fields.get("value")
    marker = _marker_text(name_node, source) if name_node is not None else ""
    value_marker = _compact_text(source, value_node).lower() if value_node is not None else ""
    session_shaped = any(item in marker for item in _SESSION_NAME_MARKERS) or any(
        item in value_marker for item in ("session", "token", "jwt", "auth")
    )
    return _CookieInfo(
        literal=_range(node),
        expiration=info[0],
        expiration_secure=info[2],
        expiration_zero=info[3],
        session_shaped=session_shaped,
    )


def _claims_info(node: Node | None, source: bytes, imports: dict[str, str]) -> _ClaimsInfo | None:
    if node is None:
        return None
    package, name = _composite_type(node, source, imports)
    if package not in _JWT_PACKAGES or name not in _JWT_CLAIM_TYPES:
        return None
    info = _expiration_info(node, source, imports)
    return _ClaimsInfo(
        literal=_range(node),
        expiration=info[0],
        expiration_secure=info[2],
        expiration_zero=info[3],
    )


def _expiration_info(
    node: Node, source: bytes, imports: dict[str, str]
) -> tuple[SourceRange | None, Node | None, bool, bool]:
    del imports
    fields = _fields(node, source)
    first_location: SourceRange | None = None
    first_value: Node | None = None
    saw_zero = False
    for key, value in fields.items():
        if key not in _EXPIRY_KEYS:
            continue
        location = _range(value)
        zero = _is_zero_value(value, source)
        secure = not zero and _is_secure_expiration(value, source)
        if first_location is None:
            first_location = location
            first_value = value
        if secure:
            return location, value, True, False
        saw_zero = saw_zero or zero
    return first_location, first_value, False, saw_zero


def _is_secure_expiration(node: Node, source: bytes) -> bool:
    text = _compact_text(source, node).lower()
    if not text or text in {"nil", "null"}:
        return False
    if "time.now" in text or "time.unix" in text or ".add(" in text:
        return True
    if any(marker in text for marker in ("time.hour", "time.minute", "time.second", "duration")):
        return True
    if node.type == "int_literal":
        try:
            return int(text, 0) != 0
        except ValueError:
            return False
    if node.type in {"interpreted_string_literal", "raw_string_literal"}:
        return False
    if node.type == "identifier":
        return text not in {"zero", "none", "noexpiry", "never"}
    if node.type in {"call_expression", "selector_expression", "binary_expression", "unary_expression"}:
        return True
    return bool(re.search(r"\b(?:ttl|expiry|expiration|expires|deadline|duration)\b", text))


def _is_zero_value(node: Node, source: bytes) -> bool:
    text = _compact_text(source, node).lower()
    if text in {"0", "0.0", "nil", "time.time{}", "time.time()"}:
        return True
    return node.type == "composite_literal" and _compact_text(source, node).lower() == "time.time{}"


def _is_max_age_selector(node: Node, source: bytes) -> bool:
    return node.type == "selector_expression" and _selector_name(node, source).lower() == "maxage"


def _selector_is_session_like(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    operand = node.child_by_field_name("operand")
    if operand is None:
        return False
    text = _compact_text(source, operand).lower()
    if any(marker in text for marker in ("session", "cookie", "store", "auth", "token")):
        return True
    return imports.get(text) in _SESSION_PACKAGES


def _composite_type(node: Node, source: bytes, imports: dict[str, str]) -> tuple[str, str]:
    type_node = node.child_by_field_name("type")
    if type_node is None or type_node.type != "qualified_type":
        return "", ""
    package_node = type_node.named_children[0] if type_node.named_children else None
    name_node = type_node.child_by_field_name("name")
    if package_node is None or name_node is None:
        return "", ""
    package_alias = _text(source, package_node)
    return imports.get(package_alias, ""), _text(source, name_node)


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


def _marker_text(node: Node, source: bytes) -> str:
    return _compact_text(source, node).strip('"`').lower()


def _selector_name(node: Node, source: bytes) -> str:
    field = node.child_by_field_name("field")
    return "" if field is None else _text(source, field)


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


def _unwrap_composite(node: Node) -> Node:
    current = node
    while current.type in {"expression_list", "unary_expression", "parenthesized_expression"}:
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
            raise GoCwe613ScanError(GoCwe613ScanErrorCode.ANALYSIS_UNAVAILABLE)
        output.append(node)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
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
    operation: GoCwe613Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-613",
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
    signals: tuple[GoCwe613Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-613",
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


Cwe613ScanErrorCode = GoCwe613ScanErrorCode
Cwe613ScanError = GoCwe613ScanError
Cwe613ScanLimits = GoCwe613ScanLimits
Cwe613ScanResult = GoCwe613ScanResult
Cwe613Signal = GoCwe613Signal


__all__ = [
    "Cwe613ScanError",
    "Cwe613ScanErrorCode",
    "Cwe613ScanLimits",
    "Cwe613ScanResult",
    "Cwe613Signal",
    "DEFAULT_GO_CWE613_SCAN_LIMITS",
    "GoCwe613Operation",
    "GoCwe613ScanError",
    "GoCwe613ScanErrorCode",
    "GoCwe613ScanLimits",
    "GoCwe613ScanResult",
    "GoCwe613Signal",
    "scan_go_cwe613",
    "scan_go_cwe613_session_expiration",
    "scan_go_session_expiration",
]
