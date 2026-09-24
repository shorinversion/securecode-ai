"""Bounded JavaScript and TypeScript CWE-613 session lifetime facts.

The scanner accepts one sealed ECMAScript :class:`SymbolIndex`, rebuilds the
index from the admitted bytes, and reports only explicit session and token
creation paths whose lifetime is missing, zero, or statically unbounded.
Dynamic options are ignored when their safety cannot be established.  This
keeps the detector useful for common Express, Koa, cookie, jsonwebtoken, and
JOSE patterns without treating arbitrary ``cookie`` or ``sign`` calls as
security findings.

Results contain immutable source ranges and content-addressed identity only.
Source text is never retained in a finding or exposed through an error.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import ParseHealth, RepositoryFile, SourcePoint, SourceRange, SymbolIndex
from tree_sitter import Language, Node, Parser

from .cst import CstAdapterError, build_javascript_symbol_index, build_typescript_symbol_index
from .cst_ecmascript import _javascript_language, _typescript_language

_MAX_LIMITS = (2_000_000, 250_000, 512, 10_000)
_MAX_LIFETIME_MILLISECONDS = 30 * 24 * 60 * 60 * 1000
_MAX_LIFETIME_SECONDS = 30 * 24 * 60 * 60
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_RULE_ID = "securecode-ecmascript-cwe613"
_DETECTOR = "securecode-ecmascript-cwe613@1.0"
_DETAIL = "session_without_bounded_expiration"

_COOKIE_ROOTS = frozenset(
    {
        "app",
        "ctx",
        "context",
        "reply",
        "res",
        "response",
        "router",
        "server",
    }
)
_COOKIE_SETTERS = frozenset({"cookie", "setCookie", "set_cookie"})
_COOKIE_SERIALIZERS = frozenset({"cookie.serialize", "set-cookie.serialize"})
_SESSION_MODULES = frozenset(
    {
        "cookie-session",
        "express-session",
        "koa-session",
        "koa-session-minimal",
        "fastify-session",
    }
)
_SESSION_NAMES = frozenset({"session", "sessionMiddleware", "sessionMiddlewareFactory"})
_JWT_SIGNERS = frozenset(
    {
        "jsonwebtoken.sign",
        "jose.SignJWT.sign",
        "jose.SignJWT.compactSign",
        "jwt.sign",
    }
)
_EXPIRATION_KEYS = frozenset(
    {
        "expires",
        "expiresIn",
        "expiration",
        "expirationTime",
        "lifetime",
        "maxAge",
        "sessionLifetime",
        "sessionTtl",
        "ttl",
    }
)
_COOKIE_EXPIRATION_KEYS = frozenset({"expires", "maxAge", "ttl"})
_JWT_EXPIRATION_KEYS = frozenset({"expiresIn", "expiration", "expirationTime", "ttl"})
_SENSITIVE_NAMES = frozenset(
    {
        "access",
        "access_token",
        "auth",
        "authn",
        "authz",
        "credential",
        "credentials",
        "id_token",
        "identity",
        "jwt",
        "login",
        "oauth",
        "oauth_token",
        "refresh",
        "refresh_token",
        "remember",
        "remember_me",
        "session",
        "session_id",
        "sessionid",
        "sessid",
        "sid",
        "token",
    }
_SENSITIVE_NAME_RE = re.compile(
    r"(?:^|[_./:-])(?:access|auth|credential|id.?token|identity|jwt|login|oauth|refresh|remember|session|sid|token)(?:$|[_./:-])",
    re.IGNORECASE,
)
_DURATION_RE = re.compile(r"\A([+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+))\s*(ms|s|m|h|d|w)?\Z", re.IGNORECASE)
_YEAR_RE = re.compile(r"\A(?:[+-]?)(\d{4})[-/]\d{1,2}[-/]\d{1,2}")


class EcmaScriptCwe613ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-613 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe613ScanError(RuntimeError):
    """Fixed scanner failure which never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe613ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe613ScanErrorCode:
            raise TypeError("ECMAScript CWE-613 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-613 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe613ScanLimits:
    """Hard ceilings applied before and during structural analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_nodes: int = _MAX_LIMITS[1]
    max_depth: int = _MAX_LIMITS[2]
    max_signals: int = _MAX_LIMITS[3]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_nodes, self.max_depth, self.max_signals)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("ECMAScript CWE-613 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE613_SCAN_LIMITS = EcmaScriptCwe613ScanLimits()


class EcmaScriptCwe613Operation(StrEnum):
    """Recognised session and token boundaries with an unsafe lifetime."""

    COOKIE_MISSING_EXPIRY = "cookie_missing_expiry"
    COOKIE_UNBOUNDED_EXPIRY = "cookie_unbounded_expiry"
    SESSION_MIDDLEWARE_MISSING_EXPIRY = "session_middleware_missing_expiry"
    SESSION_MIDDLEWARE_UNBOUNDED_EXPIRY = "session_middleware_unbounded_expiry"
    TOKEN_MISSING_EXPIRY = "token_missing_expiry"
    TOKEN_UNBOUNDED_EXPIRY = "token_unbounded_expiry"
    DOCUMENT_COOKIE_MISSING_EXPIRY = "document_cookie_missing_expiry"
    DOCUMENT_COOKIE_UNBOUNDED_EXPIRY = "document_cookie_unbounded_expiry"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe613Signal:
    """One immutable source-to-session-lifetime fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe613Operation
    subject: str = "session"
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-613"
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
            and type(self.subject) is str
            and 0 < len(self.subject) <= 256
            and len(self.subject.encode("utf-8")) <= 1024
        )
        if valid_identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid_identity = False
        valid_ranges = (
            type(self.source) is SourceRange
            and type(self.sink) is SourceRange
            and self.sink.contains(self.source)
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
                self.subject,
            )
            if valid_identity
            and valid_ranges
            and type(self.operation) is EcmaScriptCwe613Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not EcmaScriptCwe613Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-613"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("ECMAScript CWE-613 signal is invalid")
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
class EcmaScriptCwe613ScanResult:
    """Deterministic and source-free CWE-613 output for one source file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe613Signal, ...]
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
            and self.language in {"javascript", "typescript"}
        )
        if valid_identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid_identity = False
        valid_signals = type(self.signals) is tuple and all(
            type(item) is EcmaScriptCwe613Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    item.sink.start_byte,
                    item.sink.end_byte,
                    item.source.start_byte,
                    item.source.end_byte,
                    item.operation.value,
                    item.subject,
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
                self.language,
                self.signals,
            )
        ):
            raise ValueError("ECMAScript CWE-613 scan result is invalid")


def scan_javascript_cwe613(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe613ScanLimits = DEFAULT_ECMASCRIPT_CWE613_SCAN_LIMITS,
) -> EcmaScriptCwe613ScanResult:
    """Find bounded JavaScript session and token lifetime facts."""

    return _scan_ecmascript_cwe613(
        symbol_index, expected_language="javascript", limits=limits
    )


def scan_typescript_cwe613(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe613ScanLimits = DEFAULT_ECMASCRIPT_CWE613_SCAN_LIMITS,
) -> EcmaScriptCwe613ScanResult:
    """Find bounded TypeScript session and token lifetime facts."""

    return _scan_ecmascript_cwe613(
        symbol_index, expected_language="typescript", limits=limits
    )


def scan_ecmascript_cwe613(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe613ScanLimits = DEFAULT_ECMASCRIPT_CWE613_SCAN_LIMITS,
) -> EcmaScriptCwe613ScanResult:
    """Dispatch a CWE-613 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe613ScanError(EcmaScriptCwe613ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe613(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe613(symbol_index, limits=limits)
    raise EcmaScriptCwe613ScanError(EcmaScriptCwe613ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe613(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe613ScanLimits,
) -> EcmaScriptCwe613ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe613ScanLimits:
        raise EcmaScriptCwe613ScanError(EcmaScriptCwe613ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe613ScanError(EcmaScriptCwe613ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe613ScanError(EcmaScriptCwe613ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe613ScanError(EcmaScriptCwe613ScanErrorCode.ANALYSIS_UNAVAILABLE)

    builder = (
        build_javascript_symbol_index
        if expected_language == "javascript"
        else build_typescript_symbol_index
    )
    try:
        rebuilt = builder(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source=symbol_index.source,
        )
        if rebuilt != symbol_index:
            raise ValueError("symbol index mismatch")
        grammar = (
            _javascript_language()
            if expected_language == "javascript"
            else _typescript_language(tsx=symbol_index.path.endswith(".tsx"))
        )
        source = symbol_index.source
        source.decode("utf-8", errors="strict")
        root = Parser(Language(grammar)).parse(source).root_node
    except (CstAdapterError, TypeError, UnicodeDecodeError, ValueError):
        raise EcmaScriptCwe613ScanError(
            EcmaScriptCwe613ScanErrorCode.INTEGRITY_FAILURE
        ) from None
    except Exception:
        raise EcmaScriptCwe613ScanError(
            EcmaScriptCwe613ScanErrorCode.INTEGRITY_FAILURE
        ) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe613ScanError(
                EcmaScriptCwe613ScanErrorCode.ANALYSIS_UNAVAILABLE
            )
        aliases = _collect_aliases(nodes, source)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe613Operation, str]] = set()
        for node in nodes:
            if node.type == "assignment_expression":
                candidate = _document_cookie_candidate(node, source)
                if candidate is not None:
                    raw.add(candidate)
                    if len(raw) > limits.max_signals:
                        raise EcmaScriptCwe613ScanError(
                            EcmaScriptCwe613ScanErrorCode.SIGNAL_LIMIT
                        )
                continue
            if node.type not in {"call_expression", "new_expression"}:
                continue
            candidate = _call_candidate(node, source, aliases)
            if candidate is not None:
                raw.add(candidate)
                if len(raw) > limits.max_signals:
                    raise EcmaScriptCwe613ScanError(
                        EcmaScriptCwe613ScanErrorCode.SIGNAL_LIMIT
                    )
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
    except EcmaScriptCwe613ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe613ScanError(
            EcmaScriptCwe613ScanErrorCode.INTEGRITY_FAILURE
        ) from None

    signals = tuple(
        EcmaScriptCwe613Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
            subject=subject,
        )
        for source_range, sink_range, operation, subject in ordered
    )
    return EcmaScriptCwe613ScanResult(
        repository_id=symbol_index.repository_id,
        revision=symbol_index.revision,
        path=symbol_index.path,
        content_sha256=symbol_index.content_sha256,
        source_size_bytes=symbol_index.source_byte_length,
        language=expected_language,
        signals=signals,
        scan_sha256=_scan_sha256(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            expected_language,
            signals,
        ),
    )


@dataclass(frozen=True, slots=True)
class _Candidate:
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe613Operation
    subject: str


class _ExpiryState(StrEnum):
    MISSING = "missing"
    UNSAFE = "unsafe"
    SAFE = "safe"
    UNKNOWN = "unknown"


def _bounded_nodes(root: Node, limits: EcmaScriptCwe613ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe613ScanError(EcmaScriptCwe613ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe613ScanError(EcmaScriptCwe613ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _call_candidate(
    node: Node, source: bytes, aliases: dict[str, str]
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe613Operation, str] | None:
    function = node.child_by_field_name("function")
    if node.type == "new_expression":
        function = node.child_by_field_name("constructor") or function
    if function is None:
        return None
    canonical = _canonical_expression(function, source, aliases) or ""
    arguments = node.child_by_field_name("arguments")
    values = arguments.named_children if arguments is not None else ()
    sink = _range(node)

    if _is_cookie_operation(canonical):
        if len(values) < 1:
            return None
        name = _string_value(values[0], source)
        if name is None or not _is_sensitive_name(name):
            return None
        options = values[2] if len(values) >= 3 else None
        state = _cookie_expiry_state(options, source)
        if state not in {_ExpiryState.MISSING, _ExpiryState.UNSAFE}:
            return None
        operation = (
            EcmaScriptCwe613Operation.COOKIE_MISSING_EXPIRY
            if state is _ExpiryState.MISSING
            else EcmaScriptCwe613Operation.COOKIE_UNBOUNDED_EXPIRY
        )
        subject = _subject(name)
        subject_node = values[0]
        return _candidate_tuple(subject_node, sink, operation, subject)

    if _is_session_operation(canonical):
        options = values[0] if values else None
        state = _session_expiry_state(options, source)
        if state not in {_ExpiryState.MISSING, _ExpiryState.UNSAFE}:
            return None
        operation = (
            EcmaScriptCwe613Operation.SESSION_MIDDLEWARE_MISSING_EXPIRY
            if state is _ExpiryState.MISSING
            else EcmaScriptCwe613Operation.SESSION_MIDDLEWARE_UNBOUNDED_EXPIRY
        )
        source_node = options or node
        return _candidate_tuple(source_node, sink, operation, "session")

    if _is_jwt_signer(canonical, function, source, aliases):
        payload = values[0] if values else None
        payload_state = _ExpiryState.UNKNOWN
        if payload is not None:
            payload_state = _payload_expiry_state(payload, source)
            if payload_state is _ExpiryState.SAFE:
                return None
        options = values[2] if len(values) >= 3 else None
        if payload_state is _ExpiryState.UNSAFE:
            state = _ExpiryState.UNSAFE
        elif payload_state is _ExpiryState.UNKNOWN and options is None:
            return None
        else:
            state = _jwt_expiry_state(options, source)
        if state is _ExpiryState.UNKNOWN and _has_expiration_chain(function, source):
            state = _chain_expiry_state(function, source)
        if state not in {_ExpiryState.MISSING, _ExpiryState.UNSAFE}:
            return None
        operation = (
            EcmaScriptCwe613Operation.TOKEN_MISSING_EXPIRY
            if state is _ExpiryState.MISSING
            else EcmaScriptCwe613Operation.TOKEN_UNBOUNDED_EXPIRY
        )
        source_node = options or payload or node
        return _candidate_tuple(source_node, sink, operation, "token")
    return None


def _candidate_tuple(
    source_node: Node,
    sink: SourceRange,
    operation: EcmaScriptCwe613Operation,
    subject: str,
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe613Operation, str]:
    source_range = _range(source_node)
    if not sink.contains(source_range):
        raise EcmaScriptCwe613ScanError(EcmaScriptCwe613ScanErrorCode.INTEGRITY_FAILURE)
    return (source_range, sink, operation, subject)


def _document_cookie_candidate(
    node: Node, source: bytes
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe613Operation, str] | None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None or _compact_text(source, left).lower() != "document.cookie":
        return None
    value = _string_value(right, source)
    if value is None:
        return None
    match = re.match(r"([^=;\s]{1,256})=", value)
    if match is None or not _is_sensitive_name(match.group(1)):
        return None
    normalized = value.lower()
    if "max-age=" in normalized:
        marker = re.search(r"max-age=\s*([+-]?[0-9]+)", normalized)
        if marker is None:
            return None
        try:
            max_age = int(marker.group(1), 10)
        except ValueError:
            return None
        if 0 < max_age <= _MAX_LIFETIME_SECONDS:
            return None
        operation = EcmaScriptCwe613Operation.DOCUMENT_COOKIE_UNBOUNDED_EXPIRY
    elif "expires=" in normalized:
        year = _YEAR_RE.search(normalized.split("expires=", 1)[-1])
        if year is None or int(year.group(1)) < 2099:
            return None
        operation = EcmaScriptCwe613Operation.DOCUMENT_COOKIE_UNBOUNDED_EXPIRY
    else:
        operation = EcmaScriptCwe613Operation.DOCUMENT_COOKIE_MISSING_EXPIRY
    return _candidate_tuple(right, _range(node), operation, _subject(match.group(1)))


def _is_cookie_operation(canonical: str) -> bool:
    if canonical in _COOKIE_SERIALIZERS:
        return True
    parts = canonical.replace("?.", ".").split(".")
    if not parts:
        return False
    if parts[-1] not in _COOKIE_SETTERS:
        return False
    if len(parts) < 2:
        return parts[-1] in {"setCookie", "set_cookie"}
    return parts[0] in _COOKIE_ROOTS or parts[-2] in {"cookies", "cookie"}


def _is_session_operation(canonical: str) -> bool:
    if canonical in _SESSION_MODULES:
        return True
    if canonical in _SESSION_NAMES:
        return True
    return canonical.rsplit(".", 1)[-1] in _SESSION_NAMES


def _is_jwt_signer(
    canonical: str, function: Node, source: bytes, aliases: dict[str, str]
) -> bool:
    if canonical in _JWT_SIGNERS:
        return True
    if canonical.endswith((".SignJWT.sign", ".SignJWT.compactSign")):
        return True
    if _member_property(function, source) not in {"sign", "compactSign"}:
        return False
    return _contains_sign_jwt_owner(function, source, aliases)


def _contains_sign_jwt_owner(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    current = _unwrap(node)
    if current.type in {"member_expression", "subscript_expression"}:
        object_node = current.child_by_field_name("object")
        if object_node is None:
            return False
        return _contains_sign_jwt_owner(object_node, source, aliases)
    if current.type == "call_expression":
        function = current.child_by_field_name("function")
        return _contains_sign_jwt_owner(function, source, aliases) if function is not None else False
    if current.type == "new_expression":
        constructor = current.child_by_field_name("constructor") or current.child_by_field_name(
            "function"
        )
        if constructor is None:
            return False
        canonical = _canonical_expression(constructor, source, aliases) or ""
        return canonical.endswith(".SignJWT") or _compact_text(source, constructor).endswith("SignJWT")
    return False


def _cookie_expiry_state(options: Node | None, source: bytes) -> _ExpiryState:
    if options is None:
        return _ExpiryState.MISSING
    current = _unwrap(options)
    if current.type != "object":
        return _ExpiryState.UNKNOWN
    return _object_expiry_state(current, source, _COOKIE_EXPIRATION_KEYS)


def _session_expiry_state(options: Node | None, source: bytes) -> _ExpiryState:
    if options is None:
        return _ExpiryState.MISSING
    current = _unwrap(options)
    if current.type != "object":
        return _ExpiryState.UNKNOWN
    cookie = _object_property(current, source, "cookie")
    if cookie is not None:
        return _cookie_expiry_state(cookie, source)
    return _object_expiry_state(current, source, _COOKIE_EXPIRATION_KEYS)


def _jwt_expiry_state(options: Node | None, source: bytes) -> _ExpiryState:
    if options is None:
        return _ExpiryState.MISSING
    current = _unwrap(options)
    if current.type != "object":
        return _ExpiryState.UNKNOWN
    return _object_expiry_state(current, source, _JWT_EXPIRATION_KEYS, unit="seconds")


def _object_expiry_state(
    current: Node,
    source: bytes,
    keys: frozenset[str],
    *,
    unit: str = "milliseconds",
) -> _ExpiryState:
    found = False
    unknown = False
    for key, value in _object_properties(current, source):
        if key not in keys:
            continue
        found = True
        state = _static_expiry_state(value, source, unit=unit)
        if state is _ExpiryState.SAFE:
            return state
        if state is _ExpiryState.UNKNOWN:
            unknown = True
        elif state is _ExpiryState.UNSAFE:
            return state
    if not found:
        return _ExpiryState.MISSING
    return _ExpiryState.UNKNOWN if unknown else _ExpiryState.UNSAFE


def _static_expiry_state(node: Node, source: bytes, *, unit: str) -> _ExpiryState:
    current = _unwrap(node)
    compact = _compact_text(source, current)
    lowered = compact.lower()
    if current.type in {"null", "undefined"} or lowered in {
        "null",
        "undefined",
        "infinity",
        "+infinity",
        "number.infinity",
        "number.positiveinfinity",
        "number.maxvalue",
        "number.maxsafeinteger",
    }:
        return _ExpiryState.UNSAFE
    if current.type in {"false", "true"}:
        return _ExpiryState.UNSAFE if current.type == "false" else _ExpiryState.UNKNOWN
    number = _number_value(compact)
    if number is not None:
        return _bounded_number_state(number, unit)
    string = _string_value(current, source)
    if string is not None:
        return _duration_state(string, unit)
    delta = _static_delta(current, source)
    if delta is not None:
        return _bounded_number_state(delta, unit)
    if current.type == "new_expression":
        constructor = current.child_by_field_name("constructor")
        arguments = current.child_by_field_name("arguments")
        if constructor is not None and _compact_text(source, constructor) == "Date":
            values = arguments.named_children if arguments is not None else ()
            if not values:
                return _ExpiryState.UNSAFE
            return _static_expiry_state(values[0], source, unit=unit)
    return _ExpiryState.UNKNOWN


def _payload_expiry_state(node: Node, source: bytes) -> _ExpiryState:
    current = _unwrap(node)
    if current.type != "object":
        return _ExpiryState.UNKNOWN
    value = _object_property(current, source, "exp")
    if value is None:
        return _ExpiryState.MISSING
    return _static_expiry_state(value, source, unit="seconds")


def _has_expiration_chain(node: Node, source: bytes) -> bool:
    current = _unwrap(node)
    if current.type == "call_expression":
        function = current.child_by_field_name("function")
        if function is None:
            return False
        if _member_property(function, source) in {"setExpirationTime", "setExpiration"}:
            return True
        return _has_expiration_chain(function, source)
    if current.type in {"member_expression", "subscript_expression"}:
        object_node = current.child_by_field_name("object")
        return _has_expiration_chain(object_node, source) if object_node is not None else False
    return False


def _chain_expiry_state(node: Node, source: bytes) -> _ExpiryState:
    current = _unwrap(node)
    if current.type == "call_expression":
        function = current.child_by_field_name("function")
        if function is None:
            return _ExpiryState.UNKNOWN
        if _member_property(function, source) in {"setExpirationTime", "setExpiration"}:
            arguments = current.child_by_field_name("arguments")
            values = arguments.named_children if arguments is not None else ()
            if values:
                return _static_expiry_state(values[0], source, unit="seconds")
            return _ExpiryState.UNSAFE
        return _chain_expiry_state(function, source)
    if current.type in {"member_expression", "subscript_expression"}:
        object_node = current.child_by_field_name("object")
        if object_node is not None:
            return _chain_expiry_state(object_node, source)
    return _ExpiryState.UNKNOWN


def _member_property(node: Node, source: bytes) -> str | None:
    current = _unwrap(node)
    if current.type not in {"member_expression", "subscript_expression"}:
        return None
    property_node = current.child_by_field_name("property") or current.child_by_field_name("index")
    return _static_property_name(property_node, source) if property_node is not None else None


def _bounded_number_state(value: float, unit: str) -> _ExpiryState:
    if value <= 0:
        return _ExpiryState.UNSAFE
    ceiling = (
        _MAX_LIFETIME_SECONDS
        if unit == "seconds"
        else _MAX_LIFETIME_MILLISECONDS
    )
    return _ExpiryState.SAFE if value <= ceiling else _ExpiryState.UNSAFE


def _duration_state(value: str, unit: str) -> _ExpiryState:
    lowered = value.strip().lower()
    if lowered in {"", "session", "never", "infinite", "infinity", "forever"}:
        return _ExpiryState.UNSAFE
    match = _DURATION_RE.fullmatch(lowered)
    if match is None:
        year = _YEAR_RE.match(lowered)
        if year is not None and int(year.group(1)) >= 2099:
            return _ExpiryState.UNSAFE
        return _ExpiryState.UNKNOWN
    try:
        number = float(match.group(1))
    except ValueError:
        return _ExpiryState.UNKNOWN
    suffix = (match.group(2) or ("s" if unit == "seconds" else "ms")).lower()
    multiplier = {"ms": 1.0, "s": 1000.0, "m": 60_000.0, "h": 3_600_000.0, "d": 86_400_000.0, "w": 604_800_000.0}[suffix]
    milliseconds = number * multiplier
    if unit == "seconds":
        return _bounded_number_state(milliseconds / 1000.0, "seconds")
    return _bounded_number_state(milliseconds, "milliseconds")


def _static_delta(node: Node, source: bytes) -> float | None:
    current = _unwrap(node)
    if current.type == "call_expression":
        function = current.child_by_field_name("function")
        arguments = current.child_by_field_name("arguments")
        if function is None or arguments is None:
            return None
        function_name = _compact_text(source, function)
        if function_name == "Date.now" and not arguments.named_children:
            return 0.0
        if function_name in {"Math.floor", "Math.ceil", "Math.round"}:
            values = arguments.named_children
            return _static_delta(values[0], source) if len(values) == 1 else None
        return None
    if current.type not in {"binary_expression", "parenthesized_expression"}:
        return None
    if current.type == "parenthesized_expression":
        values = current.named_children
        return _static_delta(values[0], source) if values else None
    left = current.child_by_field_name("left")
    right = current.child_by_field_name("right")
    operator = next(
        (child for child in current.children if child.type in {"+", "-", "*", "/"}),
        None,
    )
    if left is None or right is None or operator is None:
        return None
    left_delta = _static_delta(left, source)
    right_delta = _number_value(_compact_text(source, right))
    if left_delta is not None and right_delta is not None:
        if operator.type == "+":
            return left_delta + right_delta
        if operator.type == "-":
            return left_delta - right_delta
        if operator.type in {"*", "/"}:
            return 0.0
        return None
    right_delta = _static_delta(right, source)
    left_number = _number_value(_compact_text(source, left))
    if right_delta is not None and left_number is not None:
        if operator.type == "+":
            return left_number + right_delta
        if operator.type == "-":
            return left_number - right_delta
        if operator.type == "*":
            return left_number * right_delta
        if operator.type == "/" and right_delta != 0:
            return left_number / right_delta
    return None


def _number_value(value: str) -> float | None:
    compact = value.replace("_", "")
    if compact.lower() in {"infinity", "+infinity", "number.infinity", "number.maxvalue", "number.maxsafeinteger"}:
        return float("inf")
    try:
        if not re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)", compact):
            return None
        return float(compact)
    except ValueError:
        return None


def _object_property(node: Node, source: bytes, name: str) -> Node | None:
    for key, value in _object_properties(node, source):
        if key == name:
            return value
    return None


def _object_properties(node: Node, source: bytes) -> tuple[tuple[str, Node], ...]:
    current = _unwrap(node)
    if current.type != "object":
        return ()
    result: list[tuple[str, Node]] = []
    for child in current.named_children:
        if child.type not in {"pair", "object_pattern_property", "shorthand_property_identifier_pattern"}:
            continue
        key = child.child_by_field_name("key") or child.child_by_field_name("name")
        value = child.child_by_field_name("value")
        names = list(child.named_children)
        if key is None and names:
            key = names[0]
        if value is None and len(names) >= 2:
            value = names[-1]
        if key is None or value is None:
            continue
        key_name = _static_property_name(key, source)
        if key_name is not None:
            result.append((key_name, value))
    return tuple(result)


def _collect_aliases(nodes: tuple[Node, ...], source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in nodes:
        if node.type == "import_statement":
            _collect_import_aliases(node, source, aliases)
        elif node.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in node.named_children:
                if declarator.type != "variable_declarator":
                    continue
                name = declarator.child_by_field_name("name")
                value = declarator.child_by_field_name("value")
                if name is None or value is None:
                    continue
                canonical = _canonical_expression(value, source, aliases)
                if canonical is None:
                    continue
                if name.type == "identifier":
                    aliases[_text(source, name)] = canonical
                elif name.type in {"object_pattern", "object"}:
                    _collect_pattern_aliases(name, canonical, source, aliases)
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                canonical = _canonical_expression(right, source, aliases)
                if canonical is not None:
                    aliases[_text(source, left)] = canonical
    return aliases


def _collect_import_aliases(node: Node, source: bytes, aliases: dict[str, str]) -> None:
    module_node = node.child_by_field_name("source")
    if module_node is None:
        return
    module = _string_value(module_node, source)
    if module is None:
        return
    module = _normalise_module(module)
    for clause in node.named_children:
        if clause.type != "import_clause":
            continue
        for item in clause.named_children:
            if item.type == "identifier":
                aliases[_text(source, item)] = module
            elif item.type == "namespace_import":
                children = item.named_children
                if children:
                    aliases[_text(source, children[-1])] = module
            elif item.type in {"named_imports", "named_import"}:
                for specifier in item.named_children:
                    if specifier.type != "import_specifier":
                        continue
                    names = list(specifier.named_children)
                    if names:
                        aliases[_text(source, names[-1])] = f"{module}.{_text(source, names[0])}"


def _collect_pattern_aliases(
    pattern: Node, module: str, source: bytes, aliases: dict[str, str]
) -> None:
    for child in pattern.named_children:
        if child.type not in {"pair", "object_pattern_property", "shorthand_property_identifier_pattern"}:
            continue
        key = child.child_by_field_name("key") or child
        value = child.child_by_field_name("value") or key
        key_name = _static_property_name(key, source)
        value_name = _static_property_name(value, source)
        if key_name is not None and value_name is not None:
            aliases[value_name] = f"{module}.{key_name}"


def _canonical_expression(node: Node, source: bytes, aliases: dict[str, str]) -> str | None:
    current = _unwrap(node)
    if current.type == "call_expression":
        function = current.child_by_field_name("function")
        arguments = current.child_by_field_name("arguments")
        if function is None or arguments is None or _compact_text(source, function) != "require":
            return None
        values = arguments.named_children
        if len(values) != 1:
            return None
        module = _string_value(values[0], source)
        return _normalise_module(module) if module is not None else None
    if current.type == "new_expression":
        constructor = current.child_by_field_name("constructor") or current.child_by_field_name(
            "function"
        )
        return _canonical_expression(constructor, source, aliases) if constructor is not None else None
    if current.type in {"member_expression", "subscript_expression"}:
        object_node = current.child_by_field_name("object")
        property_node = current.child_by_field_name("property") or current.child_by_field_name("index")
        if object_node is None or property_node is None:
            return None
        base = _canonical_expression(object_node, source, aliases)
        if base is None:
            base = _canonical_name(_compact_text(source, object_node), aliases)
        property_name = _static_property_name(property_node, source)
        return None if base is None or property_name is None else f"{base}.{property_name}"
    return _canonical_name(_compact_text(source, current), aliases)


def _canonical_name(value: str, aliases: dict[str, str]) -> str:
    parts = value.split(".")
    if not parts or not _IDENTIFIER.fullmatch(parts[0]):
        return value
    base = aliases.get(parts[0], parts[0])
    return base if len(parts) == 1 else ".".join((base, *parts[1:]))


def _normalise_module(value: str) -> str:
    return value[5:] if value.startswith("node:") else value


def _is_sensitive_name(value: str) -> bool:
    compact = value.strip().lower().replace("-", "_")
    return compact in _SENSITIVE_NAMES or bool(_SENSITIVE_NAME_RE.search(value))


def _subject(value: str) -> str:
    compact = value.strip()
    return compact[:256]


def _static_property_name(node: Node, source: bytes) -> str | None:
    current = _unwrap(node)
    if current.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        return _text(source, current)
    if current.type in {"string", "string_fragment"}:
        return _string_value(current, source)
    return None


def _unwrap(node: Node) -> Node:
    current = node
    while current.type in {"parenthesized_expression", "as_expression", "non_null_expression"}:
        values = list(current.named_children)
        if not values:
            break
        current = values[-1]
    return current


def _string_value(node: Node, source: bytes) -> str | None:
    current = _unwrap(node)
    if current.type not in {"string", "string_fragment"}:
        return None
    value = source[current.start_byte : current.end_byte]
    if current.type == "string":
        if len(value) < 2 or value[:1] not in {b"'", b'"', b"`"} or value[-1:] != value[:1]:
            return None
        value = value[1:-1]
    if b"\\" in value or b"\n" in value or b"\r" in value:
        return None
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe613ScanError(
            EcmaScriptCwe613ScanErrorCode.INTEGRITY_FAILURE
        ) from None


def _text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe613ScanError(
            EcmaScriptCwe613ScanErrorCode.INTEGRITY_FAILURE
        ) from None


def _compact_text(source: bytes, node: Node) -> str:
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
    operation: EcmaScriptCwe613Operation,
    subject: str,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "sink": _range_value(sink),
        "source": _range_value(source),
        "source_size_bytes": source_size_bytes,
        "subject": subject,
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
    language: str,
    signals: tuple[EcmaScriptCwe613Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
        "language": language,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "detector": signal.detector,
                "operation": signal.operation.value,
                "rule_id": signal.rule_id,
                "signal_id": signal.signal_id,
                "sink": _range_value(signal.sink),
                "source": _range_value(signal.source),
                "subject": signal.subject,
            }
            for signal in signals
        ],
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


Cwe613ScanErrorCode = EcmaScriptCwe613ScanErrorCode
Cwe613ScanError = EcmaScriptCwe613ScanError
Cwe613ScanLimits = EcmaScriptCwe613ScanLimits
Cwe613ScanResult = EcmaScriptCwe613ScanResult
Cwe613Signal = EcmaScriptCwe613Signal

scan_javascript_session_expiration = scan_javascript_cwe613
scan_typescript_session_expiration = scan_typescript_cwe613
scan_ecmascript_session_expiration = scan_ecmascript_cwe613
scan_javascript_insufficient_session_expiration = scan_javascript_cwe613
scan_typescript_insufficient_session_expiration = scan_typescript_cwe613
scan_ecmascript_insufficient_session_expiration = scan_ecmascript_cwe613

__all__ = [
    "Cwe613ScanError",
    "Cwe613ScanErrorCode",
    "Cwe613ScanLimits",
    "Cwe613ScanResult",
    "Cwe613Signal",
    "DEFAULT_ECMASCRIPT_CWE613_SCAN_LIMITS",
    "EcmaScriptCwe613Operation",
    "EcmaScriptCwe613ScanError",
    "EcmaScriptCwe613ScanErrorCode",
    "EcmaScriptCwe613ScanLimits",
    "EcmaScriptCwe613ScanResult",
    "EcmaScriptCwe613Signal",
    "scan_ecmascript_cwe613",
    "scan_ecmascript_insufficient_session_expiration",
    "scan_ecmascript_session_expiration",
    "scan_javascript_cwe613",
    "scan_javascript_insufficient_session_expiration",
    "scan_javascript_session_expiration",
    "scan_typescript_cwe613",
    "scan_typescript_insufficient_session_expiration",
    "scan_typescript_session_expiration",
]
