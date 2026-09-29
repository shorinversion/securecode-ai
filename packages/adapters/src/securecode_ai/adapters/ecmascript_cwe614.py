"""Bounded JavaScript and TypeScript CWE-614 cookie security facts.

The adapter accepts one sealed ECMAScript :class:`SymbolIndex`, rebuilds it
from the exact admitted bytes, and reports only statically provable sensitive
cookies emitted without the ``Secure`` attribute.  It recognises the common
Express, Koa, Fastify, ``cookie`` package, Node response-header, and browser
``document.cookie`` forms.  Dynamic cookie names, options, header arrays, and
unresolved aliases are ignored because their security properties cannot be
proven from the bounded syntax alone.

``HttpOnly`` is intentionally not inferred here.  The existing CWE-614
contract is about transport confidentiality through ``Secure``; browsers do
not permit ``HttpOnly`` to be set through ``document.cookie`` and the adapter
does not broaden that contract to make an independent claim.

Results retain immutable ranges and content-addressed metadata only.  The
scanner does not import application code, execute calls, retain source text,
or echo source/parser details through errors.
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
from .ecmascript_cwe22 import (
    _enclosing_scope,
    _latest_binding,
    _string_value,
    _text,
)

_MAX_LIMITS = (2_000_000, 250_000, 512, 10_000)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_RULE_ID = "securecode-ecmascript-cwe614"
_DETECTOR = "securecode-ecmascript-cwe614@1.0"
_DETAIL = "sensitive_cookie_without_secure_flag"

_RESPONSE_ROOTS = frozenset(
    {
        "app",
        "ctx",
        "context",
        "httpResponse",
        "reply",
        "res",
        "response",
        "server",
    }
)
_COOKIE_MODULES = frozenset({"cookie", "cookies"})
_COOKIE_SETTERS = frozenset({"cookie", "setCookie", "set_cookie"})
_HEADER_METHODS = frozenset({"append", "header", "set", "setHeader"})
_SENSITIVE_NAMES = frozenset(
    {
        "access",
        "access_token",
        "auth",
        "authn",
        "authz",
        "authtoken",
        "credential",
        "credentials",
        "csrf",
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
)
_SENSITIVE_NAME_RE = re.compile(
    r"(?:^|[_./:-])(?:access|auth|credential|csrf|id.?token|identity|jwt|login|oauth|refresh|remember|session|sid|token)(?:$|[_./:-])",
    re.IGNORECASE,
)


class EcmaScriptCwe614ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-614 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe614ScanError(RuntimeError):
    """Fixed scanner failure that never exposes repository source details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe614ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe614ScanErrorCode:
            raise TypeError("ECMAScript CWE-614 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-614 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe614ScanLimits:
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
            raise ValueError("ECMAScript CWE-614 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE614_SCAN_LIMITS = EcmaScriptCwe614ScanLimits()


class EcmaScriptCwe614Operation(StrEnum):
    """Recognised response and browser cookie emission boundaries."""

    EXPRESS_RESPONSE_COOKIE = "express.response.cookie"
    KOA_CONTEXT_COOKIES_SET = "koa.context.cookies.set"
    FASTIFY_REPLY_SET_COOKIE = "fastify.reply.setCookie"
    COOKIE_SERIALIZE = "cookie.serialize"
    COOKIES_SET = "cookies.set"
    RESPONSE_SET_HEADER = "response.setHeader"
    RESPONSE_HEADER = "response.header"
    RESPONSE_APPEND = "response.append"
    RESPONSE_SET = "response.set"
    RESPONSE_WRITE_HEAD = "response.writeHead"
    DOCUMENT_COOKIE = "document.cookie"

    # Compatibility names for generic scanner consumers.
    SET_COOKIE = "express.response.cookie"
    COOKIE = "express.response.cookie"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe614Signal:
    """One immutable sensitive-cookie fact without source text."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe614Operation
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
            and len(self.cookie_name.encode("utf-8")) <= 1024
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
                self.cookie_name,
            )
            if valid_identity and valid_ranges and type(self.operation) is EcmaScriptCwe614Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not EcmaScriptCwe614Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-614"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("ECMAScript CWE-614 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete cookie emission location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe614ScanResult:
    """Deterministic, source-free result for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe614Signal, ...]
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
            type(item) is EcmaScriptCwe614Signal for item in self.signals
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
                self.language,
                self.signals,
            )
        ):
            raise ValueError("ECMAScript CWE-614 scan result is invalid")


def scan_javascript_cwe614(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe614ScanLimits = DEFAULT_ECMASCRIPT_CWE614_SCAN_LIMITS,
) -> EcmaScriptCwe614ScanResult:
    """Find bounded JavaScript sensitive-cookie facts."""

    return _scan_ecmascript_cwe614(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe614(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe614ScanLimits = DEFAULT_ECMASCRIPT_CWE614_SCAN_LIMITS,
) -> EcmaScriptCwe614ScanResult:
    """Find bounded TypeScript sensitive-cookie facts."""

    return _scan_ecmascript_cwe614(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe614(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe614ScanLimits = DEFAULT_ECMASCRIPT_CWE614_SCAN_LIMITS,
) -> EcmaScriptCwe614ScanResult:
    """Dispatch a CWE-614 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe614ScanError(EcmaScriptCwe614ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe614(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe614(symbol_index, limits=limits)
    raise EcmaScriptCwe614ScanError(EcmaScriptCwe614ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe614(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe614ScanLimits,
) -> EcmaScriptCwe614ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe614ScanLimits:
        raise EcmaScriptCwe614ScanError(EcmaScriptCwe614ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe614ScanError(EcmaScriptCwe614ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe614ScanError(EcmaScriptCwe614ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe614ScanError(EcmaScriptCwe614ScanErrorCode.ANALYSIS_UNAVAILABLE)

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
        raise EcmaScriptCwe614ScanError(EcmaScriptCwe614ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe614ScanError(EcmaScriptCwe614ScanErrorCode.INTEGRITY_FAILURE) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe614ScanError(EcmaScriptCwe614ScanErrorCode.ANALYSIS_UNAVAILABLE)
        aliases = _collect_aliases(nodes, source)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe614Operation, str]] = set()
        for node in nodes:
            if node.type == "assignment_expression":
                candidate = _document_cookie_candidate(node, source)
                if candidate is not None:
                    raw.add(candidate)
            elif node.type in {"call_expression", "new_expression"}:
                candidate = _call_candidate(node, root, source, aliases, limits)
                if candidate is not None:
                    raw.add(candidate)
            if len(raw) > limits.max_signals:
                raise EcmaScriptCwe614ScanError(EcmaScriptCwe614ScanErrorCode.SIGNAL_LIMIT)
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
    except EcmaScriptCwe614ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe614ScanError(EcmaScriptCwe614ScanErrorCode.INTEGRITY_FAILURE) from None

    signals = tuple(
        EcmaScriptCwe614Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
            cookie_name=cookie_name,
        )
        for source_range, sink_range, operation, cookie_name in ordered
    )
    return EcmaScriptCwe614ScanResult(
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


def _bounded_nodes(root: Node, limits: EcmaScriptCwe614ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe614ScanError(EcmaScriptCwe614ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe614ScanError(EcmaScriptCwe614ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _call_candidate(
    node: Node,
    root: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe614ScanLimits,
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe614Operation, str] | None:
    function = node.child_by_field_name("function")
    if function is None:
        return None
    canonical = _canonical_expression(function, source, aliases) or ""
    arguments = node.child_by_field_name("arguments")
    values = arguments.named_children if arguments is not None else ()
    sink = _range(node)

    cookie_operation = _cookie_operation(canonical)
    if cookie_operation is not None:
        if not values:
            return None
        name = _string_value(values[0], source)
        if name is None or not _is_sensitive_name(name):
            return None
        options = values[2] if len(values) >= 3 else None
        state = _secure_state(
            options,
            node=node,
            root=root,
            source=source,
            limits=limits,
            depth=0,
            seen=frozenset(),
        )
        if state in {_FlagState.SAFE, _FlagState.UNKNOWN}:
            return None
        return _candidate_tuple(values[0], sink, cookie_operation, name)

    header_operation = _header_operation(canonical)
    if header_operation is not None:
        if len(values) < 2:
            return None
        header_name = _string_value(values[0], source)
        cookie_value = _string_value(values[1], source)
        if header_name is None or cookie_value is None:
            return None
        return _header_candidate(values[1], sink, header_operation, cookie_value, header_name)

    if _is_write_head(canonical):
        header_object = next(
            (value for value in values[1:] if _unwrap(value).type == "object"),
            None,
        )
        if header_object is None:
            return None
        for key, value in _object_properties(header_object, source):
            if key.lower() != "set-cookie":
                continue
            cookie_value = _string_value(value, source)
            if cookie_value is None:
                continue
            candidate = _header_candidate(
                value,
                sink,
                EcmaScriptCwe614Operation.RESPONSE_WRITE_HEAD,
                cookie_value,
                key,
            )
            if candidate is not None:
                return candidate
    return None


def _document_cookie_candidate(
    node: Node, source: bytes
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe614Operation, str] | None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None or _compact_text(source, left).lower() != "document.cookie":
        return None
    value = _string_value(right, source)
    if value is None:
        return None
    cookie_name = _cookie_name_from_header(value)
    if cookie_name is None or not _is_sensitive_name(cookie_name):
        return None
    if _has_secure_attribute(value):
        return None
    return _candidate_tuple(
        right, _range(node), EcmaScriptCwe614Operation.DOCUMENT_COOKIE, cookie_name
    )


class _FlagState(StrEnum):
    MISSING = "missing"
    UNSAFE = "unsafe"
    SAFE = "safe"
    UNKNOWN = "unknown"


def _secure_state(
    options: Node | None,
    *,
    node: Node,
    root: Node,
    source: bytes,
    limits: EcmaScriptCwe614ScanLimits,
    depth: int,
    seen: frozenset[str],
) -> _FlagState:
    if options is None:
        return _FlagState.MISSING
    if depth > limits.max_depth:
        raise EcmaScriptCwe614ScanError(EcmaScriptCwe614ScanErrorCode.DEPTH_LIMIT)
    current = _unwrap(options)
    if current.type == "identifier":
        name = _text(source, current)
        if name in seen:
            return _FlagState.UNKNOWN
        scope = _enclosing_scope(node, root)
        bound = _latest_binding(scope, name, current.start_byte, source)
        if bound is None:
            return _FlagState.UNKNOWN
        return _secure_state(
            bound,
            node=node,
            root=root,
            source=source,
            limits=limits,
            depth=depth + 1,
            seen=seen | {name},
        )
    if current.type != "object":
        return _FlagState.UNKNOWN
    secure_values = [
        value for key, value in _object_properties(current, source) if key.lower() == "secure"
    ]
    if not secure_values:
        return _FlagState.MISSING
    return _boolean_state(
        secure_values[-1],
        context_node=node,
        root=root,
        source=source,
        limits=limits,
        depth=depth + 1,
        seen=seen,
    )


def _boolean_state(
    value_node: Node,
    *,
    context_node: Node,
    root: Node,
    source: bytes,
    limits: EcmaScriptCwe614ScanLimits,
    depth: int,
    seen: frozenset[str],
) -> _FlagState:
    current = _unwrap(value_node)
    if current.type == "true":
        return _FlagState.SAFE
    if current.type == "false":
        return _FlagState.UNSAFE
    if current.type == "identifier":
        name = _text(source, current)
        if name in seen:
            return _FlagState.UNKNOWN
        scope = _enclosing_scope(context_node, root)
        bound = _latest_binding(scope, name, current.start_byte, source)
        if bound is None:
            return _FlagState.UNKNOWN
        return _boolean_state(
            bound,
            context_node=context_node,
            root=root,
            source=source,
            limits=limits,
            depth=depth + 1,
            seen=seen | {name},
        )
    return _FlagState.UNKNOWN


def _cookie_operation(canonical: str) -> EcmaScriptCwe614Operation | None:
    if canonical in {"cookie.serialize", "cookie.serializeCookie"}:
        return EcmaScriptCwe614Operation.COOKIE_SERIALIZE
    if canonical == "cookies.set":
        return EcmaScriptCwe614Operation.COOKIES_SET
    parts = canonical.replace("?.", ".").split(".")
    if not parts:
        return None
    method = parts[-1]
    if method == "set" and len(parts) >= 2 and parts[-2] == "cookies":
        return EcmaScriptCwe614Operation.KOA_CONTEXT_COOKIES_SET
    if method not in _COOKIE_SETTERS or len(parts) < 2:
        return None
    if parts[0] not in _RESPONSE_ROOTS:
        return None
    if method == "setCookie":
        return EcmaScriptCwe614Operation.FASTIFY_REPLY_SET_COOKIE
    return EcmaScriptCwe614Operation.EXPRESS_RESPONSE_COOKIE


def _header_operation(canonical: str) -> EcmaScriptCwe614Operation | None:
    parts = canonical.replace("?.", ".").split(".")
    if len(parts) < 2 or parts[0] not in _RESPONSE_ROOTS:
        return None
    method = parts[-1]
    return {
        "setHeader": EcmaScriptCwe614Operation.RESPONSE_SET_HEADER,
        "header": EcmaScriptCwe614Operation.RESPONSE_HEADER,
        "append": EcmaScriptCwe614Operation.RESPONSE_APPEND,
        "set": EcmaScriptCwe614Operation.RESPONSE_SET,
    }.get(method)


def _is_write_head(canonical: str) -> bool:
    parts = canonical.replace("?.", ".").split(".")
    return len(parts) >= 2 and parts[0] in _RESPONSE_ROOTS and parts[-1] == "writeHead"


def _header_candidate(
    value_node: Node,
    sink: SourceRange,
    operation: EcmaScriptCwe614Operation,
    value: str,
    header_name: str,
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe614Operation, str] | None:
    if header_name.lower() != "set-cookie":
        return None
    cookie_name = _cookie_name_from_header(value)
    if cookie_name is None or not _is_sensitive_name(cookie_name):
        return None
    if _has_secure_attribute(value):
        return None
    return _candidate_tuple(value_node, sink, operation, cookie_name)


def _cookie_name_from_header(value: str) -> str | None:
    first = value.split(";", 1)[0].strip()
    if "=" not in first:
        return None
    name, _separator, _cookie_value = first.partition("=")
    name = name.strip()
    if not name or len(name) > 256 or any(character in name for character in " ;,\t\r\n"):
        return None
    return name


def _has_secure_attribute(value: str) -> bool:
    return any(part.strip().lower() == "secure" for part in value.split(";"))


def _candidate_tuple(
    source_node: Node,
    sink: SourceRange,
    operation: EcmaScriptCwe614Operation,
    cookie_name: str,
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe614Operation, str]:
    source_range = _range(source_node)
    if not sink.contains(source_range):
        raise EcmaScriptCwe614ScanError(EcmaScriptCwe614ScanErrorCode.INTEGRITY_FAILURE)
    return source_range, sink, operation, cookie_name


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
    if module not in _COOKIE_MODULES:
        return
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
        if child.type not in {
            "pair",
            "object_pattern_property",
            "shorthand_property_identifier_pattern",
        }:
            continue
        key = child.child_by_field_name("key") or child
        value = child.child_by_field_name("value") or key
        key_name = _static_property_name(key, source)
        local_name = _static_property_name(value, source)
        if key_name is not None and local_name is not None:
            aliases[local_name] = f"{module}.{key_name}"


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
        return module if module in _COOKIE_MODULES else None
    if current.type in {"member_expression", "subscript_expression"}:
        object_node = current.child_by_field_name("object")
        property_node = current.child_by_field_name("property") or current.child_by_field_name(
            "index"
        )
        if object_node is None or property_node is None:
            return None
        base = _canonical_expression(object_node, source, aliases)
        if base is None:
            base = _canonical_name(_compact_text(source, object_node), aliases)
        property_name = _static_property_name(property_node, source)
        return None if base is None or property_name is None else f"{base}.{property_name}"
    return _canonical_name(_compact_text(source, current), aliases)


def _canonical_name(value: str, aliases: dict[str, str]) -> str | None:
    parts = value.split(".")
    if not parts or _IDENTIFIER.fullmatch(parts[0]) is None:
        return None
    base = aliases.get(parts[0], parts[0])
    return base if len(parts) == 1 else ".".join((base, *parts[1:]))


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


def _compact_text(source: bytes, node: Node) -> str:
    return "".join(_text(source, node).split())


def _is_sensitive_name(value: str) -> bool:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value).lower()
    normalized = re.sub(r"[^a-z0-9]+", "_", normalized).strip("_")
    if normalized in _SENSITIVE_NAMES:
        return True
    return _SENSITIVE_NAME_RE.search(normalized) is not None


def _object_properties(node: Node, source: bytes) -> tuple[tuple[str, Node], ...]:
    current = _unwrap(node)
    if current.type != "object":
        return ()
    result: list[tuple[str, Node]] = []
    for child in current.named_children:
        if child.type not in {"pair", "shorthand_property_identifier", "method_definition"}:
            continue
        key = child.child_by_field_name("key")
        value = child.child_by_field_name("value")
        if key is None:
            key = child
        if value is None:
            value = key
        name = _static_property_name(key, source)
        if name is not None:
            result.append((name, value))
    return tuple(result)


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
    operation: EcmaScriptCwe614Operation,
    cookie_name: str,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cookie_name": cookie_name,
        "detector": _DETECTOR,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
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
    language: str,
    signals: tuple[EcmaScriptCwe614Signal, ...],
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
                "cookie_name": signal.cookie_name,
                "detector": signal.detector,
                "operation": signal.operation.value,
                "rule_id": signal.rule_id,
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


Cwe614ScanErrorCode = EcmaScriptCwe614ScanErrorCode
Cwe614ScanError = EcmaScriptCwe614ScanError
Cwe614ScanLimits = EcmaScriptCwe614ScanLimits
Cwe614ScanResult = EcmaScriptCwe614ScanResult
Cwe614Signal = EcmaScriptCwe614Signal

scan_javascript_cookie_security = scan_javascript_cwe614
scan_typescript_cookie_security = scan_typescript_cwe614
scan_ecmascript_cookie_security = scan_ecmascript_cwe614

__all__ = [
    "DEFAULT_ECMASCRIPT_CWE614_SCAN_LIMITS",
    "Cwe614ScanError",
    "Cwe614ScanErrorCode",
    "Cwe614ScanLimits",
    "Cwe614ScanResult",
    "Cwe614Signal",
    "EcmaScriptCwe614Operation",
    "EcmaScriptCwe614ScanError",
    "EcmaScriptCwe614ScanErrorCode",
    "EcmaScriptCwe614ScanLimits",
    "EcmaScriptCwe614ScanResult",
    "EcmaScriptCwe614Signal",
    "scan_ecmascript_cookie_security",
    "scan_ecmascript_cwe614",
    "scan_javascript_cookie_security",
    "scan_javascript_cwe614",
    "scan_typescript_cookie_security",
    "scan_typescript_cwe614",
]
