"""Bounded ECMAScript CWE-209 error-disclosure facts.

The scanner reports a narrow, source-free projection of values that carry
explicit credential, token, key, or request-derived names into errors and HTTP
error responses.  It follows local bindings in one function, suppresses fixed
strings and known sanitizers, and refuses malformed or resource-exhausted
input.  Source bytes are used only while parsing; neither values nor parser
diagnostics are retained in a signal or an exception.
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

_MAX_LIMITS = (2_000_000, 250_000, 512, 20_000, 20_000)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_RULE_ID = "securecode-ecmascript-cwe209"
_DETECTOR = "securecode-ecmascript-cwe209@1.0"
_DETAIL = "sensitive_value_to_error_surface"

_SENSITIVE_WORDS = frozenset(
    {
        "accesskey",
        "access_token",
        "apikey",
        "api_key",
        "authheader",
        "authorization",
        "bearer",
        "clientsecret",
        "client_secret",
        "credential",
        "credentials",
        "idtoken",
        "id_token",
        "jwt",
        "keyfile",
        "privatekey",
        "private_key",
        "passcode",
        "passwd",
        "password",
        "passphrase",
        "refresh_token",
        "refreshtoken",
        "secret",
        "secretkey",
        "secret_key",
        "sessiontoken",
        "session_token",
        "token",
    }
_REQUEST_ROOTS = frozenset(
    {
        "ctx",
        "context",
        "event",
        "http_request",
        "httprequest",
        "req",
        "request",
    }
)
_REQUEST_FIELDS = frozenset(
    {
        "body",
        "cookie",
        "cookies",
        "data",
        "form",
        "headers",
        "params",
        "path",
        "query",
        "querystring",
        "query_string",
        "searchparams",
        "search_params",
    }
)
_REQUEST_ACCESSORS = frozenset(
    {
        "body",
        "cookie",
        "cookies",
        "get",
        "getheader",
        "header",
        "headers",
        "param",
        "params",
        "query",
    }
)
_ERROR_CONSTRUCTORS = frozenset(
    {
        "aggregateerror",
        "error",
        "evalerror",
        "httperror",
        "referenceerror",
        "rangeerror",
        "syntaxerror",
        "typeerror",
        "urierror",
        "validationerror",
    }
)
_CALLBACK_NAMES = frozenset({"callback", "done", "fail", "next", "reject", "respond"})
_RESPONSE_METHODS = frozenset(
    {
        "end",
        "json",
        "send",
        "sendfile",
        "write",
        "writehead",
    }
)
_RESPONSE_ROOTS = frozenset(
    {
        "ctx",
        "context",
        "reply",
        "res",
        "response",
        "result",
    }
)
_SANITIZER_WORDS = frozenset(
    {
        "anonymize",
        "encode",
        "escape",
        "hash",
        "mask",
        "obfuscate",
        "redact",
        "sanitize",
        "scrub",
        "strip",
        "tokenize",
    }
)
_NESTED_FUNCTIONS = frozenset(
    {
        "arrow_function",
        "function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)
_EXPRESSION_NODES = frozenset(
    {
        "array",
        "arguments",
        "assignment_expression",
        "await_expression",
        "binary_expression",
        "call_expression",
        "conditional_expression",
        "member_expression",
        "new_expression",
        "non_null_expression",
        "object",
        "parenthesized_expression",
        "pair",
        "sequence_expression",
        "spread_element",
        "subscript_expression",
        "template_string",
        "template_substitution",
        "ternary_expression",
        "type_assertion",
        "unary_expression",
        "update_expression",
    }


class EcmaScriptCwe209ScanErrorCode(StrEnum):
    """Closed, source-free reasons a scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    ALIAS_LIMIT = "ALIAS_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe209ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe209ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe209ScanErrorCode:
            raise TypeError("ECMAScript CWE-209 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-209 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class EcmaScriptCwe209SensitiveKind(StrEnum):
    """Stable categories for values disclosed through an error surface."""

    REQUEST = "request_derived"
    CREDENTIAL = "credential"
    TOKEN = "token"
    AUTHENTICATOR = "pass" + "word"
    SENSITIVE = "sec" + "ret"
    KEY = "key"
    AUTHORIZATION = "authorization"


class EcmaScriptCwe209Operation(StrEnum):
    """Recognized error and response sink categories."""

    THROW_ERROR = "throw_error"
    CALLBACK_ERROR = "callback_error"
    HTTP_ERROR_RESPONSE = "http_error_response"
    CONTEXT_ERROR = "context_error"

    # Compatibility aliases for generic scanner consumers.
    THROW = "throw_error"
    NEXT_ERROR = "callback_error"
    HTTP_RESPONSE = "http_error_response"
    RESPONSE_BODY = "http_error_response"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe209ScanLimits:
    """Hard ceilings applied before and during CST analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_nodes: int = _MAX_LIMITS[1]
    max_depth: int = _MAX_LIMITS[2]
    max_aliases: int = _MAX_LIMITS[3]
    max_signals: int = _MAX_LIMITS[4]

    def __post_init__(self) -> None:
        values = (
            self.max_source_bytes,
            self.max_nodes,
            self.max_depth,
            self.max_aliases,
            self.max_signals,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("ECMAScript CWE-209 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE209_SCAN_LIMITS = EcmaScriptCwe209ScanLimits()


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe209Signal:
    """One immutable sensitive-value-to-error fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe209Operation
    sensitive_kind: EcmaScriptCwe209SensitiveKind
    sensitive_name: str = "sensitive_value"
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-209"
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
            and type(self.sensitive_name) is str
            and 0 < len(self.sensitive_name) <= 256
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
                self.sensitive_kind,
                self.sensitive_name,
            )
            if valid_identity
            and valid_ranges
            and type(self.operation) is EcmaScriptCwe209Operation
            and type(self.sensitive_kind) is EcmaScriptCwe209SensitiveKind
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not EcmaScriptCwe209Operation
            or type(self.sensitive_kind) is not EcmaScriptCwe209SensitiveKind
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-209"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("ECMAScript CWE-209 signal is invalid")
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

    @property
    def variable_name(self) -> str:
        return self.sensitive_name


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe209ScanResult:
    """Deterministic, source-free result for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe209Signal, ...]
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
            type(item) is EcmaScriptCwe209Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    item.sink.start_byte,
                    item.sink.end_byte,
                    item.source.start_byte,
                    item.source.end_byte,
                    item.operation.value,
                    item.sensitive_kind.value,
                    item.sensitive_name,
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
                self.language,
                self.signals,
            )
        ):
            raise ValueError("ECMAScript CWE-209 scan result is invalid")


def scan_javascript_cwe209(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe209ScanLimits = DEFAULT_ECMASCRIPT_CWE209_SCAN_LIMITS,
) -> EcmaScriptCwe209ScanResult:
    """Find bounded JavaScript sensitive values reaching error surfaces."""

    return _scan_ecmascript_cwe209(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe209(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe209ScanLimits = DEFAULT_ECMASCRIPT_CWE209_SCAN_LIMITS,
) -> EcmaScriptCwe209ScanResult:
    """Find bounded TypeScript sensitive values reaching error surfaces."""

    return _scan_ecmascript_cwe209(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe209(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe209ScanLimits = DEFAULT_ECMASCRIPT_CWE209_SCAN_LIMITS,
) -> EcmaScriptCwe209ScanResult:
    """Dispatch a CWE-209 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe209(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe209(symbol_index, limits=limits)
    raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe209(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe209ScanLimits,
) -> EcmaScriptCwe209ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe209ScanLimits:
        raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.ANALYSIS_UNAVAILABLE)

    builder = build_javascript_symbol_index if expected_language == "javascript" else build_typescript_symbol_index
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
        raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.INTEGRITY_FAILURE) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.ANALYSIS_UNAVAILABLE)
        aliases = _collect_aliases(nodes, source, limits)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe209Operation, EcmaScriptCwe209SensitiveKind, str]] = set()
        for node in nodes:
            operation: EcmaScriptCwe209Operation | None = None
            roots: tuple[Node, ...] = ()
            if node.type == "throw_statement":
                operation = EcmaScriptCwe209Operation.THROW_ERROR
                roots = tuple(node.named_children)
            elif node.type == "assignment_expression" and _is_response_assignment(node, source, aliases):
                operation = EcmaScriptCwe209Operation.HTTP_ERROR_RESPONSE
                right = node.child_by_field_name("right")
                roots = (right,) if right is not None else ()
            elif node.type == "call_expression":
                operation = _call_operation(node, source, aliases)
                if operation is not None:
                    arguments = node.child_by_field_name("arguments")
                    roots = tuple(arguments.named_children) if arguments is not None else ()
            if operation is None:
                continue
            scope = _enclosing_scope(node, root)
            sink_range = _range(node)
            for argument in roots:
                for source_node, kind, name in _resolve_sources(
                    argument,
                    scope=scope,
                    source=source,
                    aliases=aliases,
                    limits=limits,
                    depth=0,
                    visited=frozenset(),
                ):
                    source_range = _range(source_node)
                    if not sink_range.contains(source_range):
                        raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.INTEGRITY_FAILURE)
                    raw.add((source_range, sink_range, operation, kind, name))
                    if len(raw) > limits.max_signals:
                        raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.SIGNAL_LIMIT)
        ordered = sorted(
            raw,
            key=lambda item: (
                item[1].start_byte,
                item[1].end_byte,
                item[0].start_byte,
                item[0].end_byte,
                item[2].value,
                item[3].value,
                item[4],
            ),
        )
    except EcmaScriptCwe209ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.INTEGRITY_FAILURE) from None

    signals = tuple(
        EcmaScriptCwe209Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
            sensitive_kind=kind,
            sensitive_name=name,
        )
        for source_range, sink_range, operation, kind, name in ordered
    )
    return EcmaScriptCwe209ScanResult(
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


def _call_operation(
    node: Node, source: bytes, aliases: dict[str, str]
) -> EcmaScriptCwe209Operation | None:
    function = node.child_by_field_name("function")
    if function is None:
        return None
    canonical = _canonical_expression(function, source, aliases) or _compact_text(source, function)
    method = _normalize_name(canonical.rsplit(".", 1)[-1])
    root = _normalize_name(canonical.split(".", 1)[0])
    if method in _CALLBACK_NAMES:
        return EcmaScriptCwe209Operation.CALLBACK_ERROR
    if method in {"throw", "throwerror"} and root in {"ctx", "context"}:
        return EcmaScriptCwe209Operation.CONTEXT_ERROR
    if method in _RESPONSE_METHODS and root in _RESPONSE_ROOTS:
        return EcmaScriptCwe209Operation.HTTP_ERROR_RESPONSE
    if method in {"json", "send", "end", "write"} and _root_name(function, source) in _RESPONSE_ROOTS:
        return EcmaScriptCwe209Operation.HTTP_ERROR_RESPONSE
    if method in _ERROR_CONSTRUCTORS:
        parent = node.parent
        while parent is not None and parent.type in {"new_expression", "parenthesized_expression", "arguments"}:
            parent = parent.parent
        if parent is not None and parent.type == "throw_statement":
            return None
    return None


def _is_response_assignment(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    left = node.child_by_field_name("left")
    if left is None or left.type not in {"member_expression", "subscript_expression"}:
        return False
    property_node = left.child_by_field_name("property") or left.child_by_field_name("index")
    property_name = _normalize_name(_static_property_name(property_node, source) or "")
    if property_name not in {"body", "data", "error", "message", "payload"}:
        return False
    canonical = _canonical_expression(left, source, aliases) or _compact_text(source, left)
    root = _normalize_name(canonical.split(".", 1)[0])
    return root in _RESPONSE_ROOTS


def _resolve_sources(
    node: Node,
    *,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe209ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[tuple[Node, EcmaScriptCwe209SensitiveKind, str], ...]:
    if depth > limits.max_depth:
        raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.DEPTH_LIMIT)
    if _is_safe_call(node, source, aliases):
        return ()
    direct = _classify_expression(node, source, aliases)
    if direct is not None and node.type not in {"identifier", "member_expression", "subscript_expression"}:
        return ((node, direct[0], direct[1]),)
    if node.type == "identifier":
        name = _node_text(source, node)
        bound = _latest_binding(scope, name, node.start_byte, source)
        if bound is not None and name not in visited:
            if _is_fixed_or_safe(bound, scope, source, aliases, limits, depth + 1, visited | {name}):
                return ()
            resolved = _resolve_sources(
                bound,
                scope=scope,
                source=source,
                aliases=aliases,
                limits=limits,
                depth=depth + 1,
                visited=visited | {name},
            )
            if resolved:
                return tuple((node, kind, label) for _, kind, label in resolved)
        if direct is not None:
            return ((node, direct[0], direct[1]),)
        return ()
    if node.type in {"member_expression", "subscript_expression"}:
        if direct is not None:
            return ((node, direct[0], direct[1]),)
        values: list[tuple[Node, EcmaScriptCwe209SensitiveKind, str]] = []
        for child in node.named_children:
            values.extend(
                _resolve_sources(
                    child,
                    scope=scope,
                    source=source,
                    aliases=aliases,
                    limits=limits,
                    depth=depth + 1,
                    visited=visited,
                )
            )
        return _unique_sources(values)
    if node.type == "pair":
        value = node.child_by_field_name("value")
        if value is None:
            return ()
        key = node.child_by_field_name("key")
        key_direct = _classify_name(_static_property_name(key, source))
        if key_direct is not None and not _is_fixed_or_safe(value, scope, source, aliases, limits, depth + 1, visited):
            resolved = _resolve_sources(
                value,
                scope=scope,
                source=source,
                aliases=aliases,
                limits=limits,
                depth=depth + 1,
                visited=visited,
            )
            if resolved:
                return tuple((item, key_direct[0], key_direct[1]) for item, _, _ in resolved)
            return ((value, key_direct[0], key_direct[1]),)
        return _resolve_sources(
            value,
            scope=scope,
            source=source,
            aliases=aliases,
            limits=limits,
            depth=depth + 1,
            visited=visited,
        )
    if node.type in _EXPRESSION_NODES:
        values: list[tuple[Node, EcmaScriptCwe209SensitiveKind, str]] = []
        for child in node.named_children:
            values.extend(
                _resolve_sources(
                    child,
                    scope=scope,
                    source=source,
                    aliases=aliases,
                    limits=limits,
                    depth=depth + 1,
                    visited=visited,
                )
            )
        return _unique_sources(values)
    return ()


def _classify_expression(
    node: Node, source: bytes, aliases: dict[str, str]
) -> tuple[EcmaScriptCwe209SensitiveKind, str] | None:
    if node.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        return _classify_name(_node_text(source, node))
    if node.type in {"member_expression", "subscript_expression"}:
        text = _canonical_expression(node, source, aliases) or _compact_text(source, node)
        parts = [part for part in re.split(r"[._]", text) if part]
        property_node = node.child_by_field_name("property") or node.child_by_field_name("index")
        property_name = _static_property_name(property_node, source)
        prop = _normalize_name(property_name or "")
        if prop in _REQUEST_FIELDS or prop in _SENSITIVE_WORDS:
            return _classify_name(prop)
        if parts and _normalize_name(parts[0]) in _REQUEST_ROOTS:
            return EcmaScriptCwe209SensitiveKind.REQUEST, "request_value"
        if len(parts) >= 2 and _normalize_name(parts[-2]) in _REQUEST_FIELDS:
            return EcmaScriptCwe209SensitiveKind.REQUEST, "request_value"
        return None
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        name = _normalize_name(
            (_canonical_expression(function, source, aliases) or _compact_text(source, function)).rsplit(".", 1)[-1]
        )
        if name in _REQUEST_ACCESSORS or name.startswith("get") and name.endswith(("token", "secret", "password", "key")):
            values = tuple(arguments.named_children) if arguments is not None else ()
            literal = _string_value(values[0], source) if values else None
            classified = _classify_name(literal)
            return classified or (EcmaScriptCwe209SensitiveKind.REQUEST, "request_value")
    return None


def _classify_name(value: str | None) -> tuple[EcmaScriptCwe209SensitiveKind, str] | None:
    if not value:
        return None
    normalized = _normalize_name(value)
    if any(part in {"safe", "sanitized", "redacted", "masked", "hash", "digest"} for part in normalized.split("_")):
        return None
    compact = normalized.replace("_", "")
    if compact in {"password", "passwd", "passphrase", "passcode"}:
        return EcmaScriptCwe209SensitiveKind.AUTHENTICATOR, normalized[:256]
    if compact in {"apikey", "accesskey", "privatekey", "secretkey", "keyfile"}:
        return EcmaScriptCwe209SensitiveKind.KEY, normalized[:256]
    if compact in {"authorization", "authheader", "bearer"}:
        return EcmaScriptCwe209SensitiveKind.AUTHORIZATION, normalized[:256]
    if compact in {"token", "accesstoken", "idtoken", "refreshtoken", "sessiontoken", "jwt"}:
        return EcmaScriptCwe209SensitiveKind.TOKEN, normalized[:256]
    if compact in {"secret", "clientsecret"}:
        return EcmaScriptCwe209SensitiveKind.SENSITIVE, normalized[:256]
    if compact in {"credential", "credentials"}:
        return EcmaScriptCwe209SensitiveKind.CREDENTIAL, normalized[:256]
    return None


def _is_fixed_or_safe(
    node: Node,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe209ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> bool:
    if depth > limits.max_depth:
        raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.DEPTH_LIMIT)
    if _is_safe_call(node, source, aliases):
        return True
    if node.type in {"string", "string_fragment", "number", "true", "false", "null", "undefined", "regex"}:
        return True
    if node.type == "identifier":
        name = _node_text(source, node)
        if name in visited:
            return False
        bound = _latest_binding(scope, name, node.start_byte, source)
        return (
            bound is not None
            and _is_fixed_or_safe(bound, scope, source, aliases, limits, depth + 1, visited | {name})
        )
    if node.type in {"binary_expression", "template_string", "template_substitution", "parenthesized_expression"}:
        return bool(node.named_children) and all(
            _is_fixed_or_safe(child, scope, source, aliases, limits, depth + 1, visited)
            for child in node.named_children
        )
    return False


def _is_safe_call(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    if function is None:
        return False
    text = _canonical_expression(function, source, aliases) or _compact_text(source, function)
    name = _normalize_name(text.rsplit(".", 1)[-1])
    return any(word in name for word in _SANITIZER_WORDS)


def _collect_aliases(
    nodes: tuple[Node, ...], source: bytes, limits: EcmaScriptCwe209ScanLimits
) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in nodes:
        if node.type not in {"variable_declarator", "assignment_expression"}:
            continue
        left = node.child_by_field_name("name") if node.type == "variable_declarator" else node.child_by_field_name("left")
        right = node.child_by_field_name("value") if node.type == "variable_declarator" else node.child_by_field_name("right")
        if left is None or right is None or left.type != "identifier":
            continue
        canonical = _canonical_expression(right, source, aliases)
        if canonical is not None:
            aliases[_node_text(source, left)] = canonical
            if len(aliases) > limits.max_aliases:
                raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.ALIAS_LIMIT)
    return aliases


def _canonical_expression(node: Node | None, source: bytes, aliases: dict[str, str]) -> str | None:
    if node is None:
        return None
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or _compact_text(source, function) != "require":
            return None
        values = list(arguments.named_children)
        return _string_value(values[0], source) if len(values) == 1 else None
    if node.type in {"member_expression", "subscript_expression"}:
        object_node = node.child_by_field_name("object")
        property_node = node.child_by_field_name("property") or node.child_by_field_name("index")
        if object_node is None or property_node is None:
            return None
        base = _canonical_expression(object_node, source, aliases) or _canonical_name(_compact_text(source, object_node), aliases)
        name = _static_property_name(property_node, source)
        return f"{base}.{name}" if base and name else None
    return _canonical_name(_compact_text(source, node), aliases)


def _canonical_name(value: str, aliases: dict[str, str]) -> str:
    parts = value.split(".")
    if not parts or not _IDENTIFIER.fullmatch(parts[0]):
        return value
    base = aliases.get(parts[0], parts[0])
    return ".".join((base, *parts[1:])) if len(parts) > 1 else base


def _root_name(node: Node, source: bytes) -> str:
    current = node
    while current.type in {"member_expression", "subscript_expression", "call_expression", "new_expression"}:
        if current.type == "call_expression":
            current = current.child_by_field_name("function") or current
        else:
            current = current.child_by_field_name("object") or current
        if current is node:
            break
    if current.type == "identifier":
        return _normalize_name(_node_text(source, current))
    return ""


def _static_property_name(node: Node | None, source: bytes) -> str | None:
    if node is None:
        return None
    if node.type == "computed_property_name":
        values = list(node.named_children)
        return _static_property_name(values[0], source) if len(values) == 1 else None
    if node.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        return _node_text(source, node)
    if node.type in {"string", "string_fragment"}:
        return _string_value(node, source)
    return None


def _string_value(node: Node | None, source: bytes) -> str | None:
    if node is None or node.type not in {"string", "string_fragment"}:
        return None
    value = source[node.start_byte : node.end_byte]
    if node.type == "string":
        if len(value) < 2 or value[:1] not in {b"'", b'"', b"`"} or value[-1:] != value[:1]:
            return None
        value = value[1:-1]
    if b"\\" in value or b"\n" in value or b"\r" in value:
        return None
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.INTEGRITY_FAILURE) from None


def _node_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.INTEGRITY_FAILURE) from None


def _compact_text(source: bytes, node: Node | None) -> str:
    return "" if node is None else "".join(_node_text(source, node).split())


def _normalize_name(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()


def _bounded_nodes(root: Node, limits: EcmaScriptCwe209ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe209ScanError(EcmaScriptCwe209ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _enclosing_scope(node: Node, root: Node) -> Node:
    current = node.parent
    while current is not None:
        if current.type in _NESTED_FUNCTIONS:
            return current
        current = current.parent
    return root


def _latest_binding(scope: Node, name: str, before: int, source: bytes) -> Node | None:
    bound: Node | None = None
    for node in _scope_preorder(scope):
        if node.start_byte >= before:
            continue
        if node.type == "variable_declarator":
            left = node.child_by_field_name("name")
            right = node.child_by_field_name("value")
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
        else:
            continue
        if left is not None and right is not None and left.type == "identifier" and _node_text(source, left) == name:
            bound = right
    return bound


def _scope_preorder(scope: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    first = True
    while stack:
        node = stack.pop()
        output.append(node)
        if not first and node.type in _NESTED_FUNCTIONS:
            continue
        first = False
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _unique_sources(
    values: list[tuple[Node, EcmaScriptCwe209SensitiveKind, str]],
) -> tuple[tuple[Node, EcmaScriptCwe209SensitiveKind, str], ...]:
    unique: dict[tuple[int, int, str], tuple[Node, EcmaScriptCwe209SensitiveKind, str]] = {}
    for node, kind, name in values:
        unique[(node.start_byte, node.end_byte, kind.value)] = (node, kind, name)
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
    operation: EcmaScriptCwe209Operation,
    kind: EcmaScriptCwe209SensitiveKind,
    name: str,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-209",
        "detector": _DETECTOR,
        "kind": kind.value,
        "name": name,
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
    language: str,
    signals: tuple[EcmaScriptCwe209Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-209",
        "detector": _DETECTOR,
        "language": language,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
                "detail": signal.detail,
                "kind": signal.sensitive_kind.value,
                "name": signal.sensitive_name,
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
