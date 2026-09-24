"""Bounded JavaScript and TypeScript CWE-307 authentication rate-limit facts.

The scanner accepts a sealed ECMAScript ``SymbolIndex`` and reparses the
admitted bytes before looking for a narrowly defined login handler.  It
recognises Express and Koa routes, plus Nest controller methods, when a
password verification call is reachable in the handler and no rate-limiting
middleware or decorator protects that route.  Ambiguous handlers are ignored.

The result contains immutable ranges and content-addressed identity only.
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
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_RULE_ID = "securecode-ecmascript-cwe307"
_DETECTOR = "securecode-ecmascript-cwe307@1.0"

_LOGIN_WORDS = re.compile(
    r"(?:^|[/_.-])(?:log[._-]?in|sign[._-]?in|authenticate|auth|session|token|password)"
    r"(?:$|[/_.-])",
    re.IGNORECASE,
)
_LOGIN_NAME = re.compile(
    r"(?:login|log_in|signin|sign_in|authenticate|auth|session|token|password)",
    re.IGNORECASE,
)
_PASSWORD_NAME = re.compile(
    r"(?:password|passwd|passcode|credential|credentials)",
    re.IGNORECASE,
)
_LIMITER_NAME = re.compile(
    r"(?:rate.?limit|rate.?limiter|throttl|slow.?down|login.?limit|auth.?limit|\blimiter\b)",
    re.IGNORECASE,
)

_FRAMEWORK_MODULES = frozenset({"express", "koa", "@koa/router", "koa-router"})
_NEST_MODULES = frozenset({"@nestjs/common", "@nestjs/core", "@nestjs/throttler"})
_LIMITER_MODULES = frozenset(
    {
        "express-rate-limit",
        "express-slow-down",
        "rate-limiter-flexible",
        "koa-ratelimit",
        "koa2-ratelimit",
        "koa-simple-ratelimit",
        "@nestjs/throttler",
        "@fastify/rate-limit",
    }
)
_ROUTE_METHODS = frozenset({"all", "delete", "get", "head", "options", "patch", "post", "put", "use"})
_VERIFY_METHODS = frozenset(
    {
        "authenticate",
        "checkPassword",
        "compare",
        "comparePassword",
        "compareSync",
        "checkCredentials",
        "checkCredential",
        "isValidPassword",
        "validateCredentials",
        "validatePassword",
        "validateUser",
        "verify",
        "verifyPassword",
        "verifySync",
    }
)
_FUNCTION_TYPES = frozenset(
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
_WRAPPER_TYPES = frozenset(
    {"as_expression", "parenthesized_expression", "non_null_expression", "type_assertion"}
)


class EcmaScriptCwe307ScanErrorCode(StrEnum):
    """Closed reasons a rate-limit analysis cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe307ScanError(RuntimeError):
    """Fixed scanner failure that never exposes parser or source details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe307ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe307ScanErrorCode:
            raise TypeError("ECMAScript CWE-307 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-307 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe307ScanLimits:
    """Hard ceilings applied before and during CST and local-flow analysis."""

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
            raise ValueError("ECMAScript CWE-307 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE307_SCAN_LIMITS = EcmaScriptCwe307ScanLimits()


class EcmaScriptCwe307Operation(StrEnum):
    """Authentication boundary detected without a rate-limit guard."""

    CREDENTIAL_VERIFICATION_WITHOUT_RATE_LIMIT = "credential_verification_without_rate_limit"
    AUTHENTICATION_HANDLER_WITHOUT_RATE_LIMIT = "credential_verification_without_rate_limit"
    LOGIN_WITHOUT_RATE_LIMIT = "credential_verification_without_rate_limit"
    AUTHENTICATION_WITHOUT_RATE_LIMIT = "credential_verification_without_rate_limit"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe307Signal:
    """One immutable source-to-authentication-boundary fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe307Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-307"
    detector: str = _DETECTOR
    detail: str = "authentication_handler_without_rate_limit"

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
            )
            if identity_valid
            and ranges_valid
            and type(self.operation) is EcmaScriptCwe307Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not EcmaScriptCwe307Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-307"
            or self.detector != _DETECTOR
            or self.detail != "authentication_handler_without_rate_limit"
        ):
            raise ValueError("ECMAScript CWE-307 signal is invalid")
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
class EcmaScriptCwe307ScanResult:
    """Deterministic and source-free CWE-307 output for one source file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe307Signal, ...]
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
            and self.language in {"javascript", "typescript"}
        )
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity_valid = False
        valid_signals = type(self.signals) is tuple and all(
            type(item) is EcmaScriptCwe307Signal for item in self.signals
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
            not identity_valid
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
            raise ValueError("ECMAScript CWE-307 scan result is invalid")


def scan_javascript_cwe307(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe307ScanLimits = DEFAULT_ECMASCRIPT_CWE307_SCAN_LIMITS,
) -> EcmaScriptCwe307ScanResult:
    """Find bounded JavaScript authentication handlers without rate limits."""

    return _scan_ecmascript_cwe307(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe307(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe307ScanLimits = DEFAULT_ECMASCRIPT_CWE307_SCAN_LIMITS,
) -> EcmaScriptCwe307ScanResult:
    """Find bounded TypeScript authentication handlers without rate limits."""

    return _scan_ecmascript_cwe307(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe307(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe307ScanLimits = DEFAULT_ECMASCRIPT_CWE307_SCAN_LIMITS,
) -> EcmaScriptCwe307ScanResult:
    """Dispatch a CWE-307 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe307ScanError(EcmaScriptCwe307ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe307(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe307(symbol_index, limits=limits)
    raise EcmaScriptCwe307ScanError(EcmaScriptCwe307ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe307(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe307ScanLimits,
) -> EcmaScriptCwe307ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe307ScanLimits:
        raise EcmaScriptCwe307ScanError(EcmaScriptCwe307ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe307ScanError(EcmaScriptCwe307ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe307ScanError(EcmaScriptCwe307ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe307ScanError(EcmaScriptCwe307ScanErrorCode.ANALYSIS_UNAVAILABLE)
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
        raise EcmaScriptCwe307ScanError(EcmaScriptCwe307ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe307ScanError(EcmaScriptCwe307ScanErrorCode.INTEGRITY_FAILURE) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe307ScanError(EcmaScriptCwe307ScanErrorCode.ANALYSIS_UNAVAILABLE)
        aliases = _collect_aliases(nodes, source)
        bindings = _collect_function_bindings(nodes, source)
        globally_limited, path_limited = _collect_route_limiters(nodes, source, aliases)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe307Operation]] = set()

        for node in nodes:
            if node.type != "call_expression":
                continue
            candidate = _route_candidate(node, source, aliases, bindings)
            if candidate is None:
                continue
            handler, path, receiver, arguments = candidate
            if _route_is_limited(
                node,
                path,
                receiver,
                arguments,
                source,
                aliases,
                globally_limited,
                path_limited,
            ):
                continue
            verification = _find_password_verification(handler, source, aliases)
            if verification is None:
                continue
            source_range = _range(verification)
            sink_range = _range(handler)
            if not sink_range.contains(source_range):
                raise EcmaScriptCwe307ScanError(EcmaScriptCwe307ScanErrorCode.INTEGRITY_FAILURE)
            raw.add(
                (
                    source_range,
                    sink_range,
                    EcmaScriptCwe307Operation.CREDENTIAL_VERIFICATION_WITHOUT_RATE_LIMIT,
                )
            )

        for method in nodes:
            if method.type != "method_definition":
                continue
            candidate = _nest_candidate(method, source, aliases)
            if candidate is None:
                continue
            handler, limited = candidate
            if limited:
                continue
            verification = _find_password_verification(handler, source, aliases)
            if verification is None:
                continue
            source_range = _range(verification)
            sink_range = _range(handler)
            if not sink_range.contains(source_range):
                raise EcmaScriptCwe307ScanError(EcmaScriptCwe307ScanErrorCode.INTEGRITY_FAILURE)
            raw.add(
                (
                    source_range,
                    sink_range,
                    EcmaScriptCwe307Operation.CREDENTIAL_VERIFICATION_WITHOUT_RATE_LIMIT,
                )
            )
            if len(raw) > limits.max_signals:
                raise EcmaScriptCwe307ScanError(EcmaScriptCwe307ScanErrorCode.SIGNAL_LIMIT)
        ordered = tuple(
            sorted(
                raw,
                key=lambda item: (
                    item[1].start_byte,
                    item[1].end_byte,
                    item[0].start_byte,
                    item[0].end_byte,
                    item[2].value,
                ),
            )
        )
    except EcmaScriptCwe307ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe307ScanError(EcmaScriptCwe307ScanErrorCode.INTEGRITY_FAILURE) from None

    signals = tuple(
        EcmaScriptCwe307Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
        )
        for source_range, sink_range, operation in ordered
    )
    return EcmaScriptCwe307ScanResult(
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
class _RouteCandidate:
    handler: Node
    path: str
    receiver: str
    arguments: tuple[Node, ...]


def _bounded_nodes(root: Node, limits: EcmaScriptCwe307ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe307ScanError(EcmaScriptCwe307ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe307ScanError(EcmaScriptCwe307ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _route_candidate(
    node: Node,
    source: bytes,
    aliases: dict[str, str],
    bindings: dict[str, Node],
) -> _RouteCandidate | None:
    function = node.child_by_field_name("function")
    arguments_node = node.child_by_field_name("arguments")
    if function is None or arguments_node is None:
        return None
    canonical = _canonical_expression(function, source, aliases)
    if canonical is None:
        return None
    method = canonical.rsplit(".", 1)[-1].lower()
    if method not in _ROUTE_METHODS or not _is_framework_route(canonical):
        return None
    arguments = tuple(arguments_node.named_children)
    if not arguments:
        return None
    path = _string_value(arguments[0], source)
    if path is None or not _LOGIN_WORDS.search(path):
        return None
    for argument in arguments[1:]:
        current = _unwrap(argument)
        if _is_function_node(current):
            return _RouteCandidate(current, path, canonical.rsplit(".", 1)[0], arguments)
        if current.type == "identifier":
            name = _node_text(source, current)
            handler = bindings.get(name)
            if handler is not None:
                return _RouteCandidate(handler, path, canonical.rsplit(".", 1)[0], arguments)
    return None


def _is_framework_route(canonical: str) -> bool:
    receiver = canonical.rsplit(".", 1)[0] if "." in canonical else ""
    root = receiver.split(".", 1)[0]
    return (
        root in {"express", "koa"}
        or receiver in _FRAMEWORK_MODULES
        or receiver.startswith("@koa/router")
        or receiver.startswith("koa-router")
    )


def _collect_function_bindings(nodes: tuple[Node, ...], source: bytes) -> dict[str, Node]:
    bindings: dict[str, Node] = {}
    for node in nodes:
        if node.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in node.named_children:
                if declarator.type != "variable_declarator":
                    continue
                name = declarator.child_by_field_name("name")
                value = declarator.child_by_field_name("value")
                if name is not None and value is not None and name.type == "identifier":
                    value = _unwrap(value)
                    if _is_function_node(value):
                        bindings[_node_text(source, name)] = value
        elif node.type == "function_declaration":
            name = node.child_by_field_name("name")
            if name is not None:
                bindings[_node_text(source, name)] = node
    return bindings


def _collect_route_limiters(
    nodes: tuple[Node, ...], source: bytes, aliases: dict[str, str]
) -> tuple[frozenset[str], frozenset[tuple[str, str]]]:
    global_limiters: set[str] = set()
    path_limiters: set[tuple[str, str]] = set()
    for node in nodes:
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        arguments_node = node.child_by_field_name("arguments")
        if function is None or arguments_node is None:
            continue
        canonical = _canonical_expression(function, source, aliases)
        if canonical is None:
            continue
        method = canonical.rsplit(".", 1)[-1].lower()
        if method != "use" or not _is_framework_route(canonical):
            continue
        arguments = tuple(arguments_node.named_children)
        if not arguments:
            continue
        path = _string_value(arguments[0], source)
        middleware = arguments[1:] if path is not None else arguments
        if not any(_is_limiter_expression(item, source, aliases) for item in middleware):
            continue
        receiver = canonical.rsplit(".", 1)[0]
        if path is None:
            global_limiters.add(receiver)
        elif _LOGIN_WORDS.search(path):
            path_limiters.add((receiver, _normalise_path(path)))
    return frozenset(global_limiters), frozenset(path_limiters)


def _route_is_limited(
    route: Node,
    path: str,
    receiver: str,
    arguments: tuple[Node, ...],
    source: bytes,
    aliases: dict[str, str],
    global_limiters: frozenset[str],
    path_limiters: frozenset[tuple[str, str]],
) -> bool:
    if receiver in global_limiters or (receiver, _normalise_path(path)) in path_limiters:
        return True
    del route
    return any(_is_limiter_expression(item, source, aliases) for item in arguments[1:])


def _is_limiter_expression(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    current = _unwrap(node)
    canonical = _canonical_expression(current, source, aliases)
    if canonical is not None:
        if canonical in _LIMITER_MODULES or any(
            canonical.startswith(f"{module}.") for module in _LIMITER_MODULES
        ):
            return True
        if _LIMITER_NAME.search(canonical.rsplit(".", 1)[-1]):
            return True
    if current.type in {"identifier", "property_identifier"}:
        return bool(_LIMITER_NAME.search(_node_text(source, current)))
    return bool(_LIMITER_NAME.search(_compact_text(source, current)))


def _find_password_verification(
    handler: Node, source: bytes, aliases: dict[str, str]
) -> Node | None:
    bindings = _collect_value_bindings(handler, source)
    for node in _walk_nodes(handler):
        if node.type != "call_expression" or _nested_function(node, handler):
            continue
        function = node.child_by_field_name("function")
        arguments_node = node.child_by_field_name("arguments")
        if function is None or arguments_node is None:
            continue
        canonical = _canonical_expression(function, source, aliases)
        if canonical is None:
            continue
        leaf = canonical.rsplit(".", 1)[-1]
        if leaf not in _VERIFY_METHODS and not _PASSWORD_NAME.search(leaf):
            continue
        arguments = tuple(arguments_node.named_children)
        password_argument = any(
            _is_password_expression(argument, source, bindings, frozenset())
            for argument in arguments
        )
        local_authenticate = (
            leaf == "authenticate"
            and any(
                (_string_value(argument, source) or "").lower() in {"local", "password", "credentials"}
                for argument in arguments
            )
        )
        if password_argument or _PASSWORD_NAME.search(leaf) or local_authenticate:
            return node
    return None


def _collect_value_bindings(handler: Node, source: bytes) -> dict[str, Node]:
    bindings: dict[str, Node] = {}
    for node in _walk_nodes(handler):
        if node.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in node.named_children:
                if declarator.type != "variable_declarator":
                    continue
                name = declarator.child_by_field_name("name")
                value = declarator.child_by_field_name("value")
                if name is not None and value is not None and name.type == "identifier":
                    bindings[_node_text(source, name)] = value
        elif node.type == "assignment_expression":
            name = node.child_by_field_name("left")
            value = node.child_by_field_name("right")
            if name is not None and value is not None and name.type == "identifier":
                bindings[_node_text(source, name)] = value
    return bindings


def _is_password_expression(
    node: Node,
    source: bytes,
    bindings: dict[str, Node],
    visited: frozenset[str],
) -> bool:
    current = _unwrap(node)
    text = _compact_text(source, current)
    if _PASSWORD_NAME.search(text):
        return True
    if current.type == "identifier":
        name = _node_text(source, current)
        if name in visited:
            return False
        bound = bindings.get(name)
        if bound is not None:
            return _is_password_expression(bound, source, bindings, visited | {name})
    if current.type in {"member_expression", "subscript_expression"}:
        property_node = current.child_by_field_name("property") or current.child_by_field_name("index")
        object_node = current.child_by_field_name("object")
        if property_node is not None and _PASSWORD_NAME.search(_compact_text(source, property_node)):
            return True
        if object_node is not None and _is_credential_container(object_node, source):
            return True
    return _is_credential_container(current, source)


def _is_credential_container(node: Node, source: bytes) -> bool:
    value = _compact_text(source, _unwrap(node)).lower()
    return any(item in value for item in (".body", "credentials", "credential", "loginpayload"))


def _nest_candidate(
    method: Node, source: bytes, aliases: dict[str, str]
) -> tuple[Node, bool] | None:
    name_node = method.child_by_field_name("name")
    if name_node is None:
        return None
    method_name = _node_text(source, name_node)
    class_node = method.parent
    while class_node is not None and class_node.type != "class_declaration":
        class_node = class_node.parent
    if class_node is None or not _has_nest_controller(class_node, source, aliases):
        return None
    class_decorators = _decorators(class_node)
    method_decorators = _decorators(method)
    route_path: str | None = None
    has_route = False
    for decorator in method_decorators:
        name, path = _decorator_info(decorator, source, aliases)
        leaf = name.rsplit(".", 1)[-1].lower() if name else ""
        if leaf in {"all", "delete", "get", "head", "options", "patch", "post", "put"}:
            has_route = True
            route_path = path or method_name
    if not has_route or not _LOGIN_WORDS.search(route_path or method_name):
        return None
    limited = any(_is_limiter_decorator(item, source, aliases) for item in (*class_decorators, *method_decorators))
    return method, limited


def _has_nest_controller(class_node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    for decorator in _decorators(class_node):
        name, _ = _decorator_info(decorator, source, aliases)
        if name is not None and name.rsplit(".", 1)[-1].lower() == "controller":
            return True
    return False


def _is_limiter_decorator(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    name, _ = _decorator_info(node, source, aliases)
    text = _compact_text(source, node).lower()
    if name is not None and _LIMITER_NAME.search(name.rsplit(".", 1)[-1]):
        return True
    return any(item in text for item in ("throttle", "ratelimit", "rate_limit", "throttlerguard"))


def _decorator_info(
    node: Node, source: bytes, aliases: dict[str, str]
) -> tuple[str | None, str | None]:
    call = next((item for item in _walk_nodes(node) if item.type == "call_expression"), None)
    if call is None:
        children = tuple(node.named_children)
        if not children:
            return None, None
        return _canonical_expression(children[0], source, aliases), None
    function = call.child_by_field_name("function")
    arguments = call.child_by_field_name("arguments")
    if function is None:
        return None, None
    path = None
    if arguments is not None and arguments.named_children:
        path = _string_value(arguments.named_children[0], source)
    return _canonical_expression(function, source, aliases), path


def _decorators(node: Node) -> tuple[Node, ...]:
    return tuple(child for child in node.named_children if child.type == "decorator")


def _nested_function(node: Node, handler: Node) -> bool:
    parent = node.parent
    while parent is not None and parent is not handler:
        if parent.type in _FUNCTION_TYPES:
            return True
        parent = parent.parent
    return False


def _walk_nodes(root: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        output.append(node)
        stack.extend(reversed(node.named_children))
    return tuple(output)


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
                if name is None or value is None or name.type != "identifier":
                    continue
                canonical = _canonical_expression(value, source, aliases)
                if canonical is not None:
                    aliases[_node_text(source, name)] = canonical
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                canonical = _canonical_expression(right, source, aliases)
                if canonical is not None:
                    aliases[_node_text(source, left)] = canonical
    return aliases


def _collect_import_aliases(node: Node, source: bytes, aliases: dict[str, str]) -> None:
    module_node = node.child_by_field_name("source")
    if module_node is None:
        return
    module = _string_value(module_node, source)
    if module is None:
        return
    module = _normalise_module(module)
    for child in node.named_children:
        if child.type != "import_clause":
            continue
        for item in child.named_children:
            if item.type == "identifier":
                aliases[_node_text(source, item)] = module
            elif item.type == "namespace_import":
                names = item.named_children
                if names:
                    aliases[_node_text(source, names[-1])] = module
            elif item.type in {"named_imports", "named_import"}:
                for specifier in item.named_children:
                    if specifier.type != "import_specifier":
                        continue
                    names = tuple(specifier.named_children)
                    if len(names) >= 2:
                        aliases[_node_text(source, names[-1])] = (
                            f"{module}.{_node_text(source, names[0])}"
                        )
                    elif names:
                        aliases[_node_text(source, names[0])] = (
                            f"{module}.{_node_text(source, names[0])}"
                        )


def _canonical_expression(node: Node, source: bytes, aliases: dict[str, str]) -> str | None:
    current = _unwrap(node)
    if current.type in {"call_expression", "new_expression"}:
        function = current.child_by_field_name("function") or current.child_by_field_name("constructor")
        arguments = current.child_by_field_name("arguments")
        if function is None:
            return None
        if _compact_text(source, function) == "require" and arguments is not None:
            values = arguments.named_children
            if len(values) == 1:
                module = _string_value(values[0], source)
                return _normalise_module(module) if module is not None else None
        return _canonical_expression(function, source, aliases)
    if current.type in {"member_expression", "subscript_expression"}:
        base = current.child_by_field_name("object")
        property_node = current.child_by_field_name("property") or current.child_by_field_name("index")
        if base is None or property_node is None:
            named = tuple(current.named_children)
            if len(named) < 2:
                return None
            base, property_node = named[0], named[-1]
        base_name = _canonical_expression(base, source, aliases)
        property_name = _static_property_name(property_node, source)
        if base_name is None or property_name is None:
            return None
        return f"{base_name}.{property_name}"
    if current.type in {"identifier", "property_identifier", "private_property_identifier"}:
        value = _node_text(source, current)
        return aliases.get(value, value)
    return None


def _static_property_name(node: Node, source: bytes) -> str | None:
    current = _unwrap(node)
    if current.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        return _node_text(source, current)
    return _string_value(current, source)


def _is_function_node(node: Node) -> bool:
    return node.type in _FUNCTION_TYPES


def _unwrap(node: Node) -> Node:
    current = node
    while current.type in _WRAPPER_TYPES:
        children = tuple(current.named_children)
        if not children:
            break
        current = children[-1]
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
        raise EcmaScriptCwe307ScanError(
            EcmaScriptCwe307ScanErrorCode.INTEGRITY_FAILURE
        ) from None


def _node_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe307ScanError(
            EcmaScriptCwe307ScanErrorCode.INTEGRITY_FAILURE
        ) from None


def _compact_text(source: bytes, node: Node) -> str:
    return "".join(_node_text(source, node).split())


def _normalise_module(value: str) -> str:
    if value.startswith("node:"):
        value = value[5:]
    if value.endswith("/index"):
        value = value[:-6]
    return value


def _normalise_path(value: str) -> str:
    result = value.strip().lower()
    if not result.startswith("/"):
        result = f"/{result}"
    return result.rstrip("/") or "/"


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
    operation: EcmaScriptCwe307Operation,
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    language: str,
    signals: tuple[EcmaScriptCwe307Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-307",
        "detector": _DETECTOR,
        "language": language,
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


scan_javascript_authentication_rate_limit = scan_javascript_cwe307
scan_typescript_authentication_rate_limit = scan_typescript_cwe307
scan_ecmascript_authentication_rate_limit = scan_ecmascript_cwe307


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE307_SCAN_LIMITS",
    "EcmaScriptCwe307Operation",
    "EcmaScriptCwe307ScanError",
    "EcmaScriptCwe307ScanErrorCode",
    "EcmaScriptCwe307ScanLimits",
    "EcmaScriptCwe307ScanResult",
    "EcmaScriptCwe307Signal",
    "scan_ecmascript_authentication_rate_limit",
    "scan_ecmascript_cwe307",
    "scan_javascript_authentication_rate_limit",
    "scan_javascript_cwe307",
    "scan_typescript_authentication_rate_limit",
    "scan_typescript_cwe307",
]
