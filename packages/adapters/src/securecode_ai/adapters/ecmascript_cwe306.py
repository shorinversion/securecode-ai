"""Bounded JavaScript and TypeScript CWE-306 authentication facts.

The adapter reports only explicit, local evidence of a critical route or
resource operation without an authentication boundary.  Route registration,
authentication middleware, guards, and resource calls are resolved through a
small syntax-only model.  Dynamic routers, cross-file configuration, and
unknown framework abstractions are ignored.

Signals contain immutable source ranges and content-addressed identity.  The
admitted source is used transiently while parsing and is never retained in a
signal or exposed through an error.
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
_RULE_ID = "securecode-ecmascript-cwe306"
_DETECTOR = "securecode-ecmascript-cwe306@1.0"
_DETAIL = "critical_function_without_authentication"

_ROUTE_METHODS = frozenset({"all", "delete", "get", "head", "options", "patch", "post", "put"})
_MUTATING_ROUTE_METHODS = frozenset({"delete", "patch", "post", "put"})
_FRAMEWORK_MODULES = frozenset(
    {
        "express",
        "fastify",
        "koa",
        "@koa/router",
        "koa-router",
        "hapi",
        "@hapi/hapi",
    }
)
_CRITICAL_ROUTE_WORDS = frozenset(
    {
        "admin",
        "approve",
        "billing",
        "config",
        "configuration",
        "credential",
        "credentials",
        "delete",
        "destroy",
        "export",
        "grant",
        "impersonate",
        "internal",
        "manage",
        "management",
        "payment",
        "payments",
        "permission",
        "permissions",
        "private",
        "publish",
        "revoke",
        "role",
        "roles",
        "rotate",
        "secret",
        "secrets",
        "settings",
        "transfer",
        "user",
        "users",
        "account",
        "accounts",
    }
)
_PUBLIC_ROUTE_WORDS = frozenset(
    {
        "docs",
        "health",
        "login",
        "logout",
        "openapi",
        "public",
        "register",
        "registration",
        "signin",
        "signout",
        "signup",
        "status",
        "token",
    }
)
_RESOURCE_CONTEXTS = frozenset(
    {
        "account",
        "accounts",
        "admin",
        "cache",
        "dao",
        "database",
        "db",
        "entity",
        "entities",
        "manager",
        "model",
        "models",
        "object",
        "objects",
        "query",
        "record",
        "records",
        "repo",
        "repository",
        "service",
        "session",
        "store",
        "user",
        "users",
    }
)
_RESOURCE_METHODS = {
    "bulkcreate": "resource_create",
    "change_" + "pass" + "word": "credential_mutation",
    "change" + "pass" + "word": "credential_mutation",
    "create": "resource_create",
    "delete": "resource_delete",
    "destroy": "resource_delete",
    "execute": "resource_execute",
    "execute_sql": "resource_execute",
    "grant": "authorization_mutation",
    "insert": "resource_create",
    "publish": "resource_publish",
    "remove": "resource_delete",
    "revoke": "authorization_mutation",
    "rotate": "credential_mutation",
    "save": "resource_update",
    "set_" + "pass" + "word": "credential_mutation",
    "set" + "pass" + "word": "credential_mutation",
    "transfer": "resource_transfer",
    "unlink": "resource_delete",
    "update": "resource_update",
    "write": "resource_update",
}
_FUNCTION_CRITICAL_WORDS = frozenset(
    {
        "admin",
        "approve",
        "billing",
        "config",
        "credential",
        "delete",
        "destroy",
        "grant",
        "impersonate",
        "manage",
        "payment",
        "permission",
        "publish",
        "revoke",
        "role",
        "rotate",
        "secret",
        "settings",
        "transfer",
        "update",
    }
)
_AUTH_MODULES = frozenset(
    {
        "passport",
        "passport-jwt",
        "express-jwt",
        "express-session",
        "jsonwebtoken",
        "koa-passport",
        "@fastify/auth",
        "@fastify/jwt",
        "@nestjs/passport",
        "@nestjs/jwt",
        "jose",
    }
)
_AUTH_LEAF = re.compile(
    r"(?:^|[_$.-])(?:auth|authenticate|authenticated|authorization|authorize|"
    r"checkauth|checkaccess|ensureauth(?:enticated)?|guard|jwt|loginrequired|"
    r"passport|requireauth(?:entication)?|requirepermission|verifytoken|"
    r"verifyuser|isloggedin|isauthenticated|canactivate)(?:$|[_$.-])",
    re.IGNORECASE,
)
_AUTH_DECORATOR = re.compile(
    r"(?:auth(?:enticated|orized)?|useguards?|jwt(?:auth)?guard|"
    r"roles?|permissions?|secure|requires?auth|canactivate)",
    re.IGNORECASE,
)
_UNAUTHORIZED_GUARD = re.compile(
    r"(?:isAuthenticated|is_logged_in|req\.user|request\.user|ctx\.state\.user|"
    r"status\s*\(\s*(?:401|403)\s*\)|unauthorized|forbidden|not.?authenticated)",
    re.IGNORECASE,
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
    {
        "as_expression",
        "parenthesized_expression",
        "non_null_expression",
        "type_assertion",
        "satisfies_expression",
    }
)


class EcmaScriptCwe306ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-306 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe306ScanError(RuntimeError):
    """Fixed scanner failure that never includes parser or source details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe306ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe306ScanErrorCode:
            raise TypeError("ECMAScript CWE-306 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-306 authentication scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe306ScanLimits:
    """Hard ceilings applied before and during syntax analysis."""

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
            raise ValueError("ECMAScript CWE-306 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE306_SCAN_LIMITS = EcmaScriptCwe306ScanLimits()


class EcmaScriptCwe306Operation(StrEnum):
    """Recognised critical operations that require authentication."""

    CRITICAL_ROUTE = "critical_route_handler"
    RESOURCE_CREATE = "resource_create"
    RESOURCE_DELETE = "resource_delete"
    RESOURCE_UPDATE = "resource_update"
    RESOURCE_EXECUTE = "resource_execute"
    RESOURCE_PUBLISH = "resource_publish"
    RESOURCE_TRANSFER = "resource_transfer"
    AUTHORIZATION_MUTATION = "authorization_mutation"
    CREDENTIAL_MUTATION = "credential_mutation"

    ROUTE_HANDLER = "critical_route_handler"
    RESOURCE_MUTATION = "resource_update"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe306Signal:
    """One immutable missing-authentication fact without source text."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe306Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-306"
    detector: str = _DETECTOR
    detail: str = _DETAIL

    def __post_init__(self) -> None:
        identity_valid = _valid_identity(
            self.repository_id,
            self.revision,
            self.path,
            self.content_sha256,
            self.source_size_bytes,
        )
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
            if identity_valid and ranges_valid and type(self.operation) is EcmaScriptCwe306Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not EcmaScriptCwe306Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-306"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("ECMAScript CWE-306 signal is invalid")
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
class EcmaScriptCwe306ScanResult:
    """Deterministic and source-free CWE-306 output for one source file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe306Signal, ...]
    scan_sha256: str

    def __post_init__(self) -> None:
        identity_valid = _valid_identity(
            self.repository_id,
            self.revision,
            self.path,
            self.content_sha256,
            self.source_size_bytes,
        ) and self.language in {"javascript", "typescript"}
        valid_signals = type(self.signals) is tuple and all(
            type(item) is EcmaScriptCwe306Signal for item in self.signals
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
            raise ValueError("ECMAScript CWE-306 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _RouteCandidate:
    route: Node
    handler: Node
    path_node: Node
    path: str
    receiver: str
    arguments: tuple[Node, ...]
    method: str


@dataclass(frozen=True, slots=True)
class _NestCandidate:
    handler: Node
    evidence: Node
    path: str
    method: str
    class_node: Node


def scan_javascript_cwe306(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe306ScanLimits = DEFAULT_ECMASCRIPT_CWE306_SCAN_LIMITS,
) -> EcmaScriptCwe306ScanResult:
    """Find explicit critical JavaScript handlers without authentication."""

    return _scan_ecmascript_cwe306(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe306(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe306ScanLimits = DEFAULT_ECMASCRIPT_CWE306_SCAN_LIMITS,
) -> EcmaScriptCwe306ScanResult:
    """Find explicit critical TypeScript handlers without authentication."""

    return _scan_ecmascript_cwe306(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe306(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe306ScanLimits = DEFAULT_ECMASCRIPT_CWE306_SCAN_LIMITS,
) -> EcmaScriptCwe306ScanResult:
    """Dispatch a CWE-306 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe306(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe306(symbol_index, limits=limits)
    raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe306(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe306ScanLimits,
) -> EcmaScriptCwe306ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe306ScanLimits:
        raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.ANALYSIS_UNAVAILABLE)

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
        raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.INTEGRITY_FAILURE) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.ANALYSIS_UNAVAILABLE)
        aliases = _collect_aliases(nodes, source)
        bindings = _collect_function_bindings(nodes, source)
        global_auth, path_auth = _collect_auth_middleware(nodes, source, aliases)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe306Operation]] = set()
        route_handlers: set[tuple[int, int]] = set()

        for node in nodes:
            if node.type != "call_expression":
                continue
            candidate = _route_candidate(node, source, aliases, bindings)
            if candidate is None or not _critical_path(candidate.path, candidate.method):
                continue
            route_handlers.add((candidate.handler.start_byte, candidate.handler.end_byte))
            if _route_has_auth(candidate, source, aliases, global_auth, path_auth):
                continue
            source_range = _range(candidate.path_node)
            sink_range = _range(candidate.route)
            if not sink_range.contains(source_range):
                raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.INTEGRITY_FAILURE)
            raw.add((source_range, sink_range, EcmaScriptCwe306Operation.CRITICAL_ROUTE))
            if len(raw) > limits.max_signals:
                raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.SIGNAL_LIMIT)

        for method in nodes:
            if method.type != "method_definition":
                continue
            nest = _nest_candidate(method, source, aliases)
            if nest is None or not _critical_path(nest.path, nest.method):
                continue
            if _nest_has_auth(nest, source, aliases):
                continue
            source_range = _range(nest.evidence)
            sink_range = _range(nest.handler)
            if not sink_range.contains(source_range):
                source_range = sink_range
            raw.add((source_range, sink_range, EcmaScriptCwe306Operation.CRITICAL_ROUTE))
            route_handlers.add((nest.handler.start_byte, nest.handler.end_byte))
            if len(raw) > limits.max_signals:
                raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.SIGNAL_LIMIT)

        for function in nodes:
            if function.type not in _FUNCTION_TYPES:
                continue
            key = (function.start_byte, function.end_byte)
            if key in route_handlers or not _critical_function_name(function, source):
                continue
            resource_calls = _resource_calls(function, source, aliases)
            if not resource_calls or _has_auth_guard(function, source, aliases):
                continue
            call, operation = resource_calls[0]
            source_range = _range(call)
            sink_range = _range(function)
            if not sink_range.contains(source_range):
                raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.INTEGRITY_FAILURE)
            raw.add((source_range, sink_range, operation))
            if len(raw) > limits.max_signals:
                raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.SIGNAL_LIMIT)

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
    except EcmaScriptCwe306ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.INTEGRITY_FAILURE) from None

    signals = tuple(
        EcmaScriptCwe306Signal(
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
    return EcmaScriptCwe306ScanResult(
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
    if len(arguments) < 2:
        return None
    path_node = _unwrap(arguments[0])
    path = _string_value(path_node, source)
    if path is None:
        return None
    for argument in reversed(arguments[1:]):
        current = _unwrap(argument)
        if _is_function_node(current):
            return _RouteCandidate(
                node,
                current,
                path_node,
                path,
                canonical.rsplit(".", 1)[0],
                arguments,
                method,
            )
        if current.type == "identifier":
            handler = bindings.get(_node_text(source, current))
            if handler is not None:
                return _RouteCandidate(
                    node,
                    handler,
                    path_node,
                    path,
                    canonical.rsplit(".", 1)[0],
                    arguments,
                    method,
                )
    return None


def _is_framework_route(canonical: str) -> bool:
    receiver = canonical.rsplit(".", 1)[0] if "." in canonical else ""
    root = receiver.split(".", 1)[0]
    return root in {"express", "fastify", "koa", "hapi", "@koa/router", "koa-router"} or any(
        receiver == module or receiver.startswith(f"{module}.") for module in _FRAMEWORK_MODULES
    )


def _critical_path(path: str, method: str) -> bool:
    tokens = {
        token for token in re.split(r"[^a-z0-9]+", path.lower()) if token and not token.isdigit()
    }
    if not tokens or (tokens & _PUBLIC_ROUTE_WORDS and not tokens & _CRITICAL_ROUTE_WORDS):
        return False
    if tokens & _CRITICAL_ROUTE_WORDS:
        return True
    return method in _MUTATING_ROUTE_METHODS and bool(
        tokens & {"item", "items", "resource", "resources", "data", "files", "file"}
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


def _collect_auth_middleware(
    nodes: tuple[Node, ...], source: bytes, aliases: dict[str, str]
) -> tuple[frozenset[str], frozenset[tuple[str, str]]]:
    global_auth: set[str] = set()
    path_auth: set[tuple[str, str]] = set()
    for node in nodes:
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        arguments_node = node.child_by_field_name("arguments")
        if function is None or arguments_node is None:
            continue
        canonical = _canonical_expression(function, source, aliases)
        if canonical is None or canonical.rsplit(".", 1)[-1].lower() != "use":
            continue
        receiver = canonical.rsplit(".", 1)[0]
        if not _is_framework_receiver(receiver):
            continue
        arguments = tuple(arguments_node.named_children)
        if not arguments:
            continue
        path = _string_value(arguments[0], source)
        middleware = arguments[1:] if path is not None else arguments
        if not any(_is_auth_expression(item, source, aliases) for item in middleware):
            continue
        if path is None:
            global_auth.add(receiver)
        else:
            path_auth.add((receiver, _normalise_path(path)))
    return frozenset(global_auth), frozenset(path_auth)


def _route_has_auth(
    candidate: _RouteCandidate,
    source: bytes,
    aliases: dict[str, str],
    global_auth: frozenset[str],
    path_auth: frozenset[tuple[str, str]],
) -> bool:
    if candidate.receiver in global_auth:
        return True
    if (candidate.receiver, _normalise_path(candidate.path)) in path_auth:
        return True
    middleware = candidate.arguments[1:]
    for item in middleware:
        current = _unwrap(item)
        if _is_function_node(current) or (
            current.type == "identifier"
            and _node_text(source, current) == _node_text(source, candidate.handler)
        ):
            continue
        if _is_auth_expression(current, source, aliases):
            return True
    return False


def _has_auth_guard(handler: Node, source: bytes, aliases: dict[str, str]) -> bool:
    for node in _walk_nodes(handler):
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function is None:
                continue
            canonical = _canonical_expression(function, source, aliases)
            if canonical is not None and _is_auth_leaf(canonical.rsplit(".", 1)[-1]):
                return True
        elif node.type == "if_statement":
            text = _compact_text(source, node)
            if _UNAUTHORIZED_GUARD.search(text) and any(
                token in text.lower() for token in ("return", "throw", "status(401", "status(403")
            ):
                return True
    return False


def _critical_function_name(function: Node, source: bytes) -> bool:
    name = function.child_by_field_name("name")
    if name is None and function.type == "method_definition":
        name = function.child_by_field_name("name")
    if name is None:
        return False
    tokens = {token for token in re.split(r"[^a-z0-9]+", _node_text(source, name).lower()) if token}
    compact = _normalise(_node_text(source, name))
    return bool(tokens & _FUNCTION_CRITICAL_WORDS) or any(
        compact.startswith(prefix)
        for prefix in ("delete", "destroy", "update", "publish", "transfer", "grant", "revoke")
    )


def _resource_calls(
    function: Node, source: bytes, aliases: dict[str, str]
) -> tuple[tuple[Node, EcmaScriptCwe306Operation], ...]:
    result: list[tuple[Node, EcmaScriptCwe306Operation]] = []
    for node in _walk_nodes(function):
        if node is function or node.type != "call_expression" or _nested_function(node, function):
            continue
        target = node.child_by_field_name("function")
        if target is None:
            continue
        canonical = _canonical_expression(target, source, aliases)
        if canonical is None:
            continue
        parts = tuple(_normalise(part) for part in canonical.split("."))
        if len(parts) < 2:
            continue
        operation = _RESOURCE_METHODS.get(parts[-1])
        if operation is None or not _resource_receiver(parts[:-1]):
            continue
        result.append((node, EcmaScriptCwe306Operation(operation)))
    result.sort(key=lambda item: (item[0].start_byte, item[0].end_byte, item[1].value))
    return tuple(result)


def _resource_receiver(parts: tuple[str, ...]) -> bool:
    receiver = set(parts)
    if receiver & {"request", "response", "logging", "logger", "json", "string", "array"}:
        return False
    return bool(receiver & _RESOURCE_CONTEXTS) or any(
        part.endswith(("repo", "repository", "dao", "manager", "service", "store", "model"))
        for part in receiver
    )


def _nest_candidate(method: Node, source: bytes, aliases: dict[str, str]) -> _NestCandidate | None:
    class_node = method.parent
    while class_node is not None and class_node.type not in {"class_declaration", "class"}:
        class_node = class_node.parent
    if class_node is None or not _has_controller_decorator(class_node, source, aliases):
        return None
    route_decorator: Node | None = None
    route_path: str | None = None
    route_method = "get"
    for decorator in _decorators(method):
        name, path = _decorator_info(decorator, source, aliases)
        leaf = name.rsplit(".", 1)[-1].lower() if name else ""
        if leaf in _ROUTE_METHODS:
            route_decorator = decorator
            route_path = path
            route_method = leaf
            break
    if route_decorator is None:
        return None
    controller_path = ""
    for decorator in _decorators(class_node):
        name, path = _decorator_info(decorator, source, aliases)
        if name is not None and name.rsplit(".", 1)[-1].lower() == "controller":
            controller_path = path or ""
            break
    method_name = method.child_by_field_name("name")
    if route_path is None:
        route_path = _node_text(source, method_name) if method_name is not None else ""
    combined = "/".join(part.strip("/") for part in (controller_path, route_path) if part).join(
        ("/", "")
    )
    return _NestCandidate(method, route_decorator, combined or "/", route_method, class_node)


def _nest_has_auth(candidate: _NestCandidate, source: bytes, aliases: dict[str, str]) -> bool:
    for node in (*_decorators(candidate.class_node), *_decorators(candidate.handler)):
        name, _ = _decorator_info(node, source, aliases)
        if name is not None and _AUTH_DECORATOR.search(name.rsplit(".", 1)[-1]):
            return True
        if _is_auth_expression(node, source, aliases):
            return True
    return _has_auth_guard(candidate.handler, source, aliases)


def _has_controller_decorator(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    return any(
        (name is not None and name.rsplit(".", 1)[-1].lower() == "controller")
        for name, _ in (_decorator_info(item, source, aliases) for item in _decorators(node))
    )


def _decorators(node: Node) -> tuple[Node, ...]:
    return tuple(child for child in node.named_children if child.type == "decorator")


def _decorator_info(
    node: Node, source: bytes, aliases: dict[str, str]
) -> tuple[str | None, str | None]:
    call = next((item for item in _walk_nodes(node) if item.type == "call_expression"), None)
    if call is None:
        children = tuple(node.named_children)
        return (
            (_canonical_expression(children[0], source, aliases), None)
            if children
            else (None, None)
        )
    function = call.child_by_field_name("function")
    arguments = call.child_by_field_name("arguments")
    if function is None:
        return None, None
    path = None
    if arguments is not None and arguments.named_children:
        path = _string_value(arguments.named_children[0], source)
    return _canonical_expression(function, source, aliases), path


def _is_auth_expression(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    current = _unwrap(node)
    canonical = _canonical_expression(current, source, aliases)
    if canonical is not None:
        module = canonical.split(".", 1)[0]
        if module in _AUTH_MODULES or any(
            canonical == item or canonical.startswith(f"{item}.") for item in _AUTH_MODULES
        ):
            return True
        if _is_auth_leaf(canonical.rsplit(".", 1)[-1]):
            return True
    if current.type in {"identifier", "property_identifier", "member_expression"}:
        return _is_auth_leaf(_compact_text(source, current))
    return False


def _is_auth_leaf(value: str) -> bool:
    return bool(_AUTH_LEAF.search(_normalise(value)))


def _bounded_nodes(root: Node, limits: EcmaScriptCwe306ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _walk_nodes(root: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        output.append(node)
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _nested_function(node: Node, function: Node) -> bool:
    parent = node.parent
    while parent is not None and parent is not function:
        if parent.type in _FUNCTION_TYPES:
            return True
        parent = parent.parent
    return False


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
                names = tuple(item.named_children)
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
        function = current.child_by_field_name("function") or current.child_by_field_name(
            "constructor"
        )
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
        property_node = current.child_by_field_name("property") or current.child_by_field_name(
            "index"
        )
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


def _is_framework_receiver(receiver: str) -> bool:
    root = receiver.split(".", 1)[0]
    return root in {"express", "fastify", "koa", "hapi", "@koa/router", "koa-router"} or any(
        receiver == module or receiver.startswith(f"{module}.") for module in _FRAMEWORK_MODULES
    )


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
        raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.INTEGRITY_FAILURE) from None


def _node_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe306ScanError(EcmaScriptCwe306ScanErrorCode.INTEGRITY_FAILURE) from None


def _compact_text(source: bytes, node: Node) -> str:
    return "".join(_node_text(source, node).split())


def _normalise(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()


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


def _valid_identity(repository_id: str, revision: str, path: str, digest: str, size: int) -> bool:
    valid = (
        type(repository_id) is str
        and bool(repository_id)
        and len(repository_id.encode("utf-8")) <= 1024
        and type(revision) is str
        and _SHA1.fullmatch(revision) is not None
        and type(path) is str
        and type(digest) is str
        and _SHA256.fullmatch(digest) is not None
        and type(size) is int
        and size >= 0
    )
    if valid:
        try:
            RepositoryFile(path, size, digest)
        except (TypeError, ValueError):
            return False
    return valid


def _signal_id(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    source: SourceRange,
    sink: SourceRange,
    operation: EcmaScriptCwe306Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-306",
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
    signals: tuple[EcmaScriptCwe306Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-306",
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


scan_javascript_missing_authentication = scan_javascript_cwe306
scan_typescript_missing_authentication = scan_typescript_cwe306
scan_ecmascript_missing_authentication = scan_ecmascript_cwe306


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE306_SCAN_LIMITS",
    "EcmaScriptCwe306Operation",
    "EcmaScriptCwe306ScanError",
    "EcmaScriptCwe306ScanErrorCode",
    "EcmaScriptCwe306ScanLimits",
    "EcmaScriptCwe306ScanResult",
    "EcmaScriptCwe306Signal",
    "scan_ecmascript_cwe306",
    "scan_ecmascript_missing_authentication",
    "scan_javascript_cwe306",
    "scan_javascript_missing_authentication",
    "scan_typescript_cwe306",
    "scan_typescript_missing_authentication",
]
