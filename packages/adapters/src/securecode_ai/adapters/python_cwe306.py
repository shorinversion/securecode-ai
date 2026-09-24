"""Bounded Python CWE-306 missing-authentication facts.

The adapter reports a narrow class of unauthenticated critical handlers.  A
handler must either expose a clearly sensitive route or perform an explicit
critical resource mutation.  Known authentication decorators, dependency
injections, middleware, and in-function guards suppress a fact.  Ambiguous
routes and dynamic authorization expressions are ignored.

Only a sealed :class:`SymbolIndex` and its matching sealed Python AST are
accepted.  Results contain source ranges and content-addressed identity only;
repository source is never retained, imported, executed, or echoed in an
error.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import RepositoryFile, SourcePoint, SourceRange, SymbolIndex

from .python_ast import (
    PythonAstAnalysis,
    PythonAstError,
    PythonAstStatus,
    analyze_python_ast,
    open_python_ast,
)

_MAX_LIMITS = (2_000_000, 10_000, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-python-cwe306"
_DETECTOR = "securecode-python-cwe306@1.0"
_DETAIL = "critical_function_without_authentication"

_ROUTE_METHODS = frozenset(
    {
        "apiroute",
        "delete",
        "get",
        "head",
        "options",
        "patch",
        "post",
        "put",
        "repath",
        "route",
        "websocket",
        "websocketroute",
    }
)
_MUTATING_ROUTE_METHODS = frozenset({"delete", "patch", "post", "put"})
_CRITICAL_ROUTE_WORDS = frozenset(
    {
        "admin",
        "approve",
        "billing",
        "config",
        "configuration",
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
        "update",
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
_CRITICAL_FUNCTION_WORDS = frozenset(
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
        "session",
        "service",
        "store",
        "user",
        "users",
    }
)
_RESOURCE_METHODS = {
    "bulkcreate": "resource_create",
    "change" + "pass" + "word": "credential_mutation",
    "create": "resource_create",
    "delete": "resource_delete",
    "destroy": "resource_delete",
    "execute": "resource_execute",
    "executesql": "resource_execute",
    "grant": "authorization_mutation",
    "insert": "resource_create",
    "publish": "resource_publish",
    "remove": "resource_delete",
    "revoke": "authorization_mutation",
    "rotate": "credential_mutation",
    "save": "resource_update",
    "set" + "pass" + "word": "credential_mutation",
    "transfer": "resource_transfer",
    "unlink": "resource_delete",
    "update": "resource_update",
    "write": "resource_update",
}
_AUTH_DECORATORS = frozenset(
    {
        "api_key_required",
        "authenticated",
        "auth_required",
        "authorize",
        "authorization_required",
        "jwt_required",
        "logged_in_required",
        "loggedinrequired",
        "login_required",
        "permission_required",
        "permissions_required",
        "requires_auth",
        "requires_authentication",
        "requires_permission",
        "requires_role",
        "role_required",
        "staff_member_required",
        "token_required",
    }
)
_AUTH_GUARDS = frozenset(
    {
        "authenticate",
        "authorize",
        "check_access",
        "check_permission",
        "ensure_authenticated",
        "ensure_authorized",
        "has_permission",
        "is_authenticated",
        "is_authorized",
        "require_access",
        "require_auth",
        "require_authentication",
        "require_permission",
        "require_role",
        "verify_token",
    }
)
_AUTH_MIDDLEWARE_WORDS = frozenset(
    {
        "authenticationmiddleware",
        "authmiddleware",
        "authzmiddleware",
        "jwtauthmiddleware",
        "jwtmiddleware",
        "oauthmiddleware",
        "oauth2middleware",
        "securitymiddleware",
    }
)
_AUTH_DEPENDENCY_WORDS = frozenset(
    {
        "authuser",
        "currentprincipal",
        "currentuser",
        "getauthuser",
        "getcurrentprincipal",
        "getcurrentuser",
        "getprincipal",
        "requirecurrentuser",
    }
)
_AUTH_STATE_WORDS = frozenset(
    {
        "authenticated",
        "authuser",
        "currentuser",
        "is_authenticated",
        "is_authenticated",
        "logged_in",
        "loggedin",
        "principal",
        "requestuser",
        "sessionuser",
        "user_id",
    }
)


class PythonCwe306ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-306 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe306ScanError(RuntimeError):
    """Fixed Python CWE-306 failure that never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe306ScanErrorCode) -> None:
        if type(code) is not PythonCwe306ScanErrorCode:
            raise TypeError("Python CWE-306 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-306 authentication scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe306Operation(StrEnum):
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

    # Compatibility names for generic scanner consumers.
    ROUTE_HANDLER = "critical_route_handler"
    RESOURCE_MUTATION = "resource_update"


@dataclass(frozen=True, slots=True)
class PythonCwe306ScanLimits:
    """Hard ceilings for source, output, and bounded AST traversal."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_resolution_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Python CWE-306 scan limits are invalid")


DEFAULT_PYTHON_CWE306_SCAN_LIMITS = PythonCwe306ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe306Signal:
    """One immutable missing-authentication fact without source text."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe306Operation
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
            if identity_valid and ranges_valid and type(self.operation) is PythonCwe306Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not PythonCwe306Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-306"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-306 signal is invalid")
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
class PythonCwe306ScanResult:
    """Source-free, deterministic CWE-306 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe306Signal, ...]
    scan_sha256: str

    def __post_init__(self) -> None:
        identity_valid = _valid_identity(
            self.repository_id,
            self.revision,
            self.path,
            self.content_sha256,
            self.source_size_bytes,
        )
        signals_valid = type(self.signals) is tuple and all(
            type(item) is PythonCwe306Signal for item in self.signals
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
            if signals_valid
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
            if signals_valid
            else False
        )
        if (
            not identity_valid
            or not signals_valid
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
            raise ValueError("Python CWE-306 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _RouteEvidence:
    node: ast.FunctionDef | ast.AsyncFunctionDef
    mutating: bool


@dataclass(frozen=True, slots=True)
class _CriticalCall:
    node: ast.Call
    operation: PythonCwe306Operation


def scan_python_cwe306(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe306ScanLimits = DEFAULT_PYTHON_CWE306_SCAN_LIMITS,
) -> PythonCwe306ScanResult:
    """Find critical Python handlers that lack a recognised auth boundary.

    Route evidence is limited to explicit route decorators and literal paths.
    Resource evidence is limited to named mutation methods on database,
    repository, model, account, or user-like receivers inside a handler-like
    function.  Unknown dynamic authorization is not treated as proof.
    """

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe306ScanLimits
    ):
        raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.SOURCE_LIMIT)
    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.ANALYSIS_UNAVAILABLE)

    if _suppressed_path(symbol_index.path):
        return _empty_result(symbol_index)
    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases = _collect_aliases(tree, limits.max_resolution_depth)
    module_auth = _module_has_auth_middleware(tree, aliases, limits.max_resolution_depth)
    classes = _classes(tree, limits.max_resolution_depth)
    raw: set[tuple[SourceRange, SourceRange, PythonCwe306Operation]] = set()
    try:
        for function in _functions(tree, limits.max_resolution_depth):
            route = _critical_route(function, aliases, limits.max_resolution_depth)
            critical_calls = _critical_calls(function, aliases, limits.max_resolution_depth)
            is_named_handler = _critical_function_name(function.name)
            if route is None and not (critical_calls and is_named_handler):
                continue
            if module_auth or _class_has_auth(classes, function, aliases, limits.max_resolution_depth):
                continue
            if _function_has_auth_decorator(function, aliases, limits.max_resolution_depth):
                continue
            evidence_call = critical_calls[0] if critical_calls else None
            if evidence_call is not None and _has_inline_auth_guard(
                function,
                evidence_call.node,
                aliases,
                limits.max_resolution_depth,
            ):
                continue
            if evidence_call is not None:
                source_node = evidence_call.node
                operation = evidence_call.operation
            elif route is not None:
                source_node = function
                operation = PythonCwe306Operation.CRITICAL_ROUTE
            else:
                continue
            sink_range = _node_range(function, source, line_starts)
            source_range = _node_range(source_node, source, line_starts)
            if not sink_range.contains(source_range):
                raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.INTEGRITY_FAILURE)
            raw.add((source_range, sink_range, operation))
            if len(raw) > limits.max_signals:
                raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.SIGNAL_LIMIT)
    except PythonCwe306ScanError:
        raise
    except (MemoryError, RecursionError, TypeError, ValueError):
        raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.INTEGRITY_FAILURE) from None

    unique = tuple(
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
    if len(unique) > limits.max_signals:
        raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe306Signal(
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
    return PythonCwe306ScanResult(
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


def _empty_result(symbol_index: SymbolIndex) -> PythonCwe306ScanResult:
    return PythonCwe306ScanResult(
        repository_id=symbol_index.repository_id,
        revision=symbol_index.revision,
        path=symbol_index.path,
        content_sha256=symbol_index.content_sha256,
        source_size_bytes=symbol_index.source_byte_length,
        signals=(),
        scan_sha256=_scan_sha256(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            (),
        ),
    )


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


def _functions(tree: ast.Module, max_depth: int) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...]:
    result: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in _bounded_nodes(tree, max_depth):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result.append(node)
    return tuple(result)


def _classes(tree: ast.Module, max_depth: int) -> tuple[ast.ClassDef, ...]:
    return tuple(node for node in _bounded_nodes(tree, max_depth) if isinstance(node, ast.ClassDef))


def _bounded_nodes(tree: ast.AST, max_depth: int) -> tuple[ast.AST, ...]:
    if type(max_depth) is not int or max_depth < 1:
        raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.REQUEST_INVALID)
    result: list[ast.AST] = []
    stack: list[tuple[ast.AST, int]] = [(tree, 0)]
    limit = max(1, max_depth * 10_000)
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.SIGNAL_LIMIT)
        result.append(node)
        if len(result) > limit:
            raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.SIGNAL_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(result)


def _function_nodes(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    max_depth: int,
) -> tuple[ast.AST, ...]:
    result: list[ast.AST] = []
    stack: list[tuple[ast.AST, int]] = [
        (statement, 1) for statement in reversed(function.body)
    ]
    limit = max(1, max_depth * 10_000)
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.SIGNAL_LIMIT)
        result.append(node)
        if node is not function and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        stack.extend((child, depth + 1) for child in reversed(tuple(ast.iter_child_nodes(node))))
        if len(result) > limit:
            raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.SIGNAL_LIMIT)
    return tuple(result)


def _collect_aliases(tree: ast.Module, max_depth: int) -> dict[str, str | None]:
    aliases: dict[str, str | None] = {}
    for node in _bounded_nodes(tree, max_depth):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".", 1)[0]] = item.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for item in node.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = f"{module}.{item.name}".strip(".")
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    aliases[target.id] = _reference(node.value, aliases, max_depth)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            aliases[node.target.id] = (
                _reference(node.value, aliases, max_depth) if node.value is not None else None
            )
    return aliases


def _critical_route(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    max_depth: int,
) -> _RouteEvidence | None:
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call):
            callable_node = decorator
            call = None
        else:
            callable_node = decorator.func
            call = decorator
        name = _reference(callable_node, aliases, max_depth) or ""
        method = _normalise(name.rsplit(".", 1)[-1])
        if method not in _ROUTE_METHODS:
            continue
        path = _route_path(call)
        if path is None:
            continue
        methods = {method}
        if method == "route" and call is not None:
            methods.update(_route_http_methods(call))
        if _critical_path(path) or bool(methods & _MUTATING_ROUTE_METHODS):
            return _RouteEvidence(function, bool(methods & _MUTATING_ROUTE_METHODS))
    return None


def _route_path(call: ast.Call | None) -> str | None:
    if call is None:
        return None
    candidates: list[ast.expr] = list(call.args[:1])
    candidates.extend(
        keyword.value
        for keyword in call.keywords
        if keyword.arg in {"path", "rule", "route", "url"}
    )
    for candidate in candidates:
        value = _literal_string(candidate)
        if value is not None:
            return value
    return None


def _route_http_methods(call: ast.Call) -> set[str]:
    for keyword in call.keywords:
        if keyword.arg != "methods":
            continue
        values: list[str] = []
        if isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
            values = [
                item.value.lower()
                for item in keyword.value.elts
                if isinstance(item, ast.Constant) and type(item.value) is str
            ]
        return {_normalise(value) for value in values}
    return set()


def _critical_path(path: str) -> bool:
    tokens = {token for token in re.split(r"[^a-z0-9]+", path.lower()) if token}
    if tokens & _PUBLIC_ROUTE_WORDS:
        return False
    return bool(tokens & _CRITICAL_ROUTE_WORDS)


def _critical_calls(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    max_depth: int,
) -> tuple[_CriticalCall, ...]:
    calls: list[_CriticalCall] = []
    for node in _function_nodes(function, max_depth):
        if isinstance(node, ast.Call):
            operation = _resource_operation(node, aliases, max_depth)
            if operation is not None:
                calls.append(_CriticalCall(node, operation))
    calls.sort(key=lambda item: _position(item.node))
    return tuple(calls)


def _resource_operation(
    call: ast.Call,
    aliases: dict[str, str | None],
    max_depth: int,
) -> PythonCwe306Operation | None:
    name = _reference(call.func, aliases, max_depth) or ""
    compact_tail = _normalise(name.rsplit(".", 1)[-1])
    raw_operation = _RESOURCE_METHODS.get(compact_tail)
    if raw_operation is None:
        return None
    parts = tuple(_normalise(part) for part in name.split("."))
    if not _resource_receiver(parts, call):
        return None
    return PythonCwe306Operation(raw_operation)


def _resource_receiver(parts: tuple[str, ...], call: ast.Call) -> bool:
    if len(parts) < 2:
        return False
    receiver = set(parts[:-1])
    if receiver & {"request", "response", "logging", "logger", "json", "string"}:
        return False
    if receiver & _RESOURCE_CONTEXTS:
        return True
    if any(
        part.endswith(("repo", "repository", "dao", "manager", "service", "store"))
        for part in receiver
    ):
        return True
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Call):
        nested = _normalise(_dotted_name(call.func.value.func))
        return any(token in nested for token in ("query", "filter", "model", "objects"))
    return False


def _critical_function_name(name: str) -> bool:
    tokens = {token for token in re.split(r"[^a-z0-9]+", name.lower()) if token}
    return bool(tokens & _CRITICAL_FUNCTION_WORDS) and any(
        token in tokens
        for token in {"handler", "endpoint", "route", "admin", "delete", "destroy", "update", "manage", "transfer", "approve", "revoke", "grant"}
    )


def _module_has_auth_middleware(
    tree: ast.Module,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    for node in _bounded_nodes(tree, max_depth):
        if isinstance(node, ast.Call):
            name = _reference(node.func, aliases, max_depth) or ""
            tail = _normalise(name.rsplit(".", 1)[-1])
            if tail == "addmiddleware":
                for argument in (*node.args, *(keyword.value for keyword in node.keywords)):
                    candidate = _normalise(_reference(argument, aliases, max_depth) or _dotted_name(argument))
                    if candidate and any(word in candidate for word in _AUTH_MIDDLEWARE_WORDS):
                        return True
            elif tail in _AUTH_MIDDLEWARE_WORDS:
                return True
        elif isinstance(node, ast.Constant) and type(node.value) is str:
            compact = _normalise(node.value)
            if compact in _AUTH_MIDDLEWARE_WORDS:
                return True
    return False


def _class_has_auth(
    classes: tuple[ast.ClassDef, ...],
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    position = _position(function)
    for class_node in classes:
        start = _position(class_node)
        end = (getattr(class_node, "end_lineno", 0), getattr(class_node, "end_col_offset", 0))
        if start <= position <= end and _decorators_have_auth(class_node.decorator_list, aliases, max_depth):
            return True
    return False


def _function_has_auth_decorator(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    return _decorators_have_auth(function.decorator_list, aliases, max_depth)


def _decorators_have_auth(
    decorators: list[ast.expr],
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    for decorator in decorators:
        if isinstance(decorator, ast.Call):
            name_node = decorator.func
        else:
            name_node = decorator
        name = _reference(name_node, aliases, max_depth) or _dotted_name(name_node)
        if _auth_name(name):
            return True
        for node in _bounded_expr_nodes(decorator, max_depth):
            if isinstance(node, ast.Call):
                nested = _reference(node.func, aliases, max_depth) or _dotted_name(node.func)
                if _auth_name(nested):
                    return True
                for argument in (*node.args, *(keyword.value for keyword in node.keywords)):
                    dependency = _reference(argument, aliases, max_depth) or _dotted_name(argument)
                    if _auth_dependency_name(dependency):
                        return True
            elif isinstance(node, ast.Constant) and type(node.value) is str:
                if _auth_name(node.value):
                    return True
    return False


def _has_inline_auth_guard(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    evidence: ast.Call,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    evidence_position = _position(evidence)
    for node in _function_nodes(function, max_depth):
        if _position(node) >= evidence_position:
            continue
        if isinstance(node, ast.Call):
            name = _reference(node.func, aliases, max_depth) or _dotted_name(node.func)
            if _strong_auth_call(name):
                return True
        elif isinstance(node, ast.If) and _auth_condition(node.test, aliases, max_depth):
            return True
        elif isinstance(node, ast.Assert) and _auth_condition(node.test, aliases, max_depth):
            return True
    return False


def _strong_auth_call(name: str) -> bool:
    compact = _normalise(name.rsplit(".", 1)[-1])
    if compact in {_normalise(item) for item in _AUTH_GUARDS}:
        return True
    return any(
        token in compact
        for token in ("requireauth", "requirepermission", "requireauthorization", "checkpermission", "checkauthorization")
    )


def _auth_condition(
    condition: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    for node in _bounded_expr_nodes(condition, max_depth):
        if isinstance(node, (ast.Name, ast.Attribute)):
            name = node.id if isinstance(node, ast.Name) else node.attr
            compact = _normalise(name)
            if compact in {_normalise(item) for item in _AUTH_STATE_WORDS}:
                return True
        elif isinstance(node, ast.Call):
            name = _reference(node.func, aliases, max_depth) or _dotted_name(node.func)
            compact = _normalise(name.rsplit(".", 1)[-1])
            if compact in {_normalise(item) for item in _AUTH_GUARDS}:
                return True
            if compact in {"get", "getitem"} and any(
                _auth_state_text(argument) for argument in (*node.args, *(keyword.value for keyword in node.keywords))
            ):
                return True
    return False


def _auth_state_text(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and type(node.value) is str and _normalise(node.value) in {
        _normalise(item) for item in _AUTH_STATE_WORDS
    }


def _auth_name(name: str) -> bool:
    compact = _normalise(name.rsplit(".", 1)[-1])
    if compact in {_normalise(item) for item in _AUTH_DECORATORS}:
        return True
    return any(
        token in compact
        for token in ("loginrequired", "requiresauth", "requireauth", "permissionrequired", "rolerequired", "jwtrequired", "tokenrequired", "authenticated")
    )


def _auth_dependency_name(name: str) -> bool:
    compact = _normalise(name.rsplit(".", 1)[-1])
    return compact in {_normalise(item) for item in _AUTH_DEPENDENCY_WORDS}


def _bounded_expr_nodes(node: ast.AST, max_depth: int) -> tuple[ast.AST, ...]:
    result: list[ast.AST] = []
    stack: list[tuple[ast.AST, int]] = [(node, 0)]
    limit = max(1, max_depth * 1000)
    while stack:
        current, depth = stack.pop()
        if depth > limit or len(result) >= limit:
            raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.SIGNAL_LIMIT)
        result.append(current)
        stack.extend((child, depth + 1) for child in reversed(tuple(ast.iter_child_nodes(current))))
    return tuple(result)


def _reference(node: ast.AST | None, aliases: dict[str, str | None], max_depth: int, depth: int = 0) -> str | None:
    if node is None:
        return None
    if depth > max_depth:
        raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Call):
        return _reference(node.func, aliases, max_depth, depth + 1)
    return None


def _dotted_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _normalise(value: str) -> str:
    return "".join(character.lower() for character in value if character.isalnum())


def _literal_string(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None


def _position(node: ast.AST) -> tuple[int, int]:
    return getattr(node, "lineno", 0), getattr(node, "col_offset", 0)


def _line_starts(source: bytes) -> tuple[int, ...]:
    starts = [0]
    starts.extend(index + 1 for index, value in enumerate(source) if value == 10)
    if starts[-1] != len(source):
        starts.append(len(source))
    return tuple(starts)


def _node_range(node: ast.AST, source: bytes, starts: tuple[int, ...]) -> SourceRange:
    try:
        start_line = node.lineno - 1  # type: ignore[attr-defined]
        end_line = node.end_lineno - 1  # type: ignore[attr-defined]
        start_column = node.col_offset  # type: ignore[attr-defined]
        end_column = node.end_col_offset  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(starts)
        or end_line + 1 >= len(starts)
    ):
        raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.INTEGRITY_FAILURE)
    start = starts[start_line] + start_column
    end = starts[end_line] + end_column
    if start < 0 or end < start or end > len(source) or end > starts[end_line + 1]:
        raise PythonCwe306ScanError(PythonCwe306ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start,
        end,
        SourcePoint(start_line, start_column),
        SourcePoint(end_line, end_column),
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
    operation: PythonCwe306Operation,
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
    signals: tuple[PythonCwe306Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-306",
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
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


def _suppressed_path(path: str) -> bool:
    normalised = path.replace("\\", "/").lower()
    parts = tuple(part for part in normalised.split("/") if part)
    stem = parts[-1] if parts else ""
    return bool(set(parts) & {"test", "tests", "fixture", "fixtures", "example", "examples", "docs"}) or stem.startswith("test_") or stem.endswith("_test.py")


Cwe306ScanErrorCode = PythonCwe306ScanErrorCode
Cwe306ScanError = PythonCwe306ScanError
Cwe306ScanLimits = PythonCwe306ScanLimits
Cwe306ScanResult = PythonCwe306ScanResult
Cwe306Signal = PythonCwe306Signal

scan_python_missing_authentication = scan_python_cwe306
scan_python_cwe306_missing_authentication = scan_python_cwe306


__all__ = [
    "DEFAULT_PYTHON_CWE306_SCAN_LIMITS",
    "Cwe306ScanError",
    "Cwe306ScanErrorCode",
    "Cwe306ScanLimits",
    "Cwe306ScanResult",
    "Cwe306Signal",
    "PythonCwe306Operation",
    "PythonCwe306ScanError",
    "PythonCwe306ScanErrorCode",
    "PythonCwe306ScanLimits",
    "PythonCwe306ScanResult",
    "PythonCwe306Signal",
    "scan_python_cwe306",
    "scan_python_cwe306_missing_authentication",
    "scan_python_missing_authentication",
]
