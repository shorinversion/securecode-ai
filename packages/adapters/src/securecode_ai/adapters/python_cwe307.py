"""Bounded Python authentication brute-force facts for CWE-307.

This adapter recognises only a small, explicit web authentication surface.  A
function must look like a Django, Flask, FastAPI, or Starlette login handler,
contain a credential verification operation, and have no known rate limiter,
throttle, lockout, or request quota on that handler.  Ambiguous functions are
ignored.  The scanner never imports application code or keeps source text in
its output.
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

_MAX_LIMIT_VALUES = (2_000_000, 10_000, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-python-cwe307"
_DETECTOR = "securecode-python-cwe307@1.0"
_DETAIL = "authentication_handler_without_rate_limit"


class PythonCwe307ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-307 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe307ScanError(RuntimeError):
    """Fixed scanner failure which never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe307ScanErrorCode) -> None:
        if type(code) is not PythonCwe307ScanErrorCode:
            raise TypeError("Python CWE-307 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-307 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe307Operation(StrEnum):
    """Recognised authentication operations lacking a request limit."""

    AUTH_HANDLER_WITHOUT_RATE_LIMIT = "auth_handler_without_rate_limit"
    AUTHENTICATE_WITHOUT_RATE_LIMIT = "auth_handler_without_rate_limit"
    LOGIN_WITHOUT_RATE_LIMIT = "auth_handler_without_rate_limit"


@dataclass(frozen=True, slots=True)
class PythonCwe307ScanLimits:
    """Hard ceilings for source, output, and bounded alias resolution."""

    max_source_bytes: int = _MAX_LIMIT_VALUES[0]
    max_signals: int = _MAX_LIMIT_VALUES[1]
    max_resolution_depth: int = _MAX_LIMIT_VALUES[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("Python CWE-307 scan limits are invalid")


DEFAULT_PYTHON_CWE307_SCAN_LIMITS = PythonCwe307ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe307Signal:
    """One immutable authentication-path fact without source text."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe307Operation
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
            if valid_identity and valid_ranges and type(self.operation) is PythonCwe307Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not PythonCwe307Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-307"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-307 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete authentication handler range."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class PythonCwe307ScanResult:
    """Deterministic, source-free CWE-307 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe307Signal, ...]
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
            type(item) is PythonCwe307Signal for item in self.signals
        )
        order = (
            tuple(
                (item.sink.start_byte, item.sink.end_byte, item.source.start_byte)
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
            raise ValueError("Python CWE-307 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _AuthEvidence:
    source: SourceRange
    operation: str


_FRAMEWORKS = frozenset({"django", "flask", "fastapi", "starlette"})
_ROUTE_METHODS = frozenset({"route", "get", "post", "put", "patch", "api_route", "websocket_route"})
_AUTH_PATH = re.compile(
    r"(?:^|[/_.-])(?:auth|login|log[-_]?in|sign[-_]?in|signin|token)(?:$|[/_.?-])", re.I
)
_AUTH_FUNCTION = re.compile(
    r"(?:^|_)(?:auth|authenticate|authentication|login|log[_]?in|sign[_]?in|signin|token)(?:$|_)",
    re.I,
)
_CREDENTIAL_WORDS = frozenset(
    {
        "credential",
        "credentials",
        "email",
        "identity",
        "pass",
        "passwd",
        "password",
        "password_hash",
        "passwordhash",
        "secret",
        "token",
        "user",
        "username",
    }
)
_CONCRETE_CREDENTIAL_WORDS = frozenset(
    {
        "credential",
        "credentials",
        "email",
        "pass",
        "passwd",
        "password",
        "password_hash",
        "passwordhash",
        "secret",
        "token",
        "username",
    }
)
_AUTH_CALLS = frozenset(
    {
        "authenticate",
        "authenticate_user",
        "check_credentials",
        "check_password",
        "check_password_hash",
        "login",
        "login_user",
        "log_in",
        "password_verify",
        "sign_in",
        "signin",
        "validate_credentials",
        "validate_password",
        "verify_credentials",
        "verify_password",
    }
)
_RATE_WORDS = frozenset(
    {
        "attempt",
        "attempts",
        "cooldown",
        "failed_attempt",
        "failed_attempts",
        "lockout",
        "quota",
        "rate",
        "ratelimit",
        "retry_after",
        "throttle",
    }
)
_RATE_DECORATOR_WORDS = frozenset(
    {
        "limit",
        "shared_limit",
        "rate_limit",
        "ratelimit",
        "throttle",
        "slowapi",
        "django_ratelimit",
        "login_rate_limit",
        "login_ratelimit",
        "quota",
        "lockout",
    }
)
_RATE_MODULES = frozenset(
    {
        "django_axes",
        "django_ratelimit",
        "flask_limiter",
        "slowapi",
        "starlette_limiter",
    }
)
_MIDDLEWARE_NAMES = frozenset(
    {
        "axesmiddleware",
        "limiter_middleware",
        "ratelimitmiddleware",
        "slowapimiddleware",
        "throttlemiddleware",
    }
)
_QUOTA_CALLS = frozenset(
    {
        "check_attempts",
        "check_login_attempts",
        "check_quota",
        "check_rate_limit",
        "consume_quota",
        "enforce_quota",
        "enforce_rate_limit",
        "is_rate_limited",
        "record_failed_login",
        "throttle_request",
    }
)


def scan_python_cwe307(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe307ScanLimits = DEFAULT_PYTHON_CWE307_SCAN_LIMITS,
) -> PythonCwe307ScanResult:
    """Find explicit web authentication handlers without request limiting.

    The AST analysis must be sealed for the exact ``SymbolIndex``.  Unresolved
    imports, dynamic decorators, and handlers without clear credential
    semantics are ignored.  Invalid input fails closed without exposing source
    content.
    """

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe307ScanLimits
    ):
        raise PythonCwe307ScanError(PythonCwe307ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe307ScanError(PythonCwe307ScanErrorCode.SOURCE_LIMIT)

    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe307ScanError(PythonCwe307ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe307ScanError(PythonCwe307ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe307ScanError(PythonCwe307ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases = _collect_aliases(tree.body, limits.max_resolution_depth)
    framework_present = _framework_present(tree, aliases, limits.max_resolution_depth)
    module_limiter = _module_has_limiter(tree, aliases, limits.max_resolution_depth)
    raw: list[tuple[SourceRange, SourceRange, PythonCwe307Operation]] = []
    for function in _functions(tree, limits.max_resolution_depth):
        if len(raw) >= limits.max_signals:
            raise PythonCwe307ScanError(PythonCwe307ScanErrorCode.SIGNAL_LIMIT)
        function_aliases = dict(aliases)
        _collect_aliases(function.body, limits.max_resolution_depth, function_aliases)
        route = _has_auth_route(function, function_aliases, limits.max_resolution_depth)
        name_matches = _AUTH_FUNCTION.search(function.name) is not None
        if not (name_matches or route):
            continue
        if not (framework_present or route):
            continue
        if _has_rate_limit(function, function_aliases, module_limiter, limits.max_resolution_depth):
            continue
        evidence = _authentication_evidence(
            function,
            function_aliases,
            limits,
            source,
            line_starts,
        )
        if evidence is None:
            continue
        sink = _node_range(function, source, line_starts)
        if not sink.contains(evidence.source):
            raise PythonCwe307ScanError(PythonCwe307ScanErrorCode.INTEGRITY_FAILURE)
        raw.append((evidence.source, sink, PythonCwe307Operation.AUTH_HANDLER_WITHOUT_RATE_LIMIT))

    unique = sorted(
        set(raw),
        key=lambda item: (
            item[1].start_byte,
            item[1].end_byte,
            item[0].start_byte,
            item[0].end_byte,
            item[2].value,
        ),
    )
    if len(unique) > limits.max_signals:
        raise PythonCwe307ScanError(PythonCwe307ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe307Signal(
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
    return PythonCwe307ScanResult(
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


def _functions(
    tree: ast.Module, max_depth: int
) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...]:
    result: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    stack: list[tuple[ast.AST, int]] = [(tree, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise PythonCwe307ScanError(PythonCwe307ScanErrorCode.SIGNAL_LIMIT)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result.append(node)
            continue
        children = tuple(ast.iter_child_nodes(node))
        stack.extend((child, depth + 1) for child in reversed(children))
    return tuple(result)


def _collect_aliases(
    statements: list[ast.stmt],
    max_depth: int,
    aliases: dict[str, str | None] | None = None,
) -> dict[str, str | None]:
    target = aliases if aliases is not None else {}
    for statement in statements:
        if isinstance(statement, ast.Import):
            for item in statement.names:
                root = item.name.split(".", 1)[0]
                target[item.asname or root] = item.name
        elif isinstance(statement, ast.ImportFrom):
            module = "." * statement.level + (statement.module or "")
            if statement.level:
                module = statement.module or ""
            for item in statement.names:
                if item.name != "*":
                    target[item.asname or item.name] = f"{module}.{item.name}".strip(".")
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            pairs: list[tuple[ast.expr, ast.expr]] = []
            if isinstance(statement, ast.Assign):
                pairs = [(target_node, statement.value) for target_node in statement.targets]
            elif statement.value is not None:
                pairs = [(statement.target, statement.value)]
            for target_node, value in pairs:
                if isinstance(target_node, ast.Name):
                    target[target_node.id] = _canonical_reference(value, target, max_depth)
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
    return target


def _framework_present(
    tree: ast.Module,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    for value in aliases.values():
        if value is not None and value.split(".", 1)[0].lower() in _FRAMEWORKS:
            return True
    for node in _iter_nodes(tree, max_depth):
        if isinstance(node, (ast.Call, ast.Attribute, ast.Name)):
            name = _canonical_reference(
                node.func if isinstance(node, ast.Call) else node, aliases, max_depth
            )
            if name is not None and name.split(".", 1)[0].lower() in _FRAMEWORKS:
                return True
    return False


def _module_has_limiter(
    tree: ast.Module,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    for value in aliases.values():
        if (
            value is not None
            and value.split(".", 1)[0].lower() in _RATE_MODULES
            and value.split(".", 1)[0].lower() in {"django_ratelimit", "django_axes"}
        ):
            return True
    for node in _iter_nodes(tree, max_depth):
        if isinstance(node, ast.Call):
            name = _canonical_reference(node.func, aliases, max_depth) or ""
            compact = _compact(name)
            if _is_middleware_call(node, aliases, max_depth) or _is_rate_name(compact):
                return True
        elif (isinstance(node, ast.Name) and _is_middleware_name(node.id)) or (
            isinstance(node, ast.Attribute) and _is_middleware_name(node.attr)
        ):
            return True
    return False


def _has_auth_route(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    return any(_route_path(decorator, aliases, max_depth) for decorator in function.decorator_list)


def _route_path(
    decorator: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
) -> str | None:
    call = decorator if isinstance(decorator, ast.Call) else None
    callable_node = call.func if call is not None else decorator
    name = _canonical_reference(callable_node, aliases, max_depth) or ""
    method = name.rsplit(".", 1)[-1].lower()
    if method not in _ROUTE_METHODS and method not in {"route", "post"}:
        return None
    candidates: list[ast.expr] = []
    if call is not None:
        candidates.extend(call.args[:1])
        candidates.extend(
            keyword.value for keyword in call.keywords if keyword.arg in {"path", "rule", "url"}
        )
    for candidate in candidates:
        value = _literal_string(candidate)
        if value is not None and _AUTH_PATH.search(value):
            return value
    return None


def _authentication_evidence(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    limits: PythonCwe307ScanLimits,
    source: bytes,
    line_starts: tuple[int, ...],
) -> _AuthEvidence | None:
    candidates: list[tuple[tuple[int, int], _AuthEvidence]] = []
    for node in _function_nodes(function, limits.max_resolution_depth):
        if isinstance(node, ast.Call):
            name = _canonical_reference(node.func, aliases, limits.max_resolution_depth)
            if name is None:
                continue
            operation = name.rsplit(".", 1)[-1].lower()
            if operation not in _AUTH_CALLS:
                continue
            if not _credential_call(node, function, aliases, limits.max_resolution_depth):
                continue
            candidates.append(
                (
                    _node_position(node),
                    _AuthEvidence(
                        source=_node_range(node, source, line_starts),
                        operation=operation,
                    ),
                )
            )
    if candidates:
        candidates.sort(key=lambda item: item[0])
        return candidates[0][1]
    return _comparison_evidence(function, aliases, limits.max_resolution_depth, source, line_starts)


def _credential_call(
    call: ast.Call,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    if call.args or call.keywords:
        return True
    return _contains_credential_word(function, aliases, max_depth)


def _comparison_evidence(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    max_depth: int,
    source: bytes,
    line_starts: tuple[int, ...],
) -> _AuthEvidence | None:
    for node in _function_nodes(function, max_depth):
        if not isinstance(node, ast.Compare):
            continue
        names = [item.id.lower() for item in ast.walk(node) if isinstance(item, ast.Name)]
        if len(set(names) & _CONCRETE_CREDENTIAL_WORDS) >= 1 and len(node.comparators) == 1:
            return _AuthEvidence(
                source=_node_range(node, source, line_starts),
                operation="compare",
            )
    return None


def _contains_credential_word(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    for node in _function_nodes(function, max_depth):
        if isinstance(node, ast.Name) and _is_concrete_credential_name(node.id):
            return True
        if isinstance(node, ast.Attribute) and _is_concrete_credential_name(node.attr):
            return True
        if isinstance(node, ast.Call):
            name = _canonical_reference(node.func, aliases, max_depth) or ""
            if _is_request_access(name):
                return True
    return False


def _has_rate_limit(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    module_limiter: bool,
    max_depth: int,
) -> bool:
    if module_limiter:
        return True
    for decorator in function.decorator_list:
        name = (
            _canonical_reference(
                decorator.func if isinstance(decorator, ast.Call) else decorator,
                aliases,
                max_depth,
            )
            or ""
        )
        if _is_rate_decorator(name):
            return True
        for node in ast.walk(decorator):
            if (
                isinstance(node, ast.Constant)
                and type(node.value) is str
                and _is_rate_name(node.value)
            ):
                return True
    for node in _function_nodes(function, max_depth):
        if isinstance(node, ast.Call):
            name = _canonical_reference(node.func, aliases, max_depth) or ""
            compact = _compact(name)
            if compact.rsplit(".", 1)[-1] in _QUOTA_CALLS or _is_rate_name(compact):
                return True
        elif isinstance(node, (ast.Name, ast.Attribute)):
            name = node.id if isinstance(node, ast.Name) else node.attr
            if _is_rate_name(name) or _is_middleware_name(name):
                return True
    return False


def _function_nodes(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    max_depth: int,
) -> tuple[ast.AST, ...]:
    result: list[ast.AST] = []
    stack: list[tuple[ast.AST, int]] = [(statement, 1) for statement in reversed(function.body)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise PythonCwe307ScanError(PythonCwe307ScanErrorCode.SIGNAL_LIMIT)
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node is not function
        ):
            continue
        result.append(node)
        children = tuple(ast.iter_child_nodes(node))
        stack.extend((child, depth + 1) for child in reversed(children))
    return tuple(result)


def _iter_nodes(tree: ast.AST, max_depth: int) -> tuple[ast.AST, ...]:
    result: list[ast.AST] = []
    stack: list[tuple[ast.AST, int]] = [(tree, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise PythonCwe307ScanError(PythonCwe307ScanErrorCode.SIGNAL_LIMIT)
        result.append(node)
        children = tuple(ast.iter_child_nodes(node))
        stack.extend((child, depth + 1) for child in reversed(children))
    return tuple(result)


def _canonical_reference(
    node: ast.AST,
    aliases: dict[str, str | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe307ScanError(PythonCwe307ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Call):
        return _canonical_reference(node.func, aliases, max_depth, depth + 1)
    return None


def _is_request_access(name: str) -> bool:
    parts = _compact(name).split(".")
    return len(parts) >= 2 and parts[-1] in {"get", "get_json", "get_data", "json", "form", "body"}


def _is_credential_name(value: str) -> bool:
    words = set(re.split(r"[^a-z0-9]+", value.lower()))
    return bool(words & _CREDENTIAL_WORDS) or value.lower() in _CREDENTIAL_WORDS


def _is_concrete_credential_name(value: str) -> bool:
    words = set(re.split(r"[^a-z0-9]+", value.lower()))
    return bool(words & _CONCRETE_CREDENTIAL_WORDS) or value.lower() in _CONCRETE_CREDENTIAL_WORDS


def _is_rate_decorator(name: str) -> bool:
    compact = _compact(name)
    tail = compact.rsplit(".", 1)[-1]
    return tail in _RATE_DECORATOR_WORDS or any(word in compact for word in _RATE_DECORATOR_WORDS)


def _is_rate_name(value: str) -> bool:
    compact = _compact(value)
    parts = set(compact.split(".")) | set(re.split(r"[^a-z0-9]+", compact))
    return bool(parts & _RATE_WORDS) or any(
        token in compact for token in ("ratelimit", "rate_limit", "throttle", "slowapi", "quota")
    )


def _is_middleware_name(value: str) -> bool:
    return _compact(value) in _MIDDLEWARE_NAMES or (
        _compact(value).endswith("middleware")
        and any(
            word in _compact(value) for word in ("rate", "limit", "throttle", "slowapi", "axes")
        )
    )


def _is_middleware_call(node: ast.Call, aliases: dict[str, str | None], max_depth: int) -> bool:
    name = _canonical_reference(node.func, aliases, max_depth) or ""
    if name.rsplit(".", 1)[-1].lower() != "add_middleware":
        return False
    return any(
        _is_middleware_name(value)
        for argument in (*node.args, *(keyword.value for keyword in node.keywords))
        for value in (_canonical_reference(argument, aliases, max_depth) or _dotted_name(argument),)
    )


def _compact(value: str) -> str:
    return value.replace("-", "_").lower()


def _dotted_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _literal_string(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None


def _node_position(node: ast.AST) -> tuple[int, int]:
    return getattr(node, "lineno", 0), getattr(node, "col_offset", 0)


def _line_starts(source: bytes) -> tuple[int, ...]:
    starts = [0]
    starts.extend(index + 1 for index, value in enumerate(source) if value == 10)
    if starts[-1] != len(source):
        starts.append(len(source))
    return tuple(starts)


def _node_range(node: ast.AST, source: bytes, line_starts: tuple[int, ...]) -> SourceRange:
    try:
        start_line = node.lineno - 1  # type: ignore[attr-defined]
        end_line = node.end_lineno - 1  # type: ignore[attr-defined]
        start_column = node.col_offset  # type: ignore[attr-defined]
        end_column = node.end_col_offset  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        raise PythonCwe307ScanError(PythonCwe307ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe307ScanError(PythonCwe307ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe307ScanError(PythonCwe307ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start,
        end,
        SourcePoint(start_line, start_column),
        SourcePoint(end_line, end_column),
    )


def _signal_id(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    source: SourceRange,
    sink: SourceRange,
    operation: PythonCwe307Operation,
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
    signals: tuple[PythonCwe307Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
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
            }
            for signal in signals
        ],
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _range_value(location: SourceRange) -> dict[str, int]:
    return {
        "end_byte": location.end_byte,
        "end_column": location.end_point.column,
        "end_row": location.end_point.row,
        "start_byte": location.start_byte,
        "start_column": location.start_point.column,
        "start_row": location.start_point.row,
    }


Cwe307ScanErrorCode = PythonCwe307ScanErrorCode
Cwe307ScanError = PythonCwe307ScanError
Cwe307ScanLimits = PythonCwe307ScanLimits
Cwe307ScanResult = PythonCwe307ScanResult
Cwe307Signal = PythonCwe307Signal


__all__ = [
    "DEFAULT_PYTHON_CWE307_SCAN_LIMITS",
    "Cwe307ScanError",
    "Cwe307ScanErrorCode",
    "Cwe307ScanLimits",
    "Cwe307ScanResult",
    "Cwe307Signal",
    "PythonCwe307Operation",
    "PythonCwe307ScanError",
    "PythonCwe307ScanErrorCode",
    "PythonCwe307ScanLimits",
    "PythonCwe307ScanResult",
    "PythonCwe307Signal",
    "scan_python_cwe307",
]
