"""Bounded Python session-fixation facts for CWE-384.

The scanner recognises a deliberately small authentication path.  It requires
an explicit web-login indication, an assignment to authenticated state, and a
session-key assignment on a compatible bounded control-flow path.  A recognised
session rotation before the key is written suppresses the fact.  Generic
session use, unresolved reflection, and unrelated state are ignored.

Only a sealed CPython AST and the matching :class:`SymbolIndex` are accepted.
Results contain immutable source ranges and content-addressed identifiers;
source bytes are used transiently for parsing and are never retained.
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
_RULE_ID = "securecode-python-cwe384"
_DETECTOR = "securecode-python-cwe384@1.0"
_DETAIL = "authenticated_state_and_session_key_without_rotation"


class PythonCwe384ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-384 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe384ScanError(RuntimeError):
    """Fixed scanner failure that never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe384ScanErrorCode) -> None:
        if type(code) is not PythonCwe384ScanErrorCode:
            raise TypeError("Python CWE-384 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-384 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe384Operation(StrEnum):
    """The bounded session-fixation finding projection."""

    LOGIN_SUCCESS_WITHOUT_ROTATION = "login_success_without_session_rotation"
    SESSION_FIXATION = "login_success_without_session_rotation"
    LOGIN_SUCCESS = "login_success_without_session_rotation"


@dataclass(frozen=True, slots=True)
class PythonCwe384ScanLimits:
    """Hard ceilings for source, output, and AST-flow resolution."""

    max_source_bytes: int = _MAX_LIMIT_VALUES[0]
    max_signals: int = _MAX_LIMIT_VALUES[1]
    max_resolution_depth: int = _MAX_LIMIT_VALUES[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("Python CWE-384 scan limits are invalid")


DEFAULT_PYTHON_CWE384_SCAN_LIMITS = PythonCwe384ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe384Signal:
    """One immutable login-path fact without source text."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe384Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-384"
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
                self.detail,
            )
            if valid_identity
            and valid_ranges
            and type(self.operation) is PythonCwe384Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not PythonCwe384Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-384"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-384 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the bounded login-path projection."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class PythonCwe384ScanResult:
    """Deterministic, source-free CWE-384 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe384Signal, ...]
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
            type(item) is PythonCwe384Signal for item in self.signals
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
            raise ValueError("Python CWE-384 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Assignment:
    kind: str
    location: SourceRange
    path: tuple[tuple[int, bool], ...]
    order: tuple[int, int]


@dataclass(frozen=True, slots=True)
class _Rotation:
    path: tuple[tuple[int, bool], ...]
    order: tuple[int, int]


_AUTHENTICATED_KEYS = frozenset(
    {
        "authenticated",
        "auth",
        "auth_user",
        "current_user",
        "identity",
        "is_authenticated",
        "logged_in",
        "loggedin",
        "principal",
        "uid",
        "user",
        "user_id",
        "userid",
    }
)
_SESSION_KEY_NAMES = frozenset(
    {
        "session_id",
        "sessionid",
        "session_key",
        "session_token",
        "sid",
    }
)
_SESSION_ROOTS = frozenset(
    {
        "session",
        "flask.session",
        "request.session",
        "req.session",
        "http_request.session",
        "django_request.session",
        "starlette_request.session",
        "self.session",
    }
)
_AUTH_CALLS = frozenset(
    {
        "authenticate",
        "authenticate_user",
        "check_password",
        "flask_login.login_user",
        "django.contrib.auth.authenticate",
        "django.contrib.auth.login",
        "login",
        "login_user",
        "log_in",
        "sign_in",
        "signin",
        "verify_password",
    }
)
_ROTATION_METHODS = frozenset(
    {
        "cycle_key",
        "flush",
        "regenerate",
        "regenerate_id",
        "regenerate_session",
        "renew",
        "renew_id",
        "rotate",
        "rotate_key",
        "rotate_session",
        "rotate_session_id",
    }
)
_ROUTE_METHODS = frozenset({"api_route", "get", "post", "put", "route"})
_LOGIN_WORDS = re.compile(r"(?:^|_)(?:auth|authenticate|log[_]?in|sign[_]?in)(?:$|_)")


def scan_python_cwe384(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe384ScanLimits = DEFAULT_PYTHON_CWE384_SCAN_LIMITS,
) -> PythonCwe384ScanResult:
    """Find bounded login paths that retain a session key without rotation."""

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe384ScanLimits
    ):
        raise PythonCwe384ScanError(PythonCwe384ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe384ScanError(PythonCwe384ScanErrorCode.SOURCE_LIMIT)

    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe384ScanError(PythonCwe384ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe384ScanError(PythonCwe384ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe384ScanError(PythonCwe384ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases = _collect_aliases(tree, limits.max_resolution_depth)
    raw: set[tuple[SourceRange, SourceRange, PythonCwe384Operation]] = set()
    for function in _functions(tree, limits.max_resolution_depth):
        if not _is_login_handler(function, aliases, source, limits.max_resolution_depth):
            continue
        assignments, rotations = _collect_path_events(
            function,
            aliases,
            source,
            line_starts,
            limits.max_resolution_depth,
        )
        authenticated = tuple(item for item in assignments if item.kind == "auth")
        session_keys = tuple(item for item in assignments if item.kind == "key")
        for auth in authenticated:
            for session_key in session_keys:
                if not _paths_compatible(auth.path, session_key.path):
                    continue
                if _constant_false_assignment(function, auth.location, source, line_starts):
                    continue
                if any(
                    _paths_compatible(rotation.path, auth.path)
                    and rotation.order <= session_key.order
                    for rotation in rotations
                ):
                    continue
                span = _span_range(
                    auth.location,
                    session_key.location,
                    source,
                    line_starts,
                )
                raw.add(
                    (
                        auth.location,
                        span,
                        PythonCwe384Operation.LOGIN_SUCCESS_WITHOUT_ROTATION,
                    )
                )
                if len(raw) > limits.max_signals:
                    raise PythonCwe384ScanError(PythonCwe384ScanErrorCode.SIGNAL_LIMIT)

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
    signals = tuple(
        PythonCwe384Signal(
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
    return PythonCwe384ScanResult(
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


def _collect_aliases(tree: ast.AST, max_depth: int) -> dict[str, str | None]:
    aliases: dict[str, str | None] = {}
    for node, _ in _bounded_nodes(tree, max_depth):
        if isinstance(node, ast.Import):
            for item in node.names:
                root = item.name.split(".", 1)[0]
                if root in {"flask", "django", "fastapi", "starlette", "werkzeug", "flask_login"}:
                    aliases[item.asname or root] = item.name
                else:
                    aliases[item.asname or root] = None
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for item in node.names:
                if item.name == "*":
                    continue
                name = item.asname or item.name
                canonical = f"{module}.{item.name}"
                if module in {
                    "flask",
                    "flask_login",
                    "django.contrib.auth",
                    "django.shortcuts",
                    "fastapi",
                    "starlette.responses",
                    "starlette.requests",
                    "werkzeug.security",
                }:
                    aliases[name] = canonical
                else:
                    aliases[name] = None
    return aliases


def _functions(tree: ast.AST, max_depth: int) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...]:
    return tuple(
        node
        for node, _ in _bounded_nodes(tree, max_depth)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )


def _is_login_handler(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    source: bytes,
    max_depth: int,
) -> bool:
    name = function.name.lower()
    named = bool(_LOGIN_WORDS.search(name))
    route_login = False
    for decorator in function.decorator_list:
        decorator_name = _canonical_name(decorator.func if isinstance(decorator, ast.Call) else decorator, aliases)
        if decorator_name and decorator_name.rsplit(".", 1)[-1] in _ROUTE_METHODS:
            literals = [item for item, _ in _bounded_nodes(decorator, max_depth) if isinstance(item, ast.Constant)]
            route_login = any(
                isinstance(item.value, str)
                and bool(re.search(r"(?:login|signin|sign-in|auth)", item.value, re.IGNORECASE))
                for item in literals
            )
        if route_login:
            break
    auth_call = any(
        isinstance(node, ast.Call)
        and _is_auth_call(_canonical_name(node.func, aliases))
        for node, _ in _bounded_nodes(function, max_depth)
    )
    return named or route_login or auth_call


def _collect_path_events(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    max_depth: int,
) -> tuple[tuple[_Assignment, ...], tuple[_Rotation, ...]]:
    assignments: list[_Assignment] = []
    rotations: list[_Rotation] = []
    branch_id = 0

    def visit(statements: list[ast.stmt], path: tuple[tuple[int, bool], ...], depth: int) -> None:
        nonlocal branch_id
        if depth > max_depth:
            raise PythonCwe384ScanError(PythonCwe384ScanErrorCode.SIGNAL_LIMIT)
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if statement is not function:
                    continue
            for node, _ in _bounded_nodes(statement, max_depth - depth):
                if node is not statement and isinstance(node, (ast.stmt, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                if isinstance(node, ast.Call):
                    if _is_rotation_call(_canonical_name(node.func, aliases)):
                        rotations.append(
                            _Rotation(path, (node.lineno, node.col_offset))
                        )
                    _record_update_assignments(
                        node,
                        path,
                        aliases,
                        source,
                        line_starts,
                        assignments,
                    )
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    _record_assignment(
                        node,
                        path,
                        aliases,
                        source,
                        line_starts,
                        assignments,
                    )
            if isinstance(statement, ast.If):
                branch_id += 1
                current = branch_id
                visit(statement.body, (*path, (current, True)), depth + 1)
                visit(statement.orelse, (*path, (current, False)), depth + 1)
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                branch_id += 1
                current = branch_id
                visit(statement.body, (*path, (current, True)), depth + 1)
                visit(statement.orelse, (*path, (current, False)), depth + 1)
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                visit(statement.body, path, depth + 1)
            elif isinstance(statement, ast.Try):
                branch_id += 1
                current = branch_id
                visit(statement.body, (*path, (current, True)), depth + 1)
                visit(statement.orelse, path, depth + 1)
                visit(statement.finalbody, path, depth + 1)
                for handler in statement.handlers:
                    visit(handler.body, (*path, (current, False)), depth + 1)
            elif isinstance(statement, ast.Match):
                branch_id += 1
                current = branch_id
                for index, case in enumerate(statement.cases):
                    visit(case.body, (*path, (current, index == 0)), depth + 1)

    visit(function.body, (), 0)
    return tuple(assignments), tuple(rotations)


def _record_assignment(
    node: ast.Assign | ast.AnnAssign | ast.AugAssign,
    path: tuple[tuple[int, bool], ...],
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    output: list[_Assignment],
) -> None:
    targets: tuple[ast.expr, ...]
    if isinstance(node, ast.Assign):
        targets = tuple(node.targets)
    else:
        targets = (node.target,)
    for target in targets:
        key = _session_assignment_key(target, aliases)
        if key is None:
            continue
        if not _meaningful_value(node.value):
            continue
        kind = "auth" if key in _AUTHENTICATED_KEYS else "key" if key in _SESSION_KEY_NAMES else ""
        if not kind:
            continue
        output.append(
            _Assignment(
                kind,
                _node_range(node, source, line_starts),
                path,
                (node.lineno, node.col_offset),
            )
        )


def _record_update_assignments(
    call: ast.Call,
    path: tuple[tuple[int, bool], ...],
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    output: list[_Assignment],
) -> None:
    name = _canonical_name(call.func, aliases)
    if not name or name.rsplit(".", 1)[-1] not in {"setdefault", "update"}:
        return
    base = name.rsplit(".", 1)[0]
    if not _is_session_name(base):
        return
    items: list[tuple[ast.AST, ast.AST]] = []
    if name.endswith(".setdefault") and len(call.args) >= 2:
        items.append((call.args[0], call.args[1]))
    elif name.endswith(".update") and call.args and isinstance(call.args[0], ast.Dict):
        dictionary = call.args[0]
        items.extend(
            (key, value)
            for key, value in zip(dictionary.keys, dictionary.values, strict=False)
            if key is not None
        )
    for key_node, value_node in items:
        key = _literal_key(key_node)
        if key is None or not _meaningful_value(value_node):
            continue
        kind = "auth" if key in _AUTHENTICATED_KEYS else "key" if key in _SESSION_KEY_NAMES else ""
        if kind:
            output.append(
                _Assignment(
                    kind,
                    _node_range(call, source, line_starts),
                    path,
                    (call.lineno, call.col_offset),
                )
            )


def _session_assignment_key(node: ast.AST, aliases: dict[str, str | None]) -> str | None:
    if isinstance(node, ast.Subscript) and _is_session_expr(node.value, aliases):
        return _literal_key(node.slice)
    if isinstance(node, ast.Attribute) and _is_session_expr(node.value, aliases):
        return _normalise_key(node.attr)
    return None


def _is_session_expr(node: ast.AST, aliases: dict[str, str | None]) -> bool:
    name = _canonical_name(node, aliases)
    return _is_session_name(name)


def _is_session_name(name: str | None) -> bool:
    if not name:
        return False
    if name in _SESSION_ROOTS:
        return True
    return name.endswith(".session") and name.split(".", 1)[0] in {
        "request",
        "req",
        "http_request",
        "django_request",
        "starlette_request",
        "self",
        "flask",
    }


def _is_auth_call(name: str | None) -> bool:
    if not name:
        return False
    if name in _AUTH_CALLS:
        return True
    return name.rsplit(".", 1)[-1] in _AUTH_CALLS


def _is_rotation_call(name: str | None) -> bool:
    if not name:
        return False
    member = name.rsplit(".", 1)[-1]
    if member in _ROTATION_METHODS:
        return True
    return name in {
        "django.contrib.auth.login",
        "flask_login.login_user",
        "starlette.authentication.login",
    }


def _canonical_name(node: ast.AST, aliases: dict[str, str | None]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _canonical_name(node.value, aliases)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Call):
        return _canonical_name(node.func, aliases)
    return None


def _literal_key(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and type(node.value) is str:
        return _normalise_key(node.value)
    return None


def _normalise_key(value: str) -> str:
    return value.strip().lower().replace("-", "_")


def _meaningful_value(node: ast.AST) -> bool:
    return not (
        isinstance(node, ast.Constant)
        and node.value in {None, False, 0, ""}
    )


def _constant_false_assignment(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    location: SourceRange,
    source: bytes,
    line_starts: tuple[int, ...],
) -> bool:
    for node in ast.walk(function):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            if _node_range(node, source, line_starts) == location:
                return isinstance(node.value, ast.Constant) and node.value.value in {
                    None,
                    False,
                    0,
                    "",
                }
    return False


def _paths_compatible(
    left: tuple[tuple[int, bool], ...], right: tuple[tuple[int, bool], ...]
) -> bool:
    left_values = dict(left)
    right_values = dict(right)
    return all(left_values.get(key, value) == right_values.get(key, value) for key, value in left_values.items() if key in right_values)


def _bounded_nodes(root: ast.AST, max_depth: int) -> tuple[tuple[ast.AST, int], ...]:
    output: list[tuple[ast.AST, int]] = []
    stack: list[tuple[ast.AST, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise PythonCwe384ScanError(PythonCwe384ScanErrorCode.SIGNAL_LIMIT)
        output.append((node, depth))
        stack.extend((child, depth + 1) for child in reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(output)


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
        raise PythonCwe384ScanError(PythonCwe384ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe384ScanError(PythonCwe384ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if start < line_starts[start_line] or end > line_starts[end_line + 1] or end < start or end > len(source):
        raise PythonCwe384ScanError(PythonCwe384ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start,
        end,
        SourcePoint(start_line, start_column),
        SourcePoint(end_line, end_column),
    )


def _span_range(
    left: SourceRange,
    right: SourceRange,
    source: bytes,
    line_starts: tuple[int, ...],
) -> SourceRange:
    start = min(left.start_byte, right.start_byte)
    end = max(left.end_byte, right.end_byte)
    if start < 0 or end > len(source) or end < start:
        raise PythonCwe384ScanError(PythonCwe384ScanErrorCode.INTEGRITY_FAILURE)
    if left.start_byte <= right.start_byte:
        start_point, end_point = left.start_point, right.end_point
    else:
        start_point, end_point = right.start_point, left.end_point
    if line_starts[start_point.row] > start or line_starts[end_point.row] > end:
        raise PythonCwe384ScanError(PythonCwe384ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start,
        end,
        start_point,
        end_point,
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
    operation: PythonCwe384Operation,
    detail: str,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detail": detail,
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
    signals: tuple[PythonCwe384Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "detail": signal.detail,
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


Cwe384ScanErrorCode = PythonCwe384ScanErrorCode
Cwe384ScanError = PythonCwe384ScanError
Cwe384ScanLimits = PythonCwe384ScanLimits
Cwe384ScanResult = PythonCwe384ScanResult
Cwe384Signal = PythonCwe384Signal


__all__ = [
    "DEFAULT_PYTHON_CWE384_SCAN_LIMITS",
    "Cwe384ScanError",
    "Cwe384ScanErrorCode",
    "Cwe384ScanLimits",
    "Cwe384ScanResult",
    "Cwe384Signal",
    "PythonCwe384Operation",
    "PythonCwe384ScanError",
    "PythonCwe384ScanErrorCode",
    "PythonCwe384ScanLimits",
    "PythonCwe384ScanResult",
    "PythonCwe384Signal",
    "scan_python_cwe384",
]
