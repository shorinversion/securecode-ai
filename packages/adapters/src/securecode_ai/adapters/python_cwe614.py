"""Bounded Python CWE-614 facts for cookies without the Secure attribute.

The scanner consumes one admitted, sealed :class:`SymbolIndex` and the
matching sealed CPython AST analysis.  It recognises response ``set_cookie``
calls from Flask, Django, Starlette, and FastAPI.  Only cookie names that can
be resolved to a constant and that are demonstrably security-sensitive are
reported.  Constantly non-sensitive names are suppressed, while dynamic
names are ignored because their sensitivity cannot be proven.

Results contain immutable source ranges and content-addressed metadata only.
The scanner never imports application code, executes a call, retains source
text, or includes source text in an error.
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
_RULE_ID = "securecode-python-cwe614"
_DETECTOR = "securecode-python-cwe614@1.0"
_DETAIL = "sensitive_cookie_without_secure_flag"


class PythonCwe614ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-614 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe614ScanError(RuntimeError):
    """Fixed Python CWE-614 failure which never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe614ScanErrorCode) -> None:
        if type(code) is not PythonCwe614ScanErrorCode:
            raise TypeError("Python CWE-614 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-614 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe614Operation(StrEnum):
    """Recognised response cookie-setting operations."""

    FLASK_SET_COOKIE = "flask.response.set_cookie"
    DJANGO_SET_COOKIE = "django.response.set_cookie"
    STARLETTE_SET_COOKIE = "starlette.response.set_cookie"
    FASTAPI_SET_COOKIE = "fastapi.response.set_cookie"
    RESPONSE_SET_COOKIE = "response.set_cookie"

    # Compatibility name used by generic scanner consumers.
    SET_COOKIE = "response.set_cookie"


@dataclass(frozen=True, slots=True)
class PythonCwe614ScanLimits:
    """Hard ceilings for source, output, and local alias resolution."""

    max_source_bytes: int = _MAX_LIMIT_VALUES[0]
    max_signals: int = _MAX_LIMIT_VALUES[1]
    max_resolution_depth: int = _MAX_LIMIT_VALUES[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("Python CWE-614 scan limits are invalid")


DEFAULT_PYTHON_CWE614_SCAN_LIMITS = PythonCwe614ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe614Signal:
    """One immutable sensitive-cookie fact without source text."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe614Operation
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
        )
        if valid_identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid_identity = False
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
                self.cookie_name,
            )
            if valid_identity
            and ranges_valid
            and type(self.operation) is PythonCwe614Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not ranges_valid
            or type(self.operation) is not PythonCwe614Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-614"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-614 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete response cookie call location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class PythonCwe614ScanResult:
    """Source-free, deterministic CWE-614 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe614Signal, ...]
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
            type(item) is PythonCwe614Signal for item in self.signals
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
            raise ValueError("Python CWE-614 scan result is invalid")


_RESPONSE_ROOTS = frozenset(
    {
        "response",
        "resp",
        "http_response",
        "httpresponse",
        "flask_response",
        "django_response",
        "starlette_response",
        "fastapi_response",
        "reply",
    }
)
_RESPONSE_CLASSES = {
    "flask.Response": PythonCwe614Operation.FLASK_SET_COOKIE,
    "flask.wrappers.Response": PythonCwe614Operation.FLASK_SET_COOKIE,
    "flask.make_response": PythonCwe614Operation.FLASK_SET_COOKIE,
    "django.http.HttpResponse": PythonCwe614Operation.DJANGO_SET_COOKIE,
    "django.http.HttpResponseRedirect": PythonCwe614Operation.DJANGO_SET_COOKIE,
    "django.http.JsonResponse": PythonCwe614Operation.DJANGO_SET_COOKIE,
    "starlette.responses.Response": PythonCwe614Operation.STARLETTE_SET_COOKIE,
    "starlette.responses.HTMLResponse": PythonCwe614Operation.STARLETTE_SET_COOKIE,
    "starlette.responses.JSONResponse": PythonCwe614Operation.STARLETTE_SET_COOKIE,
    "fastapi.Response": PythonCwe614Operation.FASTAPI_SET_COOKIE,
    "fastapi.responses.Response": PythonCwe614Operation.FASTAPI_SET_COOKIE,
    "fastapi.responses.HTMLResponse": PythonCwe614Operation.FASTAPI_SET_COOKIE,
    "fastapi.responses.JSONResponse": PythonCwe614Operation.FASTAPI_SET_COOKIE,
}
_IMPORT_ROOTS = frozenset({"flask", "django", "starlette", "fastapi"})
_RESPONSE_IMPORTS = frozenset(_RESPONSE_CLASSES)
_MAKE_RESPONSE_IMPORTS = frozenset({"flask.make_response"})
_SENSITIVE_NAME = frozenset(
    {
        "session",
        "sessionid",
        "session_id",
        "sessid",
        "sid",
        "auth",
        "authn",
        "authz",
        "authtoken",
        "access_token",
        "refresh_token",
        "id_token",
        "token",
        "jwt",
        "credential",
        "credentials",
        "identity",
        "login",
        "remember",
        "remember_me",
        "csrf",
        "oauth",
    }


def scan_python_cwe614(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe614ScanLimits = DEFAULT_PYTHON_CWE614_SCAN_LIMITS,
) -> PythonCwe614ScanResult:
    """Return bounded facts for sensitive cookies lacking ``secure=True``.

    Only statically known sensitive cookie names are emitted.  A literal name
    known to be non-sensitive is intentionally suppressed.  If a name or the
    response type is dynamic, the scanner ignores the call rather than making
    an unsupported security claim.
    """

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe614ScanLimits
    ):
        raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.SOURCE_LIMIT)

    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases = _collect_imports(tree)
    assignments = _collect_assignments(tree)
    raw: list[
        tuple[SourceRange, SourceRange, PythonCwe614Operation, str]
    ] = []
    nodes = _bounded_nodes(tree, limits.max_resolution_depth * 10_000)
    for node in nodes:
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "set_cookie":
            continue
        operation = _response_operation(
            node.func.value,
            aliases,
            assignments,
            limits.max_resolution_depth,
            _position(node),
        )
        if operation is None:
            continue
        cookie_node = _cookie_name_node(node)
        if cookie_node is None:
            continue
        cookie_name = _resolve_string(
            cookie_node,
            assignments,
            limits.max_resolution_depth,
            _position(node),
        )
        if cookie_name is None or not _is_sensitive_cookie(cookie_name):
            continue
        if _secure_true(
            node,
            assignments,
            limits.max_resolution_depth,
            _position(node),
        ):
            continue
        source_range = _node_range(cookie_node, source, line_starts)
        sink_range = _node_range(node, source, line_starts)
        if not sink_range.contains(source_range):
            raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.INTEGRITY_FAILURE)
        raw.append((source_range, sink_range, operation, cookie_name))
        if len(raw) > limits.max_signals:
            raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.SIGNAL_LIMIT)

    unique = sorted(
        set(raw),
        key=lambda item: (
            item[1].start_byte,
            item[1].end_byte,
            item[0].start_byte,
            item[0].end_byte,
            item[2].value,
            item[3],
        ),
    )
    if len(unique) > limits.max_signals:
        raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe614Signal(
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
        for source_range, sink_range, operation, cookie_name in unique
    )
    return PythonCwe614ScanResult(
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


def _bounded_nodes(tree: ast.AST, limit: int) -> tuple[ast.AST, ...]:
    if type(limit) is not int or limit < 1:
        raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.REQUEST_INVALID)
    result: list[ast.AST] = []
    stack = [tree]
    while stack:
        node = stack.pop()
        result.append(node)
        if len(result) > limit:
            raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.SIGNAL_LIMIT)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(result)


def _collect_imports(tree: ast.AST) -> dict[str, str | None]:
    aliases: dict[str, str | None] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                root = imported.name.split(".", 1)[0]
                aliases[imported.asname or root] = root if root in _IMPORT_ROOTS else None
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for imported in node.names:
                if imported.name == "*":
                    continue
                name = imported.asname or imported.name
                canonical = f"{module}.{imported.name}"
                aliases[name] = (
                    canonical
                    if canonical in _RESPONSE_IMPORTS or canonical in _MAKE_RESPONSE_IMPORTS
                    else None
                )
    return aliases


def _collect_assignments(tree: ast.AST) -> dict[str, tuple[tuple[int, int, ast.expr], ...]]:
    values: dict[str, list[tuple[int, int, ast.expr]]] = {}
    for node in ast.walk(tree):
        targets: tuple[ast.expr, ...]
        value: ast.expr | None
        if isinstance(node, ast.Assign):
            targets = tuple(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = (node.target,)
            value = node.value
        elif isinstance(node, ast.NamedExpr):
            targets = (node.target,)
            value = node.value
        else:
            continue
        if value is None:
            continue
        position = _position(node)
        for target in targets:
            if isinstance(target, ast.Name):
                values.setdefault(target.id, []).append((position[0], position[1], value))
    return {name: tuple(sorted(items)) for name, items in values.items()}


def _response_operation(
    receiver: ast.expr,
    aliases: dict[str, str | None],
    assignments: dict[str, tuple[tuple[int, int, ast.expr], ...]],
    max_depth: int,
    position: tuple[int, int],
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> PythonCwe614Operation | None:
    if depth > max_depth:
        raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.SIGNAL_LIMIT)
    canonical = _canonical_reference(
        receiver, aliases, assignments, max_depth, position, depth
    )
    if canonical is not None:
        operation = _operation_for_reference(canonical)
        if operation is not None:
            return operation
    if isinstance(receiver, ast.Name):
        if receiver.id in _RESPONSE_ROOTS:
            assignment = _latest_assignment(assignments, receiver.id, position)
            if assignment is None:
                return PythonCwe614Operation.RESPONSE_SET_COOKIE
            return None
        if receiver.id in seen:
            return None
        assignment = _latest_assignment(assignments, receiver.id, position)
        if assignment is not None:
            return _response_operation(
                assignment,
                aliases,
                assignments,
                max_depth,
                position,
                depth + 1,
                seen | {receiver.id},
            )
    return None


def _operation_for_reference(reference: str) -> PythonCwe614Operation | None:
    operation = _RESPONSE_CLASSES.get(reference)
    if operation is None:
        return None
    return operation


def _canonical_reference(
    node: ast.expr,
    aliases: dict[str, str | None],
    assignments: dict[str, tuple[tuple[int, int, ast.expr], ...]],
    max_depth: int,
    position: tuple[int, int],
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        imported = aliases.get(node.id)
        if imported is not None:
            return imported
        assignment = _latest_assignment(assignments, node.id, position)
        if assignment is not None:
            return _canonical_reference(
                assignment,
                aliases,
                assignments,
                max_depth,
                position,
                depth + 1,
            )
        return None
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(
            node.value,
            aliases,
            assignments,
            max_depth,
            position,
            depth + 1,
        )
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Call):
        return _canonical_reference(
            node.func,
            aliases,
            assignments,
            max_depth,
            position,
            depth + 1,
        )
    return None


def _latest_assignment(
    assignments: dict[str, tuple[tuple[int, int, ast.expr], ...]],
    name: str,
    position: tuple[int, int],
) -> ast.expr | None:
    candidates = [item for item in assignments.get(name, ()) if item[:2] < position]
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item[0], item[1]))[2]


def _cookie_name_node(call: ast.Call) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg in {"key", "name", "cookie", "cookie_name"}:
            return keyword.value
    return call.args[0] if call.args else None


def _resolve_string(
    node: ast.expr,
    assignments: dict[str, tuple[tuple[int, int, ast.expr], ...]],
    max_depth: int,
    position: tuple[int, int],
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> str | None:
    if depth > max_depth:
        raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Constant) and type(node.value) is str:
        return node.value if 0 < len(node.value) <= 256 else None
    if isinstance(node, ast.Name):
        if node.id in seen:
            return None
        assignment = _latest_assignment(assignments, node.id, position)
        if assignment is None:
            return None
        return _resolve_string(
            assignment,
            assignments,
            max_depth,
            position,
            depth + 1,
            seen | {node.id},
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_string(node.left, assignments, max_depth, position, depth + 1, seen)
        right = _resolve_string(node.right, assignments, max_depth, position, depth + 1, seen)
        if left is not None and right is not None and len(left) + len(right) <= 256:
            return left + right
    return None


def _secure_true(
    call: ast.Call,
    assignments: dict[str, tuple[tuple[int, int, ast.expr], ...]],
    max_depth: int,
    position: tuple[int, int],
) -> bool:
    secure: ast.expr | None = None
    for keyword in call.keywords:
        if keyword.arg == "secure":
            secure = keyword.value
            break
    if secure is None and len(call.args) > 6:
        secure = call.args[6]
    return _resolve_bool(secure, assignments, max_depth, position)


def _resolve_bool(
    node: ast.expr | None,
    assignments: dict[str, tuple[tuple[int, int, ast.expr], ...]],
    max_depth: int,
    position: tuple[int, int],
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> bool:
    if node is None:
        return False
    if depth > max_depth:
        raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Constant):
        return node.value is True
    if isinstance(node, ast.Name):
        if node.id in seen:
            return False
        assignment = _latest_assignment(assignments, node.id, position)
        if assignment is None:
            return False
        return _resolve_bool(
            assignment,
            assignments,
            max_depth,
            position,
            depth + 1,
            seen | {node.id},
        )
    return False


def _is_sensitive_cookie(name: str) -> bool:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    normalized = re.sub(r"[^a-z0-9]+", "_", normalized).strip("_")
    if normalized in _SENSITIVE_NAME:
        return True
    tokens = frozenset(normalized.split("_"))
    return bool(tokens & {"session", "sessid", "sid", "auth", "token", "jwt"})


def _position(node: ast.AST) -> tuple[int, int]:
    return (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))


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
        raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe614ScanError(PythonCwe614ScanErrorCode.INTEGRITY_FAILURE)
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
    operation: PythonCwe614Operation,
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[PythonCwe614Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


# Compatibility aliases keep this adapter usable beside the existing CWE
# scanners while retaining the Python-specific implementation names.
Cwe614ScanErrorCode = PythonCwe614ScanErrorCode
Cwe614ScanError = PythonCwe614ScanError
Cwe614ScanLimits = PythonCwe614ScanLimits
Cwe614ScanResult = PythonCwe614ScanResult
Cwe614Signal = PythonCwe614Signal


__all__ = [
    "DEFAULT_PYTHON_CWE614_SCAN_LIMITS",
    "Cwe614ScanError",
    "Cwe614ScanErrorCode",
    "Cwe614ScanLimits",
    "Cwe614ScanResult",
    "Cwe614Signal",
    "PythonCwe614Operation",
    "PythonCwe614ScanError",
    "PythonCwe614ScanErrorCode",
    "PythonCwe614ScanLimits",
    "PythonCwe614ScanResult",
    "PythonCwe614Signal",
    "scan_python_cwe614",
]
