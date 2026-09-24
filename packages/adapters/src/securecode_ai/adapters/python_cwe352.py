"""Bounded, source-free Python CWE-352 endpoint detection.

The adapter intentionally recognises a small set of concrete web endpoint
patterns.  A CSRF protection call or decorator is scoped to the function that
contains it; protection in another function in the same module never hides an
unsafe endpoint.  Unresolved middleware and wrapper abstractions are ignored.

Only a sealed :class:`PythonAstAnalysis` and its matching ``SymbolIndex`` are
accepted.  Source bytes are used transiently for ranges and are never stored
in a result or error.
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

_MAX_LIMIT_VALUES = (2_000_000, 10_000, 512)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-python-cwe352"
_DETECTOR = "securecode-python-cwe352@1.0"
_DETAIL = "mutating_endpoint_without_local_csrf_protection"
_FRAMEWORKS = frozenset({"django", "flask", "flask_wtf", "fastapi", "starlette"})
_FRAMEWORK_OUTPUT = {
    "flask_wtf": "flask",
}
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_UNSAFE_METHODS_LOWER = frozenset(item.lower() for item in _UNSAFE_METHODS)
_ROUTE_DECORATORS = frozenset(
    {
        "api_route",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "route",
        "websocket_route",
        "api_view",
    }
)
_REQUIRED_METHOD_DECORATORS = frozenset(
    {
        "require_http_method",
        "require_http_methods",
        "require_post",
        "require_put",
        "require_patch",
        "require_delete",
    }
)
_PROTECTION_NAMES = frozenset(
    {
        "csrfprotect",
        "csrfprotectview",
        "validatecsrf",
        "verifycsrf",
        "checkcsrf",
        "csrftokenrequired",
        "requirecsrf",
        "csrfmiddlewaretoken",
        "csrfmiddleware",
        "csrfguard",
        "csrfcheck",
    }
)
_NON_PROTECTION_NAMES = frozenset(
    {
        "csrfexempt",
        "csrftoken",
        "ensurecsrftoken",
        "ensurecsrfcookie",
        "getcsrftoken",
        "requesttoken",
    }
)
_DEPENDENCY_FACTORIES = frozenset({"depends", "security"})


class PythonCwe352ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-352 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe352ScanError(RuntimeError):
    """Fixed scanner failure which never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe352ScanErrorCode) -> None:
        if type(code) is not PythonCwe352ScanErrorCode:
            raise TypeError("Python CWE-352 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-352 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe352Operation(StrEnum):
    """Recognised mutating endpoint without local CSRF evidence."""

    MUTATING_ENDPOINT_WITHOUT_CSRF = "mutating_endpoint_without_csrf"
    UNSAFE_ENDPOINT_WITHOUT_CSRF = "mutating_endpoint_without_csrf"
    CSRF_MISSING = "mutating_endpoint_without_csrf"


@dataclass(frozen=True, slots=True)
class PythonCwe352ScanLimits:
    """Hard ceilings for source, output, and AST traversal."""

    max_source_bytes: int = _MAX_LIMIT_VALUES[0]
    max_signals: int = _MAX_LIMIT_VALUES[1]
    max_resolution_depth: int = _MAX_LIMIT_VALUES[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("Python CWE-352 scan limits are invalid")


DEFAULT_PYTHON_CWE352_SCAN_LIMITS = PythonCwe352ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe352Signal:
    """One immutable endpoint fact without source text."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    endpoint: SourceRange
    framework: str
    operation: PythonCwe352Operation = PythonCwe352Operation.MUTATING_ENDPOINT_WITHOUT_CSRF
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-352"
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
            and _SHA256.fullmatch(self.content_sha256) is not None
            and type(self.source_size_bytes) is int
            and self.source_size_bytes >= 0
        )
        if valid_identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid_identity = False
        valid_endpoint = (
            type(self.endpoint) is SourceRange
            and self.endpoint.end_byte <= self.source_size_bytes
        )
        expected_id = (
            _signal_id(
                self.repository_id,
                self.revision,
                self.path,
                self.content_sha256,
                self.source_size_bytes,
                self.endpoint,
                self.framework,
                self.operation,
            )
            if valid_identity
            and valid_endpoint
            and type(self.operation) is PythonCwe352Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_endpoint
            or type(self.operation) is not PythonCwe352Operation
            or type(self.framework) is not str
            or self.framework not in {"django", "flask", "fastapi", "starlette"}
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-352"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-352 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        return self.signal_id

    @property
    def location(self) -> SourceRange:
        return self.endpoint

    @property
    def source(self) -> SourceRange:
        return self.endpoint

    @property
    def sink(self) -> SourceRange:
        return self.endpoint

    @property
    def source_range(self) -> SourceRange:
        return self.endpoint

    @property
    def sink_range(self) -> SourceRange:
        return self.endpoint


@dataclass(frozen=True, slots=True)
class PythonCwe352ScanResult:
    """Deterministic, source-free CWE-352 output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe352Signal, ...]
    scan_sha256: str

    def __post_init__(self) -> None:
        valid_identity = (
            type(self.repository_id) is str
            and bool(self.repository_id)
            and type(self.revision) is str
            and _SHA1.fullmatch(self.revision) is not None
            and type(self.path) is str
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
            type(item) is PythonCwe352Signal for item in self.signals
        )
        order = (
            tuple(
                (item.endpoint.start_byte, item.endpoint.end_byte, item.operation.value)
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
        expected_hash = (
            _scan_sha256(
                self.repository_id,
                self.revision,
                self.path,
                self.content_sha256,
                self.source_size_bytes,
                self.signals,
            )
            if valid_signals
            else None
        )
        if (
            not valid_identity
            or not valid_signals
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
            or not same_identity
            or type(self.scan_sha256) is not str
            or _SHA256.fullmatch(self.scan_sha256) is None
            or self.scan_sha256 != expected_hash
        ):
            raise ValueError("Python CWE-352 scan result is invalid")


def scan_python_cwe352(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe352ScanLimits = DEFAULT_PYTHON_CWE352_SCAN_LIMITS,
) -> PythonCwe352ScanResult:
    """Find bounded mutating endpoints without local CSRF evidence."""

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe352ScanLimits
    ):
        raise PythonCwe352ScanError(PythonCwe352ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe352ScanError(PythonCwe352ScanErrorCode.SOURCE_LIMIT)
    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe352ScanError(PythonCwe352ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe352ScanError(PythonCwe352ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe352ScanError(PythonCwe352ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases = _collect_aliases(tree, limits.max_resolution_depth)
    framework = _framework(tree, aliases, limits.max_resolution_depth)
    if framework is None:
        signals: tuple[PythonCwe352Signal, ...] = ()
    else:
        raw: list[SourceRange] = []
        for function in _functions(tree, limits.max_resolution_depth):
            if _function_has_csrf_protection(function, aliases, limits.max_resolution_depth):
                continue
            if _is_unsafe_endpoint(
                function,
                framework,
                aliases,
                limits.max_resolution_depth,
            ):
                raw.append(_node_range(function, source, line_starts))
                if len(raw) > limits.max_signals:
                    raise PythonCwe352ScanError(PythonCwe352ScanErrorCode.SIGNAL_LIMIT)
        unique = tuple(
            sorted(set(raw), key=lambda item: (item.start_byte, item.end_byte))
        )
        signals = tuple(
            PythonCwe352Signal(
                repository_id=symbol_index.repository_id,
                revision=symbol_index.revision,
                path=symbol_index.path,
                content_sha256=symbol_index.content_sha256,
                source_size_bytes=symbol_index.source_byte_length,
                endpoint=endpoint,
                framework=framework,
            )
            for endpoint in unique
        )
    return PythonCwe352ScanResult(
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


def _framework(
    tree: ast.Module,
    aliases: dict[str, str | None],
    max_depth: int,
) -> str | None:
    candidates: set[str] = set()
    for value in aliases.values():
        if value:
            candidates.add(value.split(".", 1)[0].casefold())
    for node in _bounded_nodes(tree, max_depth):
        if isinstance(node, (ast.Name, ast.Attribute, ast.Call)):
            target = node.func if isinstance(node, ast.Call) else node
            name = _canonical_name(target, aliases, max_depth)
            if name:
                candidates.add(name.split(".", 1)[0].casefold())
    for candidate in ("django", "flask", "flask_wtf", "fastapi", "starlette"):
        if candidate in candidates:
            return _FRAMEWORK_OUTPUT.get(candidate, candidate)
    return None


def _is_unsafe_endpoint(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    framework: str,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    for decorator in function.decorator_list:
        if _route_is_unsafe(decorator, framework, aliases, max_depth):
            return True
    return framework == "django" and _django_view_uses_unsafe_request(
        function,
        max_depth,
    )


def _route_is_unsafe(
    decorator: ast.expr,
    framework: str,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    call = decorator if isinstance(decorator, ast.Call) else None
    callable_node = call.func if call is not None else decorator
    name = _canonical_name(callable_node, aliases, max_depth) or _dotted_name(callable_node)
    tail = name.rsplit(".", 1)[-1].casefold()
    if tail in _UNSAFE_METHODS_LOWER or tail in {
        item.casefold() for item in _REQUIRED_METHOD_DECORATORS
    }:
        if tail in {"require_http_method", "require_http_methods"}:
            return bool(call and call.args and _contains_unsafe_method(call.args[0]))
        return True
    if tail not in _ROUTE_DECORATORS or call is None:
        return False
    if tail == "websocket_route":
        return False
    if tail == "api_view":
        return bool(call.args and _contains_unsafe_method(call.args[0]))
    if tail in {"require_http_method", "require_http_methods"}:
        return bool(call.args and _contains_unsafe_method(call.args[0]))
    if tail in {"route", "api_route"}:
        method_nodes = [
            keyword.value
            for keyword in call.keywords
            if keyword.arg in {"methods", "method"}
        ]
        return any(_contains_unsafe_method(node) for node in method_nodes)
    return tail in _UNSAFE_METHODS_LOWER


def _function_has_csrf_protection(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    for decorator in function.decorator_list:
        if _decorator_protects(decorator, aliases, max_depth):
            return True
    for node in _function_nodes(function, max_depth):
        if isinstance(node, ast.Call):
            name = _canonical_name(node.func, aliases, max_depth) or _dotted_name(node.func)
            if _is_protection_name(name):
                return True
            if _is_dependency_with_csrf(node, aliases, max_depth):
                return True
    return False


def _decorator_protects(
    decorator: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    for node in _bounded_nodes(decorator, max_depth):
        if isinstance(node, ast.Call):
            name = _canonical_name(node.func, aliases, max_depth) or _dotted_name(node.func)
            if _is_protection_name(name):
                return True
            if _is_dependency_with_csrf(node, aliases, max_depth):
                return True
        elif isinstance(node, (ast.Name, ast.Attribute)):
            name = _canonical_name(node, aliases, max_depth) or _dotted_name(node)
            if _is_protection_name(name):
                return True
    return False


def _is_dependency_with_csrf(
    call: ast.Call,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    name = _canonical_name(call.func, aliases, max_depth) or _dotted_name(call.func)
    if name.rsplit(".", 1)[-1].casefold() not in _DEPENDENCY_FACTORIES:
        return False
    return any(
        _is_protection_reference(argument, aliases, max_depth)
        for argument in (*call.args, *(keyword.value for keyword in call.keywords))
    )


def _is_protection_reference(
    node: ast.AST,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    name = _canonical_name(node, aliases, max_depth) or _dotted_name(node)
    if _is_protection_name(name):
        return True
    return any(
        isinstance(item, ast.Name) and _is_protection_name(item.id)
        for item in _bounded_nodes(node, max_depth)
    )


def _is_protection_name(name: str) -> bool:
    compact = _compact(name)
    tail = compact.rsplit(".", 1)[-1]
    if tail in _NON_PROTECTION_NAMES or "exempt" in tail:
        return False
    return tail in _PROTECTION_NAMES or (
        "csrf" in tail and any(word in tail for word in ("protect", "validate", "verify", "check", "require", "guard"))
    )


def _django_view_uses_unsafe_request(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    max_depth: int,
) -> bool:
    request_args = (*function.args.posonlyargs, *function.args.args)
    if not request_args or request_args[0].arg not in {"request", "req"}:
        return False
    for child in _function_nodes(function, max_depth):
        if isinstance(child, ast.Attribute):
            value = child.value
            if (
                isinstance(value, ast.Name)
                and value.id in {"request", "req"}
                and child.attr in {"POST", "FILES", "data", "body"}
            ):
                return True
    return False


def _collect_aliases(tree: ast.Module, max_depth: int) -> dict[str, str | None]:
    aliases: dict[str, str | None] = {}
    for node in _bounded_nodes(tree, max_depth):
        if isinstance(node, ast.Import):
            for item in node.names:
                root = item.name.split(".", 1)[0]
                aliases[item.asname or root] = item.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for item in node.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = f"{module}.{item.name}".strip(".")
    return aliases


def _functions(
    tree: ast.Module,
    max_depth: int,
) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...]:
    return tuple(
        node
        for node in _bounded_nodes(tree, max_depth)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )


def _function_nodes(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    max_depth: int,
) -> tuple[ast.AST, ...]:
    output: list[ast.AST] = []
    stack: list[tuple[ast.AST, int]] = [
        (statement, 1) for statement in reversed(function.body)
    ]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise PythonCwe352ScanError(PythonCwe352ScanErrorCode.SIGNAL_LIMIT)
        output.append(node)
        if node is not function and isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            continue
        stack.extend((child, depth + 1) for child in reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(output)


def _bounded_nodes(tree: ast.AST, max_depth: int) -> tuple[ast.AST, ...]:
    output: list[ast.AST] = []
    stack: list[tuple[ast.AST, int]] = [(tree, 0)]
    max_nodes = max(1, max_depth * 10_000)
    while stack:
        node, depth = stack.pop()
        if depth > max_depth or len(output) >= max_nodes:
            raise PythonCwe352ScanError(PythonCwe352ScanErrorCode.SIGNAL_LIMIT)
        output.append(node)
        stack.extend((child, depth + 1) for child in reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(output)


def _canonical_name(
    node: ast.AST,
    aliases: dict[str, str | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe352ScanError(PythonCwe352ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _canonical_name(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Call):
        return _canonical_name(node.func, aliases, max_depth, depth + 1)
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


def _compact(value: str) -> str:
    return value.casefold().replace("_", "").replace("-", "")


def _contains_unsafe_method(node: ast.AST) -> bool:
    return any(
        isinstance(item, ast.Constant)
        and type(item.value) is str
        and item.value.upper() in _UNSAFE_METHODS
        for item in _bounded_nodes(node, 64)
    )


def _line_starts(source: bytes) -> tuple[int, ...]:
    return (0, *(index + 1 for index, value in enumerate(source) if value == 10))


def _node_range(node: ast.AST, source: bytes, line_starts: tuple[int, ...]) -> SourceRange:
    try:
        start_row = node.lineno - 1  # type: ignore[attr-defined]
        end_row = node.end_lineno - 1  # type: ignore[attr-defined]
        start_column = node.col_offset  # type: ignore[attr-defined]
        end_column = node.end_col_offset  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        raise PythonCwe352ScanError(PythonCwe352ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        any(type(value) is not int for value in (start_row, end_row, start_column, end_column))
        or start_row < 0
        or end_row < start_row
        or start_row >= len(line_starts)
        or end_row >= len(line_starts)
        or start_column < 0
        or end_column < 0
    ):
        raise PythonCwe352ScanError(PythonCwe352ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_row] + start_column
    end = line_starts[end_row] + end_column
    line_end = line_starts[end_row + 1] if end_row + 1 < len(line_starts) else len(source)
    if start < 0 or end < start or end > line_end or end > len(source):
        raise PythonCwe352ScanError(PythonCwe352ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start_byte=start,
        end_byte=end,
        start_point=SourcePoint(start_row, start_column),
        end_point=SourcePoint(end_row, end_column),
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
    endpoint: SourceRange,
    framework: str,
    operation: PythonCwe352Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-352",
        "detector": _DETECTOR,
        "endpoint": _range_value(endpoint),
        "framework": framework,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
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
    signals: tuple[PythonCwe352Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-352",
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
                "endpoint": _range_value(signal.endpoint),
                "framework": signal.framework,
                "operation": signal.operation.value,
                "signal_id": signal.signal_id,
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


Cwe352ScanErrorCode = PythonCwe352ScanErrorCode
Cwe352ScanError = PythonCwe352ScanError
Cwe352ScanLimits = PythonCwe352ScanLimits
Cwe352ScanResult = PythonCwe352ScanResult
Cwe352Signal = PythonCwe352Signal

scan_python_csrf = scan_python_cwe352
scan_python_cwe352_csrf = scan_python_cwe352


__all__ = [
    "DEFAULT_PYTHON_CWE352_SCAN_LIMITS",
    "Cwe352ScanError",
    "Cwe352ScanErrorCode",
    "Cwe352ScanLimits",
    "Cwe352ScanResult",
    "Cwe352Signal",
    "PythonCwe352Operation",
    "PythonCwe352ScanError",
    "PythonCwe352ScanErrorCode",
    "PythonCwe352ScanLimits",
    "PythonCwe352ScanResult",
    "PythonCwe352Signal",
    "scan_python_cwe352",
    "scan_python_cwe352_csrf",
    "scan_python_csrf",
]
