"""Bounded Python CWE-862 authorization facts for authenticated endpoints.

This detector covers a narrow case that authentication-only analysis does not:
an authenticated web handler mutates a resource selected from request state,
without a local authorization check. It intentionally ignores unrecognized
route shapes and dynamic policy frameworks. Source bytes are used transiently
and are never retained in results or errors.
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

_MAX = (2_000_000, 10_000, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE = "securecode-python-cwe862"
_DETECTOR = "securecode-python-cwe862@1.0"
_DETAIL = "authenticated_resource_mutation_without_authorization"
_ROUTES = frozenset({"delete", "patch", "post", "put", "route", "api_route"})
_AUTHENTICATION = frozenset(
    {
        "api_key_required",
        "authenticated",
        "auth_required",
        "jwt_required",
        "logged_in_required",
        "login_required",
        "requires_auth",
        "requires_authentication",
        "staff_member_required",
        "token_required",
    }
)
_AUTH_DEPENDENCIES = frozenset(
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
_AUTHZ = frozenset(
    {
        "authorize",
        "authorize_resource",
        "can_access",
        "check_access",
        "check_permission",
        "ensure_authorized",
        "has_permission",
        "is_authorized",
        "ownership_guard",
        "permission_required",
        "permissions_required",
        "require_access",
        "require_authorization",
        "require_permission",
        "require_role",
        "tenant_guard",
    }
)
_MUTATIONS = {
    "delete": "resource_delete",
    "destroy": "resource_delete",
    "grant": "authorization_mutation",
    "insert": "resource_create",
    "remove": "resource_delete",
    "revoke": "authorization_mutation",
    "save": "resource_update",
    "transfer": "resource_transfer",
    "update": "resource_update",
    "write": "resource_update",
}
_RESOURCE_WORDS = frozenset(
    {
        "account",
        "accounts",
        "database",
        "db",
        "entity",
        "entities",
        "manager",
        "model",
        "models",
        "object",
        "objects",
        "record",
        "records",
        "repo",
        "repository",
        "service",
        "store",
        "user",
        "users",
    }
)


class PythonCwe862ScanErrorCode(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe862ScanError(RuntimeError):
    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe862ScanErrorCode) -> None:
        if type(code) is not PythonCwe862ScanErrorCode:
            raise TypeError("Python CWE-862 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-862 authorization scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe862Operation(StrEnum):
    RESOURCE_CREATE = "resource_create"
    RESOURCE_DELETE = "resource_delete"
    RESOURCE_TRANSFER = "resource_transfer"
    RESOURCE_UPDATE = "resource_update"
    AUTHORIZATION_MUTATION = "authorization_mutation"


@dataclass(frozen=True, slots=True)
class PythonCwe862ScanLimits:
    max_source_bytes: int = _MAX[0]
    max_signals: int = _MAX[1]
    max_resolution_depth: int = _MAX[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > cap
            for value, cap in zip(values, _MAX, strict=True)
        ):
            raise ValueError("Python CWE-862 scan limits are invalid")


DEFAULT_PYTHON_CWE862_SCAN_LIMITS = PythonCwe862ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe862Signal:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    endpoint: SourceRange
    sink: SourceRange
    operation: PythonCwe862Operation
    signal_id: str = ""
    rule_id: str = _RULE
    cwe: str = "CWE-862"
    detector: str = _DETECTOR
    detail: str = _DETAIL

    def __post_init__(self) -> None:
        if not _valid_identity(
            self.repository_id,
            self.revision,
            self.path,
            self.content_sha256,
            self.source_size_bytes,
        ):
            raise ValueError("Python CWE-862 signal identity is invalid")
        if (
            type(self.endpoint) is not SourceRange
            or type(self.sink) is not SourceRange
            or not self.endpoint.contains(self.sink)
        ):
            raise ValueError("Python CWE-862 signal ranges are invalid")
        if (
            self.endpoint.end_byte > self.source_size_bytes
            or type(self.operation) is not PythonCwe862Operation
        ):
            raise ValueError("Python CWE-862 signal evidence is invalid")
        expected = _signal_id(
            self.repository_id,
            self.revision,
            self.path,
            self.content_sha256,
            self.source_size_bytes,
            self.endpoint,
            self.sink,
            self.operation,
        )
        value = self.signal_id or expected
        if (
            value != expected
            or self.rule_id != _RULE
            or self.cwe != "CWE-862"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-862 signal metadata is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", expected)

    @property
    def deterministic_id(self) -> str:
        return self.signal_id

    @property
    def location(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class PythonCwe862ScanResult:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe862Signal, ...]
    scan_sha256: str

    def __post_init__(self) -> None:
        if not _valid_identity(
            self.repository_id,
            self.revision,
            self.path,
            self.content_sha256,
            self.source_size_bytes,
        ):
            raise ValueError("Python CWE-862 scan identity is invalid")
        if type(self.signals) is not tuple or any(
            type(item) is not PythonCwe862Signal for item in self.signals
        ):
            raise ValueError("Python CWE-862 scan signals are invalid")
        keys = tuple(
            (
                item.sink.start_byte,
                item.sink.end_byte,
                item.endpoint.start_byte,
                item.operation.value,
            )
            for item in self.signals
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("Python CWE-862 scan signal order is invalid")
        if any(
            (
                item.repository_id,
                item.revision,
                item.path,
                item.content_sha256,
                item.source_size_bytes,
            )
            != (
                self.repository_id,
                self.revision,
                self.path,
                self.content_sha256,
                self.source_size_bytes,
            )
            for item in self.signals
        ):
            raise ValueError("Python CWE-862 scan signal identity mismatch")
        expected = _scan_sha256(
            self.repository_id,
            self.revision,
            self.path,
            self.content_sha256,
            self.source_size_bytes,
            self.signals,
        )
        if self.scan_sha256 != expected:
            raise ValueError("Python CWE-862 scan digest is invalid")


@dataclass(frozen=True, slots=True)
class _Fact:
    endpoint: ast.FunctionDef | ast.AsyncFunctionDef
    sink: ast.Call
    operation: PythonCwe862Operation


def scan_python_cwe862(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe862ScanLimits = DEFAULT_PYTHON_CWE862_SCAN_LIMITS,
) -> PythonCwe862ScanResult:
    """Find authenticated mutation handlers with no recognised local authz."""
    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe862ScanLimits
    ):
        raise PythonCwe862ScanError(PythonCwe862ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe862ScanError(PythonCwe862ScanErrorCode.SOURCE_LIMIT)
    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe862ScanError(PythonCwe862ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
        or ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256
    ):
        raise PythonCwe862ScanError(PythonCwe862ScanErrorCode.ANALYSIS_UNAVAILABLE)
    try:
        aliases = _aliases(tree, limits.max_resolution_depth)
        facts: set[tuple[SourceRange, SourceRange, PythonCwe862Operation]] = set()
        source = symbol_index.source
        starts = _line_starts(source)
        for function in _functions(tree, limits.max_resolution_depth):
            if not _is_endpoint(function, aliases, limits.max_resolution_depth):
                continue
            authn = _authenticated(function, aliases, limits.max_resolution_depth)
            if not authn:
                continue
            for call in _calls(function, limits.max_resolution_depth):
                operation = _mutation(call, aliases, limits.max_resolution_depth)
                if (
                    operation is None
                    or not _resource_selected(call, function, aliases, limits.max_resolution_depth)
                    or _authorized(function, call, aliases, limits.max_resolution_depth)
                ):
                    continue
                endpoint_range = _range(function, source, starts)
                sink_range = _range(call, source, starts)
                if not endpoint_range.contains(sink_range):
                    raise PythonCwe862ScanError(PythonCwe862ScanErrorCode.INTEGRITY_FAILURE)
                facts.add((endpoint_range, sink_range, operation))
                if len(facts) > limits.max_signals:
                    raise PythonCwe862ScanError(PythonCwe862ScanErrorCode.SIGNAL_LIMIT)
    except PythonCwe862ScanError:
        raise
    except (MemoryError, RecursionError, TypeError, ValueError):
        raise PythonCwe862ScanError(PythonCwe862ScanErrorCode.INTEGRITY_FAILURE) from None
    ordered = tuple(
        sorted(
            facts,
            key=lambda item: (
                item[1].start_byte,
                item[1].end_byte,
                item[0].start_byte,
                item[2].value,
            ),
        )
    )
    signals = tuple(
        PythonCwe862Signal(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            endpoint,
            sink,
            operation,
        )
        for endpoint, sink, operation in ordered
    )
    return PythonCwe862ScanResult(
        symbol_index.repository_id,
        symbol_index.revision,
        symbol_index.path,
        symbol_index.content_sha256,
        symbol_index.source_byte_length,
        signals,
        _scan_sha256(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            signals,
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


def _nodes(tree: ast.AST, max_depth: int) -> tuple[ast.AST, ...]:
    limit = max_depth * 10_000
    result: list[ast.AST] = []
    stack: list[tuple[ast.AST, int]] = [(tree, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limit or len(result) >= limit:
            raise PythonCwe862ScanError(PythonCwe862ScanErrorCode.SIGNAL_LIMIT)
        result.append(node)
        stack.extend((child, depth + 1) for child in reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(result)


def _functions(tree: ast.AST, max_depth: int) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...]:
    return tuple(
        node
        for node in _nodes(tree, max_depth)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )


def _aliases(tree: ast.AST, max_depth: int) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for node in _nodes(tree, max_depth):
        if isinstance(node, ast.Import):
            for item in node.names:
                result[item.asname or item.name.split(".", 1)[0]] = item.name
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                if item.name != "*":
                    result[item.asname or item.name] = f"{node.module or ''}.{item.name}".strip(".")
    return result


def _reference(node: ast.AST | None, aliases: dict[str, str | None], depth: int = 0) -> str | None:
    if depth > 32 or node is None:
        return None
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _reference(node.value, aliases, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    return None


def _is_endpoint(
    function: ast.FunctionDef | ast.AsyncFunctionDef, aliases: dict[str, str | None], max_depth: int
) -> bool:
    for decorator in function.decorator_list:
        node = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = _reference(node, aliases) or ""
        tail = _normalise(name.rsplit(".", 1)[-1])
        if tail not in _ROUTES:
            continue
        if tail != "route":
            return True
        if isinstance(decorator, ast.Call):
            methods = next(
                (item.value for item in decorator.keywords if item.arg == "methods"), None
            )
            if isinstance(methods, (ast.List, ast.Tuple, ast.Set)) and any(
                isinstance(value, ast.Constant)
                and str(value.value).lower() in {"post", "put", "patch", "delete"}
                for value in methods.elts
            ):
                return True
    return False


def _authenticated(
    function: ast.FunctionDef | ast.AsyncFunctionDef, aliases: dict[str, str | None], max_depth: int
) -> bool:
    for decorator in function.decorator_list:
        node = decorator.func if isinstance(decorator, ast.Call) else decorator
        if _normalise((_reference(node, aliases) or "").rsplit(".", 1)[-1]) in {
            _normalise(item) for item in _AUTHENTICATION
        }:
            return True
        if isinstance(decorator, ast.Call) and any(
            _dependency_auth(argument, aliases, max_depth)
            for argument in (*decorator.args, *(item.value for item in decorator.keywords))
        ):
            return True
    for argument in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs):
        if _normalise(argument.arg) in {_normalise(item) for item in _AUTH_DEPENDENCIES}:
            return True
        if argument.annotation is not None and _dependency_auth(
            argument.annotation, aliases, max_depth
        ):
            return True
    defaults = (*function.args.defaults, *function.args.kw_defaults)
    return bool(
        any(item is not None and _dependency_auth(item, aliases, max_depth) for item in defaults)
    )


def _dependency_auth(node: ast.AST, aliases: dict[str, str | None], max_depth: int) -> bool:
    dependency_names = {_normalise(item) for item in _AUTH_DEPENDENCIES}
    for candidate in _bounded_expr(node, max_depth):
        if not isinstance(candidate, ast.Call):
            continue
        name = _normalise((_reference(candidate.func, aliases) or "").rsplit(".", 1)[-1])
        if name not in {"depends", "security"}:
            continue
        if any(
            _normalise((_reference(argument, aliases) or "").rsplit(".", 1)[-1]) in dependency_names
            for argument in (
                *candidate.args,
                *(item.value for item in candidate.keywords),
            )
        ):
            return True
    return False


def _authorized(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    sink: ast.Call,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    for decorator in function.decorator_list:
        for node in _bounded_expr(decorator, max_depth):
            name = _reference(node.func if isinstance(node, ast.Call) else node, aliases) or ""
            if _normalise(name.rsplit(".", 1)[-1]) in {_normalise(item) for item in _AUTHZ}:
                return True
    mutation_names = _argument_names(sink, max_depth)
    for node in _function_nodes(function, max_depth):
        if not isinstance(node, ast.Call) or _position(node) >= _position(sink):
            continue
        if _normalise((_reference(node.func, aliases) or "").rsplit(".", 1)[-1]) not in {
            _normalise(item) for item in _AUTHZ
        }:
            continue
        arguments = (*node.args, *(item.value for item in node.keywords))
        # An authorization helper without a resource argument is not evidence
        # that this particular mutation was checked.  Treating it as a guard
        # made any earlier ``authorize()`` call suppress every later sink in
        # the handler.  Require a shared expression name with the mutation so
        # an unrelated or context-free check cannot create a false clean.
        if arguments and mutation_names & _argument_names(arguments, max_depth):
            return True
    return False


def _function_nodes(
    function: ast.FunctionDef | ast.AsyncFunctionDef, max_depth: int
) -> tuple[ast.AST, ...]:
    result: list[ast.AST] = []
    stack: list[ast.AST] = [function]
    limit = max_depth * 10_000
    while stack:
        node = stack.pop()
        result.append(node)
        if len(result) > limit:
            raise PythonCwe862ScanError(PythonCwe862ScanErrorCode.SIGNAL_LIMIT)
        if node is not function and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(result)


def _bounded_expr(node: ast.AST, max_depth: int) -> tuple[ast.AST, ...]:
    result: list[ast.AST] = []
    stack: list[tuple[ast.AST, int]] = [(node, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth * 1000 or len(result) >= max_depth * 1000:
            raise PythonCwe862ScanError(PythonCwe862ScanErrorCode.SIGNAL_LIMIT)
        result.append(current)
        stack.extend((child, depth + 1) for child in reversed(tuple(ast.iter_child_nodes(current))))
    return tuple(result)


def _calls(
    function: ast.FunctionDef | ast.AsyncFunctionDef, max_depth: int
) -> tuple[ast.Call, ...]:
    return tuple(
        node for node in _function_nodes(function, max_depth) if isinstance(node, ast.Call)
    )


def _mutation(
    call: ast.Call, aliases: dict[str, str | None], max_depth: int
) -> PythonCwe862Operation | None:
    name = _reference(call.func, aliases) or ""
    tail = _normalise(name.rsplit(".", 1)[-1])
    operation = _MUTATIONS.get(tail)
    if operation is None or not isinstance(call.func, ast.Attribute):
        return None
    receiver = _reference(call.func.value, aliases) or ""
    parts = {_normalise(item) for item in receiver.split(".")}
    if parts & _RESOURCE_WORDS or any(
        item.endswith(("repo", "repository", "dao", "manager", "service", "store"))
        for item in parts
    ):
        return PythonCwe862Operation(operation)
    return None


def _resource_selected(
    call: ast.Call,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    parameters = {
        item.arg
        for item in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs)
    }
    for node in (*call.args, *(item.value for item in call.keywords)):
        for candidate in _bounded_expr(node, max_depth):
            if isinstance(candidate, ast.Name) and (
                candidate.id in parameters
                or _normalise(candidate.id).endswith(("id", "key", "uuid"))
            ):
                return True
    return False


def _argument_names(node: ast.AST | tuple[ast.expr, ...], max_depth: int) -> set[str]:
    roots = (node,) if isinstance(node, ast.AST) else node
    names: set[str] = set()
    for root in roots:
        for candidate in _bounded_expr(root, max_depth):
            if isinstance(candidate, ast.Name):
                names.add(candidate.id)
    return names


def _position(node: ast.AST) -> tuple[int, int]:
    return getattr(node, "lineno", 0), getattr(node, "col_offset", 0)


def _normalise(value: str) -> str:
    return "".join(character.lower() for character in value if character.isalnum())


def _line_starts(source: bytes) -> tuple[int, ...]:
    starts = [0]
    starts.extend(index + 1 for index, value in enumerate(source) if value == 10)
    if starts[-1] != len(source):
        starts.append(len(source))
    return tuple(starts)


def _range(node: ast.AST, source: bytes, starts: tuple[int, ...]) -> SourceRange:
    try:
        start_row, end_row = node.lineno - 1, node.end_lineno - 1  # type: ignore[attr-defined]
        start_col, end_col = node.col_offset, node.end_col_offset  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        raise PythonCwe862ScanError(PythonCwe862ScanErrorCode.INTEGRITY_FAILURE) from None
    if start_row < 0 or end_row < start_row or end_row + 1 >= len(starts):
        raise PythonCwe862ScanError(PythonCwe862ScanErrorCode.INTEGRITY_FAILURE)
    start, end = starts[start_row] + start_col, starts[end_row] + end_col
    if start < 0 or end < start or end > len(source) or end > starts[end_row + 1]:
        raise PythonCwe862ScanError(PythonCwe862ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(start, end, SourcePoint(start_row, start_col), SourcePoint(end_row, end_col))


def _range_json(value: SourceRange) -> dict[str, int]:
    return {
        "end_byte": value.end_byte,
        "end_column": value.end_point.column,
        "end_row": value.end_point.row,
        "start_byte": value.start_byte,
        "start_column": value.start_point.column,
        "start_row": value.start_point.row,
    }


def _signal_id(
    repository_id: str,
    revision: str,
    path: str,
    digest: str,
    size: int,
    endpoint: SourceRange,
    sink: SourceRange,
    operation: PythonCwe862Operation,
) -> str:
    value = {
        "content_sha256": digest,
        "cwe": "CWE-862",
        "detector": _DETECTOR,
        "endpoint": _range_json(endpoint),
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE,
        "sink": _range_json(sink),
        "source_size_bytes": size,
    }
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    digest: str,
    size: int,
    signals: tuple[PythonCwe862Signal, ...],
) -> str:
    value = {
        "content_sha256": digest,
        "cwe": "CWE-862",
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE,
        "signals": [
            {
                "endpoint": _range_json(item.endpoint),
                "operation": item.operation.value,
                "signal_id": item.signal_id,
                "sink": _range_json(item.sink),
            }
            for item in signals
        ],
        "source_size_bytes": size,
    }
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
