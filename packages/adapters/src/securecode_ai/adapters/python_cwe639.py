"""Bounded Python CWE-639 request-key lookup facts.

Only sealed Python AST input is accepted.  The detector reports explicit
request values flowing into repository or ORM lookups when no owner or tenant
guard precedes the lookup in its enclosing handler.  Results keep ranges and
content-addressed identity only; source text is never retained.
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
_RULE = "securecode-python-cwe639"
_DETECTOR = "securecode-python-cwe639@1.0"
_DETAIL = "user_controlled_key_lookup_without_owner_guard"
_REQUEST_ROOTS = frozenset({"request", "req", "http_request", "django_request", "flask_request"})
_REQUEST_CONTAINERS = frozenset(
    {"args", "query", "query_params", "query_string", "path_params", "view_args", "GET", "POST", "form", "values", "json", "data", "body", "headers", "cookies"}
)
_ACCESSORS = frozenset({"get", "getlist", "getone", "pop", "setdefault"})
_KEY_NAMES = frozenset(
    {"id", "key", "pk", "uuid", "slug", "user_id", "account_id", "customer_id", "tenant_id", "owner_id", "resource_id", "object_id", "record_id", "item_id", "entity_id", "invoice_id", "order_id", "document_id", "project_id"}
)
_METHODS = {
    "get": "repository_get",
    "find": "repository_find",
    "lookup": "repository_lookup",
    "findbyid": "repository_find",
    "getbyid": "repository_get",
    "lookupbyid": "repository_lookup",
    "fetchbyid": "repository_get",
    "retrieve": "repository_get",
    "getor404": "orm_get",
    "filter": "orm_filter",
    "filterby": "orm_filter",
    "first": "orm_first",
    "one": "orm_first",
    "oneornone": "orm_first",
}
_LOOKUP_CONTEXT = frozenset(
    {"db", "database", "dao", "manager", "model", "models", "objects", "query", "repository", "repo", "session", "store", "records", "users", "accounts", "customers", "orders", "invoices"}
)
_BAD_CONTEXT = frozenset({"dict", "headers", "metadata", "config", "request"})
_STRONG_GUARDS = frozenset({"tenantguard", "requiretenant", "ensuretenant", "enforcetenant"})


class PythonCwe639ScanErrorCode(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe639ScanError(RuntimeError):
    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe639ScanErrorCode) -> None:
        if type(code) is not PythonCwe639ScanErrorCode:
            raise TypeError("Python CWE-639 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-639 authorization scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe639Operation(StrEnum):
    REPOSITORY_GET = "repository_get"
    REPOSITORY_FIND = "repository_find"
    REPOSITORY_LOOKUP = "repository_lookup"
    ORM_GET = "orm_get"
    ORM_FILTER = "orm_filter"
    ORM_FIRST = "orm_first"
    USER_CONTROLLED_KEY_LOOKUP = "repository_get"
    INSECURE_OBJECT_LOOKUP = "repository_get"


@dataclass(frozen=True, slots=True)
class PythonCwe639ScanLimits:
    max_source_bytes: int = _MAX[0]
    max_signals: int = _MAX[1]
    max_resolution_depth: int = _MAX[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(type(value) is not int or value < 1 or value > cap for value, cap in zip(values, _MAX, strict=True)):
            raise ValueError("Python CWE-639 scan limits are invalid")


DEFAULT_PYTHON_CWE639_SCAN_LIMITS = PythonCwe639ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe639Signal:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe639Operation
    signal_id: str = ""
    rule_id: str = _RULE
    cwe: str = "CWE-639"
    detector: str = _DETECTOR
    detail: str = _DETAIL

    def __post_init__(self) -> None:
        identity = _valid_identity(self.repository_id, self.revision, self.path, self.content_sha256, self.source_size_bytes)
        ranges = type(self.source) is SourceRange and type(self.sink) is SourceRange and self.sink.contains(self.source) and self.source.end_byte <= self.source_size_bytes and self.sink.end_byte <= self.source_size_bytes
        expected = _signal_id(self.repository_id, self.revision, self.path, self.content_sha256, self.source_size_bytes, self.source, self.sink, self.operation) if identity and ranges and type(self.operation) is PythonCwe639Operation else None
        signal_id = self.signal_id or expected
        if not identity or not ranges or type(self.operation) is not PythonCwe639Operation or type(signal_id) is not str or _SHA256.fullmatch(signal_id) is None or signal_id != expected or self.rule_id != _RULE or self.cwe != "CWE-639" or self.detector != _DETECTOR or self.detail != _DETAIL:
            raise ValueError("Python CWE-639 signal is invalid")
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
class PythonCwe639ScanResult:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe639Signal, ...]
    scan_sha256: str

    def __post_init__(self) -> None:
        identity = _valid_identity(self.repository_id, self.revision, self.path, self.content_sha256, self.source_size_bytes)
        valid = type(self.signals) is tuple and all(type(item) is PythonCwe639Signal for item in self.signals)
        order = tuple((item.sink.start_byte, item.sink.end_byte, item.source.start_byte, item.source.end_byte, item.operation.value) for item in self.signals) if valid else ()
        same = all(item.repository_id == self.repository_id and item.revision == self.revision and item.path == self.path and item.content_sha256 == self.content_sha256 and item.source_size_bytes == self.source_size_bytes for item in self.signals) if valid else False
        if not identity or not valid or order != tuple(sorted(order)) or len(order) != len(set(order)) or len({item.signal_id for item in self.signals}) != len(self.signals) or not same or type(self.scan_sha256) is not str or _SHA256.fullmatch(self.scan_sha256) is None or self.scan_sha256 != _scan_sha256(self.repository_id, self.revision, self.path, self.content_sha256, self.source_size_bytes, self.signals):
            raise ValueError("Python CWE-639 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Fact:
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe639Operation


def scan_python_cwe639(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe639ScanLimits = DEFAULT_PYTHON_CWE639_SCAN_LIMITS,
) -> PythonCwe639ScanResult:
    """Find request-key lookups without an explicit owner or tenant guard."""
    if type(symbol_index) is not SymbolIndex or symbol_index.language != "python" or type(ast_analysis) is not PythonAstAnalysis or type(limits) is not PythonCwe639ScanLimits:
        raise PythonCwe639ScanError(PythonCwe639ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe639ScanError(PythonCwe639ScanErrorCode.SOURCE_LIMIT)
    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe639ScanError(PythonCwe639ScanErrorCode.INTEGRITY_FAILURE) from None
    if validated.status is not PythonAstStatus.PARSED or ast_analysis.status is not PythonAstStatus.PARSED or ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe639ScanError(PythonCwe639ScanErrorCode.ANALYSIS_UNAVAILABLE)
    source = symbol_index.source
    starts = _line_starts(source)
    try:
        aliases = _aliases(tree, limits.max_resolution_depth)
        raw: set[tuple[SourceRange, SourceRange, PythonCwe639Operation]] = set()
        for node in _nodes(tree, max(1, limits.max_resolution_depth * 10_000)):
            if not isinstance(node, ast.Call):
                continue
            operation = _lookup_operation(node, aliases, limits.max_resolution_depth)
            if operation is None:
                continue
            scope = _scope(node, tree)
            assignments = _assignments(scope, limits.max_resolution_depth)
            for subject in _subjects(node, operation):
                source_node = _resolve(subject, scope=scope, assignments=assignments, aliases=aliases, before=_position(node), max_depth=limits.max_resolution_depth, seen=frozenset(), depth=0)
                if source_node is None or _guarded(node, scope, assignments, aliases, source_node, source, limits.max_resolution_depth):
                    continue
                source_range = _node_range(source_node, source, starts)
                sink_range = _node_range(node, source, starts)
                if not sink_range.contains(source_range):
                    raise PythonCwe639ScanError(PythonCwe639ScanErrorCode.INTEGRITY_FAILURE)
                raw.add((source_range, sink_range, operation))
                if len(raw) > limits.max_signals:
                    raise PythonCwe639ScanError(PythonCwe639ScanErrorCode.SIGNAL_LIMIT)
    except PythonCwe639ScanError:
        raise
    except (MemoryError, RecursionError, TypeError, ValueError):
        raise PythonCwe639ScanError(PythonCwe639ScanErrorCode.INTEGRITY_FAILURE) from None
    unique = tuple(sorted(raw, key=lambda item: (item[1].start_byte, item[1].end_byte, item[0].start_byte, item[0].end_byte, item[2].value)))
    signals = tuple(PythonCwe639Signal(symbol_index.repository_id, symbol_index.revision, symbol_index.path, symbol_index.content_sha256, symbol_index.source_byte_length, source_range, sink_range, operation) for source_range, sink_range, operation in unique)
    return PythonCwe639ScanResult(symbol_index.repository_id, symbol_index.revision, symbol_index.path, symbol_index.content_sha256, symbol_index.source_byte_length, signals, _scan_sha256(symbol_index.repository_id, symbol_index.revision, symbol_index.path, symbol_index.content_sha256, symbol_index.source_byte_length, signals))


def _valid_identity(repository_id: str, revision: str, path: str, digest: str, size: int) -> bool:
    valid = type(repository_id) is str and bool(repository_id) and len(repository_id.encode("utf-8")) <= 1024 and type(revision) is str and _SHA1.fullmatch(revision) is not None and type(path) is str and type(digest) is str and _SHA256.fullmatch(digest) is not None and type(size) is int and size >= 0
    if valid:
        try:
            RepositoryFile(path, size, digest)
        except (TypeError, ValueError):
            return False
    return valid


def _aliases(tree: ast.AST, max_depth: int) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for node in _nodes(tree, max(1, max_depth * 10_000)):
        if isinstance(node, ast.Import):
            for item in node.names:
                result[item.asname or item.name.split(".", 1)[0]] = item.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for item in node.names:
                if item.name != "*":
                    result[item.asname or item.name] = f"{module}.{item.name}".strip(".")
    return result


def _nodes(tree: ast.AST, limit: int) -> tuple[ast.AST, ...]:
    if type(limit) is not int or limit < 1:
        raise PythonCwe639ScanError(PythonCwe639ScanErrorCode.REQUEST_INVALID)
    result: list[ast.AST] = []
    stack = [tree]
    while stack:
        node = stack.pop()
        result.append(node)
        if len(result) > limit:
            raise PythonCwe639ScanError(PythonCwe639ScanErrorCode.SIGNAL_LIMIT)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(result)


def _scope_nodes(scope: ast.AST, max_depth: int) -> tuple[ast.AST, ...]:
    result: list[ast.AST] = []
    stack: list[tuple[ast.AST, int]] = [(scope, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth * 10_000:
            raise PythonCwe639ScanError(PythonCwe639ScanErrorCode.SIGNAL_LIMIT)
        result.append(node)
        if node is not scope and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        stack.extend((child, depth + 1) for child in reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(result)


def _scope(node: ast.Call, tree: ast.Module) -> ast.Module | ast.FunctionDef | ast.AsyncFunctionDef:
    position = _position(node)
    found: list[tuple[int, int, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    for item in ast.walk(tree):
        if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end = (getattr(item, "end_lineno", 0), getattr(item, "end_col_offset", 0))
        if (item.lineno, item.col_offset) <= position <= end:
            found.append((end[0] - item.lineno, item.col_offset, item))
    return min(found, default=(0, 0, tree))[2]


def _assignments(scope: ast.AST, max_depth: int) -> dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]]:
    values: dict[str, list[tuple[tuple[int, int], ast.expr]]] = {}
    for node in _scope_nodes(scope, max_depth):
        if isinstance(node, ast.Assign):
            pairs = ((target, node.value) for target in node.targets)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            pairs = ((node.target, node.value),)
        else:
            continue
        for target, value in pairs:
            if isinstance(target, ast.Name):
                values.setdefault(target.id, []).append((_position(node), value))
    return {name: tuple(sorted(items)) for name, items in values.items()}


def _lookup_operation(call: ast.Call, aliases: dict[str, str | None], max_depth: int) -> PythonCwe639Operation | None:
    canonical = _reference(call.func, aliases, max_depth) or ""
    operation_name = _METHODS.get(_normalise(canonical.rsplit(".", 1)[-1]))
    if operation_name is None:
        return None
    operation = PythonCwe639Operation(operation_name)
    if not isinstance(call.func, ast.Attribute):
        return operation if operation_name in {"repository_find", "repository_get", "repository_lookup", "orm_get"} else None
    receiver_node = call.func.value
    receiver = _reference(receiver_node, aliases, max_depth) or ""
    if _lookup_receiver(receiver):
        return operation
    if isinstance(receiver_node, ast.Call) and _lookup_operation(receiver_node, aliases, max_depth) is PythonCwe639Operation.ORM_FILTER:
        return operation if operation is PythonCwe639Operation.ORM_FIRST else None
    return None


def _lookup_receiver(value: str) -> bool:
    parts = tuple(_normalise(item) for item in value.split("."))
    return bool(parts) and not (set(parts) & _BAD_CONTEXT) and (bool(set(parts) & _LOOKUP_CONTEXT) or any(part.endswith(("repo", "repository", "dao", "manager", "query", "store")) for part in parts))


def _subjects(call: ast.Call, operation: PythonCwe639Operation) -> tuple[ast.expr, ...]:
    values = [*call.args, *(keyword.value for keyword in call.keywords)]
    if operation is PythonCwe639Operation.ORM_FIRST and isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Call):
        values.append(call.func.value)
    return tuple(values)


def _resolve(node: ast.AST, *, scope: ast.AST, assignments: dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]], aliases: dict[str, str | None], before: tuple[int, int], max_depth: int, seen: frozenset[str], depth: int) -> ast.expr | None:
    if depth > max_depth:
        raise PythonCwe639ScanError(PythonCwe639ScanErrorCode.SIGNAL_LIMIT)
    direct = _request_source(node, aliases, max_depth)
    if direct is not None:
        return direct
    if isinstance(node, ast.Name):
        if _key_name(node.id) and _has_parameter(scope, node.id):
            return node
        if node.id in seen:
            return None
        previous = [item for item in assignments.get(node.id, ()) if item[0] < before]
        if previous:
            return _resolve(previous[-1][1], scope=scope, assignments=assignments, aliases=aliases, before=previous[-1][0], max_depth=max_depth, seen=seen | {node.id}, depth=depth + 1)
        return None
    children = (*node.args, *(keyword.value for keyword in node.keywords)) if isinstance(node, ast.Call) else tuple(child for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr))
    for child in children:
        result = _resolve(child, scope=scope, assignments=assignments, aliases=aliases, before=before, max_depth=max_depth, seen=seen, depth=depth + 1)
        if result is not None:
            return result
    return None


def _request_source(node: ast.AST, aliases: dict[str, str | None], max_depth: int) -> ast.expr | None:
    if isinstance(node, ast.Call):
        name = (_reference(node.func, aliases, max_depth) or "").split(".")
        if len(name) >= 3 and _request_root(name) and _normalise(name[-2]) in {_normalise(item) for item in _REQUEST_CONTAINERS} and _normalise(name[-1]) in _ACCESSORS:
            return node
        if name and _request_root(name) and name[-1].lower() in {"get_json", "json"}:
            return node
    if isinstance(node, ast.Subscript):
        name = (_reference(node.value, aliases, max_depth) or "").split(".")
        if len(name) >= 2 and _request_root(name) and _normalise(name[-1]) in {_normalise(item) for item in _REQUEST_CONTAINERS}:
            return node
    if isinstance(node, ast.Attribute):
        name = (_reference(node, aliases, max_depth) or "").split(".")
        if len(name) >= 2 and _request_root(name) and _normalise(name[-1]) in {_normalise(item) for item in _REQUEST_CONTAINERS}:
            return node
    return None


def _request_root(parts: list[str]) -> bool:
    roots = {_normalise(item) for item in _REQUEST_ROOTS}
    if parts and _normalise(parts[0]) in roots:
        return True
    return any(
        _normalise(parts[index]) in {"flask", "django", "starlette"}
        and _normalise(parts[index + 1]) == "request"
        for index in range(len(parts) - 1)
    )


def _has_parameter(scope: ast.AST, name: str) -> bool:
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    args = (*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs, scope.args.vararg, scope.args.kwarg)
    return any(arg is not None and arg.arg == name for arg in args)


def _guarded(lookup: ast.Call, scope: ast.AST, assignments: dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]], aliases: dict[str, str | None], source_node: ast.expr, source: bytes, max_depth: int) -> bool:
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(_guard_name(_reference(dec.func if isinstance(dec, ast.Call) else dec, aliases, max_depth) or "") for dec in scope.decorator_list):
        return True
    key = _expression_key(source_node, source)
    for node in _scope_nodes(scope, max_depth):
        if not isinstance(node, ast.Call) or node is lookup or _position(node) >= _position(lookup):
            continue
        name = _reference(node.func, aliases, max_depth) or ""
        if not _guard_name(name):
            continue
        tail = _normalise(name.rsplit(".", 1)[-1])
        values = (*node.args, *(keyword.value for keyword in node.keywords))
        if tail in _STRONG_GUARDS or (not values and tail in {"authorize", "requireaccess", "checkaccess"}):
            return True
        if any(_expression_key(value, source) == key for value in values):
            return True
        for value in values:
            resolved = _resolve(value, scope=scope, assignments=assignments, aliases=aliases, before=_position(node), max_depth=max_depth, seen=frozenset(), depth=0)
            if resolved is not None and _expression_key(resolved, source) == key:
                return True
    return False


def _guard_name(value: str) -> bool:
    name = _normalise(value.rsplit(".", 1)[-1])
    if not name or name in {"authenticate", "loginrequired", "loggedinrequired"}:
        return False
    return name in _STRONG_GUARDS or any(token in name for token in ("authorize", "authz", "ownership", "owner", "tenant", "permission", "access"))


def _expression_key(node: ast.AST, source: bytes) -> str:
    try:
        return "".join(ast.unparse(node).split()).lower()
    except (AttributeError, TypeError, ValueError):
        return ""


def _key_name(value: str) -> bool:
    name = _normalise(value)
    lowered = value.lower()
    return name in {_normalise(item) for item in _KEY_NAMES} or lowered.endswith(("_id", "_key", "_uuid", "_slug", "_pk"))


def _reference(node: ast.AST, aliases: dict[str, str | None], max_depth: int, depth: int = 0) -> str | None:
    if depth > max_depth:
        raise PythonCwe639ScanError(PythonCwe639ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    return None


def _normalise(value: str) -> str:
    return "".join(char.lower() for char in value if char.isalnum())


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
        start_line, end_line = node.lineno - 1, node.end_lineno - 1  # type: ignore[attr-defined]
        start_col, end_col = node.col_offset, node.end_col_offset  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        raise PythonCwe639ScanError(PythonCwe639ScanErrorCode.INTEGRITY_FAILURE) from None
    if start_line < 0 or end_line < start_line or start_line + 1 >= len(starts) or end_line + 1 >= len(starts) or any(type(value) is not int for value in (start_col, end_col)):
        raise PythonCwe639ScanError(PythonCwe639ScanErrorCode.INTEGRITY_FAILURE)
    start, end = starts[start_line] + start_col, starts[end_line] + end_col
    if start < 0 or end < start or end > len(source) or end > starts[end_line + 1]:
        raise PythonCwe639ScanError(PythonCwe639ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(start, end, SourcePoint(start_line, start_col), SourcePoint(end_line, end_col))


def _range_value(location: SourceRange) -> dict[str, int]:
    return {"end_byte": location.end_byte, "end_column": location.end_point.column, "end_row": location.end_point.row, "start_byte": location.start_byte, "start_column": location.start_point.column, "start_row": location.start_point.row}


def _signal_id(repository_id: str, revision: str, path: str, digest: str, size: int, source: SourceRange, sink: SourceRange, operation: PythonCwe639Operation) -> str:
    value = {"content_sha256": digest, "cwe": "CWE-639", "detector": _DETECTOR, "operation": operation.value, "path": path, "repository_id": repository_id, "revision": revision, "rule_id": _RULE, "sink": _range_value(sink), "source": _range_value(source), "source_size_bytes": size}
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()


def _scan_sha256(repository_id: str, revision: str, path: str, digest: str, size: int, signals: tuple[PythonCwe639Signal, ...]) -> str:
    value = {"content_sha256": digest, "cwe": "CWE-639", "detector": _DETECTOR, "path": path, "repository_id": repository_id, "revision": revision, "rule_id": _RULE, "signals": [{"detail": item.detail, "operation": item.operation.value, "signal_id": item.signal_id, "sink": _range_value(item.sink), "source": _range_value(item.source)} for item in signals], "source_size_bytes": size}
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()


Cwe639ScanErrorCode = PythonCwe639ScanErrorCode
Cwe639ScanError = PythonCwe639ScanError
Cwe639ScanLimits = PythonCwe639ScanLimits
Cwe639ScanResult = PythonCwe639ScanResult
Cwe639Signal = PythonCwe639Signal
scan_python_cwe639_authorization_bypass = scan_python_cwe639
scan_python_user_key_lookup = scan_python_cwe639
