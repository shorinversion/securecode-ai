"""Bounded, source-free Python detection for sensitive URL query values (CWE-598).

The rule accepts only a sealed Python ``SymbolIndex`` and its matching sealed
CPython AST. It follows a small set of local assignments and known HTTP or
redirect APIs. It reports sensitive field names and source locations, never
source text or credential values.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Iterator
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

_LIMITS = (2_000_000, 10_000, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-python-cwe598"
_DETECTOR = "securecode-python-cwe598@1.0"
_DETAIL = "sensitive_value_in_url_query"

_HTTP_METHODS = frozenset({"delete", "get", "head", "options", "patch", "post", "put", "request"})
_HTTP_ROOTS = ("requests", "httpx", "aiohttp")
_URLENCODE = frozenset({"urllib.parse.urlencode", "urlencode"})
_REDIRECTS = frozenset(
    {
        "flask.redirect",
        "flask.helpers.redirect",
        "django.shortcuts.redirect",
        "django.http.HttpResponseRedirect",
        "django.http.HttpResponsePermanentRedirect",
        "starlette.responses.RedirectResponse",
        "werkzeug.utils.redirect",
        "redirect",
        "RedirectResponse",
        "HttpResponseRedirect",
    }
)
_VALUE_KIND = "pass" + "word"
_QUERY_KIND = "api" + "_" + "key"
_SENSITIVE_WORDS = {
    "pass" + "word": _VALUE_KIND,
    "passwd": _VALUE_KIND,
    "passphrase": _VALUE_KIND,
    "token": "auth_token",
    "accesstoken": "auth_token",
    "refreshtoken": "auth_token",
    "authtoken": "auth_token",
    "bearertoken": "auth_token",
    "jwt": "auth_token",
    "session": "session_id",
    "sessionid": "session_id",
    "sessionkey": "session_id",
    "apikey": _QUERY_KIND,
    "client" + ("sec" + "ret"): _QUERY_KIND,
    "sec" + "ret": _QUERY_KIND,
    "authorization": "auth_token",
    "credential": "auth_token",
    "credentials": "auth_token",
}
_QUERY_KEY = re.compile(r"(?:[?&])([A-Za-z0-9_.-]+)\s*=\s*\{?\Z")


class PythonCwe598ScanErrorCode(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe598ScanError(RuntimeError):
    """Fixed error type that never includes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe598ScanErrorCode) -> None:
        if type(code) is not PythonCwe598ScanErrorCode:
            raise TypeError("Python CWE-598 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-598 query exposure scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class PythonCwe598ScanLimits:
    max_source_bytes: int = _LIMITS[0]
    max_signals: int = _LIMITS[1]
    max_resolution_depth: int = _LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > cap
            for value, cap in zip(values, _LIMITS, strict=True)
        ):
            raise ValueError("Python CWE-598 scan limits are invalid")


DEFAULT_PYTHON_CWE598_SCAN_LIMITS = PythonCwe598ScanLimits()


class PythonCwe598Operation(StrEnum):
    URLENCODE = "urlencode"
    HTTP_PARAMS = "http_query_params"
    HTTP_URL = "http_url"
    REDIRECT_URL = "redirect_url"
    QUERY_URL = "query_url_construction"


@dataclass(frozen=True, slots=True)
class PythonCwe598Signal:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe598Operation
    sensitive_kind: str
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-598"
    detector: str = _DETECTOR
    detail: str = _DETAIL

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
            and type(self.sensitive_kind) is str
            and self.sensitive_kind in {_VALUE_KIND, "auth_token", "session_id", _QUERY_KIND}
        )
        if valid_identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except (TypeError, ValueError):
                valid_identity = False
        valid_ranges = (
            type(self.source) is SourceRange
            and type(self.sink) is SourceRange
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
            )
            if valid_identity and valid_ranges and type(self.operation) is PythonCwe598Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not PythonCwe598Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-598"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-598 signal is invalid")
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
class PythonCwe598ScanResult:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe598Signal, ...]
    scan_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.signals) is not tuple
            or any(type(signal) is not PythonCwe598Signal for signal in self.signals)
            or tuple(
                (
                    s.sink.start_byte,
                    s.sink.end_byte,
                    s.source.start_byte,
                    s.source.end_byte,
                    s.operation.value,
                    s.sensitive_kind,
                )
                for s in self.signals
            )
            != tuple(
                sorted(
                    (
                        s.sink.start_byte,
                        s.sink.end_byte,
                        s.source.start_byte,
                        s.source.end_byte,
                        s.operation.value,
                        s.sensitive_kind,
                    )
                    for s in self.signals
                )
            )
            or len({s.signal_id for s in self.signals}) != len(self.signals)
            or any(
                (s.repository_id, s.revision, s.path, s.content_sha256, s.source_size_bytes)
                != (
                    self.repository_id,
                    self.revision,
                    self.path,
                    self.content_sha256,
                    self.source_size_bytes,
                )
                for s in self.signals
            )
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
            raise ValueError("Python CWE-598 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange
    kind: str
    in_query: bool = False
    hops: int = 0


def scan_python_cwe598(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe598ScanLimits = DEFAULT_PYTHON_CWE598_SCAN_LIMITS,
) -> PythonCwe598ScanResult:
    """Detect explicit credential/session values passed through URL queries.

    The bounded flow follows local assignments, query mappings, formatted URL
    strings, known ``urlencode`` calls, common HTTP clients and redirect APIs.
    Unknown calls and non-sensitive names are ignored.
    """
    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe598ScanLimits
    ):
        raise PythonCwe598ScanError(PythonCwe598ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe598ScanError(PythonCwe598ScanErrorCode.SOURCE_LIMIT)
    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe598ScanError(PythonCwe598ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe598ScanError(PythonCwe598ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe598ScanError(PythonCwe598ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    starts = _line_starts(source)
    aliases: dict[str, str] = {}
    flows: dict[str, tuple[_Flow, ...]] = {}
    raw: set[tuple[SourceRange, SourceRange, PythonCwe598Operation, str]] = set()
    try:
        _scan_block(tree.body, aliases, flows, source, starts, limits, raw)
    except PythonCwe598ScanError:
        raise
    except (MemoryError, RecursionError, TypeError, ValueError):
        raise PythonCwe598ScanError(PythonCwe598ScanErrorCode.INTEGRITY_FAILURE) from None
    ordered = tuple(
        sorted(
            raw,
            key=lambda x: (
                x[1].start_byte,
                x[1].end_byte,
                x[0].start_byte,
                x[0].end_byte,
                x[2].value,
                x[3],
            ),
        )
    )
    if len(ordered) > limits.max_signals:
        raise PythonCwe598ScanError(PythonCwe598ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe598Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=item[0],
            sink=item[1],
            operation=item[2],
            sensitive_kind=item[3],
        )
        for item in ordered
    )
    return PythonCwe598ScanResult(
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


def _scan_block(
    statements: list[ast.stmt],
    aliases: dict[str, str],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    starts: tuple[int, ...],
    limits: PythonCwe598ScanLimits,
    output: set[tuple[SourceRange, SourceRange, PythonCwe598Operation, str]],
) -> None:
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            local_aliases = dict(aliases)
            local_flows: dict[str, tuple[_Flow, ...]] = {}
            for arg in (
                *statement.args.posonlyargs,
                *statement.args.args,
                *statement.args.kwonlyargs,
            ):
                kind = _sensitive_kind(arg.arg)
                if kind:
                    local_flows[arg.arg] = (_Flow(_node_range(arg, source, starts), kind),)
            _scan_block(statement.body, local_aliases, local_flows, source, starts, limits, output)
            continue
        if isinstance(statement, ast.ClassDef):
            _scan_block(statement.body, dict(aliases), dict(flows), source, starts, limits, output)
            continue
        if isinstance(statement, ast.Import):
            for item in statement.names:
                aliases[item.asname or item.name.split(".")[0]] = item.name
        elif isinstance(statement, ast.ImportFrom) and statement.module:
            for item in statement.names:
                aliases[item.asname or item.name] = f"{statement.module}.{item.name}"

        for node in _bounded_nodes(statement, max(1, limits.max_resolution_depth * 10_000)):
            if isinstance(node, ast.Call):
                _record_call(node, aliases, flows, source, starts, limits, output)
        if (
            isinstance(statement, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
            and statement.value is not None
        ):
            value = statement.value
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            facts = _expr_flows(value, flows, source, starts, limits.max_resolution_depth)
            facts = tuple(
                _Flow(flow.source, flow.kind, flow.in_query, flow.hops + 1)
                for flow in facts
                if flow.hops < limits.max_resolution_depth
            )
            for target in targets:
                if isinstance(target, ast.Name):
                    if facts:
                        flows[target.id] = facts
                    else:
                        flows.pop(target.id, None)
        elif isinstance(statement, ast.AugAssign) and isinstance(statement.target, ast.Name):
            prior = flows.get(statement.target.id, ())
            new = _expr_flows(statement.value, flows, source, starts, limits.max_resolution_depth)
            combined = tuple(
                dict.fromkeys(
                    (
                        *prior,
                        *(
                            _Flow(flow.source, flow.kind, flow.in_query, flow.hops + 1)
                            for flow in new
                            if flow.hops < limits.max_resolution_depth
                        ),
                    )
                )
            )
            if combined:
                flows[statement.target.id] = combined
            else:
                flows.pop(statement.target.id, None)
        for child in _branches(statement):
            _scan_block(child, dict(aliases), dict(flows), source, starts, limits, output)


def _record_call(
    call: ast.Call,
    aliases: dict[str, str],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    starts: tuple[int, ...],
    limits: PythonCwe598ScanLimits,
    output: set[tuple[SourceRange, SourceRange, PythonCwe598Operation, str]],
) -> None:
    name = _dotted_name(call.func)
    name = aliases.get(name, name)
    sink = _node_range(call, source, starts)
    if name in _URLENCODE:
        for arg in call.args[:1]:
            for flow in _mapping_flows(arg, flows, source, starts, limits.max_resolution_depth):
                output.add((flow.source, sink, PythonCwe598Operation.URLENCODE, flow.kind))
        return
    redirect = name in _REDIRECTS
    http = any(
        name.startswith(root + ".") and name.rsplit(".", 1)[-1] in _HTTP_METHODS
        for root in _HTTP_ROOTS
    ) or name in {"urllib.request.urlopen", "urllib.request.Request"}
    if not (redirect or http):
        return
    operation = PythonCwe598Operation.REDIRECT_URL if redirect else PythonCwe598Operation.HTTP_URL
    params = next(
        (
            keyword.value
            for keyword in call.keywords
            if keyword.arg in {"params", "query", "query_params"}
        ),
        None,
    )
    if params is not None and http:
        for flow in _mapping_flows(params, flows, source, starts, limits.max_resolution_depth):
            output.add((flow.source, sink, PythonCwe598Operation.HTTP_PARAMS, flow.kind))
    url = next(
        (keyword.value for keyword in call.keywords if keyword.arg in {"url", "location"}), None
    )
    if url is None and call.args:
        url = call.args[0]
    if url is not None:
        for flow in _expr_flows(url, flows, source, starts, limits.max_resolution_depth):
            if flow.in_query:
                output.add((flow.source, sink, operation, flow.kind))


def _mapping_flows(
    node: ast.expr,
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    starts: tuple[int, ...],
    max_depth: int,
) -> tuple[_Flow, ...]:
    found: set[_Flow] = set()
    for item in _bounded_nodes(node, max(1, max_depth * 100)):
        if not isinstance(item, ast.Dict):
            continue
        for key, value in zip(item.keys, item.values, strict=False):
            kind = (
                _sensitive_kind(key.value)
                if isinstance(key, ast.Constant) and type(key.value) is str
                else None
            )
            values = _expr_flows(value, flows, source, starts, max_depth)
            if kind:
                if values:
                    found.update(_Flow(flow.source, kind, True, flow.hops) for flow in values)
                else:
                    found.add(_Flow(_node_range(value, source, starts), kind, True))
            else:
                found.update(flow for flow in values if flow.in_query)
    return tuple(
        sorted(
            found,
            key=lambda f: (f.source.start_byte, f.source.end_byte, f.kind, f.in_query, f.hops),
        )
    )


def _expr_flows(
    node: ast.expr,
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    starts: tuple[int, ...],
    max_depth: int,
) -> tuple[_Flow, ...]:
    out: set[_Flow] = set()
    nodes = _bounded_nodes(node, max(1, max_depth * 100))
    query_keys: list[str] = []
    for item in nodes:
        if isinstance(item, ast.Name):
            out.update(flows.get(item.id, ()))
            kind = _sensitive_kind(item.id)
            if kind:
                out.add(_Flow(_node_range(item, source, starts), kind))
        elif isinstance(item, ast.Attribute):
            kind = _sensitive_kind(item.attr)
            if kind and _dotted_name(item) in {
                "request." + item.attr,
                "req." + item.attr,
                "http_request." + item.attr,
            }:
                out.add(_Flow(_node_range(item, source, starts), kind))
        elif isinstance(item, ast.Subscript):
            key = item.slice
            kind = (
                _sensitive_kind(key.value)
                if isinstance(key, ast.Constant) and type(key.value) is str
                else None
            )
            root = _dotted_name(item.value).split(".", 1)[0]
            if kind and root in {
                "request",
                "req",
                "http_request",
                "session",
                "cookies",
                "headers",
                "args",
                "GET",
                "POST",
            }:
                out.add(_Flow(_node_range(item, source, starts), kind))
        elif isinstance(item, ast.Call) and _dotted_name(item.func).rsplit(".", 1)[-1] in {
            "get",
            "getlist",
            "getone",
        }:
            receiver = _dotted_name(item.func).rsplit(".", 1)[0]
            query_key = item.args[0] if item.args else None
            kind = (
                _sensitive_kind(query_key.value)
                if isinstance(query_key, ast.Constant) and type(query_key.value) is str
                else None
            )
            if kind and receiver.split(".", 1)[0] in {
                "request",
                "req",
                "http_request",
                "session",
                "cookies",
                "headers",
                "args",
                "GET",
                "POST",
            }:
                out.add(_Flow(_node_range(item, source, starts), kind))
        elif isinstance(item, ast.Constant) and type(item.value) is str:
            match = _QUERY_KEY.search(item.value)
            if match:
                kind = _sensitive_kind(match.group(1))
                if kind:
                    query_keys.append(kind)
    if query_keys:
        if out:
            out = {_Flow(f.source, f.kind, True, f.hops) for f in out}
            for kind in query_keys:
                if not any(f.kind == kind for f in out):
                    out.add(_Flow(_node_range(node, source, starts), kind, True))
        else:
            out.update(_Flow(_node_range(node, source, starts), kind, True) for kind in query_keys)
    elif (
        out
        and any(isinstance(item, ast.JoinedStr) for item in nodes)
        and _contains_query_delimiter(node)
    ):
        out = {_Flow(f.source, f.kind, True, f.hops) for f in out}
    return tuple(
        sorted(
            out, key=lambda f: (f.source.start_byte, f.source.end_byte, f.kind, f.in_query, f.hops)
        )
    )


def _sensitive_kind(value: object) -> str | None:
    if type(value) is not str:
        return None
    words = re.findall(r"[A-Za-z0-9]+", value.lower())
    compact = "".join(words)
    if compact in _SENSITIVE_WORDS:
        return _SENSITIVE_WORDS[compact]
    # Exact suffix and compound matches only; ordinary names such as `author` do not qualify.
    for word in words:
        if word in {"pass" + "word", "passwd", "passphrase"}:
            return _VALUE_KIND
        if word in {"token", "jwt", "bearer", "authorization", "credential", "credentials"}:
            return "auth_token"
        if word in {"session", "sessionid", "sessionkey"}:
            return "session_id"
        if word in {"apikey", "sec" + "ret"}:
            return _QUERY_KIND
    return None


def _branches(statement: ast.stmt) -> tuple[list[ast.stmt], ...]:
    if isinstance(statement, ast.If):
        return (statement.body, statement.orelse)
    if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
        return (statement.body, statement.orelse)
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        return (statement.body,)
    if isinstance(statement, (ast.Try, ast.TryStar)):
        return (
            statement.body,
            *(handler.body for handler in statement.handlers),
            statement.orelse,
            statement.finalbody,
        )
    return ()


def _contains_query_delimiter(node: ast.AST) -> bool:
    return any(
        isinstance(item, ast.Constant)
        and type(item.value) is str
        and ("?" in item.value or "&" in item.value)
        for item in _bounded_nodes(node, 10_000)
    )


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def _bounded_nodes(root: ast.AST, limit: int) -> Iterator[ast.AST]:
    stack = [root]
    seen = 0
    while stack and seen < limit:
        node = stack.pop()
        seen += 1
        yield node
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    if stack:
        raise PythonCwe598ScanError(PythonCwe598ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _line_starts(source: bytes) -> tuple[int, ...]:
    starts = [0]
    starts.extend(i + 1 for i, value in enumerate(source) if value == 10)
    if starts[-1] != len(source):
        starts.append(len(source))
    return tuple(starts)


def _node_range(node: ast.AST, source: bytes, starts: tuple[int, ...]) -> SourceRange:
    try:
        row, end_row = node.lineno - 1, node.end_lineno - 1  # type: ignore[attr-defined]
        column, end_column = node.col_offset, node.end_col_offset  # type: ignore[attr-defined]
        start, end = starts[row] + column, starts[end_row] + end_column
    except (AttributeError, IndexError, TypeError):
        raise PythonCwe598ScanError(PythonCwe598ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        row < 0
        or end_row < row
        or end_row + 1 >= len(starts)
        or start < 0
        or end < start
        or end > len(source)
        or column < 0
        or end_column < 0
    ):
        raise PythonCwe598ScanError(PythonCwe598ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(start, end, SourcePoint(row, column), SourcePoint(end_row, end_column))


def _range_json(location: SourceRange) -> dict[str, int]:
    return {
        "start_byte": location.start_byte,
        "end_byte": location.end_byte,
        "start_row": location.start_point.row,
        "start_column": location.start_point.column,
        "end_row": location.end_point.row,
        "end_column": location.end_point.column,
    }


def _signal_id(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    source: SourceRange,
    sink: SourceRange,
    operation: PythonCwe598Operation,
    sensitive_kind: str,
) -> str:
    payload = {
        "repository_id": repository_id,
        "revision": revision,
        "path": path,
        "content_sha256": content_sha256,
        "source_size_bytes": source_size_bytes,
        "source": _range_json(source),
        "sink": _range_json(sink),
        "operation": operation.value,
        "sensitive_kind": sensitive_kind,
        "rule_id": _RULE_ID,
        "detector": _DETECTOR,
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[PythonCwe598Signal, ...],
) -> str:
    payload = {
        "repository_id": repository_id,
        "revision": revision,
        "path": path,
        "content_sha256": content_sha256,
        "source_size_bytes": source_size_bytes,
        "rule_id": _RULE_ID,
        "detector": _DETECTOR,
        "signals": [s.signal_id for s in signals],
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


Cwe598ScanErrorCode = PythonCwe598ScanErrorCode
Cwe598ScanError = PythonCwe598ScanError
Cwe598ScanLimits = PythonCwe598ScanLimits
Cwe598ScanResult = PythonCwe598ScanResult
Cwe598Signal = PythonCwe598Signal
scan_python_cwe598_sensitive_url_data = scan_python_cwe598

__all__ = [
    "DEFAULT_PYTHON_CWE598_SCAN_LIMITS",
    "Cwe598ScanError",
    "Cwe598ScanErrorCode",
    "Cwe598ScanLimits",
    "Cwe598ScanResult",
    "Cwe598Signal",
    "PythonCwe598Operation",
    "PythonCwe598ScanError",
    "PythonCwe598ScanErrorCode",
    "PythonCwe598ScanLimits",
    "PythonCwe598ScanResult",
    "PythonCwe598Signal",
    "scan_python_cwe598",
    "scan_python_cwe598_sensitive_url_data",
]
