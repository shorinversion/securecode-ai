"""Bounded Python facts for CWE-613 insufficient session expiration.

The scanner accepts only the sealed Python AST for the exact ``SymbolIndex``
that was admitted by the product runtime.  It recognises a deliberately small
set of explicit session lifetime settings and JWT construction calls.  Static
values with a bounded lifetime, browser-close/session-cookie semantics, and
tokens carrying an ``exp`` claim are suppressed.  Unknown or dynamic values
are ignored so the adapter cannot turn an unproven suspicion into a finding.

Only immutable source ranges and content-addressed identifiers leave this
module.  Source bytes are used transiently for parsing and range calculation;
they are never stored in a result or an exception.
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
_RULE_ID = "securecode-python-cwe613"
_DETECTOR = "securecode-python-cwe613@1.0"
_MAX_SESSION_SECONDS = 30 * 24 * 60 * 60


class PythonCwe613ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-613 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe613ScanError(RuntimeError):
    """Fixed scanner failure that never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe613ScanErrorCode) -> None:
        if type(code) is not PythonCwe613ScanErrorCode:
            raise TypeError("Python CWE-613 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-613 session-expiration scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe613Operation(StrEnum):
    """Recognised session and token lifetime failures."""

    SESSION_LIFETIME_TOO_LONG = "session_lifetime_too_long"
    SESSION_EXPIRATION_DISABLED = "session_expiration_disabled"
    TOKEN_WITHOUT_EXPIRY = "token_without_expiry"

    # Compatibility names used by generic scanner consumers.
    INFINITE_SESSION_LIFETIME = "session_expiration_disabled"
    UNBOUNDED_SESSION = "session_expiration_disabled"
    TOKEN_WITHOUT_EXPIRATION = "token_without_expiry"


@dataclass(frozen=True, slots=True)
class PythonCwe613ScanLimits:
    """Hard ceilings for source, output, AST traversal, and local aliases."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_resolution_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Python CWE-613 scan limits are invalid")


DEFAULT_PYTHON_CWE613_SCAN_LIMITS = PythonCwe613ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe613Signal:
    """One immutable, source-free insufficient-expiration fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe613Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-613"
    detector: str = _DETECTOR
    detail: str = "insufficient_session_expiration"

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
            except (TypeError, ValueError):
                identity_valid = False
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
            if identity_valid
            and ranges_valid
            and type(self.operation) is PythonCwe613Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not PythonCwe613Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-613"
            or self.detector != _DETECTOR
            or self.detail != "insufficient_session_expiration"
        ):
            raise ValueError("Python CWE-613 signal is invalid")
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
class PythonCwe613ScanResult:
    """Deterministic, source-free CWE-613 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe613Signal, ...]
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
        )
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except (TypeError, ValueError):
                identity_valid = False
        signals_valid = type(self.signals) is tuple and all(
            type(signal) is PythonCwe613Signal for signal in self.signals
        )
        order = (
            tuple(
                (
                    signal.sink.start_byte,
                    signal.sink.end_byte,
                    signal.source.start_byte,
                    signal.source.end_byte,
                    signal.operation.value,
                )
                for signal in self.signals
            )
            if signals_valid
            else ()
        )
        same_identity = (
            all(
                signal.repository_id == self.repository_id
                and signal.revision == self.revision
                and signal.path == self.path
                and signal.content_sha256 == self.content_sha256
                and signal.source_size_bytes == self.source_size_bytes
                for signal in self.signals
            )
            if signals_valid
            else False
        )
        if (
            not identity_valid
            or not signals_valid
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
            raise ValueError("Python CWE-613 scan result is invalid")


_SESSION_LIFETIME_KEYS = frozenset(
    {
        "PERMANENT_SESSION_LIFETIME",
        "SESSION_COOKIE_AGE",
        "SESSION_IDLE_TIMEOUT",
        "SESSION_LIFETIME",
        "SESSION_MAX_AGE",
        "SESSION_TIMEOUT",
        "SESSION_TTL",
        "SESSION_EXPIRY",
        "SESSION_EXPIRATION",
        "SESSION_EXPIRES",
        "JWT_ACCESS_TOKEN_EXPIRES",
        "JWT_REFRESH_TOKEN_EXPIRES",
        "ACCESS_TOKEN_EXPIRES",
        "REFRESH_TOKEN_EXPIRES",
        "ACCESS_TOKEN_TTL",
        "REFRESH_TOKEN_TTL",
    }
)
_SESSION_UNBOUNDED_KEYS = frozenset(
    {
        "PERMANENT_SESSION_LIFETIME",
        "SESSION_COOKIE_AGE",
        "SESSION_IDLE_TIMEOUT",
        "SESSION_LIFETIME",
        "SESSION_MAX_AGE",
        "SESSION_TIMEOUT",
        "SESSION_TTL",
        "SESSION_EXPIRY",
        "SESSION_EXPIRATION",
        "SESSION_EXPIRES",
        "JWT_ACCESS_TOKEN_EXPIRES",
        "JWT_REFRESH_TOKEN_EXPIRES",
        "ACCESS_TOKEN_EXPIRES",
        "REFRESH_TOKEN_EXPIRES",
        "ACCESS_TOKEN_TTL",
        "REFRESH_TOKEN_TTL",
    }
)
_BROWSER_CLOSE_KEYS = frozenset(
    {
        "SESSION_EXPIRE_AT_BROWSER_CLOSE",
        "SESSION_COOKIE_SESSION",
    }
)
_JWT_NAMES = frozenset({"jwt.encode", "jose.jwt.encode", "python_jwt.encode"})
_EXPIRY_KEYS = frozenset({"exp", "expires", "expires_at", "expiration", "expiry"})
_TIMEDELTA_NAMES = frozenset({"timedelta", "datetime.timedelta"})


def scan_python_cwe613(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe613ScanLimits = DEFAULT_PYTHON_CWE613_SCAN_LIMITS,
) -> PythonCwe613ScanResult:
    """Find explicit unbounded or excessively long session lifetimes."""

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe613ScanLimits
    ):
        raise PythonCwe613ScanError(PythonCwe613ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe613ScanError(PythonCwe613ScanErrorCode.SOURCE_LIMIT)
    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe613ScanError(PythonCwe613ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe613ScanError(PythonCwe613ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe613ScanError(PythonCwe613ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases = _collect_aliases(tree, limits.max_resolution_depth)
    assignments = _collect_assignments(tree, limits.max_resolution_depth)
    raw: set[tuple[SourceRange, SourceRange, PythonCwe613Operation]] = set()
    for node in _bounded_nodes(tree, limits.max_resolution_depth * 10_000):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is None:
                continue
            targets = tuple(node.targets) if isinstance(node, ast.Assign) else (node.target,)
            for target in targets:
                key = _target_key(target, aliases, limits.max_resolution_depth)
                if key is None:
                    continue
                operation = _lifetime_operation(
                    key,
                    value,
                    aliases,
                    assignments,
                    limits.max_resolution_depth,
                )
                if operation is not None:
                    _add_signal(raw, value, node, operation, source, line_starts, limits)
        elif isinstance(node, ast.Call):
            _scan_call(
                node,
                aliases,
                assignments,
                limits,
                source,
                line_starts,
                raw,
            )
        if len(raw) > limits.max_signals:
            raise PythonCwe613ScanError(PythonCwe613ScanErrorCode.SIGNAL_LIMIT)

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
        PythonCwe613Signal(
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
    return PythonCwe613ScanResult(
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


def _scan_call(
    call: ast.Call,
    aliases: dict[str, str | None],
    assignments: dict[str, tuple[tuple[int, int, ast.expr], ...]],
    limits: PythonCwe613ScanLimits,
    source: bytes,
    line_starts: tuple[int, ...],
    output: set[tuple[SourceRange, SourceRange, PythonCwe613Operation]],
) -> None:
    canonical = _canonical_reference(call.func, aliases, limits.max_resolution_depth)
    tail = (canonical or _dotted_name(call.func)).rsplit(".", 1)[-1].lower()
    if tail == "set_expiry" and call.args:
        expiry = _resolve_expr(
            call.args[0], assignments, _position(call), limits.max_resolution_depth
        )
        operation = _expiry_operation(expiry, None)
        if operation is not None:
            _add_signal(output, call.args[0], call, operation, source, line_starts, limits)
        return
    if tail == "update" and isinstance(call.func, ast.Attribute):
        receiver = _dotted_name(call.func.value).lower()
        if "config" not in receiver and receiver not in {"settings", "app.config"}:
            return
        for keyword in call.keywords:
            key = _normal_key(keyword.arg or "")
            if key in _SESSION_LIFETIME_KEYS | _BROWSER_CLOSE_KEYS:
                operation = _lifetime_operation(
                    key,
                    keyword.value,
                    aliases,
                    assignments,
                    limits.max_resolution_depth,
                )
                if operation is not None:
                    _add_signal(output, keyword.value, call, operation, source, line_starts, limits)
        for argument in call.args:
            if not isinstance(argument, ast.Dict):
                continue
            for key_node, value in zip(argument.keys, argument.values, strict=False):
                key = _literal_string(key_node)
                if key is None or value is None:
                    continue
                operation = _lifetime_operation(
                    _normal_key(key),
                    value,
                    aliases,
                    assignments,
                    limits.max_resolution_depth,
                )
                if operation is not None:
                    _add_signal(output, value, call, operation, source, line_starts, limits)
        return
    if canonical not in _JWT_NAMES and not (
        tail == "encode" and (canonical or "").lower().endswith("jwt.encode")
    ):
        return
    if not call.args:
        return
    payload = _resolve_expr(call.args[0], assignments, _position(call), limits.max_resolution_depth)
    if not _mapping_has_expiry(payload):
        _add_signal(
            output,
            call.args[0],
            call,
            PythonCwe613Operation.TOKEN_WITHOUT_EXPIRY,
            source,
            line_starts,
            limits,
        )


def _lifetime_operation(
    key: str,
    value: ast.expr,
    aliases: dict[str, str | None],
    assignments: dict[str, tuple[tuple[int, int, ast.expr], ...]],
    max_depth: int,
) -> PythonCwe613Operation | None:
    normalized = _normal_key(key)
    if normalized not in _SESSION_LIFETIME_KEYS | _BROWSER_CLOSE_KEYS:
        return None
    resolved = _resolve_expr(value, assignments, (10**9, 10**9), max_depth)
    if normalized in _BROWSER_CLOSE_KEYS:
        return (
            PythonCwe613Operation.SESSION_EXPIRATION_DISABLED
            if resolved is False
            else None
        )
    return _expiry_operation(resolved, aliases)


def _expiry_operation(
    value: ast.expr | None,
    aliases: dict[str, str | None] | None,
) -> PythonCwe613Operation | None:
    if value is None:
        return PythonCwe613Operation.SESSION_EXPIRATION_DISABLED
    if isinstance(value, ast.Constant):
        literal = value.value
        if literal is None or literal is False:
            return PythonCwe613Operation.SESSION_EXPIRATION_DISABLED
        if type(literal) in {int, float}:
            if literal < 0:
                return PythonCwe613Operation.SESSION_EXPIRATION_DISABLED
            if literal > _MAX_SESSION_SECONDS:
                return PythonCwe613Operation.SESSION_LIFETIME_TOO_LONG
            return None
    duration = _duration_seconds(value, aliases or {})
    if duration is None:
        return None
    if duration < 0:
        return PythonCwe613Operation.SESSION_EXPIRATION_DISABLED
    if duration > _MAX_SESSION_SECONDS:
        return PythonCwe613Operation.SESSION_LIFETIME_TOO_LONG
    return None


def _duration_seconds(node: ast.expr, aliases: dict[str, str | None]) -> float | None:
    if isinstance(node, ast.Call):
        name = _dotted_name(node.func)
        if name not in _TIMEDELTA_NAMES and name.rsplit(".", 1)[-1] != "timedelta":
            return None
        values = {"weeks": 0.0, "days": 0.0, "hours": 0.0, "minutes": 0.0, "seconds": 0.0}
        if node.args:
            first = _number(node.args[0])
            if first is None:
                return None
            values["days"] = first
        for keyword in node.keywords:
            if keyword.arg not in values:
                return None
            number = _number(keyword.value)
            if number is None:
                return None
            values[keyword.arg] = number
        return (
            values["weeks"] * 604800
            + values["days"] * 86400
            + values["hours"] * 3600
            + values["minutes"] * 60
            + values["seconds"]
        )
    if isinstance(node, ast.Attribute) and _dotted_name(node).endswith("timedelta.max"):
        return float("inf")
    if isinstance(node, ast.Name) and aliases.get(node.id, "").endswith("timedelta.max"):
        return float("inf")
    return None


def _mapping_has_expiry(node: ast.expr | None) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    for key in node.keys:
        literal = _literal_string(key)
        if literal is not None and literal.lower() in _EXPIRY_KEYS:
            return True
    return False


def _collect_aliases(tree: ast.AST, max_depth: int) -> dict[str, str | None]:
    aliases: dict[str, str | None] = {}
    for node in _bounded_nodes(tree, max_depth * 10_000):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".", 1)[0]] = item.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for item in node.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = f"{module}.{item.name}".strip(".")
    return aliases


def _collect_assignments(
    tree: ast.AST,
    max_depth: int,
) -> dict[str, tuple[tuple[int, int, ast.expr], ...]]:
    values: dict[str, list[tuple[int, int, ast.expr]]] = {}
    for node in _bounded_nodes(tree, max_depth * 10_000):
        if isinstance(node, ast.Assign):
            pairs = ((target, node.value) for target in node.targets)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            pairs = ((node.target, node.value),)
        else:
            continue
        for target, value in pairs:
            if isinstance(target, ast.Name):
                values.setdefault(target.id, []).append((*_position(node), value))
    return {key: tuple(sorted(items)) for key, items in values.items()}


def _resolve_expr(
    node: ast.expr,
    assignments: dict[str, tuple[tuple[int, int, ast.expr], ...]],
    position: tuple[int, int],
    max_depth: int,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> ast.expr:
    if depth > max_depth:
        raise PythonCwe613ScanError(PythonCwe613ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name) and node.id not in seen:
        previous = [item for item in assignments.get(node.id, ()) if item[:2] <= position]
        if previous:
            return _resolve_expr(
                previous[-1][2],
                assignments,
                position,
                max_depth,
                depth + 1,
                seen | {node.id},
            )
    return node


def _target_key(
    target: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
) -> str | None:
    if isinstance(target, ast.Subscript):
        key = _literal_string(target.slice)
        if key is None:
            return None
        base = _canonical_reference(target.value, aliases, max_depth) or _dotted_name(target.value)
        return _normal_key(key) if "config" in base.lower() or "settings" in base.lower() else None
    if isinstance(target, ast.Attribute):
        dotted = _dotted_name(target)
        tail = dotted.rsplit(".", 1)[-1]
        return _normal_key(tail)
    if isinstance(target, ast.Name):
        return _normal_key(target.id)
    return None


def _add_signal(
    output: set[tuple[SourceRange, SourceRange, PythonCwe613Operation]],
    source_node: ast.AST,
    sink_node: ast.AST,
    operation: PythonCwe613Operation,
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe613ScanLimits,
) -> None:
    source_range = _node_range(source_node, source, line_starts)
    sink_range = _node_range(sink_node, source, line_starts)
    if not sink_range.contains(source_range):
        raise PythonCwe613ScanError(PythonCwe613ScanErrorCode.INTEGRITY_FAILURE)
    output.add((source_range, sink_range, operation))
    if len(output) > limits.max_signals:
        raise PythonCwe613ScanError(PythonCwe613ScanErrorCode.SIGNAL_LIMIT)


def _bounded_nodes(tree: ast.AST, limit: int) -> tuple[ast.AST, ...]:
    if type(limit) is not int or limit < 1:
        raise PythonCwe613ScanError(PythonCwe613ScanErrorCode.REQUEST_INVALID)
    result: list[ast.AST] = []
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        result.append(node)
        if len(result) > limit:
            raise PythonCwe613ScanError(PythonCwe613ScanErrorCode.SIGNAL_LIMIT)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(result)


def _canonical_reference(
    node: ast.AST,
    aliases: dict[str, str | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe613ScanError(PythonCwe613ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Subscript):
        return _canonical_reference(node.value, aliases, max_depth, depth + 1)
    return None


def _normal_key(value: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", value.upper()).strip("_")


def _number(node: ast.expr) -> float | None:
    if isinstance(node, ast.Constant) and type(node.value) in {int, float}:
        return float(node.value)
    return None


def _literal_string(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None


def _dotted_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _position(node: ast.AST) -> tuple[int, int]:
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
        raise PythonCwe613ScanError(PythonCwe613ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe613ScanError(PythonCwe613ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe613ScanError(PythonCwe613ScanErrorCode.INTEGRITY_FAILURE)
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
    operation: PythonCwe613Operation,
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
    signals: tuple[PythonCwe613Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-613",
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "detail": signal.detail,
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


Cwe613ScanErrorCode = PythonCwe613ScanErrorCode
Cwe613ScanError = PythonCwe613ScanError
Cwe613ScanLimits = PythonCwe613ScanLimits
Cwe613ScanResult = PythonCwe613ScanResult
Cwe613Signal = PythonCwe613Signal


__all__ = [
    "DEFAULT_PYTHON_CWE613_SCAN_LIMITS",
    "Cwe613ScanError",
    "Cwe613ScanErrorCode",
    "Cwe613ScanLimits",
    "Cwe613ScanResult",
    "Cwe613Signal",
    "PythonCwe613Operation",
    "PythonCwe613ScanError",
    "PythonCwe613ScanErrorCode",
    "PythonCwe613ScanLimits",
    "PythonCwe613ScanResult",
    "PythonCwe613Signal",
    "scan_python_cwe613",
]
