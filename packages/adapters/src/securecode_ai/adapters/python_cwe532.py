"""Bounded Python CWE-532 facts for sensitive values reaching log sinks.

The adapter recognises a small, explicit logging surface and follows local
assignments from credential, token, and key-like values into those sinks.  It
keeps only content-addressed identity, exact source ranges, and a stable
operation code.  Unknown logger objects, dynamic reflection, and ambiguous
branch assignments are suppressed instead of being promoted to findings.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Iterable
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
_RULE_ID = "securecode-python-cwe532"
_DETECTOR = "securecode-python-cwe532@1.0"
_DETAIL = "sensitive_value_to_log_sink"


class PythonCwe532ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-532 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe532ScanError(RuntimeError):
    """Fixed scanner failure which never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe532ScanErrorCode) -> None:
        if type(code) is not PythonCwe532ScanErrorCode:
            raise TypeError("Python CWE-532 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-532 logging scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe532Operation(StrEnum):
    """Recognised logging operations accepting a message or fields."""

    LOGGING_LOG = "logging.log"
    LOGGING_DEBUG = "logging.debug"
    LOGGING_INFO = "logging.info"
    LOGGING_WARNING = "logging.warning"
    LOGGING_WARN = "logging.warn"
    LOGGING_ERROR = "logging.error"
    LOGGING_EXCEPTION = "logging.exception"
    LOGGING_CRITICAL = "logging.critical"
    LOGGER_LOG = "logging.Logger.log"
    LOGGER_DEBUG = "logging.Logger.debug"
    LOGGER_INFO = "logging.Logger.info"
    LOGGER_WARNING = "logging.Logger.warning"
    LOGGER_WARN = "logging.Logger.warn"
    LOGGER_ERROR = "logging.Logger.error"
    LOGGER_EXCEPTION = "logging.Logger.exception"
    LOGGER_CRITICAL = "logging.Logger.critical"
    ADAPTER_LOG = "logging.LoggerAdapter.log"
    ADAPTER_DEBUG = "logging.LoggerAdapter.debug"
    ADAPTER_INFO = "logging.LoggerAdapter.info"
    ADAPTER_WARNING = "logging.LoggerAdapter.warning"
    ADAPTER_WARN = "logging.LoggerAdapter.warn"
    ADAPTER_ERROR = "logging.LoggerAdapter.error"
    ADAPTER_EXCEPTION = "logging.LoggerAdapter.exception"
    ADAPTER_CRITICAL = "logging.LoggerAdapter.critical"
    LOGURU_LOG = "loguru.logger.log"
    LOGURU_DEBUG = "loguru.logger.debug"
    LOGURU_INFO = "loguru.logger.info"
    LOGURU_WARNING = "loguru.logger.warning"
    LOGURU_ERROR = "loguru.logger.error"
    LOGURU_EXCEPTION = "loguru.logger.exception"
    LOGURU_CRITICAL = "loguru.logger.critical"
    STRUCTLOG_LOG = "structlog.BoundLogger.log"
    STRUCTLOG_DEBUG = "structlog.BoundLogger.debug"
    STRUCTLOG_INFO = "structlog.BoundLogger.info"
    STRUCTLOG_WARNING = "structlog.BoundLogger.warning"
    STRUCTLOG_ERROR = "structlog.BoundLogger.error"
    STRUCTLOG_EXCEPTION = "structlog.BoundLogger.exception"
    STRUCTLOG_CRITICAL = "structlog.BoundLogger.critical"

    # Compatibility names used by generic scanner consumers.
    LOG = "logging.Logger.log"
    DEBUG = "logging.Logger.debug"
    INFO = "logging.Logger.info"
    WARNING = "logging.Logger.warning"
    ERROR = "logging.Logger.error"
    EXCEPTION = "logging.Logger.exception"
    CRITICAL = "logging.Logger.critical"


@dataclass(frozen=True, slots=True)
class PythonCwe532ScanLimits:
    """Hard ceilings for source, output, and local-flow resolution."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_resolution_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Python CWE-532 scan limits are invalid")


DEFAULT_PYTHON_CWE532_SCAN_LIMITS = PythonCwe532ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe532Signal:
    """One immutable sensitive-value-to-log fact without source text."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe532Operation
    sensitive_name: str = "sensitive_value"
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-532"
    detector: str = _DETECTOR
    detail: str = _DETAIL

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
            and type(self.sensitive_name) is str
            and 0 < len(self.sensitive_name) <= 256
        )
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
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
                self.sensitive_name,
            )
            if identity_valid and ranges_valid and type(self.operation) is PythonCwe532Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not PythonCwe532Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-532"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-532 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        return self.signal_id

    @property
    def variable_name(self) -> str:
        """Compatibility name for consumers which call the source a variable."""

        return self.sensitive_name

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
class PythonCwe532ScanResult:
    """Deterministic, source-free CWE-532 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe532Signal, ...]
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
            except ValueError:
                identity_valid = False
        valid_signals = type(self.signals) is tuple and all(
            type(item) is PythonCwe532Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    item.sink.start_byte,
                    item.sink.end_byte,
                    item.source.start_byte,
                    item.source.end_byte,
                    item.operation.value,
                    item.sensitive_name,
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
                self.signals,
            )
        ):
            raise ValueError("Python CWE-532 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _SensitiveFlow:
    source: SourceRange
    name: str


_LOG_METHODS = frozenset(
    {"log", "debug", "info", "warning", "warn", "error", "exception", "critical"}
)
_KNOWN_MODULES = frozenset({"logging", "loguru", "structlog", "os", "secrets", "hashlib"})
_LOGGER_ROOTS = frozenset(
    {"logger", "log", "logging", "audit_logger", "app_logger", "request_logger"}
)
_SENSITIVE_WORDS = frozenset(
    {
        "accesskey",
        "access_key",
        "apikey",
        "api_key",
        "auth",
        "authorization",
        "bearer",
        "client_secret",
        "credential",
        "credentials",
        "cookie",
        "encryption_key",
        "key",
        "jwt",
        "passcode",
        "passwd",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "session",
        "session_id",
        "signing_key",
        "token",
        "user_password",
    }
)
_SENSITIVE_TOKENS = frozenset(
    {
        "access",
        "apikey",
        "auth",
        "authorization",
        "bearer",
        "credential",
        "credentials",
        "jwt",
        "key",
        "passcode",
        "passwd",
        "password",
        "private",
        "refresh",
        "secret",
        "session",
        "token",
    }
)
_SAFE_WORDS = frozenset(
    {
        "digest",
        "hash",
        "hashed",
        "mask",
        "masked",
        "obfuscate",
        "redact",
        "redacted",
        "remove_secret",
        "sanitize",
        "sanitized",
        "scrub",
    }
)
_REQUEST_ROOTS = frozenset({"request", "req", "http_request", "context", "event", "scope"})
_REQUEST_ATTRIBUTES = frozenset(
    {
        "args",
        "body",
        "cookies",
        "data",
        "form",
        "GET",
        "headers",
        "json",
        "META",
        "POST",
        "query",
        "query_params",
        "values",
    }
)
_SOURCE_METHODS = frozenset({"get", "get_json", "get_data", "json", "read", "pop"})


def scan_python_cwe532(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe532ScanLimits = DEFAULT_PYTHON_CWE532_SCAN_LIMITS,
) -> PythonCwe532ScanResult:
    """Find bounded sensitive local values reaching recognised log calls."""

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe532ScanLimits
    ):
        raise PythonCwe532ScanError(PythonCwe532ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe532ScanError(PythonCwe532ScanErrorCode.SOURCE_LIMIT)
    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe532ScanError(PythonCwe532ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe532ScanError(PythonCwe532ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe532ScanError(PythonCwe532ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    try:
        aliases, logger_names, assignments = _collect_context(tree, limits)
        raw: list[tuple[SourceRange, SourceRange, PythonCwe532Operation, str]] = []
        for call in _calls(tree, limits):
            operation = _logger_operation(call, aliases, logger_names, limits.max_resolution_depth)
            if operation is None:
                continue
            for argument in _logged_values(call):
                if _is_sanitized(argument, aliases, limits.max_resolution_depth):
                    continue
                flows = _resolve_sensitive(
                    argument,
                    aliases,
                    assignments,
                    source,
                    line_starts,
                    limits,
                    _position(call),
                )
                sink = _node_range(call, source, line_starts)
                logged_source = _node_range(argument, source, line_starts)
                for flow in flows:
                    if not sink.contains(logged_source):
                        raise PythonCwe532ScanError(PythonCwe532ScanErrorCode.INTEGRITY_FAILURE)
                    raw.append((logged_source, sink, operation, flow.name))
                    if len(raw) > limits.max_signals:
                        raise PythonCwe532ScanError(PythonCwe532ScanErrorCode.SIGNAL_LIMIT)
    except PythonCwe532ScanError:
        raise
    except (MemoryError, RecursionError, TypeError, ValueError):
        raise PythonCwe532ScanError(PythonCwe532ScanErrorCode.INTEGRITY_FAILURE) from None

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
        raise PythonCwe532ScanError(PythonCwe532ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe532Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
            sensitive_name=name,
        )
        for source_range, sink_range, operation, name in unique
    )
    return PythonCwe532ScanResult(
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


def _collect_context(
    tree: ast.AST, limits: PythonCwe532ScanLimits
) -> tuple[
    dict[str, str | None], frozenset[str], dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]]
]:
    aliases: dict[str, str | None] = {}
    logger_names: set[str] = set()
    assignments: dict[str, list[tuple[tuple[int, int], ast.expr]]] = {}
    nodes = _bounded_nodes(tree, limits.max_resolution_depth * 10_000)
    for node in nodes:
        if isinstance(node, ast.Import):
            for imported in node.names:
                root = imported.name.split(".", 1)[0]
                name = imported.asname or root
                aliases[name] = imported.name if root in _KNOWN_MODULES else None
                if imported.name in {"logging", "loguru", "structlog"}:
                    logger_names.add(name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for imported in node.names:
                if imported.name == "*":
                    continue
                name = imported.asname or imported.name
                imported_name = f"{module}.{imported.name}"
                aliases[name] = (
                    imported_name
                    if module in _KNOWN_MODULES or module.startswith(tuple(_KNOWN_MODULES))
                    else None
                )
                if imported_name in {
                    "logging.getLogger",
                    "loguru.logger",
                    "structlog.get_logger",
                    "structlog.stdlib.get_logger",
                }:
                    logger_names.add(name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets: tuple[ast.expr, ...]
            value: ast.expr | None
            if isinstance(node, ast.Assign):
                targets = tuple(node.targets)
                value = node.value
            else:
                targets = (node.target,)
                value = node.value
            if value is not None:
                position = _position(node)
                for target in targets:
                    for name in _target_names(target):
                        assignments.setdefault(name, []).append((position, value))
                        canonical = _canonical_reference(
                            value, aliases, limits.max_resolution_depth
                        )
                        if _is_logger_constructor(canonical):
                            logger_names.add(name)
                        if _is_logger_name(name):
                            logger_names.add(name)
    return (
        aliases,
        frozenset(logger_names),
        {
            name: tuple(sorted(values, key=lambda item: item[0]))
            for name, values in assignments.items()
        },
    )


def _calls(tree: ast.AST, limits: PythonCwe532ScanLimits) -> tuple[ast.Call, ...]:
    return tuple(
        node
        for node in _bounded_nodes(tree, limits.max_resolution_depth * 10_000)
        if isinstance(node, ast.Call)
    )


def _bounded_nodes(tree: ast.AST, limit: int) -> tuple[ast.AST, ...]:
    if type(limit) is not int or limit < 1:
        raise PythonCwe532ScanError(PythonCwe532ScanErrorCode.REQUEST_INVALID)
    result: list[ast.AST] = []
    stack: list[tuple[ast.AST, int]] = [(tree, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            raise PythonCwe532ScanError(PythonCwe532ScanErrorCode.SIGNAL_LIMIT)
        result.append(node)
        stack.extend((child, depth + 1) for child in reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(result)


def _logger_operation(
    call: ast.Call,
    aliases: dict[str, str | None],
    logger_names: frozenset[str],
    max_depth: int,
) -> PythonCwe532Operation | None:
    if not isinstance(call.func, (ast.Attribute, ast.Name)):
        return None
    canonical = _canonical_reference(call.func, aliases, max_depth)
    if canonical is None:
        canonical = _dotted_name(call.func)
    if not canonical:
        return None
    method = canonical.rsplit(".", 1)[-1]
    if method not in _LOG_METHODS:
        return None
    direct = _DIRECT_OPERATIONS.get(canonical)
    if direct is not None:
        return direct
    if isinstance(call.func, ast.Attribute):
        receiver = call.func.value
        receiver_name = _canonical_reference(receiver, aliases, max_depth) or _dotted_name(receiver)
        if (
            receiver_name in logger_names
            or _is_logger_name(receiver_name)
            or receiver_name.endswith(".logger")
            or receiver_name.endswith("Logger")
            or "BoundLogger" in receiver_name
            or "LoggerAdapter" in receiver_name
        ):
            return _LOGGER_OPERATIONS.get(method, PythonCwe532Operation.LOGGING_INFO)
    return None


def _logged_values(call: ast.Call) -> tuple[ast.expr, ...]:
    values: list[ast.expr] = []
    for index, argument in enumerate(call.args):
        if index == 0 and _literal_string(argument) is not None:
            continue
        values.append(argument)
    values.extend(
        keyword.value
        for keyword in call.keywords
        if keyword.arg not in {"exc_info", "stack_info", "stacklevel"}
    )
    return tuple(values)


def _resolve_sensitive(
    node: ast.expr,
    aliases: dict[str, str | None],
    assignments: dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe532ScanLimits,
    position: tuple[int, int],
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> tuple[_SensitiveFlow, ...]:
    if depth > limits.max_resolution_depth:
        raise PythonCwe532ScanError(PythonCwe532ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        if node.id in seen:
            return ()
        assignment = _latest_assignment(assignments, node.id, position)
        if assignment is not None:
            value = assignment[1]
            flows = _resolve_sensitive(
                value,
                aliases,
                assignments,
                source,
                line_starts,
                limits,
                position,
                depth + 1,
                seen | {node.id},
            )
            if flows:
                return flows
            if _is_safe_constant(value):
                return ()
        if _is_sensitive_name(node.id):
            return (
                _SensitiveFlow(_node_range(node, source, line_starts), _sensitive_label(node.id)),
            )
        return ()
    if isinstance(node, ast.Attribute):
        if _is_sensitive_name(node.attr):
            return (
                _SensitiveFlow(_node_range(node, source, line_starts), _sensitive_label(node.attr)),
            )
        return _resolve_sensitive(
            node.value, aliases, assignments, source, line_starts, limits, position, depth + 1, seen
        )
    if isinstance(node, ast.Subscript):
        if _is_sensitive_subscript(node):
            return (
                _SensitiveFlow(
                    _node_range(node, source, line_starts), _sensitive_label(_subscript_label(node))
                ),
            )
        return _resolve_sensitive(
            node.value, aliases, assignments, source, line_starts, limits, position, depth + 1, seen
        )
    if isinstance(node, ast.Call):
        canonical = _canonical_reference(
            node.func, aliases, limits.max_resolution_depth
        ) or _dotted_name(node.func)
        if _is_sanitizer(canonical):
            return ()
        if _is_sensitive_call(node, canonical):
            return (
                _SensitiveFlow(_node_range(node, source, line_starts), _sensitive_label(canonical)),
            )
        return _dedupe_flows(
            flow
            for value in (*node.args, *(keyword.value for keyword in node.keywords))
            for flow in _resolve_sensitive(
                value, aliases, assignments, source, line_starts, limits, position, depth + 1, seen
            )
        )
    if isinstance(node, ast.NamedExpr):
        return _resolve_sensitive(
            node.value, aliases, assignments, source, line_starts, limits, position, depth + 1, seen
        )
    if isinstance(node, ast.Await):
        return _resolve_sensitive(
            node.value, aliases, assignments, source, line_starts, limits, position, depth + 1, seen
        )
    if isinstance(
        node, (ast.BinOp, ast.BoolOp, ast.Compare, ast.IfExp, ast.JoinedStr, ast.FormattedValue)
    ):
        return _dedupe_flows(
            flow
            for child in ast.iter_child_nodes(node)
            if isinstance(child, ast.expr)
            for flow in _resolve_sensitive(
                child, aliases, assignments, source, line_starts, limits, position, depth + 1, seen
            )
        )
    if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
        return _dedupe_flows(
            flow
            for child in ast.iter_child_nodes(node)
            if isinstance(child, ast.expr)
            for flow in _resolve_sensitive(
                child, aliases, assignments, source, line_starts, limits, position, depth + 1, seen
            )
        )
    return ()


def _latest_assignment(
    assignments: dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]],
    name: str,
    position: tuple[int, int],
) -> tuple[tuple[int, int], ast.expr] | None:
    candidates = [item for item in assignments.get(name, ()) if item[0] < position]
    return max(candidates, key=lambda item: item[0]) if candidates else None


def _dedupe_flows(flows: Iterable[_SensitiveFlow]) -> tuple[_SensitiveFlow, ...]:
    unique: dict[tuple[int, int, str], _SensitiveFlow] = {}
    for flow in flows:
        unique[(flow.source.start_byte, flow.source.end_byte, flow.name)] = flow
    return tuple(unique[key] for key in sorted(unique))


def _is_sanitized(node: ast.expr, aliases: dict[str, str | None], max_depth: int) -> bool:
    if isinstance(node, ast.Call):
        canonical = _canonical_reference(node.func, aliases, max_depth) or _dotted_name(node.func)
        return _is_sanitizer(canonical)
    return False


def _is_sanitizer(value: str | None) -> bool:
    if not value:
        return False
    normalized = value.lower().replace("-", "_")
    return any(word in normalized for word in _SAFE_WORDS)


def _is_sensitive_call(call: ast.Call, canonical: str | None) -> bool:
    if canonical and _is_sanitizer(canonical):
        return False
    if canonical and _is_sensitive_name(canonical.rsplit(".", 1)[-1]):
        return True
    if canonical in {"os.getenv", "os.environ.get", "os.environ.__getitem__"}:
        return any(
            _literal_string(arg) is not None and _is_sensitive_name(_literal_string(arg) or "")
            for arg in call.args
        )
    return False


def _is_sensitive_subscript(node: ast.Subscript) -> bool:
    label = _subscript_label(node)
    return _is_sensitive_name(label)


def _subscript_label(node: ast.Subscript) -> str:
    if isinstance(node.slice, ast.Constant) and type(node.slice.value) is str:
        return node.slice.value
    return _dotted_name(node.value)


def _is_safe_constant(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant):
        return node.value is None or isinstance(node.value, (bool, int, float, bytes, str))
    return False


def _is_logger_constructor(value: str | None) -> bool:
    return value in {
        "logging.getLogger",
        "logging.Logger",
        "structlog.get_logger",
        "structlog.stdlib.get_logger",
        "loguru.logger",
    }


def _is_logger_name(value: str | None) -> bool:
    if not value:
        return False
    tail = value.rsplit(".", 1)[-1].lower()
    return tail in _LOGGER_ROOTS or "logger" in tail or tail.startswith("log_")


def _is_sensitive_name(value: str) -> bool:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value).lower()
    normalized = re.sub(r"[^a-z0-9]+", "_", normalized).strip("_")
    if not normalized:
        return False
    if normalized in _SENSITIVE_WORDS:
        return True
    tokens = set(normalized.split("_"))
    return bool(tokens & _SENSITIVE_TOKENS) and not bool(
        tokens & {"public", "masked", "redacted", "hash", "digest"}
    )


def _sensitive_label(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9_]+", "_", value.lower()).strip("_")
    return normalized[:256] or "sensitive_value"


def _canonical_reference(
    node: ast.AST, aliases: dict[str, str | None], max_depth: int, depth: int = 0
) -> str | None:
    if depth > max_depth:
        raise PythonCwe532ScanError(PythonCwe532ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Call):
        return _canonical_reference(node.func, aliases, max_depth, depth + 1)
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


def _target_names(node: ast.AST) -> tuple[str, ...]:
    return tuple(item.id for item in ast.walk(node) if isinstance(item, ast.Name))


def _literal_string(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None


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
        raise PythonCwe532ScanError(PythonCwe532ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe532ScanError(PythonCwe532ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe532ScanError(PythonCwe532ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start, end, SourcePoint(start_line, start_column), SourcePoint(end_line, end_column)
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
    operation: PythonCwe532Operation,
    sensitive_name: str,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-532",
        "detector": _DETECTOR,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "sensitive_name": sensitive_name,
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
    signals: tuple[PythonCwe532Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-532",
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
                "detail": signal.detail,
                "operation": signal.operation.value,
                "sensitive_name": signal.sensitive_name,
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


_DIRECT_OPERATIONS: dict[str, PythonCwe532Operation] = {
    "logging.log": PythonCwe532Operation.LOGGING_LOG,
    "logging.debug": PythonCwe532Operation.LOGGING_DEBUG,
    "logging.info": PythonCwe532Operation.LOGGING_INFO,
    "logging.warning": PythonCwe532Operation.LOGGING_WARNING,
    "logging.warn": PythonCwe532Operation.LOGGING_WARN,
    "logging.error": PythonCwe532Operation.LOGGING_ERROR,
    "logging.exception": PythonCwe532Operation.LOGGING_EXCEPTION,
    "logging.critical": PythonCwe532Operation.LOGGING_CRITICAL,
    "logging.Logger.log": PythonCwe532Operation.LOGGER_LOG,
    "logging.Logger.debug": PythonCwe532Operation.LOGGER_DEBUG,
    "logging.Logger.info": PythonCwe532Operation.LOGGER_INFO,
    "logging.Logger.warning": PythonCwe532Operation.LOGGER_WARNING,
    "logging.Logger.warn": PythonCwe532Operation.LOGGER_WARN,
    "logging.Logger.error": PythonCwe532Operation.LOGGER_ERROR,
    "logging.Logger.exception": PythonCwe532Operation.LOGGER_EXCEPTION,
    "logging.Logger.critical": PythonCwe532Operation.LOGGER_CRITICAL,
    "logging.LoggerAdapter.log": PythonCwe532Operation.ADAPTER_LOG,
    "logging.LoggerAdapter.debug": PythonCwe532Operation.ADAPTER_DEBUG,
    "logging.LoggerAdapter.info": PythonCwe532Operation.ADAPTER_INFO,
    "logging.LoggerAdapter.warning": PythonCwe532Operation.ADAPTER_WARNING,
    "logging.LoggerAdapter.warn": PythonCwe532Operation.ADAPTER_WARN,
    "logging.LoggerAdapter.error": PythonCwe532Operation.ADAPTER_ERROR,
    "logging.LoggerAdapter.exception": PythonCwe532Operation.ADAPTER_EXCEPTION,
    "logging.LoggerAdapter.critical": PythonCwe532Operation.ADAPTER_CRITICAL,
    "loguru.logger.log": PythonCwe532Operation.LOGURU_LOG,
    "loguru.logger.debug": PythonCwe532Operation.LOGURU_DEBUG,
    "loguru.logger.info": PythonCwe532Operation.LOGURU_INFO,
    "loguru.logger.warning": PythonCwe532Operation.LOGURU_WARNING,
    "loguru.logger.error": PythonCwe532Operation.LOGURU_ERROR,
    "loguru.logger.exception": PythonCwe532Operation.LOGURU_EXCEPTION,
    "loguru.logger.critical": PythonCwe532Operation.LOGURU_CRITICAL,
    "structlog.BoundLogger.log": PythonCwe532Operation.STRUCTLOG_LOG,
    "structlog.BoundLogger.debug": PythonCwe532Operation.STRUCTLOG_DEBUG,
    "structlog.BoundLogger.info": PythonCwe532Operation.STRUCTLOG_INFO,
    "structlog.BoundLogger.warning": PythonCwe532Operation.STRUCTLOG_WARNING,
    "structlog.BoundLogger.error": PythonCwe532Operation.STRUCTLOG_ERROR,
    "structlog.BoundLogger.exception": PythonCwe532Operation.STRUCTLOG_EXCEPTION,
    "structlog.BoundLogger.critical": PythonCwe532Operation.STRUCTLOG_CRITICAL,
}
_LOGGER_OPERATIONS = {
    operation.value.rsplit(".", 1)[-1]: operation for operation in PythonCwe532Operation
}


Cwe532ScanErrorCode = PythonCwe532ScanErrorCode
Cwe532ScanError = PythonCwe532ScanError
Cwe532ScanLimits = PythonCwe532ScanLimits
Cwe532ScanResult = PythonCwe532ScanResult
Cwe532Signal = PythonCwe532Signal

scan_python_cwe532_logging = scan_python_cwe532
scan_python_sensitive_logging = scan_python_cwe532


__all__ = [
    "DEFAULT_PYTHON_CWE532_SCAN_LIMITS",
    "Cwe532ScanError",
    "Cwe532ScanErrorCode",
    "Cwe532ScanLimits",
    "Cwe532ScanResult",
    "Cwe532Signal",
    "PythonCwe532Operation",
    "PythonCwe532ScanError",
    "PythonCwe532ScanErrorCode",
    "PythonCwe532ScanLimits",
    "PythonCwe532ScanResult",
    "PythonCwe532Signal",
    "scan_python_cwe532",
    "scan_python_cwe532_logging",
    "scan_python_sensitive_logging",
]
