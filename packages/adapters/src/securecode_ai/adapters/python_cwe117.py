"""Bounded Python log-injection facts for CWE-117.

The scanner follows a deliberately small, sealed AST data-flow surface.  It
recognises the standard ``logging`` API and common logger aliases, tracks
request and user input through bounded local assignments, and reports only
pre-formatted or otherwise dynamic messages.  Logger calls which keep the
value as a separate formatting argument, or use a recognised structured
logger, are treated as safe projections.  Source text is never retained in a
signal or an error.
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
_RULE_ID = "securecode-python-cwe117"
_DETECTOR = "securecode-python-cwe117@1.0"
_DETAIL = "untrusted_input_to_log_message"


class PythonCwe117ScanErrorCode(StrEnum):
    """Closed reasons a log-injection scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe117ScanError(RuntimeError):
    """Fixed, non-echoing Python CWE-117 scanner failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe117ScanErrorCode) -> None:
        if type(code) is not PythonCwe117ScanErrorCode:
            raise TypeError("Python CWE-117 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-117 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe117Operation(StrEnum):
    """Recognised logging operations which accept a message."""

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

    # Short names retained for generic scanner consumers.
    LOG = "logging.Logger.log"
    DEBUG = "logging.Logger.debug"
    INFO = "logging.Logger.info"
    WARNING = "logging.Logger.warning"
    ERROR = "logging.Logger.error"
    EXCEPTION = "logging.Logger.exception"
    CRITICAL = "logging.Logger.critical"


@dataclass(frozen=True, slots=True)
class PythonCwe117ScanLimits:
    """Hard ceilings for source, output, and local-flow resolution."""

    max_source_bytes: int = _MAX_LIMIT_VALUES[0]
    max_signals: int = _MAX_LIMIT_VALUES[1]
    max_resolution_depth: int = _MAX_LIMIT_VALUES[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("Python CWE-117 scan limits are invalid")


DEFAULT_PYTHON_CWE117_SCAN_LIMITS = PythonCwe117ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe117Signal:
    """One immutable tainted-message-to-logger fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe117Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-117"
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
            if valid_identity and valid_ranges and type(self.operation) is PythonCwe117Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not PythonCwe117Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-117"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-117 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete logger call location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class PythonCwe117ScanResult:
    """Source-free, deterministic CWE-117 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe117Signal, ...]
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
            type(item) is PythonCwe117Signal for item in self.signals
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
            raise ValueError("Python CWE-117 scan result is invalid")


_DIRECT_OPERATIONS: dict[str, PythonCwe117Operation] = {
    "logging.log": PythonCwe117Operation.LOGGING_LOG,
    "logging.debug": PythonCwe117Operation.LOGGING_DEBUG,
    "logging.info": PythonCwe117Operation.LOGGING_INFO,
    "logging.warning": PythonCwe117Operation.LOGGING_WARNING,
    "logging.warn": PythonCwe117Operation.LOGGING_WARN,
    "logging.error": PythonCwe117Operation.LOGGING_ERROR,
    "logging.exception": PythonCwe117Operation.LOGGING_EXCEPTION,
    "logging.critical": PythonCwe117Operation.LOGGING_CRITICAL,
    "logging.Logger.log": PythonCwe117Operation.LOGGER_LOG,
    "logging.Logger.debug": PythonCwe117Operation.LOGGER_DEBUG,
    "logging.Logger.info": PythonCwe117Operation.LOGGER_INFO,
    "logging.Logger.warning": PythonCwe117Operation.LOGGER_WARNING,
    "logging.Logger.warn": PythonCwe117Operation.LOGGER_WARN,
    "logging.Logger.error": PythonCwe117Operation.LOGGER_ERROR,
    "logging.Logger.exception": PythonCwe117Operation.LOGGER_EXCEPTION,
    "logging.Logger.critical": PythonCwe117Operation.LOGGER_CRITICAL,
    "logging.LoggerAdapter.log": PythonCwe117Operation.ADAPTER_LOG,
    "logging.LoggerAdapter.debug": PythonCwe117Operation.ADAPTER_DEBUG,
    "logging.LoggerAdapter.info": PythonCwe117Operation.ADAPTER_INFO,
    "logging.LoggerAdapter.warning": PythonCwe117Operation.ADAPTER_WARNING,
    "logging.LoggerAdapter.warn": PythonCwe117Operation.ADAPTER_WARN,
    "logging.LoggerAdapter.error": PythonCwe117Operation.ADAPTER_ERROR,
    "logging.LoggerAdapter.exception": PythonCwe117Operation.ADAPTER_EXCEPTION,
    "logging.LoggerAdapter.critical": PythonCwe117Operation.ADAPTER_CRITICAL,
    "loguru.logger.log": PythonCwe117Operation.LOGURU_LOG,
    "loguru.logger.debug": PythonCwe117Operation.LOGURU_DEBUG,
    "loguru.logger.info": PythonCwe117Operation.LOGURU_INFO,
    "loguru.logger.warning": PythonCwe117Operation.LOGURU_WARNING,
    "loguru.logger.error": PythonCwe117Operation.LOGURU_ERROR,
    "loguru.logger.exception": PythonCwe117Operation.LOGURU_EXCEPTION,
    "loguru.logger.critical": PythonCwe117Operation.LOGURU_CRITICAL,
}
_MODULES = frozenset({"logging", "loguru", "structlog"})
_LOG_METHODS = frozenset(
    {"log", "debug", "info", "warning", "warn", "error", "exception", "critical"}
)
_SOURCE_ROOTS = frozenset(
    {
        "request",
        "req",
        "http_request",
        "flask_request",
        "django_request",
        "websocket",
        "scope",
        "event",
        "context",
    }
)
_SOURCE_ATTRIBUTES = frozenset(
    {
        "args",
        "body",
        "COOKIES",
        "cookies",
        "data",
        "FILES",
        "form",
        "GET",
        "headers",
        "json",
        "META",
        "POST",
        "path",
        "path_params",
        "query",
        "query_params",
        "query_string",
        "values",
        "url",
    }
)
_SOURCE_METHODS = frozenset(
    {"get", "getall", "getlist", "getone", "pop", "setdefault", "get_json", "get_data", "read"}
)
_PARAMETER_NAMES = frozenset(
    {
        "arg",
        "args",
        "body",
        "content",
        "cookie",
        "data",
        "form",
        "header",
        "headers",
        "identifier",
        "id",
        "input",
        "message",
        "msg",
        "name",
        "payload",
        "path",
        "params",
        "query",
        "raw",
        "request",
        "text",
        "token",
        "user",
        "username",
        "value",
    }
)
_SANITIZER_NAMES = frozenset(
    {
        "ascii",
        "escape_log",
        "escape_log_message",
        "json.dumps",
        "neutralize_crlf",
        "quote",
        "quote_from_bytes",
        "quote_plus",
        "remove_newlines",
        "repr",
        "sanitize_log",
        "sanitize_log_message",
        "strip_newlines",
    }
)
_SANITIZER_SUFFIXES = (
    "escape_log",
    "escape_log_message",
    "log_safe",
    "neutralize_crlf",
    "remove_newlines",
    "sanitize_log",
    "sanitize_log_message",
    "strip_newlines",
)
_STRUCTURED_ROOTS = frozenset({"structlog", "structlog.BoundLogger"})


def scan_python_cwe117(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe117ScanLimits = DEFAULT_PYTHON_CWE117_SCAN_LIMITS,
) -> PythonCwe117ScanResult:
    """Find bounded untrusted flows into pre-formatted logging messages.

    Standard logging calls using a literal format string and separate value
    arguments are accepted as structured logging.  Unknown reflection,
    unresolved aliases, and dynamic logger objects are ignored.  The supplied
    AST must have been sealed for the exact symbol index.
    """

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe117ScanLimits
    ):
        raise PythonCwe117ScanError(PythonCwe117ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe117ScanError(PythonCwe117ScanErrorCode.SOURCE_LIMIT)

    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe117ScanError(PythonCwe117ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe117ScanError(PythonCwe117ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe117ScanError(PythonCwe117ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases: dict[str, str | None] = {}
    raw: list[tuple[SourceRange, SourceRange, PythonCwe117Operation]] = []
    _scan_statements(tree.body, aliases, tree, source, line_starts, limits, raw)
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
        raise PythonCwe117ScanError(PythonCwe117ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe117Signal(
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
    return PythonCwe117ScanResult(
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


def _scan_statements(
    statements: list[ast.stmt],
    aliases: dict[str, str | None],
    tree: ast.AST,
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe117ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe117Operation]],
) -> None:
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _scan_function(statement, aliases, tree, source, line_starts, limits, output)
            aliases[statement.name] = None
            continue
        if isinstance(statement, ast.ClassDef):
            child_aliases = dict(aliases)
            _scan_statements(statement.body, child_aliases, tree, source, line_starts, limits, output)
            aliases[statement.name] = None
            continue

        if isinstance(statement, ast.Import):
            _record_imports(statement, aliases)
        elif isinstance(statement, ast.ImportFrom):
            _record_import_from(statement, aliases)

        _scan_expression_calls(statement, aliases, tree, source, line_starts, limits, output)
        _record_assignment_aliases(statement, aliases, limits.max_resolution_depth)
        _record_scope_bindings(statement, aliases)

        if isinstance(statement, ast.If):
            left = dict(aliases)
            right = dict(aliases)
            _scan_statements(statement.body, left, tree, source, line_starts, limits, output)
            _scan_statements(statement.orelse, right, tree, source, line_starts, limits, output)
            _merge_aliases(aliases, left, right)
        elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            body_aliases = dict(aliases)
            if isinstance(statement, (ast.For, ast.AsyncFor)):
                _invalidate_target_aliases(statement.target, body_aliases)
            _scan_statements(statement.body, body_aliases, tree, source, line_starts, limits, output)
            else_aliases = dict(aliases)
            _scan_statements(statement.orelse, else_aliases, tree, source, line_starts, limits, output)
            _merge_aliases(aliases, body_aliases, else_aliases)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            parent_aliases = dict(aliases)
            child_aliases = dict(aliases)
            for item in statement.items:
                if item.optional_vars is not None:
                    _invalidate_target_aliases(item.optional_vars, child_aliases)
            _scan_statements(statement.body, child_aliases, tree, source, line_starts, limits, output)
            _merge_aliases(aliases, parent_aliases, child_aliases)
        elif isinstance(statement, ast.Try):
            branches: list[dict[str, str | None]] = []
            body_aliases = dict(aliases)
            _scan_statements(statement.body, body_aliases, tree, source, line_starts, limits, output)
            branches.append(body_aliases)
            for handler in statement.handlers:
                handler_aliases = dict(aliases)
                if handler.name is not None:
                    handler_aliases[handler.name] = None
                _scan_statements(handler.body, handler_aliases, tree, source, line_starts, limits, output)
                branches.append(handler_aliases)
            else_aliases = dict(aliases)
            _scan_statements(statement.orelse, else_aliases, tree, source, line_starts, limits, output)
            branches.append(else_aliases)
            final_aliases = dict(aliases)
            _scan_statements(statement.finalbody, final_aliases, tree, source, line_starts, limits, output)
            branches.append(final_aliases)
            _merge_many_aliases(aliases, branches)
        else:
            for child in _nested_statement_lists(statement):
                parent_aliases = dict(aliases)
                child_aliases = dict(aliases)
                _scan_statements(child, child_aliases, tree, source, line_starts, limits, output)
                _merge_aliases(aliases, parent_aliases, child_aliases)


def _scan_function(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    tree: ast.AST,
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe117ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe117Operation]],
) -> None:
    for default in (*function.args.defaults, *(item for item in function.args.kw_defaults if item)):
        _scan_expression(default, aliases, tree, source, line_starts, limits, output)
    child_aliases = dict(aliases)
    parameters = (
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    )
    for parameter in parameters:
        child_aliases[parameter.arg] = None
    if function.args.vararg is not None:
        child_aliases[function.args.vararg.arg] = None
    if function.args.kwarg is not None:
        child_aliases[function.args.kwarg.arg] = None
    _scan_statements(function.body, child_aliases, tree, source, line_starts, limits, output)


def _scan_expression_calls(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    tree: ast.AST,
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe117ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe117Operation]],
) -> None:
    _scan_expression(statement, aliases, tree, source, line_starts, limits, output)


def _scan_expression(
    root: ast.AST,
    aliases: dict[str, str | None],
    tree: ast.AST,
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe117ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe117Operation]],
) -> None:
    stack: list[ast.AST] = [root]
    while stack:
        node = stack.pop()
        if node is not root and isinstance(node, ast.stmt):
            continue
        if node is not root and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            continue
        if isinstance(node, ast.Call):
            _record_call(node, aliases, tree, source, line_starts, limits, output)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))


def _record_call(
    call: ast.Call,
    aliases: dict[str, str | None],
    tree: ast.AST,
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe117ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe117Operation]],
) -> None:
    operation = _operation_for_callable(call.func, aliases, limits.max_resolution_depth, source)
    if operation is None:
        return
    message = _message_node(call, operation)
    if message is None or _is_structured_message(call, message, operation, aliases, source, limits):
        return
    if _is_safe_expression(message, aliases, limits.max_resolution_depth, source):
        return
    origin = _resolve_source(
        message,
        call=call,
        tree=tree,
        source=source,
        aliases=aliases,
        max_depth=limits.max_resolution_depth,
        seen=frozenset(),
    )
    if origin is None:
        return
    sink = _node_range(call, source, line_starts)
    source_range = _node_range(message, source, line_starts)
    if not sink.contains(source_range):
        raise PythonCwe117ScanError(PythonCwe117ScanErrorCode.INTEGRITY_FAILURE)
    output.append((source_range, sink, operation))
    if len(output) > limits.max_signals:
        raise PythonCwe117ScanError(PythonCwe117ScanErrorCode.SIGNAL_LIMIT)


def _message_node(call: ast.Call, operation: PythonCwe117Operation) -> ast.expr | None:
    if operation.value.endswith(".log"):
        index = 1
    else:
        index = 0
    for keyword in call.keywords:
        if keyword.arg in {"msg", "message"}:
            return keyword.value
    return call.args[index] if len(call.args) > index else None


def _is_structured_message(
    call: ast.Call,
    message: ast.expr,
    operation: PythonCwe117Operation,
    aliases: dict[str, str | None],
    source: bytes,
    limits: PythonCwe117ScanLimits,
) -> bool:
    canonical = _canonical_reference(call.func, aliases, limits.max_resolution_depth)
    if canonical is not None and (
        canonical.startswith("structlog.") or canonical.startswith("structlog.BoundLogger.")
    ):
        return True
    if not isinstance(message, (ast.Constant, ast.JoinedStr)):
        return False
    if isinstance(message, ast.JoinedStr):
        return False
    if type(message.value) is not str:
        return False
    if operation.value.endswith(".log"):
        format_index = 2
    else:
        format_index = 1
    if len(call.args) > format_index:
        return True
    return any(keyword.arg in {"extra", "context", "fields", "data"} for keyword in call.keywords)


def _operation_for_callable(
    callable_node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
    source: bytes,
) -> PythonCwe117Operation | None:
    canonical = _canonical_reference(callable_node, aliases, max_depth)
    if canonical is not None:
        direct = _DIRECT_OPERATIONS.get(canonical)
        if direct is not None:
            return direct
        if canonical.startswith("structlog.") or canonical.startswith("structlog.BoundLogger."):
            return None
        pieces = canonical.split(".")
        if len(pieces) >= 2 and pieces[-1] in _LOG_METHODS:
            base = ".".join(pieces[:-1])
            if base.endswith((".logger", ".log", "Logger", "LoggerAdapter")):
                return _logger_operation(pieces[-1], base)
    dotted = _dotted_name(callable_node)
    if dotted:
        pieces = dotted.split(".")
        if len(pieces) >= 2 and pieces[-1] in _LOG_METHODS and _looks_like_logger(pieces[:-1]):
            return _logger_operation(pieces[-1], ".".join(pieces[:-1]))
    compact = _compact(source, callable_node)
    pieces = compact.split(".")
    if len(pieces) >= 2 and pieces[-1] in _LOG_METHODS and _looks_like_logger(pieces[:-1]):
        return _logger_operation(pieces[-1], ".".join(pieces[:-1]))
    return None


def _logger_operation(method: str, base: str) -> PythonCwe117Operation:
    if base.startswith("loguru"):
        mapping = {
            "log": PythonCwe117Operation.LOGURU_LOG,
            "debug": PythonCwe117Operation.LOGURU_DEBUG,
            "info": PythonCwe117Operation.LOGURU_INFO,
            "warning": PythonCwe117Operation.LOGURU_WARNING,
            "warn": PythonCwe117Operation.LOGURU_WARNING,
            "error": PythonCwe117Operation.LOGURU_ERROR,
            "exception": PythonCwe117Operation.LOGURU_EXCEPTION,
            "critical": PythonCwe117Operation.LOGURU_CRITICAL,
        }
        return mapping[method]
    mapping = {
        "log": PythonCwe117Operation.LOGGER_LOG,
        "debug": PythonCwe117Operation.LOGGER_DEBUG,
        "info": PythonCwe117Operation.LOGGER_INFO,
        "warning": PythonCwe117Operation.LOGGER_WARNING,
        "warn": PythonCwe117Operation.LOGGER_WARN,
        "error": PythonCwe117Operation.LOGGER_ERROR,
        "exception": PythonCwe117Operation.LOGGER_EXCEPTION,
        "critical": PythonCwe117Operation.LOGGER_CRITICAL,
    }
    return mapping[method]


def _looks_like_logger(parts: list[str] | tuple[str, ...]) -> bool:
    if not parts:
        return False
    lowered = {part.lower() for part in parts}
    return bool(lowered & {"logger", "log", "logging", "loggeradapter"})


def _resolve_source(
    subject: ast.expr,
    *,
    call: ast.Call,
    tree: ast.AST | None,
    source: bytes,
    aliases: dict[str, str | None],
    max_depth: int,
    seen: frozenset[str],
    before: tuple[int, int] | None = None,
    depth: int = 0,
) -> ast.expr | None:
    if depth > max_depth:
        raise PythonCwe117ScanError(PythonCwe117ScanErrorCode.SIGNAL_LIMIT)
    if _is_safe_expression(subject, aliases, max_depth, source):
        return None
    direct = _direct_source_node(subject, source)
    if direct is not None:
        return direct
    if isinstance(subject, ast.Name):
        if subject.id in seen:
            return None
        if tree is not None:
            assignment = _latest_assignment(tree, call, subject.id, before)
            if assignment is not None and assignment.value is not None:
                return _resolve_source(
                    assignment.value,
                    call=call,
                    tree=tree,
                    source=source,
                    aliases=aliases,
                    max_depth=max_depth,
                    seen=seen | {subject.id},
                    before=(assignment.lineno, assignment.col_offset),
                    depth=depth + 1,
                )
        if _is_parameter_source(subject.id, call, tree):
            return subject
    for child in ast.iter_child_nodes(subject):
        if isinstance(child, ast.expr):
            resolved = _resolve_source(
                child,
                call=call,
                tree=tree,
                source=source,
                aliases=aliases,
                max_depth=max_depth,
                seen=seen,
                before=before,
                depth=depth + 1,
            )
            if resolved is not None:
                return resolved
    return None


def _latest_assignment(
    tree: ast.AST,
    call: ast.Call,
    name: str,
    before: tuple[int, int] | None,
) -> ast.Assign | ast.AnnAssign | None:
    scope = _enclosing_function(call, tree)
    root: ast.AST = scope if scope is not None else tree
    boundary = before or (getattr(call, "lineno", 0), getattr(call, "col_offset", 0))
    candidates: list[ast.Assign | ast.AnnAssign] = []
    stack: list[ast.AST] = [root]
    while stack:
        node = stack.pop()
        if node is not root and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            position = (node.lineno, node.col_offset)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if position < boundary and any(_target_has_name(target, name) for target in targets):
                candidates.append(node)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return max(candidates, key=lambda item: (item.lineno, item.col_offset), default=None)


def _target_has_name(target: ast.expr, name: str) -> bool:
    return any(item.id == name for item in ast.walk(target) if isinstance(item, ast.Name))


def _direct_source_node(subject: ast.expr, source: bytes) -> ast.expr | None:
    stack: list[ast.AST] = [subject]
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Call) and _source_call(node, source):
            return node
        if isinstance(node, ast.Attribute) and _source_attribute(node):
            return node
        if isinstance(node, ast.Subscript) and _source_subscript(node):
            return node
        if isinstance(node, ast.Call) and _is_safe_callable(node.func, source):
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return None


def _source_call(node: ast.Call, source: bytes) -> bool:
    name = _compact(source, node.func)
    if name in {"input", "builtins.input", "os.getenv", "os.environ.get"}:
        return True
    pieces = name.replace("[", ".[").split(".")
    if pieces and pieces[0] in _SOURCE_ROOTS:
        return bool(
            pieces[-1] in _SOURCE_METHODS
            or pieces[-1] in _SOURCE_ATTRIBUTES
            or (len(pieces) > 1 and pieces[-2] in _SOURCE_ATTRIBUTES)
        )
    return name in {"environ.get", "request.values.get", "request.args.get"}


def _source_attribute(node: ast.Attribute) -> bool:
    if node.attr not in _SOURCE_ATTRIBUTES:
        return False
    root: ast.expr = node.value
    while isinstance(root, ast.Attribute):
        root = root.value
    return isinstance(root, ast.Name) and root.id in _SOURCE_ROOTS


def _source_subscript(node: ast.Subscript) -> bool:
    value = node.value
    if isinstance(value, ast.Attribute):
        return _source_attribute(value)
    if isinstance(value, ast.Name):
        return value.id in _SOURCE_ROOTS or value.id in {"environ", "argv"}
    return False


def _is_parameter_source(name: str, call: ast.Call, tree: ast.AST | None) -> bool:
    if name.lower() not in _PARAMETER_NAMES or tree is None:
        return False
    scope = _enclosing_function(call, tree)
    if scope is None:
        return False
    parameters = (
        *scope.args.posonlyargs,
        *scope.args.args,
        *scope.args.kwonlyargs,
    )
    return any(parameter.arg == name for parameter in parameters) or (
        scope.args.vararg is not None and scope.args.vararg.arg == name
    ) or (scope.args.kwarg is not None and scope.args.kwarg.arg == name)


def _enclosing_function(
    call: ast.Call, tree: ast.AST
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    candidates: list[tuple[int, int, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    line = getattr(call, "lineno", -1)
    for item in ast.walk(tree):
        if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end_line = getattr(item, "end_lineno", None)
        if type(end_line) is int and item.lineno <= line <= end_line:
            candidates.append((end_line - item.lineno, item.col_offset, item))
    return min(candidates, default=(0, 0, None))[2]


def _is_safe_expression(
    node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
    source: bytes,
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    canonical = _canonical_reference(node.func, aliases, max_depth)
    name = canonical or _compact(source, node.func)
    if name in _SANITIZER_NAMES or name in {
        "json.dumps",
        "json.JSONEncoder.encode",
        "urllib.parse.quote",
        "urllib.parse.quote_plus",
        "urllib.parse.quote_from_bytes",
    }:
        return True
    if name.rsplit(".", 1)[-1] in _SANITIZER_SUFFIXES:
        return True
    if name.endswith(".replace"):
        return _replace_removes_line_breaks(node)
    if name.endswith(".translate"):
        return _translate_removes_line_breaks(node)
    if name in {"re.sub", "regex.sub"}:
        return _regex_sub_removes_line_breaks(node)
    return False


def _is_safe_callable(node: ast.AST, source: bytes) -> bool:
    name = _compact(source, node)
    return name.rsplit(".", 1)[-1] in _SANITIZER_SUFFIXES or name in {
        "json.dumps",
        "repr",
        "ascii",
        "urllib.parse.quote",
        "urllib.parse.quote_plus",
    }


def _replace_removes_line_breaks(call: ast.Call) -> bool:
    if len(call.args) < 2 or call.keywords:
        return False
    old = _literal_string(call.args[0])
    new = _literal_string(call.args[1])
    return old in {"\r", "\n", "\r\n"} and new is not None and "\r" not in new and "\n" not in new


def _translate_removes_line_breaks(call: ast.Call) -> bool:
    if not call.args or call.keywords:
        return False
    mapping = call.args[0]
    if not isinstance(mapping, ast.Call) or _dotted_name(mapping.func) != "str.maketrans":
        return False
    if len(mapping.args) < 2:
        return False
    old = _literal_string(mapping.args[0])
    new = _literal_string(mapping.args[1])
    return old is not None and "\r" in old and "\n" in old and new is not None and not new


def _regex_sub_removes_line_breaks(call: ast.Call) -> bool:
    if len(call.args) < 3:
        return False
    pattern = _literal_string(call.args[0])
    replacement = _literal_string(call.args[1])
    if pattern is None or replacement is None or "\r" in replacement or "\n" in replacement:
        return False
    compact = pattern.replace(" ", "")
    return ("\\r" in compact and "\\n" in compact) or compact in {"[\\r\\n]", "\\r|\\n"}


def _canonical_reference(
    node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe117ScanError(PythonCwe117ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        return aliases.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Call):
        if _dotted_name(node.func) in {"getattr", "builtins.getattr"}:
            if len(node.args) < 2 or node.keywords:
                return None
            base = _canonical_reference(node.args[0], aliases, max_depth, depth + 1)
            member = _literal_string(node.args[1])
            return None if base is None or member is None else f"{base}.{member}"
        base = _canonical_reference(node.func, aliases, max_depth, depth + 1)
        if base in {"logging.getLogger", "logging.Logger"}:
            return "logging.Logger"
        if base in {"logging.LoggerAdapter", "logging.LoggerAdapter.__init__"}:
            return "logging.LoggerAdapter"
        if base in {"loguru.logger", "loguru.logger.bind"}:
            return "loguru.logger"
        if base in {"structlog.get_logger", "structlog.wrap_logger"}:
            return "structlog.BoundLogger"
        return None
    return None


def _record_imports(statement: ast.Import, aliases: dict[str, str | None]) -> None:
    for imported in statement.names:
        root = imported.name.split(".", 1)[0]
        if root not in _MODULES:
            aliases[imported.asname or root] = None
        elif imported.asname is None:
            aliases[root] = root
        else:
            aliases[imported.asname] = imported.name


def _record_import_from(statement: ast.ImportFrom, aliases: dict[str, str | None]) -> None:
    module = statement.module or ""
    if statement.level or not (
        module == "logging"
        or module.startswith("logging.")
        or module == "loguru"
        or module.startswith("loguru.")
        or module == "structlog"
        or module.startswith("structlog.")
    ):
        for imported in statement.names:
            aliases[imported.asname or imported.name] = None
        return
    for imported in statement.names:
        if imported.name == "*":
            continue
        name = imported.asname or imported.name
        canonical = f"{module}.{imported.name}"
        if canonical in _DIRECT_OPERATIONS or canonical in {
            "logging.getLogger",
            "logging.Logger",
            "logging.LoggerAdapter",
            "loguru.logger",
            "structlog.get_logger",
            "structlog.wrap_logger",
        }:
            aliases[name] = canonical
        else:
            aliases[name] = None


def _record_assignment_aliases(
    statement: ast.stmt, aliases: dict[str, str | None], max_depth: int
) -> None:
    values: list[tuple[ast.expr, ast.expr]] = []
    if isinstance(statement, ast.Assign) and statement.targets:
        values.extend((target, statement.value) for target in statement.targets)
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        values.append((statement.target, statement.value))
    for target, value in values:
        if not isinstance(target, ast.Name):
            continue
        reference = _canonical_reference(value, aliases, max_depth)
        if reference in {"logging.getLogger", "logging.Logger"}:
            reference = "logging.Logger"
        elif reference in {"logging.LoggerAdapter", "logging.LoggerAdapter.__init__"}:
            reference = "logging.LoggerAdapter"
        elif reference in {"structlog.get_logger", "structlog.BoundLogger"}:
            reference = "structlog.BoundLogger"
        aliases[target.id] = reference


def _record_scope_bindings(statement: ast.stmt, aliases: dict[str, str | None]) -> None:
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        _invalidate_target_aliases(statement.target, aliases)
    elif isinstance(statement, (ast.With, ast.AsyncWith)):
        for item in statement.items:
            if item.optional_vars is not None:
                _invalidate_target_aliases(item.optional_vars, aliases)
    elif isinstance(statement, ast.Try):
        for handler in statement.handlers:
            if handler.name is not None:
                aliases[handler.name] = None
    elif isinstance(statement, ast.Delete):
        for target in statement.targets:
            _invalidate_target_aliases(target, aliases)


def _invalidate_target_aliases(node: ast.AST, aliases: dict[str, str | None]) -> None:
    for name in _target_names(node):
        aliases[name] = None


def _merge_aliases(
    target: dict[str, str | None], left: dict[str, str | None], right: dict[str, str | None]
) -> None:
    target.clear()
    for name in left.keys() | right.keys():
        left_value = left.get(name)
        right_value = right.get(name)
        target[name] = left_value if left_value == right_value else None


def _merge_many_aliases(
    target: dict[str, str | None], branches: list[dict[str, str | None]]
) -> None:
    if not branches:
        return
    merged = dict(branches[0])
    for branch in branches[1:]:
        _merge_aliases(merged, merged, branch)
    target.clear()
    target.update(merged)


def _target_names(node: ast.AST) -> tuple[str, ...]:
    return tuple(item.id for item in ast.walk(node) if isinstance(item, ast.Name))


def _nested_statement_lists(statement: ast.stmt) -> tuple[list[ast.stmt], ...]:
    if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
        return statement.body, statement.orelse
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        return (statement.body,)
    if isinstance(statement, ast.Try):
        return (
            statement.body,
            statement.orelse,
            statement.finalbody,
            *(handler.body for handler in statement.handlers),
        )
    if isinstance(statement, ast.Match):
        return tuple(case.body for case in statement.cases)
    return ()


def _literal_string(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None


def _dotted_name(node: ast.AST) -> str:
    parts: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


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
        raise PythonCwe117ScanError(PythonCwe117ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe117ScanError(PythonCwe117ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe117ScanError(PythonCwe117ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start,
        end,
        SourcePoint(start_line, start_column),
        SourcePoint(end_line, end_column),
    )


def _compact(source: bytes, node: ast.AST) -> str:
    location = _node_range(node, source, _line_starts(source))
    return b"".join(source[location.start_byte : location.end_byte].split()).decode(
        "ascii", "ignore"
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
    operation: PythonCwe117Operation,
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
    signals: tuple[PythonCwe117Signal, ...],
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


Cwe117ScanErrorCode = PythonCwe117ScanErrorCode
Cwe117ScanError = PythonCwe117ScanError
Cwe117ScanLimits = PythonCwe117ScanLimits
Cwe117ScanResult = PythonCwe117ScanResult
Cwe117Signal = PythonCwe117Signal


__all__ = [
    "DEFAULT_PYTHON_CWE117_SCAN_LIMITS",
    "Cwe117ScanError",
    "Cwe117ScanErrorCode",
    "Cwe117ScanLimits",
    "Cwe117ScanResult",
    "Cwe117Signal",
    "PythonCwe117Operation",
    "PythonCwe117ScanError",
    "PythonCwe117ScanErrorCode",
    "PythonCwe117ScanLimits",
    "PythonCwe117ScanResult",
    "PythonCwe117Signal",
    "scan_python_cwe117",
]
