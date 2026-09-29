"""Bounded Go facts for CWE-532 sensitive information in logs.

This module deliberately recognises a narrow source-to-sink surface.  A
finding is emitted only when a value with an explicit credential, token, or
secret shape reaches a recognised logging call without passing through a
redaction or one-way transformation.  The scanner keeps no source text in a
result and refuses malformed, oversized, or non-healthy admitted indexes.

The data-flow is intentionally local and bounded.  It follows assignments in
one function, common request and environment secret sources, and logger call
arguments.  Unknown logger abstractions and unknown data-flow are left
unresolved so callers can treat the result as a conservative projection.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import (
    ParseHealth,
    RepositoryFile,
    SourcePoint,
    SourceRange,
    SymbolIndex,
)
from tree_sitter import Language, Node, Parser

from .cst import build_go_symbol_index
from .cst_go import _go_language

_MAX_LIMITS = (2_000_000, 2_048, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SIGNAL_ID = re.compile(r"go-cwe532-[0-9a-f]{64}\Z")
_RULE_ID = "securecode-go-cwe532"
_DETECTOR = "securecode-go-cwe532@1.0"
_DETAIL = "sensitive_value_to_log_sink"

_LOG_PACKAGES = frozenset(
    {
        "log",
        "log/slog",
        "github.com/sirupsen/logrus",
        "go.uber.org/zap",
        "go.uber.org/zap/zapcore",
    }
)
_SOURCE_PACKAGES = _LOG_PACKAGES | {"os"}
_LOG_METHODS = frozenset(
    {
        "debug",
        "debugf",
        "dpanic",
        "dpanicf",
        "error",
        "errorf",
        "fatal",
        "fatalf",
        "info",
        "infof",
        "log",
        "logf",
        "output",
        "panic",
        "panicf",
        "print",
        "printf",
        "println",
        "trace",
        "tracef",
        "warn",
        "warnf",
        "warning",
        "warningf",
    }
)
_SENSITIVE_WORDS = frozenset(
    {
        "accesskey",
        "apikey",
        "auth",
        "authtoken",
        "bearer",
        "clientsecret",
        "credential",
        "credentials",
        "jwt",
        "passcode",
        "passwd",
        "password",
        "privatekey",
        "secret",
        "secrets",
        "sessiontoken",
        "token",
        "tokens",
    }
)
_SENSITIVE_LITERAL_MARKERS = frozenset(
    {
        "access-key",
        "access_key",
        "api-key",
        "api_key",
        "authorization",
        "client-secret",
        "client_secret",
        "cookie",
        "credential",
        "jwt",
        "passcode",
        "password",
        "passwd",
        "private-key",
        "private_key",
        "secret",
        "session-token",
        "session_token",
        "token",
        "x-api-key",
        "x-auth-token",
    }
)
_SANITIZER_WORDS = frozenset(
    {
        "bcrypt",
        "encrypt",
        "hmac",
        "hash",
        "mask",
        "obfuscate",
        "redact",
        "sanitize",
        "scrub",
        "sha1",
        "sha256",
        "sha512",
    }
)
_LOGGER_NAME_WORDS = frozenset({"log", "logger", "logging", "sugar", "sugared"})
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})


class GoCwe532ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-532 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe532ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe532ScanErrorCode) -> None:
        if type(code) is not GoCwe532ScanErrorCode:
            raise TypeError("Go CWE-532 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-532 sensitive-logging scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe532ScanLimits:
    """Hard ceilings applied before and during local flow analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-532 scan limits are invalid")


DEFAULT_GO_CWE532_SCAN_LIMITS = GoCwe532ScanLimits()


class GoCwe532Operation(StrEnum):
    """Recognised logging operations which may receive a sensitive value."""

    LOG_DEBUG = "log.Debug"
    LOG_ERROR = "log.Error"
    LOG_FATAL = "log.Fatal"
    LOG_OUTPUT = "log.Output"
    LOG_PANIC = "log.Panic"
    LOG_PRINT = "log.Print"
    LOG_PRINTF = "log.Printf"
    LOG_PRINTLN = "log.Println"
    SLOG_DEBUG = "log/slog.Debug"
    SLOG_ERROR = "log/slog.Error"
    SLOG_INFO = "log/slog.Info"
    SLOG_LOG = "log/slog.Log"
    SLOG_WARN = "log/slog.Warn"
    LOGRUS_LOG = "logrus.Log"
    LOGRUS_DEBUG = "logrus.Debug"
    LOGRUS_INFO = "logrus.Info"
    LOGRUS_WARN = "logrus.Warn"
    LOGRUS_ERROR = "logrus.Error"
    LOGRUS_FATAL = "logrus.Fatal"
    LOGRUS_PANIC = "logrus.Panic"
    ZAP_DEBUG = "zap.Debug"
    ZAP_INFO = "zap.Info"
    ZAP_WARN = "zap.Warn"
    ZAP_ERROR = "zap.Error"
    ZAP_DPANIC = "zap.DPanic"
    ZAP_PANIC = "zap.Panic"
    ZAP_FATAL = "zap.Fatal"
    LOGGER_DEBUG = "logger.Debug"
    LOGGER_INFO = "logger.Info"
    LOGGER_WARN = "logger.Warn"
    LOGGER_ERROR = "logger.Error"
    LOGGER_PRINT = "logger.Print"
    LOGGER_PRINTF = "logger.Printf"
    LOGGER_PRINTLN = "logger.Println"

    # Compatibility names for generic scanner consumers.
    PRINT = "log.Print"
    PRINTF = "log.Printf"
    PRINTLN = "log.Println"
    INFO = "log/slog.Info"
    ERROR = "log/slog.Error"


_PACKAGE_OPERATIONS: dict[tuple[str, str], GoCwe532Operation] = {
    ("log", "Debug"): GoCwe532Operation.LOG_DEBUG,
    ("log", "Error"): GoCwe532Operation.LOG_ERROR,
    ("log", "Fatal"): GoCwe532Operation.LOG_FATAL,
    ("log", "Output"): GoCwe532Operation.LOG_OUTPUT,
    ("log", "Panic"): GoCwe532Operation.LOG_PANIC,
    ("log", "Print"): GoCwe532Operation.LOG_PRINT,
    ("log", "Printf"): GoCwe532Operation.LOG_PRINTF,
    ("log", "Println"): GoCwe532Operation.LOG_PRINTLN,
    ("log/slog", "Debug"): GoCwe532Operation.SLOG_DEBUG,
    ("log/slog", "Error"): GoCwe532Operation.SLOG_ERROR,
    ("log/slog", "Info"): GoCwe532Operation.SLOG_INFO,
    ("log/slog", "Log"): GoCwe532Operation.SLOG_LOG,
    ("log/slog", "Warn"): GoCwe532Operation.SLOG_WARN,
    ("github.com/sirupsen/logrus", "Debug"): GoCwe532Operation.LOGRUS_DEBUG,
    ("github.com/sirupsen/logrus", "Info"): GoCwe532Operation.LOGRUS_INFO,
    ("github.com/sirupsen/logrus", "Warn"): GoCwe532Operation.LOGRUS_WARN,
    ("github.com/sirupsen/logrus", "Error"): GoCwe532Operation.LOGRUS_ERROR,
    ("github.com/sirupsen/logrus", "Fatal"): GoCwe532Operation.LOGRUS_FATAL,
    ("github.com/sirupsen/logrus", "Panic"): GoCwe532Operation.LOGRUS_PANIC,
    ("github.com/sirupsen/logrus", "Log"): GoCwe532Operation.LOGRUS_LOG,
    ("github.com/sirupsen/logrus", "Print"): GoCwe532Operation.LOGRUS_INFO,
    ("github.com/sirupsen/logrus", "Printf"): GoCwe532Operation.LOGRUS_INFO,
    ("github.com/sirupsen/logrus", "Println"): GoCwe532Operation.LOGRUS_INFO,
    ("go.uber.org/zap", "Debug"): GoCwe532Operation.ZAP_DEBUG,
    ("go.uber.org/zap", "Info"): GoCwe532Operation.ZAP_INFO,
    ("go.uber.org/zap", "Warn"): GoCwe532Operation.ZAP_WARN,
    ("go.uber.org/zap", "Error"): GoCwe532Operation.ZAP_ERROR,
    ("go.uber.org/zap", "DPanic"): GoCwe532Operation.ZAP_DPANIC,
    ("go.uber.org/zap", "Panic"): GoCwe532Operation.ZAP_PANIC,
    ("go.uber.org/zap", "Fatal"): GoCwe532Operation.ZAP_FATAL,
}


@dataclass(frozen=True, slots=True)
class GoCwe532Signal:
    """One immutable source-free sensitive-value-to-log fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe532Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-532"
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
            and 0 <= self.source.start_byte <= self.source.end_byte
            and self.source.end_byte <= self.sink.end_byte
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
            if valid_identity and valid_ranges and type(self.operation) is GoCwe532Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not GoCwe532Operation
            or type(signal_id) is not str
            or expected_id is None
            or _SIGNAL_ID.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-532"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-532 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", expected_id)

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
class GoCwe532ScanResult:
    """Deterministic, source-free result for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe532Signal, ...]
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
            type(item) is GoCwe532Signal for item in self.signals
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
        same_identity = all(
            item.repository_id == self.repository_id
            and item.revision == self.revision
            and item.path == self.path
            and item.content_sha256 == self.content_sha256
            and item.source_size_bytes == self.source_size_bytes
            for item in self.signals
        )
        if (
            not identity_valid
            or not valid_signals
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
            or len({item.signal_id for item in self.signals}) != len(self.signals)
            or not same_identity
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
            raise ValueError("Go CWE-532 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange


def scan_go_cwe532(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe532ScanLimits = DEFAULT_GO_CWE532_SCAN_LIMITS,
) -> GoCwe532ScanResult:
    """Find explicit credential, token, or secret values sent to log sinks."""

    _validate_request(symbol_index, limits)
    source = symbol_index.source
    try:
        rebuilt = build_go_symbol_index(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source=source,
        )
        if rebuilt != symbol_index:
            raise ValueError("index mismatch")
        root = Parser(Language(_go_language())).parse(source).root_node
        if root.has_error:
            raise ValueError("parse error")
        source.decode("utf-8", errors="strict")
    except Exception:
        raise GoCwe532ScanError(GoCwe532ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    raw: set[tuple[SourceRange, SourceRange, GoCwe532Operation]] = set()
    try:
        for scope in _scopes(root):
            environment: dict[str, tuple[_Flow, ...]] = {}
            logger_names = _logger_bindings(scope, source, imports, limits)
            for node in _scope_preorder(scope):
                if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                    _capture_assignment(node, environment, source, imports, limits)
                if node.type != "call_expression":
                    continue
                operation = _operation_for_sink(node, source, imports, logger_names)
                if operation is None:
                    continue
                arguments = node.child_by_field_name("arguments")
                if arguments is None:
                    continue
                for argument in arguments.named_children:
                    for flow in _resolve_sensitive(
                        argument, environment, source, imports, limits, 0
                    ):
                        sink_range = _range(node)
                        if flow.source.end_byte > sink_range.end_byte:
                            raise GoCwe532ScanError(GoCwe532ScanErrorCode.INTEGRITY_FAILURE)
                        raw.add((flow.source, sink_range, operation))
                        if len(raw) > limits.max_signals:
                            raise GoCwe532ScanError(GoCwe532ScanErrorCode.SIGNAL_LIMIT)
    except GoCwe532ScanError:
        raise
    except Exception:
        raise GoCwe532ScanError(GoCwe532ScanErrorCode.INTEGRITY_FAILURE) from None

    ordered = sorted(
        raw,
        key=lambda item: (
            item[1].start_byte,
            item[1].end_byte,
            item[0].start_byte,
            item[0].end_byte,
            item[2].value,
        ),
    )
    if len(ordered) > limits.max_signals:
        raise GoCwe532ScanError(GoCwe532ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe532Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
            signal_id=_signal_id(
                symbol_index.repository_id,
                symbol_index.revision,
                symbol_index.path,
                symbol_index.content_sha256,
                symbol_index.source_byte_length,
                source_range,
                sink_range,
                operation,
            ),
        )
        for source_range, sink_range, operation in ordered
    )
    return GoCwe532ScanResult(
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


def scan_go_sensitive_logging(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe532ScanLimits = DEFAULT_GO_CWE532_SCAN_LIMITS,
) -> GoCwe532ScanResult:
    """Descriptive alias for :func:`scan_go_cwe532`."""

    return scan_go_cwe532(symbol_index, limits=limits)


def scan_go_sensitive_data_logging(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe532ScanLimits = DEFAULT_GO_CWE532_SCAN_LIMITS,
) -> GoCwe532ScanResult:
    """Compatibility alias for callers using the full CWE description."""

    return scan_go_cwe532(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe532ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe532ScanLimits:
        raise GoCwe532ScanError(GoCwe532ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe532ScanError(GoCwe532ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe532ScanError(GoCwe532ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe532ScanError(GoCwe532ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        package = _text(source, path_node).strip('"`')
        if package not in _SOURCE_PACKAGES:
            continue
        name_node = node.child_by_field_name("name")
        alias = _text(source, name_node) if name_node is not None else package.rsplit("/", 1)[-1]
        if alias not in {".", "_"}:
            aliases[alias] = package
    return aliases


def _logger_bindings(
    scope: Node,
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe532ScanLimits,
) -> frozenset[str]:
    names: set[str] = set()
    for node in _scope_preorder(scope):
        if node.type not in {"short_var_declaration", "assignment_statement", "var_spec"}:
            continue
        left = node.child_by_field_name("left")
        if left is None:
            left = node.child_by_field_name("name")
        right = node.child_by_field_name("right")
        if right is None:
            right = node.child_by_field_name("value")
        if left is None or right is None:
            continue
        identifiers = left.named_children if left.named_children else (left,)
        values = right.named_children if right.named_children else (right,)
        for index, identifier in enumerate(identifiers):
            if index >= len(values) or identifier.type != "identifier":
                continue
            value = values[index]
            if _looks_like_logger_name(_text(source, identifier)) or _is_logger_constructor(
                value, source, imports
            ):
                names.add(_text(source, identifier))
            if len(names) > limits.max_signals:
                raise GoCwe532ScanError(GoCwe532ScanErrorCode.SIGNAL_LIMIT)
    return frozenset(names)


def _capture_assignment(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe532ScanLimits,
) -> None:
    if node.type == "var_spec":
        left = node.child_by_field_name("name")
        right = node.child_by_field_name("value")
    else:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
    if left is None or right is None:
        return
    names = left.named_children if left.named_children else (left,)
    values = right.named_children if right.named_children else (right,)
    if len(names) > limits.max_signals or len(values) > limits.max_signals:
        raise GoCwe532ScanError(GoCwe532ScanErrorCode.SIGNAL_LIMIT)
    for index, name in enumerate(names):
        if name.type != "identifier" or index >= len(values):
            continue
        identifier = _text(source, name)
        value = values[index]
        flows = _resolve_sensitive(value, environment, source, imports, limits, 0)
        if not flows and _is_sensitive_name(identifier):
            flows = (_Flow(_range(value)),)
        if flows:
            environment[identifier] = _dedupe_flows(flows)
        else:
            environment.pop(identifier, None)


def _resolve_sensitive(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe532ScanLimits,
    depth: int,
    visited: frozenset[str] = frozenset(),
) -> tuple[_Flow, ...]:
    if depth > limits.max_expression_depth:
        raise GoCwe532ScanError(GoCwe532ScanErrorCode.SIGNAL_LIMIT)
    if node.type in {"identifier", "field_identifier", "type_identifier"}:
        name = _text(source, node)
        if node.type == "identifier" and name in visited:
            return ()
        if node.type == "identifier" and name in environment:
            return environment[name]
        return (_Flow(_range(node)),) if _is_sensitive_name(name) else ()

    if node.type == "literal_value":
        return ()
    if node.type in {"interpreted_string_literal", "raw_string_literal", "int_literal"}:
        return ()
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        if _is_sanitizer_call(function, source):
            return ()
        if _is_sensitive_source_call(node, source, imports):
            return (_Flow(_range(node)),)
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            return ()
        return _dedupe_flows(
            flow
            for argument in arguments.named_children
            for flow in _resolve_sensitive(
                argument, environment, source, imports, limits, depth + 1, visited
            )
        )
    if node.type == "selector_expression":
        field = node.child_by_field_name("field")
        operand = node.child_by_field_name("operand")
        field_text = _text(source, field)
        if _is_sensitive_name(field_text):
            return (_Flow(_range(node)),)
        child_flows = _dedupe_flows(
            flow
            for child in (operand, field)
            if child is not None
            for flow in _resolve_sensitive(
                child, environment, source, imports, limits, depth + 1, visited
            )
        )
        return child_flows
    if node.type == "index_expression":
        text = _compact_text(source, node)
        if any(marker in text.casefold() for marker in _SENSITIVE_LITERAL_MARKERS):
            return (_Flow(_range(node)),)
    if node.type in {
        "parenthesized_expression",
        "unary_expression",
        "pointer_expression",
        "address_expression",
    }:
        return _dedupe_flows(
            flow
            for child in node.named_children
            for flow in _resolve_sensitive(
                child, environment, source, imports, limits, depth + 1, visited
            )
        )
    if node.type in {
        "binary_expression",
        "expression_list",
        "keyed_element",
        "composite_literal",
        "index_expression",
        "slice_expression",
    }:
        return _dedupe_flows(
            flow
            for child in node.named_children
            for flow in _resolve_sensitive(
                child, environment, source, imports, limits, depth + 1, visited
            )
        )
    return ()


def _operation_for_sink(
    node: Node,
    source: bytes,
    imports: dict[str, str],
    logger_names: frozenset[str],
) -> GoCwe532Operation | None:
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    field_name = _text(source, field)
    package = imports.get(_text(source, operand)) if operand.type == "identifier" else None
    if package is not None:
        return _PACKAGE_OPERATIONS.get((package, field_name))
    receiver = _text(source, operand)
    if _text(source, field).casefold() not in _LOG_METHODS:
        return None
    if _looks_like_logger_name(receiver) or receiver in logger_names:
        return _logger_operation(field_name)
    return None


def _logger_operation(method: str) -> GoCwe532Operation:
    normalized = method.casefold()
    values = {
        "debug": GoCwe532Operation.LOGGER_DEBUG,
        "error": GoCwe532Operation.LOGGER_ERROR,
        "info": GoCwe532Operation.LOGGER_INFO,
        "warn": GoCwe532Operation.LOGGER_WARN,
        "warning": GoCwe532Operation.LOGGER_WARN,
        "print": GoCwe532Operation.LOGGER_PRINT,
        "printf": GoCwe532Operation.LOGGER_PRINTF,
        "println": GoCwe532Operation.LOGGER_PRINTLN,
    }
    return values.get(normalized, GoCwe532Operation.LOGGER_INFO)


def _is_logger_constructor(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return False
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return False
    package = imports.get(_text(source, operand)) if operand.type == "identifier" else None
    return package in _LOG_PACKAGES and _text(source, field).casefold() in {
        "new",
        "newlogger",
        "newproduction",
        "newsugar",
        "newdevelopment",
        "newsugaredlogger",
    }


def _is_sensitive_source_call(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    function = node.child_by_field_name("function")
    if function is None:
        return False
    name = _call_name(function, source).casefold()
    compact = re.sub(r"[^a-z0-9]", "", name)
    if any(
        word in compact
        for word in (
            "getsecret",
            "gettoken",
            "readsecret",
            "loadsecret",
            "getpassword",
            "getcredential",
        )
    ):
        return True
    if function.type != "selector_expression":
        return False
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return False
    package = imports.get(_text(source, operand)) if operand.type == "identifier" else None
    method = _text(source, field).casefold()
    if package == "os" and method in {"getenv", "lookupenv"}:
        arguments = node.child_by_field_name("arguments")
        return arguments is not None and any(
            _literal_mentions_sensitive(child, source) for child in arguments.named_children
        )
    if method in {"get", "getheader", "formvalue", "query"}:
        arguments = node.child_by_field_name("arguments")
        return arguments is not None and any(
            _literal_mentions_sensitive(child, source) for child in arguments.named_children
        )
    return False


def _is_sanitizer_call(function: Node | None, source: bytes) -> bool:
    name = _call_name(function, source).casefold()
    compact = re.sub(r"[^a-z0-9]", "", name)
    return any(word in compact for word in _SANITIZER_WORDS)


def _literal_mentions_sensitive(node: Node, source: bytes) -> bool:
    if node.type not in {"interpreted_string_literal", "raw_string_literal"}:
        return False
    value = _text(source, node).strip('"`').casefold()
    return any(marker in value for marker in _SENSITIVE_LITERAL_MARKERS)


def _is_sensitive_name(value: str) -> bool:
    tokens = _name_tokens(value)
    return bool(tokens & _SENSITIVE_WORDS)


def _name_tokens(value: str) -> frozenset[str]:
    expanded = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    compact = re.sub(r"[^A-Za-z0-9]+", "", expanded).casefold()
    tokens = set(re.sub(r"[^A-Za-z0-9]+", " ", expanded).casefold().split())
    if compact:
        tokens.add(compact)
    return frozenset(tokens)


def _looks_like_logger_name(value: str) -> bool:
    return bool(_name_tokens(value) & _LOGGER_NAME_WORDS)


def _scopes(root: Node) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node.type in _GO_SCOPES)


def _scope_preorder(scope: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    while stack:
        node = stack.pop()
        output.append(node)
        if node != scope and node.type in _GO_SCOPES:
            continue
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _preorder(root: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        output.append(node)
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _call_name(function: Node | None, source: bytes) -> str:
    if function is None:
        return ""
    if function.type == "identifier":
        return _text(source, function)
    if function.type == "selector_expression":
        field = function.child_by_field_name("field")
        return _text(source, field)
    return ""


def _dedupe_flows(flows: Iterable[_Flow]) -> tuple[_Flow, ...]:
    unique: dict[tuple[int, int], _Flow] = {}
    for flow in flows:
        unique[(flow.source.start_byte, flow.source.end_byte)] = flow
    return tuple(unique[key] for key in sorted(unique))


def _text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")


def _compact_text(source: bytes, node: Node | None) -> str:
    return "".join(_text(source, node).split())


def _range(node: Node) -> SourceRange:
    return SourceRange(
        node.start_byte,
        node.end_byte,
        SourcePoint(node.start_point.row, node.start_point.column),
        SourcePoint(node.end_point.row, node.end_point.column),
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
    operation: GoCwe532Operation,
) -> str:
    material = {
        "content_sha256": content_sha256,
        "cwe": "CWE-532",
        "detector": _DETECTOR,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "sink": _range_value(sink),
        "source": _range_value(source),
        "source_size_bytes": source_size_bytes,
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    return "go-cwe532-" + digest


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe532Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "cwe": signal.cwe,
                "detail": signal.detail,
                "detector": signal.detector,
                "operation": signal.operation.value,
                "signal_id": signal.signal_id,
                "sink": _range_value(signal.sink),
                "source": _range_value(signal.source),
            }
            for signal in signals
        ],
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


Cwe532ScanErrorCode = GoCwe532ScanErrorCode
Cwe532ScanError = GoCwe532ScanError
Cwe532ScanLimits = GoCwe532ScanLimits
Cwe532ScanResult = GoCwe532ScanResult
Cwe532Signal = GoCwe532Signal

scan_go_cwe532_logging = scan_go_cwe532


__all__ = [
    "DEFAULT_GO_CWE532_SCAN_LIMITS",
    "Cwe532ScanError",
    "Cwe532ScanErrorCode",
    "Cwe532ScanLimits",
    "Cwe532ScanResult",
    "Cwe532Signal",
    "GoCwe532Operation",
    "GoCwe532ScanError",
    "GoCwe532ScanErrorCode",
    "GoCwe532ScanLimits",
    "GoCwe532ScanResult",
    "GoCwe532Signal",
    "scan_go_cwe532",
    "scan_go_cwe532_logging",
    "scan_go_sensitive_data_logging",
    "scan_go_sensitive_logging",
]
