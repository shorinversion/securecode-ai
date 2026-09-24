"""Bounded Python CWE-209 error-message exposure facts.

The adapter recognises values which are likely to contain request data or
credentials when they are placed in an exception message.  It intentionally
keeps the analysis local: assignments are followed only to a bounded depth,
unknown calls are not treated as sources, and fixed messages are ignored.
Recognised redaction helpers terminate a flow.  The returned objects contain
only immutable source ranges and content-addressed identity, never source
text or parser diagnostics.
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

_MAX_LIMIT_VALUES = (2_000_000, 10_000, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-python-cwe209"
_DETECTOR = "securecode-python-cwe209@1.0"
_DETAIL = "sensitive_value_to_error_message"


class PythonCwe209ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-209 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe209ScanError(RuntimeError):
    """Fixed scanner failure which never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe209ScanErrorCode) -> None:
        if type(code) is not PythonCwe209ScanErrorCode:
            raise TypeError("Python CWE-209 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-209 error-message scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe209Operation(StrEnum):
    """Recognised exception-message projections."""

    RAISE_EXCEPTION = "raise_exception"
    RAISE_HTTP_EXCEPTION = "raise_http_exception"
    RAISE_VALIDATION_ERROR = "raise_validation_error"
    ABORT_WITH_MESSAGE = "abort_with_sensitive_message"
    PROPAGATE_EXCEPTION = "propagate_exception"

    # Compatibility names for consumers which describe the sink rather than
    # the syntax used to reach it.
    EXCEPTION_CONSTRUCTOR = "raise_exception"
    HTTP_EXCEPTION = "raise_http_exception"
    VALIDATION_ERROR = "raise_validation_error"
    ABORT = "abort_with_sensitive_message"


@dataclass(frozen=True, slots=True)
class PythonCwe209ScanLimits:
    """Hard ceilings for source, output, and bounded local-flow resolution."""

    max_source_bytes: int = _MAX_LIMIT_VALUES[0]
    max_signals: int = _MAX_LIMIT_VALUES[1]
    max_resolution_depth: int = _MAX_LIMIT_VALUES[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("Python CWE-209 scan limits are invalid")


DEFAULT_PYTHON_CWE209_SCAN_LIMITS = PythonCwe209ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe209Signal:
    """One immutable, source-free sensitive-value-to-error fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe209Operation
    sensitive_name: str = "sensitive_value"
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-209"
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
            and type(self.sensitive_name) is str
            and 0 < len(self.sensitive_name) <= 256
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
                self.sensitive_name,
            )
            if valid_identity
            and valid_ranges
            and type(self.operation) is PythonCwe209Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not PythonCwe209Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-209"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-209 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def variable_name(self) -> str:
        """Compatibility name for the value which reaches the error sink."""

        return self.sensitive_name

    @property
    def value_name(self) -> str:
        return self.sensitive_name

    @property
    def message_range(self) -> SourceRange:
        return self.source

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
class PythonCwe209ScanResult:
    """Deterministic, source-free CWE-209 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe209Signal, ...]
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
            type(item) is PythonCwe209Signal for item in self.signals
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
            raise ValueError("Python CWE-209 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _SensitiveFlow:
    source: SourceRange
    name: str


_EXCEPTION_NAMES = frozenset(
    {
        "BaseException",
        "Exception",
        "ArithmeticError",
        "AssertionError",
        "AttributeError",
        "BufferError",
        "EOFError",
        "FileNotFoundError",
        "IOError",
        "IndexError",
        "KeyError",
        "LookupError",
        "MemoryError",
        "NameError",
        "NotImplementedError",
        "OSError",
        "PermissionError",
        "RuntimeError",
        "StopIteration",
        "SyntaxError",
        "TimeoutError",
        "TypeError",
        "UnboundLocalError",
        "UnicodeError",
        "ValueError",
        "ZeroDivisionError",
        "HTTPException",
        "HTTPError",
        "BadRequest",
        "Unauthorized",
        "Forbidden",
        "NotFound",
        "ValidationError",
        "RequestValidationError",
        "APIError",
        "ApiError",
        "ClientError",
        "ServerError",
        "DatabaseError",
        "IntegrityError",
    }
)
_HTTP_EXCEPTION_NAMES = frozenset(
    {
        "HTTPException",
        "HTTPError",
        "werkzeug.exceptions.BadRequest",
        "werkzeug.exceptions.Unauthorized",
        "werkzeug.exceptions.Forbidden",
        "werkzeug.exceptions.NotFound",
        "starlette.exceptions.HTTPException",
        "fastapi.HTTPException",
        "requests.exceptions.HTTPError",
    }
)
_VALIDATION_EXCEPTION_NAMES = frozenset(
    {
        "ValidationError",
        "RequestValidationError",
        "pydantic.ValidationError",
        "marshmallow.ValidationError",
    }
)
_ABORT_NAMES = frozenset({"abort", "flask.abort", "fastapi.abort", "starlette.exceptions.abort"})
_EXCEPTION_MESSAGE_KEYWORDS = frozenset(
    {
        "cause",
        "description",
        "detail",
        "error",
        "errors",
        "message",
        "reason",
        "title",
    }
)
_HTTP_METADATA_KEYWORDS = frozenset({"status", "status_code", "status_code_value", "headers"})
_REQUEST_ROOTS = frozenset(
    {
        "context",
        "ctx",
        "event",
        "http_request",
        "incoming",
        "request",
        "req",
        "scope",
        "web_request",
    }
)
_REQUEST_VALUE_NAMES = frozenset(
    {
        "body",
        "content",
        "data",
        "form",
        "input",
        "params",
        "payload",
        "path_params",
        "query",
        "query_params",
        "raw_body",
        "raw_input",
        "user_input",
    }
)
_REQUEST_ATTRIBUTES = frozenset(
    {
        "args",
        "body",
        "content",
        "cookies",
        "data",
        "form",
        "GET",
        "headers",
        "json",
        "META",
        "params",
        "path_params",
        "POST",
        "query",
        "query_params",
        "raw_body",
        "values",
    }
)
_REQUEST_METHODS = frozenset(
    {
        "get",
        "get_data",
        "get_json",
        "json",
        "pop",
        "read",
        "readline",
        "values",
    }
)
_SENSITIVE_WORDS = frozenset(
    {
        "access_key",
        "accesskey",
        "api_key",
        "apikey",
        "authorization",
        "bearer",
        "certificate",
        "client_secret",
        "cookie",
        "credential",
        "credentials",
        "encryption_key",
        "jwt",
        "passcode",
        "passwd",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "session",
        "session_id",
        "session_token",
        "signing_key",
        "token",
        "user_password",
    }
)
_SENSITIVE_TOKENS = frozenset(
    {
        "access",
        "apikey",
        "authorization",
        "bearer",
        "certificate",
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
_SANITIZER_WORDS = frozenset(
    {
        "escape",
        "hash",
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
_SECRET_SOURCE_CALLS = frozenset(
    {
        "getenv",
        "os.getenv",
        "os.environ.get",
        "os.environ.__getitem__",
        "secrets.token_bytes",
        "secrets.token_hex",
        "secrets.token_urlsafe",
    }
)
_SOURCE_METHODS = frozenset({"get", "get_json", "get_data", "json", "read", "pop"})
_KNOWN_MODULES = frozenset(
    {
        "django",
        "fastapi",
        "flask",
        "marshmallow",
        "os",
        "pydantic",
        "requests",
        "secrets",
        "starlette",
        "werkzeug",
    }
)


def scan_python_cwe209(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe209ScanLimits = DEFAULT_PYTHON_CWE209_SCAN_LIMITS,
) -> PythonCwe209ScanResult:
    """Find request-derived or credential-like values in raised errors."""

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe209ScanLimits
    ):
        raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.SOURCE_LIMIT)
    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    try:
        aliases, assignments, exception_names = _collect_context(tree, limits)
        raw: list[tuple[SourceRange, SourceRange, PythonCwe209Operation, str]] = []
        for node in _bounded_nodes(tree, limits.max_resolution_depth * 10_000):
            if isinstance(node, ast.Raise):
                _record_raise(
                    node,
                    aliases,
                    assignments,
                    exception_names,
                    source,
                    line_starts,
                    limits,
                    raw,
                )
            elif isinstance(node, ast.Call):
                _record_abort(
                    node,
                    aliases,
                    assignments,
                    exception_names,
                    source,
                    line_starts,
                    limits,
                    raw,
                )
    except PythonCwe209ScanError:
        raise
    except (MemoryError, RecursionError, TypeError, ValueError):
        raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.INTEGRITY_FAILURE) from None

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
        raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe209Signal(
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
    return PythonCwe209ScanResult(
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
    tree: ast.AST,
    limits: PythonCwe209ScanLimits,
) -> tuple[
    dict[str, str | None],
    dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]],
    frozenset[str],
]:
    aliases: dict[str, str | None] = {}
    assignments: dict[str, list[tuple[tuple[int, int], ast.expr]]] = {}
    exception_names: set[str] = set()
    for node in _bounded_nodes(tree, limits.max_resolution_depth * 10_000):
        if isinstance(node, ast.Import):
            for imported in node.names:
                root = imported.name.split(".", 1)[0]
                name = imported.asname or root
                aliases[name] = imported.name if root in _KNOWN_MODULES else None
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for imported in node.names:
                if imported.name == "*":
                    continue
                name = imported.asname or imported.name
                canonical = f"{module}.{imported.name}"
                aliases[name] = (
                    canonical
                    if module in _KNOWN_MODULES or module.startswith(tuple(_KNOWN_MODULES))
                    else None
                )
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                exception_names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
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
    return aliases, {
        name: tuple(sorted(values, key=lambda item: item[0]))
        for name, values in assignments.items()
    }, frozenset(exception_names)


def _record_raise(
    node: ast.Raise,
    aliases: dict[str, str | None],
    assignments: dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]],
    exception_names: frozenset[str],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe209ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe209Operation, str]],
) -> None:
    if node.exc is None:
        return
    sink = _node_range(node, source, line_starts)
    if isinstance(node.exc, ast.Call):
        operation = _exception_operation(node.exc, aliases, limits.max_resolution_depth)
        if operation is None:
            return
        for argument in _message_values(node.exc, operation):
            if _is_sanitized(argument, aliases, limits.max_resolution_depth):
                continue
            for flow in _resolve_sensitive(
                argument,
                aliases,
                assignments,
                exception_names,
                source,
                line_starts,
                limits,
                _position(node),
            ):
                message_range = _node_range(argument, source, line_starts)
                if not sink.contains(message_range):
                    raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.INTEGRITY_FAILURE)
                output.append((message_range, sink, operation, flow.name))
                if len(output) > limits.max_signals:
                    raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.SIGNAL_LIMIT)
        return
    if isinstance(node.exc, ast.Name) and node.exc.id in exception_names:
        source_range = _node_range(node.exc, source, line_starts)
        output.append(
            (
                source_range,
                sink,
                PythonCwe209Operation.PROPAGATE_EXCEPTION,
                "exception",
            )
        )
        if len(output) > limits.max_signals:
            raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.SIGNAL_LIMIT)


def _record_abort(
    node: ast.Call,
    aliases: dict[str, str | None],
    assignments: dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]],
    exception_names: frozenset[str],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe209ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe209Operation, str]],
) -> None:
    canonical = _canonical_reference(node.func, aliases, limits.max_resolution_depth)
    if canonical is None:
        canonical = _dotted_name(node.func)
    if canonical not in _ABORT_NAMES:
        return
    sink = _node_range(node, source, line_starts)
    for argument in _message_values(node, PythonCwe209Operation.ABORT_WITH_MESSAGE):
        if _is_sanitized(argument, aliases, limits.max_resolution_depth):
            continue
        for flow in _resolve_sensitive(
            argument,
            aliases,
            assignments,
            exception_names,
            source,
            line_starts,
            limits,
            _position(node),
        ):
            message_range = _node_range(argument, source, line_starts)
            if not sink.contains(message_range):
                raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.INTEGRITY_FAILURE)
            output.append(
                (
                    message_range,
                    sink,
                    PythonCwe209Operation.ABORT_WITH_MESSAGE,
                    flow.name,
                )
            )
            if len(output) > limits.max_signals:
                raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.SIGNAL_LIMIT)


def _exception_operation(
    call: ast.Call,
    aliases: dict[str, str | None],
    max_depth: int,
) -> PythonCwe209Operation | None:
    canonical = _canonical_reference(call.func, aliases, max_depth)
    if canonical is None:
        canonical = _dotted_name(call.func)
    if not canonical:
        return None
    if canonical in _HTTP_EXCEPTION_NAMES or canonical.rsplit(".", 1)[-1] in _HTTP_EXCEPTION_NAMES:
        return PythonCwe209Operation.RAISE_HTTP_EXCEPTION
    if canonical in _VALIDATION_EXCEPTION_NAMES or canonical.rsplit(".", 1)[-1] in _VALIDATION_EXCEPTION_NAMES:
        return PythonCwe209Operation.RAISE_VALIDATION_ERROR
    if canonical in _EXCEPTION_NAMES or canonical.rsplit(".", 1)[-1] in _EXCEPTION_NAMES:
        return PythonCwe209Operation.RAISE_EXCEPTION
    tail = canonical.rsplit(".", 1)[-1]
    if tail.endswith("Error") or tail.endswith("Exception"):
        return PythonCwe209Operation.RAISE_EXCEPTION
    return None


def _message_values(call: ast.Call, operation: PythonCwe209Operation) -> tuple[ast.expr, ...]:
    values: list[ast.expr] = []
    if operation is PythonCwe209Operation.ABORT_WITH_MESSAGE:
        for index, argument in enumerate(call.args):
            if index == 0 and isinstance(argument, ast.Constant) and type(argument.value) is int:
                continue
            values.append(argument)
    elif operation is PythonCwe209Operation.RAISE_HTTP_EXCEPTION:
        for index, argument in enumerate(call.args):
            if index == 0 and isinstance(argument, ast.Constant) and type(argument.value) is int:
                continue
            values.append(argument)
    else:
        values.extend(call.args)
    values.extend(
        keyword.value
        for keyword in call.keywords
        if keyword.arg is None or keyword.arg in _EXCEPTION_MESSAGE_KEYWORDS
        and keyword.arg not in _HTTP_METADATA_KEYWORDS
    )
    return tuple(values)


def _resolve_sensitive(
    node: ast.expr,
    aliases: dict[str, str | None],
    assignments: dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]],
    exception_names: frozenset[str],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe209ScanLimits,
    position: tuple[int, int],
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> tuple[_SensitiveFlow, ...]:
    if depth > limits.max_resolution_depth:
        raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.SIGNAL_LIMIT)
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
                exception_names,
                source,
                line_starts,
                limits,
                position,
                depth + 1,
                seen | {node.id},
            )
            if flows:
                return flows
            return ()
        if node.id in exception_names:
            return (_SensitiveFlow(_node_range(node, source, line_starts), "exception"),)
        if _is_request_name(node.id):
            return (_SensitiveFlow(_node_range(node, source, line_starts), _label(node.id)),)
        if _is_sensitive_name(node.id):
            return (_SensitiveFlow(_node_range(node, source, line_starts), _label(node.id)),)
        return ()
    if isinstance(node, ast.Attribute):
        if _is_request_access(node, aliases, limits.max_resolution_depth):
            return (_SensitiveFlow(_node_range(node, source, line_starts), _label(_dotted_name(node))),)
        if _is_sensitive_name(node.attr):
            return (_SensitiveFlow(_node_range(node, source, line_starts), _label(node.attr)),)
        return _resolve_sensitive(
            node.value,
            aliases,
            assignments,
            exception_names,
            source,
            line_starts,
            limits,
            position,
            depth + 1,
            seen,
        )
    if isinstance(node, ast.Subscript):
        if _is_request_access(node, aliases, limits.max_resolution_depth):
            return (_SensitiveFlow(_node_range(node, source, line_starts), _label(_dotted_name(node.value))),)
        label = _subscript_label(node)
        if _is_sensitive_name(label):
            return (_SensitiveFlow(_node_range(node, source, line_starts), _label(label)),)
        return _resolve_sensitive(
            node.value,
            aliases,
            assignments,
            exception_names,
            source,
            line_starts,
            limits,
            position,
            depth + 1,
            seen,
        )
    if isinstance(node, ast.Call):
        canonical = _canonical_reference(node.func, aliases, limits.max_resolution_depth) or _dotted_name(node.func)
        if _is_sanitizer(canonical):
            return ()
        if _is_request_source_call(node, canonical, aliases, limits.max_resolution_depth):
            return (_SensitiveFlow(_node_range(node, source, line_starts), _label(canonical)),)
        if _is_secret_source_call(node, canonical):
            return (_SensitiveFlow(_node_range(node, source, line_starts), _label(canonical)),)
        return _dedupe_flows(
            flow
            for value in (*node.args, *(keyword.value for keyword in node.keywords))
            for flow in _resolve_sensitive(
                value,
                aliases,
                assignments,
                exception_names,
                source,
                line_starts,
                limits,
                position,
                depth + 1,
                seen,
            )
        )
    if isinstance(node, ast.NamedExpr):
        return _resolve_sensitive(
            node.value,
            aliases,
            assignments,
            exception_names,
            source,
            line_starts,
            limits,
            position,
            depth + 1,
            seen,
        )
    if isinstance(node, ast.Await):
        return _resolve_sensitive(
            node.value,
            aliases,
            assignments,
            exception_names,
            source,
            line_starts,
            limits,
            position,
            depth + 1,
            seen,
        )
    if isinstance(node, (ast.BinOp, ast.BoolOp, ast.Compare, ast.IfExp, ast.JoinedStr, ast.FormattedValue, ast.UnaryOp)):
        return _dedupe_flows(
            flow
            for child in ast.iter_child_nodes(node)
            if isinstance(child, ast.expr)
            for flow in _resolve_sensitive(
                child,
                aliases,
                assignments,
                exception_names,
                source,
                line_starts,
                limits,
                position,
                depth + 1,
                seen,
            )
        )
    if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
        return _dedupe_flows(
            flow
            for child in ast.iter_child_nodes(node)
            if isinstance(child, ast.expr)
            for flow in _resolve_sensitive(
                child,
                aliases,
                assignments,
                exception_names,
                source,
                line_starts,
                limits,
                position,
                depth + 1,
                seen,
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
    return any(word in normalized for word in _SANITIZER_WORDS)


def _is_request_source_call(
    call: ast.Call,
    canonical: str | None,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    if not canonical:
        return False
    tail = canonical.rsplit(".", 1)[-1]
    if tail not in _REQUEST_METHODS:
        return False
    if isinstance(call.func, ast.Attribute):
        receiver = _canonical_reference(call.func.value, aliases, max_depth) or _dotted_name(call.func.value)
        return _is_request_access_name(receiver)
    return False


def _is_secret_source_call(call: ast.Call, canonical: str | None) -> bool:
    if canonical in _SECRET_SOURCE_CALLS:
        if canonical in {"os.getenv", "os.environ.get", "os.environ.__getitem__"}:
            if not call.args:
                return False
            literal = _literal_string(call.args[0])
            return literal is None or _is_sensitive_name(literal)
        return True
    return False


def _is_request_access(node: ast.AST, aliases: dict[str, str | None], max_depth: int) -> bool:
    if isinstance(node, ast.Subscript):
        return _is_request_access(node.value, aliases, max_depth)
    canonical = _canonical_reference(node, aliases, max_depth) or _dotted_name(node)
    return _is_request_access_name(canonical)


def _is_request_access_name(value: str | None) -> bool:
    if not value:
        return False
    parts = value.split(".")
    if not parts or parts[0] not in _REQUEST_ROOTS:
        return False
    if len(parts) == 1:
        return True
    return parts[1] in _REQUEST_ATTRIBUTES or parts[-1] in _REQUEST_METHODS


def _is_request_name(value: str) -> bool:
    normalized = _normalise_name(value)
    return normalized in _REQUEST_ROOTS or normalized in _REQUEST_VALUE_NAMES


def _is_sensitive_name(value: str) -> bool:
    normalized = _normalise_name(value)
    if not normalized:
        return False
    if normalized in _SENSITIVE_WORDS:
        return True
    tokens = set(normalized.split("_"))
    return bool(tokens & _SENSITIVE_TOKENS) and not bool(
        tokens & {"public", "masked", "redacted", "safe", "sanitized"}
    )


def _normalise_name(value: str) -> str:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value).lower()
    return re.sub(r"[^a-z0-9]+", "_", normalized).strip("_")


def _label(value: str) -> str:
    return _normalise_name(value)[:256] or "sensitive_value"


def _canonical_reference(
    node: ast.AST,
    aliases: dict[str, str | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.SIGNAL_LIMIT)
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


def _subscript_label(node: ast.Subscript) -> str:
    if isinstance(node.slice, ast.Constant) and type(node.slice.value) is str:
        return node.slice.value
    return _dotted_name(node.value)


def _position(node: ast.AST) -> tuple[int, int]:
    return (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))


def _bounded_nodes(tree: ast.AST, limit: int) -> tuple[ast.AST, ...]:
    if type(limit) is not int or limit < 1:
        raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.REQUEST_INVALID)
    result: list[ast.AST] = []
    stack: list[tuple[ast.AST, int]] = [(tree, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.SIGNAL_LIMIT)
        result.append(node)
        stack.extend((child, depth + 1) for child in reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(result)


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
        raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe209ScanError(PythonCwe209ScanErrorCode.INTEGRITY_FAILURE)
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
    operation: PythonCwe209Operation,
    sensitive_name: str,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-209",
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
    signals: tuple[PythonCwe209Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-209",
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
