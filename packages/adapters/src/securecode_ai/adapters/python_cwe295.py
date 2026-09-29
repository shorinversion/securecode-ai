"""Bounded Python facts for CWE-295 improper certificate validation.

The adapter works only with an admitted :class:`SymbolIndex` and the sealed
CPython AST analysis for that index.  It recognises explicit client-side TLS
validation bypasses in requests, httpx, urllib3, and ssl.  Unknown aliases,
dynamic attribute names, malformed syntax, and unresolved flow are treated
conservatively.  Results contain source ranges and content-addressed metadata
only; source bytes are never retained in a result or an exception.
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
_RULE_ID = "securecode-python-cwe295"
_DETECTOR = "securecode-python-cwe295@1.0"
_DETAIL = "tls_peer_verification_disabled"

_REQUEST_METHODS = frozenset(
    {"delete", "get", "head", "options", "patch", "post", "put", "request"}
)
_REQUEST_CALLS = frozenset(
    {
        "requests.request",
        "requests.api.request",
        "requests.sessions.Session",
    }
)
_HTTPX_CALLS = frozenset({"httpx.request", "httpx.Client", "httpx.AsyncClient"})
_URLLIB3_CALLS = frozenset(
    {
        "urllib3.PoolManager",
        "urllib3.ProxyManager",
        "urllib3.HTTPSConnectionPool",
        "urllib3.HTTPConnectionPool",
        "urllib3.connection.HTTPSConnection",
        "urllib3.util.ssl_.create_urllib3_context",
        "urllib3.util.ssl.create_urllib3_context",
    }
)
_SSL_CONTEXT_CALLS = frozenset(
    {
        "ssl.SSLContext",
        "_ssl.SSLContext",
    }
)
_UNVERIFIED_CONTEXT_CALLS = frozenset(
    {
        "ssl._create_unverified_context",
        "_ssl._create_unverified_context",
    }
)
_SSL_WRAP_CALLS = frozenset({"ssl.wrap_socket", "_ssl.wrap_socket"})
_SSL_PROTOCOL_SERVER = frozenset({"ssl.PROTOCOL_TLS_SERVER", "_ssl.PROTOCOL_TLS_SERVER"})
_SSL_CERT_NONE = frozenset({"ssl.CERT_NONE", "_ssl.CERT_NONE"})
_SERVER_METHODS = frozenset({"wrap_socket", "wrap_bio"})
_CONTEXT_FACTORY_CALLS = frozenset(
    {
        "ssl.create_default_context",
        "_ssl.create_default_context",
        "ssl._create_unverified_context",
        "_ssl._create_unverified_context",
        "ssl.SSLContext",
        "_ssl.SSLContext",
    }
)


class PythonCwe295ScanErrorCode(StrEnum):
    """Closed, source-free reasons a certificate scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe295ScanError(RuntimeError):
    """Fixed scanner failure which never echoes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe295ScanErrorCode) -> None:
        if type(code) is not PythonCwe295ScanErrorCode:
            raise TypeError("Python CWE-295 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-295 certificate validation scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe295Operation(StrEnum):
    """Recognised operations which disable TLS peer validation."""

    REQUESTS_VERIFY_FALSE = "requests.verify_false"
    HTTPX_VERIFY_FALSE = "httpx.verify_false"
    URLLIB3_CERT_NONE = "urllib3.cert_reqs_cert_none"
    URLLIB3_ASSERT_HOSTNAME_FALSE = "urllib3.assert_hostname_false"
    SSL_CERT_NONE = "ssl.cert_none"
    SSL_CHECK_HOSTNAME_FALSE = "ssl.check_hostname_false"
    SSL_UNVERIFIED_CONTEXT = "ssl.unverified_context"

    # Compatibility names for generic consumers.
    REQUEST_VERIFY_FALSE = "requests.verify_false"
    REQUESTS_VERIFY = "requests.verify_false"
    HTTPX_VERIFY_DISABLED = "httpx.verify_false"
    HTTPX_VERIFY = "httpx.verify_false"
    CERT_NONE = "ssl.cert_none"
    SSL_VERIFY_MODE_CERT_NONE = "ssl.cert_none"
    CHECK_HOSTNAME_FALSE = "ssl.check_hostname_false"
    SSL_HOSTNAME_DISABLED = "ssl.check_hostname_false"
    URLLIB3_CERT_REQS_NONE = "urllib3.cert_reqs_cert_none"
    URLLIB3_HOSTNAME_DISABLED = "urllib3.assert_hostname_false"
    CREATE_UNVERIFIED_CONTEXT = "ssl.unverified_context"


@dataclass(frozen=True, slots=True)
class PythonCwe295ScanLimits:
    """Hard ceilings for source, output, and local alias resolution."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_resolution_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Python CWE-295 scan limits are invalid")


DEFAULT_PYTHON_CWE295_SCAN_LIMITS = PythonCwe295ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe295Signal:
    """One immutable TLS peer-validation bypass fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe295Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-295"
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
            if valid_identity and valid_ranges and type(self.operation) is PythonCwe295Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not PythonCwe295Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-295"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-295 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete insecure configuration location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class PythonCwe295ScanResult:
    """Source-free, deterministic CWE-295 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe295Signal, ...]
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
            type(item) is PythonCwe295Signal for item in self.signals
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
            raise ValueError("Python CWE-295 scan result is invalid")


def scan_python_cwe295(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe295ScanLimits = DEFAULT_PYTHON_CWE295_SCAN_LIMITS,
) -> PythonCwe295ScanResult:
    """Find bounded Python TLS-validation bypasses in one sealed file."""

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe295ScanLimits
    ):
        raise PythonCwe295ScanError(PythonCwe295ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe295ScanError(PythonCwe295ScanErrorCode.SOURCE_LIMIT)

    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe295ScanError(PythonCwe295ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe295ScanError(PythonCwe295ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe295ScanError(PythonCwe295ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    try:
        aliases = _collect_aliases(tree, limits.max_resolution_depth)
        context_names, server_names, safe_calls = _collect_context_roles(tree, aliases)
        raw: set[tuple[SourceRange, SourceRange, PythonCwe295Operation]] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                _record_call(
                    node,
                    aliases,
                    context_names,
                    safe_calls,
                    source,
                    line_starts,
                    limits,
                    raw,
                )
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                _record_assignment(
                    node,
                    aliases,
                    server_names,
                    source,
                    line_starts,
                    limits,
                    raw,
                )
            if len(raw) > limits.max_signals:
                raise PythonCwe295ScanError(PythonCwe295ScanErrorCode.SIGNAL_LIMIT)
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
    except PythonCwe295ScanError:
        raise
    except Exception:
        raise PythonCwe295ScanError(PythonCwe295ScanErrorCode.INTEGRITY_FAILURE) from None

    if len(ordered) > limits.max_signals:
        raise PythonCwe295ScanError(PythonCwe295ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe295Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
        )
        for source_range, sink_range, operation in ordered
    )
    return PythonCwe295ScanResult(
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


def scan_python_tls_validation(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe295ScanLimits = DEFAULT_PYTHON_CWE295_SCAN_LIMITS,
) -> PythonCwe295ScanResult:
    """Descriptive alias for :func:`scan_python_cwe295`."""

    return scan_python_cwe295(symbol_index, ast_analysis, limits=limits)


def scan_python_certificate_validation(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe295ScanLimits = DEFAULT_PYTHON_CWE295_SCAN_LIMITS,
) -> PythonCwe295ScanResult:
    """Compatibility alias for callers grouping TLS scanners."""

    return scan_python_cwe295(symbol_index, ast_analysis, limits=limits)


scan_python_tls_certificate_validation = scan_python_cwe295


def _collect_aliases(tree: ast.AST, max_depth: int) -> dict[str, str | None]:
    aliases: dict[str, str | None] = {}
    nodes = sorted(
        ast.walk(tree),
        key=lambda node: (
            getattr(node, "lineno", 0),
            getattr(node, "col_offset", 0),
        ),
    )
    for node in nodes:
        if isinstance(node, ast.Import):
            for imported in node.names:
                root = imported.name.split(".", 1)[0]
                aliases[imported.asname or root] = (
                    imported.name if imported.name in _KNOWN_MODULES else None
                )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for imported in node.names:
                name = imported.asname or imported.name
                if imported.name == "*" or node.level:
                    aliases[name] = None
                else:
                    canonical = f"{module}.{imported.name}"
                    aliases[name] = canonical if canonical in _KNOWN_IMPORTS else None
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, (ast.Name, ast.Attribute)):
                    aliases[_dotted_name(target)] = _canonical_reference(
                        node.value, aliases, max_depth
                    )
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target = node.target
            if isinstance(target, (ast.Name, ast.Attribute)):
                aliases[_dotted_name(target)] = _canonical_reference(node.value, aliases, max_depth)
    return aliases


_KNOWN_MODULES = frozenset(
    {
        "requests",
        "requests.api",
        "requests.sessions",
        "httpx",
        "urllib3",
        "urllib3.util",
        "urllib3.util.ssl_",
        "urllib3.util.ssl",
        "ssl",
        "_ssl",
        "urllib",
        "urllib.request",
    }
)
_KNOWN_IMPORTS = frozenset(
    {
        *{
            f"{module}.{member}"
            for module, members in {
                "requests": {
                    "get",
                    "post",
                    "put",
                    "delete",
                    "head",
                    "options",
                    "patch",
                    "request",
                    "Session",
                },
                "httpx": {
                    "get",
                    "post",
                    "put",
                    "delete",
                    "head",
                    "options",
                    "patch",
                    "request",
                    "Client",
                    "AsyncClient",
                },
                "urllib3": {
                    "PoolManager",
                    "ProxyManager",
                    "HTTPSConnectionPool",
                    "HTTPConnectionPool",
                },
                "urllib3.util.ssl_": {"create_urllib3_context"},
                "urllib3.util.ssl": {"create_urllib3_context"},
                "ssl": {
                    "SSLContext",
                    "CERT_NONE",
                    "PROTOCOL_TLS_SERVER",
                    "create_default_context",
                    "_create_unverified_context",
                    "wrap_socket",
                },
                "_ssl": {
                    "SSLContext",
                    "CERT_NONE",
                    "PROTOCOL_TLS_SERVER",
                    "create_default_context",
                    "_create_unverified_context",
                    "wrap_socket",
                },
            }.items()
            for member in members
        }
    }
)


def _collect_context_roles(
    tree: ast.AST, aliases: dict[str, str | None]
) -> tuple[set[str], set[str], set[int]]:
    contexts: set[str] = set()
    servers: set[str] = set()
    safe_calls: set[int] = set()
    assignments = sorted(
        (node for node in ast.walk(tree) if isinstance(node, (ast.Assign, ast.AnnAssign))),
        key=lambda node: (getattr(node, "lineno", 0), getattr(node, "col_offset", 0)),
    )
    for node in assignments:
        value = node.value
        if not isinstance(value, ast.expr):
            continue
        canonical = _canonical_reference(value, aliases, 64)
        base_name = _assignment_base(node)
        if base_name is None:
            continue
        if _is_context_factory(value, canonical):
            contexts.add(base_name)
            if _uses_server_protocol(value, aliases):
                servers.add(base_name)
        elif _dotted_name(value) in contexts:
            contexts.add(base_name)
            if _dotted_name(value) in servers:
                servers.add(base_name)

    for walked in ast.walk(tree):
        if not isinstance(walked, ast.Call):
            continue
        call = walked
        if not _server_side_true(call):
            continue
        context_argument = _keyword(call, "ssl_context")
        if context_argument is not None:
            name = _dotted_name(context_argument)
            if name in contexts:
                servers.add(name)
            if isinstance(context_argument, ast.Call):
                safe_calls.add(id(context_argument))
        if isinstance(call.func, ast.Attribute) and call.func.attr in _SERVER_METHODS:
            name = _dotted_name(call.func.value)
            if name in contexts:
                servers.add(name)
        canonical = _canonical_reference(call.func, aliases, 64)
        if canonical in _SSL_WRAP_CALLS:
            value = _keyword(call, "ssl_context")
            if value is not None and isinstance(value, ast.Call):
                safe_calls.add(id(value))
        if canonical == "asyncio.start_server":
            value = _keyword(call, "ssl")
            name = _dotted_name(value) if value is not None else ""
            if name in contexts:
                servers.add(name)
    for node in assignments:
        value = node.value
        base_name = _assignment_base(node)
        if base_name in servers and isinstance(value, ast.Call):
            safe_calls.add(id(value))
    return contexts, servers, safe_calls


def _record_call(
    call: ast.Call,
    aliases: dict[str, str | None],
    context_names: set[str],
    safe_calls: set[int],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe295ScanLimits,
    output: set[tuple[SourceRange, SourceRange, PythonCwe295Operation]],
) -> None:
    canonical = _canonical_reference(call.func, aliases, limits.max_resolution_depth)
    findings: list[tuple[PythonCwe295Operation, ast.expr]] = []
    if canonical in _UNVERIFIED_CONTEXT_CALLS:
        if id(call) in safe_calls:
            return
        findings.append((PythonCwe295Operation.SSL_UNVERIFIED_CONTEXT, call))
    elif _is_requests_call(canonical):
        value_node = _keyword(call, "verify")
        if value_node is not None and _is_false(value_node):
            findings.append((PythonCwe295Operation.REQUESTS_VERIFY_FALSE, value_node))
    elif _is_httpx_call(canonical):
        value_node = _keyword(call, "verify")
        if value_node is not None and _is_false(value_node):
            findings.append((PythonCwe295Operation.HTTPX_VERIFY_FALSE, value_node))
    elif canonical in _URLLIB3_CALLS or (
        canonical is not None and canonical.startswith("urllib3.")
    ):
        value_node = _keyword(call, "cert_reqs")
        if value_node is not None and _is_cert_none(
            value_node, aliases, limits.max_resolution_depth
        ):
            findings.append((PythonCwe295Operation.URLLIB3_CERT_NONE, value_node))
        value_node = _keyword(call, "assert_hostname")
        if value_node is not None and _is_false(value_node):
            findings.append((PythonCwe295Operation.URLLIB3_ASSERT_HOSTNAME_FALSE, value_node))
    elif canonical in _SSL_WRAP_CALLS or _is_context_method(call, context_names):
        if _server_side_true(call):
            return
        value_node = _keyword(call, "cert_reqs")
        if value_node is not None and _is_cert_none(
            value_node, aliases, limits.max_resolution_depth
        ):
            findings.append((PythonCwe295Operation.SSL_CERT_NONE, value_node))
    elif canonical in {"ssl.create_default_context", "_ssl.create_default_context"}:
        value_node = _keyword(call, "check_hostname")
        if value_node is not None and _is_false(value_node):
            findings.append((PythonCwe295Operation.SSL_CHECK_HOSTNAME_FALSE, value_node))
    if not findings:
        return
    sink = _node_range(call, source, line_starts)
    for operation, value_node in findings:
        source_range = _node_range(value_node, source, line_starts)
        if not sink.contains(source_range):
            raise PythonCwe295ScanError(PythonCwe295ScanErrorCode.INTEGRITY_FAILURE)
        output.add((source_range, sink, operation))


def _record_assignment(
    statement: ast.Assign | ast.AnnAssign,
    aliases: dict[str, str | None],
    server_names: set[str],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe295ScanLimits,
    output: set[tuple[SourceRange, SourceRange, PythonCwe295Operation]],
) -> None:
    value = statement.value
    if value is None:
        return
    targets = statement.targets if isinstance(statement, ast.Assign) else (statement.target,)
    for target in targets:
        if not isinstance(target, ast.Attribute):
            continue
        attribute = target.attr
        base_name = _dotted_name(target.value)
        if not base_name:
            continue
        if base_name in server_names:
            continue
        operation: PythonCwe295Operation | None = None
        if attribute == "verify_mode" and _is_cert_none(
            value, aliases, limits.max_resolution_depth
        ):
            operation = PythonCwe295Operation.SSL_CERT_NONE
        elif attribute == "check_hostname" and _is_false(value):
            operation = PythonCwe295Operation.SSL_CHECK_HOSTNAME_FALSE
        elif attribute == "assert_hostname" and _is_false(value):
            operation = PythonCwe295Operation.URLLIB3_ASSERT_HOSTNAME_FALSE
        if operation is None:
            continue
        sink = _node_range(statement, source, line_starts)
        source_range = _node_range(value, source, line_starts)
        if not sink.contains(source_range):
            raise PythonCwe295ScanError(PythonCwe295ScanErrorCode.INTEGRITY_FAILURE)
        output.add((source_range, sink, operation))


def _is_requests_call(canonical: str | None) -> bool:
    if canonical is None:
        return False
    if canonical in _REQUEST_CALLS:
        return True
    receiver, _, method = canonical.rpartition(".")
    return method in _REQUEST_METHODS and (
        receiver in {"requests", "requests.api", "requests.sessions.Session"}
        or receiver.endswith(".Session")
    )


def _is_httpx_call(canonical: str | None) -> bool:
    if canonical is None:
        return False
    if canonical in _HTTPX_CALLS:
        return True
    receiver, _, method = canonical.rpartition(".")
    return method in _REQUEST_METHODS and (
        receiver in {"httpx", "httpx.Client", "httpx.AsyncClient"}
        or receiver.endswith((".Client", ".AsyncClient"))
    )


def _is_context_method(call: ast.Call, context_names: set[str]) -> bool:
    if not isinstance(call.func, ast.Attribute) or call.func.attr not in _SERVER_METHODS:
        return False
    return _dotted_name(call.func.value) in context_names


def _is_context_factory(value: ast.expr, canonical: str | None) -> bool:
    if not isinstance(value, ast.Call):
        return False
    return canonical in _CONTEXT_FACTORY_CALLS


def _uses_server_protocol(value: ast.expr, aliases: dict[str, str | None]) -> bool:
    if not isinstance(value, ast.Call):
        return False
    protocol = value.args[0] if value.args else _keyword(value, "protocol")
    return (
        _canonical_reference(protocol, aliases, 64) in _SSL_PROTOCOL_SERVER if protocol else False
    )


def _server_side_true(call: ast.Call) -> bool:
    value = _keyword(call, "server_side")
    return isinstance(value, ast.Constant) and value.value is True


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _is_false(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_cert_none(
    node: ast.expr | None,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    if node is None:
        return False
    if _canonical_reference(node, aliases, max_depth) in _SSL_CERT_NONE:
        return True
    return isinstance(node, ast.Constant) and node.value == "CERT_NONE"


def _canonical_reference(
    node: ast.AST | None,
    aliases: dict[str, str | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if node is None:
        return None
    if depth > max_depth:
        raise PythonCwe295ScanError(PythonCwe295ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        return aliases.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Subscript):
        return _canonical_reference(node.value, aliases, max_depth, depth + 1)
    if isinstance(node, ast.Call):
        if _dotted_name(node.func) not in {"getattr", "builtins.getattr"}:
            return _canonical_reference(node.func, aliases, max_depth, depth + 1)
        if len(node.args) < 2 or node.keywords:
            return None
        base = _canonical_reference(node.args[0], aliases, max_depth, depth + 1)
        member = _literal_string(node.args[1])
        return None if base is None or member is None else f"{base}.{member}"
    return None


def _dotted_name(node: ast.AST | None) -> str:
    if node is None:
        return ""
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    else:
        return ""
    return ".".join(reversed(parts))


def _assignment_base(node: ast.Assign | ast.AnnAssign) -> str | None:
    targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
    for target in targets:
        if isinstance(target, (ast.Name, ast.Attribute)):
            value = _dotted_name(target)
            if value:
                return value
    return None


def _literal_string(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None


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
        raise PythonCwe295ScanError(PythonCwe295ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe295ScanError(PythonCwe295ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe295ScanError(PythonCwe295ScanErrorCode.INTEGRITY_FAILURE)
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
    operation: PythonCwe295Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-295",
        "detector": _DETECTOR,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
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
    signals: tuple[PythonCwe295Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-295",
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


# Compatibility aliases keep this adapter usable beside the other CWE modules.
Cwe295ScanErrorCode = PythonCwe295ScanErrorCode
Cwe295ScanError = PythonCwe295ScanError
Cwe295ScanLimits = PythonCwe295ScanLimits
Cwe295ScanResult = PythonCwe295ScanResult
Cwe295Signal = PythonCwe295Signal


__all__ = [
    "DEFAULT_PYTHON_CWE295_SCAN_LIMITS",
    "Cwe295ScanError",
    "Cwe295ScanErrorCode",
    "Cwe295ScanLimits",
    "Cwe295ScanResult",
    "Cwe295Signal",
    "PythonCwe295Operation",
    "PythonCwe295ScanError",
    "PythonCwe295ScanErrorCode",
    "PythonCwe295ScanLimits",
    "PythonCwe295ScanResult",
    "PythonCwe295Signal",
    "scan_python_certificate_validation",
    "scan_python_cwe295",
    "scan_python_tls_certificate_validation",
    "scan_python_tls_validation",
]
