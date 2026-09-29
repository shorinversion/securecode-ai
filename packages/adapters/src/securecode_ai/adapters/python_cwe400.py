"""Bounded Python CWE-400 uncontrolled resource-consumption facts.

The adapter follows request and body values through a small, bounded local
data-flow analysis.  It reports those values when they reach unbounded stream
reads, decompression, JSON parsing, or archive extraction.  Explicit byte,
output, or member limits terminate the flow.  Results contain only immutable
identity, source ranges, and content-addressed identifiers; source text and
parser diagnostics never leave this module.
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
_RULE_ID = "securecode-python-cwe400"
_DETECTOR = "securecode-python-cwe400@1.0"


class PythonCwe400ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-400 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe400ScanError(RuntimeError):
    """Fixed scanner failure which never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe400ScanErrorCode) -> None:
        if type(code) is not PythonCwe400ScanErrorCode:
            raise TypeError("Python CWE-400 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-400 resource-consumption scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class PythonCwe400ScanLimits:
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
            raise ValueError("Python CWE-400 scan limits are invalid")


DEFAULT_PYTHON_CWE400_SCAN_LIMITS = PythonCwe400ScanLimits()


class PythonCwe400Operation(StrEnum):
    """Recognised unbounded stream, parser, decompression, and archive sinks."""

    STREAM_READ = "stream_read"
    STREAM_READLINE = "stream_readline"
    STREAM_READLINES = "stream_readlines"
    STREAM_READINTO = "stream_readinto"
    STREAM_READ_ALL = "stream_read_all"
    SHUTIL_COPYFILEOBJ = "shutil.copyfileobj"
    GZIP_DECOMPRESS = "gzip.decompress"
    ZLIB_DECOMPRESS = "zlib.decompress"
    BZ2_DECOMPRESS = "bz2.decompress"
    LZMA_DECOMPRESS = "lzma.decompress"
    DECOMPRESSION = "decompression"
    JSON_LOAD = "json.load"
    JSON_LOADS = "json.loads"
    ZIP_EXTRACTALL = "zipfile.extractall"
    ZIP_EXTRACT = "zipfile.extract"
    TAR_EXTRACTALL = "tarfile.extractall"
    TAR_EXTRACT = "tarfile.extract"
    SHUTIL_UNPACK_ARCHIVE = "shutil.unpack_archive"

    # Compatibility names used by generic scanner consumers.
    READ = "stream_read"
    READ_ALL = "stream_read_all"
    ARCHIVE_EXTRACTION = "zipfile.extractall"


@dataclass(frozen=True, slots=True)
class PythonCwe400Signal:
    """One immutable, source-free uncontrolled-consumption fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe400Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-400"
    detector: str = _DETECTOR
    detail: str = "unbounded_resource_consumption"

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
            )
            if identity_valid and ranges_valid and type(self.operation) is PythonCwe400Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not PythonCwe400Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-400"
            or self.detector != _DETECTOR
            or self.detail != "unbounded_resource_consumption"
        ):
            raise ValueError("Python CWE-400 signal is invalid")
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
class PythonCwe400ScanResult:
    """Deterministic, source-free CWE-400 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe400Signal, ...]
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
            type(item) is PythonCwe400Signal for item in self.signals
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
            raise ValueError("Python CWE-400 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange
    bounded: bool = False


_KNOWN_MODULES = frozenset(
    {
        "bz2",
        "gzip",
        "io",
        "json",
        "lzma",
        "os",
        "shutil",
        "tarfile",
        "tempfile",
        "zipfile",
        "zlib",
    }
)
_REQUEST_ROOTS = frozenset(
    {
        "context",
        "event",
        "http_request",
        "incoming",
        "req",
        "request",
        "scope",
    }
)
_REQUEST_ATTRIBUTES = frozenset(
    {
        "args",
        "body",
        "content",
        "data",
        "form",
        "GET",
        "headers",
        "json",
        "POST",
        "path_params",
        "payload",
        "query",
        "query_params",
        "query_string",
        "raw_body",
        "stream",
        "values",
    }
)
_REQUEST_ACCESS_METHODS = frozenset(
    {"body", "get", "get_data", "get_json", "json", "read", "readline", "stream"}
)
_PARAMETER_NAMES = frozenset(
    {
        "body",
        "content",
        "data",
        "input",
        "payload",
        "request_body",
        "stream",
    }
)
_FLOW_PRESERVING_CALLS = frozenset(
    {
        "bytes",
        "bytearray",
        "memoryview",
        "str",
        "io.BytesIO",
        "io.BufferedReader",
        "io.BufferedReader.raw",
        "io.BytesIO.getvalue",
        "open",
        "builtins.open",
        "os.fspath",
    }
)
_FLOW_PRESERVING_METHODS = frozenset(
    {
        "decode",
        "encode",
        "join",
        "lower",
        "lstrip",
        "replace",
        "rstrip",
        "strip",
        "translate",
        "upper",
    }
)
_READ_METHODS = frozenset(
    {"read", "read1", "readall", "read_all", "readinto", "readline", "readlines"}
)
_DECOMPRESS_NAMES = frozenset(
    {
        "bz2.decompress",
        "gzip.decompress",
        "lzma.decompress",
        "zlib.decompress",
        "zlib.decompressobj",
        "gzip.GzipFile",
        "bz2.BZ2File",
        "lzma.LZMAFile",
    }
)
_ARCHIVE_NAMES = frozenset(
    {
        "tarfile.open",
        "tarfile.TarFile",
        "zipfile.ZipFile",
        "zipfile.ZipFile.open",
        "shutil.unpack_archive",
    }
)
_LIMIT_WORDS = frozenset(
    {
        "bound",
        "bounded",
        "cap",
        "capped",
        "limit",
        "limited",
        "max",
        "maximum",
        "truncate",
    }
)
_LIMIT_KEYWORDS = frozenset(
    {
        "bufsize",
        "hint",
        "limit",
        "max_bytes",
        "max_entries",
        "max_length",
        "max_members",
        "max_output_length",
        "max_size",
        "size",
    }
)


def scan_python_cwe400(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe400ScanLimits = DEFAULT_PYTHON_CWE400_SCAN_LIMITS,
) -> PythonCwe400ScanResult:
    """Find request-derived values reaching unbounded resource consumers."""

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe400ScanLimits
    ):
        raise PythonCwe400ScanError(PythonCwe400ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe400ScanError(PythonCwe400ScanErrorCode.SOURCE_LIMIT)
    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe400ScanError(PythonCwe400ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe400ScanError(PythonCwe400ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe400ScanError(PythonCwe400ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases: dict[str, str | None] = {}
    flows: dict[str, tuple[_Flow, ...]] = {}
    raw: list[tuple[SourceRange, SourceRange, PythonCwe400Operation]] = []
    try:
        _scan_statements(tree.body, aliases, flows, source, line_starts, limits, raw)
    except PythonCwe400ScanError:
        raise
    except (MemoryError, RecursionError, TypeError, ValueError):
        raise PythonCwe400ScanError(PythonCwe400ScanErrorCode.INTEGRITY_FAILURE) from None
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
        raise PythonCwe400ScanError(PythonCwe400ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe400Signal(
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
    return PythonCwe400ScanResult(
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
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe400ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe400Operation]],
) -> None:
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            child_aliases = dict(aliases)
            child_flows = dict(flows)
            for parameter in (
                *statement.args.posonlyargs,
                *statement.args.args,
                *statement.args.kwonlyargs,
            ):
                child_aliases[parameter.arg] = None
                if parameter.arg.lower() in _PARAMETER_NAMES:
                    child_flows[parameter.arg] = (
                        _Flow(_node_range(parameter, source, line_starts)),
                    )
                else:
                    child_flows.pop(parameter.arg, None)
            if statement.args.vararg is not None:
                child_aliases[statement.args.vararg.arg] = None
                if statement.args.vararg.arg.lower() in _PARAMETER_NAMES:
                    child_flows[statement.args.vararg.arg] = (
                        _Flow(_node_range(statement.args.vararg, source, line_starts)),
                    )
                else:
                    child_flows.pop(statement.args.vararg.arg, None)
            if statement.args.kwarg is not None:
                child_aliases[statement.args.kwarg.arg] = None
                if statement.args.kwarg.arg.lower() in _PARAMETER_NAMES:
                    child_flows[statement.args.kwarg.arg] = (
                        _Flow(_node_range(statement.args.kwarg, source, line_starts)),
                    )
                else:
                    child_flows.pop(statement.args.kwarg.arg, None)
            _scan_statements(
                statement.body, child_aliases, child_flows, source, line_starts, limits, output
            )
            aliases[statement.name] = None
            flows.pop(statement.name, None)
            continue
        if isinstance(statement, ast.ClassDef):
            child_aliases, child_flows = dict(aliases), dict(flows)
            _scan_statements(
                statement.body, child_aliases, child_flows, source, line_starts, limits, output
            )
            aliases[statement.name] = None
            flows.pop(statement.name, None)
            continue

        if isinstance(statement, ast.Import):
            _record_imports(statement, aliases)
        elif isinstance(statement, ast.ImportFrom):
            _record_import_from(statement, aliases)
        _scan_statement_calls(statement, aliases, flows, source, line_starts, limits, output)
        _record_assignment(statement, aliases, flows, source, line_starts, limits)
        _record_with_bindings(statement, aliases, flows, source, line_starts, limits)
        _record_scope_bindings(statement, aliases, flows)

        if isinstance(statement, (ast.If, ast.For, ast.AsyncFor, ast.While)):
            left_aliases, left_flows = dict(aliases), dict(flows)
            right_aliases, right_flows = dict(aliases), dict(flows)
            _scan_statements(
                statement.body, left_aliases, left_flows, source, line_starts, limits, output
            )
            _scan_statements(
                statement.orelse, right_aliases, right_flows, source, line_starts, limits, output
            )
            _merge_bindings(aliases, flows, left_aliases, left_flows, right_aliases, right_flows)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            child_aliases, child_flows = dict(aliases), dict(flows)
            _scan_statements(
                statement.body, child_aliases, child_flows, source, line_starts, limits, output
            )
            _merge_bindings(aliases, flows, aliases, flows, child_aliases, child_flows)
        elif isinstance(statement, ast.Try):
            branches: list[tuple[dict[str, str | None], dict[str, tuple[_Flow, ...]]]] = []
            body_aliases, body_flows = dict(aliases), dict(flows)
            _scan_statements(
                statement.body, body_aliases, body_flows, source, line_starts, limits, output
            )
            branches.append((body_aliases, body_flows))
            for handler in statement.handlers:
                branch_aliases, branch_flows = dict(aliases), dict(flows)
                if handler.name is not None:
                    branch_aliases[handler.name] = None
                    branch_flows.pop(handler.name, None)
                _scan_statements(
                    handler.body, branch_aliases, branch_flows, source, line_starts, limits, output
                )
                branches.append((branch_aliases, branch_flows))
            if statement.orelse:
                branch_aliases, branch_flows = dict(aliases), dict(flows)
                _scan_statements(
                    statement.orelse,
                    branch_aliases,
                    branch_flows,
                    source,
                    line_starts,
                    limits,
                    output,
                )
                branches.append((branch_aliases, branch_flows))
            _merge_many_bindings(aliases, flows, branches)
        else:
            for child_statements in _nested_statement_lists(statement):
                child_aliases, child_flows = dict(aliases), dict(flows)
                _scan_statements(
                    child_statements,
                    child_aliases,
                    child_flows,
                    source,
                    line_starts,
                    limits,
                    output,
                )
                _merge_bindings(aliases, flows, aliases, flows, child_aliases, child_flows)


def _scan_statement_calls(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe400ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe400Operation]],
) -> None:
    stack: list[ast.AST] = [statement]
    while stack:
        node = stack.pop()
        if node is not statement and isinstance(node, ast.stmt):
            continue
        if node is not statement and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            continue
        if isinstance(node, ast.Call):
            _record_call(node, aliases, flows, source, line_starts, limits, output)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))


def _record_call(
    call: ast.Call,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe400ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe400Operation]],
) -> None:
    canonical = _canonical_reference(call.func, aliases, limits.max_resolution_depth)
    operation = _operation_for_call(call, canonical, source)
    if operation is None or _has_explicit_limit(call, operation, aliases, source, limits):
        return
    inputs = _input_nodes(call, operation)
    for input_node in inputs:
        resolved = _resolve_flows(input_node, aliases, flows, source, line_starts, limits, 0)
        for flow in resolved:
            if flow.bounded:
                continue
            sink = _node_range(call, source, line_starts)
            if not sink.contains(flow.source):
                raise PythonCwe400ScanError(PythonCwe400ScanErrorCode.INTEGRITY_FAILURE)
            output.append((flow.source, sink, operation))
            if len(output) > limits.max_signals:
                raise PythonCwe400ScanError(PythonCwe400ScanErrorCode.SIGNAL_LIMIT)


def _operation_for_call(
    call: ast.Call, canonical: str | None, source: bytes
) -> PythonCwe400Operation | None:
    if canonical is None:
        canonical = _dotted_name(call.func)
    tail = canonical.rsplit(".", 1)[-1]
    if tail == "read":
        return PythonCwe400Operation.STREAM_READ
    if tail == "read1":
        return PythonCwe400Operation.STREAM_READLINE
    if tail == "readline":
        return PythonCwe400Operation.STREAM_READLINE
    if tail == "readlines":
        return PythonCwe400Operation.STREAM_READLINES
    if tail in {"readall", "read_all"}:
        return PythonCwe400Operation.STREAM_READ_ALL
    if tail == "readinto":
        return PythonCwe400Operation.STREAM_READINTO
    if canonical == "shutil.copyfileobj":
        return PythonCwe400Operation.SHUTIL_COPYFILEOBJ
    if canonical == "shutil.unpack_archive":
        return PythonCwe400Operation.SHUTIL_UNPACK_ARCHIVE
    if canonical in _DECOMPRESS_NAMES:
        return {
            "gzip.decompress": PythonCwe400Operation.GZIP_DECOMPRESS,
            "zlib.decompress": PythonCwe400Operation.ZLIB_DECOMPRESS,
            "bz2.decompress": PythonCwe400Operation.BZ2_DECOMPRESS,
            "lzma.decompress": PythonCwe400Operation.LZMA_DECOMPRESS,
        }.get(canonical, PythonCwe400Operation.DECOMPRESSION)
    if canonical in {"json.load", "json.loads"}:
        return (
            PythonCwe400Operation.JSON_LOAD
            if canonical.endswith(".load")
            else PythonCwe400Operation.JSON_LOADS
        )
    if canonical.endswith(".extractall"):
        return (
            PythonCwe400Operation.TAR_EXTRACTALL
            if canonical.startswith("tarfile") or "TarFile" in canonical
            else PythonCwe400Operation.ZIP_EXTRACTALL
        )
    if canonical.endswith(".extract"):
        return (
            PythonCwe400Operation.TAR_EXTRACT
            if canonical.startswith("tarfile") or "TarFile" in canonical
            else PythonCwe400Operation.ZIP_EXTRACT
        )
    if canonical.endswith(".extractfile"):
        return PythonCwe400Operation.TAR_EXTRACT
    if canonical in _ARCHIVE_NAMES:
        return (
            PythonCwe400Operation.SHUTIL_UNPACK_ARCHIVE
            if canonical == "shutil.unpack_archive"
            else None
        )
    if tail in {"decompress", "inflate", "unzip"}:
        return PythonCwe400Operation.DECOMPRESSION
    if tail in {"extractall", "extract", "unpack_archive"}:
        return PythonCwe400Operation.ARCHIVE_EXTRACTION
    _ = source
    return None


def _input_nodes(call: ast.Call, operation: PythonCwe400Operation) -> tuple[ast.expr, ...]:
    receiver = (
        (call.func.value,)
        if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.expr)
        else ()
    )
    if operation in {
        PythonCwe400Operation.STREAM_READ,
        PythonCwe400Operation.STREAM_READLINE,
        PythonCwe400Operation.STREAM_READLINES,
        PythonCwe400Operation.STREAM_READINTO,
        PythonCwe400Operation.STREAM_READ_ALL,
        PythonCwe400Operation.ZIP_EXTRACTALL,
        PythonCwe400Operation.ZIP_EXTRACT,
        PythonCwe400Operation.TAR_EXTRACTALL,
        PythonCwe400Operation.TAR_EXTRACT,
    }:
        return receiver
    if operation is PythonCwe400Operation.SHUTIL_COPYFILEOBJ:
        return tuple(call.args[:2])
    if operation is PythonCwe400Operation.JSON_LOAD:
        return receiver or tuple(call.args[:1])
    if operation is PythonCwe400Operation.SHUTIL_UNPACK_ARCHIVE:
        return tuple(call.args[:1])
    if operation in {
        PythonCwe400Operation.GZIP_DECOMPRESS,
        PythonCwe400Operation.ZLIB_DECOMPRESS,
        PythonCwe400Operation.BZ2_DECOMPRESS,
        PythonCwe400Operation.LZMA_DECOMPRESS,
        PythonCwe400Operation.DECOMPRESSION,
        PythonCwe400Operation.JSON_LOADS,
    }:
        return tuple(call.args[:1]) or receiver
    return receiver or tuple(call.args[:1])


def _has_explicit_limit(
    call: ast.Call,
    operation: PythonCwe400Operation,
    aliases: dict[str, str | None],
    source: bytes,
    limits: PythonCwe400ScanLimits,
) -> bool:
    canonical = _canonical_reference(call.func, aliases, limits.max_resolution_depth)
    if canonical is None:
        canonical = _dotted_name(call.func)
    tail = canonical.rsplit(".", 1)[-1] if canonical else ""
    if operation in {
        PythonCwe400Operation.STREAM_READ,
        PythonCwe400Operation.STREAM_READLINE,
        PythonCwe400Operation.STREAM_READLINES,
        PythonCwe400Operation.STREAM_READINTO,
        PythonCwe400Operation.STREAM_READ_ALL,
    }:
        if tail == "readinto" and len(call.args) >= 1:
            return True
        if call.args and _positive_or_symbolic_limit(call.args[0], source):
            return True
        return any(
            keyword.arg in _LIMIT_KEYWORDS and _positive_or_symbolic_limit(keyword.value, source)
            for keyword in call.keywords
        )
    if operation in {
        PythonCwe400Operation.ZLIB_DECOMPRESS,
        PythonCwe400Operation.DECOMPRESSION,
    }:
        if any(
            keyword.arg in {"max_length", "max_output_length", "limit", "max_size"}
            and _positive_or_symbolic_limit(keyword.value, source)
            for keyword in call.keywords
        ):
            return True
        return len(call.args) > 1 and _positive_or_symbolic_limit(call.args[1], source)
    if operation in {
        PythonCwe400Operation.ZIP_EXTRACTALL,
        PythonCwe400Operation.TAR_EXTRACTALL,
        PythonCwe400Operation.SHUTIL_UNPACK_ARCHIVE,
    }:
        for keyword in call.keywords:
            if keyword.arg in {
                "max_members",
                "max_entries",
                "limit",
            } and _positive_or_symbolic_limit(keyword.value, source):
                return True
            if keyword.arg in {"members", "member"} and not (
                isinstance(keyword.value, ast.Constant) and keyword.value.value is None
            ):
                return True
        return False
    if operation in {PythonCwe400Operation.ZIP_EXTRACT, PythonCwe400Operation.TAR_EXTRACT}:
        return True
    if operation in {PythonCwe400Operation.JSON_LOAD, PythonCwe400Operation.JSON_LOADS}:
        return (
            any(
                keyword.arg in {"parse_int", "parse_float", "object_pairs_hook"}
                for keyword in call.keywords
            )
            and False
        )
    if canonical and _looks_limited(canonical):
        return True
    return _bounded_expression(call, aliases, source, limits.max_resolution_depth)


def _positive_or_symbolic_limit(node: ast.AST, source: bytes) -> bool:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value >= 0
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return False
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return True
    text = _compact(source, node)
    return bool(text) and text not in {"-1", "None"}


def _bounded_expression(
    call: ast.Call,
    aliases: dict[str, str | None],
    source: bytes,
    max_depth: int,
) -> bool:
    for argument in (*call.args, *(keyword.value for keyword in call.keywords)):
        if (
            isinstance(argument, ast.Subscript)
            and isinstance(argument.slice, ast.Slice)
            and argument.slice.upper is not None
        ):
            return True
        canonical = _canonical_reference(argument, aliases, max_depth)
        if canonical and _looks_limited(canonical):
            return True
    return False


def _resolve_flows(
    node: ast.expr,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe400ScanLimits,
    depth: int,
    seen: frozenset[str] = frozenset(),
) -> tuple[_Flow, ...]:
    if depth > limits.max_resolution_depth:
        raise PythonCwe400ScanError(PythonCwe400ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Subscript):
        direct = _source_range(node, aliases, source, line_starts, limits.max_resolution_depth)
        if direct is not None:
            bounded = isinstance(node.slice, ast.Slice) and node.slice.upper is not None
            return (_Flow(direct, bounded),)
    direct = _source_range(node, aliases, source, line_starts, limits.max_resolution_depth)
    if direct is not None:
        return (_Flow(direct),)
    if isinstance(node, ast.Name):
        if node.id in seen:
            return ()
        return flows.get(node.id, ())
    if isinstance(node, (ast.Await, ast.NamedExpr)):
        return _resolve_flows(
            node.value, aliases, flows, source, line_starts, limits, depth + 1, seen
        )
    if isinstance(node, ast.Call):
        canonical = _canonical_reference(node.func, aliases, limits.max_resolution_depth)
        if canonical is None:
            canonical = _dotted_name(node.func)
        if canonical and _looks_limited(canonical):
            bounded = True
        else:
            bounded = _bounded_expression(node, aliases, source, limits.max_resolution_depth)
        if (
            canonical in _FLOW_PRESERVING_CALLS
            or (canonical is not None and canonical.rsplit(".", 1)[-1] in _FLOW_PRESERVING_METHODS)
            or (canonical is not None and canonical.rsplit(".", 1)[-1] in _READ_METHODS)
            or canonical in _DECOMPRESS_NAMES
            or canonical in _ARCHIVE_NAMES
        ):
            return _dedupe_flows(
                _with_bounded(flow, bounded)
                for argument in _flow_arguments(node)
                for flow in _resolve_flows(
                    argument, aliases, flows, source, line_starts, limits, depth + 1, seen
                )
            )
        return ()
    if isinstance(node, ast.Attribute):
        return _resolve_flows(
            node.value, aliases, flows, source, line_starts, limits, depth + 1, seen
        )
    if isinstance(node, ast.Subscript):
        bounded = isinstance(node.slice, ast.Slice) and node.slice.upper is not None
        return _dedupe_flows(
            _with_bounded(flow, bounded)
            for flow in _resolve_flows(
                node.value, aliases, flows, source, line_starts, limits, depth + 1, seen
            )
        )
    if isinstance(node, (ast.BinOp, ast.BoolOp, ast.Compare, ast.IfExp, ast.JoinedStr)):
        return _dedupe_flows(
            flow
            for child in ast.iter_child_nodes(node)
            if isinstance(child, ast.expr)
            for flow in _resolve_flows(
                child, aliases, flows, source, line_starts, limits, depth + 1, seen
            )
        )
    if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
        return _dedupe_flows(
            flow
            for child in ast.iter_child_nodes(node)
            if isinstance(child, ast.expr)
            for flow in _resolve_flows(
                child, aliases, flows, source, line_starts, limits, depth + 1, seen
            )
        )
    return ()


def _with_bounded(flow: _Flow, bounded: bool) -> _Flow:
    return _Flow(flow.source, flow.bounded or bounded)


def _dedupe_flows(flows: Iterable[_Flow]) -> tuple[_Flow, ...]:
    unique: dict[tuple[int, int, bool], _Flow] = {}
    for flow in flows:
        unique[(flow.source.start_byte, flow.source.end_byte, flow.bounded)] = flow
    return tuple(unique[key] for key in sorted(unique))


def _source_range(
    node: ast.expr,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    max_depth: int,
) -> SourceRange | None:
    if isinstance(node, ast.Call) and _recorded_source_call(node, source):
        return _node_range(node, source, line_starts)
    canonical = _canonical_reference(node, aliases, max_depth)
    if isinstance(node, ast.Subscript):
        base = _canonical_reference(node.value, aliases, max_depth)
        if _is_source_container(base):
            return _node_range(node, source, line_starts)
    if canonical and (_is_source_container(canonical) or _is_source_access_call(canonical)):
        return _node_range(node, source, line_starts)
    return None


def _is_source_container(canonical: str | None) -> bool:
    if canonical is None:
        return False
    if canonical in _REQUEST_ROOTS:
        return False
    base, _, attribute = canonical.rpartition(".")
    return (
        base in _REQUEST_ROOTS or base.endswith(".request")
    ) and attribute in _REQUEST_ATTRIBUTES


def _is_source_access_call(canonical: str) -> bool:
    base, _, method = canonical.rpartition(".")
    if base in {"sys.stdin", "request.body", "req.body"}:
        return method in _REQUEST_ACCESS_METHODS
    if (base in _REQUEST_ROOTS or base.endswith(".request")) and method in _REQUEST_ACCESS_METHODS:
        return True
    return canonical in {"builtins.input", "input", "os.getenv", "os.environ.get"}


def _is_parameter_source(name: str, call: ast.Call, tree: ast.AST) -> bool:
    if name.lower() not in _PARAMETER_NAMES:
        return False
    scope = _enclosing_function(call, tree)
    if scope is None:
        return False
    parameters = (*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs)
    return (
        any(parameter.arg == name for parameter in parameters)
        or (scope.args.vararg is not None and scope.args.vararg.arg == name)
        or (scope.args.kwarg is not None and scope.args.kwarg.arg == name)
    )


def _record_assignment(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe400ScanLimits,
) -> None:
    values: list[tuple[ast.expr, ast.expr]] = []
    if isinstance(statement, ast.Assign):
        values.extend((target, statement.value) for target in statement.targets)
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        values.append((statement.target, statement.value))
    for target, value in values:
        names = _target_names(target)
        resolved = _resolve_flows(value, aliases, flows, source, line_starts, limits, 0)
        canonical = _canonical_reference(value, aliases, limits.max_resolution_depth)
        for name in names:
            aliases[name] = canonical
            if resolved:
                flows[name] = resolved
            else:
                flows.pop(name, None)


def _record_with_bindings(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe400ScanLimits,
) -> None:
    if not isinstance(statement, (ast.With, ast.AsyncWith)):
        return
    for item in statement.items:
        target = item.optional_vars
        if target is None:
            continue
        resolved = _resolve_flows(item.context_expr, aliases, flows, source, line_starts, limits, 0)
        canonical = _canonical_reference(item.context_expr, aliases, limits.max_resolution_depth)
        for name in _target_names(target):
            aliases[name] = canonical
            if resolved:
                flows[name] = resolved
            else:
                flows.pop(name, None)


def _record_imports(statement: ast.Import, aliases: dict[str, str | None]) -> None:
    for imported in statement.names:
        root = imported.name.split(".", 1)[0]
        aliases[imported.asname or root] = imported.name if root in _KNOWN_MODULES else None


def _record_import_from(statement: ast.ImportFrom, aliases: dict[str, str | None]) -> None:
    module = statement.module or ""
    for imported in statement.names:
        if imported.name == "*":
            continue
        name = imported.asname or imported.name
        canonical = f"{module}.{imported.name}"
        aliases[name] = (
            canonical
            if module in _KNOWN_MODULES or module.startswith(tuple(_KNOWN_MODULES))
            else None
        )


def _record_scope_bindings(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
) -> None:
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        _invalidate_target(statement.target, aliases, flows)
    elif isinstance(statement, ast.Try):
        for handler in statement.handlers:
            if handler.name is not None:
                aliases[handler.name] = None
                flows.pop(handler.name, None)
    elif isinstance(statement, ast.Delete):
        for target in statement.targets:
            _invalidate_target(target, aliases, flows)


def _invalidate_target(
    target: ast.AST,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
) -> None:
    for name in _target_names(target):
        aliases[name] = None
        flows.pop(name, None)


def _merge_bindings(
    target_aliases: dict[str, str | None],
    target_flows: dict[str, tuple[_Flow, ...]],
    left_aliases: dict[str, str | None],
    left_flows: dict[str, tuple[_Flow, ...]],
    right_aliases: dict[str, str | None],
    right_flows: dict[str, tuple[_Flow, ...]],
) -> None:
    merged_aliases: dict[str, str | None] = {}
    merged_flows: dict[str, tuple[_Flow, ...]] = {}
    for name in left_aliases.keys() | right_aliases.keys():
        left_alias = left_aliases.get(name)
        right_alias = right_aliases.get(name)
        merged_aliases[name] = left_alias if left_alias == right_alias else None
        left_flow = left_flows.get(name, ())
        right_flow = right_flows.get(name, ())
        if left_flow == right_flow and left_flow:
            merged_flows[name] = left_flow
    target_aliases.clear()
    target_aliases.update(merged_aliases)
    target_flows.clear()
    target_flows.update(merged_flows)


def _merge_many_bindings(
    target_aliases: dict[str, str | None],
    target_flows: dict[str, tuple[_Flow, ...]],
    branches: list[tuple[dict[str, str | None], dict[str, tuple[_Flow, ...]]]],
) -> None:
    if not branches:
        return
    merged_aliases, merged_flows = dict(branches[0][0]), dict(branches[0][1])
    for branch_aliases, branch_flows in branches[1:]:
        _merge_bindings(
            merged_aliases, merged_flows, merged_aliases, merged_flows, branch_aliases, branch_flows
        )
    target_aliases.clear()
    target_aliases.update(merged_aliases)
    target_flows.clear()
    target_flows.update(merged_flows)


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


def _flow_arguments(call: ast.Call) -> tuple[ast.expr, ...]:
    receiver = (
        (call.func.value,)
        if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.expr)
        else ()
    )
    return (*receiver, *call.args, *(item.value for item in call.keywords))


def _canonical_reference(
    node: ast.AST,
    aliases: dict[str, str | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe400ScanError(PythonCwe400ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        if node.id in aliases:
            return aliases[node.id]
        return node.id if node.id in _REQUEST_ROOTS or node.id in _KNOWN_MODULES else None
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Subscript):
        return _canonical_reference(node.value, aliases, max_depth, depth + 1)
    if isinstance(node, ast.Call):
        if _dotted_name(node.func) in {"getattr", "builtins.getattr"}:
            if len(node.args) < 2 or node.keywords:
                return None
            base = _canonical_reference(node.args[0], aliases, max_depth, depth + 1)
            member = _literal_string(node.args[1])
            return None if base is None or member is None else f"{base}.{member}"
        return _canonical_reference(node.func, aliases, max_depth, depth + 1)
    return None


def _looks_limited(value: str) -> bool:
    pieces = [piece for piece in re.split(r"[^a-z0-9]+", value.lower()) if piece]
    return any(
        piece in _LIMIT_WORDS or any(word in piece for word in _LIMIT_WORDS) for piece in pieces
    )


def _enclosing_function(
    call: ast.Call, tree: ast.AST
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    call_line = getattr(call, "lineno", -1)
    candidates: list[tuple[int, int, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    for item in ast.walk(tree):
        if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end_line = getattr(item, "end_lineno", None)
        if type(end_line) is int and item.lineno <= call_line <= end_line:
            candidates.append((end_line - item.lineno, item.col_offset, item))
    return min(candidates, default=(0, 0, None))[2]


def _recorded_source_call(node: ast.Call, source: bytes) -> bool:
    name = _dotted_name(node.func)
    compact = _compact(source, node)
    return name in {"builtins.input", "input", "os.getenv", "os.environ.get"} or bool(
        re.match(r"(?:request|req|http_request|context|event)\.(?:get|body|json|data)\(", compact)
    )


def _dotted_name(node: ast.AST) -> str:
    parts: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


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
        raise PythonCwe400ScanError(PythonCwe400ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe400ScanError(PythonCwe400ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe400ScanError(PythonCwe400ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start, end, SourcePoint(start_line, start_column), SourcePoint(end_line, end_column)
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
    operation: PythonCwe400Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-400",
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
    signals: tuple[PythonCwe400Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-400",
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
                "detail": signal.detail,
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


Cwe400ScanErrorCode = PythonCwe400ScanErrorCode
Cwe400ScanError = PythonCwe400ScanError
Cwe400ScanLimits = PythonCwe400ScanLimits
Cwe400ScanResult = PythonCwe400ScanResult
Cwe400Signal = PythonCwe400Signal

scan_python_cwe400_resource_consumption = scan_python_cwe400
scan_python_resource_consumption = scan_python_cwe400


__all__ = [
    "DEFAULT_PYTHON_CWE400_SCAN_LIMITS",
    "Cwe400ScanError",
    "Cwe400ScanErrorCode",
    "Cwe400ScanLimits",
    "Cwe400ScanResult",
    "Cwe400Signal",
    "PythonCwe400Operation",
    "PythonCwe400ScanError",
    "PythonCwe400ScanErrorCode",
    "PythonCwe400ScanLimits",
    "PythonCwe400ScanResult",
    "PythonCwe400Signal",
    "scan_python_cwe400",
    "scan_python_cwe400_resource_consumption",
    "scan_python_resource_consumption",
]
