"""Bounded Go facts for CWE-400 uncontrolled resource consumption.

The scanner recognises the high-risk stream boundaries that commonly turn
request or network data into an unbounded allocation or copy.  It reports
``io.ReadAll`` and ``io.Copy`` (and their direct standard-library variants),
as well as decompression and archive readers, only when the input is not
bounded by an explicit byte or entry limit.  ``io.LimitReader``,
``http.MaxBytesReader``, ``io.CopyN`` and equivalent limited-reader forms are
treated as validation boundaries.

Only a sealed :class:`~securecode_ai.core.SymbolIndex` is accepted.  Source
bytes are parsed and discarded; results contain immutable identity and exact
source ranges, but never source text or parser diagnostics.
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
_SIGNAL_ID = re.compile(r"go-cwe400-[0-9a-f]{64}\Z")
_RULE_ID = "securecode-go-cwe400"
_DETECTOR = "securecode-go-cwe400@1.0"

_IO_PACKAGE = "io"
_IOUTILS_PACKAGE = "io/ioutil"
_HTTP_PACKAGE = "net/http"
_NET_PACKAGE = "net"
_TLS_PACKAGE = "crypto/tls"
_COMPRESS_PACKAGES = frozenset(
    {
        "compress/bzip2",
        "compress/flate",
        "compress/gzip",
        "compress/lzw",
        "compress/zlib",
    }
)
_ARCHIVE_PACKAGES = frozenset({"archive/tar", "archive/zip"})
_STREAM_PACKAGES = frozenset({"bufio", "bytes", "io", "strings"})
_NETWORK_PACKAGES = frozenset({_HTTP_PACKAGE, _NET_PACKAGE, _TLS_PACKAGE})
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})

_UNBOUNDED_OPERATIONS = {
    (_IO_PACKAGE, "ReadAll"): "read",
    (_IOUTILS_PACKAGE, "ReadAll"): "read",
    (_IO_PACKAGE, "Copy"): "read",
    (_IO_PACKAGE, "CopyBuffer"): "read",
}
_BOUNDED_OPERATIONS = {
    (_IO_PACKAGE, "LimitReader"),
    (_IO_PACKAGE, "NewSectionReader"),
    (_HTTP_PACKAGE, "MaxBytesReader"),
}
_DECOMPRESS_OPERATIONS = {
    ("compress/bzip2", "NewReader"),
    ("compress/flate", "NewReader"),
    ("compress/gzip", "NewReader"),
    ("compress/lzw", "NewReader"),
    ("compress/zlib", "NewReader"),
}
_ARCHIVE_OPERATIONS = {
    ("archive/tar", "NewReader"),
    ("archive/zip", "NewReader"),
}
_STREAM_WRAPPERS = {
    ("bufio", "NewReader"),
    ("bufio", "NewReaderSize"),
    ("bufio", "NewScanner"),
    ("bytes", "NewBuffer"),
    ("bytes", "NewBufferString"),
    ("bytes", "NewReader"),
    ("io", "NopCloser"),
    ("strings", "NewReader"),
}
_NETWORK_FUNCTIONS = {
    (_HTTP_PACKAGE, "Get"),
    (_HTTP_PACKAGE, "Head"),
    (_HTTP_PACKAGE, "Post"),
    (_HTTP_PACKAGE, "PostForm"),
    (_NET_PACKAGE, "Dial"),
    (_NET_PACKAGE, "DialTimeout"),
    (_NET_PACKAGE, "Dialer"),
    (_TLS_PACKAGE, "Dial"),
    (_TLS_PACKAGE, "DialWithDialer"),
}
_LIMIT_HELPER_WORDS = frozenset(
    {
        "bound",
        "bounded",
        "limit",
        "limited",
        "maxbytes",
        "maxentries",
        "maxentry",
        "withlimit",
    }
)
_NETWORK_NAME_WORDS = frozenset(
    {
        "body",
        "conn",
        "connection",
        "network",
        "reader",
        "request",
        "req",
        "r",
        "response",
        "resp",
        "source",
        "src",
        "stream",
    }
)


class GoCwe400ScanErrorCode(StrEnum):
    """Closed, source-free reasons a Go CWE-400 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe400ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe400ScanErrorCode) -> None:
        if type(code) is not GoCwe400ScanErrorCode:
            raise TypeError("Go CWE-400 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-400 resource-consumption scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe400ScanLimits:
    """Hard ceilings applied before and during structural data-flow analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-400 scan limits are invalid")


DEFAULT_GO_CWE400_SCAN_LIMITS = GoCwe400ScanLimits()


class GoCwe400Operation(StrEnum):
    """Recognised unbounded stream, decompression, and archive boundaries."""

    IO_READ_ALL = "io.ReadAll"
    IOUTILS_READ_ALL = "io/ioutil.ReadAll"
    IO_COPY = "io.Copy"
    IO_COPY_BUFFER = "io.CopyBuffer"
    BZIP2_NEW_READER = "compress/bzip2.NewReader"
    FLATE_NEW_READER = "compress/flate.NewReader"
    GZIP_NEW_READER = "compress/gzip.NewReader"
    LZW_NEW_READER = "compress/lzw.NewReader"
    ZLIB_NEW_READER = "compress/zlib.NewReader"
    TAR_NEW_READER = "archive/tar.NewReader"
    ZIP_NEW_READER = "archive/zip.NewReader"

    # Compatibility names for generic scanner consumers.
    READ_ALL = "io.ReadAll"
    COPY = "io.Copy"
    DECOMPRESSION = "compress/gzip.NewReader"
    ARCHIVE_EXTRACTION = "archive/tar.NewReader"


_OPERATION_BY_CALL: dict[tuple[str, str], GoCwe400Operation] = {
    (_IO_PACKAGE, "ReadAll"): GoCwe400Operation.IO_READ_ALL,
    (_IOUTILS_PACKAGE, "ReadAll"): GoCwe400Operation.IOUTILS_READ_ALL,
    (_IO_PACKAGE, "Copy"): GoCwe400Operation.IO_COPY,
    (_IO_PACKAGE, "CopyBuffer"): GoCwe400Operation.IO_COPY_BUFFER,
    ("compress/bzip2", "NewReader"): GoCwe400Operation.BZIP2_NEW_READER,
    ("compress/flate", "NewReader"): GoCwe400Operation.FLATE_NEW_READER,
    ("compress/gzip", "NewReader"): GoCwe400Operation.GZIP_NEW_READER,
    ("compress/lzw", "NewReader"): GoCwe400Operation.LZW_NEW_READER,
    ("compress/zlib", "NewReader"): GoCwe400Operation.ZLIB_NEW_READER,
    ("archive/tar", "NewReader"): GoCwe400Operation.TAR_NEW_READER,
    ("archive/zip", "NewReader"): GoCwe400Operation.ZIP_NEW_READER,
}


@dataclass(frozen=True, slots=True)
class GoCwe400Signal:
    """One immutable, source-free unbounded resource-consumption fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe400Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-400"
    detector: str = _DETECTOR
    detail: str = "unbounded_resource_consumption"

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
            if valid_identity and valid_ranges and type(self.operation) is GoCwe400Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not GoCwe400Operation
            or type(signal_id) is not str
            or expected_id is None
            or _SIGNAL_ID.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-400"
            or self.detector != _DETECTOR
            or self.detail != "unbounded_resource_consumption"
        ):
            raise ValueError("Go CWE-400 signal is invalid")
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
class GoCwe400ScanResult:
    """Deterministic, source-free result for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe400Signal, ...]
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
            type(item) is GoCwe400Signal for item in self.signals
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
            raise ValueError("Go CWE-400 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange
    bounded: bool = False


def scan_go_cwe400(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe400ScanLimits = DEFAULT_GO_CWE400_SCAN_LIMITS,
) -> GoCwe400ScanResult:
    """Find unbounded reads, copies, decompression, and archive readers."""

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
        raise GoCwe400ScanError(GoCwe400ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    raw: set[tuple[SourceRange, SourceRange, GoCwe400Operation]] = set()
    try:
        for scope in _scopes(root):
            environment: dict[str, tuple[_Flow, ...]] = {}
            callable_aliases: dict[str, tuple[str, str]] = {}
            for node in _scope_preorder(scope):
                if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                    _capture_assignment(
                        node,
                        environment,
                        callable_aliases,
                        source,
                        imports,
                        limits,
                    )
                if node.type != "call_expression":
                    continue
                operation = _operation_for_call(node, source, imports, callable_aliases)
                if operation is None:
                    continue
                arguments = node.child_by_field_name("arguments")
                if arguments is None:
                    continue
                values = tuple(arguments.named_children)
                input_index = (
                    1
                    if operation
                    in {
                        GoCwe400Operation.IO_COPY,
                        GoCwe400Operation.IO_COPY_BUFFER,
                    }
                    else 0
                )
                if len(values) <= input_index:
                    continue
                flows = _resolve(values[input_index], environment, source, imports, limits, 0)
                for flow in flows:
                    if flow.bounded:
                        continue
                    sink_range = _range(node)
                    source_range = flow.source
                    if source_range.end_byte > sink_range.end_byte:
                        raise GoCwe400ScanError(GoCwe400ScanErrorCode.INTEGRITY_FAILURE)
                    raw.add((source_range, sink_range, operation))
                    if len(raw) > limits.max_signals:
                        raise GoCwe400ScanError(GoCwe400ScanErrorCode.SIGNAL_LIMIT)
    except GoCwe400ScanError:
        raise
    except Exception:
        raise GoCwe400ScanError(GoCwe400ScanErrorCode.INTEGRITY_FAILURE) from None

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
        raise GoCwe400ScanError(GoCwe400ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe400Signal(
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
    return GoCwe400ScanResult(
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


def scan_go_cwe400_resource_consumption(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe400ScanLimits = DEFAULT_GO_CWE400_SCAN_LIMITS,
) -> GoCwe400ScanResult:
    """Descriptive alias for :func:`scan_go_cwe400`."""

    return scan_go_cwe400(symbol_index, limits=limits)


def scan_go_resource_consumption(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe400ScanLimits = DEFAULT_GO_CWE400_SCAN_LIMITS,
) -> GoCwe400ScanResult:
    """Compatibility alias for callers grouping resource scans."""

    return scan_go_cwe400(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe400ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe400ScanLimits:
        raise GoCwe400ScanError(GoCwe400ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe400ScanError(GoCwe400ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe400ScanError(GoCwe400ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe400ScanError(GoCwe400ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    relevant = (
        _STREAM_PACKAGES
        | _COMPRESS_PACKAGES
        | _ARCHIVE_PACKAGES
        | _NETWORK_PACKAGES
        | {_IOUTILS_PACKAGE}
    )
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        package = _text(source, path_node).strip('"`')
        if package not in relevant:
            continue
        name_node = node.child_by_field_name("name")
        alias = _text(source, name_node) if name_node is not None else package.rsplit("/", 1)[-1]
        if alias not in {".", "_"}:
            aliases[alias] = package
    return aliases


def _operation_for_call(
    node: Node,
    source: bytes,
    imports: dict[str, str],
    callable_aliases: dict[str, tuple[str, str]],
) -> GoCwe400Operation | None:
    function = node.child_by_field_name("function")
    if function is None:
        return None
    qualified = _qualified_function(function, source, imports, callable_aliases)
    if qualified is None:
        return None
    return _OPERATION_BY_CALL.get(qualified)


def _qualified_function(
    function: Node,
    source: bytes,
    imports: dict[str, str],
    callable_aliases: dict[str, tuple[str, str]],
) -> tuple[str, str] | None:
    if function.type == "identifier":
        return callable_aliases.get(_text(source, function))
    if function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None or operand.type != "identifier":
        return None
    package = imports.get(_text(source, operand))
    return None if package is None else (package, _text(source, field))


def _capture_assignment(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    callable_aliases: dict[str, tuple[str, str]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe400ScanLimits,
) -> None:
    if node.type == "var_spec":
        names_node = node.child_by_field_name("name")
        values_node = node.child_by_field_name("value")
        if names_node is None or values_node is None:
            return
        names = tuple(names_node.named_children) or (names_node,)
        values: tuple[Node, ...] = (values_node,)
    else:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        names = tuple(left.named_children) if left.type == "expression_list" else (left,)
        values = tuple(right.named_children) if right.type == "expression_list" else (right,)
    if len(names) > limits.max_signals or len(values) > limits.max_signals:
        raise GoCwe400ScanError(GoCwe400ScanErrorCode.SIGNAL_LIMIT)
    for index, name in enumerate(names):
        if name.type != "identifier" or index >= len(values):
            continue
        value = values[index]
        binding = _resolve(value, environment, source, imports, limits, 0)
        if binding:
            environment[_text(source, name)] = binding
        else:
            environment.pop(_text(source, name), None)
        function = _qualified_function_from_value(value, source, imports)
        if function is not None:
            callable_aliases[_text(source, name)] = function
        else:
            callable_aliases.pop(_text(source, name), None)


def _qualified_function_from_value(
    node: Node, source: bytes, imports: dict[str, str]
) -> tuple[str, str] | None:
    if node.type != "selector_expression":
        return None
    operand = node.child_by_field_name("operand")
    field = node.child_by_field_name("field")
    if operand is None or field is None or operand.type != "identifier":
        return None
    package = imports.get(_text(source, operand))
    return None if package is None else (package, _text(source, field))


def _resolve(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe400ScanLimits,
    depth: int,
    visited: frozenset[str] = frozenset(),
) -> tuple[_Flow, ...]:
    if depth > limits.max_expression_depth:
        raise GoCwe400ScanError(GoCwe400ScanErrorCode.SIGNAL_LIMIT)
    if node.type == "identifier":
        name = _text(source, node)
        if name in visited:
            return ()
        return environment.get(name, ())
    direct = _network_source(node, source, imports, environment, limits, depth)
    if direct is not None:
        return (direct,)
    if node.type in {
        "parenthesized_expression",
        "unary_expression",
        "pointer_expression",
        "address_expression",
    }:
        return _dedupe_flows(
            flow
            for child in node.named_children
            for flow in _resolve(
                child,
                environment,
                source,
                imports,
                limits,
                depth + 1,
                visited,
            )
        )
    if node.type == "composite_literal":
        type_node = node.child_by_field_name("type")
        bounded = "LimitedReader" in _compact_text(source, type_node)
        return _dedupe_flows(
            _with_bounded(flow, bounded)
            for child in node.named_children
            if child != type_node
            for flow in _resolve(child, environment, source, imports, limits, depth + 1, visited)
        )
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            return ()
        values = tuple(arguments.named_children)
        qualified = _qualified_function(function, source, imports, {}) if function else None
        if qualified in _BOUNDED_OPERATIONS:
            source_values = (
                values[1:2] if qualified == (_HTTP_PACKAGE, "MaxBytesReader") else values[:1]
            )
            return _dedupe_flows(
                _with_bounded(flow, True)
                for value in source_values
                for flow in _resolve(
                    value, environment, source, imports, limits, depth + 1, visited
                )
            )
        if qualified == (_IO_PACKAGE, "CopyN"):
            return _dedupe_flows(
                _with_bounded(flow, True)
                for value in values[1:2]
                for flow in _resolve(
                    value, environment, source, imports, limits, depth + 1, visited
                )
            )
        if qualified in _DECOMPRESS_OPERATIONS or qualified in _ARCHIVE_OPERATIONS:
            return _dedupe_flows(
                flow
                for value in values[:1]
                for flow in _resolve(
                    value, environment, source, imports, limits, depth + 1, visited
                )
            )
        if qualified in _STREAM_WRAPPERS:
            return _dedupe_flows(
                flow
                for value in values[:1]
                for flow in _resolve(
                    value, environment, source, imports, limits, depth + 1, visited
                )
            )
        if qualified in _NETWORK_FUNCTIONS:
            return (_Flow(_range(node)),)
        if function is not None and function.type == "selector_expression":
            field = function.child_by_field_name("field")
            if field is not None and _text(source, field) in {
                "Accept",
                "Do",
                "Get",
                "Head",
                "Post",
                "PostForm",
                "RoundTrip",
            }:
                return (_Flow(_range(node)),)
        function_name = _call_name(function, source)
        if _is_limit_helper(function_name):
            return _dedupe_flows(
                _with_bounded(flow, True)
                for value in values[:1]
                for flow in _resolve(
                    value, environment, source, imports, limits, depth + 1, visited
                )
            )
        return _dedupe_flows(
            flow
            for value in values
            for flow in _resolve(value, environment, source, imports, limits, depth + 1, visited)
        )
    if node.type in {"selector_expression", "index_expression", "slice_expression"}:
        return _dedupe_flows(
            flow
            for child in node.named_children
            for flow in _resolve(child, environment, source, imports, limits, depth + 1, visited)
        )
    if node.type in {"binary_expression", "expression_list", "keyed_element"}:
        return _dedupe_flows(
            flow
            for child in node.named_children
            for flow in _resolve(child, environment, source, imports, limits, depth + 1, visited)
        )
    return ()


def _network_source(
    node: Node,
    source: bytes,
    imports: dict[str, str],
    environment: dict[str, tuple[_Flow, ...]],
    limits: GoCwe400ScanLimits,
    depth: int,
) -> _Flow | None:
    if node.type != "selector_expression":
        return None
    field = node.child_by_field_name("field")
    operand = node.child_by_field_name("operand")
    if field is None or operand is None or _text(source, field) not in {"Body", "Reader"}:
        return None
    inherited = _resolve(operand, environment, source, imports, limits, depth + 1)
    if inherited:
        return _Flow(_range(node), all(flow.bounded for flow in inherited))
    receiver = _compact_text(source, operand)
    if _looks_network_named(receiver):
        return _Flow(_range(node))
    return None


def _call_name(function: Node | None, source: bytes) -> str:
    if function is None:
        return ""
    if function.type == "identifier":
        return _text(source, function)
    if function.type == "selector_expression":
        field = function.child_by_field_name("field")
        return _text(source, field) if field is not None else ""
    return ""


def _is_limit_helper(name: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", name.lower())
    return any(word in compact for word in _LIMIT_HELPER_WORDS)


def _looks_network_named(value: str) -> bool:
    pieces = [piece.lower() for piece in re.split(r"[^a-z0-9]+", value) if piece]
    if not pieces:
        return False
    return any(
        piece in _NETWORK_NAME_WORDS
        or piece.endswith("request")
        or piece.endswith("response")
        or piece.endswith("conn")
        or piece.endswith("connection")
        for piece in pieces
    )


def _with_bounded(flow: _Flow, bounded: bool) -> _Flow:
    return _Flow(flow.source, flow.bounded or bounded)


def _dedupe_flows(flows: Iterable[_Flow]) -> tuple[_Flow, ...]:
    unique: dict[tuple[int, int, bool], _Flow] = {}
    for value in flows:
        key = (value.source.start_byte, value.source.end_byte, value.bounded)
        unique[key] = value
    return tuple(unique[key] for key in sorted(unique))


def _scopes(root: Node) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node == root or node.type in _GO_SCOPES)


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
    operation: GoCwe400Operation,
) -> str:
    material = {
        "content_sha256": content_sha256,
        "cwe": "CWE-400",
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
    return "go-cwe400-" + digest


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe400Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "cwe": item.cwe,
                "detail": item.detail,
                "detector": item.detector,
                "operation": item.operation.value,
                "signal_id": item.signal_id,
                "sink": _range_value(item.sink),
                "source": _range_value(item.source),
            }
            for item in signals
        ],
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


__all__ = [
    "DEFAULT_GO_CWE400_SCAN_LIMITS",
    "GoCwe400Operation",
    "GoCwe400ScanError",
    "GoCwe400ScanErrorCode",
    "GoCwe400ScanLimits",
    "GoCwe400ScanResult",
    "GoCwe400Signal",
    "scan_go_cwe400",
    "scan_go_cwe400_resource_consumption",
    "scan_go_resource_consumption",
]
