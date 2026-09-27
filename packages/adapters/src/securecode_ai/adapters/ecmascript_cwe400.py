"""Bounded JavaScript and TypeScript CWE-400 resource exhaustion facts.

The scanner works on an admitted :class:`~securecode_ai.core.SymbolIndex` and
rebuilds that index before inspecting the CST.  It reports request data flowing
to unbounded stream, body, archive, decompression, JSON, or XML operations.  A
sink with an explicit byte, entry, buffer, or stream limit is treated as safe.
Only immutable ranges and content-addressed identifiers leave this module.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import ParseHealth, RepositoryFile, SourcePoint, SourceRange, SymbolIndex
from tree_sitter import Language, Node, Parser

from .cst import CstAdapterError, build_javascript_symbol_index, build_typescript_symbol_index
from .cst_ecmascript import _javascript_language, _typescript_language

_MAX_LIMITS = (2_000_000, 250_000, 512, 10_000)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_RULE_ID = "securecode-ecmascript-cwe400"
_DETECTOR = "securecode-ecmascript-cwe400@1.0"

_REQUEST_ROOTS = frozenset({"ctx", "context", "event", "httpRequest", "req", "request", "incoming"})
_REQUEST_FIELDS = frozenset(
    {
        "body",
        "data",
        "headers",
        "params",
        "path",
        "pathParameters",
        "payload",
        "query",
        "queryStringParameters",
        "rawBody",
        "url",
    }
)
_SIZE_KEYS = frozenset(
    {
        "bufferSize",
        "chunkSize",
        "highWaterMark",
        "limit",
        "maxBodyLength",
        "maxBuffer",
        "maxBytes",
        "maxContentLength",
        "maxEntries",
        "maxEntryCount",
        "maxFileSize",
        "maxOutputLength",
        "maxSize",
        "maxTotalSize",
        "size",
        "streamLimit",
    }
)
_PRESERVING_CALLS = frozenset(
    {
        "Buffer.concat",
        "Buffer.from",
        "JSON.stringify",
        "Promise.resolve",
        "String",
        "decodeURI",
        "decodeURIComponent",
        "encodeURI",
        "encodeURIComponent",
        "Object.assign",
        "Uint8Array.from",
    }
)
_FILE_MODULES = frozenset({"fs", "fs/promises"})
_BODY_MODULES = frozenset(
    {
        "body-parser",
        "express",
        "fastify",
        "get-raw-body",
        "koa-body",
        "raw-body",
    }
)
_ARCHIVE_MODULES = frozenset(
    {
        "adm-zip",
        "decompress",
        "extract-zip",
        "node-stream-zip",
        "tar",
        "unzipper",
        "yauzl",
        "yazl",
        "zip-lib",
        "zipfile",
    }
)
_DECOMPRESSION_MODULES = frozenset({"pako", "zlib", "zlib/promises", "fflate", "decompress"})
_XML_MODULES = frozenset(
    {
        "@xmldom/xmldom",
        "fast-xml-parser",
        "libxmljs",
        "node-expat",
        "sax",
        "xml2js",
        "xml-js",
    }
)
_ARCHIVE_METHODS = frozenset(
    {
        "createExtractor",
        "extract",
        "extractAllTo",
        "extractAllToAsync",
        "open",
        "openBuffer",
        "openReadStream",
        "parseZip",
        "stream",
        "unzip",
    }
)
_DECOMPRESSION_METHODS = frozenset(
    {
        "brotliDecompress",
        "brotliDecompressSync",
        "gunzip",
        "gunzipSync",
        "inflate",
        "inflateRaw",
        "inflateRawSync",
        "inflateSync",
        "unzip",
        "unzipSync",
    }
)
_BODY_METHODS = frozenset({"arrayBuffer", "blob", "formData", "json", "text"})
_FILE_METHODS = frozenset({"createReadStream"})
_XML_METHODS = frozenset({"parse", "parseString", "parseFromString", "write"})


class EcmaScriptCwe400ScanErrorCode(StrEnum):
    """Closed, source-free reasons an analysis cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe400ScanError(RuntimeError):
    """Fixed scanner failure without source or parser diagnostics."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe400ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe400ScanErrorCode:
            raise TypeError("ECMAScript CWE-400 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-400 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe400ScanLimits:
    """Hard ceilings applied before and during CST analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_nodes: int = _MAX_LIMITS[1]
    max_depth: int = _MAX_LIMITS[2]
    max_signals: int = _MAX_LIMITS[3]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_nodes, self.max_depth, self.max_signals)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("ECMAScript CWE-400 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE400_SCAN_LIMITS = EcmaScriptCwe400ScanLimits()


class EcmaScriptCwe400Operation(StrEnum):
    """Unbounded input-consuming operations recognized by the scanner."""

    FILE_READ = "file_read"
    FILE_READ_SYNC = "file_read_sync"
    STREAM_READ = "stream_read"
    BODY_READ = "body_read"
    JSON_PARSE = "json_parse"
    XML_PARSE = "xml_parse"
    ARCHIVE_EXTRACT = "archive_extract"
    DECOMPRESSION = "decompression"

    # Descriptive compatibility aliases used by generic consumers.
    READ_FILE = "file_read"
    READ_FILE_SYNC = "file_read_sync"
    ARCHIVE_PARSE = "archive_extract"
    DECOMPRESS = "decompression"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe400Signal:
    """One immutable source-to-unbounded-consumer fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe400Operation
    signal_id: str
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
            )
            if identity_valid and ranges_valid and type(self.operation) is EcmaScriptCwe400Operation
            else None
        )
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not EcmaScriptCwe400Operation
            or type(self.signal_id) is not str
            or _SHA256.fullmatch(self.signal_id) is None
            or self.signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-400"
            or self.detector != _DETECTOR
            or self.detail != "unbounded_resource_consumption"
        ):
            raise ValueError("ECMAScript CWE-400 signal is invalid")

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
class EcmaScriptCwe400ScanResult:
    """Deterministic source-free output for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe400Signal, ...]
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
            and self.language in {"javascript", "typescript"}
        )
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity_valid = False
        valid_signals = type(self.signals) is tuple and all(
            type(item) is EcmaScriptCwe400Signal for item in self.signals
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
                self.language,
                self.signals,
            )
        ):
            raise ValueError("ECMAScript CWE-400 scan result is invalid")


def scan_javascript_cwe400(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe400ScanLimits = DEFAULT_ECMASCRIPT_CWE400_SCAN_LIMITS,
) -> EcmaScriptCwe400ScanResult:
    """Find bounded JavaScript CWE-400 facts."""

    return _scan_ecmascript_cwe400(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe400(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe400ScanLimits = DEFAULT_ECMASCRIPT_CWE400_SCAN_LIMITS,
) -> EcmaScriptCwe400ScanResult:
    """Find bounded TypeScript CWE-400 facts."""

    return _scan_ecmascript_cwe400(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe400(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe400ScanLimits = DEFAULT_ECMASCRIPT_CWE400_SCAN_LIMITS,
) -> EcmaScriptCwe400ScanResult:
    """Dispatch a CWE-400 scan using the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe400(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe400(symbol_index, limits=limits)
    raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe400(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe400ScanLimits,
) -> EcmaScriptCwe400ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe400ScanLimits:
        raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.ANALYSIS_UNAVAILABLE)
    builder = (
        build_javascript_symbol_index
        if expected_language == "javascript"
        else build_typescript_symbol_index
    )
    try:
        rebuilt = builder(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source=symbol_index.source,
        )
        if rebuilt != symbol_index:
            raise ValueError("symbol index mismatch")
        grammar = (
            _javascript_language()
            if expected_language == "javascript"
            else _typescript_language(tsx=symbol_index.path.endswith(".tsx"))
        )
        source = symbol_index.source
        source.decode("utf-8", errors="strict")
        root = Parser(Language(grammar)).parse(source).root_node
    except (CstAdapterError, TypeError, UnicodeDecodeError, ValueError):
        raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.INTEGRITY_FAILURE) from None
    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.ANALYSIS_UNAVAILABLE)
        aliases = _collect_aliases(nodes, source)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe400Operation]] = set()
        for node in nodes:
            if node.type != "call_expression":
                continue
            operation = _operation_for_call(node, source, aliases)
            if operation is None or _has_explicit_limit(node, source, aliases):
                continue
            arguments = node.child_by_field_name("arguments")
            if arguments is None:
                raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.INTEGRITY_FAILURE)
            values = tuple(arguments.named_children)
            input_nodes = _input_nodes(node, values, operation, source)
            scope = _enclosing_scope(node, root)
            request_inputs: tuple[Node, ...] = ()
            for input_node in input_nodes:
                request_inputs += _resolve_source(
                    input_node,
                    scope=scope,
                    source=source,
                    aliases=aliases,
                    limits=limits,
                    depth=0,
                    visited=frozenset(),
                )
            if request_inputs:
                for source_node in request_inputs:
                    sink_range = _range(node)
                    source_range = _range(source_node)
                    if not sink_range.contains(source_range):
                        raise EcmaScriptCwe400ScanError(
                            EcmaScriptCwe400ScanErrorCode.INTEGRITY_FAILURE
                        )
                    raw.add((source_range, sink_range, operation))
            elif (
                operation
                in {
                    EcmaScriptCwe400Operation.FILE_READ,
                    EcmaScriptCwe400Operation.FILE_READ_SYNC,
                    EcmaScriptCwe400Operation.STREAM_READ,
                }
                and _is_public_context(node, root, source)
                and values
            ):
                source_range = _range(values[0])
                sink_range = _range(node)
                if not sink_range.contains(source_range):
                    raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.INTEGRITY_FAILURE)
                raw.add((source_range, sink_range, operation))
            if len(raw) > limits.max_signals:
                raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.SIGNAL_LIMIT)
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
    except EcmaScriptCwe400ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.INTEGRITY_FAILURE) from None
    signals = tuple(
        EcmaScriptCwe400Signal(
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
    return EcmaScriptCwe400ScanResult(
        repository_id=symbol_index.repository_id,
        revision=symbol_index.revision,
        path=symbol_index.path,
        content_sha256=symbol_index.content_sha256,
        source_size_bytes=symbol_index.source_byte_length,
        language=expected_language,
        signals=signals,
        scan_sha256=_scan_sha256(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            expected_language,
            signals,
        ),
    )


def _bounded_nodes(root: Node, limits: EcmaScriptCwe400ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _operation_for_call(
    node: Node, source: bytes, aliases: dict[str, str]
) -> EcmaScriptCwe400Operation | None:
    function = node.child_by_field_name("function")
    if function is None:
        return None
    canonical = _canonical_expression(function, source, aliases)
    if canonical is None:
        return None
    parts = canonical.split(".")
    method = parts[-1]
    module = ".".join(parts[:-1])
    if canonical in {"JSON.parse", "json.parse"}:
        return EcmaScriptCwe400Operation.JSON_PARSE
    if method in _FILE_METHODS and (module in _FILE_MODULES or canonical in _FILE_METHODS):
        return EcmaScriptCwe400Operation.STREAM_READ
    if method in _BODY_METHODS and (_is_body_receiver(canonical) or module in _BODY_MODULES):
        return EcmaScriptCwe400Operation.BODY_READ
    if method in _DECOMPRESSION_METHODS and (
        module in _DECOMPRESSION_MODULES or method in _DECOMPRESSION_METHODS
    ):
        return EcmaScriptCwe400Operation.DECOMPRESSION
    if method in _ARCHIVE_METHODS and (
        module in _ARCHIVE_MODULES or _looks_like_archive(canonical)
    ):
        return EcmaScriptCwe400Operation.ARCHIVE_EXTRACT
    if method in _XML_METHODS and (module in _XML_MODULES or _looks_like_xml(canonical)):
        return EcmaScriptCwe400Operation.XML_PARSE
    if method in {"readBody", "getRawBody", "rawBody", "readAll", "collectBody"}:
        return EcmaScriptCwe400Operation.BODY_READ
    if method in {"parseJson", "parseJSON"}:
        return EcmaScriptCwe400Operation.JSON_PARSE
    if method in {"gunzip", "inflate", "unzip", "decompress"}:
        return EcmaScriptCwe400Operation.DECOMPRESSION
    return None


def _is_body_receiver(canonical: str) -> bool:
    return canonical.split(".")[0] in _REQUEST_ROOTS or canonical.startswith(
        ("response.", "request.", "req.")
    )


def _looks_like_archive(canonical: str) -> bool:
    return any(
        value in canonical.lower() for value in ("zip", "tar", "archive", "extract", "unzip")
    )


def _looks_like_xml(canonical: str) -> bool:
    return any(value in canonical.lower() for value in ("xml", "domparser", "sax"))


def _input_nodes(
    node: Node, values: tuple[Node, ...], operation: EcmaScriptCwe400Operation, source: bytes
) -> tuple[Node, ...]:
    if not values:
        return ()
    if operation in {
        EcmaScriptCwe400Operation.FILE_READ,
        EcmaScriptCwe400Operation.FILE_READ_SYNC,
        EcmaScriptCwe400Operation.STREAM_READ,
        EcmaScriptCwe400Operation.JSON_PARSE,
        EcmaScriptCwe400Operation.XML_PARSE,
        EcmaScriptCwe400Operation.ARCHIVE_EXTRACT,
        EcmaScriptCwe400Operation.DECOMPRESSION,
    }:
        return (values[0],)
    if operation is EcmaScriptCwe400Operation.BODY_READ:
        return (values[0],) if values else ()
    return (values[0],)


def _has_explicit_limit(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return False
    values = arguments.named_children
    for value in values[1:]:
        if _contains_limit_property(value, source):
            return True
    if values and _bounded_expression(values[0], source, aliases):
        return True
    function = node.child_by_field_name("function")
    return function is not None and _bounded_expression(function, source, aliases)


def _contains_limit_property(node: Node, source: bytes) -> bool:
    if node.type in {"object", "object_pattern", "array", "arguments"}:
        for child in node.named_children:
            if child.type in {"pair", "property_signature", "object_pattern_property"}:
                key = child.child_by_field_name("key") or child.child_by_field_name("name")
                if key is not None and _property_name(key, source) in _SIZE_KEYS:
                    return True
            if _contains_limit_property(child, source):
                return True
    return any(_contains_limit_property(child, source) for child in node.named_children)


def _bounded_expression(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    if node.type in {"call_expression", "new_expression"}:
        function = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        arguments = node.child_by_field_name("arguments")
        canonical = _canonical_expression(function, source, aliases) if function is not None else ""
        if canonical is not None and any(
            token in canonical.lower()
            for token in ("limit", "truncate", "slice", "subarray", "take", "bounded", "capped")
        ):
            return True
        if (
            arguments is not None
            and len(arguments.named_children) >= 2
            and _static_number(arguments.named_children[1], source)
            and canonical is not None
            and canonical.endswith(("slice", "subarray", "substring", "substr"))
        ):
            return True
    if node.type in {"member_expression", "subscript_expression"}:
        value = _compact_text(source, node).lower()
        if any(token in value for token in (".slice", ".subarray", ".take", ".limit")):
            return True
    return False


def _static_number(node: Node, source: bytes) -> bool:
    return bool(re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?", _compact_text(source, node)))


def _is_public_context(node: Node, root: Node, source: bytes) -> bool:
    current: Node | None = node
    while current is not None:
        if current.type in {
            "function_declaration",
            "function",
            "function_expression",
            "arrow_function",
            "method_definition",
        }:
            prefix = source[current.start_byte : min(current.end_byte, current.start_byte + 240)]
            text = _decode(prefix).lower()
            if any(
                token in text for token in ("req", "request", "context", "ctx", "event", "handler")
            ):
                return True
        current = current.parent
    current = node.parent
    while current is not None:
        if current.type == "call_expression":
            function = current.child_by_field_name("function")
            if function is not None:
                name = _compact_text(source, function).lower()
                if name.split(".")[-1] in {
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                    "use",
                    "route",
                    "all",
                    "handle",
                }:
                    return True
        current = current.parent
    return False


def _resolve_source(
    node: Node,
    *,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe400ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[Node, ...]:
    if depth > limits.max_depth:
        raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.DEPTH_LIMIT)
    if _is_request_source(node, source):
        return (node,)
    if node.type == "identifier":
        name = _text(source, node)
        if name in visited:
            return ()
        bound = _latest_binding(scope, name, node.start_byte, source)
        if bound is None:
            return ()
        return _resolve_source(
            bound,
            scope=scope,
            source=source,
            aliases=aliases,
            limits=limits,
            depth=depth + 1,
            visited=visited | {name},
        )
    if node.type in {
        "await_expression",
        "parenthesized_expression",
        "non_null_expression",
        "unary_expression",
        "as_expression",
        "satisfies_expression",
        "new_expression",
    }:
        return _resolve_children(node, scope, source, aliases, limits, depth + 1, visited)
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            return ()
        canonical = _canonical_expression(function, source, aliases)
        if canonical in _PRESERVING_CALLS or (
            canonical is not None
            and canonical.endswith((".toString", ".trim", ".slice", ".subarray", ".map", ".filter"))
        ):
            return _resolve_children(arguments, scope, source, aliases, limits, depth + 1, visited)
        return ()
    if node.type in {
        "binary_expression",
        "conditional_expression",
        "assignment_expression",
        "ternary_expression",
        "template_substitution",
        "template_string",
        "sequence_expression",
        "logical_expression",
        "object",
        "array",
    }:
        return _resolve_children(node, scope, source, aliases, limits, depth + 1, visited)
    if node.type in {"member_expression", "subscript_expression"}:
        return _resolve_children(node, scope, source, aliases, limits, depth + 1, visited)
    return ()


def _resolve_children(
    node: Node,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe400ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[Node, ...]:
    values: list[Node] = []
    for child in node.named_children:
        values.extend(
            _resolve_source(
                child,
                scope=scope,
                source=source,
                aliases=aliases,
                limits=limits,
                depth=depth,
                visited=visited,
            )
        )
    unique = {(value.start_byte, value.end_byte): value for value in values}
    return tuple(unique[key] for key in sorted(unique))


def _is_request_source(node: Node, source: bytes) -> bool:
    compact = _compact_text(source, node).replace("?.", ".")
    if node.type in {"member_expression", "subscript_expression"}:
        pieces = compact.replace("[", ".[").split(".")
        if len(pieces) >= 2 and pieces[0] in _REQUEST_ROOTS:
            return any(piece in _REQUEST_FIELDS for piece in pieces[1:])
        return False
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    if function is None:
        return False
    callee = _compact_text(source, function).replace("?.", ".")
    parts = callee.replace("[", ".[").split(".")
    if (
        parts
        and parts[0] in _REQUEST_ROOTS
        and callee.endswith(
            (".get", ".param", ".header", ".text", ".json", ".arrayBuffer", ".formData")
        )
    ):
        return True
    return callee.endswith((".searchParams.get", ".query.get"))


def _enclosing_scope(node: Node, root: Node) -> Node:
    current = node.parent
    while current is not None:
        if current.type in {
            "function_declaration",
            "function",
            "function_expression",
            "arrow_function",
            "generator_function",
            "generator_function_declaration",
            "method_definition",
        }:
            return current
        current = current.parent
    return root


def _latest_binding(scope: Node, name: str, before: int, source: bytes) -> Node | None:
    bound: Node | None = None
    for node in _scope_preorder(scope):
        if node.start_byte >= before:
            continue
        if node.type == "variable_declarator":
            left, right = node.child_by_field_name("name"), node.child_by_field_name("value")
        elif node.type == "assignment_expression":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        else:
            continue
        if (
            left is not None
            and right is not None
            and left.type == "identifier"
            and _text(source, left) == name
        ):
            bound = right
    return bound


def _scope_preorder(scope: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    nested = {
        "function_declaration",
        "function",
        "function_expression",
        "arrow_function",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
    first = True
    while stack:
        node = stack.pop()
        output.append(node)
        if not first and node.type in nested:
            continue
        first = False
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _collect_aliases(nodes: tuple[Node, ...], source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in nodes:
        if node.type == "import_statement":
            _collect_import_aliases(node, source, aliases)
        elif node.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in node.named_children:
                if declarator.type != "variable_declarator":
                    continue
                name, value = (
                    declarator.child_by_field_name("name"),
                    declarator.child_by_field_name("value"),
                )
                if name is None or value is None:
                    continue
                canonical = _canonical_expression(value, source, aliases)
                if canonical is None:
                    continue
                if name.type == "identifier":
                    aliases[_text(source, name)] = canonical
                elif name.type in {"object_pattern", "object"}:
                    _collect_pattern_aliases(name, canonical, source, aliases)
        elif node.type == "assignment_expression":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                canonical = _canonical_expression(right, source, aliases)
                if canonical is not None:
                    aliases[_text(source, left)] = canonical
    return aliases


def _collect_import_aliases(node: Node, source: bytes, aliases: dict[str, str]) -> None:
    module_node = node.child_by_field_name("source")
    if module_node is None:
        return
    module = _string_value(module_node, source)
    if module is None:
        return
    module = _normalise_module(module)
    if module is None:
        return
    for clause in node.named_children:
        if clause.type != "import_clause":
            continue
        for item in clause.named_children:
            if item.type == "identifier":
                aliases[_text(source, item)] = module
            elif item.type == "namespace_import":
                children = item.named_children
                if children:
                    aliases[_text(source, children[-1])] = module
            elif item.type in {"named_imports", "named_import"}:
                for specifier in item.named_children:
                    if specifier.type != "import_specifier":
                        continue
                    names = list(specifier.named_children)
                    if names:
                        aliases[_text(source, names[-1])] = f"{module}.{_text(source, names[0])}"


def _collect_pattern_aliases(
    pattern: Node, module: str, source: bytes, aliases: dict[str, str]
) -> None:
    for child in pattern.named_children:
        if child.type not in {
            "pair",
            "object_pattern_property",
            "shorthand_property_identifier_pattern",
        }:
            continue
        key = child.child_by_field_name("key") or child
        value = child.child_by_field_name("value") or key
        key_name, value_name = _property_name(key, source), _property_name(value, source)
        if key_name and value_name:
            aliases[value_name] = f"{module}.{key_name}"


def _canonical_expression(node: Node | None, source: bytes, aliases: dict[str, str]) -> str | None:
    if node is None:
        return None
    if node.type == "call_expression":
        function, arguments = (
            node.child_by_field_name("function"),
            node.child_by_field_name("arguments"),
        )
        if function is None or arguments is None or _compact_text(source, function) != "require":
            return None
        values = arguments.named_children
        if len(values) != 1:
            return None
        module = _string_value(values[0], source)
        return _normalise_module(module) if module is not None else None
    path = _member_path(node, source, aliases)
    if path is not None:
        return _canonical_name(".".join(path), aliases)
    return _canonical_name(_compact_text(source, node), aliases)


def _member_path(node: Node, source: bytes, aliases: dict[str, str]) -> tuple[str, ...] | None:
    if node.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "this",
        "super",
    }:
        value = _text(source, node)
        return (value,) if value and value != "#" else None
    if node.type in {"member_expression", "subscript_expression"}:
        object_node, property_node = (
            node.child_by_field_name("object"),
            node.child_by_field_name("property"),
        )
        property_node = property_node or node.child_by_field_name("index")
        if object_node is None or property_node is None:
            return None
        base = _canonical_expression(object_node, source, aliases)
        property_name = _property_name(property_node, source)
        if base is None or property_name is None:
            return None
        return (*base.split("."), property_name)
    return None


def _canonical_name(value: str, aliases: dict[str, str]) -> str:
    parts = value.split(".")
    if not parts or not _IDENTIFIER.fullmatch(parts[0]):
        return value
    base = aliases.get(parts[0], parts[0])
    return ".".join((base, *parts[1:])) if len(parts) > 1 else base


def _normalise_module(value: str | None) -> str | None:
    if value is None:
        return None
    return value[5:] if value.startswith("node:") else value


def _property_name(node: Node, source: bytes) -> str | None:
    value = _compact_text(source, node).strip("'\"")
    return value if value and _IDENTIFIER.fullmatch(value) else None


def _string_value(node: Node, source: bytes) -> str | None:
    if node.type not in {"string", "string_fragment"}:
        return None
    value = source[node.start_byte : node.end_byte]
    if node.type == "string":
        if len(value) < 2 or value[:1] not in {b"'", b'"', b"`"} or value[-1:] != value[:1]:
            return None
        value = value[1:-1]
    if b"\\" in value or b"\n" in value or b"\r" in value:
        return None
    return _decode(value)


def _text(source: bytes, node: Node) -> str:
    return _decode(source[node.start_byte : node.end_byte])


def _decode(value: bytes) -> str:
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe400ScanError(EcmaScriptCwe400ScanErrorCode.INTEGRITY_FAILURE) from None


def _compact_text(source: bytes, node: Node) -> str:
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
    operation: EcmaScriptCwe400Operation,
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
    language: str,
    signals: tuple[EcmaScriptCwe400Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-400",
        "detector": _DETECTOR,
        "language": language,
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


scan_javascript_resource_exhaustion = scan_javascript_cwe400
scan_typescript_resource_exhaustion = scan_typescript_cwe400
scan_ecmascript_resource_exhaustion = scan_ecmascript_cwe400


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE400_SCAN_LIMITS",
    "EcmaScriptCwe400Operation",
    "EcmaScriptCwe400ScanError",
    "EcmaScriptCwe400ScanErrorCode",
    "EcmaScriptCwe400ScanLimits",
    "EcmaScriptCwe400ScanResult",
    "EcmaScriptCwe400Signal",
    "scan_ecmascript_cwe400",
    "scan_ecmascript_resource_exhaustion",
    "scan_javascript_cwe400",
    "scan_javascript_resource_exhaustion",
    "scan_typescript_cwe400",
    "scan_typescript_resource_exhaustion",
]
