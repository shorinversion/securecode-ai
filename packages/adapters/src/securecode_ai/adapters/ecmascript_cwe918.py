"""Bounded JavaScript and TypeScript source-to-HTTP facts for CWE-918.

The scanner accepts one sealed ECMAScript ``SymbolIndex`` and reparses the
admitted bytes before inspecting the CST.  It recognizes request and
environment URL sources, common fetch/axios/got/undici and Node HTTP sinks,
and only a bounded set of local aliases and string transformations.  Values
returned by explicit URL allow-list validators are treated as sanitized.  The
result is an immutable structural fact stream, never a finding or verdict.

No source text is retained in signals or scanner errors.  Unknown aliases,
reflection, dynamic property names, and unsupported control flow are ignored
so callers can fail closed when a complete analysis is required.
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
_RULE_ID = "securecode-ecmascript-cwe918"
_DETECTOR = "securecode-ecmascript-cwe918@1.0"

_REQUEST_ROOTS = frozenset({"ctx", "context", "event", "httpRequest", "req", "request", "route"})
_REQUEST_FIELDS = frozenset(
    {
        "body",
        "cookie",
        "cookies",
        "headers",
        "host",
        "hostname",
        "params",
        "path",
        "pathParameters",
        "query",
        "queryStringParameters",
        "url",
    }
)
_ENV_ROOTS = frozenset({"process.env", "Bun.env", "import.meta.env"})
_URL_MODULES = frozenset({"url", "node:url"})
_HTTP_MODULES = frozenset({"http", "https", "node:http", "node:https"})
_FETCH_MODULES = frozenset(
    {"node-fetch", "cross-fetch", "isomorphic-fetch", "undici", "@whatwg-node/fetch"}
)
_AXIOS_MODULES = frozenset({"axios"})
_GOT_MODULES = frozenset({"got", "got-cjs"})
_UNDICI_MODULES = frozenset({"undici"})
_SINK_MODULES = _HTTP_MODULES | _FETCH_MODULES | _AXIOS_MODULES | _GOT_MODULES
_PRESERVING_FUNCTIONS = frozenset(
    {
        "String",
        "decodeURI",
        "decodeURIComponent",
        "encodeURI",
        "encodeURIComponent",
        "URLSearchParams",
        "url.format",
        "URL.prototype.toString",
    }
)
_URL_PARSERS = frozenset(
    {
        "URL",
        "url.URL",
        "url.parse",
        "URL.parse",
        "whatwgURL.URL",
    }
)
_URL_SANITIZERS = frozenset(
    {
        "allowlistedUrl",
        "allowedUrl",
        "assertAllowedUrl",
        "assertSafeUrl",
        "ensureSafeUrl",
        "isAllowedUrl",
        "isPrivateUrl",
        "isSafeUrl",
        "assertValidUrl",
        "sanitizeUrl",
        "safeUrl",
        "validateExternalUrl",
        "validateUrl",
        "validateUrlAllowlist",
        "urlValidation.validate",
        "urlValidator.validate",
    }
)


class EcmaScriptCwe918ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-918 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe918ScanError(RuntimeError):
    """Fixed scanner failure that never echoes source or parser text."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe918ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe918ScanErrorCode:
            raise TypeError("ECMAScript CWE-918 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-918 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe918ScanLimits:
    """Hard ceilings applied before and during structural data-flow analysis."""

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
            raise ValueError("ECMAScript CWE-918 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE918_SCAN_LIMITS = EcmaScriptCwe918ScanLimits()


class EcmaScriptCwe918Operation(StrEnum):
    """Recognized HTTP client boundary receiving a URL."""

    FETCH = "fetch"
    AXIOS = "axios"
    AXIOS_METHOD = "axios_method"
    GOT = "got"
    GOT_METHOD = "got_method"
    UNDICI_FETCH = "undici_fetch"
    UNDICI_REQUEST = "undici_request"
    HTTP_GET = "http_get"
    HTTP_REQUEST = "http_request"
    HTTP_CLIENT_REQUEST = "http_client_request"

    # Descriptive compatibility names used by language-neutral callers.
    FETCH_API = "fetch"
    AXIOS_REQUEST = "axios"
    NODE_HTTP = "http_request"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe918Signal:
    """One immutable untrusted URL to HTTP client fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe918Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-918"
    detector: str = _DETECTOR
    detail: str = "untrusted_url_to_http_client"

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
            if valid_ranges and type(self.operation) is EcmaScriptCwe918Operation
            else ""
        )
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not EcmaScriptCwe918Operation
            or type(self.signal_id) is not str
            or self.signal_id not in {"", expected}
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-918"
            or self.detector != _DETECTOR
            or self.detail != "untrusted_url_to_http_client"
        ):
            raise ValueError("ECMAScript CWE-918 signal is invalid")
        if self.signal_id == "":
            object.__setattr__(self, "signal_id", expected)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete HTTP sink location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe918ScanResult:
    """Deterministic source-free result for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe918Signal, ...]
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
            and self.language in {"javascript", "typescript"}
        )
        if valid_identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid_identity = False
        valid_signals = type(self.signals) is tuple and all(
            type(item) is EcmaScriptCwe918Signal for item in self.signals
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
            raise ValueError("ECMAScript CWE-918 scan result is invalid")


def scan_javascript_cwe918(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe918ScanLimits = DEFAULT_ECMASCRIPT_CWE918_SCAN_LIMITS,
) -> EcmaScriptCwe918ScanResult:
    """Find bounded JavaScript source-to-HTTP URL flows."""

    return _scan_ecmascript_cwe918(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe918(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe918ScanLimits = DEFAULT_ECMASCRIPT_CWE918_SCAN_LIMITS,
) -> EcmaScriptCwe918ScanResult:
    """Find bounded TypeScript source-to-HTTP URL flows."""

    return _scan_ecmascript_cwe918(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe918(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe918ScanLimits = DEFAULT_ECMASCRIPT_CWE918_SCAN_LIMITS,
) -> EcmaScriptCwe918ScanResult:
    """Dispatch a CWE-918 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe918(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe918(symbol_index, limits=limits)
    raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe918(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe918ScanLimits,
) -> EcmaScriptCwe918ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe918ScanLimits:
        raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.ANALYSIS_UNAVAILABLE)

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
        raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.INTEGRITY_FAILURE) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.ANALYSIS_UNAVAILABLE)
        aliases = _collect_aliases(nodes, source)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe918Operation]] = set()
        for node in nodes:
            if node.type not in {"call_expression", "new_expression"}:
                continue
            operation = _operation_for_sink(node, source, aliases)
            if operation is None:
                continue
            arguments = node.child_by_field_name("arguments")
            if arguments is None:
                continue
            sink = _range(node)
            scope = _enclosing_scope(node, root)
            for argument in _sink_arguments(arguments, operation):
                flows = _resolve_url_sources(
                    argument,
                    scope=scope,
                    source=source,
                    aliases=aliases,
                    limits=limits,
                    depth=0,
                    visited=frozenset(),
                )
                for flow in flows:
                    if flow.sanitized:
                        continue
                    if not sink.contains(_range(flow.source)):
                        raise EcmaScriptCwe918ScanError(
                            EcmaScriptCwe918ScanErrorCode.INTEGRITY_FAILURE
                        )
                    raw.add((_range(flow.source), sink, operation))
                    if len(raw) > limits.max_signals:
                        raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.SIGNAL_LIMIT)
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
    except EcmaScriptCwe918ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.INTEGRITY_FAILURE) from None

    if len(ordered) > limits.max_signals:
        raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        EcmaScriptCwe918Signal(
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
    return EcmaScriptCwe918ScanResult(
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


@dataclass(frozen=True, slots=True)
class _Flow:
    source: Node
    sanitized: bool = False


def _bounded_nodes(root: Node, limits: EcmaScriptCwe918ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _operation_for_sink(
    node: Node, source: bytes, aliases: dict[str, str]
) -> EcmaScriptCwe918Operation | None:
    function = node.child_by_field_name("function")
    if node.type == "new_expression":
        function = node.child_by_field_name("constructor") or node.child_by_field_name("function")
    if function is None:
        return None
    canonical = _canonical_expression(function, source, aliases)
    if canonical is None:
        return None
    if canonical in {"fetch", "globalThis.fetch", "window.fetch"}:
        return EcmaScriptCwe918Operation.FETCH
    if canonical in _FETCH_MODULES or (
        canonical.rsplit(".", 1)[0] in _FETCH_MODULES and canonical.rsplit(".", 1)[-1] == "fetch"
    ):
        return (
            EcmaScriptCwe918Operation.UNDICI_FETCH
            if canonical.rsplit(".", 1)[0] == "undici" or canonical == "undici"
            else EcmaScriptCwe918Operation.FETCH
        )
    if canonical == "axios":
        return EcmaScriptCwe918Operation.AXIOS
    if canonical.startswith("axios.") and canonical.rsplit(".", 1)[-1] in {
        "all",
        "delete",
        "get",
        "head",
        "options",
        "patch",
        "post",
        "put",
        "request",
    }:
        return EcmaScriptCwe918Operation.AXIOS_METHOD
    if canonical == "got":
        return EcmaScriptCwe918Operation.GOT
    if canonical.startswith("got.") and canonical.rsplit(".", 1)[-1] in {
        "delete",
        "get",
        "head",
        "patch",
        "post",
        "put",
        "stream",
    }:
        return EcmaScriptCwe918Operation.GOT_METHOD
    if canonical in {"undici.fetch", "fetch.fetch"}:
        return EcmaScriptCwe918Operation.UNDICI_FETCH
    if canonical in {"undici.request", "undici.stream", "undici.pipeline"}:
        return EcmaScriptCwe918Operation.UNDICI_REQUEST
    if canonical in {"http.get", "https.get"}:
        return EcmaScriptCwe918Operation.HTTP_GET
    if canonical in {"http.request", "https.request"}:
        return EcmaScriptCwe918Operation.HTTP_REQUEST
    if canonical.endswith(".request") and canonical.split(".", 1)[0] in {
        "client",
        "httpClient",
    }:
        return EcmaScriptCwe918Operation.HTTP_CLIENT_REQUEST
    return None


def _sink_arguments(arguments: Node, operation: EcmaScriptCwe918Operation) -> tuple[Node, ...]:
    values = arguments.named_children
    if not values:
        return ()
    if operation in {
        EcmaScriptCwe918Operation.AXIOS,
        EcmaScriptCwe918Operation.GOT,
        EcmaScriptCwe918Operation.AXIOS_METHOD,
        EcmaScriptCwe918Operation.GOT_METHOD,
        EcmaScriptCwe918Operation.UNDICI_REQUEST,
        EcmaScriptCwe918Operation.HTTP_REQUEST,
        EcmaScriptCwe918Operation.HTTP_CLIENT_REQUEST,
    }:
        return (values[0],)
    return (values[0],)


def _resolve_url_sources(
    node: Node,
    *,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe918ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[_Flow, ...]:
    if depth > limits.max_depth:
        raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.DEPTH_LIMIT)
    current = _unwrap(node)
    if _is_url_source(current, source):
        return (_Flow(current),)
    if current.type == "identifier":
        name = _text(source, current)
        if name in visited:
            return ()
        bound = _latest_binding(scope, name, current.start_byte, source)
        if bound is None:
            return ()
        return _resolve_url_sources(
            bound,
            scope=scope,
            source=source,
            aliases=aliases,
            limits=limits,
            depth=depth + 1,
            visited=visited | {name},
        )
    if current.type in {
        "await_expression",
        "parenthesized_expression",
        "non_null_expression",
        "unary_expression",
        "as_expression",
        "satisfies_expression",
    }:
        return _resolve_children(current, scope, source, aliases, limits, depth + 1, visited)
    if current.type in {"call_expression", "new_expression"}:
        function = current.child_by_field_name("function")
        if current.type == "new_expression":
            function = current.child_by_field_name("constructor") or current.child_by_field_name(
                "function"
            )
        arguments = current.child_by_field_name("arguments")
        if function is None or arguments is None:
            return ()
        canonical = _canonical_expression(function, source, aliases)
        if _is_url_sanitizer(canonical):
            flows = _resolve_children(arguments, scope, source, aliases, limits, depth + 1, visited)
            return tuple(_Flow(flow.source, sanitized=True) for flow in flows)
        if canonical in _URL_PARSERS or canonical in _PRESERVING_FUNCTIONS:
            return _resolve_children(arguments, scope, source, aliases, limits, depth + 1, visited)
        if canonical and canonical.endswith((".toString", ".trim", ".toLowerCase", ".toUpperCase")):
            return _resolve_children(current, scope, source, aliases, limits, depth + 1, visited)
        return ()
    if current.type in {
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
        "pair",
        "spread_element",
    }:
        return _resolve_children(current, scope, source, aliases, limits, depth + 1, visited)
    if current.type in {"member_expression", "subscript_expression"}:
        return _resolve_children(current, scope, source, aliases, limits, depth + 1, visited)
    return ()


def _resolve_children(
    node: Node,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe918ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[_Flow, ...]:
    values: list[_Flow] = []
    for child in node.named_children:
        values.extend(
            _resolve_url_sources(
                child,
                scope=scope,
                source=source,
                aliases=aliases,
                limits=limits,
                depth=depth,
                visited=visited,
            )
        )
    unique: dict[tuple[int, int, bool], _Flow] = {}
    for value in values:
        unique[(value.source.start_byte, value.source.end_byte, value.sanitized)] = value
    return tuple(unique[key] for key in sorted(unique))


def _is_url_source(node: Node, source: bytes) -> bool:
    compact = _compact_text(source, node).replace("?.", ".")
    if node.type in {"member_expression", "subscript_expression"}:
        return _member_url_source(compact)
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    if function is None:
        return False
    callee = _compact_text(source, function).replace("?.", ".")
    return _call_url_source(callee)


def _is_url_sanitizer(canonical: str | None) -> bool:
    if canonical is None:
        return False
    return canonical in _URL_SANITIZERS or canonical.rsplit(".", 1)[-1] in {
        "allowlistedUrl",
        "allowedUrl",
        "assertAllowedUrl",
        "assertSafeUrl",
        "assertValidUrl",
        "ensureSafeUrl",
        "sanitizeUrl",
        "safeUrl",
        "validateExternalUrl",
        "validateUrl",
        "validateUrlAllowlist",
    }


def _member_url_source(value: str) -> bool:
    normalized = value.replace("[", ".[")
    pieces = normalized.split(".")
    if len(pieces) >= 3 and pieces[0] in _REQUEST_ROOTS:
        index = 1
        if pieces[index] == "request":
            index += 1
        if index < len(pieces) and pieces[index] in _REQUEST_FIELDS:
            return len(pieces) > index + 1 and any(part for part in pieces[index + 1 :])
    if value.startswith("process.env.") or value.startswith("Bun.env."):
        return len(value.split(".")) >= 3
    if value.startswith("import.meta.env."):
        return len(value.split(".")) >= 3
    return False


def _call_url_source(callee: str) -> bool:
    pieces = callee.replace("[", ".[").split(".")
    if pieces and pieces[0] in _REQUEST_ROOTS:
        return callee.endswith((".get", ".param", ".header")) and (
            len(pieces) >= 2
            and (pieces[-2] in _REQUEST_FIELDS or pieces[-1] in {"param", "header"})
        )
    if callee in {"process.env.get", "Bun.env.get", "Deno.env.get"}:
        return True
    return callee.endswith(".searchParams.get")


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
            left = node.child_by_field_name("name")
            right = node.child_by_field_name("value")
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
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
                name = declarator.child_by_field_name("name")
                value = declarator.child_by_field_name("value")
                if name is None or value is None:
                    continue
                canonical = _canonical_expression(value, source, aliases)
                if name.type == "identifier" and canonical is not None:
                    aliases[_text(source, name)] = canonical
                elif name.type in {"object_pattern", "object"}:
                    _collect_pattern_aliases(name, value, source, aliases)
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
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
    if module not in _SINK_MODULES | _URL_MODULES:
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
                    if not names:
                        continue
                    imported = _text(source, names[0])
                    local = _text(source, names[-1])
                    aliases[local] = f"{module}.{imported}"


def _collect_pattern_aliases(
    pattern: Node, value: Node, source: bytes, aliases: dict[str, str]
) -> None:
    module = _canonical_expression(value, source, aliases)
    if module is None:
        return
    for child in pattern.named_children:
        if child.type not in {
            "pair",
            "object_pattern_property",
            "shorthand_property_identifier_pattern",
        }:
            continue
        key = child.child_by_field_name("key") or child
        local_node = child.child_by_field_name("value") or key
        key_name = _static_property_name(key, source)
        local_name = _static_property_name(local_node, source)
        if key_name is not None and local_name is not None:
            aliases[local_name] = f"{module}.{key_name}"


def _canonical_expression(node: Node, source: bytes, aliases: dict[str, str]) -> str | None:
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or _compact_text(source, function) != "require":
            return None
        values = arguments.named_children
        if len(values) != 1:
            return None
        module = _string_value(values[0], source)
        if module is None:
            return None
        return _normalise_module(module)
    if node.type == "new_expression":
        constructor = node.child_by_field_name("constructor") or node.child_by_field_name(
            "function"
        )
        return (
            _canonical_expression(constructor, source, aliases) if constructor is not None else None
        )
    if node.type in {"member_expression", "subscript_expression"}:
        object_node = node.child_by_field_name("object")
        property_node = node.child_by_field_name("property") or node.child_by_field_name("index")
        if object_node is None or property_node is None:
            return None
        base = _canonical_expression(object_node, source, aliases)
        if base is None:
            base = _canonical_name(_compact_text(source, object_node), aliases)
        property_name = _static_property_name(property_node, source)
        if base is None or property_name is None:
            return None
        return f"{base}.{property_name}"
    return _canonical_name(_compact_text(source, node), aliases)


def _canonical_name(value: str, aliases: dict[str, str]) -> str:
    parts = value.split(".")
    if not parts or not _IDENTIFIER.fullmatch(parts[0]):
        return value
    base = aliases.get(parts[0], parts[0])
    if len(parts) == 1:
        return base
    return ".".join((base, *parts[1:]))


def _normalise_module(value: str) -> str:
    return value[5:] if value.startswith("node:") else value


def _static_property_name(node: Node, source: bytes) -> str | None:
    if node.type == "computed_property_name":
        values = list(node.named_children)
        return _static_property_name(values[0], source) if len(values) == 1 else None
    if node.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        return _text(source, node)
    if node.type in {"string", "string_fragment"}:
        return _string_value(node, source)
    return None


def _unwrap(node: Node) -> Node:
    current = node
    while current.type in {"parenthesized_expression", "as_expression", "non_null_expression"}:
        values = list(current.named_children)
        if not values:
            break
        current = values[-1]
    return current


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
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.INTEGRITY_FAILURE) from None


def _text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe918ScanError(EcmaScriptCwe918ScanErrorCode.INTEGRITY_FAILURE) from None


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
    operation: EcmaScriptCwe918Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-918",
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
    signals: tuple[EcmaScriptCwe918Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-918",
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


# Discoverable names for language-neutral callers.
scan_javascript_cwe918_ssrf = scan_javascript_cwe918
scan_typescript_cwe918_ssrf = scan_typescript_cwe918
scan_ecmascript_cwe918_ssrf = scan_ecmascript_cwe918
scan_javascript_ssrf = scan_javascript_cwe918
scan_typescript_ssrf = scan_typescript_cwe918
scan_ecmascript_ssrf = scan_ecmascript_cwe918


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE918_SCAN_LIMITS",
    "EcmaScriptCwe918Operation",
    "EcmaScriptCwe918ScanError",
    "EcmaScriptCwe918ScanErrorCode",
    "EcmaScriptCwe918ScanLimits",
    "EcmaScriptCwe918ScanResult",
    "EcmaScriptCwe918Signal",
    "scan_ecmascript_cwe918",
    "scan_ecmascript_cwe918_ssrf",
    "scan_ecmascript_ssrf",
    "scan_javascript_cwe918",
    "scan_javascript_cwe918_ssrf",
    "scan_javascript_ssrf",
    "scan_typescript_cwe918",
    "scan_typescript_cwe918_ssrf",
    "scan_typescript_ssrf",
]
