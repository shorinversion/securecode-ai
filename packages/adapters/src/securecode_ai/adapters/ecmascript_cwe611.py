"""Bounded JavaScript and TypeScript XML external entity facts for CWE-611.

The scanner accepts one sealed ECMAScript ``SymbolIndex`` and reparses the
admitted bytes before inspecting a bounded CST.  It recognises the common
``xml2js``, ``xml-js``, ``fast-xml-parser``, ``xmldom``, and ``libxmljs``
entry points, follows request-derived XML values through local aliases, and
suppresses parser calls with an explicit external-entity, DTD, and network
safe configuration.  Results contain only immutable source ranges and
content-addressed identity.  Source text is never retained in findings or
errors.
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
_RULE_ID = "securecode-ecmascript-cwe611"
_DETECTOR = "securecode-ecmascript-cwe611@1.0"

_REQUEST_ROOTS = frozenset(
    {"ctx", "context", "event", "http", "httpRequest", "koa", "req", "request", "route"}
)
_REQUEST_FIELDS = frozenset(
    {
        "body",
        "content",
        "data",
        "document",
        "input",
        "payload",
        "rawBody",
        "requestBody",
        "text",
        "xml",
        "xmlData",
        "xmlDocument",
    }
)
_XML_PARAMETER_NAMES = frozenset(
    {
        "body",
        "content",
        "data",
        "document",
        "input",
        "payload",
        "rawBody",
        "requestBody",
        "text",
        "xml",
        "xmlData",
        "xmlDocument",
    }
)
_XML_MODULES = frozenset({"xml-js", "xml2js", "fast-xml-parser", "xmldom", "libxmljs"})
_SAFE_XML_TRANSFORMS = frozenset(
    {
        "decodeURI",
        "decodeURIComponent",
        "String",
        "String.raw",
        "Buffer.from",
        "TextDecoder",
        "JSON.stringify",
    }
)
_XML_SANITIZERS = frozenset(
    {
        "disableExternalEntities",
        "escapeXml",
        "escapeXML",
        "sanitizeXml",
        "safeXml",
        "validateXml",
    }
)

# These names cover the security switches exposed by the supported modules
# and by the native libxml2 bindings.  A false value disables the feature;
# ``nonet`` and its aliases are safe when true.
_SAFE_FALSE_FLAGS = frozenset(
    {
        "allowDtd",
        "allowDTD",
        "allowExternalEntities",
        "enableDtd",
        "enableDTD",
        "enableExternalEntities",
        "externalEntities",
        "fetchExternalEntities",
        "loadDtd",
        "loadDTD",
        "loadExternalDtd",
        "loadExternalDTD",
        "network",
        "noent",
        "dtd",
        "dtdattr",
        "dtdload",
        "parseNoEnt",
        "processEntities",
        "resolveEntities",
        "resolveExternalEntities",
        "replaceEntities",
        "useDTD",
    }
)
_SAFE_TRUE_FLAGS = frozenset({"disableDtd", "disableDTD", "disableExternalEntities", "noNetwork", "noNet", "nonet"})
_UNSAFE_FALSE_FLAGS = _SAFE_TRUE_FLAGS
_UNSAFE_TRUE_FLAGS = _SAFE_FALSE_FLAGS | frozenset(
    {"dtd", "dtdattr", "dtdload", "parseNoEnt", "replaceEntities"}
)


class EcmaScriptCwe611ScanErrorCode(StrEnum):
    """Closed, source-free reasons an XML scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe611ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser diagnostics."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe611ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe611ScanErrorCode:
            raise TypeError("ECMAScript CWE-611 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-611 XML external entity scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class EcmaScriptCwe611Operation(StrEnum):
    """Recognised XML parser boundaries."""

    XML2JS_PARSE_STRING = "xml2js.parseString"
    XML2JS_PARSE_STRING_PROMISE = "xml2js.parseStringPromise"
    XML2JS_PARSER_PARSE_STRING = "xml2js.Parser.parseString"
    XMLJS_TO_JSON = "xml-js.xml2js"
    FAST_XML_PARSER_PARSE = "fast-xml-parser.XMLParser.parse"
    FAST_XML_PARSE = "fast-xml-parser.parse"
    XMDOM_PARSE_FROM_STRING = "xmldom.DOMParser.parseFromString"
    LIBXMLJS_PARSE_XML = "libxmljs.parseXml"
    LIBXMLJS_PARSE_XML_ASYNC = "libxmljs.parseXmlAsync"

    # Compatibility names for language-neutral consumers.
    XML_PARSE = "xml2js.parseString"
    XML_FROM_STRING = "xml2js.parseString"
    DOM_PARSE_FROM_STRING = "xmldom.DOMParser.parseFromString"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe611ScanLimits:
    """Hard ceilings applied before and during structural analysis."""

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
            raise ValueError("ECMAScript CWE-611 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE611_SCAN_LIMITS = EcmaScriptCwe611ScanLimits()


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe611Signal:
    """One immutable request-derived XML value to an unsafe parser fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe611Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-611"
    detector: str = _DETECTOR

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
            if valid_identity
            and valid_ranges
            and type(self.operation) is EcmaScriptCwe611Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not EcmaScriptCwe611Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-611"
            or self.detector != _DETECTOR
        ):
            raise ValueError("ECMAScript CWE-611 signal is invalid")
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
class EcmaScriptCwe611ScanResult:
    """Deterministic, source-free CWE-611 output for one source file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe611Signal, ...]
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
            type(item) is EcmaScriptCwe611Signal for item in self.signals
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
                self.language,
                self.signals,
            )
        ):
            raise ValueError("ECMAScript CWE-611 scan result is invalid")


def scan_javascript_cwe611(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe611ScanLimits = DEFAULT_ECMASCRIPT_CWE611_SCAN_LIMITS,
) -> EcmaScriptCwe611ScanResult:
    """Find bounded JavaScript XML external-entity facts."""

    return _scan_ecmascript_cwe611(
        symbol_index, expected_language="javascript", limits=limits
    )


def scan_typescript_cwe611(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe611ScanLimits = DEFAULT_ECMASCRIPT_CWE611_SCAN_LIMITS,
) -> EcmaScriptCwe611ScanResult:
    """Find bounded TypeScript XML external-entity facts."""

    return _scan_ecmascript_cwe611(
        symbol_index, expected_language="typescript", limits=limits
    )


def scan_ecmascript_cwe611(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe611ScanLimits = DEFAULT_ECMASCRIPT_CWE611_SCAN_LIMITS,
) -> EcmaScriptCwe611ScanResult:
    """Dispatch a CWE-611 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe611ScanError(EcmaScriptCwe611ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe611(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe611(symbol_index, limits=limits)
    raise EcmaScriptCwe611ScanError(EcmaScriptCwe611ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe611(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe611ScanLimits,
) -> EcmaScriptCwe611ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe611ScanLimits:
        raise EcmaScriptCwe611ScanError(EcmaScriptCwe611ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe611ScanError(EcmaScriptCwe611ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe611ScanError(EcmaScriptCwe611ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe611ScanError(EcmaScriptCwe611ScanErrorCode.ANALYSIS_UNAVAILABLE)

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
        raise EcmaScriptCwe611ScanError(
            EcmaScriptCwe611ScanErrorCode.INTEGRITY_FAILURE
        ) from None
    except Exception:
        raise EcmaScriptCwe611ScanError(
            EcmaScriptCwe611ScanErrorCode.INTEGRITY_FAILURE
        ) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe611ScanError(
                EcmaScriptCwe611ScanErrorCode.ANALYSIS_UNAVAILABLE
            )
        aliases = _collect_aliases(nodes, source)
        object_literals = _collect_object_literals(nodes, source)
        parser_safety = _collect_parser_safety(nodes, source, aliases)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe611Operation]] = set()
        for node in nodes:
            if node.type not in {"call_expression", "new_expression"}:
                continue
            operation = _operation_for_parser(node, source, aliases)
            if operation is None or _is_safe_parser_call(
                node, source, aliases, parser_safety, object_literals
            ):
                continue
            arguments = node.child_by_field_name("arguments")
            if arguments is None:
                continue
            sink = _range(node)
            scope = _enclosing_scope(node, root)
            for argument in _parser_input_arguments(arguments, operation):
                flows = _resolve_xml_sources(
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
                    source_range = _range(flow.source)
                    if not sink.contains(source_range):
                        raise EcmaScriptCwe611ScanError(
                            EcmaScriptCwe611ScanErrorCode.INTEGRITY_FAILURE
                        )
                    raw.add((source_range, sink, operation))
                    if len(raw) > limits.max_signals:
                        raise EcmaScriptCwe611ScanError(
                            EcmaScriptCwe611ScanErrorCode.SIGNAL_LIMIT
                        )
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
    except EcmaScriptCwe611ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe611ScanError(
            EcmaScriptCwe611ScanErrorCode.INTEGRITY_FAILURE
        ) from None

    signals = tuple(
        EcmaScriptCwe611Signal(
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
    return EcmaScriptCwe611ScanResult(
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


def _bounded_nodes(root: Node, limits: EcmaScriptCwe611ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe611ScanError(EcmaScriptCwe611ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe611ScanError(EcmaScriptCwe611ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


_DIRECT_OPERATIONS: dict[str, EcmaScriptCwe611Operation] = {
    "xml2js.parseString": EcmaScriptCwe611Operation.XML2JS_PARSE_STRING,
    "xml2js.parseStringPromise": EcmaScriptCwe611Operation.XML2JS_PARSE_STRING_PROMISE,
    "xml2js.Parser.parseString": EcmaScriptCwe611Operation.XML2JS_PARSER_PARSE_STRING,
    "xml-js.xml2js": EcmaScriptCwe611Operation.XMLJS_TO_JSON,
    "fast-xml-parser.XMLParser.parse": EcmaScriptCwe611Operation.FAST_XML_PARSER_PARSE,
    "fast-xml-parser.parse": EcmaScriptCwe611Operation.FAST_XML_PARSE,
    "xmldom.DOMParser.parseFromString": EcmaScriptCwe611Operation.XMDOM_PARSE_FROM_STRING,
    "libxmljs.parseXml": EcmaScriptCwe611Operation.LIBXMLJS_PARSE_XML,
    "libxmljs.parseXmlAsync": EcmaScriptCwe611Operation.LIBXMLJS_PARSE_XML_ASYNC,
}
_PARSER_CONSTRUCTORS = frozenset(
    {
        "xml2js.Parser",
        "fast-xml-parser.XMLParser",
        "xmldom.DOMParser",
    }
)


def _operation_for_parser(
    node: Node, source: bytes, aliases: dict[str, str]
) -> EcmaScriptCwe611Operation | None:
    if node.type == "new_expression":
        return None
    function = node.child_by_field_name("function")
    if function is None:
        return None
    canonical = _canonical_expression(function, source, aliases)
    return _DIRECT_OPERATIONS.get(canonical or "")


def _parser_input_arguments(
    arguments: Node, operation: EcmaScriptCwe611Operation
) -> tuple[Node, ...]:
    values = arguments.named_children
    if not values:
        return ()
    # Callback and options arguments do not contain the XML document.  For
    # xml2js and libxmljs the first argument is the document.  xml-js and
    # fast-xml-parser use the same convention.  xmldom's first argument is
    # also the document and the second argument is a MIME type.
    if operation in _DIRECT_OPERATIONS.values():
        return (values[0],)
    return ()


def _is_safe_parser_call(
    node: Node,
    source: bytes,
    aliases: dict[str, str],
    parser_safety: dict[str, bool],
    object_literals: dict[str, Node],
) -> bool:
    function = node.child_by_field_name("function")
    if function is None:
        return False
    canonical = _canonical_expression(function, source, aliases)
    if canonical is None:
        return False
    if function.type in {"member_expression", "subscript_expression"}:
        object_node = function.child_by_field_name("object")
        if object_node is not None and object_node.type == "identifier":
            if parser_safety.get(_text(source, object_node), False):
                return True
        if object_node is not None and object_node.type == "new_expression":
            if _configuration_is_safe(object_node, source, object_literals):
                return True
    base = canonical.rsplit(".", 1)[0] if "." in canonical else ""
    if base and parser_safety.get(base.split(".", 1)[0], False):
        return True
    return _configuration_is_safe(node, source, object_literals)


def _collect_parser_safety(
    nodes: tuple[Node, ...], source: bytes, aliases: dict[str, str]
) -> dict[str, bool]:
    safety: dict[str, bool] = {}
    objects = _collect_object_literals(nodes, source)
    for node in nodes:
        if node.type not in {"lexical_declaration", "variable_declaration", "assignment_expression"}:
            continue
        if node.type == "assignment_expression":
            name = node.child_by_field_name("left")
            value = node.child_by_field_name("right")
            targets = ((name, value),)
        else:
            pairs: list[tuple[Node | None, Node | None]] = []
            for declarator in node.named_children:
                if declarator.type == "variable_declarator":
                    pairs.append(
                        (
                            declarator.child_by_field_name("name"),
                            declarator.child_by_field_name("value"),
                        )
                    )
            targets = tuple(pairs)
        for name, value in targets:
            if name is None or value is None or name.type != "identifier":
                continue
            canonical = _canonical_expression(value, source, aliases)
            if canonical not in _PARSER_CONSTRUCTORS:
                continue
            safety[_text(source, name)] = _configuration_is_safe(value, source, objects)
    return safety


def _configuration_is_safe(
    node: Node,
    source: bytes,
    objects: dict[str, Node] | None = None,
) -> bool:
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return False
    values = arguments.named_children
    found_security_flag = False
    for candidate in values:
        option = _resolve_object(candidate, source, objects)
        if option is None or option.type != "object":
            continue
        for child in option.named_children:
            if child.type != "pair":
                continue
            key, value = _pair_parts(child)
            if key is None or value is None:
                continue
            name = _static_property_name(key, source)
            if name is None:
                continue
            literal = _literal_bool(value)
            if literal is None:
                continue
            if name in _SAFE_FALSE_FLAGS or name in _SAFE_TRUE_FLAGS or name in _UNSAFE_FALSE_FLAGS:
                found_security_flag = True
            if name in _UNSAFE_TRUE_FLAGS and literal:
                return False
            if name in _UNSAFE_FALSE_FLAGS and not literal:
                return False
            if name in _SAFE_FALSE_FLAGS and literal:
                return False
    return found_security_flag


def _collect_object_literals(nodes: tuple[Node, ...], source: bytes) -> dict[str, Node]:
    objects: dict[str, Node] = {}
    for node in nodes:
        if node.type not in {"lexical_declaration", "variable_declaration"}:
            continue
        for declarator in node.named_children:
            if declarator.type != "variable_declarator":
                continue
            name = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if name is not None and value is not None and name.type == "identifier":
                if _unwrap(value).type == "object":
                    objects[_text(source, name)] = value
    return objects


def _resolve_object(
    node: Node,
    source: bytes,
    objects: dict[str, Node] | None,
) -> Node | None:
    current = _unwrap(node)
    if current.type == "object":
        return current
    if current.type != "identifier":
        return None
    name = _text(source, current)
    return objects.get(name) if objects is not None else None


def _resolve_xml_sources(
    node: Node,
    *,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe611ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[_Flow, ...]:
    if depth > limits.max_depth:
        raise EcmaScriptCwe611ScanError(EcmaScriptCwe611ScanErrorCode.DEPTH_LIMIT)
    current = _unwrap(node)
    if _is_xml_source(current, source, scope):
        return (_Flow(current),)
    if current.type == "identifier":
        name = _text(source, current)
        if name in visited:
            return ()
        bound = _latest_binding(scope, name, current.start_byte, source)
        if bound is None:
            return ()
        return _resolve_xml_sources(
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
            function = current.child_by_field_name("constructor") or function
        arguments = current.child_by_field_name("arguments")
        if function is None or arguments is None:
            return ()
        canonical = _canonical_expression(function, source, aliases)
        if canonical in _XML_SANITIZERS or (canonical and canonical.rsplit(".", 1)[-1] in _XML_SANITIZERS):
            flows = _resolve_children(arguments, scope, source, aliases, limits, depth + 1, visited)
            return tuple(_Flow(flow.source, sanitized=True) for flow in flows)
        if canonical in _SAFE_XML_TRANSFORMS or (
            canonical and canonical.rsplit(".", 1)[-1] in {"toString", "trim", "read", "text"}
        ):
            return _resolve_children(arguments, scope, source, aliases, limits, depth + 1, visited)
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
        "member_expression",
        "subscript_expression",
    }:
        return _resolve_children(current, scope, source, aliases, limits, depth + 1, visited)
    return ()


def _resolve_children(
    node: Node,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe611ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[_Flow, ...]:
    values: list[_Flow] = []
    for child in node.named_children:
        values.extend(
            _resolve_xml_sources(
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


def _is_xml_source(node: Node, source: bytes, scope: Node) -> bool:
    compact = _compact_text(source, node).replace("?.", ".")
    if node.type in {"member_expression", "subscript_expression"}:
        return _member_xml_source(compact)
    if node.type == "identifier":
        name = _text(source, node)
        return _is_xml_parameter(name, scope, source)
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    if function is None:
        return False
    callee = _compact_text(source, function).replace("?.", ".")
    if callee.endswith((".text", ".read", ".body")):
        return True
    if callee.endswith((".get", ".param", ".header")):
        values = node.child_by_field_name("arguments")
        if values and values.named_children:
            key = _string_value(values.named_children[0], source)
            return key is None or key.lower() in _REQUEST_FIELDS
    return _call_xml_source(callee)


def _member_xml_source(value: str) -> bool:
    pieces = value.replace("[", ".[").split(".")
    if len(pieces) >= 2 and pieces[0] in _REQUEST_ROOTS:
        return any(part in _REQUEST_FIELDS for part in pieces[1:])
    return value.startswith(("process.env.", "Bun.env.", "Deno.env.", "import.meta.env."))


def _call_xml_source(callee: str) -> bool:
    pieces = callee.replace("[", ".[").split(".")
    if pieces and pieces[0] in _REQUEST_ROOTS:
        return callee.endswith((".get", ".param", ".header", ".text", ".read"))
    return callee in {"process.env.get", "Bun.env.get", "Deno.env.get"}


def _is_xml_parameter(name: str, scope: Node, source: bytes) -> bool:
    if name not in _XML_PARAMETER_NAMES:
        return False
    if any(
        child.type == "identifier" and _text(source, child) == name
        for child in scope.named_children
    ):
        return True
    for node in scope.named_children:
        if node.type != "formal_parameters":
            continue
        return any(_compact_text(source, child) == name for child in node.named_children)
    return False


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
        if left is not None and right is not None and left.type == "identifier":
            if _text(source, left) == name:
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
    if module not in _XML_MODULES:
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
    current = _unwrap(node)
    if current.type == "call_expression":
        function = current.child_by_field_name("function")
        arguments = current.child_by_field_name("arguments")
        if function is None or arguments is None or _compact_text(source, function) != "require":
            return None
        values = arguments.named_children
        if len(values) != 1:
            return None
        module = _string_value(values[0], source)
        return _normalise_module(module) if module is not None else None
    if current.type == "new_expression":
        constructor = current.child_by_field_name("constructor") or current.child_by_field_name(
            "function"
        )
        return _canonical_expression(constructor, source, aliases) if constructor is not None else None
    if current.type in {"member_expression", "subscript_expression"}:
        object_node = current.child_by_field_name("object")
        property_node = current.child_by_field_name("property") or current.child_by_field_name("index")
        if object_node is None or property_node is None:
            return None
        base = _canonical_expression(object_node, source, aliases)
        if base is None:
            base = _canonical_name(_compact_text(source, object_node), aliases)
        property_name = _static_property_name(property_node, source)
        return None if base is None or property_name is None else f"{base}.{property_name}"
    return _canonical_name(_compact_text(source, current), aliases)


def _canonical_name(value: str, aliases: dict[str, str]) -> str:
    parts = value.split(".")
    if not parts or not _IDENTIFIER.fullmatch(parts[0]):
        return value
    base = aliases.get(parts[0], parts[0])
    return base if len(parts) == 1 else ".".join((base, *parts[1:]))


def _normalise_module(value: str) -> str:
    return value[5:] if value.startswith("node:") else value


def _static_property_name(node: Node, source: bytes) -> str | None:
    current = _unwrap(node)
    if current.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        return _text(source, current)
    if current.type in {"string", "string_fragment"}:
        return _string_value(current, source)
    return None


def _pair_parts(node: Node) -> tuple[Node | None, Node | None]:
    key = node.child_by_field_name("key")
    value = node.child_by_field_name("value")
    named = list(node.named_children)
    if key is None and named:
        key = named[0]
    if value is None and len(named) >= 2:
        value = named[-1]
    return key, value


def _literal_bool(node: Node) -> bool | None:
    current = _unwrap(node)
    if current.type == "true":
        return True
    if current.type == "false":
        return False
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
    current = _unwrap(node)
    if current.type not in {"string", "string_fragment"}:
        return None
    value = source[current.start_byte : current.end_byte]
    if current.type == "string":
        if len(value) < 2 or value[:1] not in {b"'", b'"', b"`"} or value[-1:] != value[:1]:
            return None
        value = value[1:-1]
    if b"\\" in value or b"\n" in value or b"\r" in value:
        return None
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe611ScanError(
            EcmaScriptCwe611ScanErrorCode.INTEGRITY_FAILURE
        ) from None


def _text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe611ScanError(
            EcmaScriptCwe611ScanErrorCode.INTEGRITY_FAILURE
        ) from None


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
    operation: EcmaScriptCwe611Operation,
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
    language: str,
    signals: tuple[EcmaScriptCwe611Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
        "language": language,
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


Cwe611ScanErrorCode = EcmaScriptCwe611ScanErrorCode
Cwe611ScanError = EcmaScriptCwe611ScanError
Cwe611ScanLimits = EcmaScriptCwe611ScanLimits
Cwe611ScanResult = EcmaScriptCwe611ScanResult
Cwe611Signal = EcmaScriptCwe611Signal

scan_javascript_xml_external_entities = scan_javascript_cwe611
scan_typescript_xml_external_entities = scan_typescript_cwe611
scan_ecmascript_xml_external_entities = scan_ecmascript_cwe611
scan_javascript_xxe = scan_javascript_cwe611
scan_typescript_xxe = scan_typescript_cwe611
scan_ecmascript_xxe = scan_ecmascript_cwe611

__all__ = [
    "Cwe611ScanError",
    "Cwe611ScanErrorCode",
    "Cwe611ScanLimits",
    "Cwe611ScanResult",
    "Cwe611Signal",
    "DEFAULT_ECMASCRIPT_CWE611_SCAN_LIMITS",
    "EcmaScriptCwe611Operation",
    "EcmaScriptCwe611ScanError",
    "EcmaScriptCwe611ScanErrorCode",
    "EcmaScriptCwe611ScanLimits",
    "EcmaScriptCwe611ScanResult",
    "EcmaScriptCwe611Signal",
    "scan_ecmascript_cwe611",
    "scan_ecmascript_xml_external_entities",
    "scan_ecmascript_xxe",
    "scan_javascript_cwe611",
    "scan_javascript_xml_external_entities",
    "scan_javascript_xxe",
    "scan_typescript_cwe611",
    "scan_typescript_xml_external_entities",
    "scan_typescript_xxe",
]
