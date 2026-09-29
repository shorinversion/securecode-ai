"""Bounded ECMAScript XML entity-expansion facts for CWE-776.

The scanner recognizes explicit entity-expansion and DTD-enabling options on
the XML parsers commonly used by JavaScript and TypeScript applications.  It
rebuilds the sealed symbol index before parsing and emits only immutable source
ranges and content-addressed identifiers.  A parser with an explicit safe
configuration is ignored; an unknown or dynamic configuration is not treated
as proof of safety.
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
_RULE_ID = "securecode-ecmascript-cwe776"
_DETECTOR = "securecode-ecmascript-cwe776@1.0"

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
_PARSER_CONSTRUCTORS = frozenset(
    {
        "fast-xml-parser.XMLParser",
        "xmldom.DOMParser",
        "xml2js.Parser",
        "sax.SAXParser",
        "node-expat.Parser",
    }
)

# These are options which turn on DTD or entity expansion in supported XML
# bindings.  Names are intentionally explicit to avoid guessing about an
# arbitrary option named "enabled" or "strict".
_RISKY_TRUE_FLAGS = frozenset(
    {
        "allowDtd",
        "allowDTD",
        "allowEntities",
        "dtd",
        "dtdattr",
        "dtdload",
        "enableDtd",
        "enableDTD",
        "enableEntities",
        "entityExpansion",
        "expandEntities",
        "expandEntityReferences",
        "expandEntitiesReferences",
        "loadDtd",
        "loadDTD",
        "loadExternalDtd",
        "loadExternalDTD",
        "noent",
        "parseNoEnt",
        "processEntities",
        "resolveEntities",
        "resolveExternalEntities",
        "replaceEntities",
        "substituteEntities",
        "supportDTD",
        "useDTD",
    }
)
_SAFE_FALSE_FLAGS = frozenset(
    {
        "allowDtd",
        "allowDTD",
        "allowEntities",
        "enableDtd",
        "enableDTD",
        "enableEntities",
        "entityExpansion",
        "expandEntities",
        "expandEntityReferences",
        "expandEntitiesReferences",
        "loadDtd",
        "loadDTD",
        "loadExternalDtd",
        "loadExternalDTD",
        "noent",
        "parseNoEnt",
        "processEntities",
        "resolveEntities",
        "resolveExternalEntities",
        "replaceEntities",
        "substituteEntities",
        "supportDTD",
        "useDTD",
    }
)
_SAFE_TRUE_FLAGS = frozenset(
    {
        "disableDtd",
        "disableDTD",
        "disableEntities",
        "forbidDtd",
        "forbidDTD",
        "noNetwork",
        "noNet",
        "nonet",
    }
)
_RISKY_CONSTANTS = frozenset(
    {
        "XML_PARAM_ENTITY_PARSING_ALWAYS",
        "XML_PARAM_ENTITY_PARSING_UNLESS_STANDALONE",
        "XML_PARSE_DTDATTR",
        "XML_PARSE_DTDLOAD",
        "XML_PARSE_NOENT",
        "XML_PARSE_NOENTITIES",
    }
)


class EcmaScriptCwe776ScanErrorCode(StrEnum):
    """Closed, source-free reasons an XML entity scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe776ScanError(RuntimeError):
    """Fixed scanner failure which never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe776ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe776ScanErrorCode:
            raise TypeError("ECMAScript CWE-776 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-776 XML entity expansion scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class EcmaScriptCwe776Operation(StrEnum):
    """XML parser configuration and parse boundaries recognized by the scan."""

    FAST_XML_PARSER = "fast-xml-parser.XMLParser"
    FAST_XML_PARSER_PARSE = "fast-xml-parser.XMLParser.parse"
    FAST_XML_PARSE = "fast-xml-parser.parse"
    XML2JS_PARSE_STRING = "xml2js.parseString"
    XML2JS_PARSE_STRING_PROMISE = "xml2js.parseStringPromise"
    XML2JS_PARSER = "xml2js.Parser"
    XMDOM_DOM_PARSER = "xmldom.DOMParser"
    XMDOM_PARSE_FROM_STRING = "xmldom.DOMParser.parseFromString"
    LIBXMLJS_PARSE_XML = "libxmljs.parseXml"
    SAX_PARSER = "sax.parser"
    SAX_SAX_PARSER = "sax.SAXParser"
    SAX_CREATE_STREAM = "sax.createStream"
    NODE_EXPAT_PARSER = "node-expat.Parser"
    NODE_EXPAT_PARAM_ENTITY_PARSING = "node-expat.setParamEntityParsing"

    XML_PARSE = "fast-xml-parser.parse"
    ENTITY_EXPANSION = "fast-xml-parser.XMLParser"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe776ScanLimits:
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
            raise ValueError("ECMAScript CWE-776 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE776_SCAN_LIMITS = EcmaScriptCwe776ScanLimits()


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe776Signal:
    """One immutable explicit entity-expansion configuration fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe776Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-776"
    detector: str = _DETECTOR

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
            if identity_valid and ranges_valid and type(self.operation) is EcmaScriptCwe776Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not EcmaScriptCwe776Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-776"
            or self.detector != _DETECTOR
        ):
            raise ValueError("ECMAScript CWE-776 signal is invalid")
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
class EcmaScriptCwe776ScanResult:
    """Deterministic source-free CWE-776 output for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe776Signal, ...]
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
            type(item) is EcmaScriptCwe776Signal for item in self.signals
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
            raise ValueError("ECMAScript CWE-776 scan result is invalid")


def scan_javascript_cwe776(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe776ScanLimits = DEFAULT_ECMASCRIPT_CWE776_SCAN_LIMITS,
) -> EcmaScriptCwe776ScanResult:
    """Find explicit JavaScript XML entity-expansion configurations."""

    return _scan_ecmascript_cwe776(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe776(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe776ScanLimits = DEFAULT_ECMASCRIPT_CWE776_SCAN_LIMITS,
) -> EcmaScriptCwe776ScanResult:
    """Find explicit TypeScript XML entity-expansion configurations."""

    return _scan_ecmascript_cwe776(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe776(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe776ScanLimits = DEFAULT_ECMASCRIPT_CWE776_SCAN_LIMITS,
) -> EcmaScriptCwe776ScanResult:
    """Dispatch a CWE-776 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe776(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe776(symbol_index, limits=limits)
    raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe776(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe776ScanLimits,
) -> EcmaScriptCwe776ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe776ScanLimits:
        raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.ANALYSIS_UNAVAILABLE)
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
        raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.INTEGRITY_FAILURE) from None
    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.ANALYSIS_UNAVAILABLE)
        aliases = _collect_aliases(nodes, source)
        objects = _collect_object_literals(nodes, source)
        parser_bindings = _collect_parser_bindings(nodes, source, aliases, objects)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe776Operation]] = set()
        for node in nodes:
            if node.type not in {"call_expression", "new_expression"}:
                continue
            fact = _call_fact(node, source, aliases, parser_bindings, objects)
            if fact is not None:
                raw.add(fact)
                if len(raw) > limits.max_signals:
                    raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.SIGNAL_LIMIT)
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
    except EcmaScriptCwe776ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.INTEGRITY_FAILURE) from None
    signals = tuple(
        EcmaScriptCwe776Signal(
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
    return EcmaScriptCwe776ScanResult(
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
class _ParserBinding:
    operation: EcmaScriptCwe776Operation
    safe: bool
    configuration: Node


def _bounded_nodes(root: Node, limits: EcmaScriptCwe776ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _call_fact(
    node: Node,
    source: bytes,
    aliases: dict[str, str],
    bindings: dict[str, _ParserBinding],
    objects: dict[str, Node],
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe776Operation] | None:
    function = node.child_by_field_name("function")
    if node.type == "new_expression":
        function = node.child_by_field_name("constructor") or function
    if function is None:
        return None
    canonical = _canonical_expression(function, source, aliases)
    arguments = node.child_by_field_name("arguments")
    values = tuple(arguments.named_children) if arguments is not None else ()
    if node.type == "new_expression" and canonical in _PARSER_CONSTRUCTORS:
        risky, configuration = _configuration_state(values, source, objects)
        if risky is not None and configuration is not None:
            return _fact_ranges(configuration, node, EcmaScriptCwe776Operation(canonical))
        return None
    operation = _direct_operation(canonical)
    if operation is not None:
        risky, configuration = _configuration_state(values[1:], source, objects)
        if risky is None:
            risky, configuration = _configuration_state(values, source, objects)
        if risky is False or configuration is None:
            return None
        return _fact_ranges(configuration, node, operation)
    if node.type != "call_expression" or canonical is None:
        return None
    receiver, method = canonical.rsplit(".", 1) if "." in canonical else ("", canonical)
    binding = bindings.get(receiver)
    if binding is None or method not in {"parse", "parseString", "parseFromString", "write"}:
        return None
    if binding.safe:
        return None
    if not values:
        return None
    source_node = values[0]
    if not _range(node).contains(_range(source_node)):
        raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.INTEGRITY_FAILURE)
    return (_range(source_node), _range(node), _parse_operation(binding.operation, method))


def _direct_operation(canonical: str | None) -> EcmaScriptCwe776Operation | None:
    return {
        "fast-xml-parser.parse": EcmaScriptCwe776Operation.FAST_XML_PARSE,
        "xml2js.parseString": EcmaScriptCwe776Operation.XML2JS_PARSE_STRING,
        "xml2js.parseStringPromise": EcmaScriptCwe776Operation.XML2JS_PARSE_STRING_PROMISE,
        "xml2js.Parser": EcmaScriptCwe776Operation.XML2JS_PARSER,
        "xmldom.DOMParser.parseFromString": EcmaScriptCwe776Operation.XMDOM_PARSE_FROM_STRING,
        "libxmljs.parseXml": EcmaScriptCwe776Operation.LIBXMLJS_PARSE_XML,
        "sax.parser": EcmaScriptCwe776Operation.SAX_PARSER,
        "sax.createStream": EcmaScriptCwe776Operation.SAX_CREATE_STREAM,
        "node-expat.setParamEntityParsing": EcmaScriptCwe776Operation.NODE_EXPAT_PARAM_ENTITY_PARSING,
    }.get(canonical or "")


def _parse_operation(
    operation: EcmaScriptCwe776Operation, method: str
) -> EcmaScriptCwe776Operation:
    if operation is EcmaScriptCwe776Operation.FAST_XML_PARSER:
        return EcmaScriptCwe776Operation.FAST_XML_PARSER_PARSE
    if operation is EcmaScriptCwe776Operation.XMDOM_DOM_PARSER:
        return EcmaScriptCwe776Operation.XMDOM_PARSE_FROM_STRING
    if operation is EcmaScriptCwe776Operation.SAX_PARSER:
        return EcmaScriptCwe776Operation.SAX_PARSER
    if operation is EcmaScriptCwe776Operation.SAX_SAX_PARSER:
        return EcmaScriptCwe776Operation.SAX_PARSER
    if operation is EcmaScriptCwe776Operation.XML2JS_PARSER:
        return EcmaScriptCwe776Operation.XML2JS_PARSE_STRING
    if operation is EcmaScriptCwe776Operation.NODE_EXPAT_PARSER:
        return EcmaScriptCwe776Operation.NODE_EXPAT_PARSER
    return operation


def _fact_ranges(
    configuration: Node,
    sink_node: Node,
    operation: EcmaScriptCwe776Operation,
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe776Operation]:
    source_range = _range(configuration)
    sink_range = _range(sink_node)
    if not sink_range.contains(source_range):
        raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.INTEGRITY_FAILURE)
    return source_range, sink_range, operation


def _collect_parser_bindings(
    nodes: tuple[Node, ...],
    source: bytes,
    aliases: dict[str, str],
    objects: dict[str, Node],
) -> dict[str, _ParserBinding]:
    output: dict[str, _ParserBinding] = {}
    for node in nodes:
        if node.type not in {"variable_declarator", "assignment_expression"}:
            continue
        name = node.child_by_field_name("name") or node.child_by_field_name("left")
        value = node.child_by_field_name("value") or node.child_by_field_name("right")
        if name is None or value is None or name.type != "identifier":
            continue
        current = _unwrap(value)
        constructor = current.child_by_field_name("constructor") or current.child_by_field_name(
            "function"
        )
        if current.type != "new_expression" or constructor is None:
            continue
        canonical = _canonical_expression(constructor, source, aliases)
        if canonical not in _PARSER_CONSTRUCTORS:
            continue
        arguments = current.child_by_field_name("arguments")
        values = tuple(arguments.named_children) if arguments is not None else ()
        risky, configuration = _configuration_state(values, source, objects)
        if risky is None or configuration is None:
            continue
        try:
            operation = EcmaScriptCwe776Operation(canonical)
        except ValueError:
            continue
        output[_text(source, name)] = _ParserBinding(operation, not risky, configuration)
    return output


def _configuration_state(
    values: tuple[Node, ...], source: bytes, objects: dict[str, Node] | None = None
) -> tuple[bool | None, Node | None]:
    found: Node | None = None
    risky = False
    safe = False
    for value in values:
        candidate = _resolve_object(value, source, objects)
        if candidate.type not in {"object", "array", "arguments"}:
            if _compact_text(source, candidate) in _RISKY_CONSTANTS:
                return True, candidate
            continue
        state, location = _object_state(candidate, source)
        if state is None:
            continue
        found = location or candidate
        risky = risky or state
        safe = safe or not state
    if risky:
        return True, found
    if safe:
        return False, found
    return None, None


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
            if (
                name is not None
                and value is not None
                and name.type == "identifier"
                and _unwrap(value).type == "object"
            ):
                objects[_text(source, name)] = _unwrap(value)
    return objects


def _resolve_object(node: Node, source: bytes, objects: dict[str, Node] | None) -> Node:
    current = _unwrap(node)
    if current.type == "identifier" and objects is not None:
        return objects.get(_text(source, current), current)
    return current


def _object_state(node: Node, source: bytes) -> tuple[bool | None, Node | None]:
    risky = False
    safe = False
    location: Node | None = None
    for child in node.named_children:
        if child.type == "pair":
            key = child.child_by_field_name("key")
            value = child.child_by_field_name("value")
            if key is None or value is None:
                continue
            name = _property_name(key, source)
            literal = _literal_bool(value)
            if name is not None and literal is not None:
                if name in _RISKY_TRUE_FLAGS and literal:
                    risky, location = True, value
                elif (name in _SAFE_FALSE_FLAGS and not literal) or (
                    name in _SAFE_TRUE_FLAGS and literal
                ):
                    safe, location = True, value
            if name is not None and _compact_text(source, value) in _RISKY_CONSTANTS:
                risky, location = True, value
        elif child.type in {"object", "array"}:
            nested, nested_location = _object_state(child, source)
            if nested:
                risky, location = True, nested_location or child
            elif nested is False:
                safe, location = True, nested_location or child
    if risky:
        return True, location or node
    if safe:
        return False, location or node
    return None, None


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
                elif name.type in {"object_pattern", "object"} and canonical is not None:
                    _collect_pattern_aliases(name, canonical, source, aliases)
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
    normalised = _normalise_module(module)
    if normalised is None or normalised not in _XML_MODULES:
        return
    module = normalised
    for clause in node.named_children:
        if clause.type != "import_clause":
            continue
        for item in clause.named_children:
            if item.type == "identifier":
                aliases[_text(source, item)] = module
            elif item.type == "namespace_import" and item.named_children:
                aliases[_text(source, item.named_children[-1])] = module
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
        key_name = _property_name(key, source)
        value_name = _property_name(value, source)
        if key_name is not None and value_name is not None:
            aliases[value_name] = f"{module}.{key_name}"


def _canonical_expression(node: Node | None, source: bytes, aliases: dict[str, str]) -> str | None:
    if node is None:
        return None
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
        return _canonical_expression(constructor, source, aliases)
    if current.type in {"member_expression", "subscript_expression"}:
        object_node = current.child_by_field_name("object")
        property_node = current.child_by_field_name("property") or current.child_by_field_name(
            "index"
        )
        if object_node is None or property_node is None:
            return None
        base = _canonical_expression(object_node, source, aliases)
        if base is None:
            base = _canonical_name(_compact_text(source, object_node), aliases)
        property_name = _property_name(property_node, source)
        return None if base is None or property_name is None else f"{base}.{property_name}"
    return _canonical_name(_compact_text(source, current), aliases)


def _canonical_name(value: str, aliases: dict[str, str]) -> str:
    parts = value.split(".")
    if not parts or not _IDENTIFIER.fullmatch(parts[0]):
        return value
    base = aliases.get(parts[0], parts[0])
    return base if len(parts) == 1 else ".".join((base, *parts[1:]))


def _normalise_module(value: str | None) -> str | None:
    if value is None:
        return None
    return value[5:] if value.startswith("node:") else value


def _property_name(node: Node, source: bytes) -> str | None:
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
        raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.INTEGRITY_FAILURE) from None


def _text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe776ScanError(EcmaScriptCwe776ScanErrorCode.INTEGRITY_FAILURE) from None


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
    operation: EcmaScriptCwe776Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-776",
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
    signals: tuple[EcmaScriptCwe776Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-776",
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


Cwe776ScanErrorCode = EcmaScriptCwe776ScanErrorCode
Cwe776ScanError = EcmaScriptCwe776ScanError
Cwe776ScanLimits = EcmaScriptCwe776ScanLimits
Cwe776ScanResult = EcmaScriptCwe776ScanResult
Cwe776Signal = EcmaScriptCwe776Signal

scan_javascript_xml_entity_expansion = scan_javascript_cwe776
scan_typescript_xml_entity_expansion = scan_typescript_cwe776
scan_ecmascript_xml_entity_expansion = scan_ecmascript_cwe776

__all__ = [
    "DEFAULT_ECMASCRIPT_CWE776_SCAN_LIMITS",
    "Cwe776ScanError",
    "Cwe776ScanErrorCode",
    "Cwe776ScanLimits",
    "Cwe776ScanResult",
    "Cwe776Signal",
    "EcmaScriptCwe776Operation",
    "EcmaScriptCwe776ScanError",
    "EcmaScriptCwe776ScanErrorCode",
    "EcmaScriptCwe776ScanLimits",
    "EcmaScriptCwe776ScanResult",
    "EcmaScriptCwe776Signal",
    "scan_ecmascript_cwe776",
    "scan_ecmascript_xml_entity_expansion",
    "scan_javascript_cwe776",
    "scan_javascript_xml_entity_expansion",
    "scan_typescript_cwe776",
    "scan_typescript_xml_entity_expansion",
]
