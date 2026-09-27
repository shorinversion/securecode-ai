"""Bounded Go facts for CWE-776 XML entity expansion.

The scanner deliberately reports only explicit XML entity-expansion controls.
It recognises the ``encoding/xml.Decoder.Entity`` map and the entity-related
parser flags exposed by the common libxml2 Go bindings.  A normal
``encoding/xml`` decoder is not considered unsafe because Go does not enable
general entity expansion by default.  Unknown parser abstractions and unknown
entity maps are left unresolved.

Only an admitted, sealed :class:`~securecode_ai.core.SymbolIndex` is accepted.
Source bytes are parsed transiently.  Results contain immutable identity,
exact source ranges, and content-addressed hashes, but never source text or
parser diagnostics.
"""

from __future__ import annotations

import hashlib
import json
import re
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

_MAX_LIMITS = (2_000_000, 2_048, 64, 2_048)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-go-cwe776"
_DETECTOR = "securecode-go-cwe776@1.0"
_DETAIL = "xml_entity_expansion_enabled"

_XML_PACKAGE = "encoding/xml"
_LIBXML2_PACKAGES = frozenset(
    {
        "github.com/lestrrat-go/libxml2",
        "github.com/lestrrat-go/libxml2/parser",
        "github.com/lestrrat-go/libxml2/xpath",
    }
)
_HELIUM_PACKAGES = frozenset(
    {
        "github.com/lestrrat-go/helium",
        "github.com/lestrrat-go/helium/parser",
    }
)
_XML_PARSER_PACKAGES = (
    _LIBXML2_PACKAGES
    | _HELIUM_PACKAGES
    | frozenset(
        {
            "github.com/antchfx/xmlquery",
            "github.com/beevik/etree",
            "github.com/tamerh/xml-stream-parser",
        }
    )
)
_ENTITY_OPTION_NAMES = frozenset(
    {
        "XMLParseNoEnt",
        "XMLParseDTDLoad",
        "XMLParseDTDAttr",
        "XMLParseXInclude",
        "XMLParseHuge",
        "XML_PARSE_NOENT",
        "XML_PARSE_DTDLOAD",
        "ParseOptionNoEnt",
        "ParseOptionDTDLoad",
        "ParseNoEnt",
        "ParseDTDLoad",
        "ParseDTDAttr",
        "ParseXInclude",
        "ParseHuge",
        "EnableEntityExpansion",
        "EnableEntities",
        "ExpandEntities",
        "ProcessEntities",
        "ReplaceEntities",
        "ResolveEntities",
        "ResolveExternalEntities",
        "AllowExternalEntities",
        "LoadExternalEntities",
        "WithEntityExpansion",
        "WithExternalEntities",
        "WithDTD",
        "LoadExternalDTD",
        "SubstituteEntities",
        "BlockXXE",
        "AllowNetwork",
        "PermissiveFS",
        "Catalog",
    }
)
_SAFE_OPTION_NAMES = frozenset(
    {
        "XMLParseNoNet",
        "ParseNoNet",
        "DisableEntityExpansion",
        "DisableEntities",
        "NoExternalEntities",
        "DisableExternalEntities",
        "NoNetwork",
        "NoNet",
    }
)
_PARSER_CONSTRUCTOR_NAMES = frozenset(
    {
        "New",
        "NewParser",
        "NewDecoder",
        "NewStreamParser",
        "CreateStreamParser",
        "Parse",
        "ParseXML",
        "ParseXml",
        "Read",
        "ReadFrom",
        "ReadFromString",
    }
)
_EXAMPLE_PARTS = frozenset(
    {
        "bench",
        "benchmark",
        "benchmarks",
        "demo",
        "demos",
        "example",
        "examples",
        "fixture",
        "fixtures",
        "golden",
        "test",
        "testdata",
        "tests",
    }
)
_EXAMPLE_PREFIXES = ("test", "benchmark", "example", "fuzz", "fixture")
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})


class GoCwe776ScanErrorCode(StrEnum):
    """Closed, source-free reasons a Go CWE-776 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe776ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe776ScanErrorCode) -> None:
        if type(code) is not GoCwe776ScanErrorCode:
            raise TypeError("Go CWE-776 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-776 XML entity-expansion scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe776ScanLimits:
    """Hard bounds applied before and during structural XML analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_nodes: int = _MAX_LIMITS[1]
    max_tree_depth: int = _MAX_LIMITS[2]
    max_signals: int = _MAX_LIMITS[3]

    def __post_init__(self) -> None:
        values = (
            self.max_source_bytes,
            self.max_nodes,
            self.max_tree_depth,
            self.max_signals,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-776 scan limits are invalid")

    @property
    def max_depth(self) -> int:
        """Compatibility view used by scanners with a generic depth name."""

        return self.max_tree_depth


DEFAULT_GO_CWE776_SCAN_LIMITS = GoCwe776ScanLimits()


class GoCwe776Operation(StrEnum):
    """Recognised explicit XML entity-expansion controls."""

    XML_DECODER_ENTITY_ASSIGNMENT = "encoding_xml_custom_entity_map"
    ENTITY_MAP_ASSIGNMENT = "encoding_xml_custom_entity_map"
    ENTITY_MAP_ENTRY_ASSIGNMENT = "encoding_xml_custom_entity_map"
    LIBXML2_PARSE_NOENT = "libxml_entity_substitution"
    LIBXML2_PARSE_DTD_LOAD = "libxml_external_dtd"
    LIBXML2_PARSE_DTD_ATTR = "libxml_external_dtd"
    LIBXML2_PARSE_XINCLUDE = "libxml_external_dtd"
    LIBXML2_PARSE_HUGE = "libxml_external_dtd"
    ENTITY_EXPANSION_CALL = "xml.entity_expansion"
    ENCODING_XML_CUSTOM_ENTITY_MAP = "encoding_xml_custom_entity_map"
    LIBXML_EXTERNAL_DTD = "libxml_external_dtd"
    LIBXML_ENTITY_SUBSTITUTION = "libxml_entity_substitution"
    HELIUM_EXTERNAL_DTD = "helium.external_dtd"
    HELIUM_ENTITY_SUBSTITUTION = "helium.entity_substitution"
    HELIUM_NETWORK_ACCESS = "helium.network_access"
    EXTERNAL_ENTITY_RESOLVER = "xml.external_entity_resolver"

    # Compatibility names used by generic scanner consumers.
    XML_PARSE_NOENT = "libxml_entity_substitution"
    XML_PARSE_DTD_LOAD = "libxml_external_dtd"
    XML_PARSE_DTD_ATTR = "libxml_external_dtd"
    XML_PARSE_XINCLUDE = "libxml_external_dtd"
    XML_PARSE_HUGE = "libxml_external_dtd"
    ENTITY_EXPANSION = "xml.entity_expansion"


@dataclass(frozen=True, slots=True)
class GoCwe776Signal:
    """One immutable source-free XML entity-expansion fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe776Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-776"
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
            and 0 <= self.sink.start_byte <= self.source.start_byte
            and self.source.start_byte <= self.source.end_byte
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
            if valid_identity and valid_ranges and type(self.operation) is GoCwe776Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not GoCwe776Operation
            or type(signal_id) is not str
            or expected_id is None
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-776"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-776 signal is invalid")
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
class GoCwe776ScanResult:
    """Deterministic, source-free CWE-776 output for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe776Signal, ...]
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
            type(item) is GoCwe776Signal for item in self.signals
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
            raise ValueError("Go CWE-776 scan result is invalid")


def scan_go_cwe776(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe776ScanLimits = DEFAULT_GO_CWE776_SCAN_LIMITS,
) -> GoCwe776ScanResult:
    """Find explicit Go XML entity-expansion configuration."""

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
        source.decode("utf-8", errors="strict")
        root = Parser(Language(_go_language())).parse(source).root_node
        if root.has_error:
            raise ValueError("parse error")
        nodes = _bounded_nodes(root, limits)
    except GoCwe776ScanError:
        raise
    except Exception:
        raise GoCwe776ScanError(GoCwe776ScanErrorCode.INTEGRITY_FAILURE) from None

    raw: set[tuple[SourceRange, SourceRange, GoCwe776Operation]] = set()
    if not _ignored_path(symbol_index.path):
        imports = _import_aliases(root, source)
        decoder_names = _decoder_names(nodes, source, imports)
        nonempty_maps = _nonempty_map_names(nodes, source)
        try:
            for node in nodes:
                if _ignored_scope(node, source):
                    continue
                if node.type in {"assignment_statement", "var_spec"}:
                    for source_node, sink_node, operation in _entity_assignments(
                        node, source, decoder_names, nonempty_maps
                    ):
                        raw.add((_range(source_node), _range(sink_node), operation))
                if node.type != "call_expression":
                    setting_fact = _helium_setting_fact(node, source, imports)
                    if setting_fact is not None:
                        source_node, sink_node, operation = setting_fact
                        raw.add((_range(source_node), _range(sink_node), operation))
                    continue
                fact = _parser_fact(node, source, imports)
                if fact is not None:
                    source_node, sink_node, operation = fact
                    raw.add((_range(source_node), _range(sink_node), operation))
                if len(raw) > limits.max_signals:
                    raise GoCwe776ScanError(GoCwe776ScanErrorCode.SIGNAL_LIMIT)
        except GoCwe776ScanError:
            raise
        except Exception:
            raise GoCwe776ScanError(GoCwe776ScanErrorCode.INTEGRITY_FAILURE) from None

    ordered = tuple(
        sorted(
            raw,
            key=lambda item: (
                item[1].start_byte,
                item[1].end_byte,
                item[0].start_byte,
                item[0].end_byte,
                item[2].value,
            ),
        )
    )
    if len(ordered) > limits.max_signals:
        raise GoCwe776ScanError(GoCwe776ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe776Signal(
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
    return GoCwe776ScanResult(
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


def scan_go_xml_entity_expansion(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe776ScanLimits = DEFAULT_GO_CWE776_SCAN_LIMITS,
) -> GoCwe776ScanResult:
    """Descriptive alias for :func:`scan_go_cwe776`."""

    return scan_go_cwe776(symbol_index, limits=limits)


def scan_go_unsafe_xml_entities(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe776ScanLimits = DEFAULT_GO_CWE776_SCAN_LIMITS,
) -> GoCwe776ScanResult:
    """Compatibility alias for callers using the unsafe-XML terminology."""

    return scan_go_cwe776(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe776ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe776ScanLimits:
        raise GoCwe776ScanError(GoCwe776ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe776ScanError(GoCwe776ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe776ScanError(GoCwe776ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe776ScanError(GoCwe776ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _bounded_nodes(root: Node, limits: GoCwe776ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise GoCwe776ScanError(GoCwe776ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise GoCwe776ScanError(GoCwe776ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        package = _text(source, path_node).strip('"`')
        name_node = node.child_by_field_name("name")
        alias = _text(source, name_node) if name_node is not None else package.rsplit("/", 1)[-1]
        if alias not in {".", "_"}:
            aliases[alias] = package
    return aliases


def _decoder_names(
    nodes: tuple[Node, ...], source: bytes, imports: dict[str, str]
) -> frozenset[str]:
    names: set[str] = set()
    for node in nodes:
        if node.type not in {"short_var_declaration", "assignment_statement", "var_spec"}:
            continue
        for name, value in _binding_pairs(node):
            if name.type != "identifier":
                continue
            if _is_xml_decoder(value, source, imports) or "decoder" in _text(source, name).lower():
                names.add(_text(source, name))
        if node.type == "var_spec":
            type_node = node.child_by_field_name("type")
            name_node = node.child_by_field_name("name")
            if (
                type_node is not None
                and name_node is not None
                and name_node.type == "identifier"
                and _is_xml_decoder_type(type_node, source, imports)
            ):
                names.add(_text(source, name_node))
    return frozenset(names)


def _nonempty_map_names(nodes: tuple[Node, ...], source: bytes) -> frozenset[str]:
    names: set[str] = set()
    for node in nodes:
        if node.type not in {"short_var_declaration", "assignment_statement", "var_spec"}:
            continue
        for name, value in _binding_pairs(node):
            if name.type == "identifier" and _nonempty_entity_map(value, source, names):
                names.add(_text(source, name))
    return frozenset(names)


def _binding_pairs(node: Node) -> tuple[tuple[Node, Node], ...]:
    if node.type == "var_spec":
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name is None or value is None:
            return ()
        names = name.named_children or (name,)
        values = tuple(value.named_children) or (value,)
    else:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return ()
        names = left.named_children or (left,)
        values = tuple(right.named_children) or (right,)
    if len(values) == 1 and len(names) > 1:
        values = values * len(names)
    return tuple(zip(names, values, strict=False))


def _is_xml_decoder(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    canonical = _qualified_call(node, source, imports)
    return canonical == (_XML_PACKAGE, "NewDecoder")


def _is_xml_decoder_type(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    text = _compact_text(source, node)
    return any(
        text in {f"{alias}.Decoder", f"*{alias}.Decoder"}
        for alias, package in imports.items()
        if package == _XML_PACKAGE
    )


def _entity_assignments(
    node: Node,
    source: bytes,
    decoder_names: frozenset[str],
    nonempty_maps: frozenset[str],
) -> tuple[tuple[Node, Node, GoCwe776Operation], ...]:
    pairs = _binding_pairs(node)
    results: list[tuple[Node, Node, GoCwe776Operation]] = []
    for left, right in pairs:
        target = _unwrap(left)
        entity_target = _entity_target(target, source, decoder_names)
        if entity_target is None:
            continue
        if entity_target == "map":
            if _nonempty_entity_map(right, source, nonempty_maps):
                results.append((right, node, GoCwe776Operation.XML_DECODER_ENTITY_ASSIGNMENT))
        else:
            results.append((right, node, GoCwe776Operation.ENTITY_MAP_ENTRY_ASSIGNMENT))
    return tuple(results)


def _entity_target(node: Node, source: bytes, decoder_names: frozenset[str]) -> str | None:
    current = _unwrap(node)
    if current.type == "selector_expression":
        field = current.child_by_field_name("field")
        operand = current.child_by_field_name("operand")
        if field is None or operand is None or _text(source, field) != "Entity":
            return None
        receiver = _compact_text(source, operand)
        if receiver in decoder_names or "decoder" in receiver.lower():
            return "map"
        return None
    if current.type == "index_expression":
        operand = current.child_by_field_name("operand")
        if operand is not None and _entity_target(operand, source, decoder_names) == "map":
            return "entry"
    return None


def _nonempty_entity_map(node: Node, source: bytes, known_names: frozenset[str] | set[str]) -> bool:
    current = _unwrap(node)
    if current.type == "identifier":
        return _text(source, current) in known_names
    if current.type != "composite_literal":
        return False
    literal = current.child_by_field_name("body")
    if literal is None:
        literal = next(
            (child for child in current.named_children if child.type == "literal_value"), None
        )
    return literal is not None and bool(literal.named_children)


def _parser_fact(
    node: Node, source: bytes, imports: dict[str, str]
) -> tuple[Node, Node, GoCwe776Operation] | None:
    helium_fact = _helium_fact(node, source, imports)
    if helium_fact is not None:
        return helium_fact
    function = node.child_by_field_name("function")
    if function is None:
        return None
    canonical = _qualified_call(node, source, imports)
    if canonical is None:
        return None
    package, name = canonical
    option = _risky_option(package, name)
    if option is not None:
        parent = node.parent
        while parent is not None:
            if parent.type == "call_expression" and _is_parser_constructor(parent, source, imports):
                return None
            if parent.type in _GO_SCOPES:
                break
            parent = parent.parent
        return node, node, option
    if not _is_parser_constructor(node, source, imports):
        return None
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return None
    for child in _preorder(arguments):
        if child is node or child.type != "call_expression":
            continue
        nested = child.child_by_field_name("function")
        if nested is None:
            continue
        nested_canonical = _qualified_call(child, source, imports)
        if nested_canonical is None:
            continue
        nested_option = _risky_option(*nested_canonical)
        if nested_option is not None:
            return child, node, nested_option
    return None


def _helium_setting_fact(
    node: Node, source: bytes, imports: dict[str, str]
) -> tuple[Node, Node, GoCwe776Operation] | None:
    if node.type != "keyed_element":
        return None
    key = node.child_by_field_name("key")
    value = node.child_by_field_name("value")
    if key is None or value is None or _literal_text(value, source) != "true":
        return None
    name = _text(source, key)
    operation = {
        "LoadExternalDTD": GoCwe776Operation.HELIUM_EXTERNAL_DTD,
        "SubstituteEntities": GoCwe776Operation.HELIUM_ENTITY_SUBSTITUTION,
    }.get(name)
    if operation is None or not _is_helium_settings(node.parent, source, imports):
        return None
    return value, node, operation


def _is_helium_settings(node: Node | None, source: bytes, imports: dict[str, str]) -> bool:
    current = node
    while current is not None and current.type != "composite_literal":
        current = current.parent
    if current is None:
        return False
    type_node = current.child_by_field_name("type")
    if type_node is None:
        return False
    for child in type_node.named_children:
        if child.type != "selector_expression":
            continue
        operand = child.child_by_field_name("operand")
        field = child.child_by_field_name("field")
        if (
            operand is not None
            and field is not None
            and _text(source, field) == "ParserSettings"
            and operand.type == "identifier"
            and imports.get(_text(source, operand)) in _HELIUM_PACKAGES
        ):
            return True
    return False


def _helium_fact(
    node: Node, source: bytes, imports: dict[str, str]
) -> tuple[Node, Node, GoCwe776Operation] | None:
    """Recognise explicit enabling calls on a lestrrat-go helium parser."""

    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if (
        function is None
        or function.type != "selector_expression"
        or arguments is None
        or not arguments.named_children
    ):
        return None
    method = function.child_by_field_name("field")
    receiver = function.child_by_field_name("operand")
    if method is None or receiver is None:
        return None
    method_name = _text(source, method)
    if method_name not in {
        "LoadExternalDTD",
        "SubstituteEntities",
        "BlockXXE",
        "AllowNetwork",
        "FS",
        "Catalog",
    } or not _helium_receiver(receiver, source, imports):
        return None
    value = arguments.named_children[0]
    enabled = _literal_text(value, source) == "true"
    if method_name == "BlockXXE":
        enabled = _literal_text(value, source) == "false"
    elif method_name == "FS":
        enabled = _contains_helium_call(value, source, imports, "PermissiveFS")
    elif method_name == "Catalog":
        enabled = _literal_text(value, source) != "nil"
    if not enabled:
        return None
    operation = {
        "LoadExternalDTD": GoCwe776Operation.HELIUM_EXTERNAL_DTD,
        "SubstituteEntities": GoCwe776Operation.HELIUM_ENTITY_SUBSTITUTION,
        "BlockXXE": GoCwe776Operation.HELIUM_EXTERNAL_DTD,
        "AllowNetwork": GoCwe776Operation.HELIUM_NETWORK_ACCESS,
        "FS": GoCwe776Operation.EXTERNAL_ENTITY_RESOLVER,
        "Catalog": GoCwe776Operation.EXTERNAL_ENTITY_RESOLVER,
    }[method_name]
    return value, node, operation


def _helium_receiver(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    """Verify a fluent receiver starts at an imported helium parser."""

    current = node
    while current.type == "call_expression":
        function = current.child_by_field_name("function")
        if function is None or function.type != "selector_expression":
            return False
        operand = function.child_by_field_name("operand")
        field = function.child_by_field_name("field")
        if operand is None or field is None:
            return False
        if operand.type == "identifier" and _text(source, field) == "NewParser":
            return imports.get(_text(source, operand)) in _HELIUM_PACKAGES
        if operand.type == "call_expression":
            current = operand
            continue
        return False
    return False


def _contains_helium_call(node: Node, source: bytes, imports: dict[str, str], name: str) -> bool:
    for child in _preorder(node):
        if child.type != "call_expression":
            continue
        function = child.child_by_field_name("function")
        if function is None or function.type != "selector_expression":
            continue
        operand = function.child_by_field_name("operand")
        field = function.child_by_field_name("field")
        if (
            operand is not None
            and field is not None
            and _text(source, field) == name
            and operand.type == "identifier"
            and imports.get(_text(source, operand)) in _HELIUM_PACKAGES
        ):
            return True
    return False


def _literal_text(node: Node, source: bytes) -> str:
    return _compact_text(source, node)


def _qualified_call(node: Node, source: bytes, imports: dict[str, str]) -> tuple[str, str] | None:
    if node.type != "call_expression":
        return None
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    alias = _compact_text(source, operand)
    package = imports.get(alias)
    return None if package is None else (package, _text(source, field))


def _risky_option(package: str, name: str) -> GoCwe776Operation | None:
    if name in _SAFE_OPTION_NAMES:
        return None
    if name not in _ENTITY_OPTION_NAMES:
        return None
    if package in _LIBXML2_PACKAGES:
        return {
            "XMLParseNoEnt": GoCwe776Operation.LIBXML2_PARSE_NOENT,
            "ParseNoEnt": GoCwe776Operation.LIBXML2_PARSE_NOENT,
            "XML_PARSE_NOENT": GoCwe776Operation.LIBXML2_PARSE_NOENT,
            "ParseOptionNoEnt": GoCwe776Operation.LIBXML2_PARSE_NOENT,
            "XMLParseDTDLoad": GoCwe776Operation.LIBXML2_PARSE_DTD_LOAD,
            "ParseDTDLoad": GoCwe776Operation.LIBXML2_PARSE_DTD_LOAD,
            "XML_PARSE_DTDLOAD": GoCwe776Operation.LIBXML2_PARSE_DTD_LOAD,
            "ParseOptionDTDLoad": GoCwe776Operation.LIBXML2_PARSE_DTD_LOAD,
            "XMLParseDTDAttr": GoCwe776Operation.LIBXML2_PARSE_DTD_ATTR,
            "ParseDTDAttr": GoCwe776Operation.LIBXML2_PARSE_DTD_ATTR,
            "XMLParseXInclude": GoCwe776Operation.LIBXML2_PARSE_XINCLUDE,
            "ParseXInclude": GoCwe776Operation.LIBXML2_PARSE_XINCLUDE,
            "XMLParseHuge": GoCwe776Operation.LIBXML2_PARSE_HUGE,
            "ParseHuge": GoCwe776Operation.LIBXML2_PARSE_HUGE,
        }.get(name, GoCwe776Operation.ENTITY_EXPANSION_CALL)
    return GoCwe776Operation.ENTITY_EXPANSION_CALL


def _is_parser_constructor(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    canonical = _qualified_call(node, source, imports)
    if canonical is None:
        return False
    package, name = canonical
    if name not in _PARSER_CONSTRUCTOR_NAMES:
        return False
    return package in _XML_PARSER_PACKAGES


def _ignored_path(path: str) -> bool:
    normalized = path.replace("\\", "/").strip("/").lower()
    parts = tuple(part for part in normalized.split("/") if part)
    basename = parts[-1] if parts else ""
    return (
        basename.endswith(("_test.go", "_testdata.go"))
        or any(part in _EXAMPLE_PARTS for part in parts)
        or basename.startswith(("example_", "example.", "fixture_", "fixture."))
    )


def _ignored_scope(node: Node, source: bytes) -> bool:
    current: Node | None = node
    while current is not None:
        if current.type in _GO_SCOPES:
            name = current.child_by_field_name("name")
            if name is None:
                return False
            value = _text(source, name).lower()
            return value.startswith(_EXAMPLE_PREFIXES)
        current = current.parent
    return False


def _preorder(root: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        output.append(node)
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _unwrap(node: Node) -> Node:
    current = node
    while current.type in {"parenthesized_expression", "unary_expression"}:
        children = current.named_children
        if not children:
            break
        current = children[-1]
    return current


def _text(source: bytes, node: Node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")


def _compact_text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
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
    operation: GoCwe776Operation,
) -> str:
    material = {
        "content_sha256": content_sha256,
        "cwe": "CWE-776",
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
    return digest


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe776Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
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


# Compatibility aliases keep this adapter usable beside existing CWE scanners.
Cwe776ScanErrorCode = GoCwe776ScanErrorCode
Cwe776ScanError = GoCwe776ScanError
Cwe776ScanLimits = GoCwe776ScanLimits
Cwe776ScanResult = GoCwe776ScanResult
Cwe776Signal = GoCwe776Signal


__all__ = [
    "DEFAULT_GO_CWE776_SCAN_LIMITS",
    "Cwe776ScanError",
    "Cwe776ScanErrorCode",
    "Cwe776ScanLimits",
    "Cwe776ScanResult",
    "Cwe776Signal",
    "GoCwe776Operation",
    "GoCwe776ScanError",
    "GoCwe776ScanErrorCode",
    "GoCwe776ScanLimits",
    "GoCwe776ScanResult",
    "GoCwe776Signal",
    "scan_go_cwe776",
    "scan_go_unsafe_xml_entities",
    "scan_go_xml_entity_expansion",
]
