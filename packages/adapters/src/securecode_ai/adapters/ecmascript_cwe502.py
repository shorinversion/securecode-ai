"""Bounded JavaScript and TypeScript unsafe-deserialization facts for CWE-502.

The scanner consumes an admitted ECMAScript :class:`~securecode_ai.core.SymbolIndex`
and reparses the exact sealed bytes before inspecting the CST.  It recognizes
explicit unsafe deserialization boundaries from ``js-yaml``, ``node-serialize``,
and the eval-backed paths exposed by ``serialize-to-js``.  Module imports,
``require`` aliases, and local callable aliases are resolved only when their
origin is syntactically unambiguous.  Explicit safe js-yaml loaders and safe
schemas are ignored.  Results contain immutable source ranges and
content-addressed metadata only; source text is never retained or copied into
an error.
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
_RULE_ID = "securecode-ecmascript-cwe502"
_DETECTOR = "securecode-ecmascript-cwe502@1.0"

_SAFE_JS_YAML_SCHEMA_NAMES = frozenset(
    {
        "SAFE_SCHEMA",
        "FAILSAFE_SCHEMA",
        "JSON_SCHEMA",
        "CORE_SCHEMA",
    }
)


class EcmaScriptCwe502ScanErrorCode(StrEnum):
    """Closed, source-free reasons an unsafe-deserialization scan can fail."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe502ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser diagnostics."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe502ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe502ScanErrorCode:
            raise TypeError("ECMAScript CWE-502 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-502 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class EcmaScriptCwe502Operation(StrEnum):
    """Recognized JavaScript and TypeScript unsafe-deserialization operations."""

    JS_YAML_LOAD = "js-yaml.load"
    JS_YAML_LOAD_ALL = "js-yaml.loadAll"
    NODE_SERIALIZE_UNSERIALIZE = "node-serialize.unserialize"
    NODE_SERIALIZE_DESERIALIZE = "node-serialize.deserialize"
    SERIALIZE_TO_JS_DESERIALIZE = "serialize-to-js.deserialize"
    SERIALIZE_TO_JS_UNSERIALIZE = "serialize-to-js.unserialize"
    SERIALIZE_TO_JS_EVAL = "serialize-to-js.eval"

    # Descriptive aliases for language-neutral callers.
    YAML_LOAD = "js-yaml.load"
    YAML_LOAD_ALL = "js-yaml.loadAll"
    JS_YAML_UNSAFE_LOAD = "js-yaml.load"
    JS_YAML_UNSAFE_LOAD_ALL = "js-yaml.loadAll"
    UNSERIALIZE = "node-serialize.unserialize"
    NODE_UNSERIALIZE = "node-serialize.unserialize"
    EVAL_DESERIALIZE = "serialize-to-js.deserialize"
    SERIALIZE_TO_JS_EVAL_DESERIALIZE = "serialize-to-js.deserialize"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe502ScanLimits:
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
            raise ValueError("ECMAScript CWE-502 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE502_SCAN_LIMITS = EcmaScriptCwe502ScanLimits()


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe502Signal:
    """One immutable input-to-unsafe-deserializer fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe502Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-502"
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
            and type(self.operation) is EcmaScriptCwe502Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not EcmaScriptCwe502Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-502"
            or self.detector != _DETECTOR
        ):
            raise ValueError("ECMAScript CWE-502 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete unsafe-deserializer call location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe502ScanResult:
    """Deterministic, source-free CWE-502 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe502Signal, ...]
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
            type(item) is EcmaScriptCwe502Signal for item in self.signals
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
            raise ValueError("ECMAScript CWE-502 scan result is invalid")


def scan_javascript_cwe502(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe502ScanLimits = DEFAULT_ECMASCRIPT_CWE502_SCAN_LIMITS,
) -> EcmaScriptCwe502ScanResult:
    """Find bounded JavaScript unsafe-deserialization facts."""

    return _scan_ecmascript_cwe502(
        symbol_index, expected_language="javascript", limits=limits
    )


def scan_typescript_cwe502(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe502ScanLimits = DEFAULT_ECMASCRIPT_CWE502_SCAN_LIMITS,
) -> EcmaScriptCwe502ScanResult:
    """Find bounded TypeScript unsafe-deserialization facts."""

    return _scan_ecmascript_cwe502(
        symbol_index, expected_language="typescript", limits=limits
    )


def scan_ecmascript_cwe502(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe502ScanLimits = DEFAULT_ECMASCRIPT_CWE502_SCAN_LIMITS,
) -> EcmaScriptCwe502ScanResult:
    """Dispatch a CWE-502 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe502ScanError(EcmaScriptCwe502ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe502(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe502(symbol_index, limits=limits)
    raise EcmaScriptCwe502ScanError(EcmaScriptCwe502ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe502(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe502ScanLimits,
) -> EcmaScriptCwe502ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe502ScanLimits:
        raise EcmaScriptCwe502ScanError(EcmaScriptCwe502ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe502ScanError(EcmaScriptCwe502ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe502ScanError(EcmaScriptCwe502ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe502ScanError(EcmaScriptCwe502ScanErrorCode.ANALYSIS_UNAVAILABLE)

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
        raise EcmaScriptCwe502ScanError(
            EcmaScriptCwe502ScanErrorCode.INTEGRITY_FAILURE
        ) from None
    except Exception:
        raise EcmaScriptCwe502ScanError(
            EcmaScriptCwe502ScanErrorCode.INTEGRITY_FAILURE
        ) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe502ScanError(
                EcmaScriptCwe502ScanErrorCode.ANALYSIS_UNAVAILABLE
            )
        aliases = _collect_aliases(nodes, source)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe502Operation]] = set()
        for node in nodes:
            if node.type != "call_expression":
                continue
            raw.update(_call_facts(node, source, aliases))
            if len(raw) > limits.max_signals:
                raise EcmaScriptCwe502ScanError(EcmaScriptCwe502ScanErrorCode.SIGNAL_LIMIT)
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
            raise EcmaScriptCwe502ScanError(EcmaScriptCwe502ScanErrorCode.SIGNAL_LIMIT)
    except EcmaScriptCwe502ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe502ScanError(
            EcmaScriptCwe502ScanErrorCode.INTEGRITY_FAILURE
        ) from None

    signals = tuple(
        EcmaScriptCwe502Signal(
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
    return EcmaScriptCwe502ScanResult(
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


def _bounded_nodes(root: Node, limits: EcmaScriptCwe502ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe502ScanError(EcmaScriptCwe502ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe502ScanError(EcmaScriptCwe502ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _call_facts(
    node: Node, source: bytes, aliases: dict[str, str]
) -> set[tuple[SourceRange, SourceRange, EcmaScriptCwe502Operation]]:
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None:
        return set()
    callee = _canonical_expression(function, source, aliases)
    operation = _operation_for_callee(callee)
    if operation is None:
        return set()
    values = list(arguments.named_children)
    if not values:
        return set()
    if operation in {
        EcmaScriptCwe502Operation.JS_YAML_LOAD,
        EcmaScriptCwe502Operation.JS_YAML_LOAD_ALL,
    } and _uses_safe_yaml_options(values, source, aliases):
        return set()
    sink = _range(node)
    input_node = values[0]
    input_range = _range(input_node)
    if not sink.contains(input_range):
        raise EcmaScriptCwe502ScanError(EcmaScriptCwe502ScanErrorCode.INTEGRITY_FAILURE)
    return {(input_range, sink, operation)}


def _operation_for_callee(callee: str | None) -> EcmaScriptCwe502Operation | None:
    if callee is None:
        return None
    return {
        "js-yaml.load": EcmaScriptCwe502Operation.JS_YAML_LOAD,
        "js-yaml.loadAll": EcmaScriptCwe502Operation.JS_YAML_LOAD_ALL,
        "node-serialize.unserialize": EcmaScriptCwe502Operation.NODE_SERIALIZE_UNSERIALIZE,
        "node-serialize.deserialize": EcmaScriptCwe502Operation.NODE_SERIALIZE_DESERIALIZE,
        "serialize-to-js.deserialize": EcmaScriptCwe502Operation.SERIALIZE_TO_JS_DESERIALIZE,
        "serialize-to-js.unserialize": EcmaScriptCwe502Operation.SERIALIZE_TO_JS_UNSERIALIZE,
        "serialize-to-js.eval": EcmaScriptCwe502Operation.SERIALIZE_TO_JS_EVAL,
        "serialize-to-js.evalDeserialize": EcmaScriptCwe502Operation.SERIALIZE_TO_JS_EVAL,
    }.get(callee)


def _uses_safe_yaml_options(
    values: list[Node], source: bytes, aliases: dict[str, str]
) -> bool:
    if len(values) < 2:
        return False
    options = _unwrap(values[1])
    if options.type != "object":
        return False
    for child in options.named_children:
        if child.type != "pair":
            continue
        key, value = _pair_parts(child)
        if key is None or value is None or _static_property_name(key, source) != "schema":
            continue
        schema = _canonical_expression(value, source, aliases)
        if schema is None:
            return False
        return schema.rsplit(".", 1)[-1] in _SAFE_JS_YAML_SCHEMA_NAMES
    return False


def _collect_aliases(nodes: tuple[Node, ...], source: bytes) -> dict[str, str]:
    """Collect direct, local module and callable aliases from the CST."""

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
                if canonical is None:
                    continue
                if name.type == "identifier":
                    aliases[_node_text(source, name)] = canonical
                elif name.type in {"object_pattern", "object"}:
                    _collect_destructured_aliases(name, canonical, source, aliases)
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                canonical = _canonical_expression(right, source, aliases)
                if canonical is not None:
                    aliases[_node_text(source, left)] = canonical
    return aliases


def _collect_import_aliases(node: Node, source: bytes, aliases: dict[str, str]) -> None:
    module_node = node.child_by_field_name("source")
    if module_node is None:
        return
    module = _string_value(module_node, source)
    if module is None:
        return
    module = _normalise_module(module)
    for child in node.named_children:
        if child.type != "import_clause":
            continue
        for item in child.named_children:
            if item.type in {"identifier", "namespace_import"}:
                identifier = item if item.type == "identifier" else item.named_children[0]
                aliases[_node_text(source, identifier)] = module
            elif item.type in {"named_imports", "named_import"}:
                for specifier in item.named_children:
                    if specifier.type != "import_specifier":
                        continue
                    names = list(specifier.named_children)
                    if not names:
                        continue
                    imported = _node_text(source, names[0])
                    local = _node_text(source, names[-1])
                    aliases[local] = f"{module}.{imported}"


def _collect_destructured_aliases(
    pattern: Node, module: str, source: bytes, aliases: dict[str, str]
) -> None:
    for child in pattern.named_children:
        if child.type not in {"pair", "object_pattern_property", "shorthand_property_identifier_pattern"}:
            continue
        key, value = _pair_parts(child)
        if key is None:
            key = child
        if value is None:
            value = key
        if key.type not in {"identifier", "property_identifier", "string"} or value.type not in {
            "identifier",
            "property_identifier",
            "string",
        }:
            continue
        aliases[_node_text(source, value)] = f"{module}.{_node_text(source, key)}"


def _canonical_expression(node: Node, source: bytes, aliases: dict[str, str]) -> str | None:
    current = _unwrap(node)
    if current.type == "call_expression":
        function = current.child_by_field_name("function")
        arguments = current.child_by_field_name("arguments")
        if (
            function is None
            or arguments is None
            or _compact_text(source, function) != "require"
            or len(arguments.named_children) != 1
        ):
            return None
        module = _string_value(arguments.named_children[0], source)
        return _normalise_module(module) if module is not None else None
    if current.type in {"member_expression", "subscript_expression"}:
        base = current.child_by_field_name("object")
        property_node = current.child_by_field_name("property")
        if base is None or property_node is None:
            named = list(current.named_children)
            if len(named) < 2:
                return None
            base, property_node = named[0], named[-1]
        base_name = _canonical_expression(base, source, aliases)
        property_name = _static_property_name(property_node, source)
        if base_name is None or property_name is None:
            return None
        return f"{base_name}.{property_name}"
    return _canonical_name(_compact_text(source, current), aliases)


def _canonical_name(value: str, aliases: dict[str, str]) -> str:
    parts = value.split(".")
    if not parts or not _IDENTIFIER.fullmatch(parts[0]):
        return value
    base = aliases.get(parts[0], parts[0])
    if len(parts) == 1:
        return base
    return ".".join((base, *parts[1:]))


def _normalise_module(value: str) -> str:
    if value.startswith("node:"):
        value = value[5:]
    if value.endswith("/index"):
        value = value[:-6]
    return value


def _unwrap(node: Node) -> Node:
    current = node
    while current.type in {"parenthesized_expression", "as_expression", "non_null_expression"}:
        children = list(current.named_children)
        if not children:
            break
        current = children[-1]
    return current


def _pair_parts(node: Node) -> tuple[Node | None, Node | None]:
    key = node.child_by_field_name("key")
    value = node.child_by_field_name("value")
    named = list(node.named_children)
    if key is None and named:
        key = named[0]
    if value is None and len(named) >= 2:
        value = named[-1]
    return key, value


def _static_property_name(node: Node, source: bytes) -> str | None:
    current = _unwrap(node)
    if current.type in {"identifier", "property_identifier", "private_property_identifier"}:
        return _node_text(source, current)
    value = _string_value(current, source)
    return value


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
        raise EcmaScriptCwe502ScanError(
            EcmaScriptCwe502ScanErrorCode.INTEGRITY_FAILURE
        ) from None


def _node_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe502ScanError(
            EcmaScriptCwe502ScanErrorCode.INTEGRITY_FAILURE
        ) from None


def _compact_text(source: bytes, node: Node) -> str:
    return "".join(_node_text(source, node).split())


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
    operation: EcmaScriptCwe502Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    language: str,
    signals: tuple[EcmaScriptCwe502Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "language": language,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "cwe": signal.cwe,
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


# Naming aliases keep the scanner discoverable to language-neutral callers.
scan_javascript_unsafe_deserialization = scan_javascript_cwe502
scan_typescript_unsafe_deserialization = scan_typescript_cwe502
scan_ecmascript_unsafe_deserialization = scan_ecmascript_cwe502


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE502_SCAN_LIMITS",
    "EcmaScriptCwe502Operation",
    "EcmaScriptCwe502ScanError",
    "EcmaScriptCwe502ScanErrorCode",
    "EcmaScriptCwe502ScanLimits",
    "EcmaScriptCwe502ScanResult",
    "EcmaScriptCwe502Signal",
    "scan_ecmascript_cwe502",
    "scan_ecmascript_unsafe_deserialization",
    "scan_javascript_cwe502",
    "scan_javascript_unsafe_deserialization",
    "scan_typescript_cwe502",
    "scan_typescript_unsafe_deserialization",
]
