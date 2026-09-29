"""Bounded JavaScript and TypeScript prototype-pollution facts.

The scanner consumes only an admitted, sealed ECMAScript ``SymbolIndex`` and
rebuilds the same index before inspecting the CST.  It recognizes a small set
of syntactic prototype writes and merge operations whose source or target
contains an explicit ``__proto__`` or ``constructor.prototype`` path.  The
result is an immutable source-free fact stream.  It is deliberately a scanner
primitive and never creates a finding or a verdict.
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
_RULE_ID = "securecode-ecmascript-cwe1321"
_DETECTOR = "securecode-ecmascript-cwe1321@1.0"


class EcmaScriptCwe1321ScanErrorCode(StrEnum):
    """Closed, source-free reasons a scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe1321ScanError(RuntimeError):
    """Fixed scanner failure that never echoes source or parser diagnostics."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe1321ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe1321ScanErrorCode:
            raise TypeError("ECMAScript CWE-1321 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-1321 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class EcmaScriptCwe1321Operation(StrEnum):
    """Recognized prototype-pollution write or merge operations."""

    OBJECT_ASSIGN = "object_assign"
    DEEP_MERGE = "deep_merge"
    PROTO_WRITE = "proto_write"
    CONSTRUCTOR_PROTOTYPE_WRITE = "constructor_prototype_write"
    OBJECT_PROTOTYPE_WRITE = "object_prototype_write"
    SET_PROTOTYPE_OF = "set_prototype_of"
    DEFINE_PROPERTY = "define_property"
    REFLECT_SET = "reflect_set"
    DEFINE_PROPERTIES = "define_properties"

    # Compatibility names for callers that use the descriptive terminology.
    UNSAFE_MERGE = "deep_merge"
    MERGE = "deep_merge"
    DYNAMIC_PROTO_WRITE = "proto_write"
    PROTO_ASSIGNMENT = "proto_write"
    CONSTRUCTOR_PROTOTYPE_ASSIGNMENT = "constructor_prototype_write"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe1321ScanLimits:
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
            raise ValueError("ECMAScript CWE-1321 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE1321_SCAN_LIMITS = EcmaScriptCwe1321ScanLimits()


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe1321Signal:
    """One immutable source-to-sink prototype-pollution fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe1321Operation
    signal_id: str
    rule_id: str = _RULE_ID
    cwe: str = "CWE-1321"
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
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not EcmaScriptCwe1321Operation
            or type(self.signal_id) is not str
            or _SHA256.fullmatch(self.signal_id) is None
            or self.signal_id
            != _signal_id(
                self.repository_id,
                self.revision,
                self.path,
                self.content_sha256,
                self.source_size_bytes,
                self.source,
                self.sink,
                self.operation,
            )
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-1321"
            or self.detector != _DETECTOR
        ):
            raise ValueError("ECMAScript CWE-1321 signal is invalid")

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the sink range used by generic scanner consumers."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe1321ScanResult:
    """Source-free, deterministic result for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe1321Signal, ...]
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
        order = tuple(
            (
                item.sink.start_byte,
                item.sink.end_byte,
                item.source.start_byte,
                item.source.end_byte,
                item.operation.value,
            )
            for item in self.signals
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
            or type(self.signals) is not tuple
            or any(type(item) is not EcmaScriptCwe1321Signal for item in self.signals)
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
            raise ValueError("ECMAScript CWE-1321 scan result is invalid")


def scan_javascript_cwe1321(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe1321ScanLimits = DEFAULT_ECMASCRIPT_CWE1321_SCAN_LIMITS,
) -> EcmaScriptCwe1321ScanResult:
    """Find bounded JavaScript prototype-pollution facts."""

    return _scan_ecmascript_cwe1321(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe1321(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe1321ScanLimits = DEFAULT_ECMASCRIPT_CWE1321_SCAN_LIMITS,
) -> EcmaScriptCwe1321ScanResult:
    """Find bounded TypeScript prototype-pollution facts."""

    return _scan_ecmascript_cwe1321(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe1321(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe1321ScanLimits = DEFAULT_ECMASCRIPT_CWE1321_SCAN_LIMITS,
) -> EcmaScriptCwe1321ScanResult:
    """Dispatch a CWE-1321 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe1321(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe1321(symbol_index, limits=limits)
    raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe1321(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe1321ScanLimits,
) -> EcmaScriptCwe1321ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe1321ScanLimits:
        raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.ANALYSIS_UNAVAILABLE)

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
        raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.INTEGRITY_FAILURE) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.ANALYSIS_UNAVAILABLE)
        aliases = _collect_aliases(nodes, source)
        bindings = _collect_unsafe_bindings(nodes, source, aliases)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe1321Operation]] = set()
        for node in nodes:
            if node.type == "call_expression":
                raw.update(_call_facts(node, source, aliases, bindings))
            elif node.type in {"assignment_expression", "augmented_assignment_expression"}:
                fact = _assignment_fact(node, source)
                if fact is not None:
                    raw.add(fact)
            elif node.type == "update_expression":
                fact = _update_fact(node, source)
                if fact is not None:
                    raw.add(fact)
            if len(raw) > limits.max_signals:
                raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.SIGNAL_LIMIT)
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
            raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.SIGNAL_LIMIT)
    except EcmaScriptCwe1321ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.INTEGRITY_FAILURE) from None

    signals = tuple(
        EcmaScriptCwe1321Signal(
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
    return EcmaScriptCwe1321ScanResult(
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


def _bounded_nodes(root: Node, limits: EcmaScriptCwe1321ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _call_facts(
    node: Node,
    source: bytes,
    aliases: dict[str, str],
    bindings: dict[str, tuple[bool, bool]],
) -> set[tuple[SourceRange, SourceRange, EcmaScriptCwe1321Operation]]:
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None:
        return set()
    callee = _canonical_callee(function, source, aliases)
    values = list(arguments.named_children)
    if not values:
        return set()
    sink = _range(node)
    output: set[tuple[SourceRange, SourceRange, EcmaScriptCwe1321Operation]] = set()

    if callee == "Object.assign":
        if len(values) < 2:
            return set()
        target_path = _member_path(values[0], source)
        target_operation = _unsafe_path_operation(target_path)
        for value in values[1:]:
            if target_operation is not None:
                _add_fact(output, _range(value), sink, target_operation)
            elif _unsafe_source(value, source, bindings, deep=False):
                _add_fact(output, _range(value), sink, EcmaScriptCwe1321Operation.OBJECT_ASSIGN)
        return output

    if callee in _DEEP_MERGE_NAMES:
        if len(values) < 2:
            return set()
        target_operation = _unsafe_path_operation(_member_path(values[0], source))
        for value in values[1:]:
            if target_operation is not None:
                _add_fact(output, _range(value), sink, target_operation)
            elif _unsafe_source(value, source, bindings, deep=True):
                _add_fact(output, _range(value), sink, EcmaScriptCwe1321Operation.DEEP_MERGE)
        return output

    if callee in {"Object.setPrototypeOf", "Reflect.setPrototypeOf"}:
        if len(values) >= 2:
            _add_fact(
                output,
                _range(values[1]),
                sink,
                EcmaScriptCwe1321Operation.SET_PROTOTYPE_OF,
            )
        return output

    if callee in {"Object.defineProperty", "Reflect.defineProperty"}:
        if len(values) < 2:
            return set()
        target_operation = _unsafe_path_operation(_member_path(values[0], source))
        property_name = _static_property_name(values[1], source)
        if target_operation is None and property_name != "__proto__":
            return set()
        operation = target_operation or EcmaScriptCwe1321Operation.DEFINE_PROPERTY
        value = values[2] if len(values) >= 3 else values[1]
        _add_fact(output, _range(value), sink, operation)
        return output

    if callee == "Reflect.set":
        if len(values) < 2:
            return set()
        target_operation = _unsafe_path_operation(_member_path(values[0], source))
        property_name = _static_property_name(values[1], source)
        if target_operation is None and property_name != "__proto__":
            return set()
        operation = target_operation or EcmaScriptCwe1321Operation.REFLECT_SET
        value = values[2] if len(values) >= 3 else values[1]
        _add_fact(output, _range(value), sink, operation)
        return output

    if callee in {"Object.defineProperties", "Reflect.defineProperties"}:
        if len(values) < 2:
            return set()
        target_operation = _unsafe_path_operation(_member_path(values[0], source))
        descriptors = values[1]
        if target_operation is None and not _unsafe_source(
            descriptors, source, bindings, deep=False
        ):
            return set()
        operation = target_operation or EcmaScriptCwe1321Operation.DEFINE_PROPERTIES
        _add_fact(output, _range(descriptors), sink, operation)
        return output

    return set()


_DEEP_MERGE_NAMES = frozenset(
    {
        "merge",
        "deepMerge",
        "deepmerge",
        "extend",
        "defaultsDeep",
        "lodash.merge",
        "lodash.mergeWith",
        "lodash.defaultsDeep",
        "lodash/merge",
        "lodash/mergeWith",
        "lodash/defaultsDeep",
    }
)


def _assignment_fact(
    node: Node,
    source_bytes: bytes,
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe1321Operation] | None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None:
        return None
    operation = _unsafe_path_operation(_member_path(left, source_bytes))
    if operation is None:
        return None
    sink = _range(node)
    source_range = _range(right) if right is not None else sink
    if not sink.contains(source_range):
        raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.INTEGRITY_FAILURE)
    return source_range, sink, operation


def _update_fact(
    node: Node,
    source_bytes: bytes,
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe1321Operation] | None:
    argument = node.child_by_field_name("argument")
    if argument is None:
        named = list(node.named_children)
        argument = named[-1] if named else None
    if argument is None:
        return None
    operation = _unsafe_path_operation(_member_path(argument, source_bytes))
    if operation is None:
        return None
    sink = _range(node)
    return sink, sink, operation


def _add_fact(
    output: set[tuple[SourceRange, SourceRange, EcmaScriptCwe1321Operation]],
    source: SourceRange,
    sink: SourceRange,
    operation: EcmaScriptCwe1321Operation,
) -> None:
    if not sink.contains(source):
        raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.INTEGRITY_FAILURE)
    output.add((source, sink, operation))


def _unsafe_path_operation(
    path: tuple[str, ...] | None,
) -> EcmaScriptCwe1321Operation | None:
    if not path:
        return None
    if path[-1] == "__proto__":
        return EcmaScriptCwe1321Operation.PROTO_WRITE
    for index in range(len(path) - 1):
        if path[index : index + 2] == ("constructor", "prototype"):
            return EcmaScriptCwe1321Operation.CONSTRUCTOR_PROTOTYPE_WRITE
    if len(path) >= 2 and path[:2] == ("Object", "prototype"):
        return EcmaScriptCwe1321Operation.OBJECT_PROTOTYPE_WRITE
    return None


def _collect_unsafe_bindings(
    nodes: tuple[Node, ...],
    source: bytes,
    aliases: dict[str, str],
) -> dict[str, tuple[bool, bool]]:
    output: dict[str, tuple[bool, bool]] = {}
    for node in nodes:
        if node.type not in {"lexical_declaration", "variable_declaration"}:
            continue
        for declarator in node.named_children:
            if declarator.type != "variable_declarator":
                continue
            name = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if name is None or value is None or name.type != "identifier":
                continue
            direct = _unsafe_source(value, source, output, deep=False, aliases=aliases)
            deep = _unsafe_source(value, source, output, deep=True, aliases=aliases)
            if direct or deep:
                output[_node_text(source, name)] = (direct, deep)
    return output


def _unsafe_source(
    node: Node,
    source: bytes,
    bindings: dict[str, tuple[bool, bool]],
    *,
    deep: bool,
    aliases: dict[str, str] | None = None,
) -> bool:
    current = _unwrap(node)
    if current.type in {"object", "object_pattern"}:
        return _object_has_unsafe_key(current, source, deep=deep, bindings=bindings)
    if current.type == "spread_element":
        values = list(current.named_children)
        return bool(values) and _unsafe_source(
            values[0], source, bindings, deep=deep, aliases=aliases
        )
    if current.type == "identifier":
        value = bindings.get(_node_text(source, current))
        if value is None:
            return False
        return value[1] if deep else value[0]
    if current.type == "call_expression":
        function = current.child_by_field_name("function")
        if function is None:
            return False
        name = _canonical_callee(function, source, aliases or {})
        return name in {"JSON.parse", "json.parse"}
    if current.type in {"await_expression", "parenthesized_expression", "as_expression"}:
        values = list(current.named_children)
        return bool(values) and _unsafe_source(
            values[-1], source, bindings, deep=deep, aliases=aliases
        )
    return False


def _object_has_unsafe_key(
    node: Node,
    source: bytes,
    *,
    deep: bool,
    bindings: dict[str, tuple[bool, bool]],
) -> bool:
    if not deep:
        for child in node.named_children:
            if child.type == "pair":
                key, _ = _pair_parts(child)
                if key is not None and _static_property_name(key, source) == "__proto__":
                    return True
            elif child.type == "spread_element" and _unsafe_source(
                child, source, bindings, deep=False
            ):
                return True
        return False

    stack: list[tuple[Node, bool]] = [(node, False)]
    while stack:
        current, in_constructor = stack.pop()
        for child in current.named_children:
            if child.type == "pair":
                key, value = _pair_parts(child)
                key_name = _static_property_name(key, source) if key is not None else None
                if key_name == "__proto__" or (in_constructor and key_name == "prototype"):
                    return True
                if value is not None and value.type in {"object", "object_pattern"}:
                    stack.append((value, in_constructor or key_name == "constructor"))
            elif child.type in {"object", "object_pattern"}:
                stack.append((child, in_constructor))
            elif child.type == "spread_element" and _unsafe_source(
                child, source, bindings, deep=True
            ):
                return True
    return False


def _pair_parts(node: Node) -> tuple[Node | None, Node | None]:
    key = node.child_by_field_name("key")
    value = node.child_by_field_name("value")
    if key is None:
        named = list(node.named_children)
        key = named[0] if named else None
    return key, value


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
                if name is None or value is None or name.type != "identifier":
                    continue
                canonical = _canonical_expression(value, source, aliases)
                if canonical is not None:
                    aliases[_node_text(source, name)] = canonical
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


def _canonical_expression(node: Node, source: bytes, aliases: dict[str, str]) -> str | None:
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or _compact_text(source, function) != "require":
            return None
        values = list(arguments.named_children)
        if len(values) != 1:
            return None
        module = _string_value(values[0], source)
        return _normalise_module(module) if module is not None else None
    return _canonical_name(_compact_text(source, node), aliases)


def _canonical_callee(node: Node, source: bytes, aliases: dict[str, str]) -> str:
    path = _member_path(node, source)
    text = ".".join(path) if path is not None else _compact_text(source, node)
    return _canonical_name(text, aliases)


def _canonical_name(value: str, aliases: dict[str, str]) -> str:
    parts = value.split(".")
    if not parts or not _IDENTIFIER.fullmatch(parts[0]):
        return value
    base = aliases.get(parts[0], parts[0])
    if len(parts) == 1:
        return base
    return ".".join((base, *parts[1:]))


def _member_path(node: Node, source: bytes) -> tuple[str, ...] | None:
    if node.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "this",
        "super",
    }:
        value = _node_text(source, node)
        return (value,) if value and value != "#" else None
    if node.type in {"member_expression", "subscript_expression"}:
        object_node = node.child_by_field_name("object")
        property_node = node.child_by_field_name("property")
        if property_node is None:
            property_node = node.child_by_field_name("index")
        if object_node is None or property_node is None:
            return None
        base = _member_path(object_node, source)
        property_name = _static_property_name(property_node, source)
        if base is None or property_name is None:
            return None
        return (*base, property_name)
    return None


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
        return _node_text(source, node)
    if node.type == "string":
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


def _normalise_module(value: str) -> str:
    return value[5:] if value.startswith("node:") else value


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
        raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.INTEGRITY_FAILURE) from None


def _node_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe1321ScanError(EcmaScriptCwe1321ScanErrorCode.INTEGRITY_FAILURE) from None


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
    operation: EcmaScriptCwe1321Operation,
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    language: str,
    signals: tuple[EcmaScriptCwe1321Signal, ...],
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


# Discoverable names for language-neutral callers.
scan_javascript_prototype_pollution = scan_javascript_cwe1321
scan_typescript_prototype_pollution = scan_typescript_cwe1321
scan_ecmascript_prototype_pollution = scan_ecmascript_cwe1321
scan_javascript_cwe1321_prototype_pollution = scan_javascript_cwe1321
scan_typescript_cwe1321_prototype_pollution = scan_typescript_cwe1321
scan_ecmascript_cwe1321_prototype_pollution = scan_ecmascript_cwe1321


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE1321_SCAN_LIMITS",
    "EcmaScriptCwe1321Operation",
    "EcmaScriptCwe1321ScanError",
    "EcmaScriptCwe1321ScanErrorCode",
    "EcmaScriptCwe1321ScanLimits",
    "EcmaScriptCwe1321ScanResult",
    "EcmaScriptCwe1321Signal",
    "scan_ecmascript_cwe1321",
    "scan_ecmascript_cwe1321_prototype_pollution",
    "scan_ecmascript_prototype_pollution",
    "scan_javascript_cwe1321",
    "scan_javascript_cwe1321_prototype_pollution",
    "scan_javascript_prototype_pollution",
    "scan_typescript_cwe1321",
    "scan_typescript_cwe1321_prototype_pollution",
    "scan_typescript_prototype_pollution",
]
