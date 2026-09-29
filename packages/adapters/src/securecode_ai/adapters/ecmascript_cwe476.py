"""Bounded ECMAScript facts for CWE-476 nullable dereferences.

The scanner reports only property reads and method calls whose receiver is a
locally proven nullable identifier.  Proof is limited to explicit nullish
values and TypeScript nullish annotations.  It does not infer framework or
interprocedural behavior.  A sealed symbol index is rebuilt from the exact
admitted bytes before those bytes are parsed again for analysis.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import (
    CONTRACT_SCHEMA_VERSION,
    DataClass,
    ParseHealth,
    ProducerRef,
    RawSignal,
    RepositoryFile,
    SourceLocation,
    SourcePoint,
    SourcePosition,
    SourceRange,
    SymbolIndex,
)
from tree_sitter import Language, Node, Parser

from .cst import CstAdapterError, build_javascript_symbol_index, build_typescript_symbol_index
from .cst_ecmascript import _javascript_language, _typescript_language

_MAX_LIMITS = (2_000_000, 250_000, 512, 10_000)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-ecmascript-cwe476"
_DETECTOR = "securecode-ecmascript-cwe476@1.0"
_DETAIL = "nullable_value_dereferenced_without_guard"
_SCOPES = frozenset(
    {
        "arrow_function",
        "function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)
_PARAMETERS = frozenset(
    {
        "assignment_pattern",
        "formal_parameter",
        "optional_parameter",
        "parameter",
        "required_parameter",
        "rest_parameter",
    }
)


class EcmaScriptCwe476ScanErrorCode(StrEnum):
    """Closed, source-free reasons a scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe476ScanError(RuntimeError):
    """Fixed scanner failure which never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe476ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe476ScanErrorCode:
            raise TypeError("ECMAScript CWE-476 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-476 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class EcmaScriptCwe476Operation(StrEnum):
    """Property access forms admitted by this scanner."""

    PROPERTY_READ = "property_read"
    METHOD_CALL = "method_call"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe476ScanLimits:
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
            raise ValueError("ECMAScript CWE-476 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE476_SCAN_LIMITS = EcmaScriptCwe476ScanLimits()


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe476Signal:
    """One immutable, source-free nullable-receiver fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe476Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-476"
    detector: str = _DETECTOR
    detail: str = _DETAIL

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
            and 0 <= self.source.start_byte <= self.source.end_byte
            and self.source.start_byte <= self.sink.start_byte
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
                self.language,
                self.source,
                self.sink,
                self.operation,
            )
            if identity_valid
            and ranges_valid
            and self.language in {"javascript", "typescript"}
            and type(self.operation) is EcmaScriptCwe476Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or self.language not in {"javascript", "typescript"}
            or type(self.operation) is not EcmaScriptCwe476Operation
            or expected_id is None
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-476"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("ECMAScript CWE-476 signal is invalid")
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
class EcmaScriptCwe476ScanResult:
    """Deterministic, source-free CWE-476 facts for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe476Signal, ...]
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
        valid = type(self.signals) is tuple and all(
            type(item) is EcmaScriptCwe476Signal for item in self.signals
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
            if valid
            else ()
        )
        same_identity = valid and all(
            item.repository_id == self.repository_id
            and item.revision == self.revision
            and item.path == self.path
            and item.content_sha256 == self.content_sha256
            and item.source_size_bytes == self.source_size_bytes
            and item.language == self.language
            for item in self.signals
        )
        if (
            not identity_valid
            or not valid
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
            raise ValueError("ECMAScript CWE-476 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Binding:
    source: SourceRange
    typed_nullable: bool
    initially_nullable: bool


@dataclass(frozen=True, slots=True)
class _Event:
    position: int
    source: SourceRange
    nullable: bool


def scan_javascript_cwe476(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe476ScanLimits = DEFAULT_ECMASCRIPT_CWE476_SCAN_LIMITS,
) -> EcmaScriptCwe476ScanResult:
    """Find locally proven nullable receivers in JavaScript."""

    return _scan_ecmascript_cwe476(symbol_index, language="javascript", limits=limits)


def scan_typescript_cwe476(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe476ScanLimits = DEFAULT_ECMASCRIPT_CWE476_SCAN_LIMITS,
) -> EcmaScriptCwe476ScanResult:
    """Find locally proven nullable receivers in TypeScript."""

    return _scan_ecmascript_cwe476(symbol_index, language="typescript", limits=limits)


def scan_ecmascript_cwe476(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe476ScanLimits = DEFAULT_ECMASCRIPT_CWE476_SCAN_LIMITS,
) -> EcmaScriptCwe476ScanResult:
    """Dispatch a CWE-476 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe476(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe476(symbol_index, limits=limits)
    raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe476(
    symbol_index: SymbolIndex,
    *,
    language: str,
    limits: EcmaScriptCwe476ScanLimits,
) -> EcmaScriptCwe476ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe476ScanLimits:
        raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != language:
        raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.REQUEST_INVALID)
    if symbol_index.source_byte_length > limits.max_source_bytes:
        raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.ANALYSIS_UNAVAILABLE)
    builder = (
        build_javascript_symbol_index if language == "javascript" else build_typescript_symbol_index
    )
    grammar = (
        _javascript_language()
        if language == "javascript"
        else _typescript_language(tsx=symbol_index.path.endswith(".tsx"))
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
        source = symbol_index.source
        source.decode("utf-8", errors="strict")
        root = Parser(Language(grammar)).parse(source).root_node
    except (CstAdapterError, TypeError, UnicodeDecodeError, ValueError):
        raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.INTEGRITY_FAILURE) from None
    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.ANALYSIS_UNAVAILABLE)
        facts: set[tuple[SourceRange, SourceRange, EcmaScriptCwe476Operation]] = set()
        local_nodes_by_scope = _group_scope_nodes(root, nodes)
        for scope, local_nodes in local_nodes_by_scope.items():
            bindings = _bindings(local_nodes, source, language)
            if not bindings:
                continue
            events = _events(local_nodes, bindings, source)
            for node in local_nodes:
                receiver = _receiver(node)
                if receiver is None or _is_optional(node) or _is_write_target(node):
                    continue
                name_node = _simple_identifier(receiver)
                if name_node is None:
                    continue
                name = _text(source, name_node)
                if name not in bindings:
                    continue
                event = _latest_event(events.get(name, ()), node.start_byte)
                if event is None or not event.nullable:
                    continue
                if _locally_guarded(node, name, scope, source):
                    continue
                parent = node.parent
                operation = (
                    EcmaScriptCwe476Operation.METHOD_CALL
                    if parent is not None
                    and parent.type == "call_expression"
                    and parent.child_by_field_name("function") == node
                    else EcmaScriptCwe476Operation.PROPERTY_READ
                )
                sink = (
                    _range(parent)
                    if parent is not None and operation is EcmaScriptCwe476Operation.METHOD_CALL
                    else _range(node)
                )
                facts.add((event.source, sink, operation))
                if len(facts) > limits.max_signals:
                    raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.SIGNAL_LIMIT)
        ordered = tuple(
            sorted(
                facts,
                key=lambda item: (
                    item[1].start_byte,
                    item[1].end_byte,
                    item[0].start_byte,
                    item[0].end_byte,
                    item[2].value,
                ),
            )
        )
    except EcmaScriptCwe476ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.INTEGRITY_FAILURE) from None
    signals = tuple(
        EcmaScriptCwe476Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            language=language,
            source=source_range,
            sink=sink_range,
            operation=operation,
        )
        for source_range, sink_range, operation in ordered
    )
    return EcmaScriptCwe476ScanResult(
        repository_id=symbol_index.repository_id,
        revision=symbol_index.revision,
        path=symbol_index.path,
        content_sha256=symbol_index.content_sha256,
        source_size_bytes=symbol_index.source_byte_length,
        language=language,
        signals=signals,
        scan_sha256=_scan_sha256(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            language,
            signals,
        ),
    )


def _group_scope_nodes(root: Node, nodes: tuple[Node, ...]) -> dict[Node, tuple[Node, ...]]:
    output: dict[Node, list[Node]] = {root: []}
    for node in nodes:
        if node.type in _SCOPES:
            output.setdefault(node, [])
    for node in nodes:
        current = node.parent
        owner = root
        while current is not None and current is not root:
            if current.type in _SCOPES:
                owner = current
                break
            current = current.parent
        if node.type in _SCOPES:
            continue
        output[owner].append(node)
    return {scope: tuple(items) for scope, items in output.items()}


def _bindings(
    nodes: tuple[Node, ...],
    source: bytes,
    language: str,
) -> dict[str, _Binding]:
    output: dict[str, _Binding] = {}
    for node in nodes:
        if node.type in _PARAMETERS:
            pattern = (
                node.child_by_field_name("pattern")
                or node.child_by_field_name("name")
                or node.child_by_field_name("left")
            )
            name_node = _simple_identifier(pattern) if pattern is not None else None
            if name_node is None:
                name_node = next(
                    (child for child in node.named_children if child.type == "identifier"),
                    None,
                )
            if name_node is None:
                continue
            typed = language == "typescript" and (
                node.type == "optional_parameter" or _has_nullable_type(node, source)
            )
            default = node.child_by_field_name("value") or node.child_by_field_name("right")
            default_null = default is not None and _is_nullish(default, source)
            if typed or default_null:
                output.setdefault(
                    _text(source, name_node),
                    _Binding(_range(node), typed, typed or default_null),
                )
        elif node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            name_node = _simple_identifier(name_node) if name_node is not None else None
            if name_node is None:
                continue
            value = node.child_by_field_name("value")
            typed = language == "typescript" and _has_nullable_type(node, source)
            null_init = value is not None and _is_nullish(value, source)
            if typed or null_init:
                evidence = _type_evidence(node) if typed else value
                output.setdefault(
                    _text(source, name_node),
                    _Binding(_range(evidence or node), typed, typed),
                )
        elif node.type == "assignment_expression":
            name_node = _simple_identifier(node.child_by_field_name("left"))
            value = node.child_by_field_name("right")
            if name_node is not None and value is not None and _is_nullish(value, source):
                output.setdefault(
                    _text(source, name_node),
                    _Binding(_range(value), False, False),
                )
    return output


def _events(
    nodes: tuple[Node, ...],
    bindings: dict[str, _Binding],
    source: bytes,
) -> dict[str, tuple[_Event, ...]]:
    mutable: dict[str, list[_Event]] = {
        name: [_Event(0, binding.source, binding.initially_nullable)]
        for name, binding in bindings.items()
    }
    declarations = [node for node in nodes if node.type == "variable_declarator"]
    assignments = [node for node in nodes if node.type == "assignment_expression"]
    updates = sorted((*declarations, *assignments), key=lambda item: item.start_byte)
    for node in updates:
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            name_node = _simple_identifier(name_node) if name_node is not None else None
            value = node.child_by_field_name("value")
        else:
            name_node = _simple_identifier(node.child_by_field_name("left"))
            value = node.child_by_field_name("right")
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None:
                continue
            if right.start_byte - left.end_byte > 8:
                continue
            if source[left.end_byte : right.start_byte].strip() != b"=":
                continue
        if name_node is None or value is None:
            continue
        name = _text(source, name_node)
        binding = bindings.get(name)
        if binding is None:
            continue
        nullable, evidence = _value_nullability(value, name, mutable, source, binding)
        mutable[name].append(_Event(node.start_byte, evidence, nullable))
    return {
        name: tuple(sorted(items, key=lambda event: event.position))
        for name, items in mutable.items()
    }


def _value_nullability(
    value: Node,
    name: str,
    events: dict[str, list[_Event]],
    source: bytes,
    binding: _Binding,
) -> tuple[bool, SourceRange]:
    current = value
    while current.type == "parenthesized_expression" and current.named_children:
        current = current.named_children[0]
    if _is_nullish(current, source):
        return True, _range(current)
    identifier = _simple_identifier(current)
    if identifier is not None:
        other_name = _text(source, identifier)
        other = _latest_event(events.get(other_name, ()), value.start_byte)
        if other is not None and other.nullable:
            return True, other.source
        if other is not None and not other.nullable:
            return False, other.source
    if _is_definitely_nonnull(current):
        return False, _range(current)
    if binding.typed_nullable:
        return True, binding.source
    return False, _range(value)


def _latest_event(events: tuple[_Event, ...] | list[_Event], position: int) -> _Event | None:
    selected = None
    for event in events:
        if event.position > position:
            break
        selected = event
    return selected


def _receiver(node: Node) -> Node | None:
    if node.type == "member_expression":
        return node.child_by_field_name("object")
    if node.type == "subscript_expression":
        return node.child_by_field_name("object")
    return None


def _simple_identifier(node: Node | None) -> Node | None:
    current = node
    while current is not None and current.type == "parenthesized_expression":
        children = current.named_children
        current = children[0] if len(children) == 1 else None
    return current if current is not None and current.type == "identifier" else None


def _is_optional(node: Node) -> bool:
    if any(child.type == "optional_chain" for child in node.children):
        return True
    parent = node.parent
    if parent is not None and parent.type == "call_expression":
        return any(child.type == "optional_chain" for child in parent.children)
    return False


def _is_write_target(node: Node) -> bool:
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "assignment_expression" and parent.child_by_field_name("left") == node:
        return True
    if (
        parent.type == "augmented_assignment_expression"
        and parent.child_by_field_name("left") == node
    ):
        return True
    if parent.type == "update_expression":
        return node in parent.named_children
    return False


def _locally_guarded(node: Node, name: str, scope: Node, source: bytes) -> bool:
    current: Node | None = node
    while current is not None and current != scope:
        parent = current.parent
        if parent is None:
            break
        if parent.type == "if_statement":
            condition = parent.child_by_field_name("condition")
            consequence = parent.child_by_field_name("consequence")
            alternative = parent.child_by_field_name("alternative")
            relation = _condition_relation(condition, name, source)
            if consequence is not None and _contains(consequence, node) and relation == "nonnull":
                return True
            if (
                alternative is not None
                and _contains(alternative, node)
                and relation == "null"
                and consequence is not None
                and _terminates(consequence)
            ):
                return True
        if parent.type == "ternary_expression":
            condition = parent.child_by_field_name("condition")
            consequence = parent.child_by_field_name("consequence")
            alternative = parent.child_by_field_name("alternative")
            relation = _condition_relation(condition, name, source)
            if consequence is not None and _contains(consequence, node) and relation == "nonnull":
                return True
            if alternative is not None and _contains(alternative, node) and relation == "null":
                return True
        if parent.type == "binary_expression":
            left = parent.child_by_field_name("left")
            right = parent.child_by_field_name("right")
            operator = _operator(parent, source)
            if right is not None and _contains(right, node) and operator in {"&&", "||"}:
                relation = _condition_relation(left, name, source)
                if (operator == "&&" and relation == "nonnull") or (
                    operator == "||" and relation == "null"
                ):
                    return True
        current = parent
    block = node.parent
    while block is not None and block != scope:
        if block.type in {"statement_block", "program", "switch_body"}:
            statements = tuple(block.named_children)
            for statement in statements:
                if statement.start_byte >= node.start_byte:
                    break
                if statement.type != "if_statement":
                    continue
                condition = statement.child_by_field_name("condition")
                consequence = statement.child_by_field_name("consequence")
                if (
                    _condition_relation(condition, name, source) == "null"
                    and consequence is not None
                    and _terminates(consequence)
                ):
                    return True
        block = block.parent
    return False


def _condition_relation(node: Node | None, name: str, source: bytes) -> str | None:
    if node is None:
        return None
    value = _compact(source, node)
    escaped = re.escape(name)
    if re.fullmatch(escaped, value):
        return "nonnull"
    if re.fullmatch(rf"!{escaped}", value):
        return "null"
    if re.fullmatch(rf"(?:{escaped}(?:===?|!==?)null|null(?:===?|!==?){escaped})", value):
        operator = "!=" if "!=" in value else "=="
        return "nonnull" if operator == "!=" else "null"
    if re.fullmatch(
        rf"(?:{escaped}(?:===?|!==?)(?:undefined|void0)|(?:undefined|void0)(?:===?|!==?){escaped})",
        value,
    ):
        operator = "!=" if "!=" in value else "=="
        return "nonnull" if operator == "!=" else "null"
    return None


def _terminates(node: Node) -> bool:
    children = node.named_children if node.type in {"statement_block", "program"} else (node,)
    for child in children:
        if child.type in {
            "return_statement",
            "throw_statement",
            "continue_statement",
            "break_statement",
        }:
            return True
        if child.type == "if_statement":
            consequence = child.child_by_field_name("consequence")
            alternative = child.child_by_field_name("alternative")
            if (
                consequence is not None
                and alternative is not None
                and _terminates(consequence)
                and _terminates(alternative)
            ):
                return True
    return False


def _is_nullish(node: Node, source: bytes) -> bool:
    current = node
    while current.type == "parenthesized_expression" and current.named_children:
        current = current.named_children[0]
    return current.type == "null" or (
        current.type == "identifier" and _text(source, current) == "undefined"
    )


def _is_definitely_nonnull(node: Node) -> bool:
    return node.type in {
        "array",
        "arrow_function",
        "function",
        "function_expression",
        "generator_function",
        "new_expression",
        "object",
        "regex",
        "string",
        "template_string",
        "this",
        "number",
        "true",
        "false",
        "super",
    }


def _has_nullable_type(node: Node, source: bytes) -> bool:
    annotation = _type_evidence(node)
    if annotation is None:
        return False
    return _has_top_level_nullish_union(_compact(source, annotation))


def _has_top_level_nullish_union(annotation: str) -> bool:
    value = annotation.removeprefix(":")
    segments: list[str] = []
    start = 0
    angle = 0
    paren = 0
    bracket = 0
    quote = ""
    escaped = False
    for position, char in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char == "<":
            angle += 1
        elif char == ">":
            angle = max(0, angle - 1)
        elif char == "(":
            paren += 1
        elif char == ")":
            paren = max(0, paren - 1)
        elif char == "[":
            bracket += 1
        elif char == "]":
            bracket = max(0, bracket - 1)
        elif char == "|" and angle == 0 and paren == 0 and bracket == 0:
            segments.append(value[start:position])
            start = position + 1
    segments.append(value[start:])
    if len(segments) == 1:
        return _strip_type_parens(segments[0]) in {"null", "undefined"}
    return any(_strip_type_parens(item) in {"null", "undefined"} for item in segments)


def _strip_type_parens(value: str) -> str:
    current = value.strip()
    while current.startswith("(") and current.endswith(")"):
        depth = 0
        wraps_all = True
        for position, char in enumerate(current):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0 and position != len(current) - 1:
                    wraps_all = False
                    break
        if not wraps_all or depth != 0:
            break
        current = current[1:-1].strip()
    return current


def _type_evidence(node: Node) -> Node | None:
    stack = [node]
    examined = 0
    while stack and examined < 64:
        current = stack.pop()
        examined += 1
        if current.type == "type_annotation":
            return current
        if current is not node and current.type not in {
            "name",
            "pattern",
            "required_parameter",
            "optional_parameter",
        }:
            continue
        if current.start_byte - node.start_byte > 512:
            continue
        stack.extend(reversed(current.named_children))
    return None


def _operator(node: Node, source: bytes) -> str:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return ""
    raw = source[left.end_byte : min(right.start_byte, left.end_byte + 8)]
    return raw.decode("ascii", errors="ignore").strip()


def _compact(source: bytes, node: Node) -> str:
    if node.end_byte - node.start_byte > 256:
        return ""
    try:
        return "".join(
            source[node.start_byte : node.end_byte].decode("utf-8", errors="strict").split()
        )
    except UnicodeDecodeError:
        raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.INTEGRITY_FAILURE) from None


def _text(source: bytes, node: Node) -> str:
    if node.end_byte - node.start_byte > 1024:
        return ""
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.INTEGRITY_FAILURE) from None


def _bounded_nodes(root: Node, limits: EcmaScriptCwe476ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _contains(container: Node, target: Node) -> bool:
    return container.start_byte <= target.start_byte and target.end_byte <= container.end_byte


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
    language: str,
    source: SourceRange,
    sink: SourceRange,
    operation: EcmaScriptCwe476Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-476",
        "detector": _DETECTOR,
        "language": language,
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
    signals: tuple[EcmaScriptCwe476Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-476",
        "detector": _DETECTOR,
        "language": language,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
                "detail": item.detail,
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def ecmascript_cwe476_signals_to_raw_signals(
    symbol_index: SymbolIndex,
    result: EcmaScriptCwe476ScanResult,
    *,
    tenant_id: str,
    producer: ProducerRef,
) -> tuple[RawSignal, ...]:
    """Bind revalidated facts to the source-free RawSignal boundary."""

    if (
        type(symbol_index) is not SymbolIndex
        or type(result) is not EcmaScriptCwe476ScanResult
        or type(tenant_id) is not str
        or not tenant_id
        or type(producer) is not ProducerRef
        or len(result.signals) > DEFAULT_ECMASCRIPT_CWE476_SCAN_LIMITS.max_signals
    ):
        raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.REQUEST_INVALID)
    try:
        validated = ProducerRef.model_validate(producer.model_dump(mode="python"))
        if (
            validated.producer_id != f"securecode-{result.language}-cwe476"
            or validated.producer_version != "1.0.0"
        ):
            raise ValueError("producer mismatch")
        scanner = (
            scan_javascript_cwe476 if result.language == "javascript" else scan_typescript_cwe476
        )
        if scanner(symbol_index) != result:
            raise ValueError("scanner facts mismatch")
        RepositoryFile(result.path, result.source_size_bytes, result.content_sha256)
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", tenant_id) is None:
            raise ValueError("tenant invalid")
        output: list[RawSignal] = []
        for signal in result.signals:
            binding = {
                "scan_sha256": result.scan_sha256,
                "sink": _range_value(signal.sink),
                "tenant_id": tenant_id,
                "producer": validated.model_dump(mode="json"),
                "rule_id": "cwe-476-nullable-dereference",
            }
            digest = hashlib.sha256(
                json.dumps(binding, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            output.append(
                RawSignal(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    raw_signal_id=f"cwe476-{signal.language}-{digest}",
                    tenant_id=tenant_id,
                    head_sha=signal.revision,
                    producer=validated,
                    rule_id="cwe-476-nullable-dereference",
                    location=SourceLocation(
                        schema_version=CONTRACT_SCHEMA_VERSION,
                        path=signal.path,
                        start=SourcePosition(
                            schema_version=CONTRACT_SCHEMA_VERSION,
                            line=signal.sink.start_point.row + 1,
                            column=signal.sink.start_point.column + 1,
                        ),
                        end=SourcePosition(
                            schema_version=CONTRACT_SCHEMA_VERSION,
                            line=signal.sink.end_point.row + 1,
                            column=signal.sink.end_point.column + 1,
                        ),
                        content_sha256=signal.content_sha256,
                    ),
                    payload_classification=DataClass.INTERNAL_METADATA,
                    signal_sha256=digest,
                )
            )
        return tuple(output)
    except EcmaScriptCwe476ScanError:
        raise
    except (ValueError, TypeError, AttributeError):
        raise EcmaScriptCwe476ScanError(EcmaScriptCwe476ScanErrorCode.INTEGRITY_FAILURE) from None


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE476_SCAN_LIMITS",
    "EcmaScriptCwe476Operation",
    "EcmaScriptCwe476ScanError",
    "EcmaScriptCwe476ScanErrorCode",
    "EcmaScriptCwe476ScanLimits",
    "EcmaScriptCwe476ScanResult",
    "EcmaScriptCwe476Signal",
    "ecmascript_cwe476_signals_to_raw_signals",
    "scan_ecmascript_cwe476",
    "scan_javascript_cwe476",
    "scan_typescript_cwe476",
]
