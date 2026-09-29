"""Bounded Go facts for CWE-476 nil pointer dereferences.

The adapter reports only dereferences of pointer values that are locally
provable to be nullable.  Pointer parameters, pointer receivers, uninitialised
pointer declarations, and explicit ``nil`` assignments are tracked within one
function.  A value is treated as proven non-null only after a literal
allocation or a non-nil guard which dominates the dereference.  Calls with
unknown return values remain nullable when assigned to a tracked pointer.

The implementation deliberately does not guess about interprocedural return
types, interfaces, maps, slices, or arbitrary framework semantics.  Results
contain sealed identity and source ranges only; source bytes are transient
scanner input and never appear in results or error messages.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
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

_MAX_LIMITS = (2_000_000, 2_048, 64, 50_000)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-go-cwe476"
_DETECTOR = "securecode-go-cwe476@1.0"
_DETAIL = "nullable_pointer_dereference"
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})


class GoCwe476ScanErrorCode(StrEnum):
    """Closed, source-free reasons a Go CWE-476 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe476ScanError(RuntimeError):
    """Fixed scanner failure which never echoes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe476ScanErrorCode) -> None:
        if type(code) is not GoCwe476ScanErrorCode:
            raise TypeError("Go CWE-476 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-476 nil pointer scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe476ScanLimits:
    """Hard ceilings applied before and during local nil-flow analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]
    max_nodes: int = _MAX_LIMITS[3]

    def __post_init__(self) -> None:
        values = (
            self.max_source_bytes,
            self.max_signals,
            self.max_expression_depth,
            self.max_nodes,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-476 scan limits are invalid")


DEFAULT_GO_CWE476_SCAN_LIMITS = GoCwe476ScanLimits()


class GoCwe476Operation(StrEnum):
    """Recognised pointer-dereference forms."""

    POINTER_MEMBER = "pointer_member"
    POINTER_INDIRECTION = "pointer_indirection"
    POINTER_INDEX = "pointer_index"


@dataclass(frozen=True, slots=True)
class GoCwe476Signal:
    """One immutable, source-free nullable-pointer dereference fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe476Operation
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
            if identity_valid and ranges_valid and type(self.operation) is GoCwe476Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not GoCwe476Operation
            or expected_id is None
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-476"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-476 signal is invalid")
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

    @property
    def dereference(self) -> SourceRange:
        """Compatibility alias for consumers naming the sink explicitly."""

        return self.sink


@dataclass(frozen=True, slots=True)
class GoCwe476ScanResult:
    """Deterministic, source-free CWE-476 output for one Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe476Signal, ...]
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
            type(item) is GoCwe476Signal for item in self.signals
        )
        ordering = (
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
            or ordering != tuple(sorted(ordering))
            or len(ordering) != len(set(ordering))
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
            raise ValueError("Go CWE-476 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Binding:
    name: str
    source: SourceRange
    nullable: bool


@dataclass(frozen=True, slots=True)
class _StateEvent:
    position: int
    source: SourceRange
    nullable: bool


def scan_go_cwe476(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe476ScanLimits = DEFAULT_GO_CWE476_SCAN_LIMITS,
) -> GoCwe476ScanResult:
    """Find locally provable dereferences of nullable Go pointers."""

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
        nodes = _bounded_preorder(root, limits)
    except GoCwe476ScanError:
        raise
    except Exception:
        raise GoCwe476ScanError(GoCwe476ScanErrorCode.INTEGRITY_FAILURE) from None

    raw: set[tuple[SourceRange, SourceRange, GoCwe476Operation]] = set()
    try:
        for scope in _scopes(root):
            bindings = _bindings(scope, source, nodes)
            if not bindings:
                continue
            events = _state_events(scope, source, bindings, nodes)
            for node in _scope_preorder(scope):
                operation = _dereference_operation(node, source)
                if operation is None:
                    continue
                name = _nullable_name(node, source)
                if name is None:
                    continue
                event = _latest_event(events.get(name, ()), node.start_byte)
                if event is None or not event.nullable:
                    continue
                if _is_non_nil_guarded(node, name, source):
                    continue
                raw.add((event.source, _range(node), operation))
                if len(raw) > limits.max_signals:
                    raise GoCwe476ScanError(GoCwe476ScanErrorCode.SIGNAL_LIMIT)
    except GoCwe476ScanError:
        raise
    except Exception:
        raise GoCwe476ScanError(GoCwe476ScanErrorCode.INTEGRITY_FAILURE) from None

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
        raise GoCwe476ScanError(GoCwe476ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe476Signal(
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
    return GoCwe476ScanResult(
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


def scan_go_cwe476_nil_pointer_dereference(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe476ScanLimits = DEFAULT_GO_CWE476_SCAN_LIMITS,
) -> GoCwe476ScanResult:
    """Descriptive alias for :func:`scan_go_cwe476`."""

    return scan_go_cwe476(symbol_index, limits=limits)


def scan_go_nil_pointer_dereference(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe476ScanLimits = DEFAULT_GO_CWE476_SCAN_LIMITS,
) -> GoCwe476ScanResult:
    """Compatibility alias for callers grouping Go nil-pointer scans."""

    return scan_go_cwe476(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe476ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe476ScanLimits:
        raise GoCwe476ScanError(GoCwe476ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe476ScanError(GoCwe476ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe476ScanError(GoCwe476ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe476ScanError(GoCwe476ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _scopes(root: Node) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node.type in _GO_SCOPES)


def _scope_preorder(scope: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    while stack:
        node = stack.pop()
        output.append(node)
        if node is not scope and node.type in _GO_SCOPES:
            continue
        stack.extend(reversed(node.named_children))
    return tuple(sorted(output, key=lambda item: (item.start_byte, item.end_byte)))


def _preorder(root: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        output.append(node)
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _bounded_preorder(root: Node, limits: GoCwe476ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_expression_depth:
            raise GoCwe476ScanError(GoCwe476ScanErrorCode.SIGNAL_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise GoCwe476ScanError(GoCwe476ScanErrorCode.SIGNAL_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _bindings(scope: Node, source: bytes, nodes: tuple[Node, ...]) -> dict[str, _Binding]:
    output: dict[str, _Binding] = {}
    for node in nodes:
        if not _within_scope(node, scope) or node is not scope:
            continue
        if node.type == "parameter_declaration":
            type_node = node.child_by_field_name("type")
            if not _is_pointer_type(type_node):
                continue
            name_node = node.child_by_field_name("name")
            names: Sequence[Node] = name_node.named_children if name_node is not None else ()
            if name_node is not None and name_node.type == "identifier":
                names = (name_node,)
            for item in names:
                if item.type == "identifier" and _text(source, item) not in {"_", ""}:
                    output.setdefault(
                        _text(source, item), _Binding(_text(source, item), _range(node), True)
                    )
        elif node.type == "var_spec":
            type_node = node.child_by_field_name("type")
            if not _is_pointer_type(type_node):
                continue
            name_node = node.child_by_field_name("name")
            names = name_node.named_children if name_node is not None else ()
            if name_node is not None and name_node.type == "identifier":
                names = (name_node,)
            value_node = node.child_by_field_name("value")
            values = value_node.named_children if value_node is not None else ()
            for position, item in enumerate(names):
                if item.type != "identifier" or _text(source, item) in {"_", ""}:
                    continue
                value = values[position] if position < len(values) else None
                output.setdefault(
                    _text(source, item),
                    _Binding(
                        _text(source, item),
                        _range(node),
                        not _proves_non_nil(value, source),
                    ),
                )
        elif node.type == "method_declaration":
            receiver = node.child_by_field_name("receiver")
            if receiver is None:
                continue
            for parameter in _descendants(receiver, "parameter_declaration"):
                type_node = parameter.child_by_field_name("type")
                if not _is_pointer_type(type_node):
                    continue
                name_node = parameter.child_by_field_name("name")
                if name_node is not None and name_node.type == "identifier":
                    name = _text(source, name_node)
                    if name not in {"", "_"}:
                        output.setdefault(name, _Binding(name, _range(parameter), True))
    return output


def _state_events(
    scope: Node,
    source: bytes,
    bindings: dict[str, _Binding],
    nodes: tuple[Node, ...],
) -> dict[str, tuple[_StateEvent, ...]]:
    events: dict[str, list[_StateEvent]] = {
        name: [_StateEvent(0, binding.source, binding.nullable)]
        for name, binding in bindings.items()
    }
    for node in nodes:
        if node.type not in {"assignment_statement", "short_var_declaration"}:
            continue
        if not _within_scope(node, scope):
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            continue
        names = left.named_children if left.type == "expression_list" else (left,)
        values = right.named_children if right.type == "expression_list" else (right,)
        for position, item in enumerate(names):
            if item.type != "identifier":
                continue
            name = _text(source, item)
            if name not in bindings:
                continue
            value = values[position] if position < len(values) else None
            events[name].append(
                _StateEvent(node.start_byte, _range(node), not _proves_non_nil(value, source))
            )
    return {
        name: tuple(sorted(values, key=lambda event: event.position))
        for name, values in events.items()
    }


def _latest_event(events: tuple[_StateEvent, ...], position: int) -> _StateEvent | None:
    selected: _StateEvent | None = None
    for event in events:
        if event.position > position:
            break
        selected = event
    return selected


def _dereference_operation(node: Node, source: bytes) -> GoCwe476Operation | None:
    if node.type == "pointer_expression":
        text = _text(source, node)
        if text.lstrip().startswith("*"):
            return GoCwe476Operation.POINTER_INDIRECTION
    if node.type == "selector_expression":
        operand = node.child_by_field_name("operand")
        if operand is not None and operand.type != "pointer_expression":
            return GoCwe476Operation.POINTER_MEMBER
    if node.type == "index_expression":
        return GoCwe476Operation.POINTER_INDEX
    return None


def _nullable_name(node: Node, source: bytes) -> str | None:
    if node.type == "pointer_expression":
        argument = node.child_by_field_name("argument")
        return _root_identifier(argument, source)
    if node.type == "selector_expression":
        operand = node.child_by_field_name("operand")
        return _root_identifier(operand, source)
    if node.type == "index_expression":
        operand = node.child_by_field_name("operand")
        return _root_identifier(operand, source)
    return None


def _root_identifier(node: Node | None, source: bytes) -> str | None:
    current = node
    while current is not None:
        if current.type == "identifier":
            return _text(source, current)
        if current.type in {"parenthesized_expression", "pointer_expression"}:
            children = current.named_children
            current = children[0] if len(children) == 1 else None
            continue
        if current.type == "selector_expression":
            current = current.child_by_field_name("operand")
            continue
        return None
    return None


def _is_non_nil_guarded(node: Node, name: str, source: bytes) -> bool:
    current: Node | None = node
    while current is not None:
        parent = current.parent
        if parent is None:
            break
        if parent.type == "if_statement":
            condition = parent.child_by_field_name("condition")
            consequence = parent.child_by_field_name("consequence")
            alternative = parent.child_by_field_name("alternative")
            if (
                consequence is not None
                and _contains(consequence, node)
                and _nil_check(condition, name, source) == "non_nil"
            ):
                return True
            if (
                alternative is not None
                and _contains(alternative, node)
                and (
                    consequence is not None
                    and _nil_check(condition, name, source) == "nil"
                    and _terminates(consequence)
                )
            ):
                return True
        current = parent

    current = node
    while current is not None:
        block = current.parent
        if block is None:
            break
        if block.type == "block":
            statements = tuple(block.named_children)
            index = next(
                (
                    position
                    for position, statement in enumerate(statements)
                    if _contains(statement, node)
                ),
                None,
            )
            if index is not None:
                for statement in statements[:index]:
                    condition = statement.child_by_field_name("condition")
                    consequence = statement.child_by_field_name("consequence")
                    if (
                        (
                            statement.type == "if_statement"
                            and _nil_check(condition, name, source) == "nil"
                        )
                        and consequence is not None
                        and _terminates(consequence)
                    ):
                        return True
        current = block
    return False


def _nil_check(condition: Node | None, name: str, source: bytes) -> str | None:
    if condition is None or condition.type != "binary_expression":
        return None
    text = "".join(_text(source, condition).split())
    escaped = re.escape(name)
    if re.fullmatch(rf"(?:{escaped}==nil|nil=={escaped})", text):
        return "nil"
    if re.fullmatch(rf"(?:{escaped}!=nil|nil!={escaped})", text):
        return "non_nil"
    return None


def _terminates(node: Node) -> bool:
    for item in node.named_children:
        if item.type in {"return_statement", "continue_statement", "break_statement"}:
            return True
        if item.type == "expression_statement":
            call = item.named_children[0] if item.named_children else None
            if call is not None and call.type == "call_expression":
                function = call.child_by_field_name("function")
                if function is not None and _terminal_name_from_node(function) in {
                    "panic",
                    "Fatal",
                    "Fatalf",
                }:
                    return True
        if item.type == "if_statement":
            consequence = item.child_by_field_name("consequence")
            alternative = item.child_by_field_name("alternative")
            if (
                consequence is not None
                and alternative is not None
                and _terminates(consequence)
                and _terminates(alternative)
            ):
                return True
    return False


def _terminal_name_from_node(node: Node) -> str:
    current = node
    while current.type == "selector_expression":
        field = current.child_by_field_name("field")
        if field is None:
            return ""
        current = field
    return (
        ""
        if current.type != "identifier"
        else (current.text or b"").decode("utf-8", errors="ignore")
    )


def _proves_non_nil(node: Node | None, source: bytes) -> bool:
    if node is None:
        return False
    if node.type in {"composite_literal", "address_expression"}:
        return True
    text = "".join(_text(source, node).split())
    return text.startswith("new(") or text.startswith("&")


def _is_pointer_type(node: Node | None) -> bool:
    return node is not None and node.type == "pointer_type"


def _within_scope(node: Node, scope: Node) -> bool:
    current: Node | None = node
    while current is not None:
        if current is scope:
            return True
        if current is not scope and current.type in _GO_SCOPES:
            return False
        current = current.parent
    return False


def _contains(container: Node, target: Node) -> bool:
    return container.start_byte <= target.start_byte and target.end_byte <= container.end_byte


def _descendants(root: Node, node_type: str) -> tuple[Node, ...]:
    return tuple(item for item in _preorder(root) if item.type == node_type)


def _text(source: bytes, node: Node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")


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
    operation: GoCwe476Operation,
) -> str:
    material = {
        "content_sha256": content_sha256,
        "cwe": "CWE-476",
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
    return "go-cwe476-" + digest


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe476Signal, ...],
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
    "DEFAULT_GO_CWE476_SCAN_LIMITS",
    "GoCwe476Operation",
    "GoCwe476ScanError",
    "GoCwe476ScanErrorCode",
    "GoCwe476ScanLimits",
    "GoCwe476ScanResult",
    "GoCwe476Signal",
    "scan_go_cwe476",
    "scan_go_cwe476_nil_pointer_dereference",
    "scan_go_nil_pointer_dereference",
]
