"""Bounded JavaScript and TypeScript dynamic-code execution facts.

The scanner accepts a sealed ECMAScript :class:`SymbolIndex`, rebuilds that
index through the existing CST adapter, and then inspects the same grammar
without executing repository code.  Its output contains only immutable source
ranges, rule metadata, and content-addressed identifiers.  It deliberately
recognizes a narrow set of unambiguous dynamic-execution APIs so that an
unknown alias or an unsupported runtime construct is not presented as a fact.
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
_RULE_ID = "securecode-ecmascript-cwe94"
_DETECTOR = "securecode-ecmascript-cwe94@1.0"


class EcmaScriptCwe94ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-94 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe94ScanError(RuntimeError):
    """Fixed scanner failure that never includes repository text or parser text."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe94ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe94ScanErrorCode:
            raise TypeError("ECMAScript CWE-94 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-94 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class EcmaScriptCwe94Operation(StrEnum):
    """Recognized JavaScript and TypeScript dynamic execution operations."""

    EVAL = "eval"
    FUNCTION = "Function"
    SET_TIMEOUT = "setTimeout"
    SET_INTERVAL = "setInterval"
    EXEC_SCRIPT = "execScript"
    VM_RUN_IN_THIS_CONTEXT = "vm.runInThisContext"
    VM_RUN_IN_NEW_CONTEXT = "vm.runInNewContext"
    VM_RUN_IN_CONTEXT = "vm.runInContext"
    VM_COMPILE_FUNCTION = "vm.compileFunction"
    VM_SCRIPT = "vm.Script"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe94ScanLimits:
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
            raise ValueError("ECMAScript CWE-94 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE94_SCAN_LIMITS = EcmaScriptCwe94ScanLimits()


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe94Signal:
    """One bounded input-to-dynamic-execution fact.

    ``source`` points at the expression supplied as executable code and
    ``sink`` points at the complete call or constructor expression.  Neither
    range contains source text in the returned object.
    """

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe94Operation
    signal_id: str
    rule_id: str = _RULE_ID
    cwe: str = "CWE-94"
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
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not EcmaScriptCwe94Operation
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
            or self.cwe != "CWE-94"
            or self.detector != _DETECTOR
        ):
            raise ValueError("ECMAScript CWE-94 signal is invalid")

    @property
    def deterministic_id(self) -> str:
        """Compatibility name for callers that do not use ``signal_id``."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the sink location used by generic scanner consumers."""

        return self.sink


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe94ScanResult:
    """Source-free, deterministic result for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe94Signal, ...]
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
            not valid_identity
            or type(self.signals) is not tuple
            or any(type(item) is not EcmaScriptCwe94Signal for item in self.signals)
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
            raise ValueError("ECMAScript CWE-94 scan result is invalid")


def scan_javascript_cwe94(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe94ScanLimits = DEFAULT_ECMASCRIPT_CWE94_SCAN_LIMITS,
) -> EcmaScriptCwe94ScanResult:
    """Find bounded JavaScript dynamic-code execution facts."""

    return _scan_ecmascript_cwe94(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe94(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe94ScanLimits = DEFAULT_ECMASCRIPT_CWE94_SCAN_LIMITS,
) -> EcmaScriptCwe94ScanResult:
    """Find bounded TypeScript dynamic-code execution facts."""

    return _scan_ecmascript_cwe94(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe94(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe94ScanLimits = DEFAULT_ECMASCRIPT_CWE94_SCAN_LIMITS,
) -> EcmaScriptCwe94ScanResult:
    """Dispatch a CWE-94 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe94(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe94(symbol_index, limits=limits)
    raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe94(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe94ScanLimits,
) -> EcmaScriptCwe94ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe94ScanLimits:
        raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.ANALYSIS_UNAVAILABLE)

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
        raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.INTEGRITY_FAILURE) from None

    nodes = _bounded_nodes(root, limits)
    if any(node.type == "ERROR" or node.is_missing for node in nodes):
        raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.ANALYSIS_UNAVAILABLE)

    aliases = _collect_aliases(nodes, source)
    raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe94Operation]] = set()
    for node in nodes:
        if node.type == "call_expression":
            raw.update(_call_facts(node, source, aliases))
        elif node.type == "new_expression":
            fact = _new_fact(node, source, aliases)
            if fact is not None:
                raw.add(fact)
        if len(raw) > limits.max_signals:
            raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.SIGNAL_LIMIT)

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
        raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        EcmaScriptCwe94Signal(
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
    return EcmaScriptCwe94ScanResult(
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


def _bounded_nodes(root: Node, limits: EcmaScriptCwe94ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _call_facts(
    node: Node, source: bytes, aliases: dict[str, str]
) -> set[tuple[SourceRange, SourceRange, EcmaScriptCwe94Operation]]:
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None:
        return set()
    operation = _operation_for_callee(_compact_text(source, function), aliases)
    if operation is None:
        return set()
    values = list(arguments.named_children)
    if (
        operation
        in {
            EcmaScriptCwe94Operation.SET_TIMEOUT,
            EcmaScriptCwe94Operation.SET_INTERVAL,
        }
        and values
        and _is_callable_expression(values[0])
    ):
        return set()
    source_node = _input_node(values, operation)
    sink_range = _range(node)
    source_range = _range(source_node) if source_node is not None else sink_range
    if not sink_range.contains(source_range):
        raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.INTEGRITY_FAILURE)
    return {(source_range, sink_range, operation)}


def _new_fact(
    node: Node, source: bytes, aliases: dict[str, str]
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe94Operation] | None:
    constructor = node.child_by_field_name("constructor")
    arguments = node.child_by_field_name("arguments")
    if constructor is None:
        return None
    operation = _operation_for_callee(_compact_text(source, constructor), aliases)
    if operation not in {
        EcmaScriptCwe94Operation.FUNCTION,
        EcmaScriptCwe94Operation.VM_SCRIPT,
    }:
        return None
    values = list(arguments.named_children) if arguments is not None else []
    source_node = _input_node(values, operation)
    sink_range = _range(node)
    source_range = _range(source_node) if source_node is not None else sink_range
    if not sink_range.contains(source_range):
        raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.INTEGRITY_FAILURE)
    return source_range, sink_range, operation


def _operation_for_callee(callee: str, aliases: dict[str, str]) -> EcmaScriptCwe94Operation | None:
    canonical = _canonical_name(callee, aliases)
    return {
        "eval": EcmaScriptCwe94Operation.EVAL,
        "globalThis.eval": EcmaScriptCwe94Operation.EVAL,
        "window.eval": EcmaScriptCwe94Operation.EVAL,
        "Function": EcmaScriptCwe94Operation.FUNCTION,
        "globalThis.Function": EcmaScriptCwe94Operation.FUNCTION,
        "window.Function": EcmaScriptCwe94Operation.FUNCTION,
        "setTimeout": EcmaScriptCwe94Operation.SET_TIMEOUT,
        "window.setTimeout": EcmaScriptCwe94Operation.SET_TIMEOUT,
        "globalThis.setTimeout": EcmaScriptCwe94Operation.SET_TIMEOUT,
        "setInterval": EcmaScriptCwe94Operation.SET_INTERVAL,
        "window.setInterval": EcmaScriptCwe94Operation.SET_INTERVAL,
        "globalThis.setInterval": EcmaScriptCwe94Operation.SET_INTERVAL,
        "execScript": EcmaScriptCwe94Operation.EXEC_SCRIPT,
        "window.execScript": EcmaScriptCwe94Operation.EXEC_SCRIPT,
        "vm.runInThisContext": EcmaScriptCwe94Operation.VM_RUN_IN_THIS_CONTEXT,
        "vm.runInNewContext": EcmaScriptCwe94Operation.VM_RUN_IN_NEW_CONTEXT,
        "vm.runInContext": EcmaScriptCwe94Operation.VM_RUN_IN_CONTEXT,
        "vm.compileFunction": EcmaScriptCwe94Operation.VM_COMPILE_FUNCTION,
        "vm.Script": EcmaScriptCwe94Operation.VM_SCRIPT,
    }.get(canonical)


def _input_node(values: list[Node], operation: EcmaScriptCwe94Operation) -> Node | None:
    if not values:
        return None
    if operation is EcmaScriptCwe94Operation.FUNCTION:
        return values[-1]
    return values[0]


def _is_callable_expression(node: Node) -> bool:
    return node.type in {
        "arrow_function",
        "function",
        "function_expression",
        "generator_function",
        "class",
    }


def _collect_aliases(nodes: tuple[Node, ...], source: bytes) -> dict[str, str]:
    """Collect only direct, local module and callable aliases from the CST."""

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
                    aliases[_node_text(source, name)] = canonical
                elif name.type in {"object_pattern", "object"} and canonical is not None:
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
        if child.type not in {
            "pair",
            "object_pattern_property",
            "shorthand_property_identifier_pattern",
        }:
            continue
        key = child.child_by_field_name("key")
        value = child.child_by_field_name("value")
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
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if (
            function is None
            or arguments is None
            or _compact_text(source, function) != "require"
            or len(arguments.named_children) != 1
        ):
            return None
        module = _string_value(arguments.named_children[0], source)
        return _normalise_module(module) if module is not None else None
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
        raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.INTEGRITY_FAILURE) from None


def _node_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe94ScanError(EcmaScriptCwe94ScanErrorCode.INTEGRITY_FAILURE) from None


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
    operation: EcmaScriptCwe94Operation,
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
    signals: tuple[EcmaScriptCwe94Signal, ...],
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


# Naming aliases keep the scanner discoverable to language-neutral callers.
scan_javascript_dynamic_code = scan_javascript_cwe94
scan_typescript_dynamic_code = scan_typescript_cwe94
scan_ecmascript_dynamic_code = scan_ecmascript_cwe94


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE94_SCAN_LIMITS",
    "EcmaScriptCwe94Operation",
    "EcmaScriptCwe94ScanError",
    "EcmaScriptCwe94ScanErrorCode",
    "EcmaScriptCwe94ScanLimits",
    "EcmaScriptCwe94ScanResult",
    "EcmaScriptCwe94Signal",
    "scan_ecmascript_cwe94",
    "scan_ecmascript_dynamic_code",
    "scan_javascript_cwe94",
    "scan_javascript_dynamic_code",
    "scan_typescript_cwe94",
    "scan_typescript_dynamic_code",
]
