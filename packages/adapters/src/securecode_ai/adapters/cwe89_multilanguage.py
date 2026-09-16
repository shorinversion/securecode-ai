"""Bounded JavaScript, TypeScript, and Go CWE-89 scanner facts.

The adapter consumes a sealed CST index and never executes, imports, or reads
the analysed program.  It intentionally emits deterministic source-to-sink
facts only; normalization, interpretation, verdict, and report construction
remain owned by the existing common Core pipeline.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

import tree_sitter_go
import tree_sitter_javascript
import tree_sitter_typescript
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

from .cst import (
    CstAdapterError,
    build_go_symbol_index,
    build_javascript_symbol_index,
    build_typescript_symbol_index,
)

_MAX_LIMITS = (2_000_000, 10_000, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HTTP_MEMBER = re.compile(r"(?:request|req)\.(?:query|params)\.[A-Za-z_$][A-Za-z0-9_$]*\Z")
_GO_HTTP_QUERY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\.URL\.Query\(\)\.Get\([^()]*\)\Z")
_GO_SQL_SINK = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\.(?:Query|Exec|Raw)\Z")


class MultilanguageCwe89ScanErrorCode(StrEnum):
    """Closed reasons a supported-language semantic fact cannot be emitted."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class MultilanguageCwe89ScanError(RuntimeError):
    """Fixed, source-free semantic analysis failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: MultilanguageCwe89ScanErrorCode) -> None:
        if type(code) is not MultilanguageCwe89ScanErrorCode:
            raise TypeError("multilanguage CWE-89 scan error code is invalid")
        self.code = code
        self.safe_message = "CWE-89 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class MultilanguageCwe89ScanLimits:
    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("multilanguage CWE-89 scan limits are invalid")


DEFAULT_MULTILANGUAGE_CWE89_SCAN_LIMITS = MultilanguageCwe89ScanLimits()


@dataclass(frozen=True, slots=True)
class MultilanguageCwe89Signal:
    """One supported-language HTTP-to-interpolation-to-SQL fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    source: SourceRange
    interpolation: SourceRange
    sink: SourceRange
    detector: str
    cwe: str = "CWE-89"

    def __post_init__(self) -> None:
        expected_detector = {
            "javascript": "securecode-javascript-cwe89@1.0",
            "typescript": "securecode-typescript-cwe89@1.0",
            "go": "securecode-go-cwe89@1.0",
        }.get(self.language)
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
        locations = (self.source, self.interpolation, self.sink)
        if (
            not identity_valid
            or expected_detector is None
            or self.detector != expected_detector
            or self.cwe != "CWE-89"
            or any(type(location) is not SourceRange for location in locations)
            or any(location.end_byte > self.source_size_bytes for location in locations)
            or self.source.end_byte > self.interpolation.end_byte
            or self.interpolation.end_byte > self.sink.end_byte
        ):
            raise ValueError("multilanguage CWE-89 signal is invalid")


@dataclass(frozen=True, slots=True)
class MultilanguageCwe89ScanResult:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[MultilanguageCwe89Signal, ...]
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
            and self.language in {"javascript", "typescript", "go"}
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
                item.interpolation.start_byte,
                item.source.start_byte,
            )
            for item in self.signals
        )
        same_identity = all(
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
            or type(self.signals) is not tuple
            or any(type(item) is not MultilanguageCwe89Signal for item in self.signals)
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
            or not same_identity
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
            raise ValueError("multilanguage CWE-89 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange
    interpolation: SourceRange | None


def scan_javascript_cwe89(
    symbol_index: SymbolIndex,
    *,
    limits: MultilanguageCwe89ScanLimits = DEFAULT_MULTILANGUAGE_CWE89_SCAN_LIMITS,
) -> MultilanguageCwe89ScanResult:
    return _scan_ecmascript_cwe89(
        symbol_index,
        expected_language="javascript",
        grammar=tree_sitter_javascript.language(),
        rebuild=build_javascript_symbol_index,
        limits=limits,
    )


def scan_typescript_cwe89(
    symbol_index: SymbolIndex,
    *,
    limits: MultilanguageCwe89ScanLimits = DEFAULT_MULTILANGUAGE_CWE89_SCAN_LIMITS,
) -> MultilanguageCwe89ScanResult:
    return _scan_ecmascript_cwe89(
        symbol_index,
        expected_language="typescript",
        grammar=(
            tree_sitter_typescript.language_tsx()
            if type(symbol_index) is SymbolIndex and symbol_index.path.endswith(".tsx")
            else tree_sitter_typescript.language_typescript()
        ),
        rebuild=build_typescript_symbol_index,
        limits=limits,
    )


def scan_go_cwe89(
    symbol_index: SymbolIndex,
    *,
    limits: MultilanguageCwe89ScanLimits = DEFAULT_MULTILANGUAGE_CWE89_SCAN_LIMITS,
) -> MultilanguageCwe89ScanResult:
    """Emit bounded Go HTTP-query-to-SQL-interpolation facts."""

    if type(symbol_index) is not SymbolIndex or type(limits) is not MultilanguageCwe89ScanLimits:
        raise MultilanguageCwe89ScanError(MultilanguageCwe89ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise MultilanguageCwe89ScanError(MultilanguageCwe89ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise MultilanguageCwe89ScanError(MultilanguageCwe89ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise MultilanguageCwe89ScanError(MultilanguageCwe89ScanErrorCode.ANALYSIS_UNAVAILABLE)
    try:
        reconstructed = build_go_symbol_index(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source=symbol_index.source,
        )
    except (CstAdapterError, TypeError, ValueError):
        raise MultilanguageCwe89ScanError(
            MultilanguageCwe89ScanErrorCode.INTEGRITY_FAILURE
        ) from None
    if reconstructed != symbol_index:
        raise MultilanguageCwe89ScanError(MultilanguageCwe89ScanErrorCode.INTEGRITY_FAILURE)
    try:
        root = Parser(Language(tree_sitter_go.language())).parse(symbol_index.source).root_node
    except Exception:
        raise MultilanguageCwe89ScanError(
            MultilanguageCwe89ScanErrorCode.INTEGRITY_FAILURE
        ) from None

    raw: list[tuple[SourceRange, SourceRange, SourceRange]] = []
    for scope in _lexical_scopes(root, _GO_CALLABLES):
        environment: dict[str, tuple[_Flow, ...]] = {}
        for node in _scope_preorder(scope, _GO_CALLABLES):
            if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                _capture_go_assignment(node, environment, symbol_index.source, limits)
            if node.type == "call_expression" and _is_go_sql_sink(node, symbol_index.source):
                arguments = node.child_by_field_name("arguments")
                if arguments is None or not arguments.named_children:
                    continue
                sink = _range(node)
                for flow in _resolve_go(
                    arguments.named_children[0], environment, symbol_index.source, limits, 0
                ):
                    if flow.interpolation is not None:
                        raw.append((flow.source, flow.interpolation, sink))
                        if len(raw) > limits.max_signals:
                            raise MultilanguageCwe89ScanError(
                                MultilanguageCwe89ScanErrorCode.SIGNAL_LIMIT
                            )
    unique = sorted(
        set(raw),
        key=lambda item: (
            item[2].start_byte,
            item[2].end_byte,
            item[1].start_byte,
            item[0].start_byte,
        ),
    )
    if len(unique) > limits.max_signals:
        raise MultilanguageCwe89ScanError(MultilanguageCwe89ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        MultilanguageCwe89Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            language="go",
            source=item[0],
            interpolation=item[1],
            sink=item[2],
            detector="securecode-go-cwe89@1.0",
        )
        for item in unique
    )
    return MultilanguageCwe89ScanResult(
        repository_id=symbol_index.repository_id,
        revision=symbol_index.revision,
        path=symbol_index.path,
        content_sha256=symbol_index.content_sha256,
        source_size_bytes=symbol_index.source_byte_length,
        language="go",
        signals=signals,
        scan_sha256=_scan_sha256(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            "go",
            signals,
        ),
    )


def _scan_ecmascript_cwe89(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    grammar: object,
    rebuild: object,
    limits: MultilanguageCwe89ScanLimits,
) -> MultilanguageCwe89ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not MultilanguageCwe89ScanLimits:
        raise MultilanguageCwe89ScanError(MultilanguageCwe89ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise MultilanguageCwe89ScanError(MultilanguageCwe89ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise MultilanguageCwe89ScanError(MultilanguageCwe89ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise MultilanguageCwe89ScanError(MultilanguageCwe89ScanErrorCode.ANALYSIS_UNAVAILABLE)
    try:
        reconstructed = rebuild(  # type: ignore[operator]
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source=symbol_index.source,
        )
    except (CstAdapterError, TypeError, ValueError):
        raise MultilanguageCwe89ScanError(
            MultilanguageCwe89ScanErrorCode.INTEGRITY_FAILURE
        ) from None
    if reconstructed != symbol_index:
        raise MultilanguageCwe89ScanError(MultilanguageCwe89ScanErrorCode.INTEGRITY_FAILURE)
    try:
        root = Parser(Language(grammar)).parse(symbol_index.source).root_node
    except Exception:
        raise MultilanguageCwe89ScanError(
            MultilanguageCwe89ScanErrorCode.INTEGRITY_FAILURE
        ) from None

    raw: list[tuple[SourceRange, SourceRange, SourceRange]] = []
    for scope in _lexical_scopes(root, _ECMASCRIPT_CALLABLES):
        environment: dict[str, tuple[_Flow, ...]] = {}
        for node in _scope_preorder(scope, _ECMASCRIPT_CALLABLES):
            if node.type in {"variable_declarator", "assignment_expression"}:
                _capture_assignment(node, environment, symbol_index.source, limits)
            if node.type == "call_expression" and _is_sql_sink(node, symbol_index.source):
                arguments = node.child_by_field_name("arguments")
                if arguments is None or not arguments.named_children:
                    continue
                sink = _range(node)
                for flow in _resolve(
                    arguments.named_children[0], environment, symbol_index.source, limits, 0
                ):
                    if flow.interpolation is not None:
                        raw.append((flow.source, flow.interpolation, sink))
                        if len(raw) > limits.max_signals:
                            raise MultilanguageCwe89ScanError(
                                MultilanguageCwe89ScanErrorCode.SIGNAL_LIMIT
                            )
    unique = sorted(
        set(raw),
        key=lambda item: (
            item[2].start_byte,
            item[2].end_byte,
            item[1].start_byte,
            item[0].start_byte,
        ),
    )
    if len(unique) > limits.max_signals:
        raise MultilanguageCwe89ScanError(MultilanguageCwe89ScanErrorCode.SIGNAL_LIMIT)
    index = symbol_index
    detector = f"securecode-{expected_language}-cwe89@1.0"
    signals = tuple(
        MultilanguageCwe89Signal(
            repository_id=index.repository_id,
            revision=index.revision,
            path=index.path,
            content_sha256=index.content_sha256,
            source_size_bytes=index.source_byte_length,
            language=expected_language,
            source=item[0],
            interpolation=item[1],
            sink=item[2],
            detector=detector,
        )
        for item in unique
    )
    return MultilanguageCwe89ScanResult(
        repository_id=index.repository_id,
        revision=index.revision,
        path=index.path,
        content_sha256=index.content_sha256,
        source_size_bytes=index.source_byte_length,
        language=expected_language,
        signals=signals,
        scan_sha256=_scan_sha256(
            index.repository_id,
            index.revision,
            index.path,
            index.content_sha256,
            index.source_byte_length,
            expected_language,
            signals,
        ),
    )


def _capture_assignment(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    limits: MultilanguageCwe89ScanLimits,
) -> None:
    name_node = node.child_by_field_name("name") or node.child_by_field_name("left")
    value_node = node.child_by_field_name("value") or node.child_by_field_name("right")
    if name_node is None or value_node is None or name_node.type != "identifier":
        return
    name = _text(source, name_node)
    environment[name] = _resolve(value_node, environment, source, limits, 0)


def _capture_go_assignment(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    limits: MultilanguageCwe89ScanLimits,
) -> None:
    groups = node.named_children
    if len(groups) < 2:
        return
    names = groups[0].named_children if groups[0].type == "expression_list" else groups[:1]
    values = groups[-1].named_children if groups[-1].type == "expression_list" else groups[-1:]
    for name_node, value_node in zip(names, values, strict=False):
        if name_node.type == "identifier":
            environment[_text(source, name_node)] = _resolve_go(
                value_node, environment, source, limits, 0
            )


def _resolve_go(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    limits: MultilanguageCwe89ScanLimits,
    depth: int,
) -> tuple[_Flow, ...]:
    if depth > limits.max_expression_depth:
        raise MultilanguageCwe89ScanError(MultilanguageCwe89ScanErrorCode.SIGNAL_LIMIT)
    if node.type == "identifier":
        return environment.get(_text(source, node), ())
    if node.type == "call_expression" and _GO_HTTP_QUERY.fullmatch(_compact_text(source, node)):
        return (_Flow(_range(node), None),)
    if node.type == "call_expression" and _compact_text(source, node).startswith("fmt.Sprintf("):
        arguments = node.child_by_field_name("arguments")
        if arguments is not None:
            flows = tuple(
                flow
                for argument in arguments.named_children[1:]
                for flow in _resolve_go(argument, environment, source, limits, depth + 1)
            )
            return _with_interpolation(flows, _range(node))
    if node.type == "binary_expression" and "+" in _text(source, node):
        children = node.named_children
        if len(children) == 2:
            return _with_interpolation(
                _resolve_go(children[0], environment, source, limits, depth + 1)
                + _resolve_go(children[1], environment, source, limits, depth + 1),
                _range(node),
            )
    if node.type == "parenthesized_expression" and node.named_children:
        return _resolve_go(node.named_children[0], environment, source, limits, depth + 1)
    return ()


def _resolve(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    limits: MultilanguageCwe89ScanLimits,
    depth: int,
) -> tuple[_Flow, ...]:
    if depth > limits.max_expression_depth:
        raise MultilanguageCwe89ScanError(MultilanguageCwe89ScanErrorCode.SIGNAL_LIMIT)
    if node.type == "identifier":
        return environment.get(_text(source, node), ())
    if node.type in {"member_expression", "subscript_expression"} and _HTTP_MEMBER.fullmatch(
        _compact_text(source, node)
    ):
        return (_Flow(_range(node), None),)
    if node.type == "template_string":
        flows = tuple(
            flow
            for child in node.named_children
            if child.type == "template_substitution"
            for expression in child.named_children[:1]
            for flow in _resolve(expression, environment, source, limits, depth + 1)
        )
        return _with_interpolation(flows, _range(node))
    if node.type == "binary_expression" and "+" in _text(source, node):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None and right is not None:
            return _with_interpolation(
                _resolve(left, environment, source, limits, depth + 1)
                + _resolve(right, environment, source, limits, depth + 1),
                _range(node),
            )
    if node.type == "parenthesized_expression" and node.named_children:
        return _resolve(node.named_children[0], environment, source, limits, depth + 1)
    return ()


def _with_interpolation(flows: tuple[_Flow, ...], location: SourceRange) -> tuple[_Flow, ...]:
    return tuple(_Flow(flow.source, location) for flow in flows)


def _is_sql_sink(node: Node, source: bytes) -> bool:
    function = node.child_by_field_name("function")
    if function is None:
        return False
    compact = _compact_text(source, function)
    return compact.endswith((".execute", ".query", ".raw"))


def _is_go_sql_sink(node: Node, source: bytes) -> bool:
    function = node.child_by_field_name("function")
    return (
        function is not None and _GO_SQL_SINK.fullmatch(_compact_text(source, function)) is not None
    )


def _preorder(root: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        output.append(node)
        stack.extend(reversed(node.named_children))
    return tuple(output)


_ECMASCRIPT_CALLABLES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "function",
        "arrow_function",
        "method_definition",
        "generator_function",
        "generator_function_declaration",
    }
)
_GO_CALLABLES = frozenset({"function_declaration", "method_declaration", "func_literal"})


def _lexical_scopes(root: Node, callable_types: frozenset[str]) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node is root or node.type in callable_types)


def _scope_preorder(scope: Node, callable_types: frozenset[str]) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    while stack:
        node = stack.pop()
        output.append(node)
        if node is not scope and node.type in callable_types:
            continue
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _range(node: Node) -> SourceRange:
    return SourceRange(
        node.start_byte,
        node.end_byte,
        SourcePoint(node.start_point.row, node.start_point.column),
        SourcePoint(node.end_point.row, node.end_point.column),
    )


def _text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise MultilanguageCwe89ScanError(
            MultilanguageCwe89ScanErrorCode.INTEGRITY_FAILURE
        ) from None


def _compact_text(source: bytes, node: Node) -> str:
    return "".join(_text(source, node).split())


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    language: str,
    signals: tuple[MultilanguageCwe89Signal, ...],
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
                "interpolation": _range_value(signal.interpolation),
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


def _range_value(location: SourceRange) -> dict[str, int]:
    return {
        "end_byte": location.end_byte,
        "end_column": location.end_point.column,
        "end_row": location.end_point.row,
        "start_byte": location.start_byte,
        "start_column": location.start_point.column,
        "start_row": location.start_point.row,
    }


def multilanguage_cwe89_signals_to_raw_signals(
    symbol_index: SymbolIndex,
    result: MultilanguageCwe89ScanResult,
    *,
    tenant_id: str,
    producer: ProducerRef,
) -> tuple[RawSignal, ...]:
    """Revalidate scanner facts and bind them to common source-free ingress.

    The caller supplies its trusted deployment artifact digest in ``producer``;
    this adapter checks the scanner name/version, but does not authenticate a
    deployment. Repository identity is covered by the scan and signal digests.
    No source, verdict, or confidence is put in the wire payload.
    """
    if (
        type(symbol_index) is not SymbolIndex
        or type(result) is not MultilanguageCwe89ScanResult
        or type(tenant_id) is not str
        or not tenant_id
        or type(producer) is not ProducerRef
        or type(result.signals) is not tuple
        or len(result.signals) > DEFAULT_MULTILANGUAGE_CWE89_SCAN_LIMITS.max_signals
    ):
        raise MultilanguageCwe89ScanError(MultilanguageCwe89ScanErrorCode.REQUEST_INVALID)
    try:
        validated_producer = ProducerRef.model_validate(producer.model_dump(mode="python"))
        if (
            validated_producer.producer_id != f"securecode-{symbol_index.language}-cwe89"
            or validated_producer.producer_version != "1.0.0"
        ):
            raise ValueError("producer mismatch")
        scanner = {
            "javascript": scan_javascript_cwe89,
            "typescript": scan_typescript_cwe89,
            "go": scan_go_cwe89,
        }.get(symbol_index.language)
        if scanner is None or scanner(symbol_index) != result:
            raise ValueError("scanner facts mismatch")
        # Validate tenant even on the zero-signal path, without generating a fact.
        RepositoryFile(result.path, result.source_size_bytes, result.content_sha256)
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", tenant_id) is None:
            raise ValueError("tenant invalid")
        output: list[RawSignal] = []
        for ordinal, signal in enumerate(result.signals):
            binding = {
                "scan_sha256": result.scan_sha256,
                "ordinal": ordinal,
                "tenant_id": tenant_id,
                "producer": validated_producer.model_dump(mode="json"),
                "rule_id": "cwe-89-sql-interpolation",
            }
            digest = hashlib.sha256(
                json.dumps(binding, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            output.append(
                RawSignal(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    raw_signal_id=f"cwe89-{signal.language}-{digest}",
                    tenant_id=tenant_id,
                    head_sha=signal.revision,
                    producer=validated_producer,
                    rule_id="cwe-89-sql-interpolation",
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
    except (ValueError, TypeError, AttributeError):
        raise MultilanguageCwe89ScanError(
            MultilanguageCwe89ScanErrorCode.INTEGRITY_FAILURE
        ) from None


__all__ = [
    "DEFAULT_MULTILANGUAGE_CWE89_SCAN_LIMITS",
    "MultilanguageCwe89ScanError",
    "MultilanguageCwe89ScanErrorCode",
    "MultilanguageCwe89ScanLimits",
    "MultilanguageCwe89ScanResult",
    "MultilanguageCwe89Signal",
    "multilanguage_cwe89_signals_to_raw_signals",
    "scan_go_cwe89",
    "scan_javascript_cwe89",
    "scan_typescript_cwe89",
]
