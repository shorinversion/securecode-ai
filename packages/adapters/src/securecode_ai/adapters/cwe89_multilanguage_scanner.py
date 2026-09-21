"""Bounded JavaScript, TypeScript, and Go CWE-89 scanner facts.

The adapter consumes a sealed CST index and never executes, imports, or reads
the analysed program.  It intentionally emits deterministic source-to-sink
facts only; normalization, interpretation, verdict, and report construction
remain owned by the existing common Core pipeline.
"""

from __future__ import annotations

from typing import Protocol

from securecode_ai.core import (
    ParseHealth,
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
from .cst_ecmascript import _javascript_language, _typescript_language
from .cst_go import _go_language
from .cwe89_multilanguage_models import (
    _GO_HTTP_QUERY,
    _GO_SQL_SINK,
    _HTTP_MEMBER,
    DEFAULT_MULTILANGUAGE_CWE89_SCAN_LIMITS,
    MultilanguageCwe89ScanError,
    MultilanguageCwe89ScanErrorCode,
    MultilanguageCwe89ScanLimits,
    MultilanguageCwe89ScanResult,
    MultilanguageCwe89Signal,
    _Flow,
)
from .cwe89_multilanguage_utilities import (
    _ECMASCRIPT_CALLABLES,
    _GO_CALLABLES,
    _compact_text,
    _lexical_scopes,
    _range,
    _scan_sha256,
    _scope_preorder,
    _text,
)


class _EcmascriptIndexBuilder(Protocol):
    def __call__(
        self,
        *,
        repository_id: str,
        revision: str,
        path: str,
        content_sha256: str,
        source: bytes,
    ) -> SymbolIndex: ...


def scan_javascript_cwe89(
    symbol_index: SymbolIndex,
    *,
    limits: MultilanguageCwe89ScanLimits = DEFAULT_MULTILANGUAGE_CWE89_SCAN_LIMITS,
) -> MultilanguageCwe89ScanResult:
    return _scan_ecmascript_cwe89(
        symbol_index,
        expected_language="javascript",
        grammar=_javascript_language(),
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
        grammar=_typescript_language(
            tsx=type(symbol_index) is SymbolIndex and symbol_index.path.endswith(".tsx")
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
        root = Parser(Language(_go_language())).parse(symbol_index.source).root_node
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
    rebuild: _EcmascriptIndexBuilder,
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
        reconstructed = rebuild(
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
