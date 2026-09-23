"""Bounded, source-only Python CWE-89 evidence extraction.

This adapter produces deterministic scanner facts, not findings or verdicts. It
never executes the admitted program and only accepts a sealed P2.3 symbol index
and a sealed P2.4 AST analysis for the same exact source revision.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from securecode_ai.adapters.cwe89_contracts import (
    DEFAULT_CWE89_SCAN_LIMITS,
    Cwe89EvidenceKind,
    Cwe89ScanError,
    Cwe89ScanErrorCode,
    Cwe89ScanLimits,
    Cwe89ScanResult,
    Cwe89Signal,
    _scan_sha256,
)
from securecode_ai.adapters.python_ast import (
    PythonAstAnalysis,
    PythonAstError,
    PythonAstStatus,
    analyze_python_ast,
    open_python_ast,
)
from securecode_ai.core import SourcePoint, SourceRange, SymbolIndex


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange
    interpolation: SourceRange | None


def scan_python_cwe89(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: Cwe89ScanLimits = DEFAULT_CWE89_SCAN_LIMITS,
) -> Cwe89ScanResult:
    """Extract bounded Python HTTP-to-interpolation-to-``execute`` evidence.

    The function does not expose a filesystem, shell, network, command, or code
    execution input.  Parser errors and unsealed/mismatched inputs fail closed
    instead of being represented as a clean scan.
    """

    if (
        type(symbol_index) is not SymbolIndex
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not Cwe89ScanLimits
    ):
        raise Cwe89ScanError(Cwe89ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise Cwe89ScanError(Cwe89ScanErrorCode.SOURCE_LIMIT)

    integrity_failed = False
    try:
        validated_analysis = analyze_python_ast(symbol_index)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        integrity_failed = True
        validated_analysis = None
    if integrity_failed or validated_analysis is None:
        raise Cwe89ScanError(Cwe89ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated_analysis.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise Cwe89ScanError(Cwe89ScanErrorCode.ANALYSIS_UNAVAILABLE)
    try:
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        integrity_failed = True
        tree = None
    if integrity_failed or tree is None:
        raise Cwe89ScanError(Cwe89ScanErrorCode.INTEGRITY_FAILURE) from None
    if ast_analysis.symbol_index_sha256 != validated_analysis.symbol_index_sha256:
        raise Cwe89ScanError(Cwe89ScanErrorCode.ANALYSIS_UNAVAILABLE)

    index = symbol_index
    source = index.source
    line_starts = _line_starts(source)
    functions = _top_level_functions(tree)
    raw: list[tuple[SourceRange, SourceRange, SourceRange]] = []
    _scan_scope(tree.body, {}, {}, functions, source, line_starts, limits, raw)
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
        raise Cwe89ScanError(Cwe89ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        Cwe89Signal(
            repository_id=index.repository_id,
            revision=index.revision,
            path=index.path,
            content_sha256=index.content_sha256,
            source_size_bytes=index.source_byte_length,
            source=item[0],
            interpolation=item[1],
            sink=item[2],
        )
        for item in unique
    )
    return Cwe89ScanResult(
        repository_id=index.repository_id,
        revision=index.revision,
        path=index.path,
        content_sha256=index.content_sha256,
        source_size_bytes=index.source_byte_length,
        signals=signals,
        scan_sha256=_scan_sha256(
            index.repository_id,
            index.revision,
            index.path,
            index.content_sha256,
            index.source_byte_length,
            signals,
        ),
    )


def _scan_scope(
    statements: list[ast.stmt],
    environment: dict[str, tuple[_Flow, ...]],
    object_fields: dict[tuple[str, str, str], tuple[_Flow, ...]],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: Cwe89ScanLimits,
    output: list[tuple[SourceRange, SourceRange, SourceRange]],
) -> None:
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _scan_scope(statement.body, {}, {}, functions, source, line_starts, limits, output)
            continue
        _record_object_field_write(
            statement, environment, object_fields, functions, source, line_starts, limits
        )
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            value = statement.value
            if value is not None:
                flows = _resolve(
                    value, environment, object_fields, functions, source, line_starts, limits, 0
                )
                for target in _assignment_names(statement):
                    environment[target] = flows
        for node in _statement_nodes(statement):
            if isinstance(node, ast.Call) and _is_execute_call(node):
                if not node.args:
                    continue
                sink = _node_range(node, source, line_starts)
                for flow in _resolve(
                    node.args[0],
                    environment,
                    object_fields,
                    functions,
                    source,
                    line_starts,
                    limits,
                    0,
                ):
                    if flow.interpolation is not None:
                        output.append((flow.source, flow.interpolation, sink))
                        if len(output) > limits.max_signals:
                            raise Cwe89ScanError(Cwe89ScanErrorCode.SIGNAL_LIMIT)
        if isinstance(statement, ast.If):
            body_environment = dict(environment)
            body_fields = dict(object_fields)
            _scan_scope(
                statement.body,
                body_environment,
                body_fields,
                functions,
                source,
                line_starts,
                limits,
                output,
            )
            else_environment = dict(environment)
            else_fields = dict(object_fields)
            _scan_scope(
                statement.orelse,
                else_environment,
                else_fields,
                functions,
                source,
                line_starts,
                limits,
                output,
            )
            _merge_flows(environment, body_environment, else_environment)
            _merge_flows(object_fields, body_fields, else_fields)
        elif isinstance(
            statement, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try)
        ):
            for child in _nested_statement_lists(statement):
                _scan_scope(
                    child,
                    dict(environment),
                    dict(object_fields),
                    functions,
                    source,
                    line_starts,
                    limits,
                    output,
                )


def _resolve(
    expression: ast.expr,
    environment: dict[str, tuple[_Flow, ...]],
    object_fields: dict[tuple[str, str, str], tuple[_Flow, ...]],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: Cwe89ScanLimits,
    depth: int,
) -> tuple[_Flow, ...]:
    if depth > limits.max_call_depth:
        raise Cwe89ScanError(Cwe89ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(expression, ast.Name):
        return environment.get(expression.id, ())
    if _is_http_get(expression) or _is_known_request_wrapper_source(expression):
        return (_Flow(_node_range(expression, source, line_starts), None),)
    field_key = _object_field_read_key(expression)
    if field_key is not None:
        return object_fields.get(field_key, ())
    if isinstance(expression, ast.JoinedStr):
        location = _node_range(expression, source, line_starts)
        return _with_interpolation(
            tuple(
                flow
                for value in expression.values
                if isinstance(value, ast.FormattedValue)
                for flow in _resolve(
                    value.value,
                    environment,
                    object_fields,
                    functions,
                    source,
                    line_starts,
                    limits,
                    depth,
                )
            ),
            location,
        )
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add):
        location = _node_range(expression, source, line_starts)
        return _with_interpolation(
            _resolve(
                expression.left,
                environment,
                object_fields,
                functions,
                source,
                line_starts,
                limits,
                depth,
            )
            + _resolve(
                expression.right,
                environment,
                object_fields,
                functions,
                source,
                line_starts,
                limits,
                depth,
            ),
            location,
        )
    if isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name):
        function = functions.get(expression.func.id)
        if function is not None:
            return _resolve_function_call(
                function,
                expression.args,
                environment,
                object_fields,
                functions,
                source,
                line_starts,
                limits,
                depth + 1,
            )
    if _is_known_passthrough_call(expression):
        assert isinstance(expression, ast.Call)
        assert isinstance(expression.func, ast.Attribute)
        operand = (
            expression.func.value
            if expression.func.attr in {"encode", "decode"}
            else expression.args[0]
        )
        return _resolve(
            operand, environment, object_fields, functions, source, line_starts, limits, depth
        )
    return ()


def _resolve_function_call(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    arguments: list[ast.expr],
    environment: dict[str, tuple[_Flow, ...]],
    object_fields: dict[tuple[str, str, str], tuple[_Flow, ...]],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: Cwe89ScanLimits,
    depth: int,
) -> tuple[_Flow, ...]:
    parameters = tuple(argument.arg for argument in function.args.posonlyargs + function.args.args)
    if (
        len(arguments) != len(parameters)
        or function.args.vararg is not None
        or function.args.kwarg is not None
    ):
        return ()
    bound = {
        parameter: _resolve(
            argument, environment, object_fields, functions, source, line_starts, limits, depth
        )
        for parameter, argument in zip(parameters, arguments, strict=True)
    }
    returned: tuple[_Flow, ...] = ()
    for statement in function.body:
        if isinstance(statement, ast.Return) and statement.value is not None:
            returned += _resolve(
                statement.value, bound, {}, functions, source, line_starts, limits, depth
            )
    return returned


def _with_interpolation(flows: tuple[_Flow, ...], location: SourceRange) -> tuple[_Flow, ...]:
    return tuple(_Flow(flow.source, location) for flow in flows)


def _merge_flows[FlowKey](
    target: dict[FlowKey, tuple[_Flow, ...]],
    left: dict[FlowKey, tuple[_Flow, ...]],
    right: dict[FlowKey, tuple[_Flow, ...]],
) -> None:
    """Join bounded branch facts after an unknown condition without execution."""

    target.clear()
    for key in left.keys() | right.keys():
        target[key] = tuple(sorted(set(left.get(key, ()) + right.get(key, ())), key=_flow_key))


def _flow_key(flow: _Flow) -> tuple[int, int, int, int]:
    return (
        flow.source.start_byte,
        -1 if flow.interpolation is None else flow.interpolation.start_byte,
        flow.source.end_byte,
        -1 if flow.interpolation is None else flow.interpolation.end_byte,
    )


def _record_object_field_write(
    statement: ast.stmt,
    environment: dict[str, tuple[_Flow, ...]],
    object_fields: dict[tuple[str, str, str], tuple[_Flow, ...]],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: Cwe89ScanLimits,
) -> None:
    """Track only a constant-key ``object.set(section, key, value)`` transfer.

    This captures a common configuration round-trip without treating arbitrary
    method calls as sources or attempting inter-module execution.
    """

    for node in _statement_nodes(statement):
        if not isinstance(node, ast.Call) or not _is_object_field_set(node):
            continue
        key = _object_field_write_key(node)
        if key is None:
            continue
        object_fields[key] = _resolve(
            node.args[2], environment, object_fields, functions, source, line_starts, limits, 0
        )
    if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
        key = _subscript_field_key(statement.targets[0])
        if key is not None:
            object_fields[key] = _resolve(
                statement.value,
                environment,
                object_fields,
                functions,
                source,
                line_starts,
                limits,
                0,
            )


def _literal_string(expression: ast.expr) -> str | None:
    return (
        expression.value
        if isinstance(expression, ast.Constant) and type(expression.value) is str
        else None
    )


def _object_field_write_key(expression: ast.Call) -> tuple[str, str, str] | None:
    if (
        not isinstance(expression.func, ast.Attribute)
        or not isinstance(expression.func.value, ast.Name)
        or expression.func.attr != "set"
        or len(expression.args) != 3
        or expression.keywords
    ):
        return None
    section, key = (_literal_string(item) for item in expression.args[:2])
    if section is None or key is None:
        return None
    return expression.func.value.id, section, key


def _object_field_read_key(expression: ast.expr) -> tuple[str, str, str] | None:
    subscript_key = _subscript_field_key(expression)
    if subscript_key is not None:
        return subscript_key
    if (
        not isinstance(expression, ast.Call)
        or not isinstance(expression.func, ast.Attribute)
        or not isinstance(expression.func.value, ast.Name)
        or expression.func.attr != "get"
        or len(expression.args) < 2
    ):
        return None
    section, key = (_literal_string(item) for item in expression.args[:2])
    if section is None or key is None:
        return None
    return expression.func.value.id, section, key


def _subscript_field_key(expression: ast.expr) -> tuple[str, str, str] | None:
    if not isinstance(expression, ast.Subscript) or not isinstance(expression.value, ast.Name):
        return None
    key = _literal_string(expression.slice)
    if key is None:
        return None
    return expression.value.id, "__dict__", key


def _is_object_field_set(expression: ast.Call) -> bool:
    return _object_field_write_key(expression) is not None


def _is_known_passthrough_call(expression: ast.expr) -> bool:
    """Allow only pure byte/string encoding boundaries used by the rule."""

    if not isinstance(expression, ast.Call) or not isinstance(expression.func, ast.Attribute):
        return False
    return expression.func.attr in {"encode", "decode", "b64encode", "b64decode"}


def _is_http_get(expression: ast.expr) -> bool:
    return (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Attribute)
        and expression.func.attr in {"get", "getlist"}
        and isinstance(expression.func.value, ast.Attribute)
        and expression.func.value.attr in {"args", "form", "headers", "cookies", "values"}
        and isinstance(expression.func.value.value, ast.Name)
        and expression.func.value.value.id == "request"
    )


def _is_known_request_wrapper_source(expression: ast.expr) -> bool:
    """Recognize the narrow first-party wrapper vocabulary without imports."""

    return (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Attribute)
        and isinstance(expression.func.value, ast.Name)
        and expression.func.attr in {"get_form_parameter", "get_query_parameter", "get_cookie"}
        and len(expression.args) == 1
        and not expression.keywords
    )


def _is_execute_call(expression: ast.Call) -> bool:
    return isinstance(expression.func, ast.Attribute) and expression.func.attr == "execute"


def _top_level_functions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    output: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for statement in tree.body:
        if (
            isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
            and statement.name not in output
        ):
            output[statement.name] = statement
    return output


def _assignment_names(statement: ast.Assign | ast.AnnAssign) -> tuple[str, ...]:
    targets = tuple(statement.targets) if isinstance(statement, ast.Assign) else (statement.target,)
    return tuple(target.id for target in targets if isinstance(target, ast.Name))


def _statement_nodes(statement: ast.stmt) -> tuple[ast.AST, ...]:
    output: list[ast.AST] = []
    stack: list[ast.AST] = [statement]
    while stack:
        node = stack.pop()
        if node is not statement and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
        ):
            continue
        output.append(node)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(output)


def _nested_statement_lists(statement: ast.stmt) -> tuple[list[ast.stmt], ...]:
    if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
        return (statement.body, statement.orelse)
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        return (statement.body,)
    if isinstance(statement, ast.Try):
        return (
            statement.body,
            statement.orelse,
            statement.finalbody,
            *(handler.body for handler in statement.handlers),
        )
    return ()


def _line_starts(source: bytes) -> tuple[int, ...]:
    return (0, *(offset + 1 for offset, value in enumerate(source) if value == 10), len(source))


def _node_range(node: ast.AST, source: bytes, line_starts: tuple[int, ...]) -> SourceRange:
    try:
        start_row = node.lineno - 1  # type: ignore[attr-defined]
        end_row = node.end_lineno - 1  # type: ignore[attr-defined]
        start_column = node.col_offset  # type: ignore[attr-defined]
        end_column = node.end_col_offset  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        raise Cwe89ScanError(Cwe89ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        any(type(value) is not int for value in (start_row, end_row, start_column, end_column))
        or start_row < 0
        or end_row < start_row
        or start_row + 1 >= len(line_starts)
        or end_row + 1 >= len(line_starts)
    ):
        raise Cwe89ScanError(Cwe89ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_row] + start_column
    end = line_starts[end_row] + end_column
    if (
        start < line_starts[start_row]
        or end > line_starts[end_row + 1]
        or end < start
        or end > len(source)
    ):
        raise Cwe89ScanError(Cwe89ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start,
        end,
        SourcePoint(start_row, start_column),
        SourcePoint(end_row, end_column),
    )


__all__ = [
    "DEFAULT_CWE89_SCAN_LIMITS",
    "Cwe89EvidenceKind",
    "Cwe89ScanError",
    "Cwe89ScanErrorCode",
    "Cwe89ScanLimits",
    "Cwe89ScanResult",
    "Cwe89Signal",
    "scan_python_cwe89",
]
