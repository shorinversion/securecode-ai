"""Conservative multi-language CWE portfolio facts.

This module consumes only a sealed ``SymbolIndex`` and structural parsers.  It
does not import, execute, retain, or expose analysed source.  The rules are
deliberately narrow: a result is a deterministic source-to-sink *fact*, not a
finding or verdict.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from typing import cast

from securecode_ai.core import (
    ParseHealth,
    SourcePoint,
    SourceRange,
    SymbolIndex,
)
from securecode_ai.core.symbols import SymbolKind
from tree_sitter import Language, Node, Parser

from .cst import (
    CstAdapterError,
    build_go_symbol_index,
    build_javascript_symbol_index,
    build_python_symbol_index,
    build_typescript_symbol_index,
)
from .cst_ecmascript import _javascript_language, _typescript_language
from .cst_go import _go_language
from .cwe_portfolio_models import (
    CwePortfolioScanError,
    CwePortfolioScanErrorCode,
    CwePortfolioScanLimits,
    CwePortfolioScanResult,
    CwePortfolioSignal,
    _detector_name,
)


def _with_cwe862_detector_signals(
    result: CwePortfolioScanResult,
    index: SymbolIndex,
    *,
    limits: CwePortfolioScanLimits,
) -> CwePortfolioScanResult:
    """Replace legacy CWE-862 portfolio facts with the language detectors."""
    from .ecmascript_cwe862 import (
        EcmaScriptCwe862ScanError,
        EcmaScriptCwe862ScanLimits,
        scan_ecmascript_cwe862,
    )
    from .go_cwe862 import GoCwe862ScanError, GoCwe862ScanLimits, scan_go_cwe862
    from .python_ast import PythonAstError, analyze_python_ast
    from .python_cwe862 import (
        PythonCwe862ScanError,
        PythonCwe862ScanLimits,
        scan_python_cwe862,
    )

    facts: tuple[tuple[str, SourceRange, SourceRange], ...]
    try:
        if index.language == "python":
            python_signals = scan_python_cwe862(
                index,
                analyze_python_ast(index),
                limits=PythonCwe862ScanLimits(
                    max_source_bytes=limits.max_source_bytes,
                    max_signals=limits.max_signals,
                ),
            ).signals
            facts = tuple(("CWE-862", signal.endpoint, signal.sink) for signal in python_signals)
        elif index.language in {"javascript", "typescript"}:
            ecmascript_signals = scan_ecmascript_cwe862(
                index,
                limits=EcmaScriptCwe862ScanLimits(
                    max_source_bytes=limits.max_source_bytes,
                    max_signals=limits.max_signals,
                ),
            ).signals
            facts = tuple(("CWE-862", signal.source, signal.sink) for signal in ecmascript_signals)
        elif index.language == "go":
            go_signals = scan_go_cwe862(
                index,
                limits=GoCwe862ScanLimits(
                    max_source_bytes=limits.max_source_bytes,
                    max_signals=limits.max_signals,
                ),
            ).signals
            facts = tuple(("CWE-862", signal.source, signal.sink) for signal in go_signals)
        else:
            raise CwePortfolioScanError(CwePortfolioScanErrorCode.REQUEST_INVALID)
    except (
        PythonAstError,
        PythonCwe862ScanError,
        EcmaScriptCwe862ScanError,
        GoCwe862ScanError,
    ) as error:
        code = getattr(getattr(error, "code", None), "value", None)
        if type(code) is not str:
            raise CwePortfolioScanError(CwePortfolioScanErrorCode.ANALYSIS_UNAVAILABLE) from None
        try:
            normalized = CwePortfolioScanErrorCode(code)
        except (TypeError, ValueError):
            raise CwePortfolioScanError(CwePortfolioScanErrorCode.ANALYSIS_UNAVAILABLE) from None
        raise CwePortfolioScanError(normalized) from None

    # The dedicated detectors own CWE-862 semantics.  Do not retain a legacy
    # portfolio fact when a detector returns no matching sink: that would let
    # the broad fallback bypass the language-specific authorization analysis.
    signals = [signal for signal in result.signals if signal.cwe != "CWE-862"]
    for cwe, source, sink in facts:
        signals.append(
            CwePortfolioSignal(
                repository_id=result.repository_id,
                revision=result.revision,
                path=result.path,
                content_sha256=result.content_sha256,
                source_size_bytes=result.source_size_bytes,
                language=result.language,
                cwe=cwe,
                source=source,
                sink=sink,
                detector=_detector_name(result.language, cwe),
                receiver_qualified_method_id=(
                    _go_receiver_qualified_method_id(index, sink)
                    if index.language == "go"
                    else None
                ),
            )
        )

    unique = sorted(
        {
            (
                signal.cwe,
                signal.sink.start_byte,
                signal.sink.end_byte,
                signal.source.start_byte,
                signal.source.end_byte,
            ): signal
            for signal in signals
        }.values(),
        key=lambda signal: (
            signal.cwe,
            signal.sink.start_byte,
            signal.sink.end_byte,
            signal.source.start_byte,
            signal.source.end_byte,
        ),
    )
    if len(unique) > limits.max_signals:
        raise CwePortfolioScanError(CwePortfolioScanErrorCode.SIGNAL_LIMIT)
    normalized_signals = tuple(unique)
    return CwePortfolioScanResult(
        repository_id=result.repository_id,
        revision=result.revision,
        path=result.path,
        content_sha256=result.content_sha256,
        source_size_bytes=result.source_size_bytes,
        language=result.language,
        signals=normalized_signals,
        scan_sha256=_scan_sha256(
            result.repository_id,
            result.revision,
            result.path,
            result.content_sha256,
            result.source_size_bytes,
            result.language,
            normalized_signals,
        ),
    )


def _validate_index(index: SymbolIndex, limits: CwePortfolioScanLimits) -> None:
    if type(index) is not SymbolIndex or type(limits) is not CwePortfolioScanLimits:
        raise CwePortfolioScanError(CwePortfolioScanErrorCode.REQUEST_INVALID)
    if index.language not in {"python", "javascript", "typescript", "go"}:
        raise CwePortfolioScanError(CwePortfolioScanErrorCode.REQUEST_INVALID)
    if len(index.source) > limits.max_source_bytes:
        raise CwePortfolioScanError(CwePortfolioScanErrorCode.SOURCE_LIMIT)
    if index.parse_health is not ParseHealth.HEALTHY:
        raise CwePortfolioScanError(CwePortfolioScanErrorCode.ANALYSIS_UNAVAILABLE)
    rebuild = {
        "python": build_python_symbol_index,
        "javascript": build_javascript_symbol_index,
        "typescript": build_typescript_symbol_index,
        "go": build_go_symbol_index,
    }[index.language]
    try:
        reconstructed = rebuild(
            repository_id=index.repository_id,
            revision=index.revision,
            path=index.path,
            content_sha256=index.content_sha256,
            source=index.source,
        )
    except (CstAdapterError, TypeError, ValueError):
        raise CwePortfolioScanError(CwePortfolioScanErrorCode.INTEGRITY_FAILURE) from None
    if reconstructed != index:
        raise CwePortfolioScanError(CwePortfolioScanErrorCode.INTEGRITY_FAILURE)


def _go_receiver_qualified_method_id(
    symbol_index: SymbolIndex, location: SourceRange
) -> str | None:
    if symbol_index.language != "go":
        return None
    methods = tuple(
        symbol
        for symbol in symbol_index.symbols
        if symbol.kind is SymbolKind.METHOD
        and symbol.receiver_name is not None
        and symbol.declaration.contains(location)
    )
    if not methods:
        return None
    method = min(
        methods,
        key=lambda symbol: (
            symbol.declaration.end_byte - symbol.declaration.start_byte,
            symbol.qualified_name,
            symbol.symbol_id,
        ),
    )
    return method.symbol_id


def _python_facts(source: bytes) -> tuple[tuple[str, SourceRange, SourceRange], ...]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        raise CwePortfolioScanError(CwePortfolioScanErrorCode.INTEGRITY_FAILURE) from None
    facts: list[tuple[str, SourceRange, SourceRange]] = []
    for call in (item for item in ast.walk(tree) if isinstance(item, ast.Call)):
        compact = _python_compact(source, call)
        cwe = _python_cwe(compact)
        if cwe is None:
            continue
        security_argument = _python_security_argument(call, cwe, compact)
        if security_argument is None:
            continue
        source_node = _python_resolve_source(
            security_argument,
            call=call,
            tree=tree,
            source=source,
            seen=frozenset(),
        )
        if source_node is None:
            continue
        if cwe == "CWE-862" and _python_guarded(call, tree, source, security_argument):
            continue
        facts.append((cwe, _python_range(source, source_node), _python_range(source, call)))
    return tuple(facts)


def _python_cwe(compact: str) -> str | None:
    if compact.startswith("os.system(") or (
        re.match(r"(?:subprocess\.)?(?:run|call|Popen)\(", compact) and "shell=True" in compact
    ):
        return "CWE-78"
    path_builder = "os.path.join(" in compact or "Path(" in compact or ".joinpath(" in compact
    if compact.startswith("open(") or (
        (".open(" in compact or ".read_text(" in compact or ".read_bytes(" in compact)
        and path_builder
    ):
        return "CWE-22"
    if re.match(r"(?:requests\.)?(?:get|post|request)\(", compact):
        return "CWE-918"
    if re.match(r"(?:db|repo|repository)\.(?:get|find|lookup)\(", compact):
        return "CWE-862"
    return None


def _python_security_argument(call: ast.Call, cwe: str, compact: str) -> ast.expr | None:
    if cwe == "CWE-918" and compact.startswith("requests.request(") and len(call.args) > 1:
        return call.args[1]
    if (
        cwe == "CWE-22"
        and not call.args
        and isinstance(call.func, ast.Attribute)
        and call.func.attr
        in {
            "open",
            "read_bytes",
            "read_text",
        }
    ):
        return call.func.value
    if call.args:
        return call.args[0]
    keyword = next((item.value for item in call.keywords if item.arg is not None), None)
    return keyword


def _python_guarded(call: ast.Call, tree: ast.AST, source: bytes, identity: ast.expr) -> bool:
    scope = _python_enclosing_scope(call, tree)
    if scope is None:
        return False
    normalized_identity = _python_compact(source, identity)
    for guard in _python_scope_calls(scope):
        if (guard.lineno, guard.col_offset) >= (call.lineno, call.col_offset):
            continue
        name = _python_compact(source, guard.func).lower()
        if name not in {"authorize", "require_principal", "tenant_guard"}:
            continue
        if any(_python_compact(source, argument) == normalized_identity for argument in guard.args):
            return True
    return False


def _python_enclosing_scope(
    call: ast.Call, tree: ast.AST
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    candidates: list[tuple[int, int, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    for item in ast.walk(tree):
        if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end_line = item.end_lineno
        if type(end_line) is int and item.lineno <= call.lineno <= end_line:
            candidates.append((end_line - item.lineno, item.col_offset, item))
    return min(candidates, default=(0, 0, None))[2]


def _python_scope_calls(scope: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[ast.Call, ...]:
    calls: list[ast.Call] = []
    stack: list[ast.AST] = list(reversed(scope.body))
    while stack:
        node = stack.pop()
        if node != scope and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Call):
            calls.append(node)
        stack.extend(reversed(list(ast.iter_child_nodes(node))))
    return tuple(calls)


def _python_source_node(subject: ast.expr) -> ast.expr | None:
    for node in ast.walk(subject):
        if isinstance(node, ast.expr) and _python_is_source(node):
            return node
    return None


def _python_resolve_source(
    subject: ast.expr,
    *,
    call: ast.Call,
    tree: ast.AST,
    source: bytes,
    seen: frozenset[str],
    before: tuple[int, int] | None = None,
) -> ast.expr | None:
    direct = _python_source_node(subject)
    if direct is not None:
        return direct
    if isinstance(subject, ast.Name) and subject.id not in seen:
        scope = _python_enclosing_scope(call, tree)
        if scope is not None:
            boundary = before or (call.lineno, call.col_offset)
            assignment = _python_latest_assignment(scope, subject.id, boundary)
            if assignment is not None:
                assigned_at = (assignment.lineno, assignment.col_offset)
                value = _python_assignment_value(assignment)
                if value is not None:
                    return _python_resolve_source(
                        value,
                        call=call,
                        tree=tree,
                        source=source,
                        seen=seen | {subject.id},
                        before=assigned_at,
                    )
    for child in ast.iter_child_nodes(subject):
        if isinstance(child, ast.expr):
            resolved = _python_resolve_source(
                child,
                call=call,
                tree=tree,
                source=source,
                seen=seen,
                before=before,
            )
            if resolved is not None:
                return resolved
    return None


def _python_latest_assignment(
    scope: ast.FunctionDef | ast.AsyncFunctionDef,
    name: str,
    before: tuple[int, int],
) -> ast.Assign | ast.AnnAssign | None:
    candidates: list[ast.Assign | ast.AnnAssign] = []
    stack: list[ast.AST] = list(reversed(scope.body))
    while stack:
        node = stack.pop()
        if node != scope and isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
        ):
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            position = (node.lineno, node.col_offset)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if position < before and any(
                _python_target_has_name(target, name) for target in targets
            ):
                candidates.append(node)
        stack.extend(reversed(list(ast.iter_child_nodes(node))))
    return max(candidates, key=lambda item: (item.lineno, item.col_offset), default=None)


def _python_target_has_name(target: ast.expr, name: str) -> bool:
    return any(isinstance(node, ast.Name) and node.id == name for node in ast.walk(target))


def _python_assignment_value(assignment: ast.Assign | ast.AnnAssign) -> ast.expr | None:
    return assignment.value


def _python_is_source(node: ast.expr) -> bool:
    try:
        text = ast.unparse(node).replace(" ", "")
    except (ValueError, TypeError):
        return False
    return any(
        token in text
        for token in (
            "request.args.get(",
            "request.args[",
            "request.GET[",
            "request.POST[",
            "request.POST.get(",
            "request.form.get(",
            "request.form[",
            "request.values.get(",
            "request.values[",
            "request.query_params.get(",
            "request.query_params[",
            "request.query.",
            "request.json",
            "request.data",
            "request.body",
            "request.headers.get(",
            "request.headers[",
            "request.cookies.get(",
            "request.cookies[",
            "request.get_json(",
        )
    )


def _python_range(source: bytes, node: ast.AST) -> SourceRange:
    starts = _line_starts(source)
    line = getattr(node, "lineno", None)
    column = getattr(node, "col_offset", None)
    end_line = getattr(node, "end_lineno", None)
    end_column = getattr(node, "end_col_offset", None)
    values = (line, column, end_line, end_column)
    if any(type(value) is not int for value in values):
        raise CwePortfolioScanError(CwePortfolioScanErrorCode.INTEGRITY_FAILURE)
    start_line = cast(int, line)
    start_column = cast(int, column)
    final_line = cast(int, end_line)
    final_column = cast(int, end_column)
    start = starts[start_line - 1] + start_column
    end = starts[final_line - 1] + final_column
    return SourceRange(
        start,
        end,
        SourcePoint(start_line - 1, start_column),
        SourcePoint(final_line - 1, final_column),
    )


def _python_compact(source: bytes, node: ast.AST) -> str:
    location = _python_range(source, node)
    return b"".join(source[location.start_byte : location.end_byte].split()).decode(
        "ascii", "ignore"
    )


def _tree_facts(language: str, source: bytes) -> tuple[tuple[str, SourceRange, SourceRange], ...]:
    grammar = {
        "javascript": _javascript_language(),
        "typescript": _typescript_language(tsx=False),
        "go": _go_language(),
    }[language]
    try:
        root = Parser(Language(grammar)).parse(source).root_node
    except Exception:
        raise CwePortfolioScanError(CwePortfolioScanErrorCode.INTEGRITY_FAILURE) from None
    facts: list[tuple[str, SourceRange, SourceRange]] = []
    for call in (node for node in _preorder(root) if node.type == "call_expression"):
        compact = _compact(source, call)
        cwe = _tree_cwe(compact, language)
        if cwe is None and language == "go":
            source_node = _go_path_traversal_source(source, call)
            if source_node is not None:
                facts.append(("CWE-22", _range(source_node), _range(call)))
            continue
        if cwe is None and language in {"javascript", "typescript"}:
            source_node = _javascript_path_traversal_source(source, call, language)
            if source_node is not None:
                facts.append(("CWE-22", _range(source_node), _range(call)))
            continue
        if cwe is None:
            continue
        security_argument = _tree_security_argument(call, cwe, compact, language)
        if security_argument is None:
            continue
        source_node = _tree_source_node(source, security_argument, language)
        if source_node is None and cwe in {"CWE-78", "CWE-918"}:
            if language == "go":
                function = _go_enclosing_function(call)
                if function is not None:
                    source_node = _go_resolve_path(
                        source,
                        function,
                        security_argument,
                        set(),
                    )
            elif language in {"javascript", "typescript"}:
                function = _javascript_enclosing_function(call)
                if function is not None:
                    source_node = _javascript_resolve_path(
                        source,
                        function,
                        security_argument,
                        language,
                        set(),
                    )
        if source_node is None:
            continue
        if cwe == "CWE-862" and _tree_guarded(call, source, security_argument):
            continue
        facts.append((cwe, _range(source_node), _range(call)))
    return tuple(facts)


def _tree_cwe(compact: str, language: str) -> str | None:
    if language in {"javascript", "typescript"}:
        if re.match(r"(?:child_process\.)?exec(?:Sync)?\(", compact):
            return "CWE-78"
        if re.match(r"fs\.(?:promises\.)?readFile(?:Sync)?\(", compact) and "path.join(" in compact:
            return "CWE-22"
        if re.match(r"(?:fetch|axios\.get|axios\.post)\(", compact):
            return "CWE-918"
        if re.match(r"(?:db|repo|repository)\.(?:get|find|lookup)\(", compact):
            return "CWE-862"
    else:
        if compact.startswith("exec.Command(") and ('"sh"' in compact or '"bash"' in compact):
            return "CWE-78"
        if (
            compact.startswith(
                (
                    "os.ReadFile(",
                    "ioutil.ReadFile(",
                    "ReadFile(",
                    "os.Open(",
                    "os.Create(",
                    "os.OpenFile(",
                )
            )
            and "filepath.Join(" in compact
        ):
            return "CWE-22"
        if compact.startswith("http.Get("):
            return "CWE-918"
        if re.match(r"(?:repo|repository)\.(?:Get|Find|Lookup)\(", compact):
            return "CWE-862"
    return None


def _go_path_traversal_source(source: bytes, sink: Node) -> Node | None:
    """Resolve one direct Go query-to-join-to-read flow through locals."""

    compact = _compact(source, sink)
    if not compact.startswith(
        (
            "os.ReadFile(",
            "ioutil.ReadFile(",
            "ReadFile(",
            "os.Open(",
            "os.Create(",
            "os.OpenFile(",
        )
    ):
        return None
    arguments = sink.child_by_field_name("arguments")
    if arguments is None or not arguments.named_children:
        return None
    function = _go_enclosing_function(sink)
    if function is None:
        return None
    return _go_resolve_path(source, function, arguments.named_children[0], set())


def _javascript_path_traversal_source(source: bytes, sink: Node, language: str) -> Node | None:
    """Resolve one local JavaScript path flow through a file-read sink."""

    compact = _compact(source, sink)
    if not re.match(r"fs\.(?:promises\.)?readFile(?:Sync)?\(", compact):
        return None
    arguments = sink.child_by_field_name("arguments")
    if arguments is None or not arguments.named_children:
        return None
    function = _javascript_enclosing_function(sink)
    if function is None:
        return None
    return _javascript_resolve_path(source, function, arguments.named_children[0], language, set())


def _javascript_resolve_path(
    source: bytes,
    function: Node,
    expression: Node,
    language: str,
    visited: set[str],
) -> Node | None:
    direct = _tree_source_node(source, expression, language)
    if direct is not None:
        return direct
    if expression.type == "identifier":
        name = _compact(source, expression)
        if name in visited:
            return None
        bound = _javascript_bound_expression(source, function, name, expression.start_byte)
        if bound is None:
            return None
        return _javascript_resolve_path(source, function, bound, language, visited | {name})
    if expression.type != "call_expression":
        return None
    compact = _compact(source, expression)
    if not compact.startswith("path.join("):
        return None
    arguments = expression.child_by_field_name("arguments")
    if arguments is None:
        return None
    for argument in arguments.named_children:
        found = _javascript_resolve_path(source, function, argument, language, visited)
        if found is not None:
            return found
    return None


def _javascript_enclosing_function(node: Node) -> Node | None:
    current = node.parent
    while current is not None:
        if current.type in {
            "function_declaration",
            "method_definition",
            "function",
            "arrow_function",
        }:
            return current
        current = current.parent
    return None


def _javascript_bound_expression(
    source: bytes, function: Node, name: str, before: int
) -> Node | None:
    bound: Node | None = None
    for node in _preorder(function):
        if node.start_byte >= before or node.type not in {
            "variable_declarator",
            "assignment_expression",
        }:
            continue
        left = node.child_by_field_name("name") or node.child_by_field_name("left")
        right = node.child_by_field_name("value") or node.child_by_field_name("right")
        if left is None or right is None or left.type != "identifier":
            continue
        if _compact(source, left) == name:
            bound = right
    return bound


def _go_resolve_path(
    source: bytes, function: Node, expression: Node, visited: set[str]
) -> Node | None:
    direct = _go_request_source(source, expression)
    if direct is not None:
        return direct
    if expression.type == "identifier":
        name = _compact(source, expression)
        if name in visited:
            return None
        bound = _go_bound_expression(source, function, name, expression.start_byte)
        if bound is None:
            return None
        return _go_resolve_path(source, function, bound, visited | {name})
    if expression.type != "call_expression":
        return None
    compact = _compact(source, expression)
    if not compact.startswith("filepath.Join("):
        return None
    arguments = expression.child_by_field_name("arguments")
    if arguments is None:
        return None
    for argument in arguments.named_children:
        found = _go_resolve_path(source, function, argument, visited)
        if found is not None:
            return found
    return None


def _go_request_source(source: bytes, expression: Node) -> Node | None:
    for node in _preorder(expression):
        if node.type == "call_expression" and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*\.URL\.Query\(\)\.Get\(.*\)",
            _compact(source, node),
        ):
            return node
    return None


def _go_enclosing_function(node: Node) -> Node | None:
    current = node.parent
    while current is not None:
        if current.type in {"function_declaration", "method_declaration", "func_literal"}:
            return current
        current = current.parent
    return None


def _go_bound_expression(source: bytes, function: Node, name: str, before: int) -> Node | None:
    bound: Node | None = None
    for node in _preorder(function):
        if node.start_byte >= before or node.type not in {
            "short_var_declaration",
            "assignment_statement",
        }:
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            continue
        left_values = left.named_children
        right_values = right.named_children
        for index, left_value in enumerate(left_values):
            if _compact(source, left_value) == name and index < len(right_values):
                bound = right_values[index]
    return bound


def _tree_security_argument(call: Node, cwe: str, compact: str, language: str) -> Node | None:
    arguments = call.child_by_field_name("arguments")
    if arguments is None or not arguments.named_children:
        return None
    values = arguments.named_children
    if language == "go" and cwe == "CWE-78" and compact.startswith("exec.Command("):
        return values[-1]
    return values[0]


def _tree_guarded(call: Node, source: bytes, identity: Node) -> bool:
    current = call.parent
    while current is not None:
        if current.type in {
            "function_declaration",
            "method_definition",
            "method_declaration",
            "function",
            "arrow_function",
        }:
            normalized_identity = _compact(source, identity)
            for candidate in _preorder(current):
                if candidate.type != "call_expression" or candidate.start_byte >= call.start_byte:
                    continue
                compact = _compact(source, candidate).lower()
                if not re.match(r"(?:authorize|requireprincipal|tenantguard)\(", compact):
                    continue
                arguments = candidate.child_by_field_name("arguments")
                if arguments is not None and any(
                    _compact(source, value) == normalized_identity
                    for value in arguments.named_children
                ):
                    return True
            return False
        current = current.parent
    return False


def _tree_source_node(source: bytes, subject: Node, language: str) -> Node | None:
    for node in _preorder(subject):
        compact = _compact(source, node)
        if language in {"javascript", "typescript"} and re.search(
            r"(?:req|request)\.(?:query|params|body|headers|cookies)(?:\.[A-Za-z_$][A-Za-z0-9_$]*|\[)",
            compact,
        ):
            return node
        if language in {"javascript", "typescript"} and re.search(
            r"(?:req|request)\.(?:get|header)\(", compact
        ):
            return node
        if language in {"javascript", "typescript"} and re.search(
            r"ctx\.(?:query|request\.body|headers)\.[A-Za-z_$][A-Za-z0-9_$]*", compact
        ):
            return node
        if language == "go" and re.search(
            r"[A-Za-z_][A-Za-z0-9_]*\.(?:URL\.Query\(\)(?:\.Get\(|\[)|FormValue\(|PostFormValue\(|Header\.Get\()",
            compact,
        ):
            return node
    return None


def _preorder(root: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        output.append(node)
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _range(node: Node) -> SourceRange:
    return SourceRange(
        node.start_byte,
        node.end_byte,
        SourcePoint(node.start_point.row, node.start_point.column),
        SourcePoint(node.end_point.row, node.end_point.column),
    )


def _compact(source: bytes, node: Node) -> str:
    return b"".join(source[node.start_byte : node.end_byte].split()).decode("ascii", "ignore")


def _line_starts(source: bytes) -> tuple[int, ...]:
    starts = [0]
    starts.extend(index + 1 for index, byte in enumerate(source) if byte == 10)
    return tuple(starts)


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    language: str,
    signals: tuple[CwePortfolioSignal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "language": language,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "cwe": item.cwe,
                "detector": item.detector,
                "sink": _range_value(item.sink),
                "source": _range_value(item.source),
                **(
                    {"receiver_qualified_method_id": item.receiver_qualified_method_id}
                    if item.receiver_qualified_method_id is not None
                    else {}
                ),
            }
            for item in signals
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
