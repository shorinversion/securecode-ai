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
    CwePortfolioSignal,
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
        source_node = _python_source_node(security_argument)
        if source_node is None:
            continue
        if cwe == "CWE-862" and _python_guarded(call, tree, source, security_argument):
            continue
        facts.append((cwe, _python_range(source, source_node), _python_range(source, call)))
    return tuple(facts)


def _python_cwe(compact: str) -> str | None:
    if re.match(r"(?:subprocess\.)?(?:run|call|Popen)\(", compact) and "shell=True" in compact:
        return "CWE-78"
    path_builder = "os.path.join(" in compact or "Path(" in compact or ".joinpath(" in compact
    if compact.startswith("open(") or (
        (".read_text(" in compact or ".read_bytes(" in compact) and path_builder
    ):
        return "CWE-22"
    if re.match(r"(?:requests\.)?(?:get|post|request)\(", compact):
        return "CWE-918"
    if re.match(r"(?:db|repo|repository)\.(?:get|find|lookup)\(", compact):
        return "CWE-862"
    return None


def _python_security_argument(call: ast.Call, cwe: str, compact: str) -> ast.expr:
    if cwe == "CWE-918" and compact.startswith("requests.request(") and len(call.args) > 1:
        return call.args[1]
    if cwe == "CWE-22" and not call.args:
        if isinstance(call.func, ast.Attribute) and call.func.attr in {
            "read_bytes",
            "read_text",
        }:
            return call.func.value
        raise CwePortfolioScanError(CwePortfolioScanErrorCode.INTEGRITY_FAILURE)
    if not call.args:
        raise CwePortfolioScanError(CwePortfolioScanErrorCode.INTEGRITY_FAILURE)
    return call.args[0]


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
        if node is not scope and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
        ):
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


def _python_is_source(node: ast.expr) -> bool:
    try:
        text = ast.unparse(node).replace(" ", "")
    except (ValueError, TypeError):
        return False
    return any(
        token in text
        for token in (
            "request.args.get(",
            "request.GET[",
            "request.query_params.get(",
            "request.query.",
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
        if cwe is None:
            continue
        security_argument = _tree_security_argument(call, cwe, compact, language)
        if security_argument is None:
            continue
        source_node = _tree_source_node(source, security_argument, language)
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
        if re.match(r"fs\.readFile(?:Sync)?\(", compact) and "path.join(" in compact:
            return "CWE-22"
        if re.match(r"(?:fetch|axios\.get|axios\.post)\(", compact):
            return "CWE-918"
        if re.match(r"(?:db|repo|repository)\.(?:get|find|lookup)\(", compact):
            return "CWE-862"
    else:
        if compact.startswith("exec.Command(") and ('"sh"' in compact or '"bash"' in compact):
            return "CWE-78"
        if compact.startswith("os.ReadFile(") and "filepath.Join(" in compact:
            return "CWE-22"
        if compact.startswith("http.Get("):
            return "CWE-918"
        if re.match(r"(?:repo|repository)\.(?:Get|Find|Lookup)\(", compact):
            return "CWE-862"
    return None


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
            r"(?:req|request)\.(?:query|params)\.[A-Za-z_$][A-Za-z0-9_$]*", compact
        ):
            return node
        if language == "go" and re.search(
            r"[A-Za-z_][A-Za-z0-9_]*\.URL\.Query\(\)\.Get\(", compact
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
