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
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

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
    build_python_symbol_index,
    build_typescript_symbol_index,
)

_MAX_LIMITS = (2_000_000, 2_048)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CWES = frozenset({"CWE-78", "CWE-22", "CWE-918", "CWE-862"})


class CwePortfolioScanErrorCode(StrEnum):
    """Closed reasons a portfolio fact cannot be produced."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class CwePortfolioScanError(RuntimeError):
    """Fixed source-free scanner failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: CwePortfolioScanErrorCode) -> None:
        if type(code) is not CwePortfolioScanErrorCode:
            raise TypeError("CWE portfolio scan error code is invalid")
        self.code = code
        self.safe_message = "CWE portfolio semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class CwePortfolioScanLimits:
    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("CWE portfolio scan limits are invalid")


DEFAULT_CWE_PORTFOLIO_SCAN_LIMITS = CwePortfolioScanLimits()


@dataclass(frozen=True, slots=True)
class CwePortfolioSignal:
    """A source-free, bounded recognised-flow fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    cwe: str
    source: SourceRange
    sink: SourceRange
    detector: str

    def __post_init__(self) -> None:
        expected = f"securecode-{self.language}-{self.cwe.lower()}@1.0"
        valid = (
            type(self.repository_id) is str
            and bool(self.repository_id)
            and type(self.revision) is str
            and _SHA1.fullmatch(self.revision) is not None
            and type(self.path) is str
            and type(self.content_sha256) is str
            and _SHA256.fullmatch(self.content_sha256) is not None
            and type(self.source_size_bytes) is int
            and self.source_size_bytes >= 0
            and self.language in {"python", "javascript", "typescript", "go"}
            and self.cwe in _CWES
            and self.detector == expected
            and type(self.source) is SourceRange
            and type(self.sink) is SourceRange
            and self.source.end_byte <= self.source_size_bytes
            and self.sink.end_byte <= self.source_size_bytes
        )
        if valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid = False
        if not valid:
            raise ValueError("CWE portfolio signal is invalid")


@dataclass(frozen=True, slots=True)
class CwePortfolioScanResult:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[CwePortfolioSignal, ...]
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
            and self.language in {"python", "javascript", "typescript", "go"}
        )
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity_valid = False
        order = tuple(
            (item.cwe, item.sink.start_byte, item.sink.end_byte, item.source.start_byte)
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
            or any(type(item) is not CwePortfolioSignal for item in self.signals)
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
            raise ValueError("CWE portfolio scan result is invalid")


def scan_cwe_portfolio(
    symbol_index: SymbolIndex,
    *,
    limits: CwePortfolioScanLimits = DEFAULT_CWE_PORTFOLIO_SCAN_LIMITS,
) -> CwePortfolioScanResult:
    """Return only direct, recognized source-to-sink facts for four CWEs."""

    _validate_index(symbol_index, limits)
    if symbol_index.language == "python":
        facts = _python_facts(symbol_index.source)
    else:
        facts = _tree_facts(symbol_index.language, symbol_index.source)
    unique = sorted(
        set(facts),
        key=lambda item: (item[0], item[2].start_byte, item[2].end_byte, item[1].start_byte),
    )
    if len(unique) > limits.max_signals:
        raise CwePortfolioScanError(CwePortfolioScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        CwePortfolioSignal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            language=symbol_index.language,
            cwe=cwe,
            source=source,
            sink=sink,
            detector=f"securecode-{symbol_index.language}-{cwe.lower()}@1.0",
        )
        for cwe, source, sink in unique
    )
    return CwePortfolioScanResult(
        repository_id=symbol_index.repository_id,
        revision=symbol_index.revision,
        path=symbol_index.path,
        content_sha256=symbol_index.content_sha256,
        source_size_bytes=symbol_index.source_byte_length,
        language=symbol_index.language,
        signals=signals,
        scan_sha256=_scan_sha256(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            symbol_index.language,
            signals,
        ),
    )


def portfolio_signals_to_raw_signals(
    result: CwePortfolioScanResult,
    *,
    tenant_id: str,
    producer: ProducerRef,
) -> tuple[RawSignal, ...]:
    """Translate scanner facts to the existing source-free RawSignal boundary."""

    if (
        type(result) is not CwePortfolioScanResult
        or type(tenant_id) is not str
        or not tenant_id
        or type(producer) is not ProducerRef
    ):
        raise CwePortfolioScanError(CwePortfolioScanErrorCode.REQUEST_INVALID)
    output: list[RawSignal] = []
    for ordinal, signal in enumerate(result.signals, start=1):
        location = SourceLocation(
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
        )
        stable = hashlib.sha256(f"{result.scan_sha256}:{ordinal}".encode("ascii")).hexdigest()
        output.append(
            RawSignal(
                schema_version=CONTRACT_SCHEMA_VERSION,
                raw_signal_id=(
                    f"portfolio-{signal.language}-{signal.cwe.lower()}-"
                    f"{ordinal}-{result.scan_sha256}"
                ),
                tenant_id=tenant_id,
                head_sha=signal.revision,
                producer=producer,
                rule_id=f"portfolio-{signal.cwe.lower()}",
                location=location,
                payload_classification=DataClass.INTERNAL_METADATA,
                signal_sha256=stable,
            )
        )
    return tuple(output)


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
    if (compact.startswith("open(") or ".read_text(" in compact or ".read_bytes(" in compact) and (
        "os.path.join(" in compact or "Path(" in compact
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
        "javascript": tree_sitter_javascript.language(),
        "typescript": tree_sitter_typescript.language_typescript(),
        "go": tree_sitter_go.language(),
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


__all__ = [
    "DEFAULT_CWE_PORTFOLIO_SCAN_LIMITS",
    "CwePortfolioScanError",
    "CwePortfolioScanErrorCode",
    "CwePortfolioScanLimits",
    "CwePortfolioScanResult",
    "CwePortfolioSignal",
    "portfolio_signals_to_raw_signals",
    "scan_cwe_portfolio",
]
