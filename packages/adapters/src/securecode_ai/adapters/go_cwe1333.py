"""Bounded Go facts for CWE-1333 inefficient regular-expression complexity.

Go's standard ``regexp`` package is backed by RE2 and does not use the
catastrophic-backtracking execution model targeted by CWE-1333.  This module
therefore intentionally ignores that package and recognises only known
third-party backtracking engines.  A call that compiles a pattern with one of
those engines is emitted as a source-free candidate.  The scanner does not
claim that an individual pattern is exploitable and leaves that decision to a
later auditor.

The input is one sealed Go :class:`~securecode_ai.core.SymbolIndex`.  Source
bytes are used only while parsing; immutable results contain ranges and
content-addressed identity, never source text or parser diagnostics.
"""

from __future__ import annotations

import hashlib
import json
import re
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

_MAX_LIMITS = (2_000_000, 2_048, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-go-cwe1333"
_DETECTOR = "securecode-go-cwe1333@1.0"

# regexp2 is a .NET-compatible backtracking engine.  The pcre Go binding is
# also intentionally included, while github.com/wasilibs/go-re2 is omitted:
# it preserves RE2's linear-time execution model and is not a CWE-1333 sink.
_BACKTRACKING_PACKAGES = frozenset(
    {
        "github.com/dlclark/regexp2",
        "github.com/glenn-brown/golang-pkg-pcre",
    }
)
_COMPILE_NAMES = frozenset({"Compile", "MustCompile"})
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})


class GoCwe1333ScanErrorCode(StrEnum):
    """Closed, source-free reasons a Go regex-complexity scan can fail."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe1333ScanError(RuntimeError):
    """Fixed scanner failure that never echoes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe1333ScanErrorCode) -> None:
        if type(code) is not GoCwe1333ScanErrorCode:
            raise TypeError("Go CWE-1333 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-1333 regular-expression complexity scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe1333ScanLimits:
    """Hard ceilings applied before and during structural analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-1333 scan limits are invalid")


DEFAULT_GO_CWE1333_SCAN_LIMITS = GoCwe1333ScanLimits()


class GoCwe1333Operation(StrEnum):
    """Recognised third-party backtracking-engine compilation operations."""

    REGEXP2_COMPILE = "regexp2.compile"
    REGEXP2_MUST_COMPILE = "regexp2.must_compile"
    PCRE_COMPILE = "pcre.compile"
    PCRE_MUST_COMPILE = "pcre.must_compile"


_BACKTRACKING_OPERATIONS: dict[tuple[str, str], GoCwe1333Operation] = {
    ("github.com/dlclark/regexp2", "Compile"): GoCwe1333Operation.REGEXP2_COMPILE,
    ("github.com/dlclark/regexp2", "MustCompile"): GoCwe1333Operation.REGEXP2_MUST_COMPILE,
    ("github.com/glenn-brown/golang-pkg-pcre", "Compile"): GoCwe1333Operation.PCRE_COMPILE,
    ("github.com/glenn-brown/golang-pkg-pcre", "MustCompile"): GoCwe1333Operation.PCRE_MUST_COMPILE,
}


@dataclass(frozen=True, slots=True)
class GoCwe1333Signal:
    """One immutable backtracking-engine pattern candidate."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe1333Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-1333"
    detector: str = _DETECTOR
    detail: str = "backtracking_regexp_engine_pattern"

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
            if valid_identity and valid_ranges and type(self.operation) is GoCwe1333Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not GoCwe1333Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-1333"
            or self.detector != _DETECTOR
            or self.detail != "backtracking_regexp_engine_pattern"
        ):
            raise ValueError("Go CWE-1333 signal is invalid")
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
class GoCwe1333ScanResult:
    """Deterministic, source-free result for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe1333Signal, ...]
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
            type(item) is GoCwe1333Signal for item in self.signals
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
            if valid_signals
            else ()
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
            or not valid_signals
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
                self.signals,
            )
        ):
            raise ValueError("Go CWE-1333 scan result is invalid")


def scan_go_cwe1333(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe1333ScanLimits = DEFAULT_GO_CWE1333_SCAN_LIMITS,
) -> GoCwe1333ScanResult:
    """Find third-party backtracking-engine regex compilation sites.

    The stdlib ``regexp`` package and other RE2-compatible packages do not
    enter the sink table, so a valid file using only those packages returns a
    deterministic empty result.
    """

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
    except Exception:
        raise GoCwe1333ScanError(GoCwe1333ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    raw: set[tuple[SourceRange, SourceRange, GoCwe1333Operation]] = set()
    try:
        for scope in _scopes(root):
            for node in _scope_preorder(scope):
                if node.type != "call_expression":
                    continue
                sink = _backtracking_compile(node, source, imports)
                if sink is None:
                    continue
                operation, pattern = sink
                raw.add((_range(pattern), _range(node), operation))
                if len(raw) > limits.max_signals:
                    raise GoCwe1333ScanError(GoCwe1333ScanErrorCode.SIGNAL_LIMIT)
    except GoCwe1333ScanError:
        raise
    except Exception:
        raise GoCwe1333ScanError(GoCwe1333ScanErrorCode.INTEGRITY_FAILURE) from None

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
        raise GoCwe1333ScanError(GoCwe1333ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe1333Signal(
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
    return GoCwe1333ScanResult(
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


def scan_go_cwe1333_regex_dos(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe1333ScanLimits = DEFAULT_GO_CWE1333_SCAN_LIMITS,
) -> GoCwe1333ScanResult:
    """Descriptive alias for :func:`scan_go_cwe1333`."""

    return scan_go_cwe1333(symbol_index, limits=limits)


def scan_go_regex_dos(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe1333ScanLimits = DEFAULT_GO_CWE1333_SCAN_LIMITS,
) -> GoCwe1333ScanResult:
    """Compatibility alias for callers grouping Go regex scanners."""

    return scan_go_cwe1333(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe1333ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe1333ScanLimits:
        raise GoCwe1333ScanError(GoCwe1333ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe1333ScanError(GoCwe1333ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe1333ScanError(GoCwe1333ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe1333ScanError(GoCwe1333ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        package = _text(source, path_node).strip('"`')
        if package not in _BACKTRACKING_PACKAGES:
            continue
        name_node = node.child_by_field_name("name")
        alias = _text(source, name_node) if name_node is not None else package.rsplit("/", 1)[-1]
        if alias not in {".", "_"}:
            aliases[alias] = package
    return aliases


def _backtracking_compile(
    node: Node, source: bytes, imports: dict[str, str]
) -> tuple[GoCwe1333Operation, Node] | None:
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    values = arguments.named_children
    if operand is None or field is None or not values:
        return None
    package = imports.get(_text(source, operand))
    name = _text(source, field)
    operation = _BACKTRACKING_OPERATIONS.get((package or "", name))
    if operation is None:
        return None
    return operation, values[0]


def _scopes(root: Node) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node is root or node.type in _GO_SCOPES)


def _scope_preorder(scope: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    while stack:
        node = stack.pop()
        output.append(node)
        if node is not scope and node.type in _GO_SCOPES:
            continue
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _preorder(root: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        output.append(node)
        stack.extend(reversed(node.named_children))
    return tuple(output)


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
    operation: GoCwe1333Operation,
) -> str:
    material = {
        "content_sha256": content_sha256,
        "cwe": "CWE-1333",
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
    return "go-cwe1333-" + digest


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe1333Signal, ...],
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
    "DEFAULT_GO_CWE1333_SCAN_LIMITS",
    "GoCwe1333Operation",
    "GoCwe1333ScanError",
    "GoCwe1333ScanErrorCode",
    "GoCwe1333ScanLimits",
    "GoCwe1333ScanResult",
    "GoCwe1333Signal",
    "scan_go_cwe1333",
    "scan_go_cwe1333_regex_dos",
    "scan_go_regex_dos",
]
