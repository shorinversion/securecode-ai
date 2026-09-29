"""Bounded Go facts for CWE-367 time-of-check to time-of-use races.

The scanner consumes an admitted, sealed Go :class:`SymbolIndex` and reparses
the exact admitted bytes before inspecting the CST.  It recognises a bounded
local-path alias that is checked with ``os.Stat``, ``os.Lstat``, or an
``Access`` API and is subsequently used by ``Open``, ``OpenFile``, ``Remove``,
or ``Rename``.  ``OpenFile`` is suppressed when the source explicitly proves
atomic exclusive creation with ``O_CREATE | O_EXCL`` (or ``O_TMPFILE``).

Results contain only immutable source ranges and content-addressed metadata.
Source text is used during the walk but never appears in a result or an error
message.  The scanner reports a structural race candidate; it does not decide
whether an application-level authorization policy makes the operation safe.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
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
_MAX_ALIAS_KEYS = 256
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SIGNAL_ID = re.compile(r"go-cwe367-[0-9a-f]{64}\Z")
_RULE_ID = "securecode-go-cwe367"
_DETECTOR = "securecode-go-cwe367@1.0"

_OS_PACKAGE = "os"
_ACCESS_PACKAGES = frozenset({"syscall", "golang.org/x/sys/unix", "golang.org/x/sys"})
_PATH_PACKAGES = frozenset({"path/filepath", "path"})
_CHECKS: dict[tuple[str, str], str] = {
    (_OS_PACKAGE, "Stat"): "stat",
    (_OS_PACKAGE, "Lstat"): "lstat",
    ("syscall", "Access"): "access",
    ("golang.org/x/sys/unix", "Access"): "access",
    ("golang.org/x/sys", "Access"): "access",
}
_SINKS: dict[tuple[str, str], str] = {
    (_OS_PACKAGE, "Open"): "open",
    (_OS_PACKAGE, "OpenFile"): "open_file",
    (_OS_PACKAGE, "Create"): "open",
    ("io/ioutil", "ReadFile"): "open",
    (_OS_PACKAGE, "Remove"): "remove",
    (_OS_PACKAGE, "RemoveAll"): "remove",
    (_OS_PACKAGE, "Rename"): "rename",
}
_PATH_BUILDERS = frozenset({"Abs", "Clean", "FromSlash", "Join", "Rel", "ToSlash", "VolumeName"})
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})


class GoCwe367ScanErrorCode(StrEnum):
    """Closed, source-free reasons a Go CWE-367 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe367ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe367ScanErrorCode) -> None:
        if type(code) is not GoCwe367ScanErrorCode:
            raise TypeError("Go CWE-367 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-367 TOCTOU scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe367ScanLimits:
    """Hard ceilings applied before and during structural race analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-367 scan limits are invalid")


DEFAULT_GO_CWE367_SCAN_LIMITS = GoCwe367ScanLimits()


class GoCwe367Operation(StrEnum):
    """Recognised precheck-to-filesystem-use combinations."""

    STAT_THEN_OPEN = "os.Stat->os.Open"
    STAT_THEN_OPEN_FILE = "os.Stat->os.OpenFile"
    STAT_THEN_REMOVE = "os.Stat->os.Remove"
    STAT_THEN_RENAME = "os.Stat->os.Rename"
    LSTAT_THEN_OPEN = "os.Lstat->os.Open"
    LSTAT_THEN_OPEN_FILE = "os.Lstat->os.OpenFile"
    LSTAT_THEN_REMOVE = "os.Lstat->os.Remove"
    LSTAT_THEN_RENAME = "os.Lstat->os.Rename"
    ACCESS_THEN_OPEN = "Access->os.Open"
    ACCESS_THEN_OPEN_FILE = "Access->os.OpenFile"
    ACCESS_THEN_REMOVE = "Access->os.Remove"
    ACCESS_THEN_RENAME = "Access->os.Rename"

    # Short aliases used by generic scanner consumers.
    STAT_OPEN = "os.Stat->os.Open"
    STAT_OPEN_FILE = "os.Stat->os.OpenFile"
    STAT_REMOVE = "os.Stat->os.Remove"
    STAT_RENAME = "os.Stat->os.Rename"
    LSTAT_OPEN = "os.Lstat->os.Open"
    LSTAT_OPEN_FILE = "os.Lstat->os.OpenFile"
    LSTAT_REMOVE = "os.Lstat->os.Remove"
    LSTAT_RENAME = "os.Lstat->os.Rename"
    ACCESS_OPEN = "Access->os.Open"
    ACCESS_OPEN_FILE = "Access->os.OpenFile"
    ACCESS_REMOVE = "Access->os.Remove"
    ACCESS_RENAME = "Access->os.Rename"


@dataclass(frozen=True, slots=True)
class GoCwe367Signal:
    """One immutable, source-free TOCTOU candidate."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe367Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-367"
    detector: str = _DETECTOR
    detail: str = "checked_path_reused_for_file_operation"

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
            and self.source.end_byte <= self.sink.start_byte
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
            if valid_identity and valid_ranges and type(self.operation) is GoCwe367Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not GoCwe367Operation
            or type(signal_id) is not str
            or _SIGNAL_ID.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-367"
            or self.detector != _DETECTOR
            or self.detail != "checked_path_reused_for_file_operation"
        ):
            raise ValueError("Go CWE-367 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

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
class GoCwe367ScanResult:
    """Deterministic, source-free CWE-367 output for one Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe367Signal, ...]
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
        )
        if valid_identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid_identity = False
        valid_signals = type(self.signals) is tuple and all(
            type(item) is GoCwe367Signal for item in self.signals
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
            not valid_identity
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
            raise ValueError("Go CWE-367 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Check:
    kind: str
    location: SourceRange


def scan_go_cwe367(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe367ScanLimits = DEFAULT_GO_CWE367_SCAN_LIMITS,
) -> GoCwe367ScanResult:
    """Find bounded precheck-to-file-operation sequences in Go."""

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
        raise GoCwe367ScanError(GoCwe367ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    raw: set[tuple[SourceRange, SourceRange, GoCwe367Operation]] = set()
    try:
        for scope in _scopes(root):
            aliases: dict[str, frozenset[str]] = {}
            flags: dict[str, frozenset[str]] = {}
            checks: dict[str, _Check] = {}
            for node in _scope_preorder(scope):
                if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                    changed = _capture_bindings(node, aliases, flags, source, imports, limits, 0)
                    for alias in changed:
                        checks.pop(alias, None)
                if node.type != "call_expression":
                    continue
                call = _qualified_call(node, source, imports)
                if call is None:
                    continue
                package, name = call
                arguments = node.child_by_field_name("arguments")
                values = tuple(arguments.named_children) if arguments is not None else ()
                check_kind = _CHECKS.get((package, name))
                if check_kind is not None:
                    if not values:
                        continue
                    for alias in _resolve_aliases(values[0], aliases, source, imports, limits, 0):
                        checks[alias] = _Check(check_kind, _range(node))
                    continue
                sink_kind = _SINKS.get((package, name))
                if sink_kind is None or not values:
                    continue
                if sink_kind == "open_file" and _is_atomic_open_file(
                    values, flags, source, imports
                ):
                    continue
                sink_arguments = values[:2] if name == "Rename" else values[:1]
                sink_range = _range(node)
                for argument in sink_arguments:
                    for alias in _resolve_aliases(argument, aliases, source, imports, limits, 0):
                        check = checks.get(alias)
                        if check is None or check.location.start_byte >= sink_range.start_byte:
                            continue
                        operation = _operation(check.kind, sink_kind)
                        if operation is None:
                            continue
                        raw.add((check.location, sink_range, operation))
                        if len(raw) > limits.max_signals:
                            raise GoCwe367ScanError(GoCwe367ScanErrorCode.SIGNAL_LIMIT)
    except GoCwe367ScanError:
        raise
    except Exception:
        raise GoCwe367ScanError(GoCwe367ScanErrorCode.INTEGRITY_FAILURE) from None

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
        raise GoCwe367ScanError(GoCwe367ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe367Signal(
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
    return GoCwe367ScanResult(
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


def scan_go_cwe367_toctou(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe367ScanLimits = DEFAULT_GO_CWE367_SCAN_LIMITS,
) -> GoCwe367ScanResult:
    """Descriptive alias for :func:`scan_go_cwe367`."""

    return scan_go_cwe367(symbol_index, limits=limits)


def scan_go_toctou(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe367ScanLimits = DEFAULT_GO_CWE367_SCAN_LIMITS,
) -> GoCwe367ScanResult:
    """Compatibility alias for callers grouping Go race scans."""

    return scan_go_cwe367(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe367ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe367ScanLimits:
        raise GoCwe367ScanError(GoCwe367ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe367ScanError(GoCwe367ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe367ScanError(GoCwe367ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe367ScanError(GoCwe367ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    relevant = {_OS_PACKAGE, *_ACCESS_PACKAGES, *_PATH_PACKAGES, "io/ioutil"}
    aliases: dict[str, str] = {}
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        package = _text(source, path_node).strip('"`')
        if package not in relevant:
            continue
        name_node = node.child_by_field_name("name")
        alias = _text(source, name_node) if name_node is not None else package.rsplit("/", 1)[-1]
        if alias not in {".", "_"}:
            aliases[alias] = package
    return aliases


def _qualified_call(node: Node, source: bytes, imports: dict[str, str]) -> tuple[str, str] | None:
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None or operand.type != "identifier":
        return None
    package = imports.get(_text(source, operand))
    return None if package is None else (package, _text(source, field))


def _capture_bindings(
    node: Node,
    aliases: dict[str, frozenset[str]],
    flags: dict[str, frozenset[str]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe367ScanLimits,
    depth: int,
) -> frozenset[str]:
    if depth > limits.max_expression_depth:
        raise GoCwe367ScanError(GoCwe367ScanErrorCode.SIGNAL_LIMIT)
    if node.type == "var_spec":
        names_node = node.child_by_field_name("name")
        values_node = node.child_by_field_name("value")
        if names_node is None or values_node is None:
            return frozenset()
        names = tuple(names_node.named_children) or (names_node,)
        values = tuple(values_node.named_children) or (values_node,)
    else:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return frozenset()
        names = tuple(left.named_children) if left.type == "expression_list" else (left,)
        values = tuple(right.named_children) if right.type == "expression_list" else (right,)
    changed: set[str] = set()
    if len(values) == 1 and len(names) > 1:
        values = values * len(names)
    for name, value in zip(names, values, strict=False):
        if name.type != "identifier":
            continue
        name_text = _text(source, name)
        previous = aliases.get(name_text, frozenset())
        changed.update(previous)
        changed.add("name:" + name_text)
        resolved = _resolve_aliases(value, aliases, source, imports, limits, depth + 1)
        if resolved:
            aliases[name_text] = resolved
        else:
            aliases.pop(name_text, None)
        flag_values = _resolve_flags(value, flags, source, imports, limits, depth + 1)
        if flag_values:
            flags[name_text] = flag_values
        else:
            flags.pop(name_text, None)
    return frozenset(changed)


def _resolve_aliases(
    node: Node,
    aliases: dict[str, frozenset[str]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe367ScanLimits,
    depth: int,
    visited: frozenset[str] = frozenset(),
) -> frozenset[str]:
    if depth > limits.max_expression_depth:
        raise GoCwe367ScanError(GoCwe367ScanErrorCode.SIGNAL_LIMIT)
    if node.type == "identifier":
        name = _text(source, node)
        if name in visited:
            return frozenset()
        value = aliases.get(name)
        return value if value is not None else frozenset({"name:" + name})
    if node.type in {"parenthesized_expression", "unary_expression", "pointer_expression"}:
        return _union_aliases(
            _resolve_aliases(child, aliases, source, imports, limits, depth + 1, visited)
            for child in node.named_children
        )
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            return frozenset()
        if _is_path_builder(function, source, imports):
            return _union_aliases(
                _resolve_aliases(argument, aliases, source, imports, limits, depth + 1, visited)
                for argument in arguments.named_children
            )
    if node.type in {"binary_expression", "index_expression", "slice_expression"}:
        return _union_aliases(
            _resolve_aliases(child, aliases, source, imports, limits, depth + 1, visited)
            for child in node.named_children
        )
    compact = _compact_text(source, node)
    if not compact:
        return frozenset()
    return frozenset({"expr:" + hashlib.sha256(compact.encode("utf-8")).hexdigest()})


def _resolve_flags(
    node: Node,
    flags: dict[str, frozenset[str]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe367ScanLimits,
    depth: int,
) -> frozenset[str]:
    if depth > limits.max_expression_depth:
        raise GoCwe367ScanError(GoCwe367ScanErrorCode.SIGNAL_LIMIT)
    if node.type == "identifier":
        return flags.get(_text(source, node), frozenset())
    if node.type in {"parenthesized_expression", "unary_expression"}:
        return _union_flags(
            _resolve_flags(child, flags, source, imports, limits, depth + 1)
            for child in node.named_children
        )
    if node.type == "selector_expression":
        operand = node.child_by_field_name("operand")
        field = node.child_by_field_name("field")
        if operand is None or field is None:
            return frozenset()
        package = imports.get(_text(source, operand))
        name = _text(source, field)
        if package in {_OS_PACKAGE, "syscall", "golang.org/x/sys/unix"} and name.startswith("O_"):
            return frozenset({name})
        return frozenset()
    if node.type == "binary_expression":
        return _union_flags(
            _resolve_flags(child, flags, source, imports, limits, depth + 1)
            for child in node.named_children
        )
    return frozenset()


def _is_atomic_open_file(
    values: tuple[Node, ...],
    flags: dict[str, frozenset[str]],
    source: bytes,
    imports: dict[str, str],
) -> bool:
    if len(values) < 2:
        return False
    names = _resolve_flags(values[1], flags, source, imports, DEFAULT_GO_CWE367_SCAN_LIMITS, 0)
    return "O_TMPFILE" in names or {"O_CREATE", "O_EXCL"}.issubset(names)


def _is_path_builder(function: Node | None, source: bytes, imports: dict[str, str]) -> bool:
    if function is None or function.type != "selector_expression":
        return False
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    return (
        operand is not None
        and field is not None
        and imports.get(_text(source, operand)) in _PATH_PACKAGES
        and _text(source, field) in _PATH_BUILDERS
    )


def _operation(check_kind: str, sink_kind: str) -> GoCwe367Operation | None:
    values = {
        ("stat", "open"): GoCwe367Operation.STAT_THEN_OPEN,
        ("stat", "open_file"): GoCwe367Operation.STAT_THEN_OPEN_FILE,
        ("stat", "remove"): GoCwe367Operation.STAT_THEN_REMOVE,
        ("stat", "rename"): GoCwe367Operation.STAT_THEN_RENAME,
        ("lstat", "open"): GoCwe367Operation.LSTAT_THEN_OPEN,
        ("lstat", "open_file"): GoCwe367Operation.LSTAT_THEN_OPEN_FILE,
        ("lstat", "remove"): GoCwe367Operation.LSTAT_THEN_REMOVE,
        ("lstat", "rename"): GoCwe367Operation.LSTAT_THEN_RENAME,
        ("access", "open"): GoCwe367Operation.ACCESS_THEN_OPEN,
        ("access", "open_file"): GoCwe367Operation.ACCESS_THEN_OPEN_FILE,
        ("access", "remove"): GoCwe367Operation.ACCESS_THEN_REMOVE,
        ("access", "rename"): GoCwe367Operation.ACCESS_THEN_RENAME,
    }
    return values.get((check_kind, sink_kind))


def _union_aliases(values: Iterable[frozenset[str]]) -> frozenset[str]:
    output: set[str] = set()
    for value in values:
        output.update(value)
        if len(output) > _MAX_ALIAS_KEYS:
            raise GoCwe367ScanError(GoCwe367ScanErrorCode.SIGNAL_LIMIT)
    return frozenset(output)


def _union_flags(values: Iterable[frozenset[str]]) -> frozenset[str]:
    output: set[str] = set()
    for value in values:
        output.update(value)
    return frozenset(output)


def _scopes(root: Node) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node == root or node.type in _GO_SCOPES)


def _scope_preorder(scope: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    while stack:
        node = stack.pop()
        output.append(node)
        if node != scope and node.type in _GO_SCOPES:
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


def _compact_text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return "".join(_text(source, node).split())


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
    operation: GoCwe367Operation,
) -> str:
    material = {
        "content_sha256": content_sha256,
        "cwe": "CWE-367",
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
    return "go-cwe367-" + digest


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe367Signal, ...],
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
    "DEFAULT_GO_CWE367_SCAN_LIMITS",
    "GoCwe367Operation",
    "GoCwe367ScanError",
    "GoCwe367ScanErrorCode",
    "GoCwe367ScanLimits",
    "GoCwe367ScanResult",
    "GoCwe367Signal",
    "scan_go_cwe367",
    "scan_go_cwe367_toctou",
    "scan_go_toctou",
]
