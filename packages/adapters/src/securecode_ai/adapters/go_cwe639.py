"""Bounded Go facts for CWE-639 authorization bypass through a user key.

The detector follows request-derived record keys into repository-shaped lookup
methods.  A lookup is suppressed when an explicit ownership, tenant, or access
guard for the same key appears before it in the enclosing function.  The
analysis is deliberately conservative: unknown calls are not treated as
sanitizers or guards, and unknown receivers are not treated as repositories.

Only an admitted, healthy :class:`~securecode_ai.core.SymbolIndex` is accepted.
Returned values contain immutable identity, tree-sitter ranges, and hashes;
source text and parser diagnostics never leave this module.
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
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_RULE_ID = "securecode-go-cwe639"
_DETECTOR = "securecode-go-cwe639@1.0"
_DETAIL = "user_controlled_record_key_without_owner_guard"
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})

_HTTP_PACKAGE = "net/http"
_MUX_PACKAGES = frozenset(
    {
        "github.com/gorilla/mux",
        "github.com/go-chi/chi",
        "github.com/go-chi/chi/v5",
    }
)
_REQUEST_VALUE_METHODS = frozenset(
    {"FormValue", "PostFormValue", "PathValue", "QueryParam", "PathParam"}
)
_QUERY_VALUE_METHODS = frozenset({"Get", "Lookup"})
_REQUEST_RECEIVER_METHODS = frozenset({"Param", "Query", "QueryParam", "PathParam"})
_LOOKUP_METHODS = frozenset(
    {
        "Get",
        "Find",
        "Lookup",
        "GetByID",
        "FindByID",
        "LookupByID",
        "ByID",
        "FetchByID",
        "LoadByID",
    }
)
_LOOKUP_METHOD_NORMALIZED = frozenset(
    re.sub(r"[^a-z0-9]", "", name.lower()) for name in _LOOKUP_METHODS
)
_REPOSITORY_NAMES = frozenset(
    {
        "db",
        "dao",
        "repo",
        "repository",
        "store",
        "stores",
        "records",
        "objects",
        "collection",
        "collections",
        "users",
        "accounts",
        "resources",
    }
)
_REPOSITORY_MARKERS = (
    "repo",
    "repository",
    "store",
    "dao",
    "record",
    "object",
    "collection",
    "database",
)
_GUARD_MARKERS = (
    "authorize",
    "authorise",
    "ownership",
    "owner",
    "tenant",
    "access",
    "permission",
    "principal",
    "subject",
    "acl",
    "policy",
    "canaccess",
    "isallowed",
    "isowner",
    "require",
    "enforce",
    "assert",
    "verifyaccess",
    "checkaccess",
    "checkowner",
    "checktenant",
)
_IGNORED_GUARD_NAMES = frozenset(
    {
        "r",
        "req",
        "request",
        "ctx",
        "context",
        "w",
        "writer",
        "http",
        "url",
        "query",
        "header",
        "get",
        "lookup",
        "form",
        "value",
    }
)
_STRING_HELPERS = frozenset(
    {
        "fmt.Sprintf",
        "fmt.Sprint",
        "fmt.Sprintln",
        "strings.Join",
        "strings.Replace",
        "strings.ReplaceAll",
        "strings.TrimSpace",
        "strings.TrimPrefix",
        "strings.TrimSuffix",
        "strconv.Itoa",
        "strconv.FormatInt",
        "url.QueryUnescape",
    }
)


class GoCwe639ScanErrorCode(StrEnum):
    """Closed, source-free reasons a Go CWE-639 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe639ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe639ScanErrorCode) -> None:
        if type(code) is not GoCwe639ScanErrorCode:
            raise TypeError("Go CWE-639 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-639 authorization scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe639ScanLimits:
    """Hard ceilings applied before and during structural data-flow analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-639 scan limits are invalid")


DEFAULT_GO_CWE639_SCAN_LIMITS = GoCwe639ScanLimits()


class GoCwe639Operation(StrEnum):
    """Recognised repository lookup boundaries."""

    REPOSITORY_GET = "repository_get"
    REPOSITORY_FIND = "repository_find"
    REPOSITORY_LOOKUP = "repository_lookup"
    REPOSITORY_BY_ID = "repository_by_id"


@dataclass(frozen=True, slots=True)
class GoCwe639Signal:
    """One immutable request-to-record lookup fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe639Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-639"
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
            if identity_valid and ranges_valid and type(self.operation) is GoCwe639Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not GoCwe639Operation
            or expected_id is None
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-639"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-639 signal is invalid")
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
class GoCwe639ScanResult:
    """Deterministic, source-free CWE-639 output for one Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe639Signal, ...]
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
            type(item) is GoCwe639Signal for item in self.signals
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
            raise ValueError("Go CWE-639 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange
    names: frozenset[str]


def scan_go_cwe639(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe639ScanLimits = DEFAULT_GO_CWE639_SCAN_LIMITS,
) -> GoCwe639ScanResult:
    """Find bounded request-key flows into unguarded repository lookups."""

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
        _bounded_preorder(root, limits.max_expression_depth)
    except GoCwe639ScanError:
        raise
    except Exception:
        raise GoCwe639ScanError(GoCwe639ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    raw: set[tuple[SourceRange, SourceRange, GoCwe639Operation]] = set()
    try:
        for scope in _scopes(root):
            environment: dict[str, tuple[_Flow, ...]] = {}
            for node in _scope_preorder(scope):
                if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                    _capture_assignment(node, environment, source, imports, limits)
                    continue
                if node.type != "call_expression":
                    continue
                operation, arguments = _lookup_for_call(node, source, imports)
                if operation is None:
                    continue
                for argument in arguments:
                    for flow in _resolve(
                        argument, environment, source, imports, limits, 0, frozenset()
                    ):
                        sink_range = _range(node)
                        if flow.source.end_byte > sink_range.end_byte:
                            raise GoCwe639ScanError(GoCwe639ScanErrorCode.INTEGRITY_FAILURE)
                        if _guard_dominates(scope, node, flow, source, imports):
                            continue
                        raw.add((flow.source, sink_range, operation))
                        if len(raw) > limits.max_signals:
                            raise GoCwe639ScanError(GoCwe639ScanErrorCode.SIGNAL_LIMIT)
    except GoCwe639ScanError:
        raise
    except Exception:
        raise GoCwe639ScanError(GoCwe639ScanErrorCode.INTEGRITY_FAILURE) from None

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
        raise GoCwe639ScanError(GoCwe639ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe639Signal(
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
    return GoCwe639ScanResult(
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


def scan_go_authorization_bypass(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe639ScanLimits = DEFAULT_GO_CWE639_SCAN_LIMITS,
) -> GoCwe639ScanResult:
    """Descriptive alias for :func:`scan_go_cwe639`."""

    return scan_go_cwe639(symbol_index, limits=limits)


def scan_go_cwe639_object_authorization(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe639ScanLimits = DEFAULT_GO_CWE639_SCAN_LIMITS,
) -> GoCwe639ScanResult:
    """Compatibility alias for object-authorization scanner groups."""

    return scan_go_cwe639(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe639ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe639ScanLimits:
        raise GoCwe639ScanError(GoCwe639ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe639ScanError(GoCwe639ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe639ScanError(GoCwe639ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe639ScanError(GoCwe639ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    relevant = {
        _HTTP_PACKAGE,
        *_MUX_PACKAGES,
        "fmt",
        "strings",
        "strconv",
        "net/url",
    }
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


def _lookup_for_call(
    node: Node, source: bytes, imports: dict[str, str]
) -> tuple[GoCwe639Operation | None, tuple[Node, ...]]:
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None or function.type != "selector_expression":
        return None, ()
    field = function.child_by_field_name("field")
    operand = function.child_by_field_name("operand")
    if field is None or operand is None:
        return None, ()
    method = _text(source, field)
    receiver = _compact_text(source, operand)
    normalized = re.sub(r"[^a-z0-9]", "", method.lower())
    if normalized not in _LOOKUP_METHOD_NORMALIZED or not _repository_receiver(receiver):
        return None, ()
    operation = (
        GoCwe639Operation.REPOSITORY_GET
        if method == "Get"
        else GoCwe639Operation.REPOSITORY_FIND
        if method == "Find"
        else GoCwe639Operation.REPOSITORY_LOOKUP
        if method == "Lookup"
        else GoCwe639Operation.REPOSITORY_BY_ID
    )
    del imports
    return operation, tuple(arguments.named_children)


def _repository_receiver(receiver: str) -> bool:
    compact = receiver.replace("&", "").replace("(", "").replace(")", "")
    final = compact.rsplit(".", 1)[-1].lower()
    if final in _REPOSITORY_NAMES:
        return True
    return any(marker in final for marker in _REPOSITORY_MARKERS)


def _capture_assignment(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe639ScanLimits,
) -> None:
    names, values = _assignment_pairs(node)
    for name, value in zip(names, values, strict=False):
        if name.type != "identifier":
            continue
        name_text = _text(source, name)
        flows = _resolve(value, environment, source, imports, limits, 0, frozenset())
        environment[name_text] = tuple(
            _Flow(flow.source, flow.names | {_normal(name_text)}) for flow in flows
        )


def _assignment_pairs(node: Node) -> tuple[tuple[Node, ...], tuple[Node, ...]]:
    if node.type == "var_spec":
        names_node = node.child_by_field_name("name")
        values_node = node.child_by_field_name("value")
    else:
        names_node = node.child_by_field_name("left")
        values_node = node.child_by_field_name("right")
    if names_node is None or values_node is None:
        return (), ()
    names = tuple(names_node.named_children) or (names_node,)
    values = tuple(values_node.named_children) or (values_node,)
    if len(values) == 1 and len(names) > 1:
        values = values * len(names)
    return names, values


def _resolve(
    node: Node,
    environment: dict[str, tuple[_Flow, ...]],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe639ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[_Flow, ...]:
    if depth > limits.max_expression_depth:
        raise GoCwe639ScanError(GoCwe639ScanErrorCode.SIGNAL_LIMIT)
    direct = _external_source(node, source, imports)
    if direct is not None:
        return (_Flow(_range(direct), _source_names(source, direct)),)
    if node.type == "identifier":
        name = _text(source, node)
        normalized = _normal(name)
        if normalized in visited:
            return ()
        return tuple(
            _Flow(flow.source, flow.names | {normalized}) for flow in environment.get(name, ())
        )
    if node.type in {
        "parenthesized_expression",
        "unary_expression",
        "pointer_expression",
        "type_conversion_expression",
        "composite_literal",
        "keyed_element",
        "index_expression",
        "slice_expression",
        "selector_expression",
        "binary_expression",
    }:
        return _dedupe_flows(
            (
                flow
                for child in node.named_children
                for flow in _resolve(
                    child, environment, source, imports, limits, depth + 1, visited
                )
            ),
            limits,
        )
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            return ()
        qualified = _qualified_call(function, source, imports)
        if qualified in _STRING_HELPERS:
            return _dedupe_flows(
                (
                    flow
                    for argument in arguments.named_children
                    for flow in _resolve(
                        argument, environment, source, imports, limits, depth + 1, visited
                    )
                ),
                limits,
            )
        return ()
    return ()


def _external_source(node: Node, source: bytes, imports: dict[str, str]) -> Node | None:
    compact = _compact_text(source, node)
    if node.type == "index_expression" and compact.endswith("]"):
        prefix = compact.rsplit("[", 1)[0]
        if prefix.endswith((".URL.Query()", ".Form", ".PostForm", ".Header")):
            return node
        if ".Vars(" in prefix or ".Params(" in prefix:
            return node
    if node.type != "call_expression":
        return None
    function = node.child_by_field_name("function")
    if function is None:
        return None
    qualified = _qualified_call(function, source, imports)
    if qualified in {f"{package}.Vars" for package in _MUX_PACKAGES}:
        return node
    if qualified in {f"{package}.URLParam" for package in _MUX_PACKAGES}:
        return node
    if function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    name = _text(source, field)
    receiver = _compact_text(source, operand)
    if name in _REQUEST_VALUE_METHODS and _request_receiver(receiver):
        return node
    if name in _QUERY_VALUE_METHODS and receiver.endswith(
        (".URL.Query()", ".Form", ".PostForm", ".Header")
    ):
        return node
    if name in _REQUEST_RECEIVER_METHODS and _request_receiver(receiver):
        return node
    return None


def _request_receiver(value: str) -> bool:
    final = value.rsplit(".", 1)[-1].lower()
    return final in {"r", "req", "request", "ctx", "context", "c"}


def _guard_dominates(
    scope: Node,
    sink: Node,
    flow: _Flow,
    source: bytes,
    imports: dict[str, str],
) -> bool:
    for candidate in _scope_preorder(scope):
        if candidate == sink or candidate.start_byte >= sink.start_byte:
            continue
        if candidate.end_byte > sink.start_byte:
            continue
        if (
            candidate.type == "call_expression"
            and _is_guard_call(candidate, source, imports)
            and _guard_matches(candidate, flow, source)
        ):
            return True
        if candidate.type == "if_statement" and _is_guard_statement(
            candidate, flow, source, imports
        ):
            return True
    return False


def _is_guard_call(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    function = node.child_by_field_name("function")
    if function is None:
        return False
    name = _compact_text(source, function).lower()
    member = name.rsplit(".", 1)[-1]
    del imports
    if not member or member in _LOOKUP_METHOD_NORMALIZED:
        return False
    return any(marker in member for marker in _GUARD_MARKERS)


def _guard_matches(node: Node, flow: _Flow, source: bytes) -> bool:
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return False
    guard_names = {
        _normal(value)
        for argument in arguments.named_children
        for value in _IDENTIFIER.findall(_compact_text(source, argument))
    }
    guard_names -= _IGNORED_GUARD_NAMES
    flow_names = flow.names - _IGNORED_GUARD_NAMES
    return any(
        left == right or (len(left) >= 3 and left in right) or (len(right) >= 3 and right in left)
        for left in flow_names
        for right in guard_names
    )


def _is_guard_statement(
    node: Node,
    flow: _Flow,
    source: bytes,
    imports: dict[str, str],
) -> bool:
    condition = node.child_by_field_name("condition")
    consequence = node.child_by_field_name("consequence")
    if condition is None or consequence is None:
        return False
    for candidate in _preorder(condition):
        if (
            candidate.type == "call_expression"
            and _is_guard_call(candidate, source, imports)
            and _guard_matches(candidate, flow, source)
        ):
            return _has_early_exit(consequence)
    text = _compact_text(source, condition).lower()
    if not any(marker in text for marker in _GUARD_MARKERS):
        return False
    return _has_early_exit(consequence) and _guard_text_matches(text, flow)


def _has_early_exit(node: Node) -> bool:
    return any(
        child.type in {"return_statement", "branch_statement", "panic_statement"}
        for child in _preorder(node)
    )


def _guard_text_matches(text: str, flow: _Flow) -> bool:
    values = {_normal(value) for value in _IDENTIFIER.findall(text)}
    values -= _IGNORED_GUARD_NAMES
    names = flow.names - _IGNORED_GUARD_NAMES
    return any(
        left == right or (len(left) >= 3 and left in right) or (len(right) >= 3 and right in left)
        for left in names
        for right in values
    )


def _scopes(root: Node) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node.type in _GO_SCOPES)


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


def _bounded_preorder(root: Node, max_depth: int) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise GoCwe639ScanError(GoCwe639ScanErrorCode.ANALYSIS_UNAVAILABLE)
        output.append(node)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _dedupe_flows(flows: Iterable[_Flow], limits: GoCwe639ScanLimits) -> tuple[_Flow, ...]:
    unique: dict[tuple[int, int, tuple[str, ...]], _Flow] = {}
    for flow in flows:
        key = (flow.source.start_byte, flow.source.end_byte, tuple(sorted(flow.names)))
        unique[key] = flow
        if len(unique) > limits.max_signals:
            raise GoCwe639ScanError(GoCwe639ScanErrorCode.SIGNAL_LIMIT)
    return tuple(unique[key] for key in sorted(unique))


def _qualified_call(function: Node | None, source: bytes, imports: dict[str, str]) -> str:
    if function is None or function.type != "selector_expression":
        return ""
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None or operand.type != "identifier":
        return ""
    package = imports.get(_text(source, operand))
    return "" if package is None else f"{package}.{_text(source, field)}"


def _source_names(source: bytes, node: Node) -> frozenset[str]:
    names = {_normal(value) for value in _IDENTIFIER.findall(_compact_text(source, node))}
    return frozenset(sorted(names)[:32])


def _normal(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


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
    operation: GoCwe639Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-639",
        "detector": _DETECTOR,
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
    signals: tuple[GoCwe639Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-639",
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
                "detail": signal.detail,
                "detector": signal.detector,
                "operation": signal.operation.value,
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


Cwe639ScanErrorCode = GoCwe639ScanErrorCode
Cwe639ScanError = GoCwe639ScanError
Cwe639ScanLimits = GoCwe639ScanLimits
Cwe639ScanResult = GoCwe639ScanResult
Cwe639Signal = GoCwe639Signal


__all__ = [
    "DEFAULT_GO_CWE639_SCAN_LIMITS",
    "Cwe639ScanError",
    "Cwe639ScanErrorCode",
    "Cwe639ScanLimits",
    "Cwe639ScanResult",
    "Cwe639Signal",
    "GoCwe639Operation",
    "GoCwe639ScanError",
    "GoCwe639ScanErrorCode",
    "GoCwe639ScanLimits",
    "GoCwe639ScanResult",
    "GoCwe639Signal",
    "scan_go_authorization_bypass",
    "scan_go_cwe639",
    "scan_go_cwe639_object_authorization",
]
