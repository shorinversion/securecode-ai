"""Bounded Go facts for missing authorization checks on sensitive mutations.

This adapter is intentionally narrower than authentication analysis (CWE-306)
and object-key authorization analysis (CWE-639). It recognizes sensitive
repository or account mutations inside ``net/http`` handlers and checks for an
authorization-specific guard in an ``if`` condition. Authentication-only
checks do not suppress a candidate. It consumes one admitted Go ``SymbolIndex``
and returns source-free identities and ranges only.
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

_MAX_LIMITS = (2_000_000, 2_048, 64, 50_000)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-go-cwe862"
_DETECTOR = "securecode-go-cwe862@1.0"
_DETAIL = "sensitive_mutation_without_authorization_guard"
_HTTP_PACKAGE = "net/http"
_HANDLER_TYPES = frozenset({"function_declaration", "method_declaration", "func_literal"})
_ROUTE_METHODS = frozenset(
    {"handle", "handlefunc", "get", "post", "put", "patch", "delete", "options", "head"}
)
_SENSITIVE_ROUTE = re.compile(
    r"(?:^|[/_-])(?:admin|account|accounts|billing|tenant|tenants|users?|"
    r"roles?|permissions?|settings|secrets?|credentials?)(?:[/_-]|$)",
    re.IGNORECASE,
)
_MUTATION_METHODS = frozenset(
    {
        "create",
        "delete",
        "destroy",
        "exec",
        "insert",
        "modify",
        "remove",
        "revoke",
        "save",
        "setrole",
        "setpermission",
        "update",
        "upsert",
        "write",
    }
)
_MUTATION_RECEIVERS = frozenset(
    {
        "account",
        "accounts",
        "db",
        "database",
        "dao",
        "manager",
        "repo",
        "repository",
        "role",
        "store",
        "tenant",
        "user",
        "users",
    }
)
_AUTHZ_MARKERS = frozenset(
    {
        "acl",
        "authorize",
        "authorise",
        "canaccess",
        "checkaccess",
        "checkpermission",
        "haspermission",
        "hasrole",
        "isadmin",
        "isowner",
        "ownsresource",
        "permission",
        "policy",
        "requirepermission",
        "requirepermissions",
        "requirerole",
        "tenantguard",
    }
)
_AUTHZ_PATTERN = re.compile(
    r"(?:authorize|authorise|canaccess|checkaccess|checkpermission|haspermission|"
    r"hasrole|isadmin|isowner|ownsresource|requirepermission|requirerole|"
    r"tenantguard|permission|acl|policy)",
    re.IGNORECASE,
)
_DENIAL_PATTERN = re.compile(
    r"(?:return|http\.error|statusforbidden|statusunauthorized|forbidden|"
    r"unauthorized|abort\s*\(\s*(?:401|403))",
    re.IGNORECASE,
)
_RESOURCE_IGNORED_NAMES = frozenset(
    {
        "body",
        "context",
        "ctx",
        "data",
        "db",
        "err",
        "error",
        "log",
        "logger",
        "payload",
        "r",
        "req",
        "request",
        "response",
        "rw",
        "tx",
        "txn",
        "w",
        "writer",
    }
)


class GoCwe862ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-862 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe862ScanError(RuntimeError):
    """Fixed scanner failure which never echoes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe862ScanErrorCode) -> None:
        if type(code) is not GoCwe862ScanErrorCode:
            raise TypeError("Go CWE-862 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-862 authorization scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe862ScanLimits:
    """Hard ceilings applied before and during syntax-tree analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]
    max_nodes: int = _MAX_LIMITS[3]

    def __post_init__(self) -> None:
        values = (
            self.max_source_bytes,
            self.max_signals,
            self.max_expression_depth,
            self.max_nodes,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-862 scan limits are invalid")


DEFAULT_GO_CWE862_SCAN_LIMITS = GoCwe862ScanLimits()


class GoCwe862Operation(StrEnum):
    """Recognized sensitive mutation boundaries."""

    CREATE = "sensitive_create"
    DELETE = "sensitive_delete"
    EXECUTE = "sensitive_execute"
    INSERT = "sensitive_insert"
    REVOKE = "sensitive_revoke"
    SAVE = "sensitive_save"
    UPDATE = "sensitive_update"
    WRITE = "sensitive_write"


@dataclass(frozen=True, slots=True)
class GoCwe862Signal:
    """One immutable source-free missing-authorization candidate."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe862Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-862"
    detector: str = _DETECTOR
    detail: str = _DETAIL

    def __post_init__(self) -> None:
        identity_ok = (
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
        if identity_ok:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity_ok = False
        ranges_ok = (
            type(self.source) is SourceRange
            and type(self.sink) is SourceRange
            and self.sink.contains(self.source)
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
            if identity_ok and ranges_ok and type(self.operation) is GoCwe862Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_ok
            or not ranges_ok
            or type(self.operation) is not GoCwe862Operation
            or expected_id is None
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-862"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-862 signal is invalid")
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
class GoCwe862ScanResult:
    """Deterministic output for one admitted Go source file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe862Signal, ...]
    scan_sha256: str

    def __post_init__(self) -> None:
        identity_ok = (
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
        if identity_ok:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity_ok = False
        signals_ok = type(self.signals) is tuple and all(
            type(item) is GoCwe862Signal for item in self.signals
        )
        keys = (
            tuple(
                (
                    item.sink.start_byte,
                    item.sink.end_byte,
                    item.source.start_byte,
                    item.operation.value,
                )
                for item in self.signals
            )
            if signals_ok
            else ()
        )
        same_identity = signals_ok and all(
            (
                item.repository_id,
                item.revision,
                item.path,
                item.content_sha256,
                item.source_size_bytes,
            )
            == (
                self.repository_id,
                self.revision,
                self.path,
                self.content_sha256,
                self.source_size_bytes,
            )
            for item in self.signals
        )
        if (
            not identity_ok
            or not signals_ok
            or keys != tuple(sorted(keys))
            or len(keys) != len(set(keys))
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
            raise ValueError("Go CWE-862 scan result is invalid")


def scan_go_cwe862(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe862ScanLimits = DEFAULT_GO_CWE862_SCAN_LIMITS,
) -> GoCwe862ScanResult:
    """Find sensitive Go HTTP mutations with no recognized authz guard."""

    _validate(symbol_index, limits)
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
        source.decode("utf-8", errors="strict")
        root = Parser(Language(_go_language())).parse(source).root_node
        if root.has_error:
            raise ValueError("parse error")
        nodes = _bounded_preorder(root, limits)
    except Exception:
        raise GoCwe862ScanError(GoCwe862ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(nodes, source)
    scopes = tuple(node for node in nodes if node.type in _HANDLER_TYPES)
    route_scopes = _registered_sensitive_handlers(nodes, source)
    facts: set[tuple[SourceRange, SourceRange, GoCwe862Operation]] = set()
    for scope in scopes:
        if not _is_http_handler(scope, source, imports):
            continue
        if not _sensitive_scope(scope, source, route_scopes):
            continue
        for node in _scope_preorder(scope, limits.max_nodes):
            if node.type != "call_expression":
                continue
            operation = _sensitive_mutation(node, source)
            if operation is None:
                continue
            if _has_authorization_guard(scope, source, node):
                continue
            facts.add((_range(node), _range(scope), operation))
            if len(facts) > limits.max_signals:
                raise GoCwe862ScanError(GoCwe862ScanErrorCode.SIGNAL_LIMIT)

    ordered = tuple(
        sorted(
            facts,
            key=lambda item: (
                item[1].start_byte,
                item[1].end_byte,
                item[0].start_byte,
                item[2].value,
            ),
        )
    )
    signals = tuple(
        GoCwe862Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
        )
        for source_range, sink_range, operation in ordered
    )
    return GoCwe862ScanResult(
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


def _validate(index: SymbolIndex, limits: GoCwe862ScanLimits) -> None:
    if type(index) is not SymbolIndex or type(limits) is not GoCwe862ScanLimits:
        raise GoCwe862ScanError(GoCwe862ScanErrorCode.REQUEST_INVALID)
    if index.language != "go":
        raise GoCwe862ScanError(GoCwe862ScanErrorCode.REQUEST_INVALID)
    if len(index.source) > limits.max_source_bytes:
        raise GoCwe862ScanError(GoCwe862ScanErrorCode.SOURCE_LIMIT)
    if index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe862ScanError(GoCwe862ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _bounded_preorder(root: Node, limits: GoCwe862ScanLimits) -> tuple[Node, ...]:
    result: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_expression_depth:
            raise GoCwe862ScanError(GoCwe862ScanErrorCode.ANALYSIS_UNAVAILABLE)
        result.append(node)
        if len(result) > limits.max_nodes:
            raise GoCwe862ScanError(GoCwe862ScanErrorCode.ANALYSIS_UNAVAILABLE)
        stack.extend((child, depth + 1) for child in reversed(node.children))
    return tuple(result)


def _preorder(root: Node, max_nodes: int) -> tuple[Node, ...]:
    result: list[Node] = []
    stack = [root]
    while stack and len(result) <= max_nodes:
        node = stack.pop()
        result.append(node)
        stack.extend(reversed(node.children))
    if stack:
        raise GoCwe862ScanError(GoCwe862ScanErrorCode.ANALYSIS_UNAVAILABLE)
    return tuple(result)


def _import_aliases(nodes: tuple[Node, ...], source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in nodes:
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        path = _text(source, path_node).strip('"`')
        name_node = node.child_by_field_name("name")
        alias = _text(source, name_node) if name_node is not None else path.rsplit("/", 1)[-1]
        if alias not in {".", "_"}:
            aliases[alias] = path
    return aliases


def _is_http_handler(scope: Node, source: bytes, imports: dict[str, str]) -> bool:
    parameters = scope.child_by_field_name("parameters")
    if parameters is None:
        return False
    compact = _compact(source, parameters).lower()
    aliases = tuple(alias.lower() for alias, path in imports.items() if path == _HTTP_PACKAGE)
    return (
        "request" in compact
        and "responsewriter" in compact
        and any(
            f"{alias}.request" in compact and f"{alias}.responsewriter" in compact
            for alias in aliases
        )
    )


def _registered_sensitive_handlers(nodes: tuple[Node, ...], source: bytes) -> frozenset[str]:
    targets: set[str] = set()
    for node in nodes:
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            continue
        if _call_name(function, source).rsplit(".", 1)[-1].lower() not in _ROUTE_METHODS:
            continue
        args = _preorder(arguments, _MAX_LIMITS[3])
        if not any(
            child.type in {"interpreted_string_literal", "raw_string_literal"}
            and _SENSITIVE_ROUTE.search(_text(source, child).strip('"`'))
            for child in args
        ):
            continue
        targets.update(
            _text(source, child)
            for child in args
            if child.type in {"identifier", "field_identifier"}
            and _text(source, child).lower() not in {"nil", "router", "mux", "r", "http"}
        )
    return frozenset(targets)


def _sensitive_scope(scope: Node, source: bytes, route_scopes: frozenset[str]) -> bool:
    name_node = scope.child_by_field_name("name")
    name = _text(source, name_node) if name_node is not None else ""
    compact_name = re.sub(r"[^a-z0-9]", "", name.lower())
    registered = name in route_scopes
    sensitive_name = any(
        part in compact_name
        for part in (
            "admin",
            "account",
            "billing",
            "permission",
            "role",
            "tenant",
            "user",
            "credential",
        )
    )
    if registered or sensitive_name or _has_sensitive_route_ancestor(scope, source):
        return True
    # Unregistered handlers still need a local sensitive route string or
    # authorization-sensitive object name before their mutation is considered.
    body = scope.child_by_field_name("body")
    return body is not None and bool(_SENSITIVE_ROUTE.search(_compact(source, body)))


def _has_authorization_guard(scope: Node, source: bytes, mutation: Node) -> bool:
    for node in _scope_preorder(scope, _MAX_LIMITS[3]):
        if node.type != "if_statement":
            continue
        condition = node.child_by_field_name("condition")
        consequence = node.child_by_field_name("consequence")
        if condition is None or consequence is None or not _guard_dominates(node, mutation, source):
            continue
        denial_branch = _denial_branch(node, source)
        if denial_branch is None:
            continue
        if not _same_resource(condition, mutation, source):
            continue
        if _contains_authz_call(condition, source):
            return True
    return False


def _guard_dominates(guard: Node, mutation: Node, source: bytes) -> bool:
    """Return whether an early-return guard runs on every path to a mutation."""

    if guard.start_byte >= mutation.start_byte:
        return False
    guard_block = _nearest_block(guard)
    mutation_block = _nearest_block(mutation)
    if guard_block is None or mutation_block is None:
        return False
    if _same_node(guard_block, mutation_block):
        guard_index = _child_index(guard_block, guard)
        mutation_child = _child_under(mutation, mutation_block)
        mutation_index = _child_index(mutation_block, mutation_child)
        return guard_index >= 0 and mutation_index > guard_index

    branch = _branch_under(mutation, guard)
    if branch is None:
        return False
    consequence = guard.child_by_field_name("consequence")
    alternative = guard.child_by_field_name("alternative")
    denial_branch = _denial_branch(guard, source)
    if denial_branch is None:
        return False
    return not _same_node(branch, denial_branch) and (
        _same_node(branch, consequence) or _same_node(branch, alternative)
    )


def _nearest_block(node: Node) -> Node | None:
    current = node.parent
    while current is not None:
        if current.type == "block":
            return next(
                (child for child in current.named_children if child.type == "statement_list"),
                current,
            )
        current = current.parent
    return None


def _child_under(node: Node, ancestor: Node) -> Node | None:
    current = node
    while current.parent is not None and not _same_node(current.parent, ancestor):
        current = current.parent
    return current if current.parent is not None and _same_node(current.parent, ancestor) else None


def _child_index(parent: Node | None, child: Node | None) -> int:
    if parent is None or child is None:
        return -1
    return next(
        (
            index
            for index, candidate in enumerate(parent.named_children)
            if _same_node(candidate, child)
        ),
        -1,
    )


def _same_node(left: Node | None, right: Node | None) -> bool:
    return (
        left is not None
        and right is not None
        and left.type == right.type
        and left.start_byte == right.start_byte
        and left.end_byte == right.end_byte
    )


def _branch_under(node: Node, ancestor: Node) -> Node | None:
    current = node
    while current.parent is not None and not _same_node(current.parent, ancestor):
        current = current.parent
    if current.parent is None or not _same_node(current.parent, ancestor):
        return None
    consequence = ancestor.child_by_field_name("consequence")
    alternative = ancestor.child_by_field_name("alternative")
    return current if _same_node(current, consequence) or _same_node(current, alternative) else None


def _denial_branch(guard: Node, source: bytes | None) -> Node | None:
    """Identify the branch that stops an unauthorized request."""

    consequence = guard.child_by_field_name("consequence")
    alternative = guard.child_by_field_name("alternative")
    if consequence is None:
        return None
    if source is None:
        return consequence
    condition = guard.child_by_field_name("condition")
    if condition is None:
        return None
    condition_text = _compact(source, condition)
    if _is_denial_text(condition_text, consequence, source, is_alternative=False):
        return consequence
    if alternative is not None and _is_denial_text(
        condition_text, alternative, source, is_alternative=True
    ):
        return alternative
    return None


def _is_denial_text(
    condition_text: str,
    branch: Node,
    source: bytes,
    *,
    is_alternative: bool,
) -> bool:
    branch_text = _compact(source, branch)
    if not _DENIAL_PATTERN.search(branch_text):
        return False
    if not _branch_has_terminal_exit(branch, source):
        return False
    if any(
        marker in branch_text.lower()
        for marker in (
            "http.error",
            "statusforbidden",
            "statusunauthorized",
            "forbidden",
            "unauthorized",
            "abort(401",
            "abort(403",
        )
    ):
        return True
    # A bare return is a denial only when the authorization predicate is
    # negated. This avoids treating an unrelated successful early return as a
    # security guard.
    negative = _negative_condition(condition_text)
    return not negative if is_alternative else negative


def _negative_condition(condition_text: str) -> bool:
    return bool(
        re.search(r"(?:^|[(!])!\s*[a-z_][a-z0-9_.]*", condition_text, re.IGNORECASE)
        or re.search(r"(?:==|!=)false\b", condition_text, re.IGNORECASE)
    )


def _branch_has_terminal_exit(branch: Node, source: bytes) -> bool:
    body = branch if branch.type == "block" else branch.child_by_field_name("body")
    if body is None:
        body = next(
            (child for child in branch.named_children if child.type == "block"),
            None,
        )
    if body is not None and body.type == "block":
        body = next(
            (child for child in body.named_children if child.type == "statement_list"),
            body,
        )
    if body is None or not body.named_children:
        return False
    last = body.named_children[-1]
    if last.type == "return_statement":
        return True
    if last.type == "expression_statement":
        return bool(
            re.match(
                r"(?:panic|runtime\.Goexit)\s*\(",
                _compact(source, last),
            )
        )
    return False


def _same_resource(condition: Node, mutation: Node, source: bytes) -> bool:
    guard_keys: set[str] = set()
    for call in _authz_calls(condition, source):
        arguments = call.child_by_field_name("arguments")
        if arguments is not None:
            guard_keys.update(_resource_keys(arguments, source))
    if not guard_keys:
        return False
    arguments = mutation.child_by_field_name("arguments")
    if arguments is None:
        return False
    return bool(guard_keys & _resource_keys(arguments, source))


def _resource_keys(node: Node, source: bytes) -> set[str]:
    keys: set[str] = set()
    for child in _preorder(node, _MAX_LIMITS[3]):
        if child.type not in {"identifier", "field_identifier"}:
            continue
        value = re.sub(r"[^a-z0-9]", "", _text(source, child).lower())
        if value and value not in _RESOURCE_IGNORED_NAMES:
            keys.add(value)
    return keys


def _authz_calls(node: Node, source: bytes) -> tuple[Node, ...]:
    return tuple(
        child
        for child in _preorder(node, _MAX_LIMITS[3])
        if child.type == "call_expression"
        and (function := child.child_by_field_name("function")) is not None
        and _AUTHZ_PATTERN.search(_call_name(function, source))
    )


def _has_sensitive_route_ancestor(scope: Node, source: bytes) -> bool:
    ancestor = scope.parent
    hops = 0
    while ancestor is not None and hops < 12:
        if ancestor.type == "call_expression":
            function = ancestor.child_by_field_name("function")
            arguments = ancestor.child_by_field_name("arguments")
            if function is not None and arguments is not None:
                method = _call_name(function, source).rsplit(".", 1)[-1].lower()
                if method in _ROUTE_METHODS and any(
                    child.type in {"interpreted_string_literal", "raw_string_literal"}
                    and _SENSITIVE_ROUTE.search(_text(source, child).strip('"`'))
                    for child in _preorder(arguments, _MAX_LIMITS[3])
                ):
                    return True
        ancestor = ancestor.parent
        hops += 1
    return False


def _scope_preorder(scope: Node, max_nodes: int) -> tuple[Node, ...]:
    result: list[Node] = []
    stack = [scope]
    while stack and len(result) <= max_nodes:
        node = stack.pop()
        result.append(node)
        children = tuple(
            child
            for child in reversed(node.children)
            if _same_node(child, scope) or child.type not in _HANDLER_TYPES
        )
        stack.extend(children)
    if stack:
        raise GoCwe862ScanError(GoCwe862ScanErrorCode.ANALYSIS_UNAVAILABLE)
    return tuple(result)


def _contains_authz_call(node: Node, source: bytes) -> bool:
    for child in _preorder(node, _MAX_LIMITS[3]):
        if child.type != "call_expression":
            continue
        function = child.child_by_field_name("function")
        if function is None:
            continue
        name = re.sub(r"[^a-z0-9]", "", _call_name(function, source).lower())
        if any(marker in name for marker in _AUTHZ_MARKERS):
            return True
    return False


def _sensitive_mutation(call: Node, source: bytes) -> GoCwe862Operation | None:
    function = call.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return None
    member_node = function.child_by_field_name("field")
    receiver_node = function.child_by_field_name("operand")
    if member_node is None or receiver_node is None:
        return None
    member = re.sub(r"[^a-z0-9]", "", _text(source, member_node).lower())
    receiver = re.sub(r"[^a-z0-9]", "", _text(source, receiver_node).lower())
    if member not in _MUTATION_METHODS:
        return None
    if not any(name in receiver for name in _MUTATION_RECEIVERS):
        return None
    mapping = {
        "create": GoCwe862Operation.CREATE,
        "delete": GoCwe862Operation.DELETE,
        "destroy": GoCwe862Operation.DELETE,
        "exec": GoCwe862Operation.EXECUTE,
        "insert": GoCwe862Operation.INSERT,
        "modify": GoCwe862Operation.UPDATE,
        "remove": GoCwe862Operation.DELETE,
        "revoke": GoCwe862Operation.REVOKE,
        "save": GoCwe862Operation.SAVE,
        "setrole": GoCwe862Operation.UPDATE,
        "setpermission": GoCwe862Operation.UPDATE,
        "update": GoCwe862Operation.UPDATE,
        "upsert": GoCwe862Operation.UPDATE,
        "write": GoCwe862Operation.WRITE,
    }
    return mapping.get(member)


def _call_name(node: Node, source: bytes) -> str:
    return _text(source, node)


def _compact(source: bytes, node: Node) -> str:
    return re.sub(r"\s+", "", _text(source, node))


def _text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")


def _range(node: Node) -> SourceRange:
    return SourceRange(
        start_byte=node.start_byte,
        end_byte=node.end_byte,
        start_point=SourcePoint(node.start_point.row, node.start_point.column),
        end_point=SourcePoint(node.end_point.row, node.end_point.column),
    )


def _range_value(value: SourceRange) -> dict[str, int]:
    return {
        "start_byte": value.start_byte,
        "end_byte": value.end_byte,
        "start_row": value.start_point.row,
        "start_column": value.start_point.column,
        "end_row": value.end_point.row,
        "end_column": value.end_point.column,
    }


def _signal_id(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    source: SourceRange,
    sink: SourceRange,
    operation: GoCwe862Operation,
) -> str:
    payload = {
        "content_sha256": content_sha256,
        "cwe": "CWE-862",
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "sink": _range_value(sink),
        "source": _range_value(source),
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe862Signal, ...],
) -> str:
    payload = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {"operation": item.operation.value, "signal_id": item.signal_id} for item in signals
        ],
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


__all__ = [
    "DEFAULT_GO_CWE862_SCAN_LIMITS",
    "GoCwe862Operation",
    "GoCwe862ScanError",
    "GoCwe862ScanErrorCode",
    "GoCwe862ScanLimits",
    "GoCwe862ScanResult",
    "GoCwe862Signal",
    "scan_go_cwe862",
]
