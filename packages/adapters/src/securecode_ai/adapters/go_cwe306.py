"""Bounded Go facts for CWE-306 missing authentication for critical functions.

The detector deliberately limits itself to ordinary ``net/http`` handlers.  A
candidate needs an authenticated-looking HTTP handler and an explicit critical
operation in the same function, while no recognised authentication guard is
present.  Critical operations are limited to filesystem mutation, process
execution, and SQL mutation calls with a literal mutation statement.  Unknown
frameworks and ambiguous names are left unresolved.

Only a sealed, healthy :class:`~securecode_ai.core.SymbolIndex` is accepted.
The parser sees the admitted bytes transiently; results contain immutable
ranges and hashes only and never include source text or parser diagnostics.
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
_RULE_ID = "securecode-go-cwe306"
_DETECTOR = "securecode-go-cwe306@1.0"
_DETAIL = "critical_function_without_authentication"

_HTTP_PACKAGE = "net/http"
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})
_ROUTE_METHODS = frozenset(
    {
        "any",
        "delete",
        "get",
        "handle",
        "handlecontext",
        "handlefunc",
        "patch",
        "path",
        "post",
        "put",
        "route",
        "servehttp",
    }
)
_FILE_PACKAGES = frozenset({"os", "io/ioutil", "io/fs"})
_EXEC_PACKAGES = frozenset({"os/exec"})
_SQL_PACKAGES = frozenset({"database/sql", "github.com/jmoiron/sqlx", "gorm.io/gorm"})
_FILE_CALLS = {
    ("os", "chmod"): "file_permission_change",
    ("os", "chown"): "file_owner_change",
    ("os", "create"): "file_write",
    ("os", "link"): "file_link",
    ("os", "mkdir"): "file_write",
    ("os", "mkdirall"): "file_write",
    ("os", "openfile"): "file_write",
    ("os", "remove"): "file_delete",
    ("os", "removeall"): "file_delete",
    ("os", "rename"): "file_rename",
    ("os", "symlink"): "file_link",
    ("os", "truncate"): "file_write",
    ("os", "writefile"): "file_write",
    ("io/ioutil", "writefile"): "file_write",
}
_EXEC_CALLS = frozenset({"command", "commandcontext"})
_SQL_MUTATION_CALLS = frozenset({"exec", "execcontext", "raw", "execsql"})
_SQL_MUTATION_WORDS = re.compile(
    r"\b(?:alter|create|delete|drop|insert|replace|truncate|update|upsert)\b",
    re.IGNORECASE,
)
_AUTH_CALLS = frozenset(
    {
        "authenticate",
        "authenticateuser",
        "authorize",
        "checkauth",
        "checkauthentication",
        "checkpermission",
        "checkpermissions",
        "checkrole",
        "checkroles",
        "ensureauthenticated",
        "ensureauthorized",
        "haspermission",
        "haspermissions",
        "hasrole",
        "is_authenticated",
        "isauthenticated",
        "loadprincipal",
        "requireauth",
        "requireauthentication",
        "requirepermission",
        "requirepermissions",
        "requirerole",
        "requireuser",
        "validatetoken",
        "verifytoken",
    }
)
_AUTH_PACKAGE_MARKERS = frozenset(
    {
        "github.com/auth0/go-jwt-middleware",
        "github.com/casbin/casbin",
        "github.com/golang-jwt/jwt",
        "github.com/golang-jwt/jwt/v4",
        "github.com/golang-jwt/jwt/v5",
        "github.com/lestrrat-go/jwx",
        "github.com/ory/fosite",
        "github.com/rs/cors",
    }
)
_AUTH_NAME_MARKERS = frozenset(
    {
        "authmiddleware",
        "authenticatedmiddleware",
        "authorizationmiddleware",
        "authguard",
        "permissionguard",
        "requireauth",
        "requireauthentication",
        "requirepermission",
        "requirerole",
    }
)
_CRITICAL_NAME_MARKERS = frozenset(
    {
        "admin",
        "billing",
        "command",
        "config",
        "delete",
        "deploy",
        "destroy",
        "execute",
        "export",
        "import",
        "manage",
        "payment",
        "permission",
        "privilege",
        "release",
        "remove",
        "role",
        "secret",
        "settings",
        "shell",
        "token",
        "transfer",
        "upload",
        "user",
    }
)
_CRITICAL_ROUTE_RE = re.compile(
    r"(?:/|^)(?:admin|administrator|billing|config|delete|deploy|execute|manage|payment|"
    r"permission|privilege|release|remove|role|secret|settings|shell|token|transfer|upload|user)"
    r"(?:/|$|[?:{_-])",
    re.IGNORECASE,
)


class GoCwe306ScanErrorCode(StrEnum):
    """Closed, source-free reasons a Go CWE-306 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe306ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe306ScanErrorCode) -> None:
        if type(code) is not GoCwe306ScanErrorCode:
            raise TypeError("Go CWE-306 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-306 authentication scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe306ScanLimits:
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
            raise ValueError("Go CWE-306 scan limits are invalid")


DEFAULT_GO_CWE306_SCAN_LIMITS = GoCwe306ScanLimits()


class GoCwe306Operation(StrEnum):
    """Recognised critical operations performed by an unauthenticated handler."""

    FILE_DELETE = "file_delete"
    FILE_LINK = "file_link"
    FILE_OWNER_CHANGE = "file_owner_change"
    FILE_PERMISSION_CHANGE = "file_permission_change"
    FILE_RENAME = "file_rename"
    FILE_WRITE = "file_write"
    COMMAND_EXECUTION = "command_execution"
    DATABASE_MUTATION = "database_mutation"

    # Generic compatibility name for consumers that group critical sinks.
    MISSING_AUTHENTICATION = "critical_function_without_authentication"
    CRITICAL_FUNCTION_WITHOUT_AUTHENTICATION = "critical_function_without_authentication"
    UNAUTHENTICATED_CRITICAL_FUNCTION = "critical_function_without_authentication"


@dataclass(frozen=True, slots=True)
class GoCwe306Signal:
    """One immutable, source-free missing-authentication candidate."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe306Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-306"
    detector: str = _DETECTOR
    detail: str = _DETAIL

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
            if valid_identity and valid_ranges and type(self.operation) is GoCwe306Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not GoCwe306Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-306"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-306 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        return self.signal_id

    @property
    def location(self) -> SourceRange:
        return self.source

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class GoCwe306ScanResult:
    """Deterministic, source-free CWE-306 output for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe306Signal, ...]
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
            type(item) is GoCwe306Signal for item in self.signals
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
            raise ValueError("Go CWE-306 scan result is invalid")


def scan_go_cwe306(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe306ScanLimits = DEFAULT_GO_CWE306_SCAN_LIMITS,
) -> GoCwe306ScanResult:
    """Find critical Go HTTP handlers without a recognised authentication guard."""

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
    except Exception:
        raise GoCwe306ScanError(GoCwe306ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    critical_targets = _critical_route_targets(root, source)
    facts: list[tuple[SourceRange, SourceRange, GoCwe306Operation]] = []
    for scope in _scopes(root):
        if not _is_http_handler(scope, source, imports):
            continue
        if not _is_critical_scope(scope, source, critical_targets):
            continue
        if _has_auth_evidence(scope, source, imports) or _auth_wrapped_route(scope, source):
            continue
        for call in _scope_preorder(scope):
            operation = _critical_operation(call, source, imports)
            if operation is None:
                continue
            facts.append((_range(call), _range(scope), operation))
            if len(facts) > limits.max_signals:
                raise GoCwe306ScanError(GoCwe306ScanErrorCode.SIGNAL_LIMIT)

    unique = tuple(
        sorted(
            set(facts),
            key=lambda item: (
                item[1].start_byte,
                item[1].end_byte,
                item[0].start_byte,
                item[0].end_byte,
                item[2].value,
            ),
        )
    )
    signals = tuple(
        GoCwe306Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
        )
        for source_range, sink_range, operation in unique
    )
    return GoCwe306ScanResult(
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


def scan_go_critical_function_authentication(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe306ScanLimits = DEFAULT_GO_CWE306_SCAN_LIMITS,
) -> GoCwe306ScanResult:
    """Descriptive alias for :func:`scan_go_cwe306`."""

    return scan_go_cwe306(symbol_index, limits=limits)


def scan_go_missing_authentication(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe306ScanLimits = DEFAULT_GO_CWE306_SCAN_LIMITS,
) -> GoCwe306ScanResult:
    """Compatibility alias for generic scanner dispatchers."""

    return scan_go_cwe306(symbol_index, limits=limits)


def scan_go_critical_function(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe306ScanLimits = DEFAULT_GO_CWE306_SCAN_LIMITS,
) -> GoCwe306ScanResult:
    """Short alias for generic critical-function scanner dispatchers."""

    return scan_go_cwe306(symbol_index, limits=limits)


def scan_go_unauthenticated_critical_function(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe306ScanLimits = DEFAULT_GO_CWE306_SCAN_LIMITS,
) -> GoCwe306ScanResult:
    """Explicit alias for :func:`scan_go_cwe306`."""

    return scan_go_cwe306(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe306ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe306ScanLimits:
        raise GoCwe306ScanError(GoCwe306ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe306ScanError(GoCwe306ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe306ScanError(GoCwe306ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe306ScanError(GoCwe306ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        path = _text(source, path_node).strip('"`')
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            alias = _text(source, name_node)
            if alias not in {".", "_"}:
                aliases[alias] = path
            continue
        aliases[path.rsplit("/", 1)[-1]] = path
    return aliases


def _scopes(root: Node) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node.type in _GO_SCOPES)


def _is_http_handler(scope: Node, source: bytes, imports: dict[str, str]) -> bool:
    parameters = scope.child_by_field_name("parameters")
    if parameters is None:
        return False
    text = _compact_text(source, parameters).lower()
    aliases = tuple(alias for alias, path in imports.items() if path == _HTTP_PACKAGE)
    return (
        "responsewriter" in text
        and "request" in text
        and any(f"{alias.lower()}.responsewriter" in text for alias in aliases)
        and any(f"{alias.lower()}.request" in text for alias in aliases)
    )


def _is_critical_scope(scope: Node, source: bytes, critical_targets: frozenset[str]) -> bool:
    name_node = scope.child_by_field_name("name")
    if name_node is not None:
        name = _compact_text(source, name_node)
        if _contains_critical_name(name) or name in critical_targets:
            return True
    return _critical_route_ancestor(scope, source)


def _critical_route_targets(root: Node, source: bytes) -> frozenset[str]:
    targets: set[str] = set()
    for node in _preorder(root):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            continue
        method = _call_name(function, source).rsplit(".", 1)[-1].lower()
        if method not in _ROUTE_METHODS or not _arguments_have_critical_route(arguments, source):
            continue
        for candidate in _preorder(arguments):
            if candidate.type in {"identifier", "field_identifier"}:
                value = _text(source, candidate)
                if value.lower() not in {"router", "mux", "r", "http", "nil"}:
                    targets.add(value)
    return frozenset(targets)


def _arguments_have_critical_route(arguments: Node, source: bytes) -> bool:
    return any(
        node.type in {"interpreted_string_literal", "raw_string_literal"}
        and _critical_route_literal(_text(source, node))
        for node in _preorder(arguments)
    )


def _critical_route_ancestor(scope: Node, source: bytes) -> bool:
    ancestor = scope.parent
    hops = 0
    while ancestor is not None and hops < 12:
        if ancestor.type == "call_expression":
            function = ancestor.child_by_field_name("function")
            arguments = ancestor.child_by_field_name("arguments")
            if (
                function is not None
                and arguments is not None
                and _call_name(function, source).rsplit(".", 1)[-1].lower() in _ROUTE_METHODS
                and _arguments_have_critical_route(arguments, source)
            ):
                return True
        ancestor = ancestor.parent
        hops += 1
    return False


def _auth_wrapped_route(scope: Node, source: bytes) -> bool:
    ancestor = scope.parent
    hops = 0
    while ancestor is not None and hops < 12:
        if ancestor.type == "call_expression":
            function = ancestor.child_by_field_name("function")
            arguments = ancestor.child_by_field_name("arguments")
            if function is not None and arguments is not None:
                method = _call_name(function, source).rsplit(".", 1)[-1].lower()
                if method in _ROUTE_METHODS and any(
                    _is_auth_wrapper_node(candidate, source) for candidate in _preorder(arguments)
                ):
                    return True
        ancestor = ancestor.parent
        hops += 1
    return False


def _has_auth_evidence(scope: Node, source: bytes, imports: dict[str, str]) -> bool:
    for node in _scope_preorder(scope):
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function is not None and _is_auth_call(function, node, source, imports):
                return True
        if node.type == "if_statement" and _is_explicit_auth_condition(node, source):
            return True
    return False


def _is_auth_call(function: Node, call: Node, source: bytes, imports: dict[str, str]) -> bool:
    name = _call_name(function, source)
    member = name.rsplit(".", 1)[-1].lower()
    compact_member = re.sub(r"[^a-z0-9_]", "", member)
    package = name.rsplit(".", 1)[0] if "." in name else ""
    canonical = imports.get(package, package)
    if compact_member in _AUTH_CALLS or compact_member in _AUTH_NAME_MARKERS:
        return True
    if canonical in _AUTH_PACKAGE_MARKERS and compact_member in {
        "check",
        "validate",
        "verify",
        "authorize",
        "authenticate",
    }:
        return True
    return (
        _is_auth_wrapper_node(function, source)
        and "middleware" in _compact_text(source, call).lower()
    )


def _is_explicit_auth_condition(node: Node, source: bytes) -> bool:
    text = _compact_text(source, node).lower()
    return any(
        marker in text
        for marker in (
            "requireauth",
            "requireauthentication",
            "isauthenticated",
            "checkauthentication",
            "checkpermission",
            "unauthorized",
            "forbidden",
            "notauthenticated",
        )
    )


def _is_auth_wrapper_node(node: Node, source: bytes) -> bool:
    if node.type not in {
        "identifier",
        "field_identifier",
        "selector_expression",
        "call_expression",
    }:
        return False
    text = re.sub(r"[^a-z0-9]", "", _compact_text(source, node).lower())
    return text in _AUTH_NAME_MARKERS or any(
        text.startswith(marker) or text.endswith(marker) for marker in _AUTH_NAME_MARKERS
    )


def _critical_operation(
    call: Node, source: bytes, imports: dict[str, str]
) -> GoCwe306Operation | None:
    if call.type != "call_expression":
        return None
    function = call.child_by_field_name("function")
    if function is None:
        return None
    name = _call_name(function, source)
    member = name.rsplit(".", 1)[-1].lower()
    package_alias = name.rsplit(".", 1)[0] if "." in name else ""
    package = imports.get(package_alias, package_alias)
    file_operation = _FILE_CALLS.get((package, member))
    if file_operation is not None:
        return GoCwe306Operation(file_operation)
    if package in _EXEC_PACKAGES and member in _EXEC_CALLS:
        return GoCwe306Operation.COMMAND_EXECUTION
    if (
        member in _SQL_MUTATION_CALLS
        and _has_mutating_sql_argument(call, source)
        and (not package or package in _SQL_PACKAGES or package_alias)
    ):
        return GoCwe306Operation.DATABASE_MUTATION
    return None


def _has_mutating_sql_argument(call: Node, source: bytes) -> bool:
    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return False
    return any(
        node.type in {"interpreted_string_literal", "raw_string_literal"}
        and bool(_SQL_MUTATION_WORDS.search(_text(source, node)))
        for node in _preorder(arguments)
    )


def _contains_critical_name(value: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", value.lower())
    return any(marker in compact for marker in _CRITICAL_NAME_MARKERS)


def _critical_route_literal(value: str) -> bool:
    compact = value.strip('"`').lower()
    return bool(_CRITICAL_ROUTE_RE.search(compact))


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


def _compact_text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return "".join(_text(source, node).split())


def _call_name(function: Node, source: bytes) -> str:
    return _compact_text(source, function)


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
    operation: GoCwe306Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-306",
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
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe306Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-306",
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
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


Cwe306ScanErrorCode = GoCwe306ScanErrorCode
Cwe306ScanError = GoCwe306ScanError
Cwe306ScanLimits = GoCwe306ScanLimits
Cwe306ScanResult = GoCwe306ScanResult
Cwe306Signal = GoCwe306Signal


__all__ = [
    "DEFAULT_GO_CWE306_SCAN_LIMITS",
    "Cwe306ScanError",
    "Cwe306ScanErrorCode",
    "Cwe306ScanLimits",
    "Cwe306ScanResult",
    "Cwe306Signal",
    "GoCwe306Operation",
    "GoCwe306ScanError",
    "GoCwe306ScanErrorCode",
    "GoCwe306ScanLimits",
    "GoCwe306ScanResult",
    "GoCwe306Signal",
    "scan_go_critical_function",
    "scan_go_critical_function_authentication",
    "scan_go_cwe306",
    "scan_go_missing_authentication",
    "scan_go_unauthenticated_critical_function",
]
