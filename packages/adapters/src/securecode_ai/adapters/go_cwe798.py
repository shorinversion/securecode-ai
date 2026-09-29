"""Bounded Go facts for CWE-798 hard-coded credentials.

This adapter reports only a narrow, high-confidence projection of literals that
are assigned to credential-shaped names or passed to credential-bearing APIs.
The source bytes are inspected transiently while parsing.  Returned values
contain immutable identity, ranges, and stable hashes, never the credential
literal itself.  Environment lookups, unresolved expressions, and obvious
placeholder values are deliberately left unresolved.
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
_RULE_ID = "securecode-go-cwe798"
_DETECTOR = "securecode-go-cwe798@1.0"
_DETAIL = "hardcoded_credential"
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})
_CREDENTIAL_WORDS = frozenset(
    {
        "accesskey",
        "apikey",
        "authtoken",
        "clientid",
        "clientsecret",
        "credential",
        "credentials",
        "encryptionkey",
        "jwt",
        "password",
        "passcode",
        "passphrase",
        "passwd",
        "privatekey",
        "refresh token",
        "refreshtoken",
        "secret",
        "secretkey",
        "sessionkey",
        "sessiontoken",
        "signingkey",
        "token",
    }
)
_CREDENTIAL_LITERAL_MARKERS = frozenset(
    {
        "access-key",
        "access_key",
        "api-key",
        "api_key",
        "authorization",
        "bearer",
        "client-secret",
        "client_secret",
        "cookie",
        "credential",
        "jwt",
        "password",
        "passwd",
        "private-key",
        "private_key",
        "refresh-token",
        "refresh_token",
        "secret",
        "session-token",
        "session_token",
        "signing-key",
        "signing_key",
        "token",
        "x-api-key",
        "x-auth-token",
    }
)
_PLACEHOLDERS = frozenset(
    {
        "",
        "changeme",
        "changeit",
        "default",
        "dummy",
        "example",
        "fixme",
        "password",
        "placeholder",
        "secret",
        "test",
        "testing",
        "token",
        "todo",
        "xxx",
        "yourpassword",
        "yoursecret",
        "yourtoken",
    }
)
_IGNORED_PATH_PARTS = frozenset(
    {"doc", "docs", "example", "examples", "fixture", "fixtures", "test", "testdata", "tests"}
)
_KNOWN_ENV_PACKAGES = frozenset({"os"})
_HEADER_METHODS = frozenset({"Add", "Set", "SetCanonical"})
_AUTH_CALLS = frozenset({"SetBasicAuth", "UserPassword"})
_URL_CALLS = frozenset({"NewRequest", "Parse", "ParseRequestURI"})
_SQL_PACKAGES = frozenset({"database/sql", "github.com/jmoiron/sqlx"})
_SECURITY_CALL_PREFIXES = frozenset(
    {
        "configure",
        "connect",
        "create",
        "initialize",
        "new",
        "register",
        "set",
        "with",
    }
)


class GoCwe798ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-798 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe798ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe798ScanErrorCode) -> None:
        if type(code) is not GoCwe798ScanErrorCode:
            raise TypeError("Go CWE-798 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-798 hardcoded-credential scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe798ScanLimits:
    """Hard ceilings applied before and during local structural analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-798 scan limits are invalid")


DEFAULT_GO_CWE798_SCAN_LIMITS = GoCwe798ScanLimits()


class GoCwe798Operation(StrEnum):
    """Recognised hard-coded credential contexts."""

    CREDENTIAL_ASSIGNMENT = "credential_assignment"
    CREDENTIAL_FIELD = "credential_field"
    CREDENTIAL_MAP_VALUE = "credential_map_value"
    BASIC_AUTH = "http.Request.SetBasicAuth"
    URL_AUTH_VALUE = "url.UserPassword"
    HEADER_CREDENTIAL = "http.Header.Set"
    ENVIRONMENT_CREDENTIAL = "os.Setenv"
    URL_WITH_CREDENTIAL = "url.with_credential"
    SQL_DSN_CREDENTIAL = "database/sql.dsn"
    SECURITY_CONSTRUCTOR = "credential_constructor"

    # Compatibility names used by generic scanner consumers.
    ASSIGNMENT = "credential_assignment"
    STRUCT_FIELD = "credential_field"
    MAP_VALUE = "credential_map_value"


@dataclass(frozen=True, slots=True)
class GoCwe798Signal:
    """One immutable source-free hard-coded credential fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe798Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-798"
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
            and self.sink.contains(self.source)
            and self.source.end_byte <= self.source_size_bytes
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
            if identity_valid and ranges_valid and type(self.operation) is GoCwe798Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not GoCwe798Operation
            or type(signal_id) is not str
            or expected_id is None
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-798"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-798 signal is invalid")
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
class GoCwe798ScanResult:
    """Deterministic, source-free CWE-798 output for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe798Signal, ...]
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
            type(item) is GoCwe798Signal for item in self.signals
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
            raise ValueError("Go CWE-798 scan result is invalid")


def scan_go_cwe798(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe798ScanLimits = DEFAULT_GO_CWE798_SCAN_LIMITS,
) -> GoCwe798ScanResult:
    """Find high-confidence hard-coded Go credential literals."""

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
        raise GoCwe798ScanError(GoCwe798ScanErrorCode.INTEGRITY_FAILURE) from None

    if _is_nonproduction_path(symbol_index.path):
        return _empty_result(symbol_index)

    imports = _import_aliases(root, source)
    facts: set[tuple[SourceRange, SourceRange, GoCwe798Operation]] = set()
    try:
        for node, depth in _with_depth(root):
            if depth > limits.max_expression_depth:
                raise GoCwe798ScanError(GoCwe798ScanErrorCode.ANALYSIS_UNAVAILABLE)
            if node.type in {"var_spec", "short_var_declaration", "assignment_statement"}:
                _assignment_facts(node, source, facts, limits)
            elif node.type == "keyed_element":
                _keyed_facts(node, source, facts, limits)
            elif node.type == "call_expression":
                _call_facts(node, source, imports, facts, limits)
            if len(facts) > limits.max_signals:
                raise GoCwe798ScanError(GoCwe798ScanErrorCode.SIGNAL_LIMIT)
    except GoCwe798ScanError:
        raise
    except Exception:
        raise GoCwe798ScanError(GoCwe798ScanErrorCode.INTEGRITY_FAILURE) from None

    ordered = sorted(
        facts,
        key=lambda item: (
            item[1].start_byte,
            item[1].end_byte,
            item[0].start_byte,
            item[0].end_byte,
            item[2].value,
        ),
    )
    if len(ordered) > limits.max_signals:
        raise GoCwe798ScanError(GoCwe798ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe798Signal(
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
    return GoCwe798ScanResult(
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


def scan_go_hardcoded_credentials(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe798ScanLimits = DEFAULT_GO_CWE798_SCAN_LIMITS,
) -> GoCwe798ScanResult:
    """Descriptive alias for :func:`scan_go_cwe798`."""

    return scan_go_cwe798(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe798ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe798ScanLimits:
        raise GoCwe798ScanError(GoCwe798ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe798ScanError(GoCwe798ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe798ScanError(GoCwe798ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe798ScanError(GoCwe798ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _assignment_facts(
    node: Node,
    source: bytes,
    facts: set[tuple[SourceRange, SourceRange, GoCwe798Operation]],
    limits: GoCwe798ScanLimits,
) -> None:
    if node.type == "var_spec":
        left = node.child_by_field_name("name")
        right = node.child_by_field_name("value")
    else:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
    if left is None or right is None:
        return
    names = left.named_children if left.named_children else (left,)
    values = right.named_children if right.named_children else (right,)
    for index, name in enumerate(names):
        if index >= len(values):
            break
        credential_name = _lvalue_name(name, source)
        if not _is_credential_name(credential_name):
            continue
        for literal in _direct_literals(values[index]):
            if _is_credential_literal(source, literal):
                facts.add(
                    (
                        _range(literal),
                        _range(node),
                        GoCwe798Operation.CREDENTIAL_ASSIGNMENT,
                    )
                )
                if len(facts) > limits.max_signals:
                    raise GoCwe798ScanError(GoCwe798ScanErrorCode.SIGNAL_LIMIT)


def _keyed_facts(
    node: Node,
    source: bytes,
    facts: set[tuple[SourceRange, SourceRange, GoCwe798Operation]],
    limits: GoCwe798ScanLimits,
) -> None:
    children = node.named_children
    if len(children) < 2:
        return
    key, value = children[0], children[-1]
    key_text = _text(source, key).strip('"`')
    if not _is_credential_name(key_text):
        return
    for literal in _direct_literals(value):
        if _is_credential_literal(source, literal):
            facts.add((_range(literal), _range(node), GoCwe798Operation.CREDENTIAL_MAP_VALUE))
            if len(facts) > limits.max_signals:
                raise GoCwe798ScanError(GoCwe798ScanErrorCode.SIGNAL_LIMIT)


def _call_facts(
    node: Node,
    source: bytes,
    imports: dict[str, str],
    facts: set[tuple[SourceRange, SourceRange, GoCwe798Operation]],
    limits: GoCwe798ScanLimits,
) -> None:
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None:
        return
    method, package = _function_parts(function, source, imports)
    args = arguments.named_children
    compact_name = _normalize(method)

    operation: GoCwe798Operation | None = None
    positions: tuple[int, ...] = ()
    if package in _KNOWN_ENV_PACKAGES and method in {"Setenv", "LookupEnv"}:
        if method == "Setenv" and len(args) >= 2:
            key = _text(source, args[0]).strip('"`')
            if _is_credential_name(key):
                operation = GoCwe798Operation.ENVIRONMENT_CREDENTIAL
                positions = (1,)
    elif method == "SetBasicAuth" and len(args) >= 2:
        operation = GoCwe798Operation.BASIC_AUTH
        positions = (1,)
    elif method == "UserPassword" and len(args) >= 2:
        operation = GoCwe798Operation.URL_AUTH_VALUE
        positions = (1,)
    elif method in _HEADER_METHODS and len(args) >= 2:
        key = _text(source, args[0]).strip('"`').casefold()
        if _is_credential_literal_marker(key):
            operation = GoCwe798Operation.HEADER_CREDENTIAL
            positions = (1,)
    elif package in _SQL_PACKAGES and method == "Open" and args:
        operation = GoCwe798Operation.SQL_DSN_CREDENTIAL
        positions = tuple(range(len(args)))
    elif method in _URL_CALLS:
        operation = GoCwe798Operation.URL_WITH_CREDENTIAL
        positions = tuple(range(len(args)))
    elif _is_credential_constructor(compact_name):
        operation = GoCwe798Operation.SECURITY_CONSTRUCTOR
        positions = tuple(range(len(args)))

    if operation is None:
        return
    for position in positions:
        if position >= len(args):
            continue
        for literal in _literal_nodes(args[position]):
            if not _is_credential_literal(source, literal):
                continue
            value = _literal_value(source, literal)
            should_report = operation not in {
                GoCwe798Operation.URL_WITH_CREDENTIAL,
                GoCwe798Operation.SQL_DSN_CREDENTIAL,
            } or _contains_embedded_credential(value)
            if should_report:
                facts.add((_range(literal), _range(node), operation))
                if len(facts) > limits.max_signals:
                    raise GoCwe798ScanError(GoCwe798ScanErrorCode.SIGNAL_LIMIT)


def _is_credential_constructor(name: str) -> bool:
    if not any(name.startswith(prefix) for prefix in _SECURITY_CALL_PREFIXES):
        return False
    return any(marker in name for marker in _CREDENTIAL_WORDS if " " not in marker)


def _function_parts(
    function: Node, source: bytes, imports: dict[str, str]
) -> tuple[str, str | None]:
    if function.type == "identifier":
        return _text(source, function), None
    if function.type != "selector_expression":
        return "", None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if field is None:
        return "", None
    method = _text(source, field)
    package = imports.get(_text(source, operand)) if operand is not None else None
    return method, package


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        package = _text(source, path_node).strip('"`')
        name_node = node.child_by_field_name("name")
        alias = _text(source, name_node) if name_node is not None else package.rsplit("/", 1)[-1]
        if alias not in {".", "_"}:
            aliases[alias] = package
    return aliases


def _lvalue_name(node: Node, source: bytes) -> str:
    if node.type in {"identifier", "field_identifier", "type_identifier"}:
        return _text(source, node)
    if node.type == "selector_expression":
        field = node.child_by_field_name("field")
        return _text(source, field)
    return _text(source, node)


def _is_credential_name(value: str) -> bool:
    normalized = _normalize(value)
    return bool(normalized) and any(
        marker.replace(" ", "") in normalized for marker in _CREDENTIAL_WORDS
    )


def _is_credential_literal_marker(value: str) -> bool:
    normalized = value.casefold().replace(" ", "")
    return any(
        marker.replace("-", "").replace("_", "") in normalized
        for marker in _CREDENTIAL_LITERAL_MARKERS
    )


def _is_credential_literal(source: bytes, node: Node) -> bool:
    value = _literal_value(source, node)
    if not value:
        return False
    return not _is_placeholder(value)


def _is_placeholder(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "", value.casefold())
    if normalized in _PLACEHOLDERS:
        return True
    if normalized.startswith(("your", "replace", "insert", "putyour")):
        return True
    return value.strip().startswith(("${", "{{")) or "<your-" in value.casefold()


def _contains_embedded_credential(value: str) -> bool:
    lowered = value.casefold()
    if re.search(r"^[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@", lowered):
        return True
    if re.search(r"(?:^|[?;&\s])(?:password|passwd|token|secret|api[_-]?key)=", lowered):
        return True
    if re.search(r"(?:^|\s)(?:akia|as ia|ghp_|github_pat_|xox[baprs]-)[a-z0-9_-]{8,}", lowered):
        return True
    return "-----begin " in lowered and " private key-----" in lowered


def _direct_literals(node: Node) -> tuple[Node, ...]:
    if node.type in {"interpreted_string_literal", "raw_string_literal"}:
        return (node,)
    return ()


def _literal_nodes(node: Node) -> tuple[Node, ...]:
    return tuple(
        child
        for child in _preorder(node)
        if child.type in {"interpreted_string_literal", "raw_string_literal"}
    )


def _literal_value(source: bytes, node: Node) -> str:
    raw = _text(source, node)
    if len(raw) < 2:
        return ""
    value = raw[1:-1]
    if raw.startswith('"'):
        value = re.sub(r"\\([\\\"'nrtbfv])", lambda match: match.group(1), value)
    return value


def _is_nonproduction_path(path: str) -> bool:
    normalized = path.replace("\\", "/").casefold()
    basename = normalized.rsplit("/", 1)[-1]
    if basename.endswith("_test.go") or basename.endswith("_testdata.go"):
        return True
    return any(part in _IGNORED_PATH_PARTS for part in normalized.split("/"))


def _empty_result(symbol_index: SymbolIndex) -> GoCwe798ScanResult:
    signals: tuple[GoCwe798Signal, ...] = ()
    return GoCwe798ScanResult(
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


def _with_depth(root: Node) -> tuple[tuple[Node, int], ...]:
    output: list[tuple[Node, int]] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        output.append((node, depth))
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _preorder(root: Node) -> tuple[Node, ...]:
    return tuple(node for node, _ in _with_depth(root))


def _text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")


def _normalize(value: str) -> str:
    expanded = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return re.sub(r"[^a-z0-9]+", "", expanded.casefold())


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
    operation: GoCwe798Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-798",
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
    signals: tuple[GoCwe798Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-798",
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


Cwe798ScanErrorCode = GoCwe798ScanErrorCode
Cwe798ScanError = GoCwe798ScanError
Cwe798ScanLimits = GoCwe798ScanLimits
Cwe798ScanResult = GoCwe798ScanResult
Cwe798Signal = GoCwe798Signal


__all__ = [
    "DEFAULT_GO_CWE798_SCAN_LIMITS",
    "Cwe798ScanError",
    "Cwe798ScanErrorCode",
    "Cwe798ScanLimits",
    "Cwe798ScanResult",
    "Cwe798Signal",
    "GoCwe798Operation",
    "GoCwe798ScanError",
    "GoCwe798ScanErrorCode",
    "GoCwe798ScanLimits",
    "GoCwe798ScanResult",
    "GoCwe798Signal",
    "scan_go_cwe798",
    "scan_go_hardcoded_credentials",
]
