"""Bounded JavaScript and TypeScript CWE-639 authorization facts.

The adapter reports a narrow class of insecure record access: a dynamic
record key which can be supplied by an HTTP request (or by a key-shaped route
parameter) reaches a repository, collection, or record-map lookup without a
recognisable owner or tenant guard in the enclosing handler.  Static keys,
ordinary array indexing, request parsing, and ambiguous expressions are
ignored.

Only immutable source ranges and content-addressed identity leave this
module.  The admitted bytes are reparsed after their ``SymbolIndex`` is
rebuilt, and all traversal is bounded before any finding is emitted.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import ParseHealth, RepositoryFile, SourcePoint, SourceRange, SymbolIndex
from tree_sitter import Language, Node, Parser

from .cst import CstAdapterError, build_javascript_symbol_index, build_typescript_symbol_index
from .cst_ecmascript import _javascript_language, _typescript_language

_MAX_LIMITS = (2_000_000, 250_000, 512, 10_000)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_RULE_ID = "securecode-ecmascript-cwe639"
_DETECTOR = "securecode-ecmascript-cwe639@1.0"
_DETAIL = "user_controlled_key_lookup_without_owner_guard"

_FUNCTION_TYPES = frozenset(
    {
        "arrow_function",
        "function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)
_WRAPPER_TYPES = frozenset(
    {
        "as_expression",
        "parenthesized_expression",
        "non_null_expression",
        "type_assertion",
        "satisfies_expression",
    }
)
_REQUEST_ROOTS = frozenset(
    {
        "ctx",
        "context",
        "event",
        "http",
        "httprequest",
        "input",
        "request",
        "req",
    }
)
_REQUEST_FIELDS = frozenset(
    {
        "body",
        "cookies",
        "form",
        "headers",
        "params",
        "path",
        "pathparameters",
        "pathparams",
        "query",
        "queryparameters",
        "querystring",
        "querystringparameters",
        "routeparams",
        "urlparams",
    }
)
_REQUEST_ACCESSORS = frozenset(
    {
        "get",
        "getbody",
        "getheader",
        "getinput",
        "getparam",
        "getparameter",
        "getpath",
        "getquery",
        "param",
        "parameter",
    }
)
_KEY_NAMES = frozenset(
    {
        "accountid",
        "customerid",
        "documentid",
        "entityid",
        "fileid",
        "id",
        "invoiceid",
        "itemid",
        "key",
        "objectid",
        "orderid",
        "pk",
        "projectid",
        "recordid",
        "resourceid",
        "slug",
        "tenantid",
        "userid",
        "uuid",
    }
)
_LOOKUP_CONTEXT = frozenset(
    {
        "account",
        "accounts",
        "cache",
        "collection",
        "collections",
        "customers",
        "dao",
        "database",
        "db",
        "documents",
        "entities",
        "invoices",
        "items",
        "manager",
        "model",
        "models",
        "objects",
        "orders",
        "records",
        "repo",
        "repository",
        "resources",
        "session",
        "store",
        "users",
    }
)
_NON_LOOKUP_CONTEXT = frozenset(
    {
        "array",
        "body",
        "config",
        "data",
        "headers",
        "list",
        "metadata",
        "options",
        "params",
        "query",
        "request",
        "result",
    }
)
_LOOKUP_METHODS = {
    "find": "repository_find",
    "findbyid": "repository_find",
    "findfirst": "repository_find",
    "findone": "repository_find",
    "findunique": "repository_find",
    "fetch": "repository_get",
    "fetchbyid": "repository_get",
    "get": "repository_get",
    "getbyid": "repository_get",
    "getitem": "repository_get",
    "getobject": "repository_get",
    "getrecord": "repository_get",
    "lookup": "repository_lookup",
    "lookupbyid": "repository_lookup",
    "load": "repository_get",
    "one": "orm_first",
    "oneornone": "orm_first",
    "retrieve": "repository_get",
    "select": "orm_filter",
    "where": "orm_filter",
}
_GUARD_NAMES = frozenset(
    {
        "authorize",
        "authorizeaccess",
        "canaccess",
        "checkaccess",
        "checkauthorization",
        "checkauthorized",
        "checkpermission",
        "checkowner",
        "checkownership",
        "checktenant",
        "ensureaccess",
        "ensureauthorized",
        "ensureowner",
        "ensuretenant",
        "enforceaccess",
        "enforceowner",
        "enforcetenant",
        "hasaccess",
        "mayaccess",
        "ownsresource",
        "permissionrequired",
        "requireaccess",
        "requireauthorization",
        "requireowner",
        "requiretenant",
        "tenantfilter",
        "tenantguard",
        "verifyaccess",
        "verifyowner",
        "verifyownership",
        "verifytenant",
    }
)
_GUARD_WORDS = re.compile(
    r"(?:authorize|authoriz|permission|access|ownership|owner|tenant|principal)", re.IGNORECASE
)


class EcmaScriptCwe639ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-639 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe639ScanError(RuntimeError):
    """Fixed scanner failure which never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe639ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe639ScanErrorCode:
            raise TypeError("ECMAScript CWE-639 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-639 authorization scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe639ScanLimits:
    """Hard ceilings applied before and during CST and local-flow analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_nodes: int = _MAX_LIMITS[1]
    max_depth: int = _MAX_LIMITS[2]
    max_signals: int = _MAX_LIMITS[3]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_nodes, self.max_depth, self.max_signals)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("ECMAScript CWE-639 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE639_SCAN_LIMITS = EcmaScriptCwe639ScanLimits()


class EcmaScriptCwe639Operation(StrEnum):
    """Record lookup shapes which accept a user-controlled key."""

    RECORD_SUBSCRIPT = "record_subscript"
    REPOSITORY_GET = "repository_get"
    REPOSITORY_FIND = "repository_find"
    REPOSITORY_LOOKUP = "repository_lookup"
    ORM_GET = "orm_get"
    ORM_FILTER = "orm_filter"
    ORM_FIRST = "orm_first"

    # Compatibility aliases used by generic scanner consumers.
    USER_CONTROLLED_KEY_LOOKUP = "record_subscript"
    INSECURE_OBJECT_LOOKUP = "record_subscript"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe639Signal:
    """One immutable request-key-to-record-lookup fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe639Operation
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
            except (TypeError, ValueError):
                identity_valid = False
        ranges_valid = (
            type(self.source) is SourceRange
            and type(self.sink) is SourceRange
            and self.sink.contains(self.source)
            and self.source.end_byte <= self.source_size_bytes
            and self.sink.end_byte <= self.source_size_bytes
        )
        expected = (
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
            if identity_valid
            and ranges_valid
            and type(self.operation) is EcmaScriptCwe639Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not EcmaScriptCwe639Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-639"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("ECMAScript CWE-639 signal is invalid")
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
class EcmaScriptCwe639ScanResult:
    """Deterministic, source-free CWE-639 output for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe639Signal, ...]
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
            and self.language in {"javascript", "typescript"}
        )
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except (TypeError, ValueError):
                identity_valid = False
        signals_valid = type(self.signals) is tuple and all(
            type(item) is EcmaScriptCwe639Signal for item in self.signals
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
            if signals_valid
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
            if signals_valid
            else False
        )
        if (
            not identity_valid
            or not signals_valid
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
            or len({item.signal_id for item in self.signals}) != len(self.signals)
            or not same_identity
            or type(self.scan_sha256) is not str
            or _SHA256.fullmatch(self.scan_sha256) is None
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
            raise ValueError("ECMAScript CWE-639 scan result is invalid")


def scan_javascript_cwe639(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe639ScanLimits = DEFAULT_ECMASCRIPT_CWE639_SCAN_LIMITS,
) -> EcmaScriptCwe639ScanResult:
    """Find bounded JavaScript user-controlled record-key lookups."""

    return _scan_ecmascript_cwe639(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe639(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe639ScanLimits = DEFAULT_ECMASCRIPT_CWE639_SCAN_LIMITS,
) -> EcmaScriptCwe639ScanResult:
    """Find bounded TypeScript user-controlled record-key lookups."""

    return _scan_ecmascript_cwe639(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe639(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe639ScanLimits = DEFAULT_ECMASCRIPT_CWE639_SCAN_LIMITS,
) -> EcmaScriptCwe639ScanResult:
    """Dispatch a CWE-639 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe639(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe639(symbol_index, limits=limits)
    raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.REQUEST_INVALID)


@dataclass(frozen=True, slots=True)
class _Fact:
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe639Operation


def _scan_ecmascript_cwe639(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe639ScanLimits,
) -> EcmaScriptCwe639ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe639ScanLimits:
        raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.ANALYSIS_UNAVAILABLE)
    builder = (
        build_javascript_symbol_index
        if expected_language == "javascript"
        else build_typescript_symbol_index
    )
    try:
        rebuilt = builder(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source=symbol_index.source,
        )
        if rebuilt != symbol_index:
            raise ValueError("symbol index mismatch")
        grammar = (
            _javascript_language()
            if expected_language == "javascript"
            else _typescript_language(tsx=symbol_index.path.endswith(".tsx"))
        )
        source = symbol_index.source
        source.decode("utf-8", errors="strict")
        root = Parser(Language(grammar)).parse(source).root_node
    except (CstAdapterError, TypeError, UnicodeDecodeError, ValueError):
        raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.INTEGRITY_FAILURE) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.ANALYSIS_UNAVAILABLE)
        aliases = _collect_aliases(nodes, source, limits)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe639Operation]] = set()
        for node in nodes:
            fact: _Fact | None = None
            if node.type == "subscript_expression":
                fact = _subscript_fact(node, source, aliases, limits)
            elif node.type == "call_expression":
                fact = _call_fact(node, source, aliases, limits)
            if fact is None:
                continue
            if not _is_guarded(node, source, limits):
                raw.add((fact.source, fact.sink, fact.operation))
                if len(raw) > limits.max_signals:
                    raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.SIGNAL_LIMIT)
        ordered = tuple(
            sorted(
                raw,
                key=lambda item: (
                    item[1].start_byte,
                    item[1].end_byte,
                    item[0].start_byte,
                    item[0].end_byte,
                    item[2].value,
                ),
            )
        )
    except EcmaScriptCwe639ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.INTEGRITY_FAILURE) from None

    signals = tuple(
        EcmaScriptCwe639Signal(
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
    return EcmaScriptCwe639ScanResult(
        repository_id=symbol_index.repository_id,
        revision=symbol_index.revision,
        path=symbol_index.path,
        content_sha256=symbol_index.content_sha256,
        source_size_bytes=symbol_index.source_byte_length,
        language=expected_language,
        signals=signals,
        scan_sha256=_scan_sha256(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            expected_language,
            signals,
        ),
    )


def _bounded_nodes(root: Node, limits: EcmaScriptCwe639ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _subscript_fact(
    node: Node,
    source: bytes,
    aliases: dict[str, Node],
    limits: EcmaScriptCwe639ScanLimits,
) -> _Fact | None:
    object_node = node.child_by_field_name("object")
    index_node = node.child_by_field_name("index")
    if object_node is None or index_node is None or not _is_lookup_target(object_node, source, aliases):
        return None
    source_node = _user_input_node(index_node, source, aliases, limits, frozenset(), 0)
    if source_node is None:
        return None
    return _fact(source_node, node, EcmaScriptCwe639Operation.RECORD_SUBSCRIPT)


def _call_fact(
    node: Node,
    source: bytes,
    aliases: dict[str, Node],
    limits: EcmaScriptCwe639ScanLimits,
) -> _Fact | None:
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None:
        return None
    canonical = _canonical_expression(function, source)
    if canonical is None:
        return None
    parts = [_normalise_name(part) for part in canonical.split(".") if part]
    if not parts or parts[-1] not in _LOOKUP_METHODS:
        return None
    receiver = function.child_by_field_name("object")
    if receiver is None or not _is_lookup_target(receiver, source, aliases):
        return None
    operation = EcmaScriptCwe639Operation(_LOOKUP_METHODS[parts[-1]])
    values = tuple(arguments.named_children)
    for value in values[:3]:
        source_node = _user_input_node(value, source, aliases, limits, frozenset(), 0)
        if source_node is not None:
            return _fact(source_node, node, operation)
    return None


def _fact(
    source_node: Node,
    sink_node: Node,
    operation: EcmaScriptCwe639Operation,
) -> _Fact:
    source_range = _range(source_node)
    sink_range = _range(sink_node)
    if not sink_range.contains(source_range):
        raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.INTEGRITY_FAILURE)
    return _Fact(source_range, sink_range, operation)


def _is_lookup_target(node: Node, source: bytes, aliases: dict[str, Node]) -> bool:
    current = _unwrap(node)
    canonical = _canonical_expression(current, source)
    if canonical is None:
        return False
    parts = [_normalise_name(part) for part in canonical.split(".") if part]
    if not parts:
        return False
    if parts[0] in _REQUEST_ROOTS or parts[0] in _NON_LOOKUP_CONTEXT:
        return False
    if any(part in _REQUEST_FIELDS for part in parts):
        return False
    if any(part in _LOOKUP_CONTEXT for part in parts):
        return True
    if current.type == "identifier" and _normalise_name(_node_text(source, current)) in _LOOKUP_CONTEXT:
        return True
    if current.type in {"member_expression", "subscript_expression"}:
        base = current.child_by_field_name("object")
        if base is not None and _unwrap(base).type == "this" and any(
            part in _LOOKUP_CONTEXT for part in parts[1:]
        ):
            return True
    del aliases
    return False


def _user_input_node(
    node: Node,
    source: bytes,
    aliases: dict[str, Node],
    limits: EcmaScriptCwe639ScanLimits,
    visited: frozenset[str],
    depth: int,
) -> Node | None:
    if depth > limits.max_depth:
        raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.DEPTH_LIMIT)
    current = _unwrap(node)
    if _is_request_expression(current, source):
        return current
    if current.type == "identifier":
        name = _node_text(source, current)
        bound = aliases.get(name)
        if bound is not None and name not in visited:
            resolved = _user_input_node(
                bound, source, aliases, limits, visited | {name}, depth + 1
            )
            if resolved is not None:
                return current
        if _is_key_parameter(current, source):
            return current
        return None
    if current.type in {"member_expression", "subscript_expression"}:
        if _is_request_expression(current, source):
            return current
        for child in current.named_children:
            resolved = _user_input_node(child, source, aliases, limits, visited, depth + 1)
            if resolved is not None:
                return current if current.type == "member_expression" else resolved
        return None
    if current.type == "call_expression":
        function = current.child_by_field_name("function")
        if function is not None and _is_request_accessor(function, source):
            return current
        for child in current.named_children:
            resolved = _user_input_node(child, source, aliases, limits, visited, depth + 1)
            if resolved is not None:
                return resolved
        return None
    if current.type == "pair":
        value = current.child_by_field_name("value")
        return (
            _user_input_node(value, source, aliases, limits, visited, depth + 1)
            if value is not None
            else None
        )
    for child in current.named_children:
        resolved = _user_input_node(child, source, aliases, limits, visited, depth + 1)
        if resolved is not None:
            return resolved
    return None


def _is_request_expression(node: Node, source: bytes) -> bool:
    canonical = _canonical_expression(node, source)
    if canonical is None:
        return False
    parts = [_normalise_name(part) for part in canonical.split(".") if part]
    if len(parts) < 2 or parts[0] not in _REQUEST_ROOTS:
        return False
    return any(part in _REQUEST_FIELDS for part in parts[1:])


def _is_request_accessor(node: Node, source: bytes) -> bool:
    canonical = _canonical_expression(node, source)
    if canonical is None:
        return False
    parts = [_normalise_name(part) for part in canonical.split(".") if part]
    return bool(
        len(parts) >= 2
        and parts[0] in _REQUEST_ROOTS
        and parts[-1] in _REQUEST_ACCESSORS
    )


def _is_key_parameter(node: Node, source: bytes) -> bool:
    name = _normalise_name(_node_text(source, node))
    if name not in _KEY_NAMES:
        return False
    current = node.parent
    while current is not None:
        if current.type in _FUNCTION_TYPES:
            parameters = current.child_by_field_name("parameters")
            if parameters is None:
                return False
            return any(
                child.type in {"identifier", "required_parameter", "optional_parameter", "rest_pattern"}
                and name in _normalise_name(_compact_text(source, child))
                for child in _walk_nodes(parameters)
            )
        current = current.parent
    return False


def _is_guarded(node: Node, source: bytes, limits: EcmaScriptCwe639ScanLimits) -> bool:
    scope = _enclosing_scope(node)
    if scope is None:
        return False
    for current in _scope_nodes(scope, limits):
        if current.start_byte >= node.start_byte:
            continue
        if current.type == "call_expression" and _is_guard_call(current, source):
            return True
        if current.type == "binary_expression" and _is_owner_comparison(current, source):
            return True
    return False


def _is_guard_call(node: Node, source: bytes) -> bool:
    function = node.child_by_field_name("function")
    if function is None:
        return False
    canonical = _canonical_expression(function, source)
    if canonical is None:
        return False
    leaf = _normalise_name(canonical.rsplit(".", 1)[-1])
    if leaf in _GUARD_NAMES:
        return True
    return bool(_GUARD_WORDS.search(leaf) and leaf.endswith(("guard", "check", "authorize", "access")))


def _is_owner_comparison(node: Node, source: bytes) -> bool:
    if _compact_text(source, node).count(".") < 1:
        return False
    text = _normalise_name(_compact_text(source, node))
    owner = any(word in text for word in ("owner", "tenant", "account", "principal"))
    identity = any(word in text for word in ("user", "principal", "tenant", "account", "identity", "auth"))
    return owner and identity


def _collect_aliases(
    nodes: tuple[Node, ...], source: bytes, limits: EcmaScriptCwe639ScanLimits
) -> dict[str, Node]:
    aliases: dict[str, Node] = {}
    for node in nodes:
        if node.type == "variable_declarator":
            left = node.child_by_field_name("name")
            right = node.child_by_field_name("value")
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
        else:
            continue
        if left is None or right is None or left.type != "identifier":
            continue
        aliases[_node_text(source, left)] = right
        if len(aliases) > limits.max_nodes:
            raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.NODE_LIMIT)
    return aliases


def _enclosing_scope(node: Node) -> Node | None:
    current = node.parent
    while current is not None:
        if current.type in _FUNCTION_TYPES:
            return current
        current = current.parent
    return None


def _scope_nodes(scope: Node, limits: EcmaScriptCwe639ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    while stack:
        current = stack.pop()
        output.append(current)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.NODE_LIMIT)
        if current is not scope and current.type in _FUNCTION_TYPES:
            continue
        stack.extend(reversed(current.named_children))
    return tuple(output)


def _walk_nodes(root: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [root]
    while stack:
        current = stack.pop()
        output.append(current)
        stack.extend(reversed(current.named_children))
    return tuple(output)


def _unwrap(node: Node) -> Node:
    current = node
    while current.type in _WRAPPER_TYPES and current.named_children:
        current = current.named_children[0]
    return current


def _canonical_expression(node: Node | None, source: bytes) -> str | None:
    if node is None:
        return None
    current = _unwrap(node)
    if current.type in {"identifier", "property_identifier", "private_property_identifier", "this"}:
        return _node_text(source, current)
    if current.type in {"member_expression", "subscript_expression"}:
        object_node = current.child_by_field_name("object")
        property_node = current.child_by_field_name("property") or current.child_by_field_name("index")
        base = _canonical_expression(object_node, source)
        name = _static_property_name(property_node, source)
        if base and name:
            return f"{base}.{name}"
        return None
    if current.type == "call_expression":
        function = current.child_by_field_name("function")
        if function is not None:
            return _canonical_expression(function, source)
    return None


def _static_property_name(node: Node | None, source: bytes) -> str | None:
    if node is None:
        return None
    current = _unwrap(node)
    if current.type == "computed_property_name" and current.named_children:
        return _static_property_name(current.named_children[0], source)
    if current.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        return _node_text(source, current)
    if current.type in {"string", "string_fragment"}:
        return _string_value(current, source)
    return None


def _string_value(node: Node, source: bytes) -> str | None:
    value = source[node.start_byte : node.end_byte]
    if node.type == "string":
        if len(value) < 2 or value[:1] not in {b"'", b'"', b"`"} or value[-1:] != value[:1]:
            return None
        value = value[1:-1]
    if b"\\" in value or b"\n" in value or b"\r" in value:
        return None
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.INTEGRITY_FAILURE) from None


def _node_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe639ScanError(EcmaScriptCwe639ScanErrorCode.INTEGRITY_FAILURE) from None


def _compact_text(source: bytes, node: Node) -> str:
    return "".join(_node_text(source, node).split())


def _normalise_name(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^A-Za-z0-9]+", "", value).lower()


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
    operation: EcmaScriptCwe639Operation,
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
    language: str,
    signals: tuple[EcmaScriptCwe639Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-639",
        "detector": _DETECTOR,
        "language": language,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
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
