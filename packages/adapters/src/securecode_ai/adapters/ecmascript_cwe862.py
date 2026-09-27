"""Bounded ECMAScript route checks for missing authorization (CWE-862).

This detector deliberately targets sensitive registered HTTP routes which show
an authentication boundary but no authorization check. Route discovery and
framework binding reuse the narrow syntax model from CWE-306. Authentication
and authorization are classified separately here, so a login guard alone does
not suppress an access-control finding.

Only source ranges and content-addressed identities leave this module. Unknown
frameworks, malformed syntax, and unresolved parser state fail closed.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import ParseHealth, RepositoryFile, SourceRange, SymbolIndex
from tree_sitter import Language, Node, Parser

from . import ecmascript_cwe306 as _cwe306
from .cst import CstAdapterError, build_javascript_symbol_index, build_typescript_symbol_index
from .cst_ecmascript import _javascript_language, _typescript_language

_MAX_LIMITS = (2_000_000, 250_000, 512, 10_000)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-ecmascript-cwe862"
_DETECTOR = "securecode-ecmascript-cwe862@1.0"
_DETAIL = "authenticated_critical_route_without_authorization"

_AUTHN = re.compile(
    r"(?:^|[_$.-])(?:authenticate|authentication|authenticated|authn|jwt|"
    r"loginrequired|passport|requireauth(?:entication)?|sessionauth|"
    r"verifytoken|verifyuser|isloggedin|isauthenticated)(?:$|[_$.-])",
    re.IGNORECASE,
)
_AUTHZ = re.compile(
    r"(?:^|[_$.-])(?:authorize|authorization|authz|canaccess|checkaccess|"
    r"checkauthorization|checkauthorized|checkpermission|checkowner|"
    r"checkownership|checktenant|ensureaccess|ensureauthorized|ensureowner|"
    r"ensuretenant|enforceaccess|enforceowner|enforcetenant|hasaccess|"
    r"haspermission|hasrole|mayaccess|ownsresource|permissionrequired|"
    r"requireaccess|requireauthorization|requireowner|requirepermission|"
    r"requirerole|requiretenant|rolecheck|tenantfilter|tenantguard|"
    r"verifyaccess|verifyowner|verifyownership|verifypermission|verifyrole|"
    r"verifytenant|isadmin|isowner|canactivate)(?:$|[_$.-])",
    re.IGNORECASE,
)
_AUTHZ_CONDITION = re.compile(
    r"(?:admin|authoriz|authz|access|permission|privilege|role|scope|"
    r"owner|ownership|tenant|principal|resource)",
    re.IGNORECASE,
)


class EcmaScriptCwe862ScanErrorCode(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe862ScanError(RuntimeError):
    """Fixed source-free scan error."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe862ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe862ScanErrorCode:
            raise TypeError("ECMAScript CWE-862 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-862 authorization scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe862ScanLimits:
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
            raise ValueError("ECMAScript CWE-862 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE862_SCAN_LIMITS = EcmaScriptCwe862ScanLimits()


class EcmaScriptCwe862Operation(StrEnum):
    CRITICAL_ROUTE = "critical_route_handler"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe862Signal:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe862Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-862"
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
            if identity_valid and ranges_valid and type(self.operation) is EcmaScriptCwe862Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not EcmaScriptCwe862Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-862"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("ECMAScript CWE-862 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        return self.signal_id

    @property
    def location(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe862ScanResult:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe862Signal, ...]
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
            and self.language in {"javascript", "typescript"}
        )
        if valid_identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except (TypeError, ValueError):
                valid_identity = False
        valid_signals = type(self.signals) is tuple and all(
            type(item) is EcmaScriptCwe862Signal for item in self.signals
        )
        order = (
            tuple(
                (item.sink.start_byte, item.sink.end_byte, item.source.start_byte)
                for item in self.signals
            )
            if valid_signals
            else ()
        )
        same_identity = valid_signals and all(
            item.repository_id == self.repository_id
            and item.revision == self.revision
            and item.path == self.path
            and item.content_sha256 == self.content_sha256
            and item.source_size_bytes == self.source_size_bytes
            for item in self.signals
        )
        if (
            not valid_identity
            or not valid_signals
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
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
            raise ValueError("ECMAScript CWE-862 scan result is invalid")


def scan_javascript_cwe862(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe862ScanLimits = DEFAULT_ECMASCRIPT_CWE862_SCAN_LIMITS,
) -> EcmaScriptCwe862ScanResult:
    return _scan(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe862(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe862ScanLimits = DEFAULT_ECMASCRIPT_CWE862_SCAN_LIMITS,
) -> EcmaScriptCwe862ScanResult:
    return _scan(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe862(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe862ScanLimits = DEFAULT_ECMASCRIPT_CWE862_SCAN_LIMITS,
) -> EcmaScriptCwe862ScanResult:
    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe862ScanError(EcmaScriptCwe862ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe862(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe862(symbol_index, limits=limits)
    raise EcmaScriptCwe862ScanError(EcmaScriptCwe862ScanErrorCode.REQUEST_INVALID)


def _scan(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe862ScanLimits,
) -> EcmaScriptCwe862ScanResult:
    if (
        type(symbol_index) is not SymbolIndex
        or type(limits) is not EcmaScriptCwe862ScanLimits
        or symbol_index.language != expected_language
    ):
        raise EcmaScriptCwe862ScanError(EcmaScriptCwe862ScanErrorCode.REQUEST_INVALID)
    source = symbol_index.source
    if len(source) > limits.max_source_bytes:
        raise EcmaScriptCwe862ScanError(EcmaScriptCwe862ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe862ScanError(EcmaScriptCwe862ScanErrorCode.ANALYSIS_UNAVAILABLE)
    try:
        builder = (
            build_javascript_symbol_index
            if expected_language == "javascript"
            else build_typescript_symbol_index
        )
        rebuilt = builder(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source=source,
        )
        if rebuilt != symbol_index:
            raise ValueError("index mismatch")
        source.decode("utf-8", errors="strict")
        grammar = (
            _javascript_language()
            if expected_language == "javascript"
            else _typescript_language(tsx=symbol_index.path.endswith(".tsx"))
        )
        root = Parser(Language(grammar)).parse(source).root_node
        inner_limits = _cwe306.EcmaScriptCwe306ScanLimits(
            max_source_bytes=limits.max_source_bytes,
            max_nodes=limits.max_nodes,
            max_depth=limits.max_depth,
            max_signals=limits.max_signals,
        )
        nodes = _cwe306._bounded_nodes(root, inner_limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe862ScanError(EcmaScriptCwe862ScanErrorCode.ANALYSIS_UNAVAILABLE)
        aliases = _cwe306._collect_aliases(nodes, source)
        bindings = _cwe306._collect_function_bindings(nodes, source)
        authn_global, authn_path, authz_global, authz_path = _collect_guards(nodes, source, aliases)
        raw: set[tuple[SourceRange, SourceRange]] = set()
        for node in nodes:
            if node.type != "call_expression":
                continue
            candidate = _cwe306._route_candidate(node, source, aliases, bindings)
            if candidate is None or not _cwe306._critical_path(candidate.path, candidate.method):
                continue
            if (
                _has_route_guard(
                    candidate,
                    source,
                    aliases,
                    bindings,
                    _AUTHN,
                    authn_global,
                    authn_path,
                )
                and not _has_route_guard(
                    candidate,
                    source,
                    aliases,
                    bindings,
                    _AUTHZ,
                    authz_global,
                    authz_path,
                )
                and not _handler_has_authorization(candidate, source, aliases)
            ):
                source_range = _cwe306._range(candidate.path_node)
                sink_range = _cwe306._range(candidate.route)
                if not sink_range.contains(source_range):
                    raise EcmaScriptCwe862ScanError(EcmaScriptCwe862ScanErrorCode.INTEGRITY_FAILURE)
                raw.add((source_range, sink_range))
                if len(raw) > limits.max_signals:
                    raise EcmaScriptCwe862ScanError(EcmaScriptCwe862ScanErrorCode.SIGNAL_LIMIT)
        ordered = tuple(
            sorted(raw, key=lambda pair: (pair[1].start_byte, pair[1].end_byte, pair[0].start_byte))
        )
    except EcmaScriptCwe862ScanError:
        raise
    except _cwe306.EcmaScriptCwe306ScanError as exc:
        code = {
            _cwe306.EcmaScriptCwe306ScanErrorCode.NODE_LIMIT: EcmaScriptCwe862ScanErrorCode.NODE_LIMIT,
            _cwe306.EcmaScriptCwe306ScanErrorCode.DEPTH_LIMIT: EcmaScriptCwe862ScanErrorCode.DEPTH_LIMIT,
            _cwe306.EcmaScriptCwe306ScanErrorCode.SIGNAL_LIMIT: EcmaScriptCwe862ScanErrorCode.SIGNAL_LIMIT,
            _cwe306.EcmaScriptCwe306ScanErrorCode.SOURCE_LIMIT: EcmaScriptCwe862ScanErrorCode.SOURCE_LIMIT,
            _cwe306.EcmaScriptCwe306ScanErrorCode.ANALYSIS_UNAVAILABLE: EcmaScriptCwe862ScanErrorCode.ANALYSIS_UNAVAILABLE,
        }.get(exc.code, EcmaScriptCwe862ScanErrorCode.INTEGRITY_FAILURE)
        raise EcmaScriptCwe862ScanError(code) from None
    except (CstAdapterError, TypeError, ValueError, UnicodeDecodeError):
        raise EcmaScriptCwe862ScanError(EcmaScriptCwe862ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe862ScanError(EcmaScriptCwe862ScanErrorCode.INTEGRITY_FAILURE) from None

    signals = tuple(
        EcmaScriptCwe862Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=EcmaScriptCwe862Operation.CRITICAL_ROUTE,
        )
        for source_range, sink_range in ordered
    )
    return EcmaScriptCwe862ScanResult(
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


def _collect_guards(
    nodes: tuple[Node, ...], source: bytes, aliases: dict[str, str]
) -> tuple[frozenset[str], frozenset[tuple[str, str]], frozenset[str], frozenset[tuple[str, str]]]:
    authn_global: set[str] = set()
    authn_path: set[tuple[str, str]] = set()
    authz_global: set[str] = set()
    authz_path: set[tuple[str, str]] = set()
    for node in nodes:
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        arguments_node = node.child_by_field_name("arguments")
        if function is None or arguments_node is None:
            continue
        canonical = _cwe306._canonical_expression(function, source, aliases)
        if canonical is None or canonical.rsplit(".", 1)[-1].lower() != "use":
            continue
        receiver = canonical.rsplit(".", 1)[0]
        if not _cwe306._is_framework_receiver(receiver):
            continue
        arguments = tuple(arguments_node.named_children)
        if not arguments:
            continue
        path = _cwe306._string_value(arguments[0], source)
        middleware = arguments[1:] if path is not None else arguments
        checks = tuple(_guard_kinds(item, source, aliases) for item in middleware)
        key = (receiver, _cwe306._normalise_path(path)) if path is not None else None
        if any("authn" in kinds for kinds in checks):
            if key is None:
                authn_global.add(receiver)
            else:
                authn_path.add(key)
        if any("authz" in kinds for kinds in checks):
            if key is None:
                authz_global.add(receiver)
            else:
                authz_path.add(key)
    return (
        frozenset(authn_global),
        frozenset(authn_path),
        frozenset(authz_global),
        frozenset(authz_path),
    )


def _has_route_guard(
    candidate: _cwe306._RouteCandidate,
    source: bytes,
    aliases: dict[str, str],
    bindings: dict[str, Node],
    pattern: re.Pattern[str],
    global_guards: frozenset[str],
    path_guards: frozenset[tuple[str, str]],
) -> bool:
    receiver = candidate.receiver
    path_key = (receiver, _cwe306._normalise_path(candidate.path))
    if (
        receiver in global_guards
        or path_key in path_guards
        or any(
            guard_receiver == receiver
            and (path_key[1] == guard_path or path_key[1].startswith(f"{guard_path}/"))
            for guard_receiver, guard_path in path_guards
        )
    ):
        return True
    arguments = candidate.arguments
    for item in arguments[1:]:
        current = _cwe306._unwrap(item)
        if (
            current.start_byte == candidate.handler.start_byte
            and current.end_byte == candidate.handler.end_byte
        ):
            continue
        canonical = _cwe306._canonical_expression(current, source, aliases)
        value = canonical or _cwe306._compact_text(source, current)
        if pattern.search(_normalise_name(value.rsplit(".", 1)[-1])):
            return True
        if current.type == "identifier":
            bound = bindings.get(_cwe306._node_text(source, current))
            if bound is not None and _handler_has_matching_call(bound, source, aliases, pattern):
                return True
    return False


def _guard_kinds(node: Node, source: bytes, aliases: dict[str, str]) -> frozenset[str]:
    current = _cwe306._unwrap(node)
    canonical = _cwe306._canonical_expression(current, source, aliases)
    value = canonical or _cwe306._compact_text(source, current)
    normalised = _normalise_name(value.rsplit(".", 1)[-1])
    kinds: set[str] = set()
    if _AUTHN.search(normalised):
        kinds.add("authn")
    if _AUTHZ.search(normalised):
        kinds.add("authz")
    return frozenset(kinds)


def _handler_has_authorization(
    candidate: _cwe306._RouteCandidate, source: bytes, aliases: dict[str, str]
) -> bool:
    handler = candidate.handler
    resource_calls = _handler_resource_calls(handler, source, aliases)
    route_parameters = _route_parameters(candidate.path)
    first_resource = resource_calls[0] if resource_calls else None
    for node in _cwe306._walk_nodes(handler):
        if _same_node(node, handler) or _nested_function(node, handler):
            continue
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            canonical = (
                _cwe306._canonical_expression(function, source, aliases)
                if function is not None
                else None
            )
            if canonical is None or not _AUTHZ.search(
                _normalise_name(canonical.rsplit(".", 1)[-1])
            ):
                continue
            if not _call_matches_authorization(
                node,
                handler,
                first_resource,
                route_parameters,
                source,
                aliases,
            ):
                continue
            return True
        elif node.type == "if_statement":
            condition = node.child_by_field_name("condition")
            if condition is None:
                continue
            condition_authz_calls = tuple(
                child
                for child in _cwe306._walk_nodes(condition)
                if child.type == "call_expression"
                and (function := child.child_by_field_name("function")) is not None
                and (canonical := _cwe306._canonical_expression(function, source, aliases))
                is not None
                and _AUTHZ.search(_normalise_name(canonical.rsplit(".", 1)[-1]))
            )
            if condition_authz_calls:
                if any(
                    _call_matches_authorization(
                        child,
                        handler,
                        first_resource,
                        route_parameters,
                        source,
                        aliases,
                    )
                    for child in condition_authz_calls
                ):
                    return True
                continue
            text = _cwe306._compact_text(source, condition)
            if (
                _AUTHZ_CONDITION.search(text)
                and _has_denial(node, source)
                and (
                    first_resource is None
                    or not route_parameters
                    or _condition_matches_resource(condition, first_resource, source, aliases)
                )
            ):
                return True
    return False


_RESOURCE_READ_METHODS = frozenset(
    {"fetch", "find", "findbyid", "findone", "get", "list", "load", "lookup", "query", "read"}
)


def _handler_resource_calls(
    handler: Node, source: bytes, aliases: dict[str, str]
) -> tuple[Node, ...]:
    calls: list[Node] = []
    for node in _cwe306._walk_nodes(handler):
        if (
            _same_node(node, handler)
            or node.type != "call_expression"
            or _nested_function(node, handler)
        ):
            continue
        function = node.child_by_field_name("function")
        canonical = (
            _cwe306._canonical_expression(function, source, aliases)
            if function is not None
            else None
        )
        if canonical is None:
            continue
        parts = tuple(_normalise_name(part) for part in canonical.split("."))
        if len(parts) < 2 or parts[-1] not in (
            _RESOURCE_READ_METHODS | frozenset(_cwe306._RESOURCE_METHODS) | {"update"}
        ):
            continue
        if _cwe306._resource_receiver(parts[:-1]):
            calls.append(node)
    calls.sort(key=lambda item: (item.start_byte, item.end_byte))
    return tuple(calls)


def _authorization_dominates(node: Node, handler: Node, source: bytes) -> bool:
    """Accept only a guard that runs on every path before the resource use."""
    current = node.parent
    while current is not None and not _same_node(current, handler):
        if current.type == "if_statement":
            condition = current.child_by_field_name("condition")
            if condition is None or not _contains_node(condition, node):
                return False
            return _has_denial(current, source)
        if current.type in {
            "conditional_expression",
            "do_statement",
            "for_in_statement",
            "for_of_statement",
            "for_statement",
            "switch_case",
            "switch_statement",
            "try_statement",
            "while_statement",
        }:
            return False
        current = current.parent
    return _same_node(current, handler)


def _same_node(left: Node | None, right: Node) -> bool:
    if left is None:
        return False
    return (
        left.type == right.type
        and left.start_byte == right.start_byte
        and left.end_byte == right.end_byte
    )


def _nested_function(node: Node, function: Node) -> bool:
    parent = node.parent
    while parent is not None and not _same_node(parent, function):
        if parent.type in {"arrow_function", "function_expression", "function_declaration"}:
            return True
        parent = parent.parent
    return False


def _call_matches_authorization(
    node: Node,
    handler: Node,
    first_resource: Node | None,
    route_parameters: frozenset[str],
    source: bytes,
    aliases: dict[str, str],
) -> bool:
    if not _authorization_dominates(node, handler, source):
        return False
    if first_resource is not None:
        return node.start_byte < first_resource.start_byte and _same_resource(
            node, first_resource, source, aliases
        )
    return not route_parameters or bool(
        route_parameters.intersection(_argument_tokens(node, source, aliases))
    )


def _condition_matches_resource(
    condition: Node, resource: Node, source: bytes, aliases: dict[str, str]
) -> bool:
    condition_tokens = _condition_tokens(condition, source, aliases)
    resource_tokens = _argument_tokens(resource, source, aliases)
    return bool(condition_tokens.intersection(resource_tokens))


def _same_resource(
    authorization: Node, resource: Node, source: bytes, aliases: dict[str, str]
) -> bool:
    authorized = _argument_references(authorization, source, aliases)
    selected = _argument_references(resource, source, aliases)
    return bool(authorized and selected and authorized.intersection(selected))


def _argument_references(call: Node, source: bytes, aliases: dict[str, str]) -> frozenset[str]:
    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return frozenset()
    result: set[str] = set()
    for argument in arguments.named_children:
        current = _cwe306._unwrap(argument)
        canonical = _cwe306._canonical_expression(current, source, aliases)
        if canonical is not None:
            result.add(canonical.lower())
        text = _cwe306._compact_text(source, current).lower()
        if text:
            result.add(text)
    return frozenset(result)


def _argument_tokens(call: Node, source: bytes, aliases: dict[str, str]) -> frozenset[str]:
    references = _argument_references(call, source, aliases)
    tokens: set[str] = set()
    for value in references:
        tokens.update(re.findall(r"[a-z_][a-z0-9_]*", value))
    return frozenset(tokens)


def _condition_tokens(condition: Node, source: bytes, aliases: dict[str, str]) -> frozenset[str]:
    tokens: set[str] = set()
    for node in _cwe306._walk_nodes(condition):
        if node.type == "call_expression":
            tokens.update(_argument_tokens(node, source, aliases))
        elif node.type in {
            "identifier",
            "property_identifier",
            "shorthand_property_identifier_pattern",
        }:
            tokens.add(_normalise_name(_cwe306._node_text(source, node)))
    return frozenset(tokens)


def _route_parameters(path: str) -> frozenset[str]:
    return frozenset(
        match.group(1).lower() for match in re.finditer(r":([A-Za-z_][A-Za-z0-9_]*)", path)
    )


def _contains_node(container: Node, target: Node) -> bool:
    return container.start_byte <= target.start_byte and target.end_byte <= container.end_byte


def _handler_has_matching_call(
    handler: Node, source: bytes, aliases: dict[str, str], pattern: re.Pattern[str]
) -> bool:
    return any(
        node.type == "call_expression"
        and (function := node.child_by_field_name("function")) is not None
        and (canonical := _cwe306._canonical_expression(function, source, aliases)) is not None
        and pattern.search(_normalise_name(canonical.rsplit(".", 1)[-1]))
        for node in _cwe306._walk_nodes(handler)
    )


def _has_denial(statement: Node, source: bytes) -> bool:
    text = _cwe306._compact_text(source, statement).lower()
    return any(
        token in text
        for token in (
            "return",
            "throw",
            "status(403)",
            "sendstatus(403)",
            "forbidden",
            "accessdenied",
        )
    )


def _normalise_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _signal_id(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    source: SourceRange,
    sink: SourceRange,
    operation: EcmaScriptCwe862Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-862",
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
    signals: tuple[EcmaScriptCwe862Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-862",
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


def _range_value(location: SourceRange) -> dict[str, int]:
    return {
        "end_byte": location.end_byte,
        "end_column": location.end_point.column,
        "end_row": location.end_point.row,
        "start_byte": location.start_byte,
        "start_column": location.start_point.column,
        "start_row": location.start_point.row,
    }


scan_javascript_missing_authorization = scan_javascript_cwe862
scan_typescript_missing_authorization = scan_typescript_cwe862
scan_ecmascript_missing_authorization = scan_ecmascript_cwe862
