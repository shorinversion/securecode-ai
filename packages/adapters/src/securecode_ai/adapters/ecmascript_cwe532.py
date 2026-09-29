"""Bounded ECMAScript CWE-532 sensitive-data-to-log facts.

The scanner follows explicitly named credential, token, secret, password,
authorization, and key values to known logging calls.  It accepts only the
admitted :class:`~securecode_ai.core.SymbolIndex`, rebuilds the index from the
same bytes, and fails closed for malformed or resource-exhausted input.
Signals retain immutable source ranges and content-addressed identifiers.  No
source text, secret value, parser message, or environment value is retained in
results or errors.
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

_MAX_LIMITS = (2_000_000, 250_000, 512, 20_000, 10_000)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_RULE_ID = "securecode-ecmascript-cwe532"
_DETECTOR = "securecode-ecmascript-cwe532@1.0"
_DETAIL = "sensitive_value_to_log_sink"

_SENSITIVE_COMPONENTS = frozenset(
    {
        "accesskey",
        "accesstoken",
        "apikey",
        "authheader",
        "authtoken",
        "authorization",
        "bearer",
        "clientsecret",
        "credential",
        "credentials",
        "idtoken",
        "jwt",
        "keyfile",
        "password",
        "passphrase",
        "passwd",
        "privatekey",
        "refreshtoken",
        "secret",
        "secretkey",
        "sessiontoken",
        "signingkey",
        "token",
    }
)
_PASSWORD_COMPONENTS = frozenset({"password", "passphrase", "passwd"})
_KEY_COMPONENTS = frozenset(
    {"accesskey", "apikey", "keyfile", "privatekey", "secretkey", "signingkey"}
)
_AUTH_COMPONENTS = frozenset({"authheader", "authorization", "bearer"})
_TOKEN_COMPONENTS = frozenset(
    {"accesstoken", "authtoken", "idtoken", "jwt", "refreshtoken", "sessiontoken", "token"}
)
_SECRET_COMPONENTS = frozenset({"clientsecret", "secret", "credentials", "credential"})
_SAFE_NAME_MARKERS = frozenset({"digest", "hash", "masked", "redacted", "safe", "sanitized"})
_SENSITIVE_CALL_PREFIXES = frozenset(
    {"fetch", "find", "get", "load", "lookup", "read", "retrieve", "resolve"}
)
_LOGGER_METHODS = frozenset(
    {"critical", "debug", "error", "fatal", "info", "log", "notice", "trace", "warn", "warning"}
)
_LOGGER_ROOTS = frozenset(
    {
        "audit",
        "auditlogger",
        "bunyan",
        "console",
        "debug",
        "log",
        "logger",
        "logging",
        "pino",
        "winston",
    }
)
_SAFE_REDACTION_NAMES = frozenset(
    {
        "anonymize",
        "digestsecret",
        "hashsecret",
        "mask",
        "masksecret",
        "obfuscate",
        "redact",
        "redactsecret",
        "removecredentials",
        "removesecrets",
        "sanitizeforlog",
        "sanitizeforlogging",
        "scrub",
        "scrubsecrets",
        "stripsecrets",
        "tokenize",
        "truncatesecret",
    }
)
_NESTED_FUNCTIONS = frozenset(
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
_EXPRESSION_NODES = frozenset(
    {
        "array",
        "assignment_expression",
        "await_expression",
        "binary_expression",
        "conditional_expression",
        "member_expression",
        "new_expression",
        "non_null_expression",
        "parenthesized_expression",
        "sequence_expression",
        "spread_element",
        "subscript_expression",
        "template_string",
        "template_substitution",
        "ternary_expression",
        "type_assertion",
        "unary_expression",
        "update_expression",
    }
)


class EcmaScriptCwe532ScanErrorCode(StrEnum):
    """Closed, source-free reasons an analysis cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    ALIAS_LIMIT = "ALIAS_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe532ScanError(RuntimeError):
    """Fixed scanner failure which never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe532ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe532ScanErrorCode:
            raise TypeError("ECMAScript CWE-532 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-532 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class EcmaScriptCwe532SensitiveKind(StrEnum):
    """Stable categories for explicitly named sensitive values."""

    AUTHORIZATION = "authorization"
    CREDENTIAL = "credential"
    KEY = "key"
    AUTHENTICATOR = "pass" + "word"
    SENSITIVE = "sec" + "ret"
    TOKEN = "token"


class EcmaScriptCwe532Operation(StrEnum):
    """Known logging sink classes."""

    CONSOLE = "console_log"
    LOGGER = "logger_message"
    STRUCTURED_LOGGER = "structured_logger_message"
    STREAM = "stream_log"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe532ScanLimits:
    """Hard ceilings applied before and during CST analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_nodes: int = _MAX_LIMITS[1]
    max_depth: int = _MAX_LIMITS[2]
    max_signals: int = _MAX_LIMITS[3]
    max_aliases: int = _MAX_LIMITS[4]

    def __post_init__(self) -> None:
        values = (
            self.max_source_bytes,
            self.max_nodes,
            self.max_depth,
            self.max_signals,
            self.max_aliases,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("ECMAScript CWE-532 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE532_SCAN_LIMITS = EcmaScriptCwe532ScanLimits()


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe532Signal:
    """One immutable sensitive-value-to-logging fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe532Operation
    sensitive_kind: EcmaScriptCwe532SensitiveKind
    sensitive_name: str = "sensitive_value"
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-532"
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
            and type(self.sensitive_name) is str
            and 0 < len(self.sensitive_name) <= 256
        )
        if valid_identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid_identity = False
        valid_ranges = (
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
                self.sensitive_kind,
                self.sensitive_name,
            )
            if valid_identity
            and valid_ranges
            and type(self.operation) is EcmaScriptCwe532Operation
            and type(self.sensitive_kind) is EcmaScriptCwe532SensitiveKind
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not EcmaScriptCwe532Operation
            or type(self.sensitive_kind) is not EcmaScriptCwe532SensitiveKind
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-532"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("ECMAScript CWE-532 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete logging call location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink

    @property
    def variable_name(self) -> str:
        """Compatibility name for consumers using local-flow terminology."""

        return self.sensitive_name


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe532ScanResult:
    """Deterministic, source-free result for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe532Signal, ...]
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
            except ValueError:
                valid_identity = False
        valid_signals = type(self.signals) is tuple and all(
            type(item) is EcmaScriptCwe532Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    item.sink.start_byte,
                    item.sink.end_byte,
                    item.source.start_byte,
                    item.source.end_byte,
                    item.operation.value,
                    item.sensitive_kind.value,
                    item.sensitive_name,
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
                self.language,
                self.signals,
            )
        ):
            raise ValueError("ECMAScript CWE-532 scan result is invalid")


def scan_javascript_cwe532(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe532ScanLimits = DEFAULT_ECMASCRIPT_CWE532_SCAN_LIMITS,
) -> EcmaScriptCwe532ScanResult:
    """Find bounded JavaScript sensitive values reaching logging sinks."""

    return _scan_ecmascript_cwe532(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe532(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe532ScanLimits = DEFAULT_ECMASCRIPT_CWE532_SCAN_LIMITS,
) -> EcmaScriptCwe532ScanResult:
    """Find bounded TypeScript sensitive values reaching logging sinks."""

    return _scan_ecmascript_cwe532(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe532(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe532ScanLimits = DEFAULT_ECMASCRIPT_CWE532_SCAN_LIMITS,
) -> EcmaScriptCwe532ScanResult:
    """Dispatch a CWE-532 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe532(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe532(symbol_index, limits=limits)
    raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe532(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe532ScanLimits,
) -> EcmaScriptCwe532ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe532ScanLimits:
        raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.ANALYSIS_UNAVAILABLE)

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
        raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.INTEGRITY_FAILURE) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.ANALYSIS_UNAVAILABLE)
        aliases = _collect_aliases(nodes, source, limits)
        logger_names = _collect_logger_names(nodes, source, aliases, limits)
        raw: set[
            tuple[
                SourceRange,
                SourceRange,
                EcmaScriptCwe532Operation,
                EcmaScriptCwe532SensitiveKind,
                str,
            ]
        ] = set()
        for node in nodes:
            if node.type != "call_expression":
                continue
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if function is None or arguments is None:
                continue
            operation = _logging_operation(function, source, aliases, logger_names)
            if operation is None:
                continue
            scope = _enclosing_scope(node, root)
            sink_range = _range(node)
            for argument in arguments.named_children:
                for source_node, sensitive_kind in _resolve_sensitive_occurrences(
                    argument,
                    scope=scope,
                    source=source,
                    aliases=aliases,
                    limits=limits,
                    depth=0,
                    visited=frozenset(),
                ):
                    source_range = _range(source_node)
                    if not sink_range.contains(source_range):
                        raise EcmaScriptCwe532ScanError(
                            EcmaScriptCwe532ScanErrorCode.INTEGRITY_FAILURE
                        )
                    raw.add(
                        (
                            source_range,
                            sink_range,
                            operation,
                            sensitive_kind,
                            _sensitive_label(source_node, source, sensitive_kind),
                        )
                    )
                    if len(raw) > limits.max_signals:
                        raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.SIGNAL_LIMIT)
        ordered = sorted(
            raw,
            key=lambda item: (
                item[1].start_byte,
                item[1].end_byte,
                item[0].start_byte,
                item[0].end_byte,
                item[2].value,
                item[3].value,
                item[4],
            ),
        )
    except EcmaScriptCwe532ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.INTEGRITY_FAILURE) from None

    signals = tuple(
        EcmaScriptCwe532Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
            sensitive_kind=sensitive_kind,
            sensitive_name=sensitive_name,
        )
        for source_range, sink_range, operation, sensitive_kind, sensitive_name in ordered
    )
    return EcmaScriptCwe532ScanResult(
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


def _resolve_sensitive_occurrences(
    node: Node,
    *,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe532ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[tuple[Node, EcmaScriptCwe532SensitiveKind], ...]:
    if depth > limits.max_depth:
        raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.DEPTH_LIMIT)
    if _is_safe_redaction_call(node, source, aliases):
        return ()
    direct = _sensitive_expression_kind(node, source, aliases)
    if direct is not None:
        return ((node, direct),)
    if node.type == "identifier":
        name = _node_text(source, node)
        if name in visited:
            return ()
        bound = _latest_binding(scope, name, node.start_byte, source)
        if bound is None:
            return ()
        kinds = _sensitive_value_kinds(
            bound,
            scope=scope,
            source=source,
            aliases=aliases,
            limits=limits,
            depth=depth + 1,
            visited=visited | {name},
        )
        return tuple((node, kind) for kind in sorted(kinds, key=lambda item: item.value))
    if node.type == "object":
        return _resolve_object_occurrences(
            node,
            scope=scope,
            source=source,
            aliases=aliases,
            limits=limits,
            depth=depth + 1,
            visited=visited,
        )
    if node.type == "pair":
        return _resolve_pair_occurrences(
            node,
            scope=scope,
            source=source,
            aliases=aliases,
            limits=limits,
            depth=depth + 1,
            visited=visited,
        )
    if node.type in _EXPRESSION_NODES or node.type == "call_expression":
        return _resolve_children(
            node,
            scope=scope,
            source=source,
            aliases=aliases,
            limits=limits,
            depth=depth + 1,
            visited=visited,
        )
    return ()


def _resolve_object_occurrences(
    node: Node,
    *,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe532ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[tuple[Node, EcmaScriptCwe532SensitiveKind], ...]:
    values: list[tuple[Node, EcmaScriptCwe532SensitiveKind]] = []
    for child in node.named_children:
        if child.type == "pair":
            values.extend(
                _resolve_pair_occurrences(
                    child,
                    scope=scope,
                    source=source,
                    aliases=aliases,
                    limits=limits,
                    depth=depth,
                    visited=visited,
                )
            )
        elif child.type in {
            "shorthand_property_identifier",
            "shorthand_property_identifier_pattern",
        }:
            kind = _sensitive_expression_kind(child, source, aliases)
            if kind is not None:
                values.append((child, kind))
        else:
            values.extend(
                _resolve_sensitive_occurrences(
                    child,
                    scope=scope,
                    source=source,
                    aliases=aliases,
                    limits=limits,
                    depth=depth,
                    visited=visited,
                )
            )
    return _unique_occurrences(values)


def _resolve_pair_occurrences(
    node: Node,
    *,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe532ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[tuple[Node, EcmaScriptCwe532SensitiveKind], ...]:
    value = node.child_by_field_name("value")
    key = node.child_by_field_name("key")
    if value is None:
        return ()
    key_kind = _sensitive_name_kind(_static_property_name(key, source) if key is not None else None)
    if _is_safe_redaction_call(value, source, aliases):
        return ()
    resolved = _resolve_sensitive_occurrences(
        value,
        scope=scope,
        source=source,
        aliases=aliases,
        limits=limits,
        depth=depth,
        visited=visited,
    )
    if resolved:
        if key_kind is None:
            return resolved
        return tuple((item, key_kind) for item, _ in resolved)
    if key_kind is not None:
        if _is_known_safe_value(
            value,
            scope=scope,
            source=source,
            aliases=aliases,
            limits=limits,
            depth=depth,
            visited=visited,
        ):
            return ()
        return ((value, key_kind),)
    return ()


def _resolve_children(
    node: Node,
    *,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe532ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[tuple[Node, EcmaScriptCwe532SensitiveKind], ...]:
    values: list[tuple[Node, EcmaScriptCwe532SensitiveKind]] = []
    for child in node.named_children:
        values.extend(
            _resolve_sensitive_occurrences(
                child,
                scope=scope,
                source=source,
                aliases=aliases,
                limits=limits,
                depth=depth,
                visited=visited,
            )
        )
    return _unique_occurrences(values)


def _sensitive_value_kinds(
    node: Node,
    *,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe532ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> frozenset[EcmaScriptCwe532SensitiveKind]:
    direct = _sensitive_expression_kind(node, source, aliases)
    if direct is not None:
        return frozenset({direct})
    if _is_safe_redaction_call(node, source, aliases):
        return frozenset()
    if node.type == "identifier":
        name = _node_text(source, node)
        if name in visited:
            return frozenset()
        bound = _latest_binding(scope, name, node.start_byte, source)
        if bound is None:
            return frozenset()
        return _sensitive_value_kinds(
            bound,
            scope=scope,
            source=source,
            aliases=aliases,
            limits=limits,
            depth=depth + 1,
            visited=visited | {name},
        )
    if node.type == "pair":
        value = node.child_by_field_name("value")
        key = node.child_by_field_name("key")
        key_kind = _sensitive_name_kind(
            _static_property_name(key, source) if key is not None else None
        )
        if value is None:
            return frozenset({key_kind}) if key_kind is not None else frozenset()
        nested = _sensitive_value_kinds(
            value,
            scope=scope,
            source=source,
            aliases=aliases,
            limits=limits,
            depth=depth + 1,
            visited=visited,
        )
        return frozenset({key_kind}) if key_kind is not None else nested
    if node.type == "object":
        kinds: set[EcmaScriptCwe532SensitiveKind] = set()
        for child in node.named_children:
            kinds.update(
                _sensitive_value_kinds(
                    child,
                    scope=scope,
                    source=source,
                    aliases=aliases,
                    limits=limits,
                    depth=depth + 1,
                    visited=visited,
                )
            )
        return frozenset(kinds)
    if node.type in _EXPRESSION_NODES or node.type == "call_expression":
        kinds = set()
        for child in node.named_children:
            kinds.update(
                _sensitive_value_kinds(
                    child,
                    scope=scope,
                    source=source,
                    aliases=aliases,
                    limits=limits,
                    depth=depth + 1,
                    visited=visited,
                )
            )
        return frozenset(kinds)
    return frozenset()


def _is_known_safe_value(
    node: Node,
    *,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe532ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> bool:
    if depth > limits.max_depth:
        raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.DEPTH_LIMIT)
    if _is_safe_redaction_call(node, source, aliases):
        return True
    if node.type != "identifier":
        return False
    name = _node_text(source, node)
    if name in visited:
        return False
    bound = _latest_binding(scope, name, node.start_byte, source)
    if bound is None:
        return False
    return _is_known_safe_value(
        bound,
        scope=scope,
        source=source,
        aliases=aliases,
        limits=limits,
        depth=depth + 1,
        visited=visited | {name},
    )


def _unique_occurrences(
    values: list[tuple[Node, EcmaScriptCwe532SensitiveKind]],
) -> tuple[tuple[Node, EcmaScriptCwe532SensitiveKind], ...]:
    unique: dict[
        tuple[int, int, EcmaScriptCwe532SensitiveKind], tuple[Node, EcmaScriptCwe532SensitiveKind]
    ] = {}
    for node, kind in values:
        unique[(node.start_byte, node.end_byte, kind)] = (node, kind)
    return tuple(
        unique[key] for key in sorted(unique, key=lambda item: (item[0], item[1], item[2].value))
    )


def _sensitive_expression_kind(
    node: Node,
    source: bytes,
    aliases: dict[str, str],
) -> EcmaScriptCwe532SensitiveKind | None:
    if node.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        return _sensitive_name_kind(_node_text(source, node))
    if node.type in {"member_expression", "subscript_expression"}:
        property_node = node.child_by_field_name("property") or node.child_by_field_name("index")
        return _sensitive_name_kind(_static_property_name(property_node, source))
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        canonical = _canonical_expression(function, source, aliases)
        function_name = (canonical or _compact_text(source, function)).rsplit(".", 1)[-1]
        normalized = _normalize_name(function_name)
        parts = normalized.split("_")
        if len(parts) >= 2 and parts[0] in _SENSITIVE_CALL_PREFIXES:
            direct = _sensitive_name_kind("".join(parts[1:]))
            if direct is not None:
                return direct
        if arguments is not None and normalized in {
            "get",
            "getheader",
            "header",
            "headerget",
            "input",
            "param",
            "query",
        }:
            for argument in arguments.named_children:
                value = _string_value(argument, source)
                kind = _sensitive_name_kind(value)
                if kind is not None:
                    return kind
    return None


def _sensitive_name_kind(value: str | None) -> EcmaScriptCwe532SensitiveKind | None:
    if value is None or not value:
        return None
    normalized = _normalize_name(value)
    if any(marker in normalized.split("_") for marker in _SAFE_NAME_MARKERS):
        return None
    compact = normalized.replace("_", "")
    if compact in _PASSWORD_COMPONENTS:
        return EcmaScriptCwe532SensitiveKind.AUTHENTICATOR
    if compact in _KEY_COMPONENTS:
        return EcmaScriptCwe532SensitiveKind.KEY
    if compact in _AUTH_COMPONENTS:
        return EcmaScriptCwe532SensitiveKind.AUTHORIZATION
    if compact in _TOKEN_COMPONENTS:
        return EcmaScriptCwe532SensitiveKind.TOKEN
    if compact in _SECRET_COMPONENTS:
        return EcmaScriptCwe532SensitiveKind.SENSITIVE
    tokens = tuple(part for part in normalized.split("_") if part)
    if any(part in _PASSWORD_COMPONENTS for part in tokens):
        return EcmaScriptCwe532SensitiveKind.AUTHENTICATOR
    if any(part in _KEY_COMPONENTS for part in tokens):
        return EcmaScriptCwe532SensitiveKind.KEY
    if any(part in _AUTH_COMPONENTS for part in tokens):
        return EcmaScriptCwe532SensitiveKind.AUTHORIZATION
    if any(part in _TOKEN_COMPONENTS for part in tokens):
        return EcmaScriptCwe532SensitiveKind.TOKEN
    if any(part in _SECRET_COMPONENTS for part in tokens):
        return EcmaScriptCwe532SensitiveKind.SENSITIVE
    if compact in _SENSITIVE_COMPONENTS:
        return EcmaScriptCwe532SensitiveKind.CREDENTIAL
    return None


def _normalize_name(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    value = re.sub(r"[^A-Za-z0-9]+", "_", value)
    return value.strip("_").lower()


def _sensitive_label(
    node: Node,
    source: bytes,
    sensitive_kind: EcmaScriptCwe532SensitiveKind,
) -> str:
    """Return a bounded, source-free label without retaining a secret value."""

    if node.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        value = _normalize_name(_node_text(source, node))
    elif node.type in {"member_expression", "subscript_expression"}:
        value = _normalize_name(
            _static_property_name(
                node.child_by_field_name("property") or node.child_by_field_name("index"),
                source,
            )
            or ""
        )
    else:
        value = ""
    return value[:256] or sensitive_kind.value


def _is_safe_redaction_call(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    if function is None:
        return False
    canonical = _canonical_expression(function, source, aliases)
    name = _normalize_name((canonical or _compact_text(source, function)).rsplit(".", 1)[-1])
    return name in _SAFE_REDACTION_NAMES


def _logging_operation(
    function: Node,
    source: bytes,
    aliases: dict[str, str],
    logger_names: set[str],
) -> EcmaScriptCwe532Operation | None:
    canonical = _canonical_expression(function, source, aliases)
    text = canonical or _compact_text(source, function)
    if function.type == "identifier" and text in logger_names:
        return EcmaScriptCwe532Operation.LOGGER
    method = text.rsplit(".", 1)[-1]
    root = text.split(".", 1)[0]
    if method not in _LOGGER_METHODS:
        if text in {"process.stdout.write", "process.stderr.write"}:
            return EcmaScriptCwe532Operation.STREAM
        return None
    if root == "console":
        return EcmaScriptCwe532Operation.CONSOLE
    if root in {"pino", "winston", "bunyan"} or _is_logger_receiver(text, root, logger_names):
        if text.count(".") >= 1 and root in {"pino", "winston", "bunyan"}:
            return EcmaScriptCwe532Operation.STRUCTURED_LOGGER
        return EcmaScriptCwe532Operation.LOGGER
    if text.startswith("pino(") or text.startswith("winston("):
        return EcmaScriptCwe532Operation.STRUCTURED_LOGGER
    return None


def _is_logger_receiver(text: str, root: str, logger_names: set[str]) -> bool:
    if root in _LOGGER_ROOTS or root in logger_names:
        return True
    if "." in text:
        receiver = text.rsplit(".", 1)[0]
        return receiver in logger_names or receiver.rsplit(".", 1)[-1] in _LOGGER_ROOTS
    return False


def _collect_logger_names(
    nodes: tuple[Node, ...],
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe532ScanLimits,
) -> set[str]:
    names = set(_LOGGER_ROOTS)
    for node in nodes:
        if node.type not in {"variable_declarator", "assignment_expression"}:
            continue
        left = (
            node.child_by_field_name("name")
            if node.type == "variable_declarator"
            else node.child_by_field_name("left")
        )
        right = (
            node.child_by_field_name("value")
            if node.type == "variable_declarator"
            else node.child_by_field_name("right")
        )
        if left is None or right is None or left.type != "identifier":
            continue
        canonical = _canonical_expression(right, source, aliases) or _compact_text(source, right)
        compact = canonical.replace(" ", "")
        if (
            compact.startswith("pino(")
            or compact.startswith("winston.createLogger(")
            or compact.startswith("createLogger(")
            or ".child(" in compact
            or any(compact.startswith(f"{name}.") for name in names)
            or _normalize_name(_node_text(source, left))
            in {"audit", "audit_logger", "logger", "logging"}
        ):
            names.add(_node_text(source, left))
            if len(names) > limits.max_aliases:
                raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.ALIAS_LIMIT)
    return names


def _collect_aliases(
    nodes: tuple[Node, ...],
    source: bytes,
    limits: EcmaScriptCwe532ScanLimits,
) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in nodes:
        if node.type not in {"variable_declarator", "assignment_expression"}:
            continue
        left = (
            node.child_by_field_name("name")
            if node.type == "variable_declarator"
            else node.child_by_field_name("left")
        )
        right = (
            node.child_by_field_name("value")
            if node.type == "variable_declarator"
            else node.child_by_field_name("right")
        )
        if left is None or right is None or left.type != "identifier":
            continue
        canonical = _canonical_expression(right, source, aliases)
        if canonical is not None:
            aliases[_node_text(source, left)] = canonical
            if len(aliases) > limits.max_aliases:
                raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.ALIAS_LIMIT)
    return aliases


def _canonical_expression(node: Node | None, source: bytes, aliases: dict[str, str]) -> str | None:
    if node is None:
        return None
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or _compact_text(source, function) != "require":
            return None
        values = list(arguments.named_children)
        return _string_value(values[0], source) if len(values) == 1 else None
    if node.type in {"member_expression", "subscript_expression"}:
        object_node = node.child_by_field_name("object")
        property_node = node.child_by_field_name("property") or node.child_by_field_name("index")
        if object_node is None or property_node is None:
            return None
        base = _canonical_expression(object_node, source, aliases)
        if base is None:
            base = _canonical_name(_compact_text(source, object_node), aliases)
        name = _static_property_name(property_node, source)
        return f"{base}.{name}" if base and name else None
    return _canonical_name(_compact_text(source, node), aliases)


def _canonical_name(value: str, aliases: dict[str, str]) -> str:
    parts = value.split(".")
    if not parts or not _IDENTIFIER.fullmatch(parts[0]):
        return value
    base = aliases.get(parts[0], parts[0])
    return ".".join((base, *parts[1:])) if len(parts) > 1 else base


def _static_property_name(node: Node | None, source: bytes) -> str | None:
    if node is None:
        return None
    if node.type == "computed_property_name":
        values = list(node.named_children)
        return _static_property_name(values[0], source) if len(values) == 1 else None
    if node.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        return _node_text(source, node)
    if node.type in {"string", "string_fragment"}:
        return _string_value(node, source)
    return None


def _string_value(node: Node | None, source: bytes) -> str | None:
    if node is None or node.type not in {"string", "string_fragment"}:
        return None
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
        raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.INTEGRITY_FAILURE) from None


def _node_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.INTEGRITY_FAILURE) from None


def _compact_text(source: bytes, node: Node | None) -> str:
    return "" if node is None else "".join(_node_text(source, node).split())


def _bounded_nodes(root: Node, limits: EcmaScriptCwe532ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe532ScanError(EcmaScriptCwe532ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _enclosing_scope(node: Node, root: Node) -> Node:
    current = node.parent
    while current is not None:
        if current.type in _NESTED_FUNCTIONS:
            return current
        current = current.parent
    return root


def _latest_binding(scope: Node, name: str, before: int, source: bytes) -> Node | None:
    bound: Node | None = None
    for node in _scope_preorder(scope):
        if node.start_byte >= before:
            continue
        if node.type == "variable_declarator":
            left = node.child_by_field_name("name")
            right = node.child_by_field_name("value")
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
        else:
            continue
        if (
            left is not None
            and right is not None
            and left.type == "identifier"
            and _node_text(source, left) == name
        ):
            bound = right
    return bound


def _scope_preorder(scope: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    first = True
    while stack:
        node = stack.pop()
        output.append(node)
        if not first and node.type in _NESTED_FUNCTIONS:
            continue
        first = False
        stack.extend(reversed(node.named_children))
    return tuple(output)


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
    operation: EcmaScriptCwe532Operation,
    sensitive_kind: EcmaScriptCwe532SensitiveKind,
    sensitive_name: str,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-532",
        "detector": _DETECTOR,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "sensitive_kind": sensitive_kind.value,
        "sensitive_name": sensitive_name,
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
    signals: tuple[EcmaScriptCwe532Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-532",
        "detector": _DETECTOR,
        "language": language,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
                "detail": signal.detail,
                "operation": signal.operation.value,
                "sensitive_kind": signal.sensitive_kind.value,
                "sensitive_name": signal.sensitive_name,
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


scan_javascript_sensitive_logging = scan_javascript_cwe532
scan_typescript_sensitive_logging = scan_typescript_cwe532
scan_ecmascript_sensitive_logging = scan_ecmascript_cwe532


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE532_SCAN_LIMITS",
    "EcmaScriptCwe532Operation",
    "EcmaScriptCwe532ScanError",
    "EcmaScriptCwe532ScanErrorCode",
    "EcmaScriptCwe532ScanLimits",
    "EcmaScriptCwe532ScanResult",
    "EcmaScriptCwe532SensitiveKind",
    "EcmaScriptCwe532Signal",
    "scan_ecmascript_cwe532",
    "scan_ecmascript_sensitive_logging",
    "scan_javascript_cwe532",
    "scan_javascript_sensitive_logging",
    "scan_typescript_cwe532",
    "scan_typescript_sensitive_logging",
]
