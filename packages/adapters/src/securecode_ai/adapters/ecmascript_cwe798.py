"""Bounded ECMAScript CWE-798 hard-coded credential facts.

The scanner recognizes credential-shaped names whose values are static string
literals.  It also recognizes static credential arguments in high-confidence
authentication calls and credential fields in object literals.  Values are
used only transiently while classifying a syntax node and never leave this
module.  Signals contain source ranges, not source text or literal values.
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
_RULE_ID = "securecode-ecmascript-cwe798"
_DETECTOR = "securecode-ecmascript-cwe798@1.0"
_DETAIL = "hardcoded_credential"

_AUTH_NAME = re.compile(
    r"(?:^|[_$-])(?:password|passwd|passphrase|passcode|secret|token|api[_-]?key|"
    r"access[_-]?key|access[_-]?token|auth(?:entication|orization)?[_-]?token|"
    r"client[_-]?secret|credential|private[_-]?key|signing[_-]?key|jwt|bearer)"
    r"(?:$|[_$-])",
    re.IGNORECASE,
)
_AUTH_CALL = re.compile(
    r"(?:authenticate|authentication|authorize|basicauth|connect|createclient|"
    r"login|log_in|signin|sign_in|setcredentials|verifycredentials|"
    r"exchangecredentials|issue(?:token)?|refresh(?:token)?|resetpassword)",
    re.IGNORECASE,
)
_AUTH_FIELD = re.compile(
    r"(?:password|passwd|passphrase|passcode|secret|token|api[_-]?key|access[_-]?key|"
    r"access[_-]?token|credential|private[_-]?key|signing[_-]?key|jwt|bearer|"
    r"authorization)",
    re.IGNORECASE,
)
_PLACEHOLDER = re.compile(
    r"(?:^|[_\- .])(?:changeme|change[-_ ]?this|dummy|example|fake|fixture|"
    r"placeholder|sample|test(?:ing)?|todo|your(?:[-_ ]|$)|replace(?:[-_ ]|$)|"
    r"redacted|not[-_ ]?set)(?:$|[_\- .])",
    re.IGNORECASE,
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


class EcmaScriptCwe798ScanErrorCode(StrEnum):
    """Closed, source-free reasons a hard-coded credential scan can fail."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe798ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe798ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe798ScanErrorCode:
            raise TypeError("ECMAScript CWE-798 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-798 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe798ScanLimits:
    """Hard ceilings applied before and during CST analysis."""

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
            raise ValueError("ECMAScript CWE-798 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE798_SCAN_LIMITS = EcmaScriptCwe798ScanLimits()


class EcmaScriptCwe798CredentialKind(StrEnum):
    """Stable categories without retaining the credential value."""

    AUTHENTICATOR = "authenticator"
    TOKEN = "token"
    KEY = "key_material"
    CREDENTIAL = "credential"
    AUTHORIZATION = "authorization"


class EcmaScriptCwe798Operation(StrEnum):
    """Where a static credential was observed."""

    HARDCODED_VALUE = "hardcoded_value"
    HARDCODED_FIELD = "hardcoded_field"
    HARDCODED_ARGUMENT = "hardcoded_argument"
    HARDCODED_DEFAULT = "hardcoded_default"

    # Compatibility aliases used by generic scanner consumers.
    STATIC_CREDENTIAL = "hardcoded_value"
    CONFIGURATION_FIELD = "hardcoded_field"
    AUTH_CALL_ARGUMENT = "hardcoded_argument"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe798Signal:
    """One immutable source-to-credential fact without the credential value."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe798Operation
    credential_kind: EcmaScriptCwe798CredentialKind
    credential_name: str = "credential_value"
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
            and type(self.credential_name) is str
            and 0 < len(self.credential_name) <= 256
            and "\n" not in self.credential_name
            and "\r" not in self.credential_name
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
                self.credential_kind,
                self.credential_name,
            )
            if identity_valid
            and ranges_valid
            and type(self.operation) is EcmaScriptCwe798Operation
            and type(self.credential_kind) is EcmaScriptCwe798CredentialKind
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not EcmaScriptCwe798Operation
            or type(self.credential_kind) is not EcmaScriptCwe798CredentialKind
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-798"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("ECMAScript CWE-798 signal is invalid")
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

    @property
    def variable_name(self) -> str:
        return self.credential_name


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe798ScanResult:
    """Deterministic and source-free output for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe798Signal, ...]
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
            except ValueError:
                identity_valid = False
        valid_signals = type(self.signals) is tuple and all(
            type(item) is EcmaScriptCwe798Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    item.sink.start_byte,
                    item.sink.end_byte,
                    item.source.start_byte,
                    item.source.end_byte,
                    item.operation.value,
                    item.credential_kind.value,
                    item.credential_name,
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
            raise ValueError("ECMAScript CWE-798 scan result is invalid")


def scan_javascript_cwe798(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe798ScanLimits = DEFAULT_ECMASCRIPT_CWE798_SCAN_LIMITS,
) -> EcmaScriptCwe798ScanResult:
    """Find JavaScript hard-coded credential facts."""

    return _scan_ecmascript_cwe798(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe798(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe798ScanLimits = DEFAULT_ECMASCRIPT_CWE798_SCAN_LIMITS,
) -> EcmaScriptCwe798ScanResult:
    """Find TypeScript hard-coded credential facts."""

    return _scan_ecmascript_cwe798(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe798(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe798ScanLimits = DEFAULT_ECMASCRIPT_CWE798_SCAN_LIMITS,
) -> EcmaScriptCwe798ScanResult:
    """Dispatch a CWE-798 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe798ScanError(EcmaScriptCwe798ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe798(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe798(symbol_index, limits=limits)
    raise EcmaScriptCwe798ScanError(EcmaScriptCwe798ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe798(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe798ScanLimits,
) -> EcmaScriptCwe798ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe798ScanLimits:
        raise EcmaScriptCwe798ScanError(EcmaScriptCwe798ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe798ScanError(EcmaScriptCwe798ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe798ScanError(EcmaScriptCwe798ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe798ScanError(EcmaScriptCwe798ScanErrorCode.ANALYSIS_UNAVAILABLE)

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
        raise EcmaScriptCwe798ScanError(EcmaScriptCwe798ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe798ScanError(EcmaScriptCwe798ScanErrorCode.INTEGRITY_FAILURE) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe798ScanError(EcmaScriptCwe798ScanErrorCode.ANALYSIS_UNAVAILABLE)
        raw: set[
            tuple[
                SourceRange,
                SourceRange,
                EcmaScriptCwe798Operation,
                EcmaScriptCwe798CredentialKind,
                str,
            ]
        ] = set()
        for node in nodes:
            if node.type in {"variable_declarator", "assignment_expression", "field_definition"}:
                _collect_binding_fact(node, source, raw)
            elif node.type == "pair":
                _collect_pair_fact(node, source, raw)
            elif node.type in {"assignment_pattern", "required_parameter"}:
                _collect_default_fact(node, source, raw)
            elif node.type in {"call_expression", "new_expression"}:
                _collect_call_facts(node, source, raw)
            if len(raw) > limits.max_signals:
                raise EcmaScriptCwe798ScanError(EcmaScriptCwe798ScanErrorCode.SIGNAL_LIMIT)
        ordered = tuple(
            sorted(
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
        )
    except EcmaScriptCwe798ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe798ScanError(EcmaScriptCwe798ScanErrorCode.INTEGRITY_FAILURE) from None

    signals = tuple(
        EcmaScriptCwe798Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
            credential_kind=kind,
            credential_name=name,
        )
        for source_range, sink_range, operation, kind, name in ordered
    )
    return EcmaScriptCwe798ScanResult(
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


def _collect_binding_fact(
    node: Node,
    source: bytes,
    raw: set[
        tuple[
            SourceRange, SourceRange, EcmaScriptCwe798Operation, EcmaScriptCwe798CredentialKind, str
        ]
    ],
) -> None:
    if node.type == "variable_declarator":
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
    elif node.type == "field_definition":
        name = node.child_by_field_name("property") or node.child_by_field_name("name")
        value = node.child_by_field_name("value")
    else:
        name = node.child_by_field_name("left")
        value = node.child_by_field_name("right")
    if name is None or value is None:
        return
    name_text = _node_text(source, name)
    if not _is_credential_name(name_text):
        return
    literal = _static_literal(value, source)
    if literal is None:
        return
    classification = _classify_name(name_text)
    if classification is None or not _is_credential_literal(literal, source):
        return
    operation = (
        EcmaScriptCwe798Operation.HARDCODED_DEFAULT
        if node.type == "assignment_expression"
        else EcmaScriptCwe798Operation.HARDCODED_VALUE
    )
    raw.add((_range(literal), _range(node), operation, classification, _safe_name(name_text)))


def _collect_pair_fact(
    node: Node,
    source: bytes,
    raw: set[
        tuple[
            SourceRange, SourceRange, EcmaScriptCwe798Operation, EcmaScriptCwe798CredentialKind, str
        ]
    ],
) -> None:
    key = node.child_by_field_name("key")
    value = node.child_by_field_name("value")
    if key is None or value is None:
        return
    key_text = _static_property_name(key, source)
    if key_text is None or not _is_credential_name(key_text):
        return
    literal = _static_literal(value, source)
    if literal is None or not _is_credential_literal(literal, source):
        return
    classification = _classify_name(key_text)
    if classification is not None:
        raw.add(
            (
                _range(literal),
                _range(node),
                EcmaScriptCwe798Operation.HARDCODED_FIELD,
                classification,
                _safe_name(key_text),
            )
        )


def _collect_default_fact(
    node: Node,
    source: bytes,
    raw: set[
        tuple[
            SourceRange, SourceRange, EcmaScriptCwe798Operation, EcmaScriptCwe798CredentialKind, str
        ]
    ],
) -> None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return
    name_text = _node_text(source, left)
    literal = _static_literal(right, source)
    classification = _classify_name(name_text)
    if classification is None or literal is None or not _is_credential_literal(literal, source):
        return
    raw.add(
        (
            _range(literal),
            _range(node),
            EcmaScriptCwe798Operation.HARDCODED_DEFAULT,
            classification,
            _safe_name(name_text),
        )
    )


def _collect_call_facts(
    node: Node,
    source: bytes,
    raw: set[
        tuple[
            SourceRange, SourceRange, EcmaScriptCwe798Operation, EcmaScriptCwe798CredentialKind, str
        ]
    ],
) -> None:
    function = node.child_by_field_name("function") or node.child_by_field_name("constructor")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None:
        return
    name = _static_property_name(function, source) or _compact_text(source, function)
    leaf = name.rsplit(".", 1)[-1]
    if not _AUTH_CALL.search(leaf):
        return
    values = tuple(arguments.named_children)
    for index, argument in enumerate(values):
        if index == 0 and len(values) > 1 and _looks_user_argument(argument, source):
            continue
        literal = _static_literal(argument, source)
        if literal is None or not _is_credential_literal(literal, source):
            continue
        kind = _classify_name(leaf) or EcmaScriptCwe798CredentialKind.AUTHENTICATOR
        raw.add(
            (
                _range(literal),
                _range(node),
                EcmaScriptCwe798Operation.HARDCODED_ARGUMENT,
                kind,
                _safe_name(leaf),
            )
        )


def _is_credential_name(value: str) -> bool:
    normalized = _normalize_name(value)
    return bool(_AUTH_NAME.search(normalized) or _AUTH_FIELD.search(normalized))


def _classify_name(value: str) -> EcmaScriptCwe798CredentialKind | None:
    normalized = _normalize_name(value)
    compact = normalized.replace("_", "")
    if any(word in compact for word in ("password", "passwd", "passphrase", "passcode")):
        return EcmaScriptCwe798CredentialKind.AUTHENTICATOR
    if any(word in compact for word in ("token", "jwt", "bearer")):
        return EcmaScriptCwe798CredentialKind.TOKEN
    if any(word in compact for word in ("apikey", "accesskey", "privatekey", "signingkey")):
        return EcmaScriptCwe798CredentialKind.KEY
    if "authorization" in compact or compact.startswith("auth"):
        return EcmaScriptCwe798CredentialKind.AUTHORIZATION
    if any(word in compact for word in ("secret", "credential")):
        return EcmaScriptCwe798CredentialKind.CREDENTIAL
    return None


def _is_credential_literal(node: Node, source: bytes) -> bool:
    value = _literal_value(node, source)
    if value is None or len(value.strip()) < 4:
        return False
    normalized = _normalize_name(value)
    return not _PLACEHOLDER.search(normalized)


def _looks_user_argument(node: Node, source: bytes) -> bool:
    text = _compact_text(source, node)
    return bool(
        re.search(r"(?:^|[_$.-])(?:user|username|login|email|identity)(?:$|[_$.-])", text, re.I)
    )


def _static_literal(node: Node, source: bytes) -> Node | None:
    current = _unwrap(node)
    if current.type == "string":
        return current
    if current.type == "template_string" and not any(
        child.type == "template_substitution" for child in current.named_children
    ):
        return current
    return None


def _literal_value(node: Node, source: bytes) -> str | None:
    try:
        value = source[node.start_byte : node.end_byte]
        if node.type == "string":
            if len(value) < 2 or value[:1] not in {b"'", b'"', b"`"} or value[-1:] != value[:1]:
                return None
            value = value[1:-1]
        if b"\\" in value or b"\n" in value or b"\r" in value:
            return None
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe798ScanError(EcmaScriptCwe798ScanErrorCode.INTEGRITY_FAILURE) from None


def _safe_name(value: str) -> str:
    normalized = _normalize_name(value)
    return normalized[:256] or "credential_value"


def _normalize_name(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()


def _compact_text(source: bytes, node: Node) -> str:
    return "".join(_node_text(source, node).split())


def _node_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe798ScanError(EcmaScriptCwe798ScanErrorCode.INTEGRITY_FAILURE) from None


def _static_property_name(node: Node, source: bytes) -> str | None:
    current = _unwrap(node)
    if current.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        return _node_text(source, current)
    if current.type == "string":
        return _literal_value(current, source)
    return None


def _unwrap(node: Node) -> Node:
    current = node
    while current.type in _WRAPPER_TYPES:
        children = tuple(current.named_children)
        if not children:
            break
        current = children[-1]
    return current


def _bounded_nodes(root: Node, limits: EcmaScriptCwe798ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe798ScanError(EcmaScriptCwe798ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe798ScanError(EcmaScriptCwe798ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
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
    operation: EcmaScriptCwe798Operation,
    credential_kind: EcmaScriptCwe798CredentialKind,
    credential_name: str,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "credential_kind": credential_kind.value,
        "credential_name": credential_name,
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    language: str,
    signals: tuple[EcmaScriptCwe798Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-798",
        "detector": _DETECTOR,
        "language": language,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
                "credential_kind": signal.credential_kind.value,
                "credential_name": signal.credential_name,
                "detail": signal.detail,
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


scan_javascript_hardcoded_credentials = scan_javascript_cwe798
scan_typescript_hardcoded_credentials = scan_typescript_cwe798
scan_ecmascript_hardcoded_credentials = scan_ecmascript_cwe798


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE798_SCAN_LIMITS",
    "EcmaScriptCwe798CredentialKind",
    "EcmaScriptCwe798Operation",
    "EcmaScriptCwe798ScanError",
    "EcmaScriptCwe798ScanErrorCode",
    "EcmaScriptCwe798ScanLimits",
    "EcmaScriptCwe798ScanResult",
    "EcmaScriptCwe798Signal",
    "scan_ecmascript_cwe798",
    "scan_ecmascript_hardcoded_credentials",
    "scan_javascript_cwe798",
    "scan_javascript_hardcoded_credentials",
    "scan_typescript_cwe798",
    "scan_typescript_hardcoded_credentials",
]
