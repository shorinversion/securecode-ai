"""Bounded JavaScript and TypeScript CWE-338 weak PRNG facts.

The scanner looks for ``Math.random`` values that reach names and APIs which
normally carry authentication, session, reset, token, nonce, or key material.
It deliberately recognises only the deterministic weak PRNG family.  Calls to
``crypto.randomBytes``, Web Crypto ``getRandomValues`` and other CSPRNG APIs
therefore remain clean.  Findings contain immutable source ranges and hashes;
source text and parser diagnostics never leave this module.
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
_RULE_ID = "securecode-ecmascript-cwe338"
_DETECTOR = "securecode-ecmascript-cwe338@1.0"

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
    {"as_expression", "parenthesized_expression", "non_null_expression", "type_assertion"}
)
_SENSITIVE_WORDS = frozenset(
    {
        "accesskey",
        "apikey",
        "auth",
        "authorization",
        "cookie",
        "csrf",
        "csrftoken",
        "invite",
        "invitecode",
        "jwt",
        "key",
        "keymaterial",
        "magiclink",
        "nonce",
        "otp",
        "passcode",
        "passwordreset",
        "privatekey",
        "refresh",
        "refreshtoken",
        "reset",
        "resetlink",
        "resettoken",
        "secret",
        "session",
        "sessionid",
        "sessionkey",
        "signingkey",
        "token",
        "tokenvalue",
        "verification",
        "verificationcode",
        "verify",
    }
)
_SENSITIVE_NAME = re.compile(
    r"(?:access[_-]?key|api[_-]?key|auth(?:entication|orization)?|cookie|csrf|xsrf|"
    r"invite|jwt|magic[_-]?link|nonce|otp|passcode|password[_-]?reset|private[_-]?key|"
    r"refresh[_-]?token|reset(?:[_-]?link|[_-]?token)?|secret|session(?:[_-]?id|[_-]?key)?|"
    r"signing[_-]?key|token|verification(?:[_-]?code)?|verify)",
    re.IGNORECASE,
)
_SECURITY_SINKS = frozenset(
    {
        "createSession",
        "createSessionId",
        "createToken",
        "generateToken",
        "issueToken",
        "makeToken",
        "newSession",
        "resetPassword",
        "sendResetLink",
        "setCookie",
        "setHeader",
        "storeSession",
        "writeCookie",
    }
)
_SECURITY_SINK_TEXT = re.compile(
    r"(?:create|generate|issue|make|new|send|set|store|write).*(?:auth|cookie|key|nonce|reset|"
    r"secret|session|token|verification)|(?:password|reset).*(?:link|token)",
    re.IGNORECASE,
)


class EcmaScriptCwe338ScanErrorCode(StrEnum):
    """Closed reasons a weak-PRNG analysis cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe338ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe338ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe338ScanErrorCode:
            raise TypeError("ECMAScript CWE-338 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-338 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe338ScanLimits:
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
            raise ValueError("ECMAScript CWE-338 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE338_SCAN_LIMITS = EcmaScriptCwe338ScanLimits()


class EcmaScriptCwe338Operation(StrEnum):
    """Security value fed by a non-cryptographic pseudo-random source."""

    WEAK_PRNG_SECURITY_VALUE = "weak_prng_security_value"
    WEAK_PRNG_TOKEN = "weak_prng_token"
    WEAK_PRNG_SESSION_ID = "weak_prng_session_id"
    WEAK_PRNG_RESET_LINK = "weak_prng_reset_link"
    WEAK_PRNG_KEY_MATERIAL = "weak_prng_key_material"

    # Compatibility aliases for generic CWE consumers.
    INSECURE_RANDOM = "weak_prng_security_value"
    WEAK_RANDOM = "weak_prng_security_value"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe338Signal:
    """One immutable weak-randomness source-to-security-sink fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe338Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-338"
    detector: str = _DETECTOR
    detail: str = "weak_prng_security_value"

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
            if identity_valid and ranges_valid and type(self.operation) is EcmaScriptCwe338Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not EcmaScriptCwe338Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-338"
            or self.detector != _DETECTOR
            or self.detail != "weak_prng_security_value"
        ):
            raise ValueError("ECMAScript CWE-338 signal is invalid")
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
class EcmaScriptCwe338ScanResult:
    """Deterministic and source-free CWE-338 output for one source file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe338Signal, ...]
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
            type(item) is EcmaScriptCwe338Signal for item in self.signals
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
            raise ValueError("ECMAScript CWE-338 scan result is invalid")


def scan_javascript_cwe338(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe338ScanLimits = DEFAULT_ECMASCRIPT_CWE338_SCAN_LIMITS,
) -> EcmaScriptCwe338ScanResult:
    """Find JavaScript weak PRNG values used as security material."""

    return _scan_ecmascript_cwe338(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe338(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe338ScanLimits = DEFAULT_ECMASCRIPT_CWE338_SCAN_LIMITS,
) -> EcmaScriptCwe338ScanResult:
    """Find TypeScript weak PRNG values used as security material."""

    return _scan_ecmascript_cwe338(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe338(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe338ScanLimits = DEFAULT_ECMASCRIPT_CWE338_SCAN_LIMITS,
) -> EcmaScriptCwe338ScanResult:
    """Dispatch a CWE-338 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe338ScanError(EcmaScriptCwe338ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe338(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe338(symbol_index, limits=limits)
    raise EcmaScriptCwe338ScanError(EcmaScriptCwe338ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe338(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe338ScanLimits,
) -> EcmaScriptCwe338ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe338ScanLimits:
        raise EcmaScriptCwe338ScanError(EcmaScriptCwe338ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe338ScanError(EcmaScriptCwe338ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe338ScanError(EcmaScriptCwe338ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe338ScanError(EcmaScriptCwe338ScanErrorCode.ANALYSIS_UNAVAILABLE)
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
        raise EcmaScriptCwe338ScanError(EcmaScriptCwe338ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe338ScanError(EcmaScriptCwe338ScanErrorCode.INTEGRITY_FAILURE) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe338ScanError(EcmaScriptCwe338ScanErrorCode.ANALYSIS_UNAVAILABLE)
        aliases = _collect_aliases(nodes, source)
        bindings = _collect_bindings(nodes, source)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe338Operation]] = set()
        for node in nodes:
            sink_context = _sink_context(node, source, aliases)
            if sink_context is None:
                continue
            sink, name, operation = sink_context
            value_nodes = _sink_values(node)
            random_nodes: set[Node] = set()
            for value in value_nodes:
                random_nodes.update(
                    _weak_random_nodes(
                        value,
                        source=source,
                        aliases=aliases,
                        bindings=bindings,
                        visited=frozenset(),
                        depth=0,
                        max_depth=min(limits.max_depth, 32),
                    )
                )
            for random_node in random_nodes:
                source_range = _range(random_node)
                if not sink.contains(source_range):
                    raise EcmaScriptCwe338ScanError(EcmaScriptCwe338ScanErrorCode.INTEGRITY_FAILURE)
                raw.add((source_range, sink, operation or _operation_for_name(name)))
                if len(raw) > limits.max_signals:
                    raise EcmaScriptCwe338ScanError(EcmaScriptCwe338ScanErrorCode.SIGNAL_LIMIT)
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
    except EcmaScriptCwe338ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe338ScanError(EcmaScriptCwe338ScanErrorCode.INTEGRITY_FAILURE) from None

    signals = tuple(
        EcmaScriptCwe338Signal(
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
    return EcmaScriptCwe338ScanResult(
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


def _bounded_nodes(root: Node, limits: EcmaScriptCwe338ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe338ScanError(EcmaScriptCwe338ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe338ScanError(EcmaScriptCwe338ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _sink_context(
    node: Node, source: bytes, aliases: dict[str, str]
) -> tuple[SourceRange, str, EcmaScriptCwe338Operation | None] | None:
    if node.type == "variable_declarator":
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        name_text = _node_text(source, name) if name is not None else ""
        if name is not None and value is not None and _is_sensitive_name(name_text):
            return _range(node), name_text, None
    elif node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        name_text = _property_or_identifier(left, source) if left is not None else ""
        if left is not None and right is not None and _is_sensitive_name(name_text):
            return _range(node), name_text, None
    elif node.type == "pair":
        key = node.child_by_field_name("key")
        value = node.child_by_field_name("value")
        name_text = _property_or_identifier(key, source) if key is not None else ""
        if key is not None and value is not None and _is_sensitive_name(name_text):
            return _range(node), name_text, None
    elif node.type == "call_expression":
        function = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if function is None or args is None:
            return None
        canonical = _canonical_expression(function, source, aliases)
        leaf = canonical.rsplit(".", 1)[-1] if canonical else ""
        if leaf in _SECURITY_SINKS or _SECURITY_SINK_TEXT.search(leaf):
            return _range(node), leaf, _operation_for_name(leaf)
    elif node.type == "return_statement":
        value = node.child_by_field_name("argument")
        function = node.parent
        while function is not None and function.type not in _FUNCTION_TYPES:
            function = function.parent
        if value is not None and function is not None:
            name_node = function.child_by_field_name("name")
            name_text = _node_text(source, name_node) if name_node is not None else ""
            if _is_sensitive_name(name_text):
                return _range(node), name_text, _operation_for_name(name_text)
    return None


def _sink_values(node: Node) -> tuple[Node, ...]:
    if node.type in {"variable_declarator", "assignment_expression", "pair", "return_statement"}:
        value = node.child_by_field_name("value") or node.child_by_field_name("right")
        if value is None:
            value = node.child_by_field_name("argument")
        return (value,) if value is not None else ()
    if node.type == "call_expression":
        arguments = node.child_by_field_name("arguments")
        return tuple(arguments.named_children) if arguments is not None else ()
    return ()


def _weak_random_nodes(
    node: Node,
    *,
    source: bytes,
    aliases: dict[str, str],
    bindings: dict[str, Node],
    visited: frozenset[str],
    depth: int,
    max_depth: int,
) -> set[Node]:
    if depth > max_depth:
        return set()
    current = _unwrap(node)
    if current.type == "call_expression":
        function = current.child_by_field_name("function")
        if (
            function is not None
            and _canonical_expression(function, source, aliases) == "Math.random"
        ):
            return {current}
    if current.type in {"identifier", "property_identifier"}:
        name = _node_text(source, current)
        bound = bindings.get(name)
        if bound is not None and name not in visited:
            return _weak_random_nodes(
                bound,
                source=source,
                aliases=aliases,
                bindings=bindings,
                visited=visited | {name},
                depth=depth + 1,
                max_depth=max_depth,
            )
    output: set[Node] = set()
    for child in current.named_children:
        output.update(
            _weak_random_nodes(
                child,
                source=source,
                aliases=aliases,
                bindings=bindings,
                visited=visited,
                depth=depth + 1,
                max_depth=max_depth,
            )
        )
    return output


def _collect_bindings(nodes: tuple[Node, ...], source: bytes) -> dict[str, Node]:
    bindings: dict[str, Node] = {}
    for node in nodes:
        if node.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in node.named_children:
                if declarator.type != "variable_declarator":
                    continue
                name = declarator.child_by_field_name("name")
                value = declarator.child_by_field_name("value")
                if name is not None and value is not None and name.type == "identifier":
                    bindings[_node_text(source, name)] = value
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                bindings[_node_text(source, left)] = right
    return bindings


def _collect_aliases(nodes: tuple[Node, ...], source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in nodes:
        if node.type == "import_statement":
            module_node = node.child_by_field_name("source")
            module = _string_value(module_node, source) if module_node is not None else None
            if module is None:
                continue
            for child in node.named_children:
                if child.type != "import_clause":
                    continue
                for item in child.named_children:
                    if item.type == "identifier":
                        aliases[_node_text(source, item)] = module
                    elif item.type == "namespace_import":
                        names = tuple(item.named_children)
                        if names:
                            aliases[_node_text(source, names[-1])] = module
                    elif item.type in {"named_imports", "named_import"}:
                        for specifier in item.named_children:
                            if specifier.type != "import_specifier":
                                continue
                            names = tuple(specifier.named_children)
                            if len(names) >= 2:
                                aliases[_node_text(source, names[-1])] = (
                                    f"{module}.{_node_text(source, names[0])}"
                                )
                            elif names:
                                aliases[_node_text(source, names[0])] = (
                                    f"{module}.{_node_text(source, names[0])}"
                                )
        elif node.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in node.named_children:
                if declarator.type != "variable_declarator":
                    continue
                name = declarator.child_by_field_name("name")
                value = declarator.child_by_field_name("value")
                if name is not None and value is not None and name.type == "identifier":
                    canonical = _canonical_expression(value, source, aliases)
                    if canonical is not None:
                        aliases[_node_text(source, name)] = canonical
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                canonical = _canonical_expression(right, source, aliases)
                if canonical is not None:
                    aliases[_node_text(source, left)] = canonical
    return aliases


def _canonical_expression(node: Node, source: bytes, aliases: dict[str, str]) -> str | None:
    current = _unwrap(node)
    if current.type in {"call_expression", "new_expression"}:
        function = current.child_by_field_name("function") or current.child_by_field_name(
            "constructor"
        )
        arguments = current.child_by_field_name("arguments")
        if function is None:
            return None
        if _compact_text(source, function) == "require" and arguments is not None:
            values = arguments.named_children
            if len(values) == 1:
                module = _string_value(values[0], source)
                return module
        return _canonical_expression(function, source, aliases)
    if current.type in {"member_expression", "subscript_expression"}:
        base = current.child_by_field_name("object")
        property_node = current.child_by_field_name("property") or current.child_by_field_name(
            "index"
        )
        named = tuple(current.named_children)
        if base is None or property_node is None:
            if len(named) < 2:
                return None
            base, property_node = named[0], named[-1]
        base_name = _canonical_expression(base, source, aliases)
        property_name = _static_property_name(property_node, source)
        if base_name is None or property_name is None:
            return None
        return f"{base_name}.{property_name}"
    if current.type in {"identifier", "property_identifier", "private_property_identifier"}:
        value = _node_text(source, current)
        return aliases.get(value, value)
    return None


def _operation_for_name(name: str) -> EcmaScriptCwe338Operation:
    compact = re.sub(r"[^a-z0-9]", "", name.lower())
    if "session" in compact:
        return EcmaScriptCwe338Operation.WEAK_PRNG_SESSION_ID
    if "reset" in compact or "magiclink" in compact:
        return EcmaScriptCwe338Operation.WEAK_PRNG_RESET_LINK
    if "key" in compact or "secret" in compact or "nonce" in compact:
        return EcmaScriptCwe338Operation.WEAK_PRNG_KEY_MATERIAL
    if "token" in compact or "jwt" in compact or "auth" in compact:
        return EcmaScriptCwe338Operation.WEAK_PRNG_TOKEN
    return EcmaScriptCwe338Operation.WEAK_PRNG_SECURITY_VALUE


def _is_sensitive_name(name: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", name.lower())
    return bool(compact) and (compact in _SENSITIVE_WORDS or bool(_SENSITIVE_NAME.search(name)))


def _property_or_identifier(node: Node, source: bytes) -> str:
    current = _unwrap(node)
    if current.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "string",
    }:
        return _node_text(source, current).strip("'\"")
    if current.type in {"member_expression", "subscript_expression"}:
        property_node = current.child_by_field_name("property") or current.child_by_field_name(
            "index"
        )
        if property_node is not None:
            return _property_or_identifier(property_node, source)
    return _compact_text(source, current)


def _is_identifier_name(node: Node) -> bool:
    return node.type in {"identifier", "property_identifier", "private_property_identifier"}


def _static_property_name(node: Node, source: bytes) -> str | None:
    current = _unwrap(node)
    if _is_identifier_name(current):
        return _node_text(source, current)
    return _string_value(current, source)


def _unwrap(node: Node) -> Node:
    current = node
    while current.type in _WRAPPER_TYPES:
        children = tuple(current.named_children)
        if not children:
            break
        current = children[-1]
    return current


def _string_value(node: Node | None, source: bytes) -> str | None:
    if node is None:
        return None
    current = _unwrap(node)
    if current.type not in {"string", "string_fragment"}:
        return None
    value = source[current.start_byte : current.end_byte]
    if current.type == "string":
        if len(value) < 2 or value[:1] not in {b"'", b'"', b"`"} or value[-1:] != value[:1]:
            return None
        value = value[1:-1]
    if b"\\" in value or b"\n" in value or b"\r" in value:
        return None
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe338ScanError(EcmaScriptCwe338ScanErrorCode.INTEGRITY_FAILURE) from None


def _node_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe338ScanError(EcmaScriptCwe338ScanErrorCode.INTEGRITY_FAILURE) from None


def _compact_text(source: bytes, node: Node) -> str:
    return "".join(_node_text(source, node).split())


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
    operation: EcmaScriptCwe338Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-338",
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
    signals: tuple[EcmaScriptCwe338Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-338",
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


scan_javascript_weak_prng = scan_javascript_cwe338
scan_typescript_weak_prng = scan_typescript_cwe338
scan_ecmascript_weak_prng = scan_ecmascript_cwe338


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE338_SCAN_LIMITS",
    "EcmaScriptCwe338Operation",
    "EcmaScriptCwe338ScanError",
    "EcmaScriptCwe338ScanErrorCode",
    "EcmaScriptCwe338ScanLimits",
    "EcmaScriptCwe338ScanResult",
    "EcmaScriptCwe338Signal",
    "scan_ecmascript_cwe338",
    "scan_ecmascript_weak_prng",
    "scan_javascript_cwe338",
    "scan_javascript_weak_prng",
    "scan_typescript_cwe338",
    "scan_typescript_weak_prng",
]
