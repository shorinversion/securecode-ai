"""Bounded JavaScript and TypeScript CWE-295 TLS-validation facts.

The scanner consumes a sealed ECMAScript ``SymbolIndex`` and reparses the
exact admitted bytes before inspecting the CST.  It recognizes explicit
``rejectUnauthorized: false`` options and assignments which disable
Node.js' ``NODE_TLS_REJECT_UNAUTHORIZED`` bypass guard.  Direct server-only
TLS option objects are excluded because ``rejectUnauthorized`` there controls
optional client-certificate admission rather than peer certificate
validation.  Results contain only immutable source ranges and
content-addressed metadata; source text is never retained in output or
errors.
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
_RULE_ID = "securecode-ecmascript-cwe295"
_DETECTOR = "securecode-ecmascript-cwe295@1.0"
_TLS_ENV_NAME = "NODE_TLS_REJECT_UNAUTHORIZED"
_SERVER_FACTORIES = frozenset(
    {
        "https.createServer",
        "http2.createSecureServer",
        "tls.createServer",
        "tls.Server",
    }
)


class EcmaScriptCwe295ScanErrorCode(StrEnum):
    """Closed, source-free reasons a TLS-validation scan can fail."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe295ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser diagnostics."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe295ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe295ScanErrorCode:
            raise TypeError("ECMAScript CWE-295 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-295 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class EcmaScriptCwe295Operation(StrEnum):
    """Recognized operations which disable TLS peer verification."""

    REJECT_UNAUTHORIZED_FALSE = "rejectUnauthorized:false"
    NODE_TLS_REJECT_UNAUTHORIZED_ZERO = "NODE_TLS_REJECT_UNAUTHORIZED:0"

    # Descriptive aliases for language-neutral consumers.
    TLS_OPTION = "rejectUnauthorized:false"
    NODE_TLS_ENV_BYPASS = "NODE_TLS_REJECT_UNAUTHORIZED:0"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe295ScanLimits:
    """Hard ceilings applied before and during structural analysis."""

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
            raise ValueError("ECMAScript CWE-295 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE295_SCAN_LIMITS = EcmaScriptCwe295ScanLimits()


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe295Signal:
    """One immutable TLS-validation bypass fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe295Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-295"
    detector: str = _DETECTOR
    detail: str = "tls_peer_verification_disabled"

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
            if valid_identity and valid_ranges and type(self.operation) is EcmaScriptCwe295Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not EcmaScriptCwe295Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-295"
            or self.detector != _DETECTOR
            or self.detail != "tls_peer_verification_disabled"
        ):
            raise ValueError("ECMAScript CWE-295 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete option or assignment location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe295ScanResult:
    """Deterministic, source-free CWE-295 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe295Signal, ...]
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
            type(item) is EcmaScriptCwe295Signal for item in self.signals
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
            raise ValueError("ECMAScript CWE-295 scan result is invalid")


def scan_javascript_cwe295(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe295ScanLimits = DEFAULT_ECMASCRIPT_CWE295_SCAN_LIMITS,
) -> EcmaScriptCwe295ScanResult:
    """Find bounded JavaScript TLS-validation bypass facts."""

    return _scan_ecmascript_cwe295(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe295(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe295ScanLimits = DEFAULT_ECMASCRIPT_CWE295_SCAN_LIMITS,
) -> EcmaScriptCwe295ScanResult:
    """Find bounded TypeScript TLS-validation bypass facts."""

    return _scan_ecmascript_cwe295(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe295(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe295ScanLimits = DEFAULT_ECMASCRIPT_CWE295_SCAN_LIMITS,
) -> EcmaScriptCwe295ScanResult:
    """Dispatch a CWE-295 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe295(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe295(symbol_index, limits=limits)
    raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe295(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe295ScanLimits,
) -> EcmaScriptCwe295ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe295ScanLimits:
        raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.ANALYSIS_UNAVAILABLE)

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
        raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.INTEGRITY_FAILURE) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.ANALYSIS_UNAVAILABLE)
        aliases = _collect_aliases(nodes, source)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe295Operation]] = set()
        for node in nodes:
            if node.type == "pair":
                fact = _pair_fact(node, source, aliases)
                if fact is not None:
                    raw.add(fact)
            elif node.type in {"assignment_expression", "augmented_assignment_expression"}:
                fact = _environment_assignment_fact(node, source, aliases)
                if fact is not None:
                    raw.add(fact)
            if len(raw) > limits.max_signals:
                raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.SIGNAL_LIMIT)
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
    except EcmaScriptCwe295ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.INTEGRITY_FAILURE) from None

    if len(ordered) > limits.max_signals:
        raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        EcmaScriptCwe295Signal(
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
    return EcmaScriptCwe295ScanResult(
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


def _pair_fact(
    node: Node, source: bytes, aliases: dict[str, str]
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe295Operation] | None:
    key, value = _pair_parts(node)
    if key is None or value is None:
        return None
    key_name = _static_property_name(key, source)
    if key_name == "rejectUnauthorized":
        if not _is_false_literal(value, source):
            return None
        if _is_direct_server_option(node, source, aliases):
            return None
        return (
            _range(value),
            _enclosing_sink(node),
            EcmaScriptCwe295Operation.REJECT_UNAUTHORIZED_FALSE,
        )
    if key_name == _TLS_ENV_NAME and _is_zero_literal(value, source):
        return (
            _range(value),
            _enclosing_sink(node),
            EcmaScriptCwe295Operation.NODE_TLS_REJECT_UNAUTHORIZED_ZERO,
        )
    return None


def _environment_assignment_fact(
    node: Node, source: bytes, aliases: dict[str, str]
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe295Operation] | None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None or not _is_tls_environment(left, source, aliases):
        return None
    if not _is_zero_literal(right, source):
        return None
    sink = _range(node)
    value_range = _range(right)
    if not sink.contains(value_range):
        raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.INTEGRITY_FAILURE)
    return value_range, sink, EcmaScriptCwe295Operation.NODE_TLS_REJECT_UNAUTHORIZED_ZERO


def _is_direct_server_option(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    """Exclude only an object literal directly passed to a server factory."""

    object_node = node.parent
    while object_node is not None and object_node.type not in {"object", "object_pattern"}:
        object_node = object_node.parent
    if object_node is None:
        return False
    argument = object_node.parent
    while argument is not None and argument.type in {
        "as_expression",
        "parenthesized_expression",
        "non_null_expression",
        "type_assertion",
    }:
        argument = argument.parent
    if argument is None or argument.type != "arguments" or argument.parent is None:
        return False
    call = argument.parent
    if call.type not in {"call_expression", "new_expression"}:
        return False
    if object_node not in argument.named_children:
        return False
    function = call.child_by_field_name("function")
    if call.type == "new_expression":
        function = call.child_by_field_name("constructor") or function
    if function is None:
        return False
    return _canonical_expression(function, source, aliases) in _SERVER_FACTORIES


def _enclosing_sink(node: Node) -> SourceRange:
    current: Node | None = node
    while current is not None:
        if current.type in {"call_expression", "new_expression", "assignment_expression"}:
            return _range(current)
        current = current.parent
    return _range(node)


def _is_false_literal(node: Node, source: bytes) -> bool:
    current = _unwrap(node)
    return current.type == "false" or _compact_text(source, current) == "false"


def _is_zero_literal(node: Node, source: bytes) -> bool:
    current = _unwrap(node)
    if current.type in {"string", "string_fragment"}:
        return _string_value(current, source) == "0"
    return current.type in {"number", "numeric_literal"} and _compact_text(source, current) == "0"


def _is_tls_environment(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    current = _unwrap(node)
    canonical = _canonical_expression(current, source, aliases)
    if canonical in {
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED",
        "Bun.env.NODE_TLS_REJECT_UNAUTHORIZED",
        "Deno.env.NODE_TLS_REJECT_UNAUTHORIZED",
    }:
        return True
    return canonical is not None and canonical.endswith(f".env.{_TLS_ENV_NAME}")


def _bounded_nodes(root: Node, limits: EcmaScriptCwe295ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _collect_aliases(nodes: tuple[Node, ...], source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in nodes:
        if node.type == "import_statement":
            _collect_import_aliases(node, source, aliases)
        elif node.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in node.named_children:
                if declarator.type != "variable_declarator":
                    continue
                name = declarator.child_by_field_name("name")
                value = declarator.child_by_field_name("value")
                if name is None or value is None:
                    continue
                canonical = _canonical_expression(value, source, aliases)
                if name.type == "identifier" and canonical is not None:
                    aliases[_node_text(source, name)] = canonical
                elif name.type in {"object_pattern", "object"} and canonical is not None:
                    _collect_destructured_aliases(name, canonical, source, aliases)
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                canonical = _canonical_expression(right, source, aliases)
                if canonical is not None:
                    aliases[_node_text(source, left)] = canonical
    return aliases


def _collect_import_aliases(node: Node, source: bytes, aliases: dict[str, str]) -> None:
    module_node = node.child_by_field_name("source")
    if module_node is None:
        return
    module = _string_value(module_node, source)
    if module is None:
        return
    module = _normalise_module(module)
    for child in node.named_children:
        if child.type != "import_clause":
            continue
        for item in child.named_children:
            if item.type == "identifier":
                aliases[_node_text(source, item)] = module
            elif item.type == "namespace_import":
                children = item.named_children
                if children:
                    aliases[_node_text(source, children[-1])] = module
            elif item.type in {"named_imports", "named_import"}:
                for specifier in item.named_children:
                    if specifier.type != "import_specifier":
                        continue
                    names = list(specifier.named_children)
                    if names:
                        aliases[_node_text(source, names[-1])] = (
                            f"{module}.{_node_text(source, names[0])}"
                        )


def _collect_destructured_aliases(
    pattern: Node, module: str, source: bytes, aliases: dict[str, str]
) -> None:
    for child in pattern.named_children:
        if child.type not in {
            "pair",
            "object_pattern_property",
            "shorthand_property_identifier_pattern",
        }:
            continue
        key, value = _pair_parts(child)
        key = key or child
        value = value or key
        key_name = _static_property_name(key, source)
        value_name = _static_property_name(value, source)
        if key_name is not None and value_name is not None:
            aliases[value_name] = f"{module}.{key_name}"


def _canonical_expression(node: Node, source: bytes, aliases: dict[str, str]) -> str | None:
    current = _unwrap(node)
    if current.type == "call_expression":
        function = current.child_by_field_name("function")
        arguments = current.child_by_field_name("arguments")
        if (
            function is None
            or arguments is None
            or _compact_text(source, function) != "require"
            or len(arguments.named_children) != 1
        ):
            return None
        module = _string_value(arguments.named_children[0], source)
        return _normalise_module(module) if module is not None else None
    if current.type in {"member_expression", "subscript_expression"}:
        base = current.child_by_field_name("object")
        property_node = current.child_by_field_name("property") or current.child_by_field_name(
            "index"
        )
        if base is None or property_node is None:
            named = list(current.named_children)
            if len(named) < 2:
                return None
            base, property_node = named[0], named[-1]
        base_name = _canonical_expression(base, source, aliases)
        property_name = _static_property_name(property_node, source)
        if base_name is None or property_name is None:
            return None
        return f"{base_name}.{property_name}"
    return _canonical_name(_compact_text(source, current), aliases)


def _canonical_name(value: str, aliases: dict[str, str]) -> str:
    parts = value.split(".")
    if not parts or not _IDENTIFIER.fullmatch(parts[0]):
        return value
    base = aliases.get(parts[0], parts[0])
    return base if len(parts) == 1 else ".".join((base, *parts[1:]))


def _normalise_module(value: str) -> str:
    if value.startswith("node:"):
        value = value[5:]
    if value.endswith("/index"):
        value = value[:-6]
    return value


def _unwrap(node: Node) -> Node:
    current = node
    while current.type in {
        "parenthesized_expression",
        "as_expression",
        "non_null_expression",
        "type_assertion",
    }:
        children = list(current.named_children)
        if not children:
            break
        current = children[-1]
    return current


def _pair_parts(node: Node) -> tuple[Node | None, Node | None]:
    key = node.child_by_field_name("key")
    value = node.child_by_field_name("value")
    named = list(node.named_children)
    return key or (named[0] if named else None), value or (named[-1] if len(named) >= 2 else None)


def _static_property_name(node: Node, source: bytes) -> str | None:
    current = _unwrap(node)
    if current.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        return _node_text(source, current)
    return _string_value(current, source)


def _string_value(node: Node, source: bytes) -> str | None:
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
        raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.INTEGRITY_FAILURE) from None


def _node_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe295ScanError(EcmaScriptCwe295ScanErrorCode.INTEGRITY_FAILURE) from None


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
    operation: EcmaScriptCwe295Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-295",
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
    signals: tuple[EcmaScriptCwe295Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-295",
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


scan_javascript_tls_validation = scan_javascript_cwe295
scan_typescript_tls_validation = scan_typescript_cwe295
scan_ecmascript_tls_validation = scan_ecmascript_cwe295


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE295_SCAN_LIMITS",
    "EcmaScriptCwe295Operation",
    "EcmaScriptCwe295ScanError",
    "EcmaScriptCwe295ScanErrorCode",
    "EcmaScriptCwe295ScanLimits",
    "EcmaScriptCwe295ScanResult",
    "EcmaScriptCwe295Signal",
    "scan_ecmascript_cwe295",
    "scan_ecmascript_tls_validation",
    "scan_javascript_cwe295",
    "scan_javascript_tls_validation",
    "scan_typescript_cwe295",
    "scan_typescript_tls_validation",
]
