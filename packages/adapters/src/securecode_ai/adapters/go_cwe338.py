"""Bounded Go facts for CWE-338 weak pseudo-random values.

The scanner follows a deliberately small local data-flow graph from the
``math/rand`` and ``math/rand/v2`` APIs to security-sensitive values.  A fact
is emitted only when the value reaches a sensitive name, a known token/cookie
or redirect API, or a cryptographic key API.  ``crypto/rand`` and a small set
of maintained CSPRNG wrappers are excluded before any value is propagated.

Only a sealed :class:`~securecode_ai.core.SymbolIndex` is accepted.  Source
bytes are parsed transiently and findings retain identity, exact ranges, and
content-addressed hashes only.  Unknown functions and malformed trees are
left unresolved, while request, size, parse, and signal limits fail closed
with fixed source-free error codes.
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
_RULE_ID = "securecode-go-cwe338"
_DETECTOR = "securecode-go-cwe338@1.0"
_DETAIL = "weak_prng_to_security_sensitive_value"

_MATH_RAND_PACKAGES = frozenset({"math/rand", "math/rand/v2"})
_CRYPTO_RAND_PACKAGE = "crypto/rand"
_CSPRNG_PACKAGES = frozenset(
    {
        "github.com/google/uuid",
        "github.com/gofrs/uuid/v5",
        "github.com/gofrs/uuid/v4",
        "github.com/oklog/ulid/v2",
        "github.com/segmentio/ksuid",
    }
)
_CSPRNG_EXTERNAL_METHODS = frozenset(
    {
        "make",
        "new",
        "newrandom",
        "newrandomfromreader",
        "newv4",
        "must",
    }
)
_MATH_RAND_VALUE_METHODS = frozenset(
    {
        "ExpFloat64",
        "Float32",
        "Float64",
        "Int",
        "Int31",
        "Int31n",
        "Int63",
        "Int63n",
        "Intn",
        "NormFloat64",
        "Perm",
        "Read",
        "Uint32",
        "Uint64",
        "Uint32n",
        "Uint64n",
    }
)
_MATH_RAND_CONSTRUCTORS = frozenset(
    {
        "New",
        "NewChaCha8",
        "NewPCG",
        "NewSource",
        "NewSource64",
    }
)
_MATH_RAND_NON_VALUES = frozenset({"Seed", "Shuffle"})
_READ_METHODS = frozenset({"Read"})
_SENSITIVE_NAME_MARKERS = frozenset(
    {
        "activation",
        "api",
        "auth",
        "authorization",
        "code",
        "confirmation",
        "credential",
        "csrf",
        "encryption",
        "hmac",
        "invite",
        "iv",
        "key",
        "magiclink",
        "nonce",
        "one_time",
        "otp",
        "password",
        "private",
        "reset",
        "salt",
        "secret",
        "session",
        "signing",
        "token",
        "verification",
    }
_SENSITIVE_LITERAL_MARKERS = frozenset(
    {
        "access-key",
        "access_key",
        "api-key",
        "api_key",
        "auth",
        "authorization",
        "confirmation",
        "cookie",
        "credential",
        "csrf",
        "invite",
        "magic-link",
        "magic_link",
        "nonce",
        "one-time",
        "one_time",
        "otp",
        "password",
        "reset",
        "secret",
        "session",
        "session-id",
        "session_id",
        "token",
        "verification",
    }
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})
_KEY_PACKAGES = frozenset({"crypto/aes", "crypto/des", "crypto/hmac"})
_JWT_PACKAGES = frozenset(
    {
        "github.com/dgrijalva/jwt-go",
        "github.com/golang-jwt/jwt",
        "github.com/golang-jwt/jwt/v4",
        "github.com/golang-jwt/jwt/v5",
    }
)
_KEY_METHODS = frozenset({"NewCipher", "NewTripleDESCipher", "New"})
_JWT_METHODS = frozenset({"NewWithClaims", "SignedString"})
_REDIRECT_METHODS = frozenset({"Redirect", "RedirectHandler"})
_HEADER_METHODS = frozenset({"Add", "Set", "SetCanonical"})
_SINK_NAME_MARKERS = frozenset(
    {
        "auth",
        "code",
        "confirmation",
        "credential",
        "csrf",
        "invite",
        "key",
        "nonce",
        "otp",
        "password",
        "reset",
        "secret",
        "session",
        "token",
        "verification",
    }
)


class GoCwe338ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-338 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe338ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe338ScanErrorCode) -> None:
        if type(code) is not GoCwe338ScanErrorCode:
            raise TypeError("Go CWE-338 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-338 weak-randomness scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe338ScanLimits:
    """Hard ceilings applied before and during local data-flow analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-338 scan limits are invalid")


DEFAULT_GO_CWE338_SCAN_LIMITS = GoCwe338ScanLimits()


class GoCwe338Operation(StrEnum):
    """Recognised weak pseudo-random operations."""

    MATH_RAND_INT = "math/rand.Int"
    MATH_RAND_INTN = "math/rand.Intn"
    MATH_RAND_INT31 = "math/rand.Int31"
    MATH_RAND_INT31N = "math/rand.Int31n"
    MATH_RAND_INT63 = "math/rand.Int63"
    MATH_RAND_INT63N = "math/rand.Int63n"
    MATH_RAND_FLOAT32 = "math/rand.Float32"
    MATH_RAND_FLOAT64 = "math/rand.Float64"
    MATH_RAND_NORM_FLOAT64 = "math/rand.NormFloat64"
    MATH_RAND_EXP_FLOAT64 = "math/rand.ExpFloat64"
    MATH_RAND_PERM = "math/rand.Perm"
    MATH_RAND_UINT32 = "math/rand.Uint32"
    MATH_RAND_UINT64 = "math/rand.Uint64"
    MATH_RAND_READ = "math/rand.Read"
    MATH_RAND_NEW = "math/rand.New"
    MATH_RAND_NEW_SOURCE = "math/rand.NewSource"
    MATH_RAND_NEW_SOURCE64 = "math/rand.NewSource64"
    MATH_RAND_NEW_PCG = "math/rand/v2.NewPCG"
    MATH_RAND_NEW_CHACHA8 = "math/rand/v2.NewChaCha8"
    RAND_GENERATOR_VALUE = "math/rand.Rand.value"
    RAND_SOURCE_VALUE = "math/rand.Source.value"

    # Compatibility name for generic scanner consumers.
    WEAK_PRNG = "math/rand.value"


_DIRECT_OPERATION: dict[str, GoCwe338Operation] = {
    "ExpFloat64": GoCwe338Operation.MATH_RAND_EXP_FLOAT64,
    "Float32": GoCwe338Operation.MATH_RAND_FLOAT32,
    "Float64": GoCwe338Operation.MATH_RAND_FLOAT64,
    "Int": GoCwe338Operation.MATH_RAND_INT,
    "Int31": GoCwe338Operation.MATH_RAND_INT31,
    "Int31n": GoCwe338Operation.MATH_RAND_INT31N,
    "Int63": GoCwe338Operation.MATH_RAND_INT63,
    "Int63n": GoCwe338Operation.MATH_RAND_INT63N,
    "Intn": GoCwe338Operation.MATH_RAND_INTN,
    "NormFloat64": GoCwe338Operation.MATH_RAND_NORM_FLOAT64,
    "Perm": GoCwe338Operation.MATH_RAND_PERM,
    "Read": GoCwe338Operation.MATH_RAND_READ,
    "Uint32": GoCwe338Operation.MATH_RAND_UINT32,
    "Uint32n": GoCwe338Operation.MATH_RAND_UINT32,
    "Uint64": GoCwe338Operation.MATH_RAND_UINT64,
    "Uint64n": GoCwe338Operation.MATH_RAND_UINT64,
}

_CONSTRUCTOR_OPERATION: dict[str, GoCwe338Operation] = {
    "New": GoCwe338Operation.MATH_RAND_NEW,
    "NewChaCha8": GoCwe338Operation.MATH_RAND_NEW_CHACHA8,
    "NewPCG": GoCwe338Operation.MATH_RAND_NEW_PCG,
    "NewSource": GoCwe338Operation.MATH_RAND_NEW_SOURCE,
    "NewSource64": GoCwe338Operation.MATH_RAND_NEW_SOURCE64,
}
_MATH_RAND_CONSTRUCTOR_OPERATIONS = frozenset(_CONSTRUCTOR_OPERATION.values())


@dataclass(frozen=True, slots=True)
class GoCwe338Signal:
    """One immutable weak-randomness fact without source text."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe338Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-338"
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
            and self.source.start_byte <= self.sink.end_byte
            and self.source.end_byte <= self.sink.end_byte
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
            if valid_identity
            and valid_ranges
            and type(self.operation) is GoCwe338Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not GoCwe338Operation
            or type(signal_id) is not str
            or expected_id is None
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-338"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-338 signal is invalid")
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
class GoCwe338ScanResult:
    """Deterministic, source-free result for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe338Signal, ...]
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
            type(item) is GoCwe338Signal for item in self.signals
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
            raise ValueError("Go CWE-338 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange
    operation: GoCwe338Operation


@dataclass(frozen=True, slots=True)
class _Binding:
    flows: tuple[_Flow, ...] = ()
    weak_generator: bool = False


def scan_go_cwe338(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe338ScanLimits = DEFAULT_GO_CWE338_SCAN_LIMITS,
) -> GoCwe338ScanResult:
    """Find weak ``math/rand`` values reaching security-sensitive sinks."""

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
        raise GoCwe338ScanError(GoCwe338ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    raw: set[tuple[SourceRange, SourceRange, GoCwe338Operation]] = set()
    try:
        for scope in _scopes(root):
            environment: dict[str, _Binding] = {}
            scope_name = scope.child_by_field_name("name")
            sensitive_scope = scope_name is not None and _is_sensitive_name(
                _text(source, scope_name)
            )
            for node in _scope_preorder(scope):
                if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                    _capture_assignment(node, environment, source, imports, limits)
                if node.type == "call_expression":
                    _capture_random_read(node, environment, source, imports)
                    bindings = _call_bindings(node, environment, source, imports, limits)
                    if bindings and _is_sensitive_sink(node, source, imports):
                        _add_facts(raw, bindings, _range(node), limits)
                elif node.type == "return_statement":
                    bindings = _bindings_from_children(
                        node, environment, source, imports, limits
                    )
                    if bindings and sensitive_scope:
                        _add_facts(raw, bindings, _range(node), limits)
                if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                    _capture_assignment_sinks(node, environment, source, imports, raw, limits)
    except GoCwe338ScanError:
        raise
    except Exception:
        raise GoCwe338ScanError(GoCwe338ScanErrorCode.INTEGRITY_FAILURE) from None

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
        raise GoCwe338ScanError(GoCwe338ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe338Signal(
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
    return GoCwe338ScanResult(
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


def scan_go_weak_randomness(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe338ScanLimits = DEFAULT_GO_CWE338_SCAN_LIMITS,
) -> GoCwe338ScanResult:
    """Descriptive alias for :func:`scan_go_cwe338`."""

    return scan_go_cwe338(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe338ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe338ScanLimits:
        raise GoCwe338ScanError(GoCwe338ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe338ScanError(GoCwe338ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe338ScanError(GoCwe338ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe338ScanError(GoCwe338ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    relevant = _MATH_RAND_PACKAGES | _CSPRNG_PACKAGES | {
        _CRYPTO_RAND_PACKAGE,
        *_KEY_PACKAGES,
        *_JWT_PACKAGES,
        "net/http",
        "net/url",
        "os",
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
        alias = (
            _text(source, name_node)
            if name_node is not None
            else _default_import_alias(package)
        )
        if alias not in {".", "_"}:
            aliases[alias] = package
    return aliases


def _default_import_alias(package: str) -> str:
    if package in {"math/rand/v2", "github.com/golang-jwt/jwt/v4", "github.com/golang-jwt/jwt/v5"}:
        return "rand" if package == "math/rand/v2" else "jwt"
    if package == "github.com/gofrs/uuid/v4" or package == "github.com/gofrs/uuid/v5":
        return "uuid"
    if package == "github.com/oklog/ulid/v2":
        return "ulid"
    return package.rsplit("/", 1)[-1]


def _capture_assignment(
    node: Node,
    environment: dict[str, _Binding],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe338ScanLimits,
) -> None:
    left, right = _assignment_parts(node)
    if left is None or right is None:
        return
    names = left.named_children if left.type == "expression_list" else (left,)
    values = right.named_children if right.type == "expression_list" else (right,)
    if len(names) > limits.max_signals or len(values) > limits.max_signals:
        raise GoCwe338ScanError(GoCwe338ScanErrorCode.SIGNAL_LIMIT)
    for index, name in enumerate(names):
        if index >= len(values):
            continue
        identifier = _binding_name(name, source)
        if identifier is None or identifier == "_":
            continue
        binding = _binding_from_node(values[index], environment, source, imports, limits, 0)
        environment[identifier] = binding


def _capture_assignment_sinks(
    node: Node,
    environment: dict[str, _Binding],
    source: bytes,
    imports: dict[str, str],
    raw: set[tuple[SourceRange, SourceRange, GoCwe338Operation]],
    limits: GoCwe338ScanLimits,
) -> None:
    left, right = _assignment_parts(node)
    if left is None or right is None:
        return
    names = left.named_children if left.type == "expression_list" else (left,)
    values = right.named_children if right.type == "expression_list" else (right,)
    for index, name in enumerate(names):
        if index >= len(values):
            continue
        binding = _binding_from_node(values[index], environment, source, imports, limits, 0)
        if not binding.flows:
            continue
        text = _binding_name(name, source) or _compact_text(source, name)
        if _is_sensitive_name(text) or _is_sensitive_literal(text):
            _add_facts(raw, binding, _range(node), limits)


def _assignment_parts(node: Node) -> tuple[Node | None, Node | None]:
    if node.type not in {"short_var_declaration", "assignment_statement", "var_spec"}:
        return None, None
    if node.type == "var_spec":
        return node.child_by_field_name("name"), node.child_by_field_name("value")
    return node.child_by_field_name("left"), node.child_by_field_name("right")


def _capture_random_read(
    node: Node,
    environment: dict[str, _Binding],
    source: bytes,
    imports: dict[str, str],
) -> None:
    operation = _operation_for_call(node, environment, source, imports)
    if operation is not GoCwe338Operation.MATH_RAND_READ:
        return
    arguments = node.child_by_field_name("arguments")
    if arguments is None or not arguments.named_children:
        return
    flow = _Flow(_range(node), operation)
    for argument in arguments.named_children[:1]:
        name = _binding_name(argument, source)
        if name is not None and name != "_":
            environment[name] = _Binding((flow,), False)


def _call_bindings(
    node: Node,
    environment: dict[str, _Binding],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe338ScanLimits,
) -> tuple[_Flow, ...]:
    return _binding_from_node(node, environment, source, imports, limits, 0).flows


def _binding_from_node(
    node: Node,
    environment: dict[str, _Binding],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe338ScanLimits,
    depth: int,
    visited: frozenset[str] = frozenset(),
) -> _Binding:
    if depth > limits.max_expression_depth:
        raise GoCwe338ScanError(GoCwe338ScanErrorCode.SIGNAL_LIMIT)
    if node.type == "identifier":
        name = _text(source, node)
        if name in visited:
            return _Binding()
        return environment.get(name, _Binding())
    if node.type == "call_expression":
        operation = _operation_for_call(node, environment, source, imports)
        if operation in _MATH_RAND_CONSTRUCTOR_OPERATIONS:
            return _Binding(weak_generator=True)
        if operation is not None:
            return _Binding((_Flow(_range(node), operation),), False)
        if _is_csprng_call(node, source, imports):
            return _Binding()
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            return _Binding()
        return _merge_bindings(
            _binding_from_node(child, environment, source, imports, limits, depth + 1)
            for child in arguments.named_children
        )
    if node.type == "selector_expression":
        return _merge_bindings(
            _binding_from_node(child, environment, source, imports, limits, depth + 1)
            for child in node.named_children
        )
    if node.type in {
        "parenthesized_expression",
        "unary_expression",
        "pointer_expression",
        "address_expression",
        "index_expression",
        "slice_expression",
        "type_assertion_expression",
        "type_conversion_expression",
        "composite_literal",
        "literal_value",
        "keyed_element",
        "expression_list",
        "binary_expression",
    }:
        return _merge_bindings(
            _binding_from_node(child, environment, source, imports, limits, depth + 1)
            for child in node.named_children
        )
    return _Binding()


def _operation_for_call(
    node: Node,
    environment: dict[str, _Binding],
    source: bytes,
    imports: dict[str, str],
) -> GoCwe338Operation | None:
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    member = _text(source, field)
    if operand.type != "identifier":
        return None
    receiver = _text(source, operand)
    package = imports.get(receiver)
    if package in _MATH_RAND_PACKAGES:
        if member in _MATH_RAND_VALUE_METHODS:
            return _DIRECT_OPERATION[member]
        if member in _MATH_RAND_CONSTRUCTORS:
            return _CONSTRUCTOR_OPERATION[member]
        return None
    binding = environment.get(receiver)
    if binding is not None and binding.weak_generator and member in _MATH_RAND_VALUE_METHODS:
        return (
            GoCwe338Operation.MATH_RAND_READ
            if member == "Read"
            else GoCwe338Operation.RAND_GENERATOR_VALUE
        )
    return None


def _is_csprng_call(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return False
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None or operand.type != "identifier":
        return False
    package = imports.get(_text(source, operand))
    member = _text(source, field).lower()
    return package == _CRYPTO_RAND_PACKAGE or (
        package in _CSPRNG_PACKAGES and member in _CSPRNG_EXTERNAL_METHODS
    )


def _is_sensitive_sink(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return False
    field = function.child_by_field_name("field")
    operand = function.child_by_field_name("operand")
    if field is None:
        return False
    member = _text(source, field)
    package = ""
    if operand is not None and operand.type == "identifier":
        package = imports.get(_text(source, operand), "")
    if package == "net/http" and member in _REDIRECT_METHODS | {"SetCookie"}:
        return True
    if package in _JWT_PACKAGES and member in _JWT_METHODS:
        return True
    if package in _KEY_PACKAGES and member in _KEY_METHODS:
        return True
    if package == "crypto/hmac" and member == "New":
        return True
    if member in _HEADER_METHODS and _has_sensitive_literal(node, source):
        return True
    if _has_sensitive_literal(node, source) and _is_sensitive_name(member):
        return True
    return _is_sensitive_name(member)


def _has_sensitive_literal(node: Node, source: bytes) -> bool:
    for child in _preorder(node):
        if child.type not in {"interpreted_string_literal", "raw_string_literal"}:
            continue
        value = _text(source, child).strip('"`').lower()
        compact = re.sub(r"[^a-z0-9]+", "_", value).strip("_")
        if any(marker in value or marker in compact for marker in _SENSITIVE_LITERAL_MARKERS):
            return True
    return False


def _is_sensitive_name(value: str) -> bool:
    compact = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    if not compact:
        return False
    pieces = tuple(piece for piece in compact.split("_") if piece)
    if any(piece in _SENSITIVE_NAME_MARKERS for piece in pieces):
        return True
    joined = "".join(pieces)
    return any(
        len(marker.replace("_", "")) >= 5 and marker.replace("_", "") in joined
        for marker in _SENSITIVE_NAME_MARKERS
    )


def _binding_name(node: Node, source: bytes) -> str | None:
    if node.type == "identifier":
        return _text(source, node)
    if node.type == "selector_expression":
        field = node.child_by_field_name("field")
        return _text(source, field) if field is not None else None
    return None


def _bindings_from_children(
    node: Node,
    environment: dict[str, _Binding],
    source: bytes,
    imports: dict[str, str],
    limits: GoCwe338ScanLimits,
) -> tuple[_Flow, ...]:
    return _merge_bindings(
        _binding_from_node(child, environment, source, imports, limits, 0)
        for child in node.named_children
    ).flows


def _add_facts(
    raw: set[tuple[SourceRange, SourceRange, GoCwe338Operation]],
    bindings: tuple[_Flow, ...] | _Binding,
    sink: SourceRange,
    limits: GoCwe338ScanLimits,
) -> None:
    flows = bindings if isinstance(bindings, tuple) else bindings.flows
    for flow in flows:
        if flow.source.end_byte > sink.end_byte:
            continue
        raw.add((flow.source, sink, flow.operation))
        if len(raw) > limits.max_signals:
            raise GoCwe338ScanError(GoCwe338ScanErrorCode.SIGNAL_LIMIT)


def _merge_bindings(bindings: Iterable[_Binding]) -> _Binding:
    output: dict[tuple[int, int, str], _Flow] = {}
    weak_generator = False
    for value in bindings:
        if not isinstance(value, _Binding):
            continue
        weak_generator = weak_generator or value.weak_generator
        for flow in value.flows:
            output[(flow.source.start_byte, flow.source.end_byte, flow.operation.value)] = flow
    return _Binding(
        tuple(output[key] for key in sorted(output)),
        weak_generator,
    )


def _scopes(root: Node) -> tuple[Node, ...]:
    return (root, *tuple(node for node in _preorder(root) if node.type in _GO_SCOPES))


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
    operation: GoCwe338Operation,
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
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe338Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-338",
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


Cwe338ScanErrorCode = GoCwe338ScanErrorCode
Cwe338ScanError = GoCwe338ScanError
Cwe338ScanLimits = GoCwe338ScanLimits
Cwe338ScanResult = GoCwe338ScanResult
Cwe338Signal = GoCwe338Signal


__all__ = [
    "Cwe338ScanError",
    "Cwe338ScanErrorCode",
    "Cwe338ScanLimits",
    "Cwe338ScanResult",
    "Cwe338Signal",
    "DEFAULT_GO_CWE338_SCAN_LIMITS",
    "GoCwe338Operation",
    "GoCwe338ScanError",
    "GoCwe338ScanErrorCode",
    "GoCwe338ScanLimits",
    "GoCwe338ScanResult",
    "GoCwe338Signal",
    "scan_go_cwe338",
    "scan_go_weak_randomness",
]
