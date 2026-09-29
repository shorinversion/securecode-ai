"""Bounded Go facts for risky cryptography and disabled TLS verification.

The scanner consumes a sealed Go ``SymbolIndex`` and emits only structural
source ranges plus stable rule metadata.  It does not retain or return source
text, and it deliberately recognizes a small set of unambiguous standard
library APIs.  Normalization, finding interpretation, and verdict policy stay
in the common Core pipeline.
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

_MAX_LIMITS = (2_000_000, 2_048)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

_WEAK_CRYPTO_APIS: dict[str, frozenset[str]] = {
    "crypto/des": frozenset({"NewCipher", "NewTripleDESCipher"}),
    "crypto/md5": frozenset({"New", "Sum"}),
    "crypto/rc4": frozenset({"NewCipher"}),
    "crypto/sha1": frozenset({"New", "Sum"}),
}
_TLS_PACKAGE = "crypto/tls"
_TLS_INSECURE_FIELD = "InsecureSkipVerify"


class GoCweCryptoScanErrorCode(StrEnum):
    """Closed reasons a Go cryptography fact cannot be emitted."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCweCryptoScanError(RuntimeError):
    """Fixed source-free semantic analysis failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCweCryptoScanErrorCode) -> None:
        if type(code) is not GoCweCryptoScanErrorCode:
            raise TypeError("Go CWE crypto scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE crypto semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCweCryptoScanLimits:
    """Hard bounds applied before and during structural analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE crypto scan limits are invalid")


DEFAULT_GO_CWE_CRYPTO_SCAN_LIMITS = GoCweCryptoScanLimits()


@dataclass(frozen=True, slots=True)
class GoCweCryptoSignal:
    """One source-free risky-cryptography or TLS configuration fact."""

    source: SourceRange
    sink: SourceRange
    cwe: str
    detector: str
    detail: str

    def __post_init__(self) -> None:
        expected = {
            "CWE-295": "securecode-go-cwe295@1.0",
            "CWE-327": "securecode-go-cwe327@1.0",
        }.get(self.cwe)
        valid = (
            expected is not None
            and self.detector == expected
            and self.detail in {"tls_insecure_skip_verify", "weak_crypto_api"}
            and type(self.source) is SourceRange
            and type(self.sink) is SourceRange
            and self.source.start_byte <= self.sink.start_byte
            and self.source.end_byte <= self.sink.end_byte
        )
        if not valid:
            raise ValueError("Go CWE crypto signal is invalid")


@dataclass(frozen=True, slots=True)
class GoCweCryptoScanResult:
    """Deterministic, content-addressed result for one Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCweCryptoSignal, ...]
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
        order = tuple(
            (
                signal.sink.start_byte,
                signal.sink.end_byte,
                signal.source.start_byte,
                signal.cwe,
                signal.detector,
            )
            for signal in self.signals
        )
        if (
            not identity_valid
            or type(self.signals) is not tuple
            or any(type(signal) is not GoCweCryptoSignal for signal in self.signals)
            or any(
                signal.source.end_byte > self.source_size_bytes
                or signal.sink.end_byte > self.source_size_bytes
                for signal in self.signals
            )
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
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
            raise ValueError("Go CWE crypto scan result is invalid")


def scan_go_cwe_crypto(
    symbol_index: SymbolIndex,
    *,
    limits: GoCweCryptoScanLimits = DEFAULT_GO_CWE_CRYPTO_SCAN_LIMITS,
) -> GoCweCryptoScanResult:
    """Find standard-library weak crypto APIs and disabled TLS verification."""

    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCweCryptoScanLimits:
        raise GoCweCryptoScanError(GoCweCryptoScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCweCryptoScanError(GoCweCryptoScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCweCryptoScanError(GoCweCryptoScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCweCryptoScanError(GoCweCryptoScanErrorCode.ANALYSIS_UNAVAILABLE)
    try:
        rebuilt = build_go_symbol_index(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source=symbol_index.source,
        )
        if rebuilt != symbol_index:
            raise ValueError("index mismatch")
        root = Parser(Language(_go_language())).parse(symbol_index.source).root_node
    except Exception:
        raise GoCweCryptoScanError(GoCweCryptoScanErrorCode.INTEGRITY_FAILURE) from None

    source = symbol_index.source
    aliases = _import_aliases(root, source)
    facts: list[tuple[SourceRange, SourceRange, str, str, str]] = []
    for node in _preorder(root):
        if node.type == "call_expression":
            fact = _weak_crypto_fact(node, source, aliases)
            if fact is not None:
                facts.append(fact)
        elif node.type == "keyed_element":
            fact = _insecure_tls_literal_fact(node, source, aliases)
            if fact is not None:
                facts.append(fact)
        elif node.type == "assignment_statement":
            fact = _insecure_tls_assignment_fact(node, source)
            if fact is not None:
                facts.append(fact)
        if len(facts) > limits.max_signals:
            raise GoCweCryptoScanError(GoCweCryptoScanErrorCode.SIGNAL_LIMIT)

    unique = sorted(
        set(facts),
        key=lambda item: (item[1].start_byte, item[1].end_byte, item[0].start_byte, item[2]),
    )
    if len(unique) > limits.max_signals:
        raise GoCweCryptoScanError(GoCweCryptoScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCweCryptoSignal(
            source=item[0],
            sink=item[1],
            cwe=item[2],
            detector=item[3],
            detail=item[4],
        )
        for item in unique
    )
    return GoCweCryptoScanResult(
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


def scan_go_crypto(
    symbol_index: SymbolIndex,
    *,
    limits: GoCweCryptoScanLimits = DEFAULT_GO_CWE_CRYPTO_SCAN_LIMITS,
) -> GoCweCryptoScanResult:
    """Compatibility name for callers that group Go crypto scanners."""

    return scan_go_cwe_crypto(symbol_index, limits=limits)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        package = _text(source, path_node).strip('"`')
        if package not in {*_WEAK_CRYPTO_APIS, _TLS_PACKAGE}:
            continue
        name_node = node.child_by_field_name("name")
        alias = _text(source, name_node) if name_node is not None else package.rsplit("/", 1)[-1]
        if alias not in {".", "_"}:
            aliases[alias] = package
    return aliases


def _weak_crypto_fact(
    node: Node, source: bytes, aliases: dict[str, str]
) -> tuple[SourceRange, SourceRange, str, str, str] | None:
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    package = aliases.get(_text(source, operand))
    function_name = _text(source, field)
    if package is None or function_name not in _WEAK_CRYPTO_APIS.get(package, frozenset()):
        return None
    return (
        _range(function),
        _range(node),
        "CWE-327",
        "securecode-go-cwe327@1.0",
        "weak_crypto_api",
    )


def _insecure_tls_literal_fact(
    node: Node, source: bytes, aliases: dict[str, str]
) -> tuple[SourceRange, SourceRange, str, str, str] | None:
    key = node.child_by_field_name("key")
    value = node.child_by_field_name("value")
    if key is None or value is None:
        children = node.named_children
        if len(children) < 2:
            return None
        key, value = children[0], children[1]
    if _text(source, key) != _TLS_INSECURE_FIELD or _compact_text(source, value) != "true":
        return None
    composite = node.parent
    while composite is not None and composite.type != "composite_literal":
        composite = composite.parent
    if composite is None:
        return None
    type_node = composite.child_by_field_name("type")
    if type_node is None:
        return None
    type_text = _compact_text(source, type_node)
    tls_aliases = {alias for alias, package in aliases.items() if package == _TLS_PACKAGE}
    if not any(type_text == f"{alias}.Config" for alias in tls_aliases):
        return None
    return (
        _range(key),
        _range(composite),
        "CWE-295",
        "securecode-go-cwe295@1.0",
        "tls_insecure_skip_verify",
    )


def _insecure_tls_assignment_fact(
    node: Node, source: bytes
) -> tuple[SourceRange, SourceRange, str, str, str] | None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None or _compact_text(source, right) != "true":
        return None
    if left.type != "selector_expression":
        return None
    field = left.child_by_field_name("field")
    if field is None or _text(source, field) != _TLS_INSECURE_FIELD:
        return None
    return (
        _range(field),
        _range(node),
        "CWE-295",
        "securecode-go-cwe295@1.0",
        "tls_insecure_skip_verify",
    )


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


def _compact_text(source: bytes, node: Node) -> str:
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


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCweCryptoSignal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "cwe": signal.cwe,
                "detail": signal.detail,
                "detector": signal.detector,
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


__all__ = [
    "DEFAULT_GO_CWE_CRYPTO_SCAN_LIMITS",
    "GoCweCryptoScanError",
    "GoCweCryptoScanErrorCode",
    "GoCweCryptoScanLimits",
    "GoCweCryptoScanResult",
    "GoCweCryptoSignal",
    "scan_go_crypto",
    "scan_go_cwe_crypto",
]
