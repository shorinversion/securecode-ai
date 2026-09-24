"""Bounded JavaScript and TypeScript CWE-352 route facts.

The detector reports unsafe state-changing route registrations only when the
same route has no visible CSRF middleware or guard.  Protection is evaluated
per route, so middleware attached to one route cannot hide an unrelated route.
The input is a sealed CST index and results contain only immutable ranges and
content-addressed metadata.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from securecode_ai.core import (
    CONTRACT_SCHEMA_VERSION,
    DataClass,
    ParseHealth,
    ProducerRef,
    RawSignal,
    RepositoryFile,
    SourceLocation,
    SourcePoint,
    SourcePosition,
    SourceRange,
    SymbolIndex,
)
from tree_sitter import Language, Node, Parser

from .cst import CstAdapterError, build_javascript_symbol_index, build_typescript_symbol_index
from .cst_ecmascript import _javascript_language, _typescript_language

_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CSRF_GUARD = re.compile(
    r"(?:csrf|xsrf)(?:protection|protect|middleware|guard|verify|validator|validate|sync)"
    r"|(?:protection|protect|middleware|guard|verify|validator|validate)(?:csrf|xsrf)"
)
_ROUTE_METHODS = frozenset({"post", "put", "patch", "delete"})
_MAX_LIMITS = (2_000_000, 250_000, 512, 10_000)
_CALLABLES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
        "generator_function",
        "generator_function_declaration",
    }
)


class EcmascriptCwe352ScanErrorCode(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmascriptCwe352ScanError(RuntimeError):
    """Fixed source-free scanner failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmascriptCwe352ScanErrorCode) -> None:
        if type(code) is not EcmascriptCwe352ScanErrorCode:
            raise TypeError("ECMAScript CWE-352 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-352 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EcmascriptCwe352ScanLimits:
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
            raise ValueError("ECMAScript CWE-352 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE352_SCAN_LIMITS = EcmascriptCwe352ScanLimits()


@dataclass(frozen=True, slots=True)
class EcmascriptCwe352Signal:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    source: SourceRange
    sink: SourceRange
    detector: str
    cwe: str = "CWE-352"

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
        ranges_valid = (
            type(self.source) is SourceRange
            and type(self.sink) is SourceRange
            and 0 <= self.source.start_byte <= self.source.end_byte
            and self.sink.start_byte <= self.source.start_byte
            and self.source.end_byte <= self.sink.end_byte
            and self.sink.end_byte <= self.source_size_bytes
        )
        if (
            not identity_valid
            or self.language not in {"javascript", "typescript"}
            or self.detector != f"securecode-{self.language}-cwe352@1.0"
            or self.cwe != "CWE-352"
            or not ranges_valid
        ):
            raise ValueError("ECMAScript CWE-352 signal is invalid")


@dataclass(frozen=True, slots=True)
class EcmascriptCwe352ScanResult:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmascriptCwe352Signal, ...]
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
        valid = type(self.signals) is tuple and all(
            type(item) is EcmascriptCwe352Signal for item in self.signals
        )
        order = (
            tuple((item.sink.start_byte, item.sink.end_byte, item.source.start_byte) for item in self.signals)
            if valid
            else ()
        )
        same_identity = (
            all(
                item.repository_id == self.repository_id
                and item.revision == self.revision
                and item.path == self.path
                and item.content_sha256 == self.content_sha256
                and item.source_size_bytes == self.source_size_bytes
                and item.language == self.language
                for item in self.signals
            )
            if valid
            else False
        )
        if (
            not identity_valid
            or not valid
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
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
            raise ValueError("ECMAScript CWE-352 scan result is invalid")


class _IndexBuilder(Protocol):
    def __call__(
        self,
        *,
        repository_id: str,
        revision: str,
        path: str,
        content_sha256: str,
        source: bytes,
    ) -> SymbolIndex: ...


def scan_javascript_cwe352(
    symbol_index: SymbolIndex,
    *,
    limits: EcmascriptCwe352ScanLimits = DEFAULT_ECMASCRIPT_CWE352_SCAN_LIMITS,
) -> EcmascriptCwe352ScanResult:
    return _scan_ecmascript_cwe352(
        symbol_index,
        language="javascript",
        grammar=_javascript_language(),
        rebuild=build_javascript_symbol_index,
        limits=limits,
    )


def scan_typescript_cwe352(
    symbol_index: SymbolIndex,
    *,
    limits: EcmascriptCwe352ScanLimits = DEFAULT_ECMASCRIPT_CWE352_SCAN_LIMITS,
) -> EcmascriptCwe352ScanResult:
    return _scan_ecmascript_cwe352(
        symbol_index,
        language="typescript",
        grammar=_typescript_language(
            tsx=type(symbol_index) is SymbolIndex and symbol_index.path.endswith(".tsx")
        ),
        rebuild=build_typescript_symbol_index,
        limits=limits,
    )


def _scan_ecmascript_cwe352(
    symbol_index: SymbolIndex,
    *,
    language: str,
    grammar: object,
    rebuild: _IndexBuilder,
    limits: EcmascriptCwe352ScanLimits,
) -> EcmascriptCwe352ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmascriptCwe352ScanLimits:
        raise EcmascriptCwe352ScanError(EcmascriptCwe352ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != language:
        raise EcmascriptCwe352ScanError(EcmascriptCwe352ScanErrorCode.REQUEST_INVALID)
    if symbol_index.source_byte_length > limits.max_source_bytes:
        raise EcmascriptCwe352ScanError(EcmascriptCwe352ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmascriptCwe352ScanError(EcmascriptCwe352ScanErrorCode.ANALYSIS_UNAVAILABLE)
    try:
        rebuilt = rebuild(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source=symbol_index.source,
        )
        if rebuilt != symbol_index:
            raise ValueError("symbol index mismatch")
        root = Parser(Language(grammar)).parse(symbol_index.source).root_node
        symbol_index.source.decode("utf-8", errors="strict")
    except (CstAdapterError, TypeError, UnicodeDecodeError, ValueError):
        raise EcmascriptCwe352ScanError(
            EcmascriptCwe352ScanErrorCode.INTEGRITY_FAILURE
        ) from None
    except Exception:
        raise EcmascriptCwe352ScanError(
            EcmascriptCwe352ScanErrorCode.INTEGRITY_FAILURE
        ) from None
    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmascriptCwe352ScanError(EcmascriptCwe352ScanErrorCode.ANALYSIS_UNAVAILABLE)
        raw: set[tuple[SourceRange, SourceRange]] = set()
        for node in nodes:
            if node.type != "call_expression":
                continue
            route = _route_fact(node, symbol_index.source)
            if route is not None:
                raw.add(route)
                if len(raw) > limits.max_signals:
                    raise EcmascriptCwe352ScanError(EcmascriptCwe352ScanErrorCode.SIGNAL_LIMIT)
        ordered = tuple(
            sorted(raw, key=lambda item: (item[1].start_byte, item[1].end_byte, item[0].start_byte))
        )
    except EcmascriptCwe352ScanError:
        raise
    except Exception:
        raise EcmascriptCwe352ScanError(
            EcmascriptCwe352ScanErrorCode.INTEGRITY_FAILURE
        ) from None
    signals = tuple(
        EcmascriptCwe352Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            language=language,
            source=source_range,
            sink=sink_range,
            detector=f"securecode-{language}-cwe352@1.0",
        )
        for source_range, sink_range in ordered
    )
    return EcmascriptCwe352ScanResult(
        repository_id=symbol_index.repository_id,
        revision=symbol_index.revision,
        path=symbol_index.path,
        content_sha256=symbol_index.content_sha256,
        source_size_bytes=symbol_index.source_byte_length,
        language=language,
        signals=signals,
        scan_sha256=_scan_sha256(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            language,
            signals,
        ),
    )


def _route_fact(node: Node, source: bytes) -> tuple[SourceRange, SourceRange] | None:
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None:
        return None
    property_node = function.child_by_field_name("property")
    if property_node is None or _text(source, property_node).lower() not in _ROUTE_METHODS:
        return None
    args = arguments.named_children
    if len(args) < 2 or not _is_route_path(args[0], source):
        return None
    if not any(_contains_handler(arg) for arg in args[1:]):
        return None
    # Only middleware and guards attached to this route may suppress it.
    if any(_is_route_protection(arg, source) for arg in args[1:]):
        return None
    return _range(property_node), _range(node)


def _is_route_path(node: Node, source: bytes) -> bool:
    if node.type == "string":
        value = _text(source, node).strip()
        return len(value) >= 2 and value[1] in {"/", "*"}
    if node.type == "template_string":
        return any(child.type == "string_fragment" for child in node.named_children) or not node.named_children
    return False


def _contains_handler(node: Node) -> bool:
    if node.type in _CALLABLES:
        return True
    if node.type in {"identifier", "member_expression", "call_expression"}:
        return True
    current = node
    for _ in range(8):
        if current.type in _CALLABLES:
            return True
        if current.type != "parenthesized_expression" or len(current.named_children) != 1:
            return False
        current = current.named_children[0]
    return False


def _is_route_protection(node: Node, source: bytes) -> bool:
    if _is_protection_argument(node, source):
        return True
    stack = list(node.named_children)
    while stack:
        current = stack.pop()
        if current.type == "call_expression" and _is_csrf_protection_call(current, source):
            return True
        stack.extend(current.named_children)
    return False


def _is_csrf_protection_call(node: Node, source: bytes) -> bool:
    function = node.child_by_field_name("function")
    if function is None:
        return False
    name = _function_name(function, source)
    if name in {"csrf", "csurf", "doublecsrf", "csrfprotect", "csrfprotection"}:
        return True
    if function.type == "call_expression":
        factory = function.child_by_field_name("function")
        args = function.child_by_field_name("arguments")
        if (
            factory is not None
            and _function_name(factory, source) == "require"
            and args is not None
            and any(
                child.type == "string" and "csurf" in _text(source, child).lower()
                for child in args.named_children
            )
        ):
            return True
    return _is_guard_name(name)


def _is_protection_argument(node: Node, source: bytes) -> bool:
    if node.type == "array":
        return any(_is_protection_argument(child, source) for child in node.named_children)
    current = node
    while current.type == "parenthesized_expression" and current.named_children:
        current = current.named_children[0]
    if current.type == "call_expression":
        return _is_csrf_protection_call(current, source)
    return current.type in {"identifier", "member_expression"} and _is_guard_name(
        _function_name(current, source)
    )


def _function_name(node: Node, source: bytes) -> str:
    if node.type == "identifier":
        return _text(source, node).lower()
    if node.type == "member_expression":
        prop = node.child_by_field_name("property")
        if prop is not None:
            return _text(source, prop).lower()
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        if function is not None:
            return _function_name(function, source)
    return ""


def _is_guard_name(name: str) -> bool:
    return _CSRF_GUARD.fullmatch(name) is not None or name in {
        "csrf",
        "csurf",
        "doublecsrf",
    }


def ecmascript_cwe352_signals_to_raw_signals(
    symbol_index: SymbolIndex,
    result: EcmascriptCwe352ScanResult,
    *,
    tenant_id: str,
    producer: ProducerRef,
) -> tuple[RawSignal, ...]:
    """Bind revalidated route facts to the source-free RawSignal boundary."""

    if (
        type(symbol_index) is not SymbolIndex
        or type(result) is not EcmascriptCwe352ScanResult
        or type(tenant_id) is not str
        or not tenant_id
        or type(producer) is not ProducerRef
        or len(result.signals) > DEFAULT_ECMASCRIPT_CWE352_SCAN_LIMITS.max_signals
    ):
        raise EcmascriptCwe352ScanError(EcmascriptCwe352ScanErrorCode.REQUEST_INVALID)
    try:
        validated_producer = ProducerRef.model_validate(producer.model_dump(mode="python"))
        if (
            validated_producer.producer_id != f"securecode-{symbol_index.language}-cwe352"
            or validated_producer.producer_version != "1.0.0"
        ):
            raise ValueError("producer mismatch")
        scanner = {
            "javascript": scan_javascript_cwe352,
            "typescript": scan_typescript_cwe352,
        }.get(symbol_index.language)
        if scanner is None or scanner(symbol_index) != result:
            raise ValueError("scanner facts mismatch")
        RepositoryFile(result.path, result.source_size_bytes, result.content_sha256)
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", tenant_id) is None:
            raise ValueError("tenant invalid")
        output: list[RawSignal] = []
        for signal in result.signals:
            binding = {
                "scan_sha256": result.scan_sha256,
                "sink": _range_value(signal.sink),
                "tenant_id": tenant_id,
                "producer": validated_producer.model_dump(mode="json"),
                "rule_id": "cwe-352-missing-csrf-protection",
            }
            digest = hashlib.sha256(
                json.dumps(binding, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            output.append(
                RawSignal(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    raw_signal_id=f"cwe352-{signal.language}-{digest}",
                    tenant_id=tenant_id,
                    head_sha=signal.revision,
                    producer=validated_producer,
                    rule_id="cwe-352-missing-csrf-protection",
                    location=SourceLocation(
                        schema_version=CONTRACT_SCHEMA_VERSION,
                        path=signal.path,
                        start=SourcePosition(
                            schema_version=CONTRACT_SCHEMA_VERSION,
                            line=signal.sink.start_point.row + 1,
                            column=signal.sink.start_point.column + 1,
                        ),
                        end=SourcePosition(
                            schema_version=CONTRACT_SCHEMA_VERSION,
                            line=signal.sink.end_point.row + 1,
                            column=signal.sink.end_point.column + 1,
                        ),
                        content_sha256=signal.content_sha256,
                    ),
                    payload_classification=DataClass.INTERNAL_METADATA,
                    signal_sha256=digest,
                )
            )
        return tuple(output)
    except (ValueError, TypeError, AttributeError):
        raise EcmascriptCwe352ScanError(
            EcmascriptCwe352ScanErrorCode.INTEGRITY_FAILURE
        ) from None


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    language: str,
    signals: tuple[EcmascriptCwe352Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "language": language,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {"cwe": item.cwe, "detector": item.detector, "sink": _range_value(item.sink)}
            for item in signals
        ],
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


def _bounded_nodes(root: Node, limits: EcmascriptCwe352ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmascriptCwe352ScanError(EcmascriptCwe352ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmascriptCwe352ScanError(EcmascriptCwe352ScanErrorCode.NODE_LIMIT)
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


def _text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmascriptCwe352ScanError(
            EcmascriptCwe352ScanErrorCode.INTEGRITY_FAILURE
        ) from None


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE352_SCAN_LIMITS",
    "EcmascriptCwe352ScanError",
    "EcmascriptCwe352ScanErrorCode",
    "EcmascriptCwe352ScanLimits",
    "EcmascriptCwe352ScanResult",
    "EcmascriptCwe352Signal",
    "ecmascript_cwe352_signals_to_raw_signals",
    "scan_javascript_cwe352",
    "scan_typescript_cwe352",
]
