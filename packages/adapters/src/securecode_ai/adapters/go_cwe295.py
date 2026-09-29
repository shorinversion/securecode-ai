"""Bounded Go facts for CWE-295 improper certificate validation.

The scanner recognises ``crypto/tls.Config.InsecureSkipVerify = true`` and
emits a fact unless the same configuration has a custom verifier that has a
reachable rejecting path.  It deliberately handles only the standard TLS
configuration shape.  Unknown aliases, malformed syntax, and unresolved
configuration flow are treated conservatively and never produce a safe
result.  Source bytes are used during the CST walk but are not retained in a
signal or an error.
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
_RULE_ID = "securecode-go-cwe295"
_DETECTOR = "securecode-go-cwe295@1.0"
_TLS_PACKAGE = "crypto/tls"
_INSECURE_FIELD = "InsecureSkipVerify"
_VERIFIER_FIELDS = frozenset({"VerifyConnection", "VerifyPeerCertificate"})
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})
_VALIDATION_NAMES = frozenset(
    {
        "cert",
        "certificate",
        "certificates",
        "chain",
        "chains",
        "peer",
        "peercertificates",
        "rawcerts",
        "verifiedchains",
        "verify",
        "verified",
        "verification",
        "validate",
        "validation",
        "valid",
        "trusted",
        "trust",
        "hostname",
        "issuer",
        "signature",
        "root",
        "roots",
        "x509",
    }
)
_VALIDATION_CALL_MARKERS = frozenset(
    {
        "verify",
        "validate",
        "certificate",
        "certificates",
        "parsecert",
        "trusted",
        "hostname",
        "signature",
        "chain",
    }
)


class GoCwe295ScanErrorCode(StrEnum):
    """Closed, source-free reasons a TLS validation scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe295ScanError(RuntimeError):
    """Fixed scanner failure that never echoes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe295ScanErrorCode) -> None:
        if type(code) is not GoCwe295ScanErrorCode:
            raise TypeError("Go CWE-295 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-295 certificate validation scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe295ScanLimits:
    """Hard bounds applied before and during structural analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-295 scan limits are invalid")


DEFAULT_GO_CWE295_SCAN_LIMITS = GoCwe295ScanLimits()


@dataclass(frozen=True, slots=True)
class GoCwe295Signal:
    """One immutable disabled-certificate-validation configuration fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    detector: str = _DETECTOR
    cwe: str = "CWE-295"
    detail: str = "tls_insecure_skip_verify"
    signal_id: str = ""
    rule_id: str = _RULE_ID

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
            )
            if valid_identity and valid_ranges
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or self.detector != _DETECTOR
            or self.cwe != "CWE-295"
            or self.detail != "tls_insecure_skip_verify"
            or self.rule_id != _RULE_ID
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
        ):
            raise ValueError("Go CWE-295 signal is invalid")
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
class GoCwe295ScanResult:
    """Deterministic, source-free result for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe295Signal, ...]
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
        )
        if valid_identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid_identity = False
        valid_signals = type(self.signals) is tuple and all(
            type(item) is GoCwe295Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    item.sink.start_byte,
                    item.sink.end_byte,
                    item.source.start_byte,
                    item.source.end_byte,
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
                self.signals,
            )
        ):
            raise ValueError("Go CWE-295 scan result is invalid")


def scan_go_cwe295(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe295ScanLimits = DEFAULT_GO_CWE295_SCAN_LIMITS,
) -> GoCwe295ScanResult:
    """Find disabled TLS verification without a rejecting custom verifier."""

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
    except Exception:
        raise GoCwe295ScanError(GoCwe295ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    functions = _named_functions(root, source)
    facts: list[tuple[SourceRange, SourceRange]] = []
    for scope in _scopes(root):
        nodes = _scope_preorder(scope)
        bindings = _verifier_bindings(nodes, source, imports, functions)
        for node in nodes:
            if node.type == "keyed_element":
                fact = _composite_fact(node, source, imports, functions)
                if fact is not None:
                    facts.append(fact)
            elif node.type == "assignment_statement":
                fact = _assignment_fact(node, source, imports, bindings)
                if fact is not None:
                    facts.append(fact)
            if len(facts) > limits.max_signals:
                raise GoCwe295ScanError(GoCwe295ScanErrorCode.SIGNAL_LIMIT)

    unique = sorted(
        set(facts),
        key=lambda item: (
            item[1].start_byte,
            item[1].end_byte,
            item[0].start_byte,
            item[0].end_byte,
        ),
    )
    if len(unique) > limits.max_signals:
        raise GoCwe295ScanError(GoCwe295ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe295Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
        )
        for source_range, sink_range in unique
    )
    return GoCwe295ScanResult(
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


def scan_go_tls_certificate_validation(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe295ScanLimits = DEFAULT_GO_CWE295_SCAN_LIMITS,
) -> GoCwe295ScanResult:
    """Descriptive alias for :func:`scan_go_cwe295`."""

    return scan_go_cwe295(symbol_index, limits=limits)


def scan_go_tls(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe295ScanLimits = DEFAULT_GO_CWE295_SCAN_LIMITS,
) -> GoCwe295ScanResult:
    """Compatibility alias for callers grouping Go TLS scanners."""

    return scan_go_cwe295(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe295ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe295ScanLimits:
        raise GoCwe295ScanError(GoCwe295ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe295ScanError(GoCwe295ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe295ScanError(GoCwe295ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe295ScanError(GoCwe295ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None or _text(source, path_node).strip('"`') != _TLS_PACKAGE:
            continue
        name_node = node.child_by_field_name("name")
        alias = _text(source, name_node) if name_node is not None else "tls"
        if alias not in {".", "_"}:
            aliases[alias] = _TLS_PACKAGE
    return aliases


def _named_functions(root: Node, source: bytes) -> dict[str, Node]:
    functions: dict[str, Node] = {}
    for node in _preorder(root):
        if node.type != "function_declaration":
            continue
        name = node.child_by_field_name("name")
        body = node.child_by_field_name("body")
        if name is not None and body is not None:
            functions[_text(source, name)] = body
    return functions


def _verifier_bindings(
    nodes: tuple[Node, ...],
    source: bytes,
    imports: dict[str, str],
    functions: dict[str, Node],
) -> dict[str, bool]:
    """Return receiver names with a valid custom verifier in one Go scope."""

    bindings: dict[str, bool] = {}
    for node in nodes:
        if node.type not in {"short_var_declaration", "var_spec", "assignment_statement"}:
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None:
            left = node.child_by_field_name("name")
        if right is None:
            right = node.child_by_field_name("value")
        if left is None or right is None:
            continue
        if node.type in {"short_var_declaration", "var_spec"}:
            names = _left_names(left, source)
            composite = _tls_composite(right, source, imports)
            if composite is None:
                continue
            bindings.update(
                {
                    name: _composite_has_valid_verifier(composite, source, functions)
                    for name in names
                }
            )
            continue
        selector = left if left.type == "selector_expression" else None
        if selector is None:
            continue
        field = selector.child_by_field_name("field")
        operand = selector.child_by_field_name("operand")
        if field is None or operand is None or _text(source, field) not in _VERIFIER_FIELDS:
            continue
        receiver = _compact_text(source, operand)
        bindings[receiver] = _callback_is_valid(right, source, functions)
    return bindings


def _composite_fact(
    node: Node,
    source: bytes,
    imports: dict[str, str],
    functions: dict[str, Node],
) -> tuple[SourceRange, SourceRange] | None:
    key = node.child_by_field_name("key")
    value = node.child_by_field_name("value")
    if key is None or value is None or _text(source, key) != _INSECURE_FIELD:
        return None
    if _compact_text(source, value) != "true":
        return None
    composite = node.parent
    while composite is not None and composite.type != "composite_literal":
        composite = composite.parent
    if composite is None or _tls_composite(composite, source, imports) is None:
        return None
    if _composite_has_valid_verifier(composite, source, functions):
        return None
    return _range(key), _range(composite)


def _assignment_fact(
    node: Node,
    source: bytes,
    imports: dict[str, str],
    bindings: dict[str, bool],
) -> tuple[SourceRange, SourceRange] | None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None or _compact_text(source, right) != "true":
        return None
    if left.type != "selector_expression":
        return None
    field = left.child_by_field_name("field")
    operand = left.child_by_field_name("operand")
    if field is None or operand is None or _text(source, field) != _INSECURE_FIELD:
        return None
    receiver = _compact_text(source, operand)
    if bindings.get(receiver, False):
        return None
    # A receiver can be inferred as a TLS config only when it was declared in
    # this scope. Unknown receivers are still reported: enabling this field is
    # unsafe by itself, while an unrecognised custom verifier cannot justify a
    # safe result.
    del imports
    return _range(field), _range(node)


def _tls_composite(node: Node, source: bytes, imports: dict[str, str]) -> Node | None:
    candidate: Node | None = node
    while candidate is not None and candidate.type != "composite_literal":
        candidate = candidate.parent
    if candidate is None:
        return None
    type_node = candidate.child_by_field_name("type")
    if type_node is None:
        return None
    type_text = _compact_text(source, type_node)
    if type_text.startswith("&"):
        type_text = type_text[1:]
    if "." not in type_text:
        return None
    alias, type_name = type_text.rsplit(".", 1)
    if type_name != "Config" or imports.get(alias) != _TLS_PACKAGE:
        return None
    return candidate


def _composite_has_valid_verifier(
    composite: Node,
    source: bytes,
    functions: dict[str, Node],
) -> bool:
    for child in composite.named_children:
        if child.type != "keyed_element":
            continue
        key = child.child_by_field_name("key")
        value = child.child_by_field_name("value")
        if key is None or value is None or _text(source, key) not in _VERIFIER_FIELDS:
            continue
        if _callback_is_valid(value, source, functions):
            return True
    return False


def _callback_is_valid(node: Node, source: bytes, functions: dict[str, Node]) -> bool:
    candidate = node
    while candidate.type in {"parenthesized_expression", "unary_expression", "pointer_expression"}:
        children = candidate.named_children
        if len(children) != 1:
            return False
        candidate = children[0]
    if candidate.type == "identifier":
        body = functions.get(_text(source, candidate))
        return body is not None and _body_rejects_invalid_certificate(body, source)
    if candidate.type != "function_literal":
        return False
    body = candidate.child_by_field_name("body")
    return body is not None and _body_rejects_invalid_certificate(body, source)


def _body_rejects_invalid_certificate(body: Node, source: bytes) -> bool:
    returns = tuple(node for node in _preorder(body) if node.type == "return_statement")
    non_nil_return = any(
        children and _compact_text(source, children[0]) != "nil"
        for item in returns
        for children in (item.named_children,)
    )
    if not non_nil_return:
        return False
    identifiers = {
        _text(source, node).lower()
        for node in _preorder(body)
        if node.type in {"identifier", "field_identifier"}
    }
    call_names = {
        _text(source, node).lower()
        for node in _preorder(body)
        if node.type == "field_identifier"
        and node.parent is not None
        and node.parent.type == "selector_expression"
    }
    has_validation_name = bool(
        identifiers & _VALIDATION_NAMES
        or any(marker in name for name in call_names for marker in _VALIDATION_CALL_MARKERS)
    )
    has_rejection_branch = any(
        node.type in {"if_statement", "expression_switch_statement", "type_switch_statement"}
        for node in _preorder(body)
    )
    return has_validation_name or has_rejection_branch


def _left_names(node: Node, source: bytes) -> tuple[str, ...]:
    if node.type in {"identifier", "field_identifier"}:
        return (_text(source, node),)
    return tuple(
        _text(source, child)
        for child in node.named_children
        if child.type in {"identifier", "field_identifier"}
    )


def _scopes(root: Node) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node is root or node.type in _GO_SCOPES)


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
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-295",
        "detector": _DETECTOR,
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
    signals: tuple[GoCwe295Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-295",
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
                "detail": signal.detail,
                "detector": signal.detector,
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


# Compatibility aliases keep the module usable beside the existing portfolio
# adapters while retaining a Go-specific public name.
Cwe295ScanErrorCode = GoCwe295ScanErrorCode
Cwe295ScanError = GoCwe295ScanError
Cwe295ScanLimits = GoCwe295ScanLimits
Cwe295ScanResult = GoCwe295ScanResult
Cwe295Signal = GoCwe295Signal


__all__ = [
    "DEFAULT_GO_CWE295_SCAN_LIMITS",
    "Cwe295ScanError",
    "Cwe295ScanErrorCode",
    "Cwe295ScanLimits",
    "Cwe295ScanResult",
    "Cwe295Signal",
    "GoCwe295ScanError",
    "GoCwe295ScanErrorCode",
    "GoCwe295ScanLimits",
    "GoCwe295ScanResult",
    "GoCwe295Signal",
    "scan_go_cwe295",
    "scan_go_tls",
    "scan_go_tls_certificate_validation",
]
