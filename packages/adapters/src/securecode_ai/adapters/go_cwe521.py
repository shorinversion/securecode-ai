"""Bounded Go CWE-521 weak password-requirement facts.

The detector is intentionally narrow.  It reports an explicitly named
password validator or password-policy configuration only when the source
contains a concrete weak length requirement, or when the validator is reduced
to an empty-string/trivial acceptance check.  Unknown validation helpers and
unresolved values are left alone.  Strong minimum and maximum requirements in
the same validation scope suppress the corresponding weak fact.

Only an admitted, sealed :class:`~securecode_ai.core.SymbolIndex` is accepted.
Results contain immutable identity, exact source ranges, and content-addressed
hashes.  Source text and parser diagnostics never leave this module.
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
_RULE_ID = "securecode-go-cwe521"
_DETECTOR = "securecode-go-cwe521@1.0"
_DETAIL = "weak_password_requirement"
_MINIMUM_LENGTH = 8
_STRONG_MINIMUM_LENGTH = 12
_STRONG_MAXIMUM_LENGTH = 64
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})
_POLICY_NODE_TYPES = frozenset(
    {
        "assignment_statement",
        "const_spec",
        "short_var_declaration",
        "var_spec",
        "keyed_element",
    }
)
_PASSWORD_WORDS = frozenset(
    {"pass", "passwd", "passcode", "passphrase", "password", "pwd", "credential"}
)
_VALIDATOR_WORDS = frozenset({"check", "policy", "require", "valid", "validate", "verify"})
_IGNORED_PATH_PARTS = frozenset(
    {"doc", "docs", "example", "examples", "fixture", "fixtures", "test", "testdata", "tests"}
)
_IGNORED_SCOPE_PREFIXES = ("test", "benchmark", "example", "fuzz", "fixture", "golden")


class GoCwe521ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-521 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe521ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe521ScanErrorCode) -> None:
        if type(code) is not GoCwe521ScanErrorCode:
            raise TypeError("Go CWE-521 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-521 password-policy scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe521ScanLimits:
    """Hard bounds applied before and during local structural analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-521 scan limits are invalid")


DEFAULT_GO_CWE521_SCAN_LIMITS = GoCwe521ScanLimits()


class GoCwe521Operation(StrEnum):
    """Recognised weak password-policy conditions."""

    MINIMUM_LENGTH = "minimum_length"
    MAXIMUM_LENGTH = "maximum_length"
    MISSING_POLICY = "missing_policy"


@dataclass(frozen=True, slots=True)
class GoCwe521Signal:
    """One immutable source-free weak password-policy fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe521Operation
    threshold: int | None = None
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-521"
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
            except ValueError:
                identity_valid = False
        ranges_valid = (
            type(self.source) is SourceRange
            and type(self.sink) is SourceRange
            and self.sink.contains(self.source)
            and self.source.end_byte <= self.source_size_bytes
            and self.sink.end_byte <= self.source_size_bytes
        )
        threshold_valid = self.threshold is None or (
            type(self.threshold) is int and 0 <= self.threshold <= 1_000_000
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
                self.threshold,
            )
            if identity_valid
            and ranges_valid
            and threshold_valid
            and type(self.operation) is GoCwe521Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or not threshold_valid
            or type(self.operation) is not GoCwe521Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-521"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-521 signal is invalid")
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
class GoCwe521ScanResult:
    """Deterministic, source-free CWE-521 output for one admitted Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe521Signal, ...]
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
            type(item) is GoCwe521Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    item.sink.start_byte,
                    item.sink.end_byte,
                    item.source.start_byte,
                    item.source.end_byte,
                    item.operation.value,
                    item.threshold if item.threshold is not None else -1,
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
            raise ValueError("Go CWE-521 scan result is invalid")


def scan_go_cwe521(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe521ScanLimits = DEFAULT_GO_CWE521_SCAN_LIMITS,
) -> GoCwe521ScanResult:
    """Find explicit weak Go password requirements with bounded evidence."""

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
        raise GoCwe521ScanError(GoCwe521ScanErrorCode.INTEGRITY_FAILURE) from None

    if _is_nonproduction_path(symbol_index.path):
        return _empty_result(symbol_index)

    facts: set[tuple[SourceRange, SourceRange, GoCwe521Operation, int | None]] = set()
    try:
        for scope in _function_scopes(root):
            for source_range, sink_range, operation, threshold in _length_facts(
                scope, source, limits
            ):
                facts.add((source_range, sink_range, operation, threshold))
            missing = _missing_policy_fact(scope, source)
            if missing is not None:
                facts.add(missing)
            if len(facts) > limits.max_signals:
                raise GoCwe521ScanError(GoCwe521ScanErrorCode.SIGNAL_LIMIT)
        for fact in _configuration_facts(root, source, limits):
            facts.add(fact)
            if len(facts) > limits.max_signals:
                raise GoCwe521ScanError(GoCwe521ScanErrorCode.SIGNAL_LIMIT)
    except GoCwe521ScanError:
        raise
    except Exception:
        raise GoCwe521ScanError(GoCwe521ScanErrorCode.INTEGRITY_FAILURE) from None

    ordered = sorted(
        facts,
        key=lambda item: (
            item[1].start_byte,
            item[1].end_byte,
            item[0].start_byte,
            item[0].end_byte,
            item[2].value,
            item[3] if item[3] is not None else -1,
        ),
    )
    if len(ordered) > limits.max_signals:
        raise GoCwe521ScanError(GoCwe521ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe521Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
            threshold=threshold,
        )
        for source_range, sink_range, operation, threshold in ordered
    )
    return GoCwe521ScanResult(
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


def scan_go_weak_password_requirements(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe521ScanLimits = DEFAULT_GO_CWE521_SCAN_LIMITS,
) -> GoCwe521ScanResult:
    """Descriptive alias for :func:`scan_go_cwe521`."""

    return scan_go_cwe521(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe521ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe521ScanLimits:
        raise GoCwe521ScanError(GoCwe521ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe521ScanError(GoCwe521ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe521ScanError(GoCwe521ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe521ScanError(GoCwe521ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _length_facts(
    scope: Node, source: bytes, limits: GoCwe521ScanLimits
) -> tuple[tuple[SourceRange, SourceRange, GoCwe521Operation, int | None], ...]:
    rules: list[tuple[SourceRange, SourceRange, GoCwe521Operation, int | None]] = []
    strong_min = False
    strong_max = False
    for node, depth in _with_depth(scope, stop_nested=True):
        if depth > limits.max_expression_depth:
            raise GoCwe521ScanError(GoCwe521ScanErrorCode.ANALYSIS_UNAVAILABLE)
        if node.type != "binary_expression":
            continue
        compact = _compact_text(source, node)
        if not _has_password_length_subject(compact):
            continue
        operator = _comparison_operator(compact)
        value = _single_numeric_value(node, source)
        if operator is None or value is None:
            continue
        if operator in {">=", ">"} and value >= _STRONG_MINIMUM_LENGTH:
            strong_min = True
        if operator in {"<=", "<"} and value >= _STRONG_MAXIMUM_LENGTH:
            strong_max = True
        if operator in {">=", ">"} and value < _MINIMUM_LENGTH:
            operation = GoCwe521Operation.MINIMUM_LENGTH
        elif operator in {"<=", "<"} and value <= _MINIMUM_LENGTH:
            operation = GoCwe521Operation.MAXIMUM_LENGTH
        else:
            continue
        child = _password_subject_node(node, source)
        if child is None:
            child = node
        rules.append((_range(child), _range(node), operation, value))
    if strong_min or strong_max:
        rules = [
            item
            for item in rules
            if not (
                (item[2] is GoCwe521Operation.MINIMUM_LENGTH and strong_min)
                or (item[2] is GoCwe521Operation.MAXIMUM_LENGTH and strong_max)
            )
        ]
    return tuple(rules)


def _configuration_facts(
    root: Node, source: bytes, limits: GoCwe521ScanLimits
) -> tuple[tuple[SourceRange, SourceRange, GoCwe521Operation, int | None], ...]:
    output: list[tuple[SourceRange, SourceRange, GoCwe521Operation, int | None]] = []
    for node, depth in _with_depth(root):
        if depth > limits.max_expression_depth:
            raise GoCwe521ScanError(GoCwe521ScanErrorCode.ANALYSIS_UNAVAILABLE)
        if node.type not in _POLICY_NODE_TYPES:
            continue
        text = _compact_text(source, node)
        kind = _policy_kind(text, _configuration_context(node, source))
        if kind is None:
            continue
        value = _single_numeric_value(node, source)
        if value is None:
            continue
        weak = (
            kind == "min" and value < _MINIMUM_LENGTH
        ) or (kind == "max" and value <= _MINIMUM_LENGTH)
        if not weak:
            continue
        operation = (
            GoCwe521Operation.MINIMUM_LENGTH
            if kind == "min"
            else GoCwe521Operation.MAXIMUM_LENGTH
        )
        output.append((_range(node), _range(node), operation, value))
    return tuple(output)


def _missing_policy_fact(
    scope: Node, source: bytes
) -> tuple[SourceRange, SourceRange, GoCwe521Operation, int | None] | None:
    name_node = scope.child_by_field_name("name")
    if name_node is None:
        return None
    name = _normalize(_text(source, name_node))
    if not any(word in name for word in _PASSWORD_WORDS) or not any(
        word in name for word in _VALIDATOR_WORDS
    ):
        return None
    parameter = _password_parameter(scope, source)
    if parameter is None:
        return None
    body = scope.child_by_field_name("body")
    if body is None:
        return None
    compact = _compact_text(source, body).lower()
    if not _trivial_password_acceptance(compact):
        return None
    return (
        _range(parameter),
        _range(scope),
        GoCwe521Operation.MISSING_POLICY,
        None,
    )


def _password_parameter(scope: Node, source: bytes) -> Node | None:
    parameters = scope.child_by_field_name("parameters")
    if parameters is None:
        return None
    for node in _preorder(parameters):
        if node.type != "parameter_declaration":
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        if _is_password_name(_text(source, name_node)):
            return name_node
    return None


def _trivial_password_acceptance(compact: str) -> bool:
    if compact == "{returntrue}":
        return True
    if re.fullmatch(r"\{return(?:password|passwd|passphrase|passcode|pwd)!=(?:\"\"|``)\}", compact):
        return True
    if re.fullmatch(r"\{returnlen\((?:password|passwd|passphrase|passcode|pwd)\)(?:>|>=)[01]\}", compact):
        return True
    return bool(
        re.fullmatch(
            r"\{if(?:password|passwd|passphrase|passcode|pwd)==\"\"\{returnfalse\}returntrue\}",
            compact,
        )
    )


def _has_password_length_subject(text: str) -> bool:
    lowered = text.lower()
    if not any(word in lowered for word in _PASSWORD_WORDS):
        return False
    return "len(" in lowered or "length" in lowered or "rune_count" in lowered


def _password_subject_node(node: Node, source: bytes) -> Node | None:
    for child in _preorder(node):
        if child.type in {"call_expression", "identifier", "field_identifier"}:
            text = _compact_text(source, child).lower()
            if _has_password_length_subject(text):
                return child
    return None


def _comparison_operator(text: str) -> str | None:
    match = re.search(r"(?<![<>=])(?:<=|>=|<|>|==|!=)(?![<>=])", text)
    return match.group(0) if match else None


def _single_numeric_value(node: Node, source: bytes) -> int | None:
    values: list[int] = []
    for child in _preorder(node):
        if child.type != "int_literal":
            continue
        raw = _text(source, child).replace("_", "")
        try:
            values.append(int(raw, 0))
        except ValueError:
            return None
    return values[0] if len(values) == 1 else None


def _policy_kind(text: str, context: str) -> str | None:
    normalized = _normalize(text)
    combined = f"{normalized}{_normalize(context)}"
    has_password = any(word in combined for word in _PASSWORD_WORDS)
    is_min = any(marker in normalized for marker in ("min", "minimum"))
    is_max = any(marker in normalized for marker in ("max", "maximum"))
    has_length = "length" in normalized or normalized.endswith("len") or "len" in normalized
    if is_min and has_length and (has_password or "policy" in _normalize(context)):
        return "min"
    if is_max and has_length and (has_password or "policy" in _normalize(context)):
        return "max"
    return None


def _configuration_context(node: Node, source: bytes) -> str:
    ancestor = node.parent
    hops = 0
    values: list[str] = []
    while ancestor is not None and hops < 5:
        if ancestor.type == "composite_literal":
            values.append(_text(source, ancestor))
        ancestor = ancestor.parent
        hops += 1
    return " ".join(values)


def _is_password_name(value: str) -> bool:
    return any(word in _normalize(value) for word in _PASSWORD_WORDS)


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _function_scopes(root: Node) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node.type in _GO_SCOPES)


def _scope_preorder(scope: Node) -> tuple[Node, ...]:
    return tuple(node for node, _ in _with_depth(scope, stop_nested=True))


def _with_depth(root: Node, *, stop_nested: bool = False) -> tuple[tuple[Node, int], ...]:
    output: list[tuple[Node, int]] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        output.append((node, depth))
        if stop_nested and node is not root and node.type in _GO_SCOPES:
            continue
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _preorder(root: Node) -> tuple[Node, ...]:
    return tuple(node for node, _ in _with_depth(root))


def _is_nonproduction_path(path: str) -> bool:
    normalized = path.replace("\\", "/").casefold()
    basename = normalized.rsplit("/", 1)[-1]
    if basename.endswith("_test.go") or basename.endswith("_testdata.go"):
        return True
    return any(part in _IGNORED_PATH_PARTS for part in normalized.split("/"))


def _empty_result(symbol_index: SymbolIndex) -> GoCwe521ScanResult:
    signals: tuple[GoCwe521Signal, ...] = ()
    return GoCwe521ScanResult(
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
    operation: GoCwe521Operation,
    threshold: int | None,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-521",
        "detector": _DETECTOR,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "sink": _range_value(sink),
        "source": _range_value(source),
        "source_size_bytes": source_size_bytes,
        "threshold": threshold,
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
    signals: tuple[GoCwe521Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-521",
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
                "threshold": signal.threshold,
            }
            for signal in signals
        ],
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


Cwe521ScanErrorCode = GoCwe521ScanErrorCode
Cwe521ScanError = GoCwe521ScanError
Cwe521ScanLimits = GoCwe521ScanLimits
Cwe521ScanResult = GoCwe521ScanResult
Cwe521Signal = GoCwe521Signal


__all__ = [
    "Cwe521ScanError",
    "Cwe521ScanErrorCode",
    "Cwe521ScanLimits",
    "Cwe521ScanResult",
    "Cwe521Signal",
    "DEFAULT_GO_CWE521_SCAN_LIMITS",
    "GoCwe521Operation",
    "GoCwe521ScanError",
    "GoCwe521ScanErrorCode",
    "GoCwe521ScanLimits",
    "GoCwe521ScanResult",
    "GoCwe521Signal",
    "scan_go_cwe521",
    "scan_go_weak_password_requirements",
]
