"""Bounded Python CWE-521 weak-password-requirement facts.

The scanner recognises explicit password-policy configuration and reports only
policies whose statically known limits are below a conservative minimum.  It
also reports a policy that explicitly disables every recognised complexity
requirement.  Dynamic values, generic length validators, and partial
complexity configuration are ignored because they do not establish a
high-confidence security claim.

Only an admitted, sealed :class:`SymbolIndex` and its matching sealed CPython
AST are accepted.  Results contain immutable identity, source ranges, and
content-addressed identifiers.  Repository source and parser diagnostics are
never retained in results or errors.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import RepositoryFile, SourcePoint, SourceRange, SymbolIndex

from .python_ast import (
    PythonAstAnalysis,
    PythonAstError,
    PythonAstStatus,
    analyze_python_ast,
    open_python_ast,
)

_MAX_LIMIT_VALUES = (2_000_000, 10_000, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-python-cwe521"
_DETECTOR = "securecode-python-cwe521@1.0"
_DETAIL = "weak_password_requirement"
_WEAK_LENGTH_THRESHOLD = 8


class PythonCwe521ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-521 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe521ScanError(RuntimeError):
    """Fixed scanner failure which never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe521ScanErrorCode) -> None:
        if type(code) is not PythonCwe521ScanErrorCode:
            raise TypeError("Python CWE-521 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-521 password-policy scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe521Operation(StrEnum):
    """Recognised weak password-policy operations."""

    MINIMUM_LENGTH = "minimum_length"
    MAXIMUM_LENGTH = "maximum_length"
    COMPLEXITY_DISABLED = "complexity_disabled"

    # Compatibility names used by generic scanner consumers.
    WEAK_MINIMUM_LENGTH = "minimum_password_length"
    WEAK_MAXIMUM_LENGTH = "maximum_password_length"
    MISSING_COMPLEXITY = "password_complexity_disabled"


@dataclass(frozen=True, slots=True)
class PythonCwe521ScanLimits:
    """Hard ceilings for source, output, and bounded AST traversal."""

    max_source_bytes: int = _MAX_LIMIT_VALUES[0]
    max_signals: int = _MAX_LIMIT_VALUES[1]
    max_resolution_depth: int = _MAX_LIMIT_VALUES[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("Python CWE-521 scan limits are invalid")


DEFAULT_PYTHON_CWE521_SCAN_LIMITS = PythonCwe521ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe521Signal:
    """One immutable weak-password-policy fact without source text."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe521Operation
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
            except (TypeError, ValueError):
                identity_valid = False
        ranges_valid = (
            type(self.source) is SourceRange
            and type(self.sink) is SourceRange
            and self.sink.contains(self.source)
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
            if identity_valid and ranges_valid and type(self.operation) is PythonCwe521Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not PythonCwe521Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-521"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-521 signal is invalid")
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
class PythonCwe521ScanResult:
    """Deterministic, source-free CWE-521 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe521Signal, ...]
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
            except (TypeError, ValueError):
                identity_valid = False
        signals_valid = type(self.signals) is tuple and all(
            type(item) is PythonCwe521Signal for item in self.signals
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
            if signals_valid
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
            if signals_valid
            else False
        )
        if (
            not identity_valid
            or not signals_valid
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
                self.signals,
            )
        ):
            raise ValueError("Python CWE-521 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _WeakFact:
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe521Operation


_MINIMUM_KEYS = frozenset(
    {
        "min",
        "minlength",
        "minimumlength",
        "minpasswordlength",
        "passwordminlength",
        "passwordminimumlength",
    }
)
_MAXIMUM_KEYS = frozenset(
    {
        "max",
        "maxlength",
        "maximumlength",
        "maxpasswordlength",
        "passwordmaxlength",
        "passwordmaximumlength",
    }
)
_COMPLEXITY_KEYS = frozenset(
    {
        "complexity",
        "passwordcomplexity",
        "requirecomplexity",
        "requireuppercase",
        "requirelowercase",
        "requiredigit",
        "requirenumber",
        "requirenumbers",
        "requirespecial",
        "requiresymbol",
        "requirecapital",
        "uppercase",
        "lowercase",
        "digit",
        "digits",
        "number",
        "numbers",
        "special",
        "symbol",
        "symbols",
    }
)
_COMPLEXITY_COMPONENTS = frozenset(
    {
        "requireuppercase",
        "requirelowercase",
        "requiredigit",
        "requirenumber",
        "requirenumbers",
        "requirespecial",
        "requiresymbol",
        "requirecapital",
        "uppercase",
        "lowercase",
        "digit",
        "digits",
        "number",
        "numbers",
        "special",
        "symbol",
        "symbols",
    }
)
_PASSWORD_POLICY_CALLS = frozenset(
    {
        "passwordpolicy",
        "passwordvalidator",
        "passwordvalidators",
        "passwordfield",
        "passwordformfield",
        "passwordcheck",
        "validatepassword",
        "checkpassword",
        "setpasswordpolicy",
        "configurepasswordpolicy",
        "passwordrules",
        "passwordrequirements",
        "passwordschema",
    }
)
_PASSWORD_WORDS = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "passcode",
        "credential",
        "credentials",
        "secret",
        "loginpassword",
    }
)
_POLICY_WORDS = frozenset(
    {"policy", "policies", "validator", "validators", "requirements", "rules"}
)
_SUPPRESSED_PATH_PARTS = frozenset(
    {"test", "tests", "fixture", "fixtures", "example", "examples", "docs", "documentation"}
)


def scan_python_cwe521(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe521ScanLimits = DEFAULT_PYTHON_CWE521_SCAN_LIMITS,
) -> PythonCwe521ScanResult:
    """Find explicit Python password requirements below safe bounds.

    Only literal integer values below eight characters and an explicit policy
    that disables all recognised complexity checks are reported.  Unknown
    aliases, dynamic values, generic validators, and partial complexity
    settings are ignored.  A mismatched AST analysis fails closed.
    """

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe521ScanLimits
    ):
        raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.SOURCE_LIMIT)
    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    if _suppressed_path(symbol_index.path):
        return _empty_result(symbol_index)
    parents = _parent_map(tree, limits.max_resolution_depth)
    assignments = _collect_assignments(tree, limits.max_resolution_depth)
    raw: list[_WeakFact] = []
    for node in _bounded_nodes(tree, limits.max_resolution_depth * 10_000):
        if len(raw) > limits.max_signals:
            raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.SIGNAL_LIMIT)
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            raw.extend(
                _assignment_facts(
                    node,
                    assignments,
                    parents,
                    source,
                    line_starts,
                    limits.max_resolution_depth,
                )
            )
        elif isinstance(node, ast.Call):
            raw.extend(
                _call_facts(
                    node,
                    assignments,
                    parents,
                    source,
                    line_starts,
                    limits.max_resolution_depth,
                )
            )
        elif isinstance(node, ast.Dict):
            raw.extend(
                _dict_facts(
                    node,
                    assignments,
                    parents,
                    source,
                    line_starts,
                    limits.max_resolution_depth,
                )
            )
        if len(raw) > limits.max_signals * 2:
            raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.SIGNAL_LIMIT)

    unique = sorted(
        set(raw),
        key=lambda item: (
            item.sink.start_byte,
            item.sink.end_byte,
            item.source.start_byte,
            item.source.end_byte,
            item.operation.value,
        ),
    )
    if len(unique) > limits.max_signals:
        raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe521Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=item.source,
            sink=item.sink,
            operation=item.operation,
        )
        for item in unique
    )
    return PythonCwe521ScanResult(
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


def _empty_result(symbol_index: SymbolIndex) -> PythonCwe521ScanResult:
    return PythonCwe521ScanResult(
        repository_id=symbol_index.repository_id,
        revision=symbol_index.revision,
        path=symbol_index.path,
        content_sha256=symbol_index.content_sha256,
        source_size_bytes=symbol_index.source_byte_length,
        signals=(),
        scan_sha256=_scan_sha256(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            (),
        ),
    )


def _assignment_facts(
    node: ast.Assign | ast.AnnAssign,
    assignments: dict[str, tuple[ast.expr, ...]],
    parents: dict[int, ast.AST],
    source: bytes,
    line_starts: tuple[int, ...],
    max_depth: int,
) -> tuple[_WeakFact, ...]:
    values = (node.value,) if isinstance(node, ast.AnnAssign) and node.value is not None else ()
    if isinstance(node, ast.Assign):
        values = (node.value,)
    if not values:
        return ()
    target_names = tuple(
        name for target in _assignment_targets(node) for name in _target_names(target)
    )
    context = _name_has_password_context(target_names)
    policy_context = context or _name_has_policy_context(target_names)
    if not policy_context:
        return ()
    value = values[0]
    facts: list[_WeakFact] = []
    if (
        isinstance(value, ast.Constant)
        and type(value.value) is int
        and not isinstance(value.value, bool)
    ):
        key = _normalise_name(" ".join(target_names))
        operation = _length_operation(key, value.value)
        if operation is not None:
            facts.append(_fact_from_nodes(value, node, operation, source, line_starts))
    if isinstance(value, ast.Dict):
        facts.extend(
            _dict_facts(
                value,
                assignments,
                parents,
                source,
                line_starts,
                max_depth,
                forced_context=True,
            )
        )
    if isinstance(value, ast.Call):
        facts.extend(
            _call_facts(
                value,
                assignments,
                parents,
                source,
                line_starts,
                max_depth,
                forced_context=True,
            )
        )
    return tuple(facts)


def _call_facts(
    node: ast.Call,
    assignments: dict[str, tuple[ast.expr, ...]],
    parents: dict[int, ast.AST],
    source: bytes,
    line_starts: tuple[int, ...],
    max_depth: int,
    *,
    forced_context: bool = False,
) -> tuple[_WeakFact, ...]:
    call_name = _normalise_name(_dotted_name(node.func) or "")
    context = forced_context or _call_has_password_context(node, parents, max_depth)
    if not context and call_name not in _PASSWORD_POLICY_CALLS:
        return ()
    facts: list[_WeakFact] = []
    length_values: list[tuple[ast.expr, PythonCwe521Operation]] = []
    complexity_false: list[ast.expr] = []
    complexity_true: list[ast.expr] = []
    for keyword in node.keywords:
        if keyword.arg is None:
            continue
        key = _normalise_name(keyword.arg)
        value = _resolve_int(keyword.value, assignments, max_depth)
        if key in _MINIMUM_KEYS and value is not None and value < _WEAK_LENGTH_THRESHOLD:
            length_values.append((keyword.value, PythonCwe521Operation.MINIMUM_LENGTH))
        elif key in _MAXIMUM_KEYS and value is not None and value < _WEAK_LENGTH_THRESHOLD:
            length_values.append((keyword.value, PythonCwe521Operation.MAXIMUM_LENGTH))
        elif key in _COMPLEXITY_KEYS:
            boolean = _resolve_bool(keyword.value, assignments, max_depth)
            if boolean is False:
                complexity_false.append(keyword.value)
            elif boolean is True:
                complexity_true.append(keyword.value)
    for length_node, operation in length_values:
        facts.append(_fact_from_nodes(length_node, node, operation, source, line_starts))
    if _complexity_is_disabled(complexity_false, complexity_true, node, assignments, max_depth):
        source_node = complexity_false[0] if complexity_false else node
        facts.append(
            _fact_from_nodes(
                source_node,
                node,
                PythonCwe521Operation.COMPLEXITY_DISABLED,
                source,
                line_starts,
            )
        )
    return tuple(facts)


def _dict_facts(
    node: ast.Dict,
    assignments: dict[str, tuple[ast.expr, ...]],
    parents: dict[int, ast.AST],
    source: bytes,
    line_starts: tuple[int, ...],
    max_depth: int,
    *,
    forced_context: bool = False,
) -> tuple[_WeakFact, ...]:
    context = forced_context or _dict_has_password_context(node, parents, max_depth)
    if not context:
        return ()
    facts: list[_WeakFact] = []
    length_values: list[tuple[ast.expr, PythonCwe521Operation]] = []
    complexity_false: list[ast.expr] = []
    complexity_true: list[ast.expr] = []
    for key_node, value_node in zip(node.keys, node.values, strict=True):
        key = _literal_key(key_node)
        if key is None:
            continue
        normalised = _normalise_name(key)
        value = _resolve_int(value_node, assignments, max_depth)
        if normalised in _MINIMUM_KEYS and value is not None and value < _WEAK_LENGTH_THRESHOLD:
            length_values.append((value_node, PythonCwe521Operation.MINIMUM_LENGTH))
        elif normalised in _MAXIMUM_KEYS and value is not None and value < _WEAK_LENGTH_THRESHOLD:
            length_values.append((value_node, PythonCwe521Operation.MAXIMUM_LENGTH))
        elif normalised in _COMPLEXITY_KEYS:
            boolean = _resolve_bool(value_node, assignments, max_depth)
            if boolean is False:
                complexity_false.append(value_node)
            elif boolean is True:
                complexity_true.append(value_node)
    for length_node, operation in length_values:
        facts.append(_fact_from_nodes(length_node, node, operation, source, line_starts))
    if _complexity_is_disabled(complexity_false, complexity_true, node, assignments, max_depth):
        source_node = complexity_false[0] if complexity_false else node
        facts.append(
            _fact_from_nodes(
                source_node,
                node,
                PythonCwe521Operation.COMPLEXITY_DISABLED,
                source,
                line_starts,
            )
        )
    return tuple(facts)


def _complexity_is_disabled(
    false_values: list[ast.expr],
    true_values: list[ast.expr],
    node: ast.AST,
    assignments: dict[str, tuple[ast.expr, ...]],
    max_depth: int,
) -> bool:
    if not false_values:
        return False
    # A direct complexity=False/require_complexity=False is unambiguous.
    direct = False
    if isinstance(node, ast.Call):
        for keyword in node.keywords:
            if keyword.arg is None:
                continue
            if _normalise_name(keyword.arg) in {
                "complexity",
                "passwordcomplexity",
                "requirecomplexity",
            }:
                direct = _resolve_bool(keyword.value, assignments, max_depth) is False
    if direct:
        return True
    # Do not report a policy that disables only one optional character class.
    # A full set of known component switches set to false is explicit.
    false_keys: set[str] = set()
    if isinstance(node, ast.Call):
        for keyword in node.keywords:
            if (
                keyword.arg is not None
                and _normalise_name(keyword.arg) in _COMPLEXITY_COMPONENTS
                and _resolve_bool(keyword.value, assignments, max_depth) is False
            ):
                false_keys.add(_normalise_name(keyword.arg))
    else:
        # Dict keys are inspected by _dict_facts; a false value count alone is
        # insufficient because unrelated keys may be present.
        false_keys = set()
        if isinstance(node, ast.Dict):
            for key_node, value_node in zip(node.keys, node.values, strict=True):
                key = _literal_key(key_node)
                if key is None:
                    continue
                normalised = _normalise_name(key)
                boolean = _resolve_bool(value_node, assignments, max_depth)
                if normalised in {"complexity", "passwordcomplexity", "requirecomplexity"}:
                    if boolean is False:
                        return True
                elif normalised in _COMPLEXITY_COMPONENTS and boolean is False:
                    false_keys.add(normalised)
    return len(false_keys) >= 4 and not true_values


def _fact_from_nodes(
    source_node: ast.AST,
    sink_node: ast.AST,
    operation: PythonCwe521Operation,
    source: bytes,
    line_starts: tuple[int, ...],
) -> _WeakFact:
    source_range = _node_range(source_node, source, line_starts)
    sink_range = _node_range(sink_node, source, line_starts)
    if not sink_range.contains(source_range):
        raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.INTEGRITY_FAILURE)
    return _WeakFact(source_range, sink_range, operation)


def _collect_assignments(tree: ast.AST, max_depth: int) -> dict[str, tuple[ast.expr, ...]]:
    values: dict[str, list[ast.expr]] = {}
    for node in _bounded_nodes(tree, max_depth * 10_000):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                for name in _target_names(target):
                    values.setdefault(name, []).append(node.value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            for name in _target_names(node.target):
                values.setdefault(name, []).append(node.value)
    return {name: tuple(items[-4:]) for name, items in values.items()}


def _assignment_targets(node: ast.Assign | ast.AnnAssign) -> tuple[ast.expr, ...]:
    return tuple(node.targets) if isinstance(node, ast.Assign) else (node.target,)


def _target_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(name for element in node.elts for name in _target_names(element))
    if isinstance(node, ast.Attribute):
        return (node.attr,)
    return ()


def _parent_map(tree: ast.AST, max_depth: int) -> dict[int, ast.AST]:
    parents: dict[int, ast.AST] = {}
    stack: list[tuple[ast.AST, int]] = [(tree, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth * 10_000:
            raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.SIGNAL_LIMIT)
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
            stack.append((child, depth + 1))
    return parents


def _bounded_nodes(tree: ast.AST, limit: int) -> tuple[ast.AST, ...]:
    if type(limit) is not int or limit < 1:
        raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.REQUEST_INVALID)
    result: list[ast.AST] = []
    stack = [tree]
    while stack:
        node = stack.pop()
        result.append(node)
        if len(result) > limit:
            raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.SIGNAL_LIMIT)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(result)


def _call_has_password_context(node: ast.Call, parents: dict[int, ast.AST], max_depth: int) -> bool:
    current: ast.AST | None = node
    depth = 0
    while current is not None and depth <= max_depth:
        name = (
            _normalise_name(_dotted_name(current.func) or "")
            if isinstance(current, ast.Call)
            else ""
        )
        if name in _PASSWORD_POLICY_CALLS or _name_has_password_context((name,)):
            return True
        if isinstance(current, (ast.Assign, ast.AnnAssign)):
            names = tuple(
                name for target in _assignment_targets(current) for name in _target_names(target)
            )
            if _name_has_password_context(names) or _name_has_policy_context(names):
                return True
        current = parents.get(id(current))
        depth += 1
    return False


def _dict_has_password_context(node: ast.Dict, parents: dict[int, ast.AST], max_depth: int) -> bool:
    current: ast.AST | None = node
    depth = 0
    while current is not None and depth <= max_depth:
        if isinstance(current, ast.Call):
            name = _normalise_name(_dotted_name(current.func) or "")
            if name in _PASSWORD_POLICY_CALLS or _name_has_password_context((name,)):
                return True
        elif isinstance(current, (ast.Assign, ast.AnnAssign)):
            names = tuple(
                name for target in _assignment_targets(current) for name in _target_names(target)
            )
            if _name_has_password_context(names) or _name_has_policy_context(names):
                return True
        current = parents.get(id(current))
        depth += 1
    return False


def _name_has_password_context(names: tuple[str, ...]) -> bool:
    return any(
        token in _PASSWORD_WORDS or any(word in _normalise_name(name) for word in _PASSWORD_WORDS)
        for name in names
        for token in re.split(r"[^a-z0-9]+", name.lower())
        if token
    )


def _name_has_policy_context(names: tuple[str, ...]) -> bool:
    normalised = " ".join(names).lower().replace("_", " ")
    return "password" in normalised and any(word in normalised for word in _POLICY_WORDS)


def _length_operation(name: str, value: int) -> PythonCwe521Operation | None:
    if value >= _WEAK_LENGTH_THRESHOLD:
        return None
    if any(token in name for token in _MINIMUM_KEYS):
        return PythonCwe521Operation.MINIMUM_LENGTH
    if any(token in name for token in _MAXIMUM_KEYS):
        return PythonCwe521Operation.MAXIMUM_LENGTH
    return None


def _resolve_int(
    node: ast.expr,
    assignments: dict[str, tuple[ast.expr, ...]],
    max_depth: int,
    depth: int = 0,
) -> int | None:
    if depth > max_depth:
        raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.SIGNAL_LIMIT)
    if (
        isinstance(node, ast.Constant)
        and type(node.value) is int
        and not isinstance(node.value, bool)
    ):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _resolve_int(node.operand, assignments, max_depth, depth + 1)
        if value is None:
            return None
        return value if isinstance(node.op, ast.UAdd) else -value
    if isinstance(node, ast.Name):
        values = assignments.get(node.id, ())
        if len(values) != 1:
            return None
        return _resolve_int(values[0], assignments, max_depth, depth + 1)
    return None


def _resolve_bool(
    node: ast.expr,
    assignments: dict[str, tuple[ast.expr, ...]],
    max_depth: int,
    depth: int = 0,
) -> bool | None:
    if depth > max_depth:
        raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Constant) and type(node.value) is bool:
        return node.value
    if isinstance(node, ast.Name):
        values = assignments.get(node.id, ())
        if len(values) != 1:
            return None
        return _resolve_bool(values[0], assignments, max_depth, depth + 1)
    return None


def _dotted_name(node: ast.AST) -> str | None:
    parts: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _literal_key(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None


def _normalise_name(value: str) -> str:
    return "".join(character.lower() for character in value if character.isalnum())


def _suppressed_path(path: str) -> bool:
    normalised = path.replace("\\", "/").lower()
    parts = tuple(part for part in normalised.split("/") if part)
    stem = parts[-1] if parts else ""
    return (
        bool(set(parts) & _SUPPRESSED_PATH_PARTS)
        or stem.startswith("test_")
        or stem.endswith("_test.py")
    )


def _line_starts(source: bytes) -> tuple[int, ...]:
    starts = [0]
    starts.extend(index + 1 for index, value in enumerate(source) if value == 10)
    if starts[-1] != len(source):
        starts.append(len(source))
    return tuple(starts)


def _node_range(node: ast.AST, source: bytes, line_starts: tuple[int, ...]) -> SourceRange:
    try:
        start_line = node.lineno - 1  # type: ignore[attr-defined]
        end_line = node.end_lineno - 1  # type: ignore[attr-defined]
        start_column = node.col_offset  # type: ignore[attr-defined]
        end_column = node.end_col_offset  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe521ScanError(PythonCwe521ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start,
        end,
        SourcePoint(start_line, start_column),
        SourcePoint(end_line, end_column),
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
    operation: PythonCwe521Operation,
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
    signals: tuple[PythonCwe521Signal, ...],
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


Cwe521ScanErrorCode = PythonCwe521ScanErrorCode
Cwe521ScanError = PythonCwe521ScanError
Cwe521ScanLimits = PythonCwe521ScanLimits
Cwe521ScanResult = PythonCwe521ScanResult
Cwe521Signal = PythonCwe521Signal

scan_python_cwe521_password_requirements = scan_python_cwe521
scan_python_password_requirements = scan_python_cwe521


__all__ = [
    "DEFAULT_PYTHON_CWE521_SCAN_LIMITS",
    "Cwe521ScanError",
    "Cwe521ScanErrorCode",
    "Cwe521ScanLimits",
    "Cwe521ScanResult",
    "Cwe521Signal",
    "PythonCwe521Operation",
    "PythonCwe521ScanError",
    "PythonCwe521ScanErrorCode",
    "PythonCwe521ScanLimits",
    "PythonCwe521ScanResult",
    "PythonCwe521Signal",
    "scan_python_cwe521",
    "scan_python_cwe521_password_requirements",
    "scan_python_password_requirements",
]
