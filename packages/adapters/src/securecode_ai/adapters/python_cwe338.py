"""Bounded Python facts for CWE-338 weak pseudo-random security values.

The scanner follows only explicit uses of the standard ``random`` module (and
local aliases) into names and APIs that conventionally carry tokens, session
identifiers, reset links, keys, or other security values.  It does not import
repository code or execute it.  ``secrets``, ``os.urandom``,
``SystemRandom``, and known cryptographic random APIs are treated as safe
sources.  Findings contain immutable source ranges and content-addressed
identity only.
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

_MAX_LIMITS = (2_000_000, 10_000, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-python-cwe338"
_DETECTOR = "securecode-python-cwe338@1.0"
_DETAIL = "weak_random_security_value"

_RANDOM_MODULES = frozenset({"random"})
_SAFE_MODULES = frozenset({"secrets", "os", "cryptography", "Crypto", "nacl"})
_WEAK_METHODS = frozenset(
    {
        "choice",
        "choices",
        "getrandbits",
        "randint",
        "randrange",
        "sample",
        "uniform",
    }
)
_SENSITIVE_WORDS = frozenset(
    {
        "access",
        "api",
        "auth",
        "authorization",
        "challenge",
        "cookie",
        "credential",
        "csrf",
        "encryption",
        "identifier",
        "key",
        "nonce",
        "password",
        "reset",
        "secret",
        "security",
        "session",
        "signing",
        "token",
        "verification",
        "verify",
        "xsrf",
    }
)
_SENSITIVE_CALL_WORDS = _SENSITIVE_WORDS | frozenset({"link", "login", "signin"})
_SAFE_CALL_TAILS = frozenset(
    {
        "choice",
        "randbelow",
        "randbits",
        "token_bytes",
        "token_hex",
        "token_urlsafe",
        "urandom",
    }
)


class PythonCwe338ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-338 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe338ScanError(RuntimeError):
    """Fixed scanner failure which never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe338ScanErrorCode) -> None:
        if type(code) is not PythonCwe338ScanErrorCode:
            raise TypeError("Python CWE-338 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-338 weak-randomness scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe338Operation(StrEnum):
    """Recognised weak pseudo-random operations."""

    RANDOM_RANDOM = "random.random"
    RANDOM_RANDINT = "random.randint"
    RANDOM_RANDRANGE = "random.randrange"
    RANDOM_CHOICE = "random.choice"
    RANDOM_CHOICES = "random.choices"
    RANDOM_SAMPLE = "random.sample"
    RANDOM_UNIFORM = "random.uniform"
    RANDOM_GETRANDBITS = "random.getrandbits"
    RANDOM_INSTANCE = "random.Random"
    RANDOM_INSTANCE_METHOD = "random.Random.method"

    # Compatibility names used by generic scanner consumers.
    RANDOM = "random.random"
    WEAK_RANDOM = "random.random"
    PSEUDO_RANDOM = "random.random"
    RANDOM_GENERATOR = "random.Random"
    GETRANDBITS = "random.getrandbits"


@dataclass(frozen=True, slots=True)
class PythonCwe338ScanLimits:
    """Hard ceilings for source, output, and bounded local resolution."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_resolution_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Python CWE-338 scan limits are invalid")


DEFAULT_PYTHON_CWE338_SCAN_LIMITS = PythonCwe338ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe338Signal:
    """One immutable weak-randomness fact without source text."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe338Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-338"
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
            if identity_valid
            and ranges_valid
            and type(self.operation) is PythonCwe338Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not PythonCwe338Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-338"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-338 signal is invalid")
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
class PythonCwe338ScanResult:
    """Deterministic, source-free CWE-338 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe338Signal, ...]
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
            type(signal) is PythonCwe338Signal for signal in self.signals
        )
        order = (
            tuple(
                (
                    signal.sink.start_byte,
                    signal.sink.end_byte,
                    signal.source.start_byte,
                    signal.source.end_byte,
                    signal.operation.value,
                )
                for signal in self.signals
            )
            if signals_valid
            else ()
        )
        same_identity = (
            all(
                signal.repository_id == self.repository_id
                and signal.revision == self.revision
                and signal.path == self.path
                and signal.content_sha256 == self.content_sha256
                and signal.source_size_bytes == self.source_size_bytes
                for signal in self.signals
            )
            if signals_valid
            else False
        )
        if (
            not identity_valid
            or not signals_valid
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
            or len({signal.signal_id for signal in self.signals}) != len(self.signals)
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
            raise ValueError("Python CWE-338 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _WeakEvidence:
    source: SourceRange
    operation: PythonCwe338Operation


def scan_python_cwe338(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe338ScanLimits = DEFAULT_PYTHON_CWE338_SCAN_LIMITS,
) -> PythonCwe338ScanResult:
    """Find weak PRNG output reaching a security-sensitive value."""

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe338ScanLimits
    ):
        raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.SOURCE_LIMIT)
    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    try:
        aliases = _collect_aliases(tree, limits.max_resolution_depth)
        assignments = _collect_assignments(tree, limits.max_resolution_depth)
        raw: set[tuple[SourceRange, SourceRange, PythonCwe338Operation]] = set()
        nodes = _bounded_nodes(tree, max(1, limits.max_resolution_depth * 10_000))
        for node in nodes:
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                value = node.value
                if value is not None:
                    evidence = _resolve_weak_values(
                        value,
                        aliases,
                        assignments,
                        _position(node),
                        limits.max_resolution_depth,
                        source,
                        line_starts,
                    )
                    for target in _assignment_targets(node):
                        if _sensitive_target(target, aliases, limits.max_resolution_depth):
                            _add_evidence(raw, evidence, node, source, line_starts)
                    _scan_sensitive_dicts(
                        value,
                        evidence,
                        aliases,
                        limits,
                        source,
                        line_starts,
                        raw,
                    )
            elif isinstance(node, ast.Call):
                if _sensitive_call(node, aliases, limits.max_resolution_depth):
                    evidence = _resolve_call_arguments(
                        node,
                        aliases,
                        assignments,
                        limits.max_resolution_depth,
                        source,
                        line_starts,
                    )
                    _add_evidence(raw, evidence, node, source, line_starts)
            if len(raw) > limits.max_signals:
                raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.SIGNAL_LIMIT)
        _scan_sensitive_returns(
            tree,
            aliases,
            assignments,
            limits,
            source,
            line_starts,
            raw,
        )
    except PythonCwe338ScanError:
        raise
    except (MemoryError, RecursionError, TypeError, ValueError):
        raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.INTEGRITY_FAILURE) from None

    unique = tuple(
        sorted(
            raw,
            key=lambda item: (
                item[1].start_byte,
                item[1].end_byte,
                item[0].start_byte,
                item[0].end_byte,
                item[2].value,
            ),
        )
    )
    if len(unique) > limits.max_signals:
        raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe338Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
        )
        for source_range, sink_range, operation in unique
    )
    return PythonCwe338ScanResult(
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


def _collect_aliases(tree: ast.AST, max_depth: int) -> dict[str, str | None]:
    aliases: dict[str, str | None] = {}
    for node in _bounded_nodes(tree, max(1, max_depth * 10_000)):
        if isinstance(node, ast.Import):
            for item in node.names:
                root = item.name.split(".", 1)[0]
                aliases[item.asname or root] = item.name if root in _SAFE_MODULES | _RANDOM_MODULES else None
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            root = module.split(".", 1)[0]
            for item in node.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = (
                        f"{module}.{item.name}" if root in _SAFE_MODULES | _RANDOM_MODULES else None
                    )
    return aliases


def _collect_assignments(
    tree: ast.AST,
    max_depth: int,
) -> dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]]:
    values: dict[str, list[tuple[tuple[int, int], ast.expr]]] = {}
    for node in _bounded_nodes(tree, max(1, max_depth * 10_000)):
        if isinstance(node, ast.Assign):
            pairs = ((target, node.value) for target in node.targets)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            pairs = ((node.target, node.value),)
        else:
            continue
        for target, value in pairs:
            if isinstance(target, ast.Name):
                values.setdefault(target.id, []).append((_position(node), value))
    return {key: tuple(sorted(items)) for key, items in values.items()}


def _resolve_weak_values(
    node: ast.AST,
    aliases: dict[str, str | None],
    assignments: dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]],
    position: tuple[int, int],
    max_depth: int,
    source: bytes,
    line_starts: tuple[int, ...],
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> tuple[_WeakEvidence, ...]:
    if depth > max_depth:
        raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.SIGNAL_LIMIT)
    direct = _weak_source(
        node,
        aliases,
        assignments,
        position,
        max_depth,
        source,
        line_starts,
    )
    if direct is not None:
        return (direct,)
    if isinstance(node, ast.Name) and node.id not in seen:
        previous = [item for item in assignments.get(node.id, ()) if item[0] <= position]
        if previous:
            return _resolve_weak_values(
                previous[-1][1],
                aliases,
                assignments,
                position,
                max_depth,
                source,
                line_starts,
                depth + 1,
                seen | {node.id},
            )
        return ()
    if isinstance(node, ast.Call):
        children = (*node.args, *(keyword.value for keyword in node.keywords))
    elif isinstance(node, ast.NamedExpr):
        children = (node.value,)
    else:
        children = tuple(ast.iter_child_nodes(node))
    output: list[_WeakEvidence] = []
    for child in children:
        output.extend(
            _resolve_weak_values(
                child,
                aliases,
                assignments,
                position,
                max_depth,
                source,
                line_starts,
                depth + 1,
                seen,
            )
        )
    return _unique_evidence(output)


def _weak_source(
    node: ast.AST,
    aliases: dict[str, str | None],
    assignments: dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]],
    position: tuple[int, int],
    max_depth: int,
    source: bytes,
    line_starts: tuple[int, ...],
) -> _WeakEvidence | None:
    if not isinstance(node, ast.Call):
        return None
    canonical = _canonical_reference(node.func, aliases, max_depth) or ""
    operation = _weak_operation(canonical)
    if operation is not None:
        return _WeakEvidence(_node_range(node, source, line_starts), operation)
    if isinstance(node.func, ast.Attribute):
        receiver = node.func.value
        method = node.func.attr
        if isinstance(receiver, ast.Call):
            receiver_name = _canonical_reference(receiver.func, aliases, max_depth) or ""
            if receiver_name == "random.Random" and method in _WEAK_METHODS:
                return _WeakEvidence(
                    _node_range(node, source, line_starts),
                    PythonCwe338Operation.RANDOM_INSTANCE_METHOD,
                )
            if receiver_name == "random.SystemRandom":
                return None
        if method in _WEAK_METHODS and _is_weak_instance(
            receiver, aliases, assignments, position, max_depth
        ):
            return _WeakEvidence(
                _node_range(node, source, line_starts),
                PythonCwe338Operation.RANDOM_INSTANCE_METHOD,
            )
    return None


def _weak_operation(canonical: str) -> PythonCwe338Operation | None:
    if canonical == "random.random":
        return PythonCwe338Operation.RANDOM_RANDOM
    if canonical == "random.randint":
        return PythonCwe338Operation.RANDOM_RANDINT
    if canonical == "random.randrange":
        return PythonCwe338Operation.RANDOM_RANDRANGE
    if canonical == "random.choice":
        return PythonCwe338Operation.RANDOM_CHOICE
    if canonical == "random.choices":
        return PythonCwe338Operation.RANDOM_CHOICES
    if canonical == "random.sample":
        return PythonCwe338Operation.RANDOM_SAMPLE
    if canonical == "random.uniform":
        return PythonCwe338Operation.RANDOM_UNIFORM
    if canonical == "random.getrandbits":
        return PythonCwe338Operation.RANDOM_GETRANDBITS
    if canonical == "random.Random":
        return PythonCwe338Operation.RANDOM_INSTANCE
    return None


def _is_weak_instance(
    node: ast.AST,
    aliases: dict[str, str | None],
    assignments: dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]],
    position: tuple[int, int],
    max_depth: int,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> bool:
    if depth > max_depth:
        raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.SIGNAL_LIMIT)
    canonical = _canonical_reference(node, aliases, max_depth)
    if canonical == "random.Random":
        return True
    if canonical == "random.SystemRandom":
        return False
    if isinstance(node, ast.Name) and node.id not in seen:
        previous = [item for item in assignments.get(node.id, ()) if item[0] <= position]
        if previous:
            value = previous[-1][1]
            if isinstance(value, ast.Call):
                return _is_weak_instance(value, aliases, assignments, position, max_depth, depth + 1, seen | {node.id})
    return False


def _assignment_targets(node: ast.Assign | ast.AnnAssign | ast.AugAssign) -> tuple[ast.expr, ...]:
    if isinstance(node, ast.Assign):
        return tuple(node.targets)
    return (node.target,)


def _sensitive_target(
    node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
) -> bool:
    if isinstance(node, ast.Name):
        return _sensitive_text(node.id)
    if isinstance(node, ast.Attribute):
        return _sensitive_text(node.attr) or _sensitive_text(
            _dotted_name(node.value, aliases, max_depth)
        )
    if isinstance(node, ast.Subscript):
        key = _literal_string(node.slice)
        return key is not None and _sensitive_text(key)
    return False


def _sensitive_call(node: ast.Call, aliases: dict[str, str | None], max_depth: int) -> bool:
    name = _canonical_reference(node.func, aliases, max_depth) or _dotted_name(node.func, aliases, max_depth)
    compact = _words(name)
    tail = name.rsplit(".", 1)[-1].lower()
    if tail in _SAFE_CALL_TAILS or name.startswith(("secrets.", "os.urandom", "cryptography.", "Crypto.Random.", "nacl.")):
        return False
    return bool(compact & _SENSITIVE_CALL_WORDS) or tail in {
        "set_cookie",
        "set_header",
        "setdefault",
        "update",
    } and any(_sensitive_text(_literal_string(argument) or "") for argument in node.args)


def _resolve_call_arguments(
    node: ast.Call,
    aliases: dict[str, str | None],
    assignments: dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]],
    max_depth: int,
    source: bytes,
    line_starts: tuple[int, ...],
) -> tuple[_WeakEvidence, ...]:
    evidence: list[_WeakEvidence] = []
    for argument in (*node.args, *(keyword.value for keyword in node.keywords)):
        evidence.extend(
            _resolve_weak_values(
                argument,
                aliases,
                assignments,
                _position(node),
                max_depth,
                source,
                line_starts,
            )
        )
    return _unique_evidence(evidence)


def _scan_sensitive_dicts(
    value: ast.expr,
    outer_evidence: tuple[_WeakEvidence, ...],
    aliases: dict[str, str | None],
    limits: PythonCwe338ScanLimits,
    source: bytes,
    line_starts: tuple[int, ...],
    output: set[tuple[SourceRange, SourceRange, PythonCwe338Operation]],
) -> None:
    for node in _bounded_nodes(value, max(1, limits.max_resolution_depth * 100)):
        if not isinstance(node, ast.Dict):
            continue
        for key, item in zip(node.keys, node.values, strict=False):
            literal = _literal_string(key)
            if item is None or literal is None or not _sensitive_text(literal):
                continue
            evidence = outer_evidence or ()
            if not evidence:
                continue
            _add_evidence(output, evidence, node, source, line_starts)


def _scan_sensitive_returns(
    tree: ast.Module,
    aliases: dict[str, str | None],
    assignments: dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]],
    limits: PythonCwe338ScanLimits,
    source: bytes,
    line_starts: tuple[int, ...],
    output: set[tuple[SourceRange, SourceRange, PythonCwe338Operation]],
) -> None:
    for function in _bounded_nodes(tree, max(1, limits.max_resolution_depth * 10_000)):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _sensitive_text(function.name):
            continue
        for node in _bounded_nodes(function, max(1, limits.max_resolution_depth * 100)):
            if not isinstance(node, ast.Return) or node.value is None:
                continue
            evidence = _resolve_weak_values(
                node.value,
                aliases,
                assignments,
                _position(node),
                limits.max_resolution_depth,
                source,
                line_starts,
            )
            _add_evidence(output, evidence, node, source, line_starts)


def _add_evidence(
    output: set[tuple[SourceRange, SourceRange, PythonCwe338Operation]],
    evidence: tuple[_WeakEvidence, ...],
    sink_node: ast.AST,
    source: bytes,
    line_starts: tuple[int, ...],
) -> None:
    sink = _node_range(sink_node, source, line_starts)
    for item in evidence:
        source_range = item.source
        if not sink.contains(source_range):
            sink = _span_range(source_range, sink, source, line_starts)
        output.add((source_range, sink, item.operation))


def _unique_evidence(values: list[_WeakEvidence]) -> tuple[_WeakEvidence, ...]:
    return tuple(
        sorted(
            set(values),
            key=lambda item: (item.source.start_byte, item.source.end_byte, item.operation.value),
        )
    )


def _canonical_reference(node: ast.AST, aliases: dict[str, str | None], max_depth: int, depth: int = 0) -> str | None:
    if depth > max_depth:
        raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    return None


def _dotted_name(node: ast.AST, aliases: dict[str, str | None], max_depth: int) -> str:
    return _canonical_reference(node, aliases, max_depth) or ""


def _sensitive_text(value: str) -> bool:
    words = _words(value)
    return bool(words & _SENSITIVE_WORDS) or any(
        value.lower().replace("-", "_").endswith(f"_{suffix}")
        for suffix in ("token", "nonce", "session_id", "reset_link", "api_key", "secret_key")
    )


def _words(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", value.lower()))


def _literal_string(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None


def _bounded_nodes(tree: ast.AST, limit: int) -> tuple[ast.AST, ...]:
    if type(limit) is not int or limit < 1:
        raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.REQUEST_INVALID)
    result: list[ast.AST] = []
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        result.append(node)
        if len(result) > limit:
            raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.SIGNAL_LIMIT)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(result)


def _position(node: ast.AST) -> tuple[int, int]:
    return getattr(node, "lineno", 0), getattr(node, "col_offset", 0)


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
        raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if start < line_starts[start_line] or end > line_starts[end_line + 1] or end < start or end > len(source):
        raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(start, end, SourcePoint(start_line, start_column), SourcePoint(end_line, end_column))


def _span_range(
    left: SourceRange,
    right: SourceRange,
    source: bytes,
    line_starts: tuple[int, ...],
) -> SourceRange:
    start = min(left.start_byte, right.start_byte)
    end = max(left.end_byte, right.end_byte)
    if start < 0 or end > len(source) or end < start:
        raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.INTEGRITY_FAILURE)
    if left.start_byte <= right.start_byte:
        start_point, end_point = left.start_point, right.end_point
    else:
        start_point, end_point = right.start_point, left.end_point
    if line_starts[start_point.row] > start or line_starts[end_point.row] > end:
        raise PythonCwe338ScanError(PythonCwe338ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(start, end, start_point, end_point)


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
    operation: PythonCwe338Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
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
    signals: tuple[PythonCwe338Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-338",
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "detail": signal.detail,
                "operation": signal.operation.value,
                "rule_id": signal.rule_id,
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


# These aliases keep this adapter compatible with generic CWE scanner imports.
Cwe338ScanErrorCode = PythonCwe338ScanErrorCode
Cwe338ScanError = PythonCwe338ScanError
Cwe338ScanLimits = PythonCwe338ScanLimits
Cwe338ScanResult = PythonCwe338ScanResult
Cwe338Signal = PythonCwe338Signal


__all__ = [
    "DEFAULT_PYTHON_CWE338_SCAN_LIMITS",
    "Cwe338ScanError",
    "Cwe338ScanErrorCode",
    "Cwe338ScanLimits",
    "Cwe338ScanResult",
    "Cwe338Signal",
    "PythonCwe338Operation",
    "PythonCwe338ScanError",
    "PythonCwe338ScanErrorCode",
    "PythonCwe338ScanLimits",
    "PythonCwe338ScanResult",
    "PythonCwe338Signal",
    "scan_python_cwe338",
]
