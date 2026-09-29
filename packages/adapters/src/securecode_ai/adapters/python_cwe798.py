"""Bounded Python CWE-798 hard-coded credential facts.

The adapter reports a credential-like name or authentication argument whose
value is a literal embedded in the admitted Python source.  It follows only
small, local aliases and never imports or executes repository code.  Values
obtained from environment/configuration providers, empty placeholders, and
ambiguous dynamic expressions are ignored.  Results contain immutable source
ranges and content-addressed identity only; source text and parser details do
not cross this boundary.
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
_RULE_ID = "securecode-python-cwe798"
_DETECTOR = "securecode-python-cwe798@1.0"
_DETAIL = "hardcoded_credential"

_CREDENTIAL_WORDS = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "passcode",
        "pwd",
        "credential",
        "credentials",
        "secret",
        "secrets",
        "token",
        "tokens",
        "apikey",
        "accesskey",
        "privatekey",
        "clientsecret",
        "authtoken",
        "bearertoken",
        "sessiontoken",
        "signingkey",
        "encryptionkey",
        "username",
        "login",
        "user",
        "pin",
    }
)
_COMPOUND_KEY_WORDS = frozenset(
    {
        "api_key",
        "access_key",
        "private_key",
        "client_key",
        "secret_key",
        "signing_key",
        "encryption_key",
        "auth_key",
        "consumer_key",
        "username_password",
        "user_password",
        "login_password",
        "client_secret",
        "auth_token",
        "access_token",
        "refresh_token",
        "session_token",
        "bearer_token",
    }
)
_AUTH_CALLS = frozenset(
    {
        "basicauth",
        "httpbasicauth",
        "credential",
        "credentials",
        "login",
        "authenticate",
        "usernamepassword",
        "username_password",
        "setcredentials",
        "setcredential",
        "configureauth",
        "configurecredentials",
    }
)
_SAFE_PROVIDER_CALLS = frozenset(
    {
        "getenv",
        "environget",
        "load_dotenv",
        "loadenv",
        "readsecret",
        "getsecret",
        "fetchsecret",
        "getcredential",
        "loadcredential",
        "gettoken",
        "loadtoken",
        "keyring.get_password",
        "keyring.get_credential",
        "vault.read",
        "secretsmanager.get_secret_value",
    }
)
_SUPPRESSED_PATH_PARTS = frozenset(
    {
        "test",
        "tests",
        "fixture",
        "fixtures",
        "example",
        "examples",
        "sample",
        "samples",
        "docs",
        "documentation",
    }
)


class PythonCwe798ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-798 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe798ScanError(RuntimeError):
    """Fixed scanner failure that never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe798ScanErrorCode) -> None:
        if type(code) is not PythonCwe798ScanErrorCode:
            raise TypeError("Python CWE-798 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-798 credential scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe798Operation(StrEnum):
    """Recognised hard-coded credential projections."""

    CREDENTIAL_LITERAL = "credential_literal"
    CREDENTIAL_ARGUMENT = "credential_argument"
    CREDENTIAL_DEFAULT = "credential_default"
    CREDENTIAL_MAPPING = "credential_mapping"
    CREDENTIAL_CONSTRUCTOR = "credential_constructor"

    # Compatibility names used by generic scanner consumers.
    HARDCODED_CREDENTIAL = "credential_literal"
    HARDCODED_ARGUMENT = "credential_argument"
    HARDCODED_DEFAULT = "credential_default"


@dataclass(frozen=True, slots=True)
class PythonCwe798ScanLimits:
    """Hard ceilings for source, output, and bounded local-flow resolution."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_resolution_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Python CWE-798 scan limits are invalid")


DEFAULT_PYTHON_CWE798_SCAN_LIMITS = PythonCwe798ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe798Signal:
    """One immutable hard-coded credential fact without source text."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe798Operation
    credential_name: str = "credential"
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
                self.credential_name,
            )
            if identity_valid and ranges_valid and type(self.operation) is PythonCwe798Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not PythonCwe798Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-798"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-798 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        return self.signal_id

    @property
    def variable_name(self) -> str:
        return self.credential_name

    @property
    def value_name(self) -> str:
        return self.credential_name

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
class PythonCwe798ScanResult:
    """Deterministic, source-free CWE-798 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe798Signal, ...]
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
            type(item) is PythonCwe798Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    item.sink.start_byte,
                    item.sink.end_byte,
                    item.source.start_byte,
                    item.source.end_byte,
                    item.operation.value,
                    item.credential_name,
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
            raise ValueError("Python CWE-798 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _CredentialFact:
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe798Operation
    credential_name: str


@dataclass(frozen=True, slots=True)
class _LiteralEvidence:
    node: ast.expr
    credential_name: str


def scan_python_cwe798(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe798ScanLimits = DEFAULT_PYTHON_CWE798_SCAN_LIMITS,
) -> PythonCwe798ScanResult:
    """Find hard-coded credentials in one admitted Python file.

    Only literal values under explicit credential names, credential mapping
    keys, recognised authentication calls, or credential-bearing defaults are
    reported.  Dynamic expressions and values from known providers are not
    evidence of a hard-coded credential and are ignored.
    """

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe798ScanLimits
    ):
        raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.SOURCE_LIMIT)
    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.ANALYSIS_UNAVAILABLE)

    if _suppressed_path(symbol_index.path):
        return _empty_result(symbol_index)

    source = symbol_index.source
    line_starts = _line_starts(source)
    try:
        parents = _parent_map(tree, limits.max_resolution_depth)
        assignments = _collect_assignments(tree, limits.max_resolution_depth)
        raw: set[tuple[SourceRange, SourceRange, PythonCwe798Operation, str]] = set()
        for node in _bounded_nodes(tree, max(1, limits.max_resolution_depth * 10_000)):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                raw.update(
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
                raw.update(
                    _call_facts(
                        node,
                        assignments,
                        parents,
                        source,
                        line_starts,
                        limits.max_resolution_depth,
                    )
                )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                raw.update(_default_facts(node, source, line_starts))
            if len(raw) > limits.max_signals:
                raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.SIGNAL_LIMIT)
        unique = tuple(
            sorted(
                raw,
                key=lambda item: (
                    item[1].start_byte,
                    item[1].end_byte,
                    item[0].start_byte,
                    item[0].end_byte,
                    item[2].value,
                    item[3],
                ),
            )
        )
    except PythonCwe798ScanError:
        raise
    except (MemoryError, RecursionError, TypeError, ValueError):
        raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.INTEGRITY_FAILURE) from None
    if len(unique) > limits.max_signals:
        raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe798Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=item[0],
            sink=item[1],
            operation=item[2],
            credential_name=item[3],
        )
        for item in unique
    )
    return PythonCwe798ScanResult(
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


def _empty_result(symbol_index: SymbolIndex) -> PythonCwe798ScanResult:
    return PythonCwe798ScanResult(
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
    node: ast.Assign | ast.AnnAssign | ast.AugAssign,
    assignments: dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]],
    parents: dict[int, ast.AST],
    source: bytes,
    line_starts: tuple[int, ...],
    max_depth: int,
) -> tuple[tuple[SourceRange, SourceRange, PythonCwe798Operation, str], ...]:
    value = node.value
    if value is None:
        return ()
    target_names = tuple(
        name for target in _assignment_targets(node) for name in _target_names(target)
    )
    direct_facts: list[_CredentialFact] = []
    for target in _assignment_targets(node):
        name = _target_credential_name(target)
        if name is not None:
            evidence = _resolve_literal(
                value,
                assignments,
                _position(node),
                max_depth,
            )
            if evidence is not None:
                direct_facts.append(
                    _fact_from_nodes(
                        evidence.node,
                        node,
                        PythonCwe798Operation.CREDENTIAL_LITERAL,
                        name,
                        source,
                        line_starts,
                    )
                )
    facts = direct_facts
    facts.extend(
        _mapping_facts(
            value,
            assignments,
            _position(node),
            max_depth,
            node,
            source,
            line_starts,
        )
    )
    if not facts and target_names and _name_has_auth_context(target_names):
        evidence = _resolve_literal(value, assignments, _position(node), max_depth)
        if evidence is not None:
            facts.append(
                _fact_from_nodes(
                    evidence.node,
                    node,
                    PythonCwe798Operation.CREDENTIAL_LITERAL,
                    _safe_name(target_names[0]),
                    source,
                    line_starts,
                )
            )
    return tuple(
        (
            item.source,
            item.sink,
            item.operation,
            item.credential_name,
        )
        for item in facts
    )


def _mapping_facts(
    value: ast.expr,
    assignments: dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]],
    position: tuple[int, int],
    max_depth: int,
    sink_node: ast.AST,
    source: bytes,
    line_starts: tuple[int, ...],
) -> tuple[_CredentialFact, ...]:
    facts: list[_CredentialFact] = []
    for item in _bounded_nodes(value, max(1, max_depth * 100)):
        if not isinstance(item, ast.Dict):
            continue
        for key_node, value_node in zip(item.keys, item.values, strict=False):
            key = _literal_string(key_node)
            if key is None or value_node is None:
                continue
            name = _credential_name(key)
            if name is None:
                continue
            evidence = _resolve_literal(value_node, assignments, position, max_depth)
            if evidence is None:
                continue
            facts.append(
                _fact_from_nodes(
                    evidence.node,
                    sink_node,
                    PythonCwe798Operation.CREDENTIAL_MAPPING,
                    name,
                    source,
                    line_starts,
                )
            )
    return tuple(facts)


def _call_facts(
    node: ast.Call,
    assignments: dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]],
    parents: dict[int, ast.AST],
    source: bytes,
    line_starts: tuple[int, ...],
    max_depth: int,
) -> tuple[tuple[SourceRange, SourceRange, PythonCwe798Operation, str], ...]:
    call_name = _normalise_name(_dotted_name(node.func))
    safe_call = _canonical_call_name(node.func) in _SAFE_PROVIDER_CALLS
    facts: list[_CredentialFact] = []
    for keyword in node.keywords:
        if keyword.arg is None or safe_call:
            continue
        name = _credential_name(keyword.arg)
        if name is None:
            continue
        evidence = _resolve_literal(keyword.value, assignments, _position(node), max_depth)
        if evidence is None:
            continue
        operation = (
            PythonCwe798Operation.CREDENTIAL_CONSTRUCTOR
            if call_name in {_normalise_name(item) for item in _AUTH_CALLS}
            else PythonCwe798Operation.CREDENTIAL_ARGUMENT
        )
        facts.append(
            _fact_from_nodes(
                evidence.node,
                node,
                operation,
                name,
                source,
                line_starts,
            )
        )
    if not safe_call and _is_auth_call(node):
        for argument in node.args[:2]:
            evidence = _resolve_literal(argument, assignments, _position(node), max_depth)
            if evidence is None:
                continue
            name = "username" if argument is node.args[0] else "password"
            facts.append(
                _fact_from_nodes(
                    evidence.node,
                    node,
                    PythonCwe798Operation.CREDENTIAL_CONSTRUCTOR,
                    name,
                    source,
                    line_starts,
                )
            )
    return tuple((item.source, item.sink, item.operation, item.credential_name) for item in facts)


def _default_facts(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    source: bytes,
    line_starts: tuple[int, ...],
) -> tuple[tuple[SourceRange, SourceRange, PythonCwe798Operation, str], ...]:
    positional = (*node.args.posonlyargs, *node.args.args)
    defaults = (*((None,) * (len(positional) - len(node.args.defaults))), *node.args.defaults)
    facts: list[_CredentialFact] = []
    for argument, default in zip(positional, defaults, strict=True):
        if default is None:
            continue
        name = _credential_name(argument.arg)
        if name is None or _literal_value(default) is None:
            continue
        facts.append(
            _fact_from_nodes(
                default,
                default,
                PythonCwe798Operation.CREDENTIAL_DEFAULT,
                name,
                source,
                line_starts,
            )
        )
    for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True):
        if default is None:
            continue
        name = _credential_name(argument.arg)
        if name is None or _literal_value(default) is None:
            continue
        facts.append(
            _fact_from_nodes(
                default,
                default,
                PythonCwe798Operation.CREDENTIAL_DEFAULT,
                name,
                source,
                line_starts,
            )
        )
    return tuple((item.source, item.sink, item.operation, item.credential_name) for item in facts)


def _resolve_literal(
    node: ast.expr,
    assignments: dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]],
    position: tuple[int, int],
    max_depth: int,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> _LiteralEvidence | None:
    if depth > max_depth:
        raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.SIGNAL_LIMIT)
    if _literal_value(node) is not None:
        return _LiteralEvidence(node, "credential")
    if isinstance(node, ast.Name) and node.id not in seen:
        previous = [item for item in assignments.get(node.id, ()) if item[0] <= position]
        if len(previous) == 1:
            return _resolve_literal(
                previous[0][1],
                assignments,
                position,
                max_depth,
                depth + 1,
                seen | {node.id},
            )
    return None


def _collect_assignments(
    tree: ast.AST,
    max_depth: int,
) -> dict[str, tuple[tuple[tuple[int, int], ast.expr], ...]]:
    values: dict[str, list[tuple[tuple[int, int], ast.expr]]] = {}
    for node in _bounded_nodes(tree, max(1, max_depth * 10_000)):
        if isinstance(node, ast.Assign):
            pairs = tuple((target, node.value) for target in node.targets)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            pairs = ((node.target, node.value),)
        else:
            continue
        for target, value in pairs:
            for name in _target_names(target):
                values.setdefault(name, []).append((_position(node), value))
    return {name: tuple(items[-4:]) for name, items in values.items()}


def _assignment_targets(
    node: ast.Assign | ast.AnnAssign | ast.AugAssign,
) -> tuple[ast.expr, ...]:
    if isinstance(node, ast.Assign):
        return tuple(node.targets)
    return (node.target,)


def _target_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(name for element in node.elts for name in _target_names(element))
    if isinstance(node, ast.Attribute):
        return (node.attr,)
    if isinstance(node, ast.Subscript):
        key = _literal_string(node.slice)
        return (key,) if key is not None else ()
    return ()


def _target_credential_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Subscript):
        return _credential_name(_literal_string(node.slice) or "")
    if isinstance(node, (ast.Name, ast.Attribute)):
        return _credential_name(node.id if isinstance(node, ast.Name) else node.attr)
    return None


def _fact_from_nodes(
    source_node: ast.AST,
    sink_node: ast.AST,
    operation: PythonCwe798Operation,
    name: str,
    source: bytes,
    line_starts: tuple[int, ...],
) -> _CredentialFact:
    source_range = _node_range(source_node, source, line_starts)
    sink_range = _node_range(sink_node, source, line_starts)
    if not sink_range.contains(source_range):
        sink_range = _span_range(source_range, sink_range, source, line_starts)
    return _CredentialFact(source_range, sink_range, operation, _safe_name(name))


def _parent_map(tree: ast.AST, max_depth: int) -> dict[int, ast.AST]:
    parents: dict[int, ast.AST] = {}
    stack: list[tuple[ast.AST, int]] = [(tree, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth * 10_000:
            raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.SIGNAL_LIMIT)
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
            stack.append((child, depth + 1))
    return parents


def _bounded_nodes(tree: ast.AST, limit: int) -> tuple[ast.AST, ...]:
    if type(limit) is not int or limit < 1:
        raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.REQUEST_INVALID)
    result: list[ast.AST] = []
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        result.append(node)
        if len(result) > limit:
            raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.SIGNAL_LIMIT)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(result)


def _credential_name(value: str) -> str | None:
    if not value:
        return None
    normalised = value.lower().replace("-", "_")
    compact = _normalise_name(normalised)
    words = set(re.findall(r"[a-z0-9]+", normalised))
    if normalised in _COMPOUND_KEY_WORDS:
        return _safe_name(normalised)
    if compact in _CREDENTIAL_WORDS:
        return _safe_name(normalised)
    if words & _CREDENTIAL_WORDS:
        return _safe_name(normalised)
    return None


def _name_has_auth_context(names: tuple[str, ...]) -> bool:
    return any(_credential_name(name) is not None for name in names)


def _is_auth_call(node: ast.Call) -> bool:
    compact = _normalise_name(_dotted_name(node.func))
    return compact in {_normalise_name(item) for item in _AUTH_CALLS}


def _canonical_call_name(node: ast.AST) -> str:
    dotted = _dotted_name(node)
    return dotted.lower()


def _dotted_name(node: ast.AST) -> str:
    parts: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _literal_value(node: ast.AST | None) -> str | bytes | int | float | None:
    if isinstance(node, ast.Constant):
        constant = node.value
        # Exact type check: bool (an int subclass) is intentionally excluded.
        if not isinstance(constant, (str, bytes, int, float)) or type(constant) not in {
            str,
            bytes,
            int,
            float,
        }:
            return None
        if isinstance(constant, str) and not constant.strip():
            return None
        if isinstance(constant, bytes) and not constant:
            return None
        return constant
    if isinstance(node, ast.JoinedStr):
        constants = [item for item in node.values if isinstance(item, ast.Constant)]
        if len(constants) == len(node.values):
            value = "".join(str(item.value) for item in constants)
            return value if value.strip() else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal_value(node.left)
        right = _literal_value(node.right)
        if type(left) is type(right):
            if isinstance(left, str) and isinstance(right, str):
                return left + right
            if isinstance(left, bytes) and isinstance(right, bytes):
                return left + right
            if isinstance(left, int) and isinstance(right, int):
                return left + right
            if isinstance(left, float) and isinstance(right, float):
                return left + right
    return None


def _literal_string(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None


def _normalise_name(value: str) -> str:
    return "".join(character.lower() for character in value if character.isalnum())


def _safe_name(value: str) -> str:
    normalised = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return normalised[:256] or "credential"


def _suppressed_path(path: str) -> bool:
    normalised = path.replace("\\", "/").lower()
    parts = tuple(part for part in normalised.split("/") if part)
    stem = parts[-1] if parts else ""
    return (
        bool(set(parts) & _SUPPRESSED_PATH_PARTS)
        or stem.startswith("test_")
        or stem.endswith("_test.py")
    )


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
        raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start, end, SourcePoint(start_line, start_column), SourcePoint(end_line, end_column)
    )


def _span_range(
    left: SourceRange,
    right: SourceRange,
    source: bytes,
    line_starts: tuple[int, ...],
) -> SourceRange:
    start = min(left.start_byte, right.start_byte)
    end = max(left.end_byte, right.end_byte)
    if start < 0 or end > len(source) or end < start:
        raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.INTEGRITY_FAILURE)
    if left.start_byte <= right.start_byte:
        start_point, end_point = left.start_point, right.end_point
    else:
        start_point, end_point = right.start_point, left.end_point
    if line_starts[start_point.row] > start or line_starts[end_point.row] > end:
        raise PythonCwe798ScanError(PythonCwe798ScanErrorCode.INTEGRITY_FAILURE)
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
    operation: PythonCwe798Operation,
    credential_name: str,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-798",
        "credential_name": credential_name,
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
    signals: tuple[PythonCwe798Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-798",
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
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


Cwe798ScanErrorCode = PythonCwe798ScanErrorCode
Cwe798ScanError = PythonCwe798ScanError
Cwe798ScanLimits = PythonCwe798ScanLimits
Cwe798ScanResult = PythonCwe798ScanResult
Cwe798Signal = PythonCwe798Signal

scan_python_cwe798_hardcoded_credentials = scan_python_cwe798
scan_python_hardcoded_credentials = scan_python_cwe798


__all__ = [
    "DEFAULT_PYTHON_CWE798_SCAN_LIMITS",
    "Cwe798ScanError",
    "Cwe798ScanErrorCode",
    "Cwe798ScanLimits",
    "Cwe798ScanResult",
    "Cwe798Signal",
    "PythonCwe798Operation",
    "PythonCwe798ScanError",
    "PythonCwe798ScanErrorCode",
    "PythonCwe798ScanLimits",
    "PythonCwe798ScanResult",
    "PythonCwe798Signal",
    "scan_python_cwe798",
    "scan_python_cwe798_hardcoded_credentials",
    "scan_python_hardcoded_credentials",
]
