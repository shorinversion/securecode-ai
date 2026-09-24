"""Bounded Python weak-cryptography facts for CWE-327.

The scanner recognises a small, explicit set of standard and commonly used
Python cryptography APIs.  It resolves only imports and local aliases, accepts
only literal algorithm names, and emits content-addressed source ranges.  It
never imports repository code and never puts source text in a finding or an
exception.
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
_RULE_ID = "securecode-python-cwe327"
_DETECTOR = "securecode-python-cwe327@1.0"
_DETAIL = "weak_cryptographic_algorithm"

_WEAK_NAMES = frozenset({"md5", "md4", "sha", "sha1", "sha-1"})
_SUPPRESSED_PATH_PARTS = frozenset(
    {"test", "tests", "fixture", "fixtures", "doc", "docs", "example", "examples"}
)
_HASHLIB_NAMES = frozenset(
    {
        "hashlib.md5",
        "hashlib.md4",
        "hashlib.sha1",
        "hashlib.sha",
        "hashlib.sha_1",
    }
)
_CRYPTOGRAPHY_NAMES = frozenset(
    {
        "cryptography.hazmat.primitives.hashes.MD5",
        "cryptography.hazmat.primitives.hashes.SHA1",
    }
)
_CRYPTO_HASH_NAMES = frozenset({"Crypto.Hash.MD5.new", "Crypto.Hash.SHA1.new"})


class PythonCwe327ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-327 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe327ScanError(RuntimeError):
    """Fixed scanner failure which never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe327ScanErrorCode) -> None:
        if type(code) is not PythonCwe327ScanErrorCode:
            raise TypeError("Python CWE-327 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-327 cryptography scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe327Operation(StrEnum):
    """Recognised weak cryptography operations."""

    HASHLIB_MD5 = "hashlib.md5"
    HASHLIB_SHA1 = "hashlib.sha1"
    HASHLIB_NEW_MD5 = "hashlib.new.md5"
    HASHLIB_NEW_SHA1 = "hashlib.new.sha1"
    HASHLIB_PBKDF2_MD5 = "hashlib.pbkdf2_hmac.md5"
    HASHLIB_PBKDF2_SHA1 = "hashlib.pbkdf2_hmac.sha1"
    CRYPTOGRAPHY_MD5 = "cryptography.hashes.MD5"
    CRYPTOGRAPHY_SHA1 = "cryptography.hashes.SHA1"
    CRYPTO_HASH_MD5 = "Crypto.Hash.MD5.new"
    CRYPTO_HASH_SHA1 = "Crypto.Hash.SHA1.new"
    HMAC_MD5 = "hmac.new.md5"
    HMAC_SHA1 = "hmac.new.sha1"

    # Compatibility names used by generic scanner consumers.
    MD5 = "hashlib.md5"
    SHA1 = "hashlib.sha1"
    HASHLIB_NEW = "hashlib.new.md5"
    PBKDF2_HMAC = "hashlib.pbkdf2_hmac.md5"
    HMAC = "hmac.new.md5"


@dataclass(frozen=True, slots=True)
class PythonCwe327ScanLimits:
    """Hard ceilings for source, output, and bounded alias resolution."""

    max_source_bytes: int = _MAX_LIMIT_VALUES[0]
    max_signals: int = _MAX_LIMIT_VALUES[1]
    max_resolution_depth: int = _MAX_LIMIT_VALUES[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("Python CWE-327 scan limits are invalid")


DEFAULT_PYTHON_CWE327_SCAN_LIMITS = PythonCwe327ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe327Signal:
    """One immutable weak-cryptography fact without source text."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe327Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-327"
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
            if valid_identity
            and valid_ranges
            and type(self.operation) is PythonCwe327Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not PythonCwe327Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-327"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Python CWE-327 signal is invalid")
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
class PythonCwe327ScanResult:
    """Deterministic, source-free CWE-327 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe327Signal, ...]
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
            type(item) is PythonCwe327Signal for item in self.signals
        )
        order = (
            tuple(
                (item.sink.start_byte, item.sink.end_byte, item.source.start_byte, item.operation.value)
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
            raise ValueError("Python CWE-327 scan result is invalid")


def scan_python_cwe327(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe327ScanLimits = DEFAULT_PYTHON_CWE327_SCAN_LIMITS,
) -> PythonCwe327ScanResult:
    """Find explicit uses of weak Python cryptographic algorithms.

    Unknown aliases, dynamic algorithm names, and source paths belonging to
    tests, fixtures, documentation, or examples are ignored.  A mismatched
    AST analysis fails closed with a typed, source-free error.
    """

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe327ScanLimits
    ):
        raise PythonCwe327ScanError(PythonCwe327ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe327ScanError(PythonCwe327ScanErrorCode.SOURCE_LIMIT)
    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe327ScanError(PythonCwe327ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe327ScanError(PythonCwe327ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe327ScanError(PythonCwe327ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    raw: list[tuple[SourceRange, SourceRange, PythonCwe327Operation]] = []
    if not _suppressed_path(symbol_index.path):
        _scan_statements(tree.body, {}, source, line_starts, limits, raw)
    unique = sorted(
        set(raw),
        key=lambda item: (
            item[1].start_byte,
            item[1].end_byte,
            item[0].start_byte,
            item[0].end_byte,
            item[2].value,
        ),
    )
    if len(unique) > limits.max_signals:
        raise PythonCwe327ScanError(PythonCwe327ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe327Signal(
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
    return PythonCwe327ScanResult(
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


def _scan_statements(
    statements: list[ast.stmt],
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe327ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe327Operation]],
) -> None:
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            child = dict(aliases)
            for parameter in (
                *statement.args.posonlyargs,
                *statement.args.args,
                *statement.args.kwonlyargs,
            ):
                child[parameter.arg] = None
            if statement.args.vararg is not None:
                child[statement.args.vararg.arg] = None
            if statement.args.kwarg is not None:
                child[statement.args.kwarg.arg] = None
            _scan_statements(statement.body, child, source, line_starts, limits, output)
            aliases[statement.name] = None
            continue
        if isinstance(statement, ast.ClassDef):
            _scan_statements(statement.body, dict(aliases), source, line_starts, limits, output)
            aliases[statement.name] = None
            continue
        if isinstance(statement, ast.Import):
            _record_imports(statement, aliases)
        elif isinstance(statement, ast.ImportFrom):
            _record_import_from(statement, aliases)
        for node in _statement_nodes(statement):
            if isinstance(node, ast.Call):
                _record_call(node, aliases, source, line_starts, limits, output)
        _record_assignment_aliases(statement, aliases, limits.max_resolution_depth)
        if isinstance(statement, ast.If):
            left = dict(aliases)
            right = dict(aliases)
            _scan_statements(statement.body, left, source, line_starts, limits, output)
            _scan_statements(statement.orelse, right, source, line_starts, limits, output)
            _merge_aliases(aliases, left, right)
        else:
            for body in _nested_statement_lists(statement):
                _scan_statements(body, dict(aliases), source, line_starts, limits, output)


def _record_call(
    call: ast.Call,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe327ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe327Operation]],
) -> None:
    operation, source_node = _operation_for_call(call, aliases, limits.max_resolution_depth)
    if operation is None or source_node is None:
        return
    if operation in {
        PythonCwe327Operation.HASHLIB_MD5,
        PythonCwe327Operation.HASHLIB_SHA1,
    } and _false_usedforsecurity(call):
        return
    sink = _node_range(call, source, line_starts)
    source_range = _node_range(source_node, source, line_starts)
    if not sink.contains(source_range):
        raise PythonCwe327ScanError(PythonCwe327ScanErrorCode.INTEGRITY_FAILURE)
    output.append((source_range, sink, operation))
    if len(output) > limits.max_signals:
        raise PythonCwe327ScanError(PythonCwe327ScanErrorCode.SIGNAL_LIMIT)


def _operation_for_call(
    call: ast.Call,
    aliases: dict[str, str | None],
    max_depth: int,
) -> tuple[PythonCwe327Operation | None, ast.expr | None]:
    canonical = _canonical_reference(call.func, aliases, max_depth)
    if canonical in _HASHLIB_NAMES:
        operation = (
            PythonCwe327Operation.HASHLIB_MD5
            if canonical.endswith("md5") or canonical.endswith("md4")
            else PythonCwe327Operation.HASHLIB_SHA1
        )
        return operation, call.func
    if canonical in _CRYPTOGRAPHY_NAMES:
        operation = (
            PythonCwe327Operation.CRYPTOGRAPHY_MD5
            if canonical.endswith("MD5")
            else PythonCwe327Operation.CRYPTOGRAPHY_SHA1
        )
        return operation, call.func
    if canonical in _CRYPTO_HASH_NAMES:
        operation = (
            PythonCwe327Operation.CRYPTO_HASH_MD5
            if canonical.endswith("MD5.new")
            else PythonCwe327Operation.CRYPTO_HASH_SHA1
        )
        return operation, call.func
    if canonical in {"hashlib.new", "hashlib.pbkdf2_hmac"}:
        algorithm = _algorithm_argument(call)
        weak = _literal_weak(algorithm)
        if weak is None:
            return None, None
        if canonical == "hashlib.new":
            operation = (
                PythonCwe327Operation.HASHLIB_NEW_MD5
                if weak == "md5"
                else PythonCwe327Operation.HASHLIB_NEW_SHA1
            )
        else:
            operation = (
                PythonCwe327Operation.HASHLIB_PBKDF2_MD5
                if weak == "md5"
                else PythonCwe327Operation.HASHLIB_PBKDF2_SHA1
            )
        return operation, algorithm
    if canonical == "hmac.new":
        digest = _digest_argument(call)
        weak = _weak_digest_reference(digest, aliases, max_depth)
        if weak is None:
            return None, None
        operation = (
            PythonCwe327Operation.HMAC_MD5 if weak == "md5" else PythonCwe327Operation.HMAC_SHA1
        )
        return operation, digest
    return None, None


def _algorithm_argument(call: ast.Call) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg in {"name", "hash_name", "digestmod"}:
            return keyword.value
    return call.args[0] if call.args else None


def _digest_argument(call: ast.Call) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == "digestmod":
            return keyword.value
    return call.args[2] if len(call.args) >= 3 else None


def _weak_digest_reference(
    node: ast.expr | None,
    aliases: dict[str, str | None],
    max_depth: int,
) -> str | None:
    if node is None:
        return None
    literal = _literal_weak(node)
    if literal is not None:
        return literal
    canonical = _canonical_reference(node, aliases, max_depth)
    if canonical in _HASHLIB_NAMES:
        return "md5" if canonical.endswith("md5") or canonical.endswith("md4") else "sha1"
    if canonical in _CRYPTOGRAPHY_NAMES:
        return "md5" if canonical.endswith("MD5") else "sha1"
    return None


def _literal_weak(node: ast.expr | None) -> str | None:
    if not isinstance(node, ast.Constant) or type(node.value) is not str:
        return None
    compact = node.value.lower().replace("-", "").replace("_", "")
    if compact in {"md5", "md4"}:
        return "md5"
    if compact in {"sha", "sha1"}:
        return "sha1"
    return None


def _false_usedforsecurity(call: ast.Call) -> bool:
    return any(
        keyword.arg == "usedforsecurity"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is False
        for keyword in call.keywords
    )


def _record_imports(statement: ast.Import, aliases: dict[str, str | None]) -> None:
    supported_roots = {"hashlib", "hmac", "cryptography", "Crypto"}
    for imported in statement.names:
        root = imported.name.split(".", 1)[0]
        aliases[imported.asname or root] = imported.name if root in supported_roots else None


def _record_import_from(statement: ast.ImportFrom, aliases: dict[str, str | None]) -> None:
    module = statement.module or ""
    if statement.level:
        for imported in statement.names:
            aliases[imported.asname or imported.name] = None
        return
    supported = {
        "hashlib",
        "hmac",
        "cryptography.hazmat.primitives.hashes",
        "Crypto.Hash",
    }
    for imported in statement.names:
        name = imported.asname or imported.name
        if imported.name == "*":
            continue
        aliases[name] = f"{module}.{imported.name}" if module in supported else None


def _record_assignment_aliases(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    max_depth: int,
) -> None:
    values: list[tuple[ast.expr, ast.expr]] = []
    if isinstance(statement, ast.Assign):
        values.extend((target, statement.value) for target in statement.targets)
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        values.append((statement.target, statement.value))
    for target, value in values:
        if isinstance(target, ast.Name):
            aliases[target.id] = _canonical_reference(value, aliases, max_depth)


def _canonical_reference(
    node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe327ScanError(PythonCwe327ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        return aliases.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    return None


def _statement_nodes(statement: ast.stmt) -> tuple[ast.AST, ...]:
    output: list[ast.AST] = []
    stack: list[ast.AST] = [statement]
    while stack:
        node = stack.pop()
        if node is not statement and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            continue
        output.append(node)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(output)


def _nested_statement_lists(statement: ast.stmt) -> tuple[list[ast.stmt], ...]:
    if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
        return statement.body, statement.orelse
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        return (statement.body,)
    if isinstance(statement, ast.Try):
        return (
            statement.body,
            statement.orelse,
            statement.finalbody,
            *(handler.body for handler in statement.handlers),
        )
    return ()


def _merge_aliases(
    target: dict[str, str | None], left: dict[str, str | None], right: dict[str, str | None]
) -> None:
    target.clear()
    for name in left.keys() | right.keys():
        left_value = left.get(name)
        right_value = right.get(name)
        target[name] = left_value if left_value == right_value else None


def _literal_string(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None


def _suppressed_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    parts = tuple(part for part in normalized.split("/") if part)
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
        raise PythonCwe327ScanError(PythonCwe327ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe327ScanError(PythonCwe327ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if start < line_starts[start_line] or end > line_starts[end_line + 1] or end < start or end > len(source):
        raise PythonCwe327ScanError(PythonCwe327ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(
        start,
        end,
        SourcePoint(start_line, start_column),
        SourcePoint(end_line, end_column),
    )


def _signal_id(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    source: SourceRange,
    sink: SourceRange,
    operation: PythonCwe327Operation,
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
    signals: tuple[PythonCwe327Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "detector": signal.detector,
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


def _range_value(location: SourceRange) -> dict[str, int]:
    return {
        "end_byte": location.end_byte,
        "end_column": location.end_point.column,
        "end_row": location.end_point.row,
        "start_byte": location.start_byte,
        "start_column": location.start_point.column,
        "start_row": location.start_point.row,
    }


Cwe327ScanErrorCode = PythonCwe327ScanErrorCode
Cwe327ScanError = PythonCwe327ScanError
Cwe327ScanLimits = PythonCwe327ScanLimits
Cwe327Signal = PythonCwe327Signal
Cwe327ScanResult = PythonCwe327ScanResult


__all__ = [
    "DEFAULT_PYTHON_CWE327_SCAN_LIMITS",
    "Cwe327ScanError",
    "Cwe327ScanErrorCode",
    "Cwe327ScanLimits",
    "Cwe327Signal",
    "Cwe327ScanResult",
    "PythonCwe327Operation",
    "PythonCwe327ScanError",
    "PythonCwe327ScanErrorCode",
    "PythonCwe327ScanLimits",
    "PythonCwe327Signal",
    "PythonCwe327ScanResult",
    "scan_python_cwe327",
]
