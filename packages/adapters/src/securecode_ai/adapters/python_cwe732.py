"""Bounded Python CWE-732 improper-permission facts.

This adapter works only on an admitted :class:`SymbolIndex` and its matching
sealed CPython AST analysis.  It recognises a small set of file and directory
creation APIs, resolves local aliases and integer permission expressions, and
returns immutable source-free facts.  Temporary-file helpers are deliberately
treated as safe because their standard library contract creates private
objects.  No repository source is retained in a result or error.
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
_RULE_ID = "securecode-python-cwe732"
_DETECTOR = "securecode-python-cwe732@1.0"


class PythonCwe732ScanErrorCode(StrEnum):
    """Closed reasons a CWE-732 scan cannot produce a result."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe732ScanError(RuntimeError):
    """Fixed, source-free Python CWE-732 scanner failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe732ScanErrorCode) -> None:
        if type(code) is not PythonCwe732ScanErrorCode:
            raise TypeError("Python CWE-732 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-732 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe732Operation(StrEnum):
    """Recognised file and directory permission operations."""

    OS_OPEN = "os.open"
    OS_CHMOD = "os.chmod"
    OS_FCHMOD = "os.fchmod"
    OS_MKDIR = "os.mkdir"
    OS_MAKEDIRS = "os.makedirs"
    PATH_CHMOD = "pathlib.Path.chmod"
    PATH_MKDIR = "pathlib.Path.mkdir"
    PATH_OPEN = "pathlib.Path.open"
    PATH_WRITE_TEXT = "pathlib.Path.write_text"
    PATH_WRITE_BYTES = "pathlib.Path.write_bytes"
    PATH_TOUCH = "pathlib.Path.touch"
    BUILTIN_OPEN = "builtins.open"

    # Compatibility aliases used by generic scanner callers.
    OPEN = "os.open"
    CHMOD = "os.chmod"
    MKDIR = "os.mkdir"
    MAKEDIRS = "os.makedirs"


@dataclass(frozen=True, slots=True)
class PythonCwe732ScanLimits:
    """Hard ceilings for source, output, and alias resolution."""

    max_source_bytes: int = _MAX_LIMIT_VALUES[0]
    max_signals: int = _MAX_LIMIT_VALUES[1]
    max_resolution_depth: int = _MAX_LIMIT_VALUES[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("Python CWE-732 scan limits are invalid")


DEFAULT_PYTHON_CWE732_SCAN_LIMITS = PythonCwe732ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe732Signal:
    """One immutable source-to-improper-permission fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe732Operation
    permission: int | None = None
    detail: str = ""
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-732"
    detector: str = _DETECTOR

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
        valid_permission = self.permission is None or (
            type(self.permission) is int and 0 <= self.permission <= 0o7777
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
                self.permission,
                self.detail,
            )
            if valid_identity
            and valid_ranges
            and valid_permission
            and type(self.operation) is PythonCwe732Operation
            and type(self.detail) is str
            and bool(self.detail)
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or not valid_permission
            or type(self.operation) is not PythonCwe732Operation
            or type(self.detail) is not str
            or not self.detail
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-732"
            or self.detector != _DETECTOR
        ):
            raise ValueError("Python CWE-732 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name for generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete permission-affecting call location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink

    @property
    def mode(self) -> int | None:
        """Compatibility name for the permission mode, when statically known."""

        return self.permission


@dataclass(frozen=True, slots=True)
class PythonCwe732ScanResult:
    """Source-free, deterministic CWE-732 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe732Signal, ...]
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
            type(item) is PythonCwe732Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    item.sink.start_byte,
                    item.sink.end_byte,
                    item.source.start_byte,
                    item.source.end_byte,
                    item.operation.value,
                    item.detail,
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
            raise ValueError("Python CWE-732 scan result is invalid")


_DIRECT_OPERATIONS: dict[str, PythonCwe732Operation] = {
    "os.open": PythonCwe732Operation.OS_OPEN,
    "os.chmod": PythonCwe732Operation.OS_CHMOD,
    "os.fchmod": PythonCwe732Operation.OS_FCHMOD,
    "os.mkdir": PythonCwe732Operation.OS_MKDIR,
    "os.makedirs": PythonCwe732Operation.OS_MAKEDIRS,
    "builtins.open": PythonCwe732Operation.BUILTIN_OPEN,
}
_PATH_OPERATIONS: dict[str, PythonCwe732Operation] = {
    "chmod": PythonCwe732Operation.PATH_CHMOD,
    "mkdir": PythonCwe732Operation.PATH_MKDIR,
    "open": PythonCwe732Operation.PATH_OPEN,
    "write_text": PythonCwe732Operation.PATH_WRITE_TEXT,
    "write_bytes": PythonCwe732Operation.PATH_WRITE_BYTES,
    "touch": PythonCwe732Operation.PATH_TOUCH,
}
_TEMPFILE_CALLS = frozenset(
    {
        "tempfile.NamedTemporaryFile",
        "tempfile.TemporaryFile",
        "tempfile.SpooledTemporaryFile",
        "tempfile.TemporaryDirectory",
        "tempfile.mkstemp",
        "tempfile.mkdtemp",
    }
)
_SUPPORTED_MODULES = frozenset({"os", "pathlib", "tempfile", "stat", "builtins"})
_SENSITIVE_WORDS = frozenset(
    {
        "authorized_keys",
        "credentials",
        "credential",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "jwt",
        "passwd",
        "password",
        "private",
        "secret",
        "shadow",
        "token",
    }
)
_SENSITIVE_SUFFIXES = frozenset({".env", ".pem", ".p12", ".pfx", ".key"})
_STAT_MODES = {
    "stat.S_IRUSR": 0o400,
    "stat.S_IWUSR": 0o200,
    "stat.S_IXUSR": 0o100,
    "stat.S_IRGRP": 0o040,
    "stat.S_IWGRP": 0o020,
    "stat.S_IXGRP": 0o010,
    "stat.S_IROTH": 0o004,
    "stat.S_IWOTH": 0o002,
    "stat.S_IXOTH": 0o001,
    "stat.S_IRWXU": 0o700,
    "stat.S_IRWXG": 0o070,
    "stat.S_IRWXO": 0o007,
    "stat.S_IRWXU": 0o700,
}
_OS_FLAGS = {
    "os.O_CREAT": 0x40,
    "os.O_WRONLY": 0x1,
    "os.O_RDWR": 0x2,
    "os.O_APPEND": 0x400,
    "os.O_EXCL": 0x80,
}


def scan_python_cwe732(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe732ScanLimits = DEFAULT_PYTHON_CWE732_SCAN_LIMITS,
) -> PythonCwe732ScanResult:
    """Find bounded improper-permission facts in one sealed Python file."""

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe732ScanLimits
    ):
        raise PythonCwe732ScanError(PythonCwe732ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe732ScanError(PythonCwe732ScanErrorCode.SOURCE_LIMIT)

    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe732ScanError(PythonCwe732ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe732ScanError(PythonCwe732ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe732ScanError(PythonCwe732ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases = _collect_aliases(tree, limits.max_resolution_depth)
    raw: set[tuple[SourceRange, SourceRange, PythonCwe732Operation, int | None, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            _record_call(node, aliases, source, line_starts, limits, raw)
            if len(raw) > limits.max_signals:
                raise PythonCwe732ScanError(PythonCwe732ScanErrorCode.SIGNAL_LIMIT)

    unique = tuple(
        sorted(
            raw,
            key=lambda item: (
                item[1].start_byte,
                item[1].end_byte,
                item[0].start_byte,
                item[0].end_byte,
                item[2].value,
                item[4],
            ),
        )
    )
    if len(unique) > limits.max_signals:
        raise PythonCwe732ScanError(PythonCwe732ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe732Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
            permission=permission,
            detail=detail,
        )
        for source_range, sink_range, operation, permission, detail in unique
    )
    return PythonCwe732ScanResult(
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


def _record_call(
    call: ast.Call,
    aliases: dict[str, str | int | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe732ScanLimits,
    output: set[tuple[SourceRange, SourceRange, PythonCwe732Operation, int | None, str]],
) -> None:
    canonical = _canonical_reference(call.func, aliases, limits.max_resolution_depth)
    operation = _DIRECT_OPERATIONS.get(canonical or "")
    resource: ast.expr | None = None
    mode_node: ast.expr | None = None
    if canonical in _TEMPFILE_CALLS:
        return
    if operation is not None:
        resource = _argument(call, 0, ("path", "name"))
        if operation is PythonCwe732Operation.OS_OPEN:
            mode_node = _argument(call, 2, ("mode",))
            if mode_node is None:
                flags = _argument(call, 1, ("flags",))
                create = _contains_create_flag(flags, aliases, limits.max_resolution_depth)
                if create is False:
                    return
                _add_fact(
                    call,
                    resource or call,
                    operation,
                    None,
                    "missing_restrictive_mode",
                    source,
                    line_starts,
                    output,
                )
                return
        elif operation in {
            PythonCwe732Operation.OS_CHMOD,
            PythonCwe732Operation.OS_FCHMOD,
            PythonCwe732Operation.OS_MKDIR,
            PythonCwe732Operation.OS_MAKEDIRS,
        }:
            mode_node = _argument(call, 1, ("mode",))
            if mode_node is None and operation in {
                PythonCwe732Operation.OS_MKDIR,
                PythonCwe732Operation.OS_MAKEDIRS,
            }:
                _add_fact(
                    call,
                    resource or call,
                    operation,
                    None,
                    "missing_restrictive_mode",
                    source,
                    line_starts,
                    output,
                )
                return
        if resource is None:
            return
        permission = _literal_permission(mode_node, aliases, limits.max_resolution_depth)
        if mode_node is None:
            return
        detail = _unsafe_permission_detail(permission)
        if detail is not None:
            _add_fact(call, resource, operation, permission, detail, source, line_starts, output)
        return

    if canonical == "builtins.open":
        resource = _argument(call, 0, ("file",))
        if resource is None or not _is_sensitive(resource, aliases, limits.max_resolution_depth):
            return
        mode = _argument(call, 1, ("mode",))
        if _open_is_write(mode, aliases, limits.max_resolution_depth):
            _add_fact(
                call,
                resource,
                PythonCwe732Operation.BUILTIN_OPEN,
                None,
                "sensitive_resource",
                source,
                line_starts,
                output,
            )
        return

    if not isinstance(call.func, ast.Attribute):
        return
    method = _PATH_OPERATIONS.get(call.func.attr)
    if method is None:
        return
    resource = call.func.value
    sensitive = _is_sensitive(resource, aliases, limits.max_resolution_depth)
    if method is PythonCwe732Operation.PATH_MKDIR:
        mode_node = _argument(call, 0, ("mode",))
        if mode_node is None:
            _add_fact(
                call,
                resource,
                method,
                None,
                "missing_restrictive_mode",
                source,
                line_starts,
                output,
            )
        else:
            permission = _literal_permission(mode_node, aliases, limits.max_resolution_depth)
            detail = _unsafe_permission_detail(permission)
            if detail is not None:
                _add_fact(call, resource, method, permission, detail, source, line_starts, output)
    elif method is PythonCwe732Operation.PATH_CHMOD:
        mode_node = _argument(call, 0, ("mode",))
        permission = _literal_permission(mode_node, aliases, limits.max_resolution_depth)
        detail = _unsafe_permission_detail(permission)
        if detail is not None:
            _add_fact(call, resource, method, permission, detail, source, line_starts, output)
    elif sensitive and method in {
        PythonCwe732Operation.PATH_OPEN,
        PythonCwe732Operation.PATH_WRITE_TEXT,
        PythonCwe732Operation.PATH_WRITE_BYTES,
        PythonCwe732Operation.PATH_TOUCH,
    }:
        mode = _argument(call, 0, ("mode",)) if method is PythonCwe732Operation.PATH_OPEN else None
        if method is not PythonCwe732Operation.PATH_OPEN or _open_is_write(
            mode, aliases, limits.max_resolution_depth
        ):
            _add_fact(
                call,
                resource,
                method,
                None,
                "sensitive_resource",
                source,
                line_starts,
                output,
            )


def _add_fact(
    call: ast.Call,
    resource: ast.AST,
    operation: PythonCwe732Operation,
    permission: int | None,
    detail: str,
    source: bytes,
    line_starts: tuple[int, ...],
    output: set[tuple[SourceRange, SourceRange, PythonCwe732Operation, int | None, str]],
) -> None:
    sink = _node_range(call, source, line_starts)
    source_range = _node_range(resource, source, line_starts)
    if not sink.contains(source_range):
        raise PythonCwe732ScanError(PythonCwe732ScanErrorCode.INTEGRITY_FAILURE)
    output.add((source_range, sink, operation, permission, detail))


def _collect_aliases(tree: ast.Module, max_depth: int) -> dict[str, str | int | None]:
    aliases: dict[str, str | int | None] = {}
    nodes = sorted(
        ast.walk(tree),
        key=lambda node: (
            getattr(node, "lineno", 0),
            getattr(node, "col_offset", 0),
            0 if isinstance(node, (ast.Import, ast.ImportFrom)) else 1,
        ),
    )
    for node in nodes:
        if isinstance(node, ast.Import):
            for imported in node.names:
                local = imported.asname or imported.name.split(".", 1)[0]
                aliases[local] = imported.name if imported.name.split(".", 1)[0] in _SUPPORTED_MODULES else None
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for imported in node.names:
                if imported.name == "*":
                    continue
                local = imported.asname or imported.name
                canonical = f"{module}.{imported.name}"
                if canonical in _DIRECT_OPERATIONS or canonical in _PATH_OPERATIONS:
                    aliases[local] = canonical
                elif canonical in _TEMPFILE_CALLS:
                    aliases[local] = canonical
                elif canonical in _STAT_MODES:
                    aliases[local] = _STAT_MODES[canonical]
                else:
                    aliases[local] = None
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
            resolved = _resolve_alias_value(value, aliases, max_depth)
            for target in targets:
                if isinstance(target, ast.Name):
                    aliases[target.id] = resolved
    return aliases


def _resolve_alias_value(
    node: ast.expr, aliases: dict[str, str | int | None], max_depth: int
) -> str | int | None:
    permission = _literal_permission(node, aliases, max_depth)
    if permission is not None:
        return permission
    return _canonical_reference(node, aliases, max_depth)


def _canonical_reference(
    node: ast.expr,
    aliases: dict[str, str | int | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe732ScanError(PythonCwe732ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        if node.id == "open":
            return "builtins.open"
        value = aliases.get(node.id)
        return value if type(value) is str else None
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        if base is not None:
            return f"{base}.{node.attr}"
        dotted = _dotted_name(node)
        if dotted in _DIRECT_OPERATIONS or dotted in _TEMPFILE_CALLS or dotted in _STAT_MODES:
            return dotted
        return None
    if isinstance(node, ast.Call):
        if _dotted_name(node.func) not in {"getattr", "builtins.getattr"}:
            return None
        if len(node.args) < 2 or node.keywords:
            return None
        base = _canonical_reference(node.args[0], aliases, max_depth, depth + 1)
        member = _literal_string(node.args[1])
        return None if base is None or member is None else f"{base}.{member}"
    return None


def _argument(call: ast.Call, index: int, names: tuple[str, ...]) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg in names:
            return keyword.value
    return call.args[index] if len(call.args) > index else None


def _literal_permission(
    node: ast.expr | None, aliases: dict[str, str | int | None], max_depth: int, depth: int = 0
) -> int | None:
    if node is None:
        return None
    if depth > max_depth:
        raise PythonCwe732ScanError(PythonCwe732ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        value = aliases.get(node.id)
        return value if type(value) is int else None
    if isinstance(node, ast.Attribute):
        dotted = _dotted_name(node)
        if dotted in _STAT_MODES:
            return _STAT_MODES[dotted]
        return None
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value if 0 <= node.value <= 0o7777 else None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
        value = _literal_permission(node.operand, aliases, max_depth, depth + 1)
        return None if value is None else (~value) & 0o7777
    if isinstance(node, ast.BinOp) and type(node.op) in {
        ast.BitOr,
        ast.BitAnd,
        ast.BitXor,
        ast.LShift,
        ast.RShift,
    }:
        left = _literal_permission(node.left, aliases, max_depth, depth + 1)
        right = _literal_permission(node.right, aliases, max_depth, depth + 1)
        if left is None or right is None:
            return None
        value = (
            left | right
            if isinstance(node.op, ast.BitOr)
            else left & right
            if isinstance(node.op, ast.BitAnd)
            else left ^ right
            if isinstance(node.op, ast.BitXor)
            else left << right
            if isinstance(node.op, ast.LShift)
            else left >> right
        )
        return value if 0 <= value <= 0o7777 else None
    return None


def _contains_create_flag(
    node: ast.expr | None, aliases: dict[str, str | int | None], max_depth: int
) -> bool | None:
    value = _literal_flag(node, aliases, max_depth)
    if value is None:
        return None
    create = _OS_FLAGS["os.O_CREAT"]
    return bool(value & create)


def _literal_flag(
    node: ast.expr | None, aliases: dict[str, str | int | None], max_depth: int, depth: int = 0
) -> int | None:
    if node is None:
        return None
    if depth > max_depth:
        raise PythonCwe732ScanError(PythonCwe732ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        value = aliases.get(node.id)
        return value if type(value) is int else None
    if isinstance(node, ast.Attribute):
        return _OS_FLAGS.get(_dotted_name(node))
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.BitOr, ast.BitAnd, ast.BitXor)):
        left = _literal_flag(node.left, aliases, max_depth, depth + 1)
        right = _literal_flag(node.right, aliases, max_depth, depth + 1)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.BitOr):
            return left | right
        if isinstance(node.op, ast.BitAnd):
            return left & right
        return left ^ right
    return None


def _unsafe_permission_detail(permission: int | None) -> str | None:
    if permission is None:
        return "unknown_permission_mode"
    access = permission & 0o777
    other = access & 0o007
    group = access & 0o070
    if other & 0o002:
        return "world_writable"
    if other & 0o004:
        return "world_readable"
    if other & 0o001:
        return "world_executable"
    if group:
        return "group_accessible"
    return None


def _open_is_write(
    node: ast.expr | None, aliases: dict[str, str | int | None], max_depth: int
) -> bool:
    if node is None:
        return True
    value = _literal_string(node)
    if value is None:
        return True
    return not value or value[0] in {"w", "a", "x"} or "+" in value


def _is_sensitive(
    node: ast.expr, aliases: dict[str, str | int | None], max_depth: int, depth: int = 0
) -> bool:
    if depth > max_depth:
        raise PythonCwe732ScanError(PythonCwe732ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Constant) and type(node.value) is str:
        return _sensitive_text(node.value)
    if isinstance(node, ast.Name):
        return _sensitive_text(node.id)
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(value, ast.Constant)
            and type(value.value) is str
            and _sensitive_text(value.value)
            for value in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_sensitive(node.left, aliases, max_depth, depth + 1) or _is_sensitive(
            node.right, aliases, max_depth, depth + 1
        )
    if isinstance(node, ast.Call) and node.args:
        return _is_sensitive(node.args[0], aliases, max_depth, depth + 1)
    if isinstance(node, ast.Attribute):
        return _sensitive_text(node.attr) or _is_sensitive(
            node.value, aliases, max_depth, depth + 1
        )
    return False


def _sensitive_text(value: str) -> bool:
    lowered = value.lower().replace("\\", "/")
    if any(lowered.endswith(suffix) for suffix in _SENSITIVE_SUFFIXES):
        return True
    tokens = {token for token in re.split(r"[^a-z0-9]+", lowered) if token}
    return bool(tokens & _SENSITIVE_WORDS)


def _literal_string(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None


def _dotted_name(node: ast.AST) -> str:
    parts: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


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
        raise PythonCwe732ScanError(PythonCwe732ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe732ScanError(PythonCwe732ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if start < line_starts[start_line] or end > line_starts[end_line + 1] or end < start:
        raise PythonCwe732ScanError(PythonCwe732ScanErrorCode.INTEGRITY_FAILURE)
    if end > len(source):
        raise PythonCwe732ScanError(PythonCwe732ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(start, end, SourcePoint(start_line, start_column), SourcePoint(end_line, end_column))


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
    operation: PythonCwe732Operation,
    permission: int | None,
    detail: str,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detail": detail,
        "detector": _DETECTOR,
        "operation": operation.value,
        "path": path,
        "permission": permission,
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
    signals: tuple[PythonCwe732Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "detail": signal.detail,
                "detector": signal.detector,
                "operation": signal.operation.value,
                "permission": signal.permission,
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


Cwe732ScanErrorCode = PythonCwe732ScanErrorCode
Cwe732ScanError = PythonCwe732ScanError
Cwe732ScanLimits = PythonCwe732ScanLimits
Cwe732ScanResult = PythonCwe732ScanResult
Cwe732Signal = PythonCwe732Signal


__all__ = [
    "DEFAULT_PYTHON_CWE732_SCAN_LIMITS",
    "Cwe732ScanError",
    "Cwe732ScanErrorCode",
    "Cwe732ScanLimits",
    "Cwe732ScanResult",
    "Cwe732Signal",
    "PythonCwe732Operation",
    "PythonCwe732ScanError",
    "PythonCwe732ScanErrorCode",
    "PythonCwe732ScanLimits",
    "PythonCwe732ScanResult",
    "PythonCwe732Signal",
    "scan_python_cwe732",
]
