"""Bounded JavaScript and TypeScript CWE-367 TOCTOU facts.

The scanner consumes a sealed ECMAScript :class:`SymbolIndex`, rebuilds the
index from the admitted bytes, and then inspects the same bytes with the
repository's tree-sitter grammar.  It records a check such as
``fs.exists(path)`` followed later in the same lexical scope by a filesystem
operation on the same path expression.  Imports, ``require`` aliases,
``fs.promises`` calls, and local path aliases are resolved conservatively.

This is a structural race candidate, rather than a proof that another actor
can win the race at runtime.  Atomic exclusive opens and ``mkdtemp`` are
explicitly treated as safe operations.  Results contain only immutable source
ranges and content-addressed metadata.  Source text is never retained in a
result or exposed in an error.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeGuard

from securecode_ai.core import ParseHealth, RepositoryFile, SourcePoint, SourceRange, SymbolIndex
from tree_sitter import Language, Node, Parser

from .cst import CstAdapterError, build_javascript_symbol_index, build_typescript_symbol_index
from .cst_ecmascript import _javascript_language, _typescript_language

_MAX_LIMITS = (2_000_000, 250_000, 512, 10_000)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_RULE_ID = "securecode-ecmascript-cwe367"
_DETECTOR = "securecode-ecmascript-cwe367@1.0"

_FUNCTION_SCOPE_TYPES = frozenset(
    {
        "arrow_function",
        "function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)
_PATH_BUILDERS = frozenset(
    {
        "dirname",
        "extname",
        "join",
        "normalize",
        "parse",
        "relative",
        "resolve",
        "toNamespacedPath",
        "basename",
    }
)


class EcmaScriptCwe367ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-367 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe367ScanError(RuntimeError):
    """Fixed scanner failure which never exposes parser or source details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe367ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe367ScanErrorCode:
            raise TypeError("ECMAScript CWE-367 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-367 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe367ScanLimits:
    """Hard ceilings applied before and during CST analysis."""

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
            raise ValueError("ECMAScript CWE-367 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE367_SCAN_LIMITS = EcmaScriptCwe367ScanLimits()


class EcmaScriptCwe367Operation(StrEnum):
    """Recognized check-to-filesystem-use operation pairs."""

    EXISTS_THEN_OPEN = "fs.exists->fs.open"
    EXISTS_THEN_OPEN_SYNC = "fs.exists->fs.openSync"
    EXISTS_THEN_WRITE_FILE = "fs.exists->fs.writeFile"
    EXISTS_THEN_WRITE_FILE_SYNC = "fs.exists->fs.writeFileSync"
    EXISTS_THEN_UNLINK = "fs.exists->fs.unlink"
    EXISTS_THEN_UNLINK_SYNC = "fs.exists->fs.unlinkSync"
    EXISTS_THEN_RENAME = "fs.exists->fs.rename"
    EXISTS_THEN_RENAME_SYNC = "fs.exists->fs.renameSync"
    STAT_THEN_OPEN = "fs.stat->fs.open"
    STAT_THEN_OPEN_SYNC = "fs.stat->fs.openSync"
    STAT_THEN_WRITE_FILE = "fs.stat->fs.writeFile"
    STAT_THEN_WRITE_FILE_SYNC = "fs.stat->fs.writeFileSync"
    STAT_THEN_UNLINK = "fs.stat->fs.unlink"
    STAT_THEN_UNLINK_SYNC = "fs.stat->fs.unlinkSync"
    STAT_THEN_RENAME = "fs.stat->fs.rename"
    STAT_THEN_RENAME_SYNC = "fs.stat->fs.renameSync"
    LSTAT_THEN_OPEN = "fs.lstat->fs.open"
    LSTAT_THEN_OPEN_SYNC = "fs.lstat->fs.openSync"
    LSTAT_THEN_WRITE_FILE = "fs.lstat->fs.writeFile"
    LSTAT_THEN_WRITE_FILE_SYNC = "fs.lstat->fs.writeFileSync"
    LSTAT_THEN_UNLINK = "fs.lstat->fs.unlink"
    LSTAT_THEN_UNLINK_SYNC = "fs.lstat->fs.unlinkSync"
    LSTAT_THEN_RENAME = "fs.lstat->fs.rename"
    LSTAT_THEN_RENAME_SYNC = "fs.lstat->fs.renameSync"
    ACCESS_THEN_OPEN = "fs.access->fs.open"
    ACCESS_THEN_OPEN_SYNC = "fs.access->fs.openSync"
    ACCESS_THEN_WRITE_FILE = "fs.access->fs.writeFile"
    ACCESS_THEN_WRITE_FILE_SYNC = "fs.access->fs.writeFileSync"
    ACCESS_THEN_UNLINK = "fs.access->fs.unlink"
    ACCESS_THEN_UNLINK_SYNC = "fs.access->fs.unlinkSync"
    ACCESS_THEN_RENAME = "fs.access->fs.rename"
    ACCESS_THEN_RENAME_SYNC = "fs.access->fs.renameSync"
    PROMISES_STAT_THEN_OPEN = "fs.promises.stat->fs.promises.open"
    PROMISES_STAT_THEN_WRITE_FILE = "fs.promises.stat->fs.promises.writeFile"
    PROMISES_STAT_THEN_UNLINK = "fs.promises.stat->fs.promises.unlink"
    PROMISES_STAT_THEN_RENAME = "fs.promises.stat->fs.promises.rename"
    PROMISES_LSTAT_THEN_OPEN = "fs.promises.lstat->fs.promises.open"
    PROMISES_LSTAT_THEN_WRITE_FILE = "fs.promises.lstat->fs.promises.writeFile"
    PROMISES_LSTAT_THEN_UNLINK = "fs.promises.lstat->fs.promises.unlink"
    PROMISES_LSTAT_THEN_RENAME = "fs.promises.lstat->fs.promises.rename"
    PROMISES_ACCESS_THEN_OPEN = "fs.promises.access->fs.promises.open"
    PROMISES_ACCESS_THEN_WRITE_FILE = "fs.promises.access->fs.promises.writeFile"
    PROMISES_ACCESS_THEN_UNLINK = "fs.promises.access->fs.promises.unlink"
    PROMISES_ACCESS_THEN_RENAME = "fs.promises.access->fs.promises.rename"
    EXISTS_THEN_WRITE_STREAM = "fs.exists->fs.createWriteStream"
    STAT_THEN_WRITE_STREAM = "fs.stat->fs.createWriteStream"
    LSTAT_THEN_WRITE_STREAM = "fs.lstat->fs.createWriteStream"
    ACCESS_THEN_WRITE_STREAM = "fs.access->fs.createWriteStream"

    # Short names used by language-neutral consumers.
    EXISTS_OPEN = "fs.exists->fs.open"
    STAT_OPEN = "fs.stat->fs.open"
    LSTAT_OPEN = "fs.lstat->fs.open"
    ACCESS_OPEN = "fs.access->fs.open"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe367Signal:
    """One immutable, source-free TOCTOU candidate."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe367Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-367"
    detector: str = _DETECTOR
    detail: str = "checked_path_reused_for_file_operation"

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
            and 0 <= self.source.start_byte <= self.source.end_byte
            and self.source.end_byte <= self.sink.start_byte
            and self.sink.end_byte <= self.source_size_bytes
        )
        expected = (
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
            if identity_valid and ranges_valid and type(self.operation) is EcmaScriptCwe367Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not EcmaScriptCwe367Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-367"
            or self.detector != _DETECTOR
            or self.detail != "checked_path_reused_for_file_operation"
        ):
            raise ValueError("ECMAScript CWE-367 signal is invalid")
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
class EcmaScriptCwe367ScanResult:
    """Deterministic, source-free CWE-367 output for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe367Signal, ...]
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
        valid_signals = type(self.signals) is tuple and all(
            type(item) is EcmaScriptCwe367Signal for item in self.signals
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
            or type(self.scan_sha256) is not str
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
            raise ValueError("ECMAScript CWE-367 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Check:
    kind: str
    path_key: str
    source: SourceRange
    call_start: int


def scan_javascript_cwe367(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe367ScanLimits = DEFAULT_ECMASCRIPT_CWE367_SCAN_LIMITS,
) -> EcmaScriptCwe367ScanResult:
    """Find bounded JavaScript check-to-filesystem-use race candidates."""

    return _scan_ecmascript_cwe367(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe367(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe367ScanLimits = DEFAULT_ECMASCRIPT_CWE367_SCAN_LIMITS,
) -> EcmaScriptCwe367ScanResult:
    """Find bounded TypeScript check-to-filesystem-use race candidates."""

    return _scan_ecmascript_cwe367(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe367(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe367ScanLimits = DEFAULT_ECMASCRIPT_CWE367_SCAN_LIMITS,
) -> EcmaScriptCwe367ScanResult:
    """Dispatch a CWE-367 scan according to a sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe367(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe367(symbol_index, limits=limits)
    raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe367(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe367ScanLimits,
) -> EcmaScriptCwe367ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe367ScanLimits:
        raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.ANALYSIS_UNAVAILABLE)

    builder = (
        build_javascript_symbol_index
        if expected_language == "javascript"
        else build_typescript_symbol_index
    )
    try:
        rebuilt = builder(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source=symbol_index.source,
        )
        if rebuilt != symbol_index:
            raise ValueError("symbol index mismatch")
        grammar = (
            _javascript_language()
            if expected_language == "javascript"
            else _typescript_language(tsx=symbol_index.path.endswith(".tsx"))
        )
        source = symbol_index.source
        source.decode("utf-8", errors="strict")
        root = Parser(Language(grammar)).parse(source).root_node
    except (CstAdapterError, TypeError, UnicodeDecodeError, ValueError):
        raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.INTEGRITY_FAILURE) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.ANALYSIS_UNAVAILABLE)
        module_aliases = _collect_module_aliases(nodes, source)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe367Operation]] = set()
        for scope in _scopes(root):
            raw.update(_scan_scope(scope, source, module_aliases, limits))
            if len(raw) > limits.max_signals:
                raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.SIGNAL_LIMIT)
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
            raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.SIGNAL_LIMIT)
    except EcmaScriptCwe367ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.INTEGRITY_FAILURE) from None

    signals = tuple(
        EcmaScriptCwe367Signal(
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
    return EcmaScriptCwe367ScanResult(
        repository_id=symbol_index.repository_id,
        revision=symbol_index.revision,
        path=symbol_index.path,
        content_sha256=symbol_index.content_sha256,
        source_size_bytes=symbol_index.source_byte_length,
        language=expected_language,
        signals=signals,
        scan_sha256=_scan_sha256(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            expected_language,
            signals,
        ),
    )


def _scan_scope(
    scope: Node,
    source: bytes,
    module_aliases: dict[str, str],
    limits: EcmaScriptCwe367ScanLimits,
) -> set[tuple[SourceRange, SourceRange, EcmaScriptCwe367Operation]]:
    aliases = dict(module_aliases)
    checks: dict[str, _Check] = {}
    raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe367Operation]] = set()
    for node in _scope_nodes(scope):
        if node.type == "variable_declarator":
            _bind_variable(node, source, aliases, checks)
        elif node.type == "assignment_expression":
            _bind_assignment(node, source, aliases, checks)
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            continue
        callee = _normalise_callee(_canonical_expression(function, source, aliases))
        if callee is None:
            continue
        values = tuple(arguments.named_children)
        check_kind = _CHECKS.get(callee)
        if check_kind is not None:
            if not values:
                continue
            path_key = _path_key(values[0], source, aliases, 0, frozenset())
            if path_key is not None:
                checks[path_key] = _Check(check_kind, path_key, _range(values[0]), node.start_byte)
            continue
        sink_kind = _SINKS.get(callee)
        if sink_kind is None or not values or _is_mkdtemp(callee):
            continue
        if _is_exclusive_sink(callee, values, source, aliases):
            continue
        path_values = (
            values[:2] if sink_kind in {"rename", "rename_sync", "promises_rename"} else values[:1]
        )
        sink_range = _range(node)
        for path_node in path_values:
            path_key = _path_key(path_node, source, aliases, 0, frozenset())
            if path_key is None:
                continue
            check = checks.get(path_key)
            if check is None or check.call_start >= node.start_byte:
                continue
            operation = _operation(check.kind, sink_kind)
            if operation is None:
                continue
            if not (check.source.end_byte <= sink_range.start_byte):
                continue
            raw.add((check.source, sink_range, operation))
            if len(raw) > limits.max_signals:
                raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.SIGNAL_LIMIT)
    return raw


def _bind_variable(
    node: Node, source: bytes, aliases: dict[str, str], checks: dict[str, _Check]
) -> None:
    name = node.child_by_field_name("name")
    value = node.child_by_field_name("value")
    if name is None or value is None:
        return
    module = _canonical_expression(value, source, aliases)
    if _is_module_binding(module):
        if name.type == "identifier":
            _replace_alias(_node_text(source, name), module, aliases, checks)
        elif name.type in {"object_pattern", "object"}:
            _bind_destructured(name, module[7:], source, aliases, checks)
        return
    key = _path_key(value, source, aliases, 0, frozenset())
    if name.type == "identifier":
        _replace_alias(_node_text(source, name), key, aliases, checks)
    elif name.type in {"object_pattern", "object"}:
        module = _canonical_expression(value, source, aliases)
        if module is not None:
            _bind_destructured(name, module, source, aliases, checks)


def _bind_assignment(
    node: Node, source: bytes, aliases: dict[str, str], checks: dict[str, _Check]
) -> None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None or left.type != "identifier":
        return
    key = _path_key(right, source, aliases, 0, frozenset())
    _replace_alias(_node_text(source, left), key, aliases, checks)


def _replace_alias(
    name: str, key: str | None, aliases: dict[str, str], checks: dict[str, _Check]
) -> None:
    old = aliases.get(name)
    if old is not None:
        checks.pop(old, None)
    if key is None:
        aliases.pop(name, None)
    else:
        aliases[name] = key


def _bind_destructured(
    pattern: Node,
    module: str,
    source: bytes,
    aliases: dict[str, str],
    checks: dict[str, _Check],
) -> None:
    for child in pattern.named_children:
        key_node, value_node = _pair_parts(child)
        if key_node is None:
            key_node = child
        if value_node is None:
            value_node = key_node
        key_name = _static_property_name(key_node, source)
        local_name = _static_property_name(value_node, source)
        if key_name is None or local_name is None:
            continue
        if module == "fs" and key_name == "promises":
            _replace_alias(local_name, "module:fs/promises", aliases, checks)
        else:
            _replace_alias(local_name, f"module:{module}.{key_name}", aliases, checks)


def _operation(check_kind: str, sink_kind: str) -> EcmaScriptCwe367Operation | None:
    prefixes = {
        "exists": "exists",
        "exists_sync": "exists",
        "stat": "stat",
        "stat_sync": "stat",
        "lstat": "lstat",
        "lstat_sync": "lstat",
        "access": "access",
        "access_sync": "access",
        "promises_stat": "promises_stat",
        "promises_lstat": "promises_lstat",
        "promises_access": "promises_access",
    }
    prefix = prefixes.get(check_kind)
    if prefix is None:
        return None
    names = {
        "open": "open",
        "open_sync": "openSync",
        "write_file": "writeFile",
        "write_file_sync": "writeFileSync",
        "unlink": "unlink",
        "unlink_sync": "unlinkSync",
        "rename": "rename",
        "rename_sync": "renameSync",
        "write_stream": "createWriteStream",
        "promises_open": "promises.open",
        "promises_write_file": "promises.writeFile",
        "promises_unlink": "promises.unlink",
        "promises_rename": "promises.rename",
    }
    sink = names.get(sink_kind)
    if sink is None:
        return None
    if prefix.startswith("promises_"):
        value = f"fs.{prefix.replace('_', '.')}->{sink if sink.startswith('fs.') else 'fs.' + sink}"
    else:
        value = f"fs.{prefix}->fs.{sink}"
    try:
        return EcmaScriptCwe367Operation(value)
    except ValueError:
        # The enum contains the portable common combinations.  Promise calls
        # with an unusual sink are still represented by their closest common
        # operation so the finding remains typed and deterministic.
        fallback = {
            "open": "open",
            "open_sync": "openSync",
            "write_file": "writeFile",
            "write_file_sync": "writeFileSync",
            "unlink": "unlink",
            "unlink_sync": "unlinkSync",
            "rename": "rename",
            "rename_sync": "renameSync",
        }.get(sink_kind)
        if fallback is None:
            return None
        try:
            return EcmaScriptCwe367Operation(f"fs.{prefix.split('_')[-1]}->fs.{fallback}")
        except ValueError:
            return None


_CHECKS: dict[str, str] = {
    "fs.exists": "exists",
    "fs.existsSync": "exists_sync",
    "fs.stat": "stat",
    "fs.statSync": "stat_sync",
    "fs.lstat": "lstat",
    "fs.lstatSync": "lstat_sync",
    "fs.access": "access",
    "fs.accessSync": "access_sync",
    "fs.promises.stat": "promises_stat",
    "fs.promises.lstat": "promises_lstat",
    "fs.promises.access": "promises_access",
}
_SINKS: dict[str, str] = {
    "fs.open": "open",
    "fs.openSync": "open_sync",
    "fs.writeFile": "write_file",
    "fs.writeFileSync": "write_file_sync",
    "fs.createWriteStream": "write_stream",
    "fs.appendFile": "write_file",
    "fs.appendFileSync": "write_file_sync",
    "fs.unlink": "unlink",
    "fs.unlinkSync": "unlink_sync",
    "fs.rm": "unlink",
    "fs.rmSync": "unlink_sync",
    "fs.rmdir": "unlink",
    "fs.rmdirSync": "unlink_sync",
    "fs.rename": "rename",
    "fs.renameSync": "rename_sync",
    "fs.promises.open": "promises_open",
    "fs.promises.writeFile": "promises_write_file",
    "fs.promises.appendFile": "promises_write_file",
    "fs.promises.unlink": "promises_unlink",
    "fs.promises.rm": "promises_unlink",
    "fs.promises.rmdir": "promises_unlink",
    "fs.promises.rename": "promises_rename",
}


def _is_exclusive_sink(
    callee: str, values: tuple[Node, ...], source: bytes, aliases: dict[str, str]
) -> bool:
    if callee in {"fs.open", "fs.openSync", "fs.promises.open"}:
        return len(values) >= 2 and _is_exclusive_flag(values[1], source, aliases)
    if callee in {
        "fs.writeFile",
        "fs.writeFileSync",
        "fs.appendFile",
        "fs.appendFileSync",
        "fs.promises.writeFile",
        "fs.promises.appendFile",
    }:
        return len(values) >= 3 and _is_exclusive_options(values[2], source, aliases)
    if callee == "fs.createWriteStream":
        return len(values) >= 2 and _is_exclusive_options(values[1], source, aliases)
    return False


def _is_exclusive_options(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    current = _unwrap(node)
    if current.type == "object":
        for pair in current.named_children:
            key, value = _pair_parts(pair)
            if key is None or value is None:
                continue
            if _static_property_name(key, source) in {"flag", "flags"} and _is_exclusive_flag(
                value, source, aliases
            ):
                return True
        return False
    return _is_exclusive_flag(current, source, aliases)


def _is_exclusive_flag(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    current = _unwrap(node)
    literal = _string_value(current, source)
    if literal is not None:
        return bool(re.search(r"(?:^|[^a-z])(?:w|a)x(?:\+)?(?:$|[^a-z])", literal, re.I))
    text = _compact_text(source, current)
    if current.type == "identifier":
        text = aliases.get(_node_text(source, current), text)
    lowered = text.lower()
    return "o_excl" in lowered and "o_creat" in lowered


def _is_mkdtemp(callee: str) -> bool:
    return callee.rsplit(".", 1)[-1].lower() in {"mkdtemp", "mkdtempsync"}


def _path_key(
    node: Node,
    source: bytes,
    aliases: dict[str, str],
    depth: int,
    seen: frozenset[str],
) -> str | None:
    if depth > 32:
        raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.DEPTH_LIMIT)
    current = _unwrap(node)
    if current.type == "identifier":
        name = _node_text(source, current)
        if name in seen:
            return None
        return aliases.get(name, f"path:id:{name}")
    if current.type in {"string", "string_fragment", "number", "regex"}:
        value = _string_value(current, source) or _compact_text(source, current)
        return _fingerprint_path(f"literal:{value}")
    if current.type == "call_expression":
        function = current.child_by_field_name("function")
        arguments = current.child_by_field_name("arguments")
        if function is None or arguments is None:
            return None
        callee = _normalise_callee(_canonical_expression(function, source, aliases))
        values = tuple(arguments.named_children)
        if callee is None:
            return None
        if _is_path_builder(callee):
            argument_keys = [_path_key(value, source, aliases, depth + 1, seen) for value in values]
            present_keys = [key for key in argument_keys if key is not None]
            if len(present_keys) != len(argument_keys):
                return None
            return _fingerprint_path(f"call:{callee}({','.join(present_keys)})")
        # A deterministic call expression is still a local alias when it is
        # assigned and used again.  Hashing the compact expression keeps the
        # actual argument text out of the signal and allows conservative
        # matching of a repeated direct expression.
        return _fingerprint_path(f"call:{_compact_text(source, current)}")
    if current.type in {
        "binary_expression",
        "template_string",
        "template_substitution",
        "ternary_expression",
        "conditional_expression",
        "logical_expression",
        "sequence_expression",
        "array",
        "object",
        "member_expression",
        "subscript_expression",
    }:
        parts: list[str] = []
        for child in current.named_children:
            child_key = _path_key(child, source, aliases, depth + 1, seen)
            if child_key is None:
                parts.append(f"text:{_compact_text(source, child)}")
            else:
                parts.append(child_key)
        if parts:
            return _fingerprint_path(f"{current.type}:{'|'.join(parts)}")
    compact = _compact_text(source, current)
    return _fingerprint_path(f"expr:{compact}") if compact else None


def _is_path_builder(callee: str) -> bool:
    parts = callee.split(".")
    if len(parts) == 2:
        return parts[0] == "path" and parts[1] in _PATH_BUILDERS
    return (
        len(parts) == 3
        and tuple(parts[:2]) in {("path", "posix"), ("path", "win32")}
        and parts[2] in _PATH_BUILDERS
    )


def _fingerprint_path(value: str) -> str:
    return "path:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _collect_module_aliases(nodes: tuple[Node, ...], source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in nodes:
        if node.type == "import_statement":
            _collect_import_aliases(node, source, aliases)
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            name = node.child_by_field_name("name")
            if value is None or name is None:
                continue
            module = _canonical_expression(value, source, aliases)
            if not _is_module_binding(module):
                continue
            if name.type == "identifier":
                aliases[_node_text(source, name)] = module
            elif name.type in {"object_pattern", "object"}:
                _bind_destructured(name, module[7:], source, aliases, {})
    return aliases


def _collect_import_aliases(node: Node, source: bytes, aliases: dict[str, str]) -> None:
    module_node = node.child_by_field_name("source")
    if module_node is None:
        return
    module = _string_value(module_node, source)
    if module is None or module not in {"fs", "node:fs", "path", "node:path"}:
        return
    module = module[5:] if module.startswith("node:") else module
    for clause in node.named_children:
        if clause.type != "import_clause":
            continue
        for item in clause.named_children:
            if item.type == "identifier":
                aliases[_node_text(source, item)] = f"module:{module}"
            elif item.type == "namespace_import":
                named = item.named_children
                if named:
                    aliases[_node_text(source, named[-1])] = f"module:{module}"
            elif item.type in {"named_imports", "named_import"}:
                for specifier in item.named_children:
                    if specifier.type != "import_specifier":
                        continue
                    names = tuple(specifier.named_children)
                    if not names:
                        continue
                    imported = _node_text(source, names[0])
                    local = _node_text(source, names[-1])
                    aliases[local] = f"module:{module}.{imported}"


def _canonical_expression(node: Node, source: bytes, aliases: dict[str, str]) -> str | None:
    current = _unwrap(node)
    if current.type == "call_expression":
        function = current.child_by_field_name("function")
        arguments = current.child_by_field_name("arguments")
        if function is None or arguments is None or _compact_text(source, function) != "require":
            return None
        values = tuple(arguments.named_children)
        if len(values) != 1:
            return None
        module = _string_value(values[0], source)
        if module is None:
            return None
        module = module[5:] if module.startswith("node:") else module
        return f"module:{module}" if module in {"fs", "path"} else None
    if current.type in {"member_expression", "subscript_expression"}:
        base = current.child_by_field_name("object")
        prop = current.child_by_field_name("property")
        if base is None or prop is None:
            named = tuple(current.named_children)
            if len(named) < 2:
                return None
            base, prop = named[0], named[-1]
        base_name = _canonical_expression(base, source, aliases)
        property_name = _static_property_name(prop, source)
        if base_name is None or property_name is None:
            return None
        return f"{base_name}.{property_name}"
    if current.type == "identifier":
        return aliases.get(_node_text(source, current), _node_text(source, current))
    compact = _compact_text(source, current)
    if not compact:
        return None
    parts = compact.split(".")
    if not _IDENTIFIER.fullmatch(parts[0]):
        return None
    base_name = aliases.get(parts[0], parts[0])
    return ".".join((base_name, *parts[1:])) if len(parts) > 1 else base_name


def _normalise_callee(value: str | None) -> str | None:
    if value is None:
        return None
    value = value[7:] if value.startswith("module:") else value
    return value.replace("fs/promises.", "fs.promises.", 1)


def _is_module_binding(value: str | None) -> TypeGuard[str]:
    if value is None or not value.startswith("module:"):
        return False
    canonical = value[7:]
    if canonical in {"fs", "fs/promises", "path"}:
        return True
    return canonical in _CHECKS or canonical in _SINKS


def _scopes(root: Node) -> tuple[Node, ...]:
    scopes: list[Node] = [root]
    for node in _preorder(root):
        if node is not root and node.type in _FUNCTION_SCOPE_TYPES:
            scopes.append(node)
    return tuple(scopes)


def _scope_nodes(scope: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    first = True
    while stack:
        node = stack.pop()
        output.append(node)
        if not first and node.type in _FUNCTION_SCOPE_TYPES:
            continue
        first = False
        stack.extend(reversed(node.named_children))
    return tuple(sorted(output, key=lambda node: (node.start_byte, node.end_byte)))


def _preorder(root: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        output.append(node)
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _bounded_nodes(root: Node, limits: EcmaScriptCwe367ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _pair_parts(node: Node) -> tuple[Node | None, Node | None]:
    key = node.child_by_field_name("key")
    value = node.child_by_field_name("value")
    named = tuple(node.named_children)
    if key is None and named:
        key = named[0]
    if value is None and len(named) >= 2:
        value = named[-1]
    return key, value


def _static_property_name(node: Node, source: bytes) -> str | None:
    current = _unwrap(node)
    if current.type in {"identifier", "property_identifier", "private_property_identifier"}:
        return _node_text(source, current)
    return _string_value(current, source)


def _unwrap(node: Node) -> Node:
    current = node
    while current.type in {
        "parenthesized_expression",
        "as_expression",
        "non_null_expression",
        "await_expression",
    }:
        named = tuple(current.named_children)
        if not named:
            break
        current = named[-1]
    return current


def _string_value(node: Node, source: bytes) -> str | None:
    current = _unwrap(node)
    if current.type not in {"string", "string_fragment"}:
        return None
    value = source[current.start_byte : current.end_byte]
    if current.type == "string":
        if len(value) < 2 or value[:1] not in {b"'", b'"', b"`"} or value[-1:] != value[:1]:
            return None
        value = value[1:-1]
    if b"\\" in value or b"\n" in value or b"\r" in value:
        return None
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.INTEGRITY_FAILURE) from None


def _node_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe367ScanError(EcmaScriptCwe367ScanErrorCode.INTEGRITY_FAILURE) from None


def _compact_text(source: bytes, node: Node) -> str:
    return "".join(_node_text(source, node).split())


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
    operation: EcmaScriptCwe367Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-367",
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
    language: str,
    signals: tuple[EcmaScriptCwe367Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-367",
        "detector": _DETECTOR,
        "language": language,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
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


# Descriptive aliases keep the scanner discoverable to language-neutral callers.
scan_javascript_toctou = scan_javascript_cwe367
scan_typescript_toctou = scan_typescript_cwe367
scan_ecmascript_toctou = scan_ecmascript_cwe367
scan_javascript_cwe367_toctou = scan_javascript_cwe367
scan_typescript_cwe367_toctou = scan_typescript_cwe367
scan_ecmascript_cwe367_toctou = scan_ecmascript_cwe367
scan_javascript_time_of_check_to_time_of_use = scan_javascript_cwe367
scan_typescript_time_of_check_to_time_of_use = scan_typescript_cwe367
scan_ecmascript_time_of_check_to_time_of_use = scan_ecmascript_cwe367


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE367_SCAN_LIMITS",
    "EcmaScriptCwe367Operation",
    "EcmaScriptCwe367ScanError",
    "EcmaScriptCwe367ScanErrorCode",
    "EcmaScriptCwe367ScanLimits",
    "EcmaScriptCwe367ScanResult",
    "EcmaScriptCwe367Signal",
    "scan_ecmascript_cwe367",
    "scan_ecmascript_cwe367_toctou",
    "scan_ecmascript_toctou",
    "scan_javascript_cwe367",
    "scan_javascript_cwe367_toctou",
    "scan_javascript_time_of_check_to_time_of_use",
    "scan_javascript_toctou",
    "scan_typescript_cwe367",
    "scan_typescript_cwe367_toctou",
    "scan_typescript_time_of_check_to_time_of_use",
    "scan_typescript_toctou",
]
