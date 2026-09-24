"""Bounded JavaScript and TypeScript CWE-732 permission facts.

The scanner inspects a sealed ECMAScript ``SymbolIndex`` and reparses the
admitted bytes before examining filesystem calls.  It follows a deliberately
small set of Node ``fs`` write, chmod, and mkdir operations, evaluates static
numeric and bitwise modes, and resolves local aliases through bounded CST
bindings.  Results contain only immutable ranges and content-addressed
metadata.  Source text is never retained in a signal or an exception.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import ParseHealth, RepositoryFile, SourcePoint, SourceRange, SymbolIndex
from tree_sitter import Language, Node, Parser

from .cst import CstAdapterError, build_javascript_symbol_index, build_typescript_symbol_index
from .cst_ecmascript import _javascript_language, _typescript_language
from .ecmascript_cwe22 import (
    _canonical_expression,
    _compact_text,
    _collect_aliases,
    _enclosing_scope,
    _latest_binding,
    _string_value,
    _text,
)

_MAX_LIMITS = (2_000_000, 250_000, 512, 10_000, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-ecmascript-cwe732"
_DETECTOR = "securecode-ecmascript-cwe732@1.0"

_FS_MODULES = frozenset({"fs", "fs/promises"})
_WRITE_OPERATIONS = frozenset(
    {
        "writeFile",
        "writeFileSync",
        "appendFile",
        "appendFileSync",
        "createWriteStream",
        "open",
        "openSync",
    }
)
_CHMOD_OPERATIONS = frozenset({"chmod", "chmodSync"})
_MKDIR_OPERATIONS = frozenset({"mkdir", "mkdirSync"})
_TEMP_OPERATIONS = frozenset({"mkdtemp", "mkdtempSync"})
_PERMISSION_OPERATIONS = _WRITE_OPERATIONS | _CHMOD_OPERATIONS | _MKDIR_OPERATIONS
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
_FLAG_VALUES = {
    "fs.constants.O_CREAT": 0x40,
    "fs.constants.O_WRONLY": 0x1,
    "fs.constants.O_RDWR": 0x2,
    "fs.constants.O_APPEND": 0x400,
    "fs.constants.O_EXCL": 0x80,
    "fs.constants.O_TRUNC": 0x200,
    "fs/promises.constants.O_CREAT": 0x40,
    "fs/promises.constants.O_WRONLY": 0x1,
    "fs/promises.constants.O_RDWR": 0x2,
    "fs/promises.constants.O_APPEND": 0x400,
    "fs/promises.constants.O_EXCL": 0x80,
    "fs/promises.constants.O_TRUNC": 0x200,
    "fs.constants.S_IRUSR": 0o400,
    "fs.constants.S_IWUSR": 0o200,
    "fs.constants.S_IXUSR": 0o100,
    "fs.constants.S_IRGRP": 0o040,
    "fs.constants.S_IWGRP": 0o020,
    "fs.constants.S_IXGRP": 0o010,
    "fs.constants.S_IROTH": 0o004,
    "fs.constants.S_IWOTH": 0o002,
    "fs.constants.S_IXOTH": 0o001,
    "fs.constants.S_IRWXU": 0o700,
    "fs.constants.S_IRWXG": 0o070,
    "fs.constants.S_IRWXO": 0o007,
    "fs/promises.constants.S_IRUSR": 0o400,
    "fs/promises.constants.S_IWUSR": 0o200,
    "fs/promises.constants.S_IXUSR": 0o100,
    "fs/promises.constants.S_IRGRP": 0o040,
    "fs/promises.constants.S_IWGRP": 0o020,
    "fs/promises.constants.S_IXGRP": 0o010,
    "fs/promises.constants.S_IROTH": 0o004,
    "fs/promises.constants.S_IWOTH": 0o002,
    "fs/promises.constants.S_IXOTH": 0o001,
    "fs/promises.constants.S_IRWXU": 0o700,
    "fs/promises.constants.S_IRWXG": 0o070,
    "fs/promises.constants.S_IRWXO": 0o007,
}


class EcmaScriptCwe732ScanErrorCode(StrEnum):
    """Closed, source-free reasons a scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe732ScanError(RuntimeError):
    """Fixed scanner failure that never echoes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe732ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe732ScanErrorCode:
            raise TypeError("ECMAScript CWE-732 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-732 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe732ScanLimits:
    """Hard ceilings for source, CST, output, and alias resolution."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_nodes: int = _MAX_LIMITS[1]
    max_depth: int = _MAX_LIMITS[2]
    max_signals: int = _MAX_LIMITS[3]
    max_resolution_depth: int = _MAX_LIMITS[4]

    def __post_init__(self) -> None:
        values = (
            self.max_source_bytes,
            self.max_nodes,
            self.max_depth,
            self.max_signals,
            self.max_resolution_depth,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("ECMAScript CWE-732 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE732_SCAN_LIMITS = EcmaScriptCwe732ScanLimits()


class EcmaScriptCwe732Operation(StrEnum):
    """Recognized Node filesystem permission operations."""

    WRITE_FILE = "fs.writeFile"
    WRITE_FILE_SYNC = "fs.writeFileSync"
    APPEND_FILE = "fs.appendFile"
    APPEND_FILE_SYNC = "fs.appendFileSync"
    CREATE_WRITE_STREAM = "fs.createWriteStream"
    OPEN = "fs.open"
    OPEN_SYNC = "fs.openSync"
    CHMOD = "fs.chmod"
    CHMOD_SYNC = "fs.chmodSync"
    MKDIR = "fs.mkdir"
    MKDIR_SYNC = "fs.mkdirSync"
    MKDTEMP = "fs.mkdtemp"
    MKDTEMP_SYNC = "fs.mkdtempSync"

    # Compatibility names used by generic scanner consumers.
    WRITE = "fs.writeFile"
    OPEN_FILE = "fs.open"
    MAKE_DIRECTORY = "fs.mkdir"


_OPERATION_BY_NAME: dict[str, EcmaScriptCwe732Operation] = {
    "writeFile": EcmaScriptCwe732Operation.WRITE_FILE,
    "writeFileSync": EcmaScriptCwe732Operation.WRITE_FILE_SYNC,
    "appendFile": EcmaScriptCwe732Operation.APPEND_FILE,
    "appendFileSync": EcmaScriptCwe732Operation.APPEND_FILE_SYNC,
    "createWriteStream": EcmaScriptCwe732Operation.CREATE_WRITE_STREAM,
    "open": EcmaScriptCwe732Operation.OPEN,
    "openSync": EcmaScriptCwe732Operation.OPEN_SYNC,
    "chmod": EcmaScriptCwe732Operation.CHMOD,
    "chmodSync": EcmaScriptCwe732Operation.CHMOD_SYNC,
    "mkdir": EcmaScriptCwe732Operation.MKDIR,
    "mkdirSync": EcmaScriptCwe732Operation.MKDIR_SYNC,
    "mkdtemp": EcmaScriptCwe732Operation.MKDTEMP,
    "mkdtempSync": EcmaScriptCwe732Operation.MKDTEMP_SYNC,
}


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe732Signal:
    """One immutable sensitive-resource-to-permission fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe732Operation
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
                self.permission,
                self.detail,
            )
            if valid_identity
            and valid_ranges
            and valid_permission
            and type(self.operation) is EcmaScriptCwe732Operation
            and type(self.detail) is str
            and bool(self.detail)
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not valid_identity
            or not valid_ranges
            or not valid_permission
            or type(self.operation) is not EcmaScriptCwe732Operation
            or type(self.detail) is not str
            or not self.detail
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-732"
            or self.detector != _DETECTOR
        ):
            raise ValueError("ECMAScript CWE-732 signal is invalid")
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
        """Compatibility name for the statically resolved permission mode."""

        return self.permission


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe732ScanResult:
    """Deterministic, source-free result for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe732Signal, ...]
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
            and self.language in {"javascript", "typescript"}
        )
        if valid_identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid_identity = False
        order = tuple(
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
        same_identity = all(
            item.repository_id == self.repository_id
            and item.revision == self.revision
            and item.path == self.path
            and item.content_sha256 == self.content_sha256
            and item.source_size_bytes == self.source_size_bytes
            for item in self.signals
        )
        if (
            not valid_identity
            or type(self.signals) is not tuple
            or any(type(item) is not EcmaScriptCwe732Signal for item in self.signals)
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
            raise ValueError("ECMAScript CWE-732 scan result is invalid")


def scan_javascript_cwe732(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe732ScanLimits = DEFAULT_ECMASCRIPT_CWE732_SCAN_LIMITS,
) -> EcmaScriptCwe732ScanResult:
    """Find bounded JavaScript sensitive-file permission facts."""

    return _scan_ecmascript_cwe732(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe732(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe732ScanLimits = DEFAULT_ECMASCRIPT_CWE732_SCAN_LIMITS,
) -> EcmaScriptCwe732ScanResult:
    """Find bounded TypeScript sensitive-file permission facts."""

    return _scan_ecmascript_cwe732(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe732(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe732ScanLimits = DEFAULT_ECMASCRIPT_CWE732_SCAN_LIMITS,
) -> EcmaScriptCwe732ScanResult:
    """Dispatch a CWE-732 scan using the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe732(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe732(symbol_index, limits=limits)
    raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe732(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe732ScanLimits,
) -> EcmaScriptCwe732ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe732ScanLimits:
        raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.ANALYSIS_UNAVAILABLE)

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
        raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.INTEGRITY_FAILURE) from None

    nodes = _bounded_nodes(root, limits)
    if any(node.type == "ERROR" or node.is_missing for node in nodes):
        raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.ANALYSIS_UNAVAILABLE)
    try:
        aliases = _collect_aliases(nodes, source)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe732Operation, int | None, str]] = set()
        for node in nodes:
            if node.type != "call_expression":
                continue
            fact = _fact_for_call(node, root, source, aliases, limits)
            if fact is not None:
                raw.add(fact)
                if len(raw) > limits.max_signals:
                    raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.SIGNAL_LIMIT)
    except EcmaScriptCwe732ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.INTEGRITY_FAILURE) from None

    ordered = sorted(
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
    signals = tuple(
        EcmaScriptCwe732Signal(
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
        for source_range, sink_range, operation, permission, detail in ordered
    )
    return EcmaScriptCwe732ScanResult(
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


def _bounded_nodes(root: Node, limits: EcmaScriptCwe732ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _fact_for_call(
    node: Node,
    root: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe732ScanLimits,
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe732Operation, int | None, str] | None:
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None:
        raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.INTEGRITY_FAILURE)
    canonical = _canonical_expression(function, source, aliases)
    if canonical is None:
        return None
    parts = canonical.rsplit(".", 1)
    if len(parts) != 2 or parts[0] not in _FS_MODULES:
        return None
    operation_name = parts[1]
    operation = _OPERATION_BY_NAME.get(operation_name)
    if operation is None:
        return None
    values = arguments.named_children
    if not values:
        return None
    scope = _enclosing_scope(node, root)
    resource = values[0]
    if operation_name in _TEMP_OPERATIONS:
        return None
    if not _is_sensitive_resource(resource, scope, source, limits):
        return None

    permission_node: Node | None
    if operation_name in {"writeFile", "writeFileSync", "appendFile", "appendFileSync"}:
        options = values[2] if len(values) >= 3 else None
        permission_node = _option_value(options, "mode", scope, source, limits)
        permission = _permission_value(permission_node, scope, source, aliases, limits)
        detail = _permission_detail(permission, permission_node is None)
    elif operation_name == "createWriteStream":
        options = values[1] if len(values) >= 2 else None
        permission_node = _option_value(options, "mode", scope, source, limits)
        permission = _permission_value(permission_node, scope, source, aliases, limits)
        detail = _permission_detail(permission, permission_node is None)
    elif operation_name in {"open", "openSync"}:
        flags = values[1] if len(values) >= 2 else None
        if not _is_write_open(flags, scope, source, aliases, limits):
            return None
        if _is_exclusive_temp(flags, resource, scope, source, aliases, limits):
            return None
        permission_node = values[2] if len(values) >= 3 else None
        permission = _permission_value(permission_node, scope, source, aliases, limits)
        detail = _permission_detail(permission, permission_node is None)
    elif operation_name in {"mkdir", "mkdirSync"}:
        options = values[1] if len(values) >= 2 else None
        permission_node = _option_value(options, "mode", scope, source, limits)
        permission = _permission_value(permission_node, scope, source, aliases, limits)
        detail = _permission_detail(permission, permission_node is None, directory=True)
    elif operation_name in {"chmod", "chmodSync"}:
        permission_node = values[1] if len(values) >= 2 else None
        permission = _permission_value(permission_node, scope, source, aliases, limits)
        detail = _permission_detail(permission, permission_node is None)
    else:
        return None
    if detail is None:
        return None
    return _range(resource), _range(node), operation, permission, detail


def _option_value(
    node: Node | None,
    name: str,
    scope: Node,
    source: bytes,
    limits: EcmaScriptCwe732ScanLimits,
    depth: int = 0,
    visited: frozenset[str] = frozenset(),
) -> Node | None:
    if node is None:
        return None
    if depth > limits.max_resolution_depth:
        raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.DEPTH_LIMIT)
    if node.type == "identifier":
        identifier = _text(source, node)
        if identifier in visited:
            return None
        bound = _latest_binding(scope, identifier, node.start_byte, source)
        if bound is None:
            return None
        return _option_value(
            bound,
            name,
            scope,
            source,
            limits,
            depth + 1,
            visited | {identifier},
        )
    if node.type != "object":
        return None
    for child in node.named_children:
        if child.type in {"pair", "object_pattern_property"}:
            key = child.child_by_field_name("key")
            value = child.child_by_field_name("value")
            if key is None:
                named = child.named_children
                key = named[0] if named else None
            if value is None:
                named = child.named_children
                value = named[-1] if len(named) >= 2 else key
            if key is not None and _property_name(key, source) == name:
                return value
        elif child.type in {"shorthand_property_identifier", "shorthand_property_identifier_pattern"}:
            if _property_name(child, source) == name:
                return child
    return None


def _property_name(node: Node, source: bytes) -> str:
    value = _text(source, node).strip()
    if len(value) >= 2 and value[:1] in {"'", '"', "`"} and value[-1:] == value[:1]:
        return value[1:-1]
    return value


def _permission_value(
    node: Node | None,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe732ScanLimits,
) -> int | None:
    if node is None:
        return None
    value = _integer_value(node, scope, source, aliases, limits, 0, frozenset())
    if value is None or value < 0 or value > 0o7777:
        return None
    return value


def _integer_value(
    node: Node | None,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe732ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> int | None:
    if node is None:
        return None
    if depth > limits.max_resolution_depth:
        raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.DEPTH_LIMIT)
    if node.type == "identifier":
        name = _text(source, node)
        if name in visited:
            return None
        bound = _latest_binding(scope, name, node.start_byte, source)
        if bound is None:
            return None
        return _integer_value(
            bound, scope, source, aliases, limits, depth + 1, visited | {name}
        )
    if node.type in {"number", "number_literal"}:
        return _parse_number(_text(source, node))
    if node.type == "parenthesized_expression":
        children = node.named_children
        return _integer_value(children[0] if children else None, scope, source, aliases, limits, depth + 1, visited)
    if node.type == "unary_expression":
        children = node.named_children
        if not children:
            return None
        value = _integer_value(children[-1], scope, source, aliases, limits, depth + 1, visited)
        if value is None:
            return None
        operator = _operator_before(source, node, children[-1])
        if operator == "~":
            return (~value) & 0o7777
        if operator == "+":
            return value
        if operator == "-":
            return -value
        return None
    if node.type == "binary_expression":
        children = node.named_children
        if len(children) != 2:
            return None
        left = _integer_value(children[0], scope, source, aliases, limits, depth + 1, visited)
        right = _integer_value(children[1], scope, source, aliases, limits, depth + 1, visited)
        if left is None or right is None:
            return None
        operator = _operator_between(source, children[0], children[1])
        try:
            if operator == "|":
                return left | right
            if operator == "&":
                return left & right
            if operator == "^":
                return left ^ right
            if operator == "<<":
                return left << right
            if operator == ">>":
                return left >> right
            if operator == "+":
                return left + right
            if operator == "-":
                return left - right
        except (ValueError, OverflowError):
            return None
        return None
    canonical = _canonical_expression(node, source, aliases)
    if canonical is not None:
        return _FLAG_VALUES.get(canonical)
    return None


def _parse_number(value: str) -> int | None:
    compact = value.replace("_", "")
    try:
        if compact.lower().startswith(("0x", "0o", "0b")):
            result = int(compact, 0)
        elif re.fullmatch(r"[0-9]+", compact):
            result = int(compact, 10)
        else:
            return None
    except ValueError:
        return None
    return result if abs(result) <= 0xFFFFFFFF else None


def _operator_between(source: bytes, left: Node, right: Node) -> str:
    try:
        text = source[left.end_byte : right.start_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.INTEGRITY_FAILURE) from None
    return text.strip()


def _operator_before(source: bytes, node: Node, operand: Node) -> str:
    try:
        text = source[node.start_byte : operand.start_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.INTEGRITY_FAILURE) from None
    return text.strip()


def _permission_detail(
    permission: int | None,
    missing: bool,
    *,
    directory: bool = False,
) -> str | None:
    if missing:
        return "missing_restrictive_mode"
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


def _is_write_open(
    node: Node | None,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe732ScanLimits,
) -> bool:
    if node is None:
        return False
    text = _string_value(node, source)
    if text is not None:
        return not text or text[0] in {"w", "a", "x"} or "+" in text
    value = _integer_value(node, scope, source, aliases, limits, 0, frozenset())
    if value is None:
        return True
    return bool(value & (0x1 | 0x2 | 0x400))


def _is_exclusive_temp(
    flags: Node | None,
    resource: Node,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe732ScanLimits,
) -> bool:
    if not _is_temp_resource(resource, scope, source, limits):
        return False
    text = _string_value(flags, source) if flags is not None else None
    if text is not None:
        return "x" in text
    value = _integer_value(flags, scope, source, aliases, limits, 0, frozenset())
    return value is not None and bool(value & 0x80)


def _is_sensitive_resource(
    node: Node,
    scope: Node,
    source: bytes,
    limits: EcmaScriptCwe732ScanLimits,
    depth: int = 0,
    visited: frozenset[str] = frozenset(),
) -> bool:
    if depth > limits.max_resolution_depth:
        raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.DEPTH_LIMIT)
    if node.type == "identifier":
        name = _text(source, node)
        if name in visited:
            return False
        bound = _latest_binding(scope, name, node.start_byte, source)
        return (
            _is_sensitive_resource(bound, scope, source, limits, depth + 1, visited | {name})
            if bound is not None
            else _sensitive_text(name)
        )
    if node.type in {"string", "string_fragment", "template_string", "template_substitution"}:
        return _sensitive_text(_text(source, node))
    compact = _compact_text(source, node)
    if _sensitive_text(compact):
        return True
    if node.type in {
        "binary_expression",
        "template_string",
        "template_substitution",
        "call_expression",
        "arguments",
        "array",
        "member_expression",
        "subscript_expression",
        "parenthesized_expression",
    }:
        return any(
            _is_sensitive_resource(child, scope, source, limits, depth + 1, visited)
            for child in node.named_children
        )
    return False


def _is_temp_resource(
    node: Node,
    scope: Node,
    source: bytes,
    limits: EcmaScriptCwe732ScanLimits,
    depth: int = 0,
    visited: frozenset[str] = frozenset(),
) -> bool:
    if depth > limits.max_resolution_depth:
        raise EcmaScriptCwe732ScanError(EcmaScriptCwe732ScanErrorCode.DEPTH_LIMIT)
    compact = _compact_text(source, node).lower()
    if any(token in compact for token in ("tmp", "temp", "temporary")):
        return True
    if node.type == "identifier":
        name = _text(source, node)
        if name in visited:
            return False
        bound = _latest_binding(scope, name, node.start_byte, source)
        return (
            _is_temp_resource(bound, scope, source, limits, depth + 1, visited | {name})
            if bound is not None
            else False
        )
    return any(
        _is_temp_resource(child, scope, source, limits, depth + 1, visited)
        for child in node.named_children
        if child.type in {"call_expression", "arguments", "member_expression", "string", "template_string"}
    )


def _sensitive_text(value: str) -> bool:
    lowered = value.lower().replace("\\", "/").strip("'\"`")
    if any(lowered.endswith(suffix) for suffix in _SENSITIVE_SUFFIXES):
        return True
    tokens = {token for token in re.split(r"[^a-z0-9]+", lowered) if token}
    return bool(tokens & _SENSITIVE_WORDS)


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
    operation: EcmaScriptCwe732Operation,
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
    signals: tuple[EcmaScriptCwe732Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
        "language": language,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
                "detail": signal.detail,
                "operation": signal.operation.value,
                "permission": signal.permission,
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


Cwe732ScanErrorCode = EcmaScriptCwe732ScanErrorCode
Cwe732ScanError = EcmaScriptCwe732ScanError
Cwe732ScanLimits = EcmaScriptCwe732ScanLimits
Cwe732ScanResult = EcmaScriptCwe732ScanResult
Cwe732Signal = EcmaScriptCwe732Signal


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE732_SCAN_LIMITS",
    "Cwe732ScanError",
    "Cwe732ScanErrorCode",
    "Cwe732ScanLimits",
    "Cwe732ScanResult",
    "Cwe732Signal",
    "EcmaScriptCwe732Operation",
    "EcmaScriptCwe732ScanError",
    "EcmaScriptCwe732ScanErrorCode",
    "EcmaScriptCwe732ScanLimits",
    "EcmaScriptCwe732ScanResult",
    "EcmaScriptCwe732Signal",
    "scan_ecmascript_cwe732",
    "scan_javascript_cwe732",
    "scan_typescript_cwe732",
]
