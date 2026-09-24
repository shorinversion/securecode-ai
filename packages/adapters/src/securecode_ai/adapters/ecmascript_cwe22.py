"""Bounded JavaScript and TypeScript source-to-filesystem facts for CWE-22.

The scanner accepts a sealed ECMAScript :class:`~securecode_ai.core.SymbolIndex`
and re-parses the exact admitted bytes through the existing CST adapter.  It
recognises only a small, explicit set of request sources, path-preserving
expressions, and Node.js filesystem APIs.  Results contain source locations and
content-addressed metadata only: source text is never copied into a signal or
an error.  A signal is a structural fact for downstream policy, not a finding
or a verdict.
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

_MAX_LIMITS = (2_000_000, 250_000, 512, 10_000)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_RULE_ID = "securecode-ecmascript-cwe22"
_DETECTOR = "securecode-ecmascript-cwe22@1.0"

_FS_MODULES = frozenset({"fs", "fs/promises"})
_PATH_MODULES = frozenset({"path", "path/posix", "path/win32"})
_PATH_BUILDERS = frozenset({"join", "resolve", "normalize", "relative"})
_PRESERVING_FUNCTIONS = frozenset(
    {
        "String",
        "decodeURI",
        "decodeURIComponent",
        "encodeURI",
        "encodeURIComponent",
    }
)
_REQUEST_ROOTS = frozenset(
    {"ctx", "context", "event", "httpRequest", "req", "request"}
)
_REQUEST_FIELDS = frozenset(
    {
        "body",
        "cookies",
        "headers",
        "params",
        "path",
        "pathParameters",
        "query",
        "queryStringParameters",
    }
)
_FS_OPERATION_NAMES = frozenset(
    {
        "access",
        "accessSync",
        "appendFile",
        "appendFileSync",
        "chmod",
        "chmodSync",
        "chown",
        "chownSync",
        "copyFile",
        "copyFileSync",
        "cp",
        "cpSync",
        "createReadStream",
        "createWriteStream",
        "exists",
        "existsSync",
        "lstat",
        "lstatSync",
        "mkdir",
        "mkdirSync",
        "mkdtemp",
        "mkdtempSync",
        "open",
        "openSync",
        "readFile",
        "readFileSync",
        "readlink",
        "readlinkSync",
        "readdir",
        "readdirSync",
        "realpath",
        "realpathSync",
        "rename",
        "renameSync",
        "rm",
        "rmSync",
        "rmdir",
        "rmdirSync",
        "stat",
        "statSync",
        "symlink",
        "symlinkSync",
        "truncate",
        "truncateSync",
        "unlink",
        "unlinkSync",
        "utimes",
        "utimesSync",
        "writeFile",
        "writeFileSync",
    }
)
_TWO_PATH_OPERATIONS = frozenset(
    {"copyFile", "copyFileSync", "cp", "cpSync", "rename", "renameSync", "symlink", "symlinkSync"}
)


class EcmaScriptCwe22ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-22 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe22ScanError(RuntimeError):
    """Fixed scanner failure that never includes repository or parser text."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe22ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe22ScanErrorCode:
            raise TypeError("ECMAScript CWE-22 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-22 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe22ScanLimits:
    """Hard ceilings applied before and during structural analysis."""

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
            raise ValueError("ECMAScript CWE-22 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE22_SCAN_LIMITS = EcmaScriptCwe22ScanLimits()


class EcmaScriptCwe22Operation(StrEnum):
    """Filesystem operation receiving a request-controlled path."""

    ACCESS = "access"
    ACCESS_SYNC = "accessSync"
    APPEND_FILE = "appendFile"
    APPEND_FILE_SYNC = "appendFileSync"
    CHMOD = "chmod"
    CHMOD_SYNC = "chmodSync"
    CHOWN = "chown"
    CHOWN_SYNC = "chownSync"
    COPY_FILE = "copyFile"
    COPY_FILE_SYNC = "copyFileSync"
    CP = "cp"
    CP_SYNC = "cpSync"
    CREATE_READ_STREAM = "createReadStream"
    CREATE_WRITE_STREAM = "createWriteStream"
    EXISTS = "exists"
    EXISTS_SYNC = "existsSync"
    LSTAT = "lstat"
    LSTAT_SYNC = "lstatSync"
    MKDIR = "mkdir"
    MKDIR_SYNC = "mkdirSync"
    MKDTEMP = "mkdtemp"
    MKDTEMP_SYNC = "mkdtempSync"
    OPEN = "open"
    OPEN_SYNC = "openSync"
    READ_FILE = "readFile"
    READ_FILE_SYNC = "readFileSync"
    READLINK = "readlink"
    READLINK_SYNC = "readlinkSync"
    READDIR = "readdir"
    READDIR_SYNC = "readdirSync"
    REALPATH = "realpath"
    REALPATH_SYNC = "realpathSync"
    RENAME = "rename"
    RENAME_SYNC = "renameSync"
    RM = "rm"
    RM_SYNC = "rmSync"
    RMDIR = "rmdir"
    RMDIR_SYNC = "rmdirSync"
    STAT = "stat"
    STAT_SYNC = "statSync"
    SYMLINK = "symlink"
    SYMLINK_SYNC = "symlinkSync"
    TRUNCATE = "truncate"
    TRUNCATE_SYNC = "truncateSync"
    UNLINK = "unlink"
    UNLINK_SYNC = "unlinkSync"
    UTIMES = "utimes"
    UTIMES_SYNC = "utimesSync"
    WRITE_FILE = "writeFile"
    WRITE_FILE_SYNC = "writeFileSync"


_OPERATIONS = {item.value: item for item in EcmaScriptCwe22Operation}


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe22Signal:
    """One source-free request-to-filesystem fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe22Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-22"
    detector: str = _DETECTOR
    detail: str = "untrusted_path_to_filesystem"

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
            and self.source.end_byte <= self.sink.end_byte
            and self.source.start_byte <= self.sink.end_byte
            and self.source.end_byte <= self.source_size_bytes
            and self.sink.end_byte <= self.source_size_bytes
        )
        expected = _signal_id(
            self.repository_id,
            self.revision,
            self.path,
            self.content_sha256,
            self.source_size_bytes,
            self.source,
            self.sink,
            self.operation,
        ) if valid_ranges and type(self.operation) is EcmaScriptCwe22Operation else ""
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not EcmaScriptCwe22Operation
            or type(self.signal_id) is not str
            or self.signal_id not in {"", expected}
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-22"
            or self.detector != _DETECTOR
            or self.detail != "untrusted_path_to_filesystem"
        ):
            raise ValueError("ECMAScript CWE-22 signal is invalid")
        if self.signal_id == "":
            object.__setattr__(self, "signal_id", expected)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name for generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the sink location used by generic scanner consumers."""

        return self.sink


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe22ScanResult:
    """Deterministic, source-free result for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe22Signal, ...]
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
            or any(type(item) is not EcmaScriptCwe22Signal for item in self.signals)
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
                self.language,
                self.signals,
            )
        ):
            raise ValueError("ECMAScript CWE-22 scan result is invalid")


def scan_javascript_cwe22(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe22ScanLimits = DEFAULT_ECMASCRIPT_CWE22_SCAN_LIMITS,
) -> EcmaScriptCwe22ScanResult:
    """Find bounded JavaScript request-to-filesystem path facts."""

    return _scan_ecmascript_cwe22(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe22(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe22ScanLimits = DEFAULT_ECMASCRIPT_CWE22_SCAN_LIMITS,
) -> EcmaScriptCwe22ScanResult:
    """Find bounded TypeScript request-to-filesystem path facts."""

    return _scan_ecmascript_cwe22(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe22(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe22ScanLimits = DEFAULT_ECMASCRIPT_CWE22_SCAN_LIMITS,
) -> EcmaScriptCwe22ScanResult:
    """Dispatch a CWE-22 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe22(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe22(symbol_index, limits=limits)
    raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe22(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe22ScanLimits,
) -> EcmaScriptCwe22ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe22ScanLimits:
        raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.ANALYSIS_UNAVAILABLE)

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
        raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.INTEGRITY_FAILURE) from None

    nodes = _bounded_nodes(root, limits)
    if any(node.type == "ERROR" or node.is_missing for node in nodes):
        raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.ANALYSIS_UNAVAILABLE)

    aliases = _collect_aliases(nodes, source)
    raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe22Operation]] = set()
    try:
        for node in nodes:
            if node.type != "call_expression":
                continue
            operation = _operation_for_call(node, source, aliases)
            if operation is None:
                continue
            arguments = node.child_by_field_name("arguments")
            if arguments is None:
                raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.INTEGRITY_FAILURE)
            scope = _enclosing_scope(node, root)
            for argument in _sink_arguments(arguments, operation):
                for source_node in _resolve_source(
                    argument,
                    scope=scope,
                    source=source,
                    aliases=aliases,
                    limits=limits,
                    depth=0,
                    visited=frozenset(),
                ):
                    raw.add((_range(source_node), _range(node), operation))
                    if len(raw) > limits.max_signals:
                        raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.SIGNAL_LIMIT)
    except EcmaScriptCwe22ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.INTEGRITY_FAILURE) from None

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
        raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        EcmaScriptCwe22Signal(
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
    return EcmaScriptCwe22ScanResult(
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


def _bounded_nodes(root: Node, limits: EcmaScriptCwe22ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _operation_for_call(
    node: Node, source: bytes, aliases: dict[str, str]
) -> EcmaScriptCwe22Operation | None:
    function = node.child_by_field_name("function")
    if function is None:
        return None
    canonical = _canonical_expression(function, source, aliases)
    if canonical is None:
        return None
    parts = canonical.split(".")
    if len(parts) < 2 or parts[-1] not in _FS_OPERATION_NAMES:
        return None
    module = ".".join(parts[:-1])
    if module not in _FS_MODULES:
        return None
    return _OPERATIONS.get(parts[-1])


def _sink_arguments(
    arguments: Node, operation: EcmaScriptCwe22Operation
) -> tuple[Node, ...]:
    values = arguments.named_children
    if not values:
        return ()
    if operation.value in _TWO_PATH_OPERATIONS:
        return tuple(values[:2])
    return (values[0],)


def _resolve_source(
    node: Node,
    *,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe22ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[Node, ...]:
    if depth > limits.max_depth:
        raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.DEPTH_LIMIT)
    if _is_request_source(node, source):
        return (node,)
    if node.type == "identifier":
        name = _text(source, node)
        if name in visited:
            return ()
        bound = _latest_binding(scope, name, node.start_byte, source)
        if bound is None:
            return ()
        return _resolve_source(
            bound,
            scope=scope,
            source=source,
            aliases=aliases,
            limits=limits,
            depth=depth + 1,
            visited=visited | {name},
        )
    if node.type in {
        "await_expression",
        "parenthesized_expression",
        "non_null_expression",
        "unary_expression",
        "update_expression",
    }:
        return _resolve_children(
            node, scope, source, aliases, limits, depth + 1, visited
        )
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            return ()
        canonical = _canonical_expression(function, source, aliases)
        if canonical is not None and (
            _is_path_builder(canonical) or canonical in _PRESERVING_FUNCTIONS
        ):
            return _resolve_children(
                arguments, scope, source, aliases, limits, depth + 1, visited
            )
        return ()
    if node.type in {
        "binary_expression",
        "conditional_expression",
        "assignment_expression",
        "ternary_expression",
        "template_substitution",
        "template_string",
        "sequence_expression",
        "logical_expression",
    }:
        return _resolve_children(node, scope, source, aliases, limits, depth + 1, visited)
    if node.type in {"member_expression", "subscript_expression"}:
        return _resolve_children(node, scope, source, aliases, limits, depth + 1, visited)
    return ()


def _resolve_children(
    node: Node,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe22ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[Node, ...]:
    values: list[Node] = []
    for child in node.named_children:
        values.extend(
            _resolve_source(
                child,
                scope=scope,
                source=source,
                aliases=aliases,
                limits=limits,
                depth=depth,
                visited=visited,
            )
        )
    unique: dict[tuple[int, int], Node] = {}
    for value in values:
        unique[(value.start_byte, value.end_byte)] = value
    return tuple(unique[key] for key in sorted(unique))


def _is_path_builder(canonical: str) -> bool:
    parts = canonical.split(".")
    if len(parts) != 2 or parts[0] not in _PATH_MODULES:
        return False
    return parts[1] in _PATH_BUILDERS


def _is_request_source(node: Node, source: bytes) -> bool:
    compact = _compact_text(source, node)
    normalized = compact.replace("?.", ".")
    if node.type in {"member_expression", "subscript_expression"}:
        return _member_request_source(normalized)
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    if function is None:
        return False
    callee = _compact_text(source, function).replace("?.", ".")
    arguments = node.child_by_field_name("arguments")
    return bool(arguments and _call_request_source(callee, normalized))


def _member_request_source(value: str) -> bool:
    pieces = value.replace("[", ".[").split(".")
    if len(pieces) < 3 or pieces[0] not in _REQUEST_ROOTS:
        return False
    index = 1
    if pieces[index] == "request":
        index += 1
    if index >= len(pieces) or pieces[index] not in _REQUEST_FIELDS:
        return False
    return len(pieces) > index + 1 and any(part for part in pieces[index + 1 :])


def _call_request_source(callee: str, expression: str) -> bool:
    pieces = callee.replace("[", ".[").split(".")
    if not pieces or pieces[0] not in _REQUEST_ROOTS:
        if not re.search(r"(?:^|\.)searchParams\.get\Z", callee):
            return False
    if callee.endswith(".get") or callee.endswith(".param") or callee.endswith(".header"):
        if pieces[0] in _REQUEST_ROOTS:
            return len(pieces) >= 2 and (
                pieces[-2] in _REQUEST_FIELDS or pieces[-1] in {"param", "header"}
            )
        return callee.endswith(".searchParams.get")
    return False


def _enclosing_scope(node: Node, root: Node) -> Node:
    current = node.parent
    while current is not None:
        if current.type in {
            "function_declaration",
            "function",
            "function_expression",
            "arrow_function",
            "generator_function",
            "generator_function_declaration",
            "method_definition",
        }:
            return current
        current = current.parent
    return root


def _latest_binding(scope: Node, name: str, before: int, source: bytes) -> Node | None:
    bound: Node | None = None
    for node in _scope_preorder(scope):
        if node.start_byte >= before:
            continue
        if node.type == "variable_declarator":
            left = node.child_by_field_name("name")
            right = node.child_by_field_name("value")
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
        else:
            continue
        if left is not None and right is not None and left.type == "identifier":
            if _text(source, left) == name:
                bound = right
    return bound


def _scope_preorder(scope: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    nested = {
        "function_declaration",
        "function",
        "function_expression",
        "arrow_function",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
    first = True
    while stack:
        node = stack.pop()
        output.append(node)
        if not first and node.type in nested:
            continue
        first = False
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _collect_aliases(nodes: tuple[Node, ...], source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in nodes:
        if node.type == "import_statement":
            _collect_import_aliases(node, source, aliases)
        elif node.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in node.named_children:
                if declarator.type != "variable_declarator":
                    continue
                name = declarator.child_by_field_name("name")
                value = declarator.child_by_field_name("value")
                if name is None or value is None:
                    continue
                canonical = _canonical_expression(value, source, aliases)
                if canonical is None:
                    continue
                if name.type == "identifier":
                    aliases[_text(source, name)] = canonical
                elif name.type in {"object_pattern", "object"}:
                    _collect_pattern_aliases(name, canonical, source, aliases)
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                canonical = _canonical_expression(right, source, aliases)
                if canonical is not None:
                    aliases[_text(source, left)] = canonical
    return aliases


def _collect_import_aliases(node: Node, source: bytes, aliases: dict[str, str]) -> None:
    module_node = node.child_by_field_name("source")
    if module_node is None:
        return
    module = _string_value(module_node, source)
    if module is None:
        return
    module = _normalise_module(module)
    if module not in _FS_MODULES | _PATH_MODULES:
        return
    for clause in node.named_children:
        if clause.type != "import_clause":
            continue
        for item in clause.named_children:
            if item.type == "identifier":
                aliases[_text(source, item)] = module
            elif item.type == "namespace_import":
                children = item.named_children
                if children:
                    aliases[_text(source, children[-1])] = module
            elif item.type in {"named_imports", "named_import"}:
                for specifier in item.named_children:
                    if specifier.type != "import_specifier":
                        continue
                    names = list(specifier.named_children)
                    if len(names) < 1:
                        continue
                    imported = _text(source, names[0])
                    local = _text(source, names[-1])
                    aliases[local] = f"{module}.{imported}"


def _collect_pattern_aliases(
    pattern: Node, module: str, source: bytes, aliases: dict[str, str]
) -> None:
    for child in pattern.named_children:
        if child.type not in {
            "pair",
            "object_pattern_property",
            "shorthand_property_identifier_pattern",
        }:
            continue
        key = child.child_by_field_name("key") or child
        value = child.child_by_field_name("value") or key
        if key.type not in {"identifier", "property_identifier", "string"} or value.type not in {
            "identifier",
            "property_identifier",
            "string",
        }:
            continue
        key_text = _text(source, key).strip("'\"")
        local = _text(source, value).strip("'\"")
        if key_text == "promises" and module == "fs":
            aliases[local] = "fs/promises"
        else:
            aliases[local] = f"{module}.{key_text}"


def _canonical_expression(node: Node, source: bytes, aliases: dict[str, str]) -> str | None:
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or _compact_text(source, function) != "require":
            return None
        values = arguments.named_children
        if len(values) != 1:
            return None
        module = _string_value(values[0], source)
        return _normalise_module(module) if module in _FS_MODULES | _PATH_MODULES else None
    if node.type == "member_expression":
        object_node = node.child_by_field_name("object")
        property_node = node.child_by_field_name("property")
        if object_node is None or property_node is None:
            return None
        base = _canonical_expression(object_node, source, aliases)
        if base is None:
            base = _canonical_name(_compact_text(source, object_node), aliases)
        property_name = _text(source, property_node)
        if base == "fs" and property_name == "promises":
            return "fs/promises"
        if base not in _FS_MODULES | _PATH_MODULES and base not in aliases.values():
            return None
        return f"{base}.{property_name}"
    return _canonical_name(_compact_text(source, node), aliases)


def _canonical_name(value: str, aliases: dict[str, str]) -> str:
    parts = value.split(".")
    if not parts or not _IDENTIFIER.fullmatch(parts[0]):
        return value
    base = aliases.get(parts[0], parts[0])
    if len(parts) == 1:
        return base
    return ".".join((base, *parts[1:]))


def _normalise_module(value: str | None) -> str | None:
    if value is None:
        return None
    return value[5:] if value.startswith("node:") else value


def _string_value(node: Node, source: bytes) -> str | None:
    if node.type not in {"string", "string_fragment"}:
        return None
    value = source[node.start_byte : node.end_byte]
    if node.type == "string":
        if len(value) < 2 or value[:1] not in {b"'", b'"', b"`"} or value[-1:] != value[:1]:
            return None
        value = value[1:-1]
    if b"\\" in value or b"\n" in value or b"\r" in value:
        return None
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.INTEGRITY_FAILURE) from None


def _text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe22ScanError(EcmaScriptCwe22ScanErrorCode.INTEGRITY_FAILURE) from None


def _compact_text(source: bytes, node: Node) -> str:
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
    operation: EcmaScriptCwe22Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-22",
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    language: str,
    signals: tuple[EcmaScriptCwe22Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-22",
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


def scan_javascript_cwe22_path_traversal(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe22ScanLimits = DEFAULT_ECMASCRIPT_CWE22_SCAN_LIMITS,
) -> EcmaScriptCwe22ScanResult:
    """Descriptive alias for :func:`scan_javascript_cwe22`."""

    return scan_javascript_cwe22(symbol_index, limits=limits)


def scan_typescript_cwe22_path_traversal(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe22ScanLimits = DEFAULT_ECMASCRIPT_CWE22_SCAN_LIMITS,
) -> EcmaScriptCwe22ScanResult:
    """Descriptive alias for :func:`scan_typescript_cwe22`."""

    return scan_typescript_cwe22(symbol_index, limits=limits)


def scan_ecmascript_cwe22_path_traversal(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe22ScanLimits = DEFAULT_ECMASCRIPT_CWE22_SCAN_LIMITS,
) -> EcmaScriptCwe22ScanResult:
    """Descriptive alias for :func:`scan_ecmascript_cwe22`."""

    return scan_ecmascript_cwe22(symbol_index, limits=limits)


scan_javascript_path_traversal = scan_javascript_cwe22
scan_typescript_path_traversal = scan_typescript_cwe22
scan_ecmascript_path_traversal = scan_ecmascript_cwe22


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE22_SCAN_LIMITS",
    "EcmaScriptCwe22Operation",
    "EcmaScriptCwe22ScanError",
    "EcmaScriptCwe22ScanErrorCode",
    "EcmaScriptCwe22ScanLimits",
    "EcmaScriptCwe22ScanResult",
    "EcmaScriptCwe22Signal",
    "scan_ecmascript_cwe22",
    "scan_ecmascript_cwe22_path_traversal",
    "scan_ecmascript_path_traversal",
    "scan_javascript_cwe22",
    "scan_javascript_cwe22_path_traversal",
    "scan_javascript_path_traversal",
    "scan_typescript_cwe22",
    "scan_typescript_cwe22_path_traversal",
    "scan_typescript_path_traversal",
]
