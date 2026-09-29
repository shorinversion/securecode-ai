"""Bounded JavaScript and TypeScript command-injection facts for CWE-78.

The scanner consumes a sealed ECMAScript :class:`~securecode_ai.core.SymbolIndex`
and reparses the exact admitted bytes before inspecting the CST.  It follows a
small allow-list of ``child_process`` command sinks and local aliases, and
tracks explicit request and environment sources through concatenations,
templates, and local bindings.  Shell escaping helpers are treated as
sanitizers.  Results contain immutable source ranges and content-addressed
metadata only; source text is never retained or copied into an error.
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
_RULE_ID = "securecode-ecmascript-cwe78"
_DETECTOR = "securecode-ecmascript-cwe78@1.0"

_CHILD_PROCESS_MODULES = frozenset({"child_process"})
_SANITIZER_MODULES = frozenset({"shell-escape", "shell-quote", "command-args"})
_REQUEST_ROOTS = frozenset({"ctx", "context", "event", "httpRequest", "req", "request", "http"})
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
        "searchParams",
        "querystring",
    }
)
_ENV_ROOTS = frozenset({"env", "environment", "process.env"})
_PRESERVING_FUNCTIONS = frozenset(
    {
        "String",
        "Number",
        "Boolean",
        "decodeURI",
        "decodeURIComponent",
        "encodeURI",
        "encodeURIComponent",
        "String.raw",
        "Buffer.from",
        "JSON.stringify",
    }
)
_PRESERVING_METHODS = frozenset({"trim", "toString", "valueOf", "replace", "replaceAll"})
_SANITIZERS = frozenset(
    {
        "shellEscape",
        "shell_escape",
        "escapeShell",
        "escapeShellArg",
        "escape_shell_arg",
        "escapeArg",
        "escape_arg",
        "quoteShell",
        "quote_shell",
        "shellQuote",
        "shell_quote",
        "shell-escape",
        "shell-escape.quote",
        "shell-quote",
        "shell-quote.quote",
        "shellQuote.quote",
        "shellEscape.quote",
        "quote",
        "escape",
        "command-args",
        "commandArgs",
    }
)


class EcmaScriptCwe78ScanErrorCode(StrEnum):
    """Closed, source-free reasons a scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe78ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe78ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe78ScanErrorCode:
            raise TypeError("ECMAScript CWE-78 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-78 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class EcmaScriptCwe78Operation(StrEnum):
    """Recognized command execution operations."""

    EXEC = "child_process.exec"
    EXEC_SYNC = "child_process.execSync"
    EXEC_FILE = "child_process.execFile(shell)"
    EXEC_FILE_SYNC = "child_process.execFileSync(shell)"

    # Descriptive names for callers grouping Node child-process operations.
    CHILD_PROCESS_EXEC = "child_process.exec"
    CHILD_PROCESS_EXEC_SYNC = "child_process.execSync"
    CHILD_PROCESS_EXEC_FILE = "child_process.execFile(shell)"
    CHILD_PROCESS_EXEC_FILE_SYNC = "child_process.execFileSync(shell)"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe78ScanLimits:
    """Hard ceilings applied before and during structural data-flow analysis."""

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
            raise ValueError("ECMAScript CWE-78 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE78_SCAN_LIMITS = EcmaScriptCwe78ScanLimits()


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe78Signal:
    """One immutable external-input-to-command-sink fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe78Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-78"
    detector: str = _DETECTOR
    detail: str = "untrusted_command_to_child_process"

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
            if valid_identity and valid_ranges and type(self.operation) is EcmaScriptCwe78Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not EcmaScriptCwe78Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-78"
            or self.detector != _DETECTOR
            or self.detail != "untrusted_command_to_child_process"
        ):
            raise ValueError("ECMAScript CWE-78 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete child-process call location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe78ScanResult:
    """Deterministic, source-free result for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe78Signal, ...]
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
        valid_signals = type(self.signals) is tuple and all(
            type(item) is EcmaScriptCwe78Signal for item in self.signals
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
        same_identity = valid_signals and all(
            item.repository_id == self.repository_id
            and item.revision == self.revision
            and item.path == self.path
            and item.content_sha256 == self.content_sha256
            and item.source_size_bytes == self.source_size_bytes
            for item in self.signals
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
                self.language,
                self.signals,
            )
        ):
            raise ValueError("ECMAScript CWE-78 scan result is invalid")


def scan_javascript_cwe78(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe78ScanLimits = DEFAULT_ECMASCRIPT_CWE78_SCAN_LIMITS,
) -> EcmaScriptCwe78ScanResult:
    """Find bounded JavaScript request/environment-to-command facts."""

    return _scan_ecmascript_cwe78(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe78(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe78ScanLimits = DEFAULT_ECMASCRIPT_CWE78_SCAN_LIMITS,
) -> EcmaScriptCwe78ScanResult:
    """Find bounded TypeScript request/environment-to-command facts."""

    return _scan_ecmascript_cwe78(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe78(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe78ScanLimits = DEFAULT_ECMASCRIPT_CWE78_SCAN_LIMITS,
) -> EcmaScriptCwe78ScanResult:
    """Dispatch a CWE-78 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe78(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe78(symbol_index, limits=limits)
    raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe78(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe78ScanLimits,
) -> EcmaScriptCwe78ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe78ScanLimits:
        raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.ANALYSIS_UNAVAILABLE)

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
        raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.INTEGRITY_FAILURE) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.ANALYSIS_UNAVAILABLE)
        aliases = _collect_aliases(nodes, source)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe78Operation]] = set()
        for node in nodes:
            if node.type != "call_expression":
                continue
            scope = _enclosing_scope(node, root)
            operation = _operation_for_call(node, source, aliases, scope)
            if operation is None:
                continue
            arguments = node.child_by_field_name("arguments")
            if arguments is None:
                raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.INTEGRITY_FAILURE)
            values = list(arguments.named_children)
            if not values:
                continue
            command = values[0]
            for source_node in _resolve_source(
                command,
                scope=scope,
                source=source,
                aliases=aliases,
                limits=limits,
                depth=0,
                visited=frozenset(),
            ):
                source_range = _range(source_node)
                sink_range = _range(node)
                if not sink_range.contains(source_range):
                    raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.INTEGRITY_FAILURE)
                raw.add((source_range, sink_range, operation))
                if len(raw) > limits.max_signals:
                    raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.SIGNAL_LIMIT)
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
    except EcmaScriptCwe78ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.INTEGRITY_FAILURE) from None

    if len(ordered) > limits.max_signals:
        raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        EcmaScriptCwe78Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
        )
        for source_range, sink_range, operation in ordered
    )
    return EcmaScriptCwe78ScanResult(
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


def _bounded_nodes(root: Node, limits: EcmaScriptCwe78ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _operation_for_call(
    node: Node, source: bytes, aliases: dict[str, str], scope: Node
) -> EcmaScriptCwe78Operation | None:
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None:
        return None
    canonical = _canonical_expression(function, source, aliases)
    direct = {
        "child_process.exec": EcmaScriptCwe78Operation.EXEC,
        "child_process.execSync": EcmaScriptCwe78Operation.EXEC_SYNC,
        "child_process.execFile": EcmaScriptCwe78Operation.EXEC_FILE,
        "child_process.execFileSync": EcmaScriptCwe78Operation.EXEC_FILE_SYNC,
    }.get(canonical or "")
    if direct in {
        EcmaScriptCwe78Operation.EXEC_FILE,
        EcmaScriptCwe78Operation.EXEC_FILE_SYNC,
    } and not _shell_option_enabled(arguments.named_children, source, scope):
        return None
    return direct


def _shell_option_enabled(values: list[Node], source: bytes, scope: Node) -> bool:
    """Return true only for an explicit literal ``shell: true`` option."""

    for value in values[1:]:
        candidate = value
        if candidate.type == "identifier":
            bound = _latest_binding(
                scope, _node_text(source, candidate), candidate.start_byte, source
            )
            if bound is None:
                continue
            candidate = bound
        if candidate.type != "object":
            continue
        for pair in candidate.named_children:
            if pair.type != "pair":
                continue
            key = pair.child_by_field_name("key")
            item = pair.child_by_field_name("value")
            if key is None or item is None or _static_property_name(key, source) != "shell":
                continue
            return _compact_text(source, item) == "true"
    return False


def _resolve_source(
    node: Node,
    *,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe78ScanLimits,
    depth: int,
    visited: frozenset[str],
) -> tuple[Node, ...]:
    if depth > limits.max_depth:
        raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.DEPTH_LIMIT)
    if _is_sanitizer_expression(node, source, aliases):
        return ()
    if _is_external_source(node, source):
        return (node,)
    if node.type == "identifier":
        name = _node_text(source, node)
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
        "as_expression",
        "type_assertion",
    }:
        return _resolve_children(node, scope, source, aliases, limits, depth + 1, visited)
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            return ()
        canonical = _canonical_expression(function, source, aliases)
        if canonical in _PRESERVING_FUNCTIONS or (
            canonical is not None and canonical.rsplit(".", 1)[-1] in _PRESERVING_METHODS
        ):
            return _resolve_children(
                node=arguments,
                scope=scope,
                source=source,
                aliases=aliases,
                limits=limits,
                depth=depth + 1,
                visited=visited,
            )
        return ()
    if node.type in {
        "binary_expression",
        "conditional_expression",
        "ternary_expression",
        "assignment_expression",
        "logical_expression",
        "template_substitution",
        "template_string",
        "sequence_expression",
        "object",
        "array",
        "pair",
        "arguments",
        "member_expression",
        "subscript_expression",
        "spread_element",
    }:
        return _resolve_children(node, scope, source, aliases, limits, depth + 1, visited)
    return ()


def _resolve_children(
    node: Node,
    scope: Node,
    source: bytes,
    aliases: dict[str, str],
    limits: EcmaScriptCwe78ScanLimits,
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


def _is_external_source(node: Node, source: bytes) -> bool:
    compact = _compact_text(source, node).replace("?.", ".")
    if node.type in {"member_expression", "subscript_expression"}:
        return _member_source(compact)
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None or not arguments.named_children:
        return False
    return _call_source(_compact_text(source, function))


def _member_source(value: str) -> bool:
    pieces = value.replace("[", ".[", 1).split(".")
    if len(pieces) < 2:
        return False
    if pieces[0] == "process" and pieces[1] == "env":
        return len(pieces) > 2 and any(part for part in pieces[2:])
    if pieces[0] in _ENV_ROOTS:
        return len(pieces) > 1 and any(part for part in pieces[1:])
    if pieces[0] not in _REQUEST_ROOTS:
        return False
    index = 1
    if index < len(pieces) and pieces[index] == "request":
        index += 1
    if index >= len(pieces):
        return False
    return pieces[index] in _REQUEST_FIELDS


def _call_source(callee: str) -> bool:
    compact = callee.replace("?.", ".").replace("[", ".[", 1)
    pieces = compact.split(".")
    if not pieces:
        return False
    if pieces[0] == "process" and len(pieces) >= 3 and pieces[1] == "env":
        return pieces[-1] in {"get", "getenv"}
    if pieces[0] not in _REQUEST_ROOTS:
        return False
    if pieces[-1] in {"get", "param", "header", "input", "query", "body"}:
        return len(pieces) >= 2
    return pieces[-1] in {"getQuery", "getParam", "getHeader", "getInput"}


def _is_sanitizer_expression(node: Node, source: bytes, aliases: dict[str, str]) -> bool:
    if node.type not in {"call_expression", "new_expression"}:
        return False
    function = node.child_by_field_name("function") or node.child_by_field_name("constructor")
    if function is None:
        return False
    canonical = _canonical_expression(function, source, aliases)
    if canonical in _SANITIZERS:
        return True
    return canonical is not None and canonical.rsplit(".", 1)[-1] in _SANITIZERS


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
        if (
            left is not None
            and right is not None
            and left.type == "identifier"
            and _node_text(source, left) == name
        ):
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
                if name.type == "identifier" and canonical is not None:
                    aliases[_node_text(source, name)] = canonical
                elif name.type in {"object_pattern", "object"} and canonical is not None:
                    _collect_destructured_aliases(name, canonical, source, aliases)
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                canonical = _canonical_expression(right, source, aliases)
                if canonical is not None:
                    aliases[_node_text(source, left)] = canonical
    return aliases


def _collect_import_aliases(node: Node, source: bytes, aliases: dict[str, str]) -> None:
    module_node = node.child_by_field_name("source")
    if module_node is None:
        return
    module = _string_value(module_node, source)
    if module is None:
        return
    module = _normalise_module(module)
    if module not in _CHILD_PROCESS_MODULES | _SANITIZER_MODULES:
        return
    for child in node.named_children:
        if child.type != "import_clause":
            continue
        for item in child.named_children:
            if item.type == "identifier":
                aliases[_node_text(source, item)] = module
            elif item.type == "namespace_import":
                names = item.named_children
                if names:
                    aliases[_node_text(source, names[-1])] = module
            elif item.type in {"named_imports", "named_import"}:
                for specifier in item.named_children:
                    if specifier.type != "import_specifier":
                        continue
                    names = list(specifier.named_children)
                    if names:
                        aliases[_node_text(source, names[-1])] = (
                            f"{module}.{_node_text(source, names[0])}"
                        )


def _collect_destructured_aliases(
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
        if key.type not in {"identifier", "property_identifier", "string"}:
            continue
        if value.type not in {"identifier", "property_identifier", "string"}:
            continue
        aliases[_node_text(source, value).strip("'\"")] = (
            f"{module}.{_node_text(source, key).strip(chr(39) + chr(34))}"
        )


def _canonical_expression(node: Node, source: bytes, aliases: dict[str, str]) -> str | None:
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or _compact_text(source, function) != "require":
            return None
        values = list(arguments.named_children)
        if len(values) != 1:
            return None
        module = _string_value(values[0], source)
        return _normalise_module(module) if module is not None else None
    if node.type in {"member_expression", "subscript_expression"}:
        object_node = node.child_by_field_name("object")
        property_node = node.child_by_field_name("property") or node.child_by_field_name("index")
        if object_node is None or property_node is None:
            return None
        base = _canonical_expression(object_node, source, aliases)
        if base is None:
            base = _canonical_name(_compact_text(source, object_node), aliases)
        name = _static_property_name(property_node, source)
        return f"{base}.{name}" if base and name else None
    return _canonical_name(_compact_text(source, node), aliases)


def _canonical_name(value: str, aliases: dict[str, str]) -> str:
    parts = value.split(".")
    if not parts or not _IDENTIFIER.fullmatch(parts[0]):
        return value
    base = aliases.get(parts[0], parts[0])
    if len(parts) == 1:
        return base
    return ".".join((base, *parts[1:]))


def _static_property_name(node: Node, source: bytes) -> str | None:
    if node.type == "computed_property_name":
        values = list(node.named_children)
        return _static_property_name(values[0], source) if len(values) == 1 else None
    if node.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        return _node_text(source, node)
    if node.type in {"string", "string_fragment"}:
        return _string_value(node, source)
    return None


def _normalise_module(value: str) -> str:
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
        raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.INTEGRITY_FAILURE) from None


def _node_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe78ScanError(EcmaScriptCwe78ScanErrorCode.INTEGRITY_FAILURE) from None


def _compact_text(source: bytes, node: Node | None) -> str:
    return "" if node is None else "".join(_node_text(source, node).split())


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
    operation: EcmaScriptCwe78Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-78",
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
    signals: tuple[EcmaScriptCwe78Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-78",
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


# Discoverable names for language-neutral callers.
scan_javascript_command_injection = scan_javascript_cwe78
scan_typescript_command_injection = scan_typescript_cwe78
scan_ecmascript_command_injection = scan_ecmascript_cwe78


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE78_SCAN_LIMITS",
    "EcmaScriptCwe78Operation",
    "EcmaScriptCwe78ScanError",
    "EcmaScriptCwe78ScanErrorCode",
    "EcmaScriptCwe78ScanLimits",
    "EcmaScriptCwe78ScanResult",
    "EcmaScriptCwe78Signal",
    "scan_ecmascript_command_injection",
    "scan_ecmascript_cwe78",
    "scan_javascript_command_injection",
    "scan_javascript_cwe78",
    "scan_typescript_command_injection",
    "scan_typescript_cwe78",
]
