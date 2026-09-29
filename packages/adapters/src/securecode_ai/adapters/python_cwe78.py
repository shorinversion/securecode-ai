"""Bounded Python command-injection facts for CWE-78.

The scanner consumes a sealed :class:`~securecode_ai.core.SymbolIndex` and
the matching sealed CPython AST analysis.  It follows only local aliases and
explicit request, environment, and input sources.  Shell-capable process
APIs are distinguished from argv-safe forms, and shell quoting helpers stop a
flow.  Results contain immutable ranges and content-addressed metadata only.
Repository source is never retained in a result or an error.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Iterable
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
_RULE_ID = "securecode-python-cwe78"
_DETECTOR = "securecode-python-cwe78@1.0"
_DETAIL_SHELL = "untrusted_command_to_shell"
_DETAIL_ARGV = "untrusted_command_token_to_argv"


class PythonCwe78ScanErrorCode(StrEnum):
    """Closed, source-free reasons a command-injection scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe78ScanError(RuntimeError):
    """Fixed Python CWE-78 failure which never echoes repository input."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe78ScanErrorCode) -> None:
        if type(code) is not PythonCwe78ScanErrorCode:
            raise TypeError("Python CWE-78 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-78 command-injection scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe78Operation(StrEnum):
    """Recognized command execution operations."""

    OS_SYSTEM = "os.system"
    OS_POPEN = "os.popen"
    SUBPROCESS_RUN = "subprocess.run"
    SUBPROCESS_CALL = "subprocess.call"
    SUBPROCESS_CHECK_CALL = "subprocess.check_call"
    SUBPROCESS_CHECK_OUTPUT = "subprocess.check_output"
    SUBPROCESS_POPEN = "subprocess.Popen"
    SUBPROCESS_GETOUTPUT = "subprocess.getoutput"
    SUBPROCESS_GETSTATUSOUTPUT = "subprocess.getstatusoutput"
    SUBPROCESS_ARGV = "subprocess.argv"


@dataclass(frozen=True, slots=True)
class PythonCwe78ScanLimits:
    """Hard ceilings for source, output, and local flow resolution."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_resolution_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Python CWE-78 scan limits are invalid")


DEFAULT_PYTHON_CWE78_SCAN_LIMITS = PythonCwe78ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe78Signal:
    """One immutable source-to-command-sink fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe78Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-78"
    detector: str = _DETECTOR
    detail: str = _DETAIL_SHELL

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
                self.detail,
            )
            if identity_valid and ranges_valid and type(self.operation) is PythonCwe78Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not PythonCwe78Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-78"
            or self.detector != _DETECTOR
            or self.detail not in {_DETAIL_SHELL, _DETAIL_ARGV}
        ):
            raise ValueError("Python CWE-78 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete command call location."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class PythonCwe78ScanResult:
    """Deterministic, source-free CWE-78 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe78Signal, ...]
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
            type(item) is PythonCwe78Signal for item in self.signals
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
            not identity_valid
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
            raise ValueError("Python CWE-78 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange


@dataclass(frozen=True, slots=True)
class _Sink:
    operation: PythonCwe78Operation
    argument_index: int
    argument_names: frozenset[str]
    shell_always: bool
    shell_capable: bool


_SHELL_CAPABLE: dict[str, PythonCwe78Operation] = {
    "subprocess.run": PythonCwe78Operation.SUBPROCESS_RUN,
    "subprocess.call": PythonCwe78Operation.SUBPROCESS_CALL,
    "subprocess.check_call": PythonCwe78Operation.SUBPROCESS_CHECK_CALL,
    "subprocess.check_output": PythonCwe78Operation.SUBPROCESS_CHECK_OUTPUT,
    "subprocess.Popen": PythonCwe78Operation.SUBPROCESS_POPEN,
}
_SHELL_ALWAYS: dict[str, PythonCwe78Operation] = {
    "os.system": PythonCwe78Operation.OS_SYSTEM,
    "os.popen": PythonCwe78Operation.OS_POPEN,
    "subprocess.getoutput": PythonCwe78Operation.SUBPROCESS_GETOUTPUT,
    "subprocess.getstatusoutput": PythonCwe78Operation.SUBPROCESS_GETSTATUSOUTPUT,
}
_SUBPROCESS_MODULES = frozenset({"subprocess"})
_KNOWN_MODULES = frozenset({"os", "subprocess", "shlex", "pipes", "sys", "flask"})
_REQUEST_ROOTS = frozenset(
    {
        "request",
        "req",
        "http_request",
        "scope",
        "websocket",
        "websocket_scope",
    }
)
_REQUEST_ATTRIBUTES = frozenset(
    {
        "args",
        "body",
        "COOKIES",
        "cookies",
        "data",
        "FILES",
        "form",
        "GET",
        "headers",
        "json",
        "META",
        "POST",
        "path_params",
        "query",
        "query_params",
        "query_string",
        "values",
        "url",
    }
)
_REQUEST_ACCESS_METHODS = frozenset(
    {"body", "get_data", "get_json", "json", "read", "form", "stream"}
)
_CONTAINER_ACCESS_METHODS = frozenset({"get", "getall", "getlist", "pop"})
_ENVIRONMENT_CONTAINERS = frozenset({"os.environ", "environ", "env"})
_ARGV_CONTAINER = "sys.argv"
_FLOW_PRESERVING_METHODS = frozenset(
    {
        "decode",
        "encode",
        "format",
        "join",
        "replace",
        "strip",
        "lstrip",
        "rstrip",
        "removeprefix",
        "removesuffix",
        "lower",
        "upper",
        "casefold",
    }
)
_FLOW_PRESERVING_CALLS = frozenset(
    {
        "bytes",
        "str",
        "os.fspath",
        "urllib.parse.unquote",
        "urllib.parse.unquote_plus",
    }
)
_SANITIZER_CALLS = frozenset(
    {
        "shlex.quote",
        "shlex.join",
        "pipes.quote",
        "subprocess.list2cmdline",
    }
)


def scan_python_cwe78(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe78ScanLimits = DEFAULT_PYTHON_CWE78_SCAN_LIMITS,
) -> PythonCwe78ScanResult:
    """Find bounded untrusted flows into shell or command-token sinks.

    Shell-capable subprocess calls are considered only when ``shell=True`` or
    when the shell mode is dynamic.  With the default ``shell=False``, an
    argv call is reported only when an untrusted value reaches the command
    token itself.  Quoting helpers such as :func:`shlex.quote` terminate a
    flow.
    """

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe78ScanLimits
    ):
        raise PythonCwe78ScanError(PythonCwe78ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe78ScanError(PythonCwe78ScanErrorCode.SOURCE_LIMIT)

    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe78ScanError(PythonCwe78ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe78ScanError(PythonCwe78ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe78ScanError(PythonCwe78ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases: dict[str, str | None] = {}
    flows: dict[str, tuple[_Flow, ...]] = {}
    raw: list[tuple[SourceRange, SourceRange, PythonCwe78Operation, str]] = []
    _scan_statements(tree.body, aliases, flows, source, line_starts, limits, raw)
    unique = sorted(
        set(raw),
        key=lambda item: (
            item[1].start_byte,
            item[1].end_byte,
            item[0].start_byte,
            item[0].end_byte,
            item[2].value,
            item[3],
        ),
    )
    if len(unique) > limits.max_signals:
        raise PythonCwe78ScanError(PythonCwe78ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe78Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
            detail=detail,
        )
        for source_range, sink_range, operation, detail in unique
    )
    return PythonCwe78ScanResult(
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
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe78ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe78Operation, str]],
) -> None:
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _scan_function(statement, aliases, flows, source, line_starts, limits, output)
            aliases[statement.name] = None
            flows.pop(statement.name, None)
            continue
        if isinstance(statement, ast.ClassDef):
            child_aliases = dict(aliases)
            child_flows = dict(flows)
            _scan_statements(
                statement.body,
                child_aliases,
                child_flows,
                source,
                line_starts,
                limits,
                output,
            )
            aliases[statement.name] = None
            flows.pop(statement.name, None)
            continue

        if isinstance(statement, ast.Import):
            _record_imports(statement, aliases)
        elif isinstance(statement, ast.ImportFrom):
            _record_import_from(statement, aliases)

        _scan_statement_calls(statement, aliases, flows, source, line_starts, limits, output)
        _record_assignment(statement, aliases, flows, source, line_starts, limits)
        _record_scope_bindings(statement, aliases, flows)

        if isinstance(statement, ast.If):
            left_aliases = dict(aliases)
            left_flows = dict(flows)
            right_aliases = dict(aliases)
            right_flows = dict(flows)
            _scan_statements(
                statement.body,
                left_aliases,
                left_flows,
                source,
                line_starts,
                limits,
                output,
            )
            _scan_statements(
                statement.orelse,
                right_aliases,
                right_flows,
                source,
                line_starts,
                limits,
                output,
            )
            _merge_bindings(aliases, flows, left_aliases, left_flows, right_aliases, right_flows)
        elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            body_aliases = dict(aliases)
            body_flows = dict(flows)
            _scan_statements(
                statement.body,
                body_aliases,
                body_flows,
                source,
                line_starts,
                limits,
                output,
            )
            else_aliases = dict(aliases)
            else_flows = dict(flows)
            _scan_statements(
                statement.orelse,
                else_aliases,
                else_flows,
                source,
                line_starts,
                limits,
                output,
            )
            _merge_bindings(aliases, flows, body_aliases, body_flows, else_aliases, else_flows)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            child_aliases = dict(aliases)
            child_flows = dict(flows)
            _scan_statements(
                statement.body,
                child_aliases,
                child_flows,
                source,
                line_starts,
                limits,
                output,
            )
            _merge_bindings(aliases, flows, aliases, flows, child_aliases, child_flows)
        elif isinstance(statement, ast.Try):
            branches: list[tuple[dict[str, str | None], dict[str, tuple[_Flow, ...]]]] = []
            body_aliases = dict(aliases)
            body_flows = dict(flows)
            _scan_statements(
                statement.body,
                body_aliases,
                body_flows,
                source,
                line_starts,
                limits,
                output,
            )
            branches.append((body_aliases, body_flows))
            for handler in statement.handlers:
                handler_aliases = dict(aliases)
                handler_flows = dict(flows)
                if handler.name is not None:
                    handler_aliases[handler.name] = None
                    handler_flows.pop(handler.name, None)
                _scan_statements(
                    handler.body,
                    handler_aliases,
                    handler_flows,
                    source,
                    line_starts,
                    limits,
                    output,
                )
                branches.append((handler_aliases, handler_flows))
            else_aliases = dict(aliases)
            else_flows = dict(flows)
            _scan_statements(
                statement.orelse,
                else_aliases,
                else_flows,
                source,
                line_starts,
                limits,
                output,
            )
            branches.append((else_aliases, else_flows))
            final_aliases = dict(aliases)
            final_flows = dict(flows)
            _scan_statements(
                statement.finalbody,
                final_aliases,
                final_flows,
                source,
                line_starts,
                limits,
                output,
            )
            branches.append((final_aliases, final_flows))
            _merge_many_bindings(aliases, flows, branches)
        else:
            for child in _nested_statement_lists(statement):
                child_aliases = dict(aliases)
                child_flows = dict(flows)
                _scan_statements(
                    child,
                    child_aliases,
                    child_flows,
                    source,
                    line_starts,
                    limits,
                    output,
                )
                _merge_bindings(
                    aliases,
                    flows,
                    aliases,
                    flows,
                    child_aliases,
                    child_flows,
                )


def _scan_function(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe78ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe78Operation, str]],
) -> None:
    for default in (*function.args.defaults, *(item for item in function.args.kw_defaults if item)):
        _scan_expression_calls(default, aliases, flows, source, line_starts, limits, output)
    child_aliases = dict(aliases)
    child_flows = dict(flows)
    parameters = (
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    )
    for parameter in parameters:
        if parameter.arg in _REQUEST_ROOTS:
            child_aliases.pop(parameter.arg, None)
        else:
            child_aliases[parameter.arg] = None
        child_flows.pop(parameter.arg, None)
    if function.args.vararg is not None:
        child_aliases[function.args.vararg.arg] = None
        child_flows.pop(function.args.vararg.arg, None)
    if function.args.kwarg is not None:
        child_aliases[function.args.kwarg.arg] = None
        child_flows.pop(function.args.kwarg.arg, None)
    _scan_statements(
        function.body,
        child_aliases,
        child_flows,
        source,
        line_starts,
        limits,
        output,
    )


def _scan_statement_calls(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe78ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe78Operation, str]],
) -> None:
    stack: list[ast.AST] = [statement]
    while stack:
        node = stack.pop()
        for child in reversed(tuple(ast.iter_child_nodes(node))):
            if isinstance(child, ast.stmt):
                continue
            stack.append(child)
        if isinstance(node, ast.Call):
            _record_call(node, aliases, flows, source, line_starts, limits, output)


def _scan_expression_calls(
    expression: ast.expr,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe78ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe78Operation, str]],
) -> None:
    stack: list[ast.AST] = [expression]
    while stack:
        node = stack.pop()
        for child in reversed(tuple(ast.iter_child_nodes(node))):
            if isinstance(child, (ast.stmt, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            stack.append(child)
        if isinstance(node, ast.Call):
            _record_call(node, aliases, flows, source, line_starts, limits, output)


def _record_call(
    call: ast.Call,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe78ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe78Operation, str]],
) -> None:
    sink = _sink_for_callable(call.func, aliases, limits.max_resolution_depth)
    if sink is None:
        return
    argument = _call_argument(call, sink.argument_index, sink.argument_names)
    if argument is None:
        return
    shell_mode = _shell_mode(call) if sink.shell_capable else True
    if sink.shell_capable and shell_mode is False:
        source_flows = _resolve_command_token_flows(
            argument, aliases, flows, source, line_starts, limits, 0
        )
        detail = _DETAIL_ARGV
        operation = PythonCwe78Operation.SUBPROCESS_ARGV
    else:
        source_flows = _resolve_flows(argument, aliases, flows, source, line_starts, limits, 0)
        detail = _DETAIL_SHELL
        operation = sink.operation
    if not source_flows:
        return
    sink_range = _node_range(call, source, line_starts)
    for flow in source_flows:
        if not sink_range.contains(flow.source):
            raise PythonCwe78ScanError(PythonCwe78ScanErrorCode.INTEGRITY_FAILURE)
        output.append((flow.source, sink_range, operation, detail))
        if len(output) > limits.max_signals:
            raise PythonCwe78ScanError(PythonCwe78ScanErrorCode.SIGNAL_LIMIT)


def _sink_for_callable(
    callable_node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
) -> _Sink | None:
    canonical = _canonical_reference(callable_node, aliases, max_depth)
    if canonical is None:
        return None
    operation = _SHELL_ALWAYS.get(canonical)
    if operation is not None:
        return _Sink(operation, 0, frozenset({"command", "cmd", "args"}), True, False)
    operation = _SHELL_CAPABLE.get(canonical)
    if operation is not None:
        return _Sink(operation, 0, frozenset({"args", "command", "cmd"}), False, True)
    return None


def _call_argument(
    call: ast.Call,
    index: int,
    names: frozenset[str],
) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg in names:
            return keyword.value
    return call.args[index] if len(call.args) > index else None


def _shell_mode(call: ast.Call) -> bool | None:
    for keyword in call.keywords:
        if keyword.arg != "shell":
            continue
        if isinstance(keyword.value, ast.Constant) and type(keyword.value.value) is bool:
            return keyword.value.value
        return None
    return False


def _resolve_command_token_flows(
    node: ast.expr,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe78ScanLimits,
    depth: int,
) -> tuple[_Flow, ...]:
    if isinstance(node, (ast.List, ast.Tuple)):
        if not node.elts:
            return ()
        return _resolve_flows(node.elts[0], aliases, flows, source, line_starts, limits, depth + 1)
    return _resolve_flows(node, aliases, flows, source, line_starts, limits, depth + 1)


def _resolve_flows(
    node: ast.expr,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe78ScanLimits,
    depth: int,
) -> tuple[_Flow, ...]:
    if depth > limits.max_resolution_depth:
        raise PythonCwe78ScanError(PythonCwe78ScanErrorCode.SIGNAL_LIMIT)
    direct = _source_range(node, aliases, source, line_starts, limits.max_resolution_depth)
    if direct is not None:
        return (_Flow(direct),)
    if isinstance(node, ast.Name):
        return flows.get(node.id, ())
    if isinstance(node, (ast.Await, ast.NamedExpr)):
        return _resolve_flows(node.value, aliases, flows, source, line_starts, limits, depth + 1)
    if isinstance(node, ast.Call):
        canonical = _canonical_reference(node.func, aliases, limits.max_resolution_depth)
        if canonical in _SANITIZER_CALLS:
            return ()
        if canonical in _FLOW_PRESERVING_CALLS or (
            canonical is not None and canonical.rsplit(".", 1)[-1] in _FLOW_PRESERVING_METHODS
        ):
            return _dedupe_flows(
                (
                    flow
                    for argument in _flow_arguments(node)
                    for flow in _resolve_flows(
                        argument, aliases, flows, source, line_starts, limits, depth + 1
                    )
                ),
                limits,
            )
        return ()
    if isinstance(node, ast.Attribute):
        return _resolve_flows(node.value, aliases, flows, source, line_starts, limits, depth + 1)
    if isinstance(node, ast.Subscript):
        return _resolve_flows(node.value, aliases, flows, source, line_starts, limits, depth + 1)
    if isinstance(node, (ast.BinOp, ast.BoolOp, ast.Compare, ast.IfExp, ast.JoinedStr)):
        return _dedupe_flows(
            (
                flow
                for child in ast.iter_child_nodes(node)
                if isinstance(child, ast.expr)
                for flow in _resolve_flows(
                    child, aliases, flows, source, line_starts, limits, depth + 1
                )
            ),
            limits,
        )
    if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
        return _dedupe_flows(
            (
                flow
                for child in ast.iter_child_nodes(node)
                if isinstance(child, ast.expr)
                for flow in _resolve_flows(
                    child, aliases, flows, source, line_starts, limits, depth + 1
                )
            ),
            limits,
        )
    return ()


def _dedupe_flows(flows: Iterable[_Flow], limits: PythonCwe78ScanLimits) -> tuple[_Flow, ...]:
    unique: dict[tuple[int, int], _Flow] = {}
    for flow in flows:
        unique[(flow.source.start_byte, flow.source.end_byte)] = flow
        if len(unique) > limits.max_signals:
            raise PythonCwe78ScanError(PythonCwe78ScanErrorCode.SIGNAL_LIMIT)
    return tuple(unique[key] for key in sorted(unique))


def _source_range(
    node: ast.expr,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    max_depth: int,
) -> SourceRange | None:
    canonical = _canonical_reference(node, aliases, max_depth)
    if isinstance(node, ast.Subscript):
        if _source_range(node.value, aliases, source, line_starts, max_depth) is not None:
            return _node_range(node, source, line_starts)
        base = _canonical_reference(node.value, aliases, max_depth)
        if _is_source_container(base):
            return _node_range(node, source, line_starts)
    if canonical is not None:
        if _is_source_attribute(canonical) or _is_source_container(canonical):
            return _node_range(node, source, line_starts)
        if _is_source_access_call(canonical, node):
            return _node_range(node, source, line_starts)
    return None


def _is_source_root(canonical: str | None) -> bool:
    if canonical is None:
        return False
    return (
        canonical in _REQUEST_ROOTS
        or canonical.endswith(".request")
        or canonical.endswith(".Request")
    )


def _is_source_container(canonical: str | None) -> bool:
    if canonical is None:
        return False
    if canonical in _ENVIRONMENT_CONTAINERS or canonical == _ARGV_CONTAINER:
        return True
    base, _, attribute = canonical.rpartition(".")
    return _is_source_root(base) and attribute in _REQUEST_ATTRIBUTES


def _is_source_attribute(canonical: str) -> bool:
    return _is_source_container(canonical)


def _is_source_access_call(canonical: str, node: ast.AST) -> bool:
    if canonical in {"os.getenv", "getenv", "os.getlogin"}:
        return True
    if canonical in {"builtins.input", "input", "getpass.getpass"}:
        return True
    base, _, method = canonical.rpartition(".")
    if base in {"sys.stdin", "request.body"} and method in {"read", "readline", "readlines"}:
        return True
    if _is_source_root(base) and method in _REQUEST_ACCESS_METHODS:
        return True
    return bool(_is_source_container(base) and method in _CONTAINER_ACCESS_METHODS)


def _canonical_reference(
    node: ast.AST,
    aliases: dict[str, str | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe78ScanError(PythonCwe78ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        if node.id in aliases:
            return aliases[node.id]
        if node.id in _REQUEST_ROOTS or node.id in {
            "os",
            "sys",
            "subprocess",
            "input",
            "environ",
            "env",
        }:
            return node.id
        return None
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Subscript):
        return _canonical_reference(node.value, aliases, max_depth, depth + 1)
    if isinstance(node, ast.Call):
        if _dotted_name(node.func) in {"getattr", "builtins.getattr"}:
            if len(node.args) < 2 or node.keywords:
                return None
            base = _canonical_reference(node.args[0], aliases, max_depth, depth + 1)
            member = _literal_string(node.args[1])
            return None if base is None or member is None else f"{base}.{member}"
        return _canonical_reference(node.func, aliases, max_depth, depth + 1)
    return None


def _record_imports(statement: ast.Import, aliases: dict[str, str | None]) -> None:
    for imported in statement.names:
        root = imported.name.split(".", 1)[0]
        aliases[imported.asname or root] = imported.name if root in _KNOWN_MODULES else None


def _record_import_from(statement: ast.ImportFrom, aliases: dict[str, str | None]) -> None:
    module = statement.module or ""
    known: dict[str, frozenset[str]] = {
        "os": frozenset({"system", "popen", "getenv", "environ"}),
        "subprocess": frozenset(
            {
                "run",
                "call",
                "check_call",
                "check_output",
                "Popen",
                "getoutput",
                "getstatusoutput",
                "list2cmdline",
            }
        ),
        "shlex": frozenset({"quote", "join", "split"}),
        "pipes": frozenset({"quote"}),
        "builtins": frozenset({"input"}),
        "flask": frozenset({"request"}),
        "starlette.requests": frozenset({"Request"}),
        "fastapi": frozenset({"Request"}),
    }
    if statement.level or module not in known:
        for imported in statement.names:
            aliases[imported.asname or imported.name] = None
        return
    for imported in statement.names:
        if imported.name == "*":
            continue
        name = imported.asname or imported.name
        aliases[name] = f"{module}.{imported.name}" if imported.name in known[module] else None


def _record_assignment(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe78ScanLimits,
) -> None:
    values: list[tuple[ast.expr, ast.expr]] = []
    if isinstance(statement, ast.Assign):
        values.extend((target, statement.value) for target in statement.targets)
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        values.append((statement.target, statement.value))
    for target, value in values:
        names = _target_names(target)
        resolved = _resolve_flows(value, aliases, flows, source, line_starts, limits, 0)
        canonical = _canonical_reference(value, aliases, limits.max_resolution_depth)
        for name in names:
            aliases[name] = canonical
            if resolved:
                flows[name] = resolved
            else:
                flows.pop(name, None)


def _record_scope_bindings(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
) -> None:
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        _invalidate_target(statement.target, aliases, flows)
    elif isinstance(statement, (ast.With, ast.AsyncWith)):
        for item in statement.items:
            if item.optional_vars is not None:
                _invalidate_target(item.optional_vars, aliases, flows)
    elif isinstance(statement, ast.Try):
        for handler in statement.handlers:
            if handler.name is not None:
                aliases[handler.name] = None
                flows.pop(handler.name, None)
    elif isinstance(statement, ast.Delete):
        for target in statement.targets:
            _invalidate_target(target, aliases, flows)


def _invalidate_target(
    target: ast.AST,
    aliases: dict[str, str | None],
    flows: dict[str, tuple[_Flow, ...]],
) -> None:
    for name in _target_names(target):
        aliases[name] = None
        flows.pop(name, None)


def _merge_bindings(
    target_aliases: dict[str, str | None],
    target_flows: dict[str, tuple[_Flow, ...]],
    left_aliases: dict[str, str | None],
    left_flows: dict[str, tuple[_Flow, ...]],
    right_aliases: dict[str, str | None],
    right_flows: dict[str, tuple[_Flow, ...]],
) -> None:
    merged_aliases: dict[str, str | None] = {}
    merged_flows: dict[str, tuple[_Flow, ...]] = {}
    for name in left_aliases.keys() | right_aliases.keys():
        left_alias = left_aliases.get(name)
        right_alias = right_aliases.get(name)
        merged_aliases[name] = left_alias if left_alias == right_alias else None
        left_flow = left_flows.get(name, ())
        right_flow = right_flows.get(name, ())
        if left_flow == right_flow and left_flow:
            merged_flows[name] = left_flow
    target_aliases.clear()
    target_aliases.update(merged_aliases)
    target_flows.clear()
    target_flows.update(merged_flows)


def _merge_many_bindings(
    target_aliases: dict[str, str | None],
    target_flows: dict[str, tuple[_Flow, ...]],
    branches: list[tuple[dict[str, str | None], dict[str, tuple[_Flow, ...]]]],
) -> None:
    if not branches:
        return
    merged_aliases = dict(branches[0][0])
    merged_flows = dict(branches[0][1])
    for branch_aliases, branch_flows in branches[1:]:
        _merge_bindings(
            merged_aliases,
            merged_flows,
            merged_aliases,
            merged_flows,
            branch_aliases,
            branch_flows,
        )
    target_aliases.clear()
    target_aliases.update(merged_aliases)
    target_flows.clear()
    target_flows.update(merged_flows)


def _target_names(node: ast.AST) -> tuple[str, ...]:
    return tuple(item.id for item in ast.walk(node) if isinstance(item, ast.Name))


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
    if isinstance(statement, ast.Match):
        return tuple(case.body for case in statement.cases)
    return ()


def _flow_arguments(call: ast.Call) -> tuple[ast.expr, ...]:
    receiver = (
        (call.func.value,)
        if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.expr)
        else ()
    )
    return (*receiver, *call.args, *(item.value for item in call.keywords))


def _literal_string(node: ast.AST) -> str | None:
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
        raise PythonCwe78ScanError(PythonCwe78ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe78ScanError(PythonCwe78ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe78ScanError(PythonCwe78ScanErrorCode.INTEGRITY_FAILURE)
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
    operation: PythonCwe78Operation,
    detail: str,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detail": detail,
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
    signals: tuple[PythonCwe78Signal, ...],
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


# Compatibility aliases keep this adapter usable beside the existing CWE
# scanners while retaining the Python-specific implementation names.
Cwe78ScanErrorCode = PythonCwe78ScanErrorCode
Cwe78ScanError = PythonCwe78ScanError
Cwe78ScanLimits = PythonCwe78ScanLimits
Cwe78ScanResult = PythonCwe78ScanResult
Cwe78Signal = PythonCwe78Signal


__all__ = [
    "DEFAULT_PYTHON_CWE78_SCAN_LIMITS",
    "Cwe78ScanError",
    "Cwe78ScanErrorCode",
    "Cwe78ScanLimits",
    "Cwe78ScanResult",
    "Cwe78Signal",
    "PythonCwe78Operation",
    "PythonCwe78ScanError",
    "PythonCwe78ScanErrorCode",
    "PythonCwe78ScanLimits",
    "PythonCwe78ScanResult",
    "PythonCwe78Signal",
    "scan_python_cwe78",
]
