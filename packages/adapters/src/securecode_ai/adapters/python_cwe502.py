"""Bounded Python unsafe-deserialization facts for CWE-502.

The scanner accepts a sealed :class:`~securecode_ai.core.SymbolIndex` and its
matching sealed CPython AST analysis.  It recognises only explicit pickle,
marshal, and PyYAML deserialisation APIs, including imports and local aliases.
The result contains immutable source ranges and content-addressed metadata; it
never imports, executes, or retains analysed source text.
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
_RULE_ID = "securecode-python-cwe502"
_DETECTOR = "securecode-python-cwe502@1.0"


class PythonCwe502ScanErrorCode(StrEnum):
    """Closed reasons an unsafe-deserialization scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe502ScanError(RuntimeError):
    """Fixed, non-echoing Python CWE-502 scanner failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe502ScanErrorCode) -> None:
        if type(code) is not PythonCwe502ScanErrorCode:
            raise TypeError("Python CWE-502 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-502 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe502Operation(StrEnum):
    """Recognised unsafe deserialisation operations."""

    PICKLE_LOAD = "pickle.load"
    PICKLE_LOADS = "pickle.loads"
    PICKLE_UNPICKLER = "pickle.Unpickler"
    MARSHAL_LOAD = "marshal.load"
    MARSHAL_LOADS = "marshal.loads"
    YAML_LOAD = "yaml.load"
    YAML_LOAD_ALL = "yaml.load_all"
    YAML_UNSAFE_LOAD = "yaml.unsafe_load"
    YAML_UNSAFE_LOAD_ALL = "yaml.unsafe_load_all"
    YAML_LOADER = "yaml.Loader"
    YAML_UNSAFE_LOADER = "yaml.UnsafeLoader"
    YAML_CLOADER = "yaml.CLoader"


@dataclass(frozen=True, slots=True)
class PythonCwe502ScanLimits:
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
            raise ValueError("Python CWE-502 scan limits are invalid")


DEFAULT_PYTHON_CWE502_SCAN_LIMITS = PythonCwe502ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe502Signal:
    """One source-to-unsafe-deserialisation fact without source text."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe502Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-502"
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
            if valid_identity and valid_ranges and type(self.operation) is PythonCwe502Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not PythonCwe502Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-502"
            or self.detector != _DETECTOR
        ):
            raise ValueError("Python CWE-502 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name for generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the complete unsafe call location."""

        return self.sink


@dataclass(frozen=True, slots=True)
class PythonCwe502ScanResult:
    """Source-free, deterministic CWE-502 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe502Signal, ...]
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
            type(item) is PythonCwe502Signal for item in self.signals
        )
        order = tuple(
            (
                item.sink.start_byte,
                item.sink.end_byte,
                item.source.start_byte,
                item.source.end_byte,
                item.operation.value,
            )
            for item in self.signals
        ) if valid_signals else ()
        same_identity = all(
            item.repository_id == self.repository_id
            and item.revision == self.revision
            and item.path == self.path
            and item.content_sha256 == self.content_sha256
            and item.source_size_bytes == self.source_size_bytes
            for item in self.signals
        ) if valid_signals else False
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
            raise ValueError("Python CWE-502 scan result is invalid")


_DIRECT_OPERATIONS: dict[str, PythonCwe502Operation] = {
    "pickle.load": PythonCwe502Operation.PICKLE_LOAD,
    "pickle.loads": PythonCwe502Operation.PICKLE_LOADS,
    "pickle.Unpickler": PythonCwe502Operation.PICKLE_UNPICKLER,
    "_pickle.load": PythonCwe502Operation.PICKLE_LOAD,
    "_pickle.loads": PythonCwe502Operation.PICKLE_LOADS,
    "_pickle.Unpickler": PythonCwe502Operation.PICKLE_UNPICKLER,
    "cPickle.load": PythonCwe502Operation.PICKLE_LOAD,
    "cPickle.loads": PythonCwe502Operation.PICKLE_LOADS,
    "cPickle.Unpickler": PythonCwe502Operation.PICKLE_UNPICKLER,
    "marshal.load": PythonCwe502Operation.MARSHAL_LOAD,
    "marshal.loads": PythonCwe502Operation.MARSHAL_LOADS,
    "yaml.load": PythonCwe502Operation.YAML_LOAD,
    "yaml.load_all": PythonCwe502Operation.YAML_LOAD_ALL,
    "yaml.unsafe_load": PythonCwe502Operation.YAML_UNSAFE_LOAD,
    "yaml.unsafe_load_all": PythonCwe502Operation.YAML_UNSAFE_LOAD_ALL,
    "yaml.Loader": PythonCwe502Operation.YAML_LOADER,
    "yaml.UnsafeLoader": PythonCwe502Operation.YAML_UNSAFE_LOADER,
    "yaml.CLoader": PythonCwe502Operation.YAML_CLOADER,
}
_MODULES = frozenset({"pickle", "_pickle", "cPickle", "marshal", "yaml"})
_SAFE_YAML_LOADERS = frozenset(
    {
        "yaml.SafeLoader",
        "yaml.CSafeLoader",
        "yaml.FullLoader",
        "yaml.CFullLoader",
        "yaml.BaseLoader",
    }
)
_YAML_LOAD_OPERATIONS = frozenset(
    {
        PythonCwe502Operation.YAML_LOAD,
        PythonCwe502Operation.YAML_LOAD_ALL,
    }
)
_YAML_STREAM_KEY = frozenset({"stream", "data"})
_PICKLE_FILE_KEY = frozenset({"file"})
_PICKLE_DATA_KEY = frozenset({"data"})


def scan_python_cwe502(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe502ScanLimits = DEFAULT_PYTHON_CWE502_SCAN_LIMITS,
) -> PythonCwe502ScanResult:
    """Return bounded facts for explicit Python unsafe deserialisation calls.

    The supplied AST analysis must be produced for the exact sealed symbol
    index.  Unknown imports, reflection, and unresolved aliases are ignored.
    Invalid or mismatched inputs fail closed with a typed source-free error.
    """

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe502ScanLimits
    ):
        raise PythonCwe502ScanError(PythonCwe502ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe502ScanError(PythonCwe502ScanErrorCode.SOURCE_LIMIT)

    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe502ScanError(PythonCwe502ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe502ScanError(PythonCwe502ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe502ScanError(PythonCwe502ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases: dict[str, str | None] = {}
    raw: list[tuple[SourceRange, SourceRange, PythonCwe502Operation]] = []
    _scan_statements(tree.body, aliases, source, line_starts, limits, raw)
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
        raise PythonCwe502ScanError(PythonCwe502ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe502Signal(
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
    return PythonCwe502ScanResult(
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
    limits: PythonCwe502ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe502Operation]],
) -> None:
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _scan_function(statement, aliases, source, line_starts, limits, output)
            aliases[statement.name] = None
            continue
        if isinstance(statement, ast.ClassDef):
            _scan_decorators(statement.decorator_list, aliases, source, line_starts, limits, output)
            child_aliases = dict(aliases)
            _scan_statements(statement.body, child_aliases, source, line_starts, limits, output)
            aliases[statement.name] = None
            continue

        if isinstance(statement, ast.Import):
            _record_imports(statement, aliases)
        elif isinstance(statement, ast.ImportFrom):
            _record_import_from(statement, aliases)

        _scan_expression_calls(statement, aliases, source, line_starts, limits, output)
        _record_assignment_aliases(statement, aliases, limits.max_resolution_depth)
        _record_scope_bindings(statement, aliases)

        if isinstance(statement, ast.If):
            left = dict(aliases)
            right = dict(aliases)
            _scan_statements(statement.body, left, source, line_starts, limits, output)
            _scan_statements(statement.orelse, right, source, line_starts, limits, output)
            _merge_aliases(aliases, left, right)
        elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            body_aliases = dict(aliases)
            if isinstance(statement, (ast.For, ast.AsyncFor)):
                _invalidate_target_aliases(statement.target, body_aliases)
            _scan_statements(statement.body, body_aliases, source, line_starts, limits, output)
            else_aliases = dict(aliases)
            _scan_statements(statement.orelse, else_aliases, source, line_starts, limits, output)
            _merge_aliases(aliases, body_aliases, else_aliases)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            parent_aliases = dict(aliases)
            child_aliases = dict(aliases)
            for item in statement.items:
                if item.optional_vars is not None:
                    _invalidate_target_aliases(item.optional_vars, child_aliases)
            _scan_statements(statement.body, child_aliases, source, line_starts, limits, output)
            _merge_aliases(aliases, parent_aliases, child_aliases)
        elif isinstance(statement, ast.Try):
            branches: list[dict[str, str | None]] = []
            body_aliases = dict(aliases)
            _scan_statements(statement.body, body_aliases, source, line_starts, limits, output)
            branches.append(body_aliases)
            for handler in statement.handlers:
                handler_aliases = dict(aliases)
                if handler.name is not None:
                    handler_aliases[handler.name] = None
                _scan_statements(handler.body, handler_aliases, source, line_starts, limits, output)
                branches.append(handler_aliases)
            else_aliases = dict(aliases)
            _scan_statements(statement.orelse, else_aliases, source, line_starts, limits, output)
            branches.append(else_aliases)
            final_aliases = dict(aliases)
            _scan_statements(
                statement.finalbody, final_aliases, source, line_starts, limits, output
            )
            branches.append(final_aliases)
            _merge_many_aliases(aliases, branches)
        else:
            for child in _nested_statement_lists(statement):
                parent_aliases = dict(aliases)
                child_aliases = dict(aliases)
                _scan_statements(child, child_aliases, source, line_starts, limits, output)
                _merge_aliases(aliases, parent_aliases, child_aliases)


def _scan_function(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe502ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe502Operation]],
) -> None:
    _scan_decorators(function.decorator_list, aliases, source, line_starts, limits, output)
    for default in (*function.args.defaults, *(item for item in function.args.kw_defaults if item)):
        _scan_expression(default, aliases, source, line_starts, limits, output)
    child_aliases = dict(aliases)
    parameters = (
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    )
    for parameter in parameters:
        child_aliases[parameter.arg] = None
    if function.args.vararg is not None:
        child_aliases[function.args.vararg.arg] = None
    if function.args.kwarg is not None:
        child_aliases[function.args.kwarg.arg] = None
    _scan_statements(function.body, child_aliases, source, line_starts, limits, output)


def _scan_decorators(
    decorators: list[ast.expr],
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe502ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe502Operation]],
) -> None:
    for decorator in decorators:
        _scan_expression(decorator, aliases, source, line_starts, limits, output)


def _scan_expression_calls(
    statement: ast.stmt,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe502ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe502Operation]],
) -> None:
    _scan_expression(statement, aliases, source, line_starts, limits, output)


def _scan_expression(
    root: ast.AST,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe502ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe502Operation]],
) -> None:
    stack: list[ast.AST] = [root]
    while stack:
        node = stack.pop()
        if node is not root and isinstance(node, ast.stmt):
            continue
        if node is not root and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            continue
        if isinstance(node, ast.Call):
            _record_call(node, aliases, source, line_starts, limits, output)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))


def _record_call(
    call: ast.Call,
    aliases: dict[str, str | None],
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe502ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe502Operation]],
) -> None:
    operation = _operation_for_callable(call.func, aliases, limits.max_resolution_depth)
    if operation is None:
        return
    if operation in _YAML_LOAD_OPERATIONS and _uses_safe_yaml_loader(call, aliases, limits):
        return
    sink = _node_range(call, source, line_starts)
    input_node = _input_node(call, operation)
    input_range = _node_range(input_node, source, line_starts) if input_node is not None else sink
    if not sink.contains(input_range):
        raise PythonCwe502ScanError(PythonCwe502ScanErrorCode.INTEGRITY_FAILURE)
    output.append((input_range, sink, operation))
    if len(output) > limits.max_signals:
        raise PythonCwe502ScanError(PythonCwe502ScanErrorCode.SIGNAL_LIMIT)


def _operation_for_callable(
    callable_node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
) -> PythonCwe502Operation | None:
    if isinstance(callable_node, ast.Call):
        if _dotted_name(callable_node.func) not in {"getattr", "builtins.getattr"}:
            return None
        if len(callable_node.args) < 2 or callable_node.keywords:
            return None
        base = _canonical_reference(callable_node.args[0], aliases, max_depth)
        member = _literal_string(callable_node.args[1])
        if base is None or member is None:
            return None
        return _DIRECT_OPERATIONS.get(f"{base}.{member}")
    canonical = _canonical_reference(callable_node, aliases, max_depth)
    if canonical is None:
        return None
    return _DIRECT_OPERATIONS.get(canonical)


def _canonical_reference(
    node: ast.expr,
    aliases: dict[str, str | None],
    max_depth: int,
    depth: int = 0,
) -> str | None:
    if depth > max_depth:
        raise PythonCwe502ScanError(PythonCwe502ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        return aliases.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Subscript):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        member = _literal_string(node.slice)
        return None if base is None or member is None else f"{base}.{member}"
    if isinstance(node, ast.Call):
        if _dotted_name(node.func) not in {"getattr", "builtins.getattr"}:
            return None
        if len(node.args) < 2 or node.keywords:
            return None
        base = _canonical_reference(node.args[0], aliases, max_depth, depth + 1)
        member = _literal_string(node.args[1])
        return None if base is None or member is None else f"{base}.{member}"
    return None


def _uses_safe_yaml_loader(
    call: ast.Call,
    aliases: dict[str, str | None],
    limits: PythonCwe502ScanLimits,
) -> bool:
    loader: ast.expr | None = None
    for keyword in call.keywords:
        if keyword.arg == "Loader":
            loader = keyword.value
            break
    if loader is None and len(call.args) > 1:
        loader = call.args[1]
    if loader is None:
        return False
    return _canonical_reference(loader, aliases, limits.max_resolution_depth) in _SAFE_YAML_LOADERS


def _input_node(call: ast.Call, operation: PythonCwe502Operation) -> ast.expr | None:
    if operation in {
        PythonCwe502Operation.PICKLE_LOAD,
        PythonCwe502Operation.PICKLE_UNPICKLER,
        PythonCwe502Operation.MARSHAL_LOAD,
    }:
        keyword_names = _PICKLE_FILE_KEY
    elif operation in {
        PythonCwe502Operation.PICKLE_LOADS,
        PythonCwe502Operation.MARSHAL_LOADS,
    }:
        keyword_names = _PICKLE_DATA_KEY
    else:
        keyword_names = _YAML_STREAM_KEY
    for keyword in call.keywords:
        if keyword.arg in keyword_names:
            return keyword.value
    return call.args[0] if call.args else None


def _record_imports(statement: ast.Import, aliases: dict[str, str | None]) -> None:
    for imported in statement.names:
        root = imported.name.split(".", 1)[0]
        aliases[imported.asname or root] = root if root in _MODULES else None


def _record_import_from(statement: ast.ImportFrom, aliases: dict[str, str | None]) -> None:
    module = statement.module or ""
    if statement.level or module not in _MODULES:
        for imported in statement.names:
            aliases[imported.asname or imported.name] = None
        return
    for imported in statement.names:
        if imported.name == "*":
            continue
        name = imported.asname or imported.name
        canonical = f"{module}.{imported.name}"
        is_safe_loader = module == "yaml" and imported.name in {
            "SafeLoader",
            "CSafeLoader",
            "FullLoader",
            "CFullLoader",
            "BaseLoader",
        }
        aliases[name] = canonical if canonical in _DIRECT_OPERATIONS or is_safe_loader else None


def _record_assignment_aliases(
    statement: ast.stmt, aliases: dict[str, str | None], max_depth: int
) -> None:
    values: list[tuple[ast.expr, ast.expr]] = []
    if isinstance(statement, ast.Assign) and statement.targets:
        values.extend((target, statement.value) for target in statement.targets)
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        values.append((statement.target, statement.value))
    for target, value in values:
        if not isinstance(target, ast.Name):
            continue
        aliases[target.id] = _canonical_reference(value, aliases, max_depth)


def _record_scope_bindings(statement: ast.stmt, aliases: dict[str, str | None]) -> None:
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        _invalidate_target_aliases(statement.target, aliases)
    elif isinstance(statement, (ast.With, ast.AsyncWith)):
        for item in statement.items:
            if item.optional_vars is not None:
                _invalidate_target_aliases(item.optional_vars, aliases)
    elif isinstance(statement, ast.Try):
        for handler in statement.handlers:
            if handler.name is not None:
                aliases[handler.name] = None
    elif isinstance(statement, ast.Delete):
        for target in statement.targets:
            _invalidate_target_aliases(target, aliases)


def _invalidate_target_aliases(node: ast.AST, aliases: dict[str, str | None]) -> None:
    for name in _target_names(node):
        aliases[name] = None


def _merge_aliases(
    target: dict[str, str | None], left: dict[str, str | None], right: dict[str, str | None]
) -> None:
    left_values = dict(left)
    right_values = dict(right)
    target.clear()
    for name in left_values.keys() | right_values.keys():
        left_value = left_values.get(name)
        right_value = right_values.get(name)
        target[name] = left_value if left_value == right_value else None


def _merge_many_aliases(
    target: dict[str, str | None], branches: list[dict[str, str | None]]
) -> None:
    if not branches:
        return
    merged = dict(branches[0])
    for branch in branches[1:]:
        _merge_aliases(merged, merged, branch)
    target.clear()
    target.update(merged)


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
        raise PythonCwe502ScanError(PythonCwe502ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe502ScanError(PythonCwe502ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if (
        start < line_starts[start_line]
        or end > line_starts[end_line + 1]
        or end < start
        or end > len(source)
    ):
        raise PythonCwe502ScanError(PythonCwe502ScanErrorCode.INTEGRITY_FAILURE)
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
    operation: PythonCwe502Operation,
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
    signals: tuple[PythonCwe502Signal, ...],
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
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
Cwe502ScanErrorCode = PythonCwe502ScanErrorCode
Cwe502ScanError = PythonCwe502ScanError
Cwe502ScanLimits = PythonCwe502ScanLimits
Cwe502ScanResult = PythonCwe502ScanResult
Cwe502Signal = PythonCwe502Signal


__all__ = [
    "DEFAULT_PYTHON_CWE502_SCAN_LIMITS",
    "Cwe502ScanError",
    "Cwe502ScanErrorCode",
    "Cwe502ScanLimits",
    "Cwe502ScanResult",
    "Cwe502Signal",
    "PythonCwe502Operation",
    "PythonCwe502ScanError",
    "PythonCwe502ScanErrorCode",
    "PythonCwe502ScanLimits",
    "PythonCwe502ScanResult",
    "PythonCwe502Signal",
    "scan_python_cwe502",
]
