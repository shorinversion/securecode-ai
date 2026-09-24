"""Bounded Python XML external-entity facts for CWE-611.

This adapter recognises explicit XML parser entry points and follows request,
environment, and parameter values into them with a bounded local data-flow
walk.  It records only immutable source ranges and content-addressed identity.
No module is imported and no repository source is retained in a result or
error.
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
_RULE_ID = "securecode-python-cwe611"
_DETECTOR = "securecode-python-cwe611@1.0"


class PythonCwe611ScanErrorCode(StrEnum):
    """Closed, source-free reasons the XML scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PythonCwe611ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser text."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: PythonCwe611ScanErrorCode) -> None:
        if type(code) is not PythonCwe611ScanErrorCode:
            raise TypeError("Python CWE-611 scan error code is invalid")
        self.code = code
        self.safe_message = "Python CWE-611 XML external entity scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class PythonCwe611Operation(StrEnum):
    """Recognised XML parsing operations."""

    LXML_FROMSTRING = "lxml.etree.fromstring"
    LXML_PARSE = "lxml.etree.parse"
    LXML_XML = "lxml.etree.XML"
    LXML_XML_ID = "lxml.etree.XMLID"
    LXML_ITERPARSE = "lxml.etree.iterparse"
    LXML_XML_PARSER = "lxml.etree.XMLParser"
    ELEMENTTREE_FROMSTRING = "xml.etree.ElementTree.fromstring"
    ELEMENTTREE_PARSE = "xml.etree.ElementTree.parse"
    ELEMENTTREE_XML = "xml.etree.ElementTree.XML"
    ELEMENTTREE_XML_ID = "xml.etree.ElementTree.XMLID"
    ELEMENTTREE_ITERPARSE = "xml.etree.ElementTree.iterparse"
    ELEMENTTREE_XML_PARSER = "xml.etree.ElementTree.XMLParser"
    MINIDOM_PARSE_STRING = "xml.dom.minidom.parseString"
    MINIDOM_PARSE = "xml.dom.minidom.parse"
    SAX_PARSE_STRING = "xml.sax.parseString"
    SAX_PARSE = "xml.sax.parse"
    PULLDOM_PARSE = "xml.dom.pulldom.parse"
    PULLDOM_PARSE_STRING = "xml.dom.pulldom.parseString"

    # Compatibility aliases used by generic finding consumers.
    XML_PARSE = "lxml.etree.parse"
    XML_FROM_STRING = "lxml.etree.fromstring"


@dataclass(frozen=True, slots=True)
class PythonCwe611ScanLimits:
    """Hard ceilings for source, output, and local-flow resolution."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_resolution_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_resolution_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Python CWE-611 scan limits are invalid")


DEFAULT_PYTHON_CWE611_SCAN_LIMITS = PythonCwe611ScanLimits()


@dataclass(frozen=True, slots=True)
class PythonCwe611Signal:
    """One immutable untrusted XML input to parser operation fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: PythonCwe611Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-611"
    detector: str = _DETECTOR

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
            )
            if identity_valid and ranges_valid and type(self.operation) is PythonCwe611Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not PythonCwe611Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-611"
            or self.detector != _DETECTOR
        ):
            raise ValueError("Python CWE-611 signal is invalid")
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
class PythonCwe611ScanResult:
    """Source-free, deterministic CWE-611 scan output."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[PythonCwe611Signal, ...]
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
            type(item) is PythonCwe611Signal for item in self.signals
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
            raise ValueError("Python CWE-611 scan result is invalid")


_MODULES = frozenset(
    {
        "defusedxml",
        "defusedxml.ElementTree",
        "defusedxml.minidom",
        "defusedxml.pulldom",
        "defusedxml.sax",
        "lxml",
        "lxml.etree",
        "xml",
        "xml.dom",
        "xml.dom.minidom",
        "xml.dom.pulldom",
        "xml.etree",
        "xml.etree.ElementTree",
        "xml.sax",
    }
)
_SAFE_ROOTS = frozenset({"defusedxml", "defusedxml.ElementTree", "defusedxml.minidom", "defusedxml.pulldom", "defusedxml.sax"})
_SAFE_NAMES = frozenset(
    {
        "defusedxml.ElementTree.fromstring",
        "defusedxml.ElementTree.parse",
        "defusedxml.ElementTree.iterparse",
        "defusedxml.minidom.parse",
        "defusedxml.minidom.parseString",
        "defusedxml.pulldom.parse",
        "defusedxml.pulldom.parseString",
        "defusedxml.sax.parse",
        "defusedxml.sax.parseString",
    }
)
_DIRECT_OPERATIONS: dict[str, PythonCwe611Operation] = {
    "lxml.etree.fromstring": PythonCwe611Operation.LXML_FROMSTRING,
    "lxml.etree.parse": PythonCwe611Operation.LXML_PARSE,
    "lxml.etree.XML": PythonCwe611Operation.LXML_XML,
    "lxml.etree.XMLID": PythonCwe611Operation.LXML_XML_ID,
    "lxml.etree.iterparse": PythonCwe611Operation.LXML_ITERPARSE,
    "lxml.etree.XMLParser": PythonCwe611Operation.LXML_XML_PARSER,
    "etree.fromstring": PythonCwe611Operation.LXML_FROMSTRING,
    "etree.parse": PythonCwe611Operation.LXML_PARSE,
    "etree.XML": PythonCwe611Operation.LXML_XML,
    "etree.XMLID": PythonCwe611Operation.LXML_XML_ID,
    "etree.iterparse": PythonCwe611Operation.LXML_ITERPARSE,
    "etree.XMLParser": PythonCwe611Operation.LXML_XML_PARSER,
    "xml.etree.ElementTree.fromstring": PythonCwe611Operation.ELEMENTTREE_FROMSTRING,
    "xml.etree.ElementTree.parse": PythonCwe611Operation.ELEMENTTREE_PARSE,
    "xml.etree.ElementTree.XML": PythonCwe611Operation.ELEMENTTREE_XML,
    "xml.etree.ElementTree.XMLID": PythonCwe611Operation.ELEMENTTREE_XML_ID,
    "xml.etree.ElementTree.iterparse": PythonCwe611Operation.ELEMENTTREE_ITERPARSE,
    "xml.etree.ElementTree.XMLParser": PythonCwe611Operation.ELEMENTTREE_XML_PARSER,
    "xml.dom.minidom.parseString": PythonCwe611Operation.MINIDOM_PARSE_STRING,
    "xml.dom.minidom.parse": PythonCwe611Operation.MINIDOM_PARSE,
    "xml.sax.parseString": PythonCwe611Operation.SAX_PARSE_STRING,
    "xml.sax.parse": PythonCwe611Operation.SAX_PARSE,
    "xml.dom.pulldom.parse": PythonCwe611Operation.PULLDOM_PARSE,
    "xml.dom.pulldom.parseString": PythonCwe611Operation.PULLDOM_PARSE_STRING,
    "minidom.parseString": PythonCwe611Operation.MINIDOM_PARSE_STRING,
    "minidom.parse": PythonCwe611Operation.MINIDOM_PARSE,
    "sax.parseString": PythonCwe611Operation.SAX_PARSE_STRING,
    "sax.parse": PythonCwe611Operation.SAX_PARSE,
    "pulldom.parse": PythonCwe611Operation.PULLDOM_PARSE,
    "pulldom.parseString": PythonCwe611Operation.PULLDOM_PARSE_STRING,
}
_SOURCE_ROOTS = frozenset({"request", "req", "http_request", "flask_request", "scope", "event", "context"})
_SOURCE_ATTRIBUTES = frozenset(
    {
        "args",
        "body",
        "cookies",
        "data",
        "form",
        "GET",
        "headers",
        "json",
        "POST",
        "path_params",
        "query",
        "query_params",
        "query_string",
        "values",
    }
)
_PARAMETER_NAMES = frozenset(
    {
        "body",
        "data",
        "document",
        "input",
        "payload",
        "request_body",
        "xml",
        "xml_data",
        "xml_document",
    }
)
_SOURCE_CALLS = frozenset({"input", "builtins.input", "os.getenv", "os.environ.get"})
_FLOW_CALLS = frozenset({"bytes", "bytearray", "str", "decode", "encode", "read", "get", "get_data", "get_json"})


def scan_python_cwe611(
    symbol_index: SymbolIndex,
    ast_analysis: PythonAstAnalysis,
    *,
    limits: PythonCwe611ScanLimits = DEFAULT_PYTHON_CWE611_SCAN_LIMITS,
) -> PythonCwe611ScanResult:
    """Return bounded facts for request-derived XML parser input.

    Safe ``defusedxml`` APIs are excluded.  For lxml parser construction, a
    finding is produced only when an explicit dangerous option is enabled;
    parser objects created with safe options are treated as sanitising config.
    Standard-library XML parser entry points remain findings because their
    security behaviour depends on runtime/parser configuration.
    """

    if (
        type(symbol_index) is not SymbolIndex
        or symbol_index.language != "python"
        or type(ast_analysis) is not PythonAstAnalysis
        or type(limits) is not PythonCwe611ScanLimits
    ):
        raise PythonCwe611ScanError(PythonCwe611ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise PythonCwe611ScanError(PythonCwe611ScanErrorCode.SOURCE_LIMIT)
    try:
        validated = analyze_python_ast(symbol_index)
        tree = open_python_ast(ast_analysis)
    except (PythonAstError, AttributeError, TypeError, ValueError):
        raise PythonCwe611ScanError(PythonCwe611ScanErrorCode.INTEGRITY_FAILURE) from None
    if (
        validated.status is not PythonAstStatus.PARSED
        or ast_analysis.status is not PythonAstStatus.PARSED
    ):
        raise PythonCwe611ScanError(PythonCwe611ScanErrorCode.ANALYSIS_UNAVAILABLE)
    if ast_analysis.symbol_index_sha256 != validated.symbol_index_sha256:
        raise PythonCwe611ScanError(PythonCwe611ScanErrorCode.ANALYSIS_UNAVAILABLE)

    source = symbol_index.source
    line_starts = _line_starts(source)
    aliases: dict[str, str | None] = {}
    raw: list[tuple[SourceRange, SourceRange, PythonCwe611Operation]] = []
    _scan_statements(tree.body, aliases, tree, source, line_starts, limits, raw)
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
        raise PythonCwe611ScanError(PythonCwe611ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        PythonCwe611Signal(
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
    return PythonCwe611ScanResult(
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
    tree: ast.AST,
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe611ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe611Operation]],
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
            _scan_statements(statement.body, child, tree, source, line_starts, limits, output)
            aliases[statement.name] = None
            continue
        if isinstance(statement, ast.ClassDef):
            child = dict(aliases)
            _scan_statements(statement.body, child, tree, source, line_starts, limits, output)
            aliases[statement.name] = None
            continue
        if isinstance(statement, ast.Import):
            _record_imports(statement, aliases)
        elif isinstance(statement, ast.ImportFrom):
            _record_import_from(statement, aliases)
        _scan_expression(statement, aliases, tree, source, line_starts, limits, output)
        _record_assignments(statement, aliases, limits.max_resolution_depth)
        if isinstance(statement, ast.If):
            left, right = dict(aliases), dict(aliases)
            _scan_statements(statement.body, left, tree, source, line_starts, limits, output)
            _scan_statements(statement.orelse, right, tree, source, line_starts, limits, output)
            _merge_aliases(aliases, left, right)
        elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            child = dict(aliases)
            _scan_statements(statement.body, child, tree, source, line_starts, limits, output)
            _scan_statements(statement.orelse, aliases, tree, source, line_starts, limits, output)
            _merge_aliases(aliases, child, aliases)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            child = dict(aliases)
            _scan_statements(statement.body, child, tree, source, line_starts, limits, output)
            _merge_aliases(aliases, aliases, child)
        elif isinstance(statement, ast.Try):
            branches = [dict(aliases)]
            _scan_statements(statement.body, branches[0], tree, source, line_starts, limits, output)
            for handler in statement.handlers:
                branch = dict(aliases)
                _scan_statements(handler.body, branch, tree, source, line_starts, limits, output)
                branches.append(branch)
            if statement.orelse:
                branch = dict(aliases)
                _scan_statements(statement.orelse, branch, tree, source, line_starts, limits, output)
                branches.append(branch)
            _merge_many_aliases(aliases, branches)
        else:
            for child_statements in _nested_statement_lists(statement):
                child = dict(aliases)
                _scan_statements(child_statements, child, tree, source, line_starts, limits, output)
                _merge_aliases(aliases, aliases, child)


def _scan_expression(
    root: ast.AST,
    aliases: dict[str, str | None],
    tree: ast.AST,
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe611ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe611Operation]],
) -> None:
    stack: list[ast.AST] = [root]
    while stack:
        node = stack.pop()
        if node is not root and isinstance(node, ast.stmt):
            continue
        if node is not root and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, ast.Call):
            _record_call(node, aliases, tree, source, line_starts, limits, output)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))


def _record_call(
    call: ast.Call,
    aliases: dict[str, str | None],
    tree: ast.AST,
    source: bytes,
    line_starts: tuple[int, ...],
    limits: PythonCwe611ScanLimits,
    output: list[tuple[SourceRange, SourceRange, PythonCwe611Operation]],
) -> None:
    canonical = _canonical_reference(call.func, aliases, limits.max_resolution_depth)
    operation = _DIRECT_OPERATIONS.get(canonical or "")
    if operation is None or _is_safe_reference(canonical):
        return
    if operation in {
        PythonCwe611Operation.LXML_XML_PARSER,
        PythonCwe611Operation.ELEMENTTREE_XML_PARSER,
    } and not _unsafe_parser_options(call):
        return
    if _uses_inline_safe_parser(call, aliases, limits.max_resolution_depth):
        return
    input_nodes = _input_nodes(call, operation)
    sink = _node_range(call, source, line_starts)
    for input_node in input_nodes:
        if _is_known_safe_expression(input_node, aliases, limits.max_resolution_depth):
            continue
        if _resolve_source(
            input_node,
            call=call,
            tree=tree,
            source=source,
            aliases=aliases,
            max_depth=limits.max_resolution_depth,
            seen=frozenset(),
        ) is None:
            continue
        input_range = _node_range(input_node, source, line_starts)
        if not sink.contains(input_range):
            raise PythonCwe611ScanError(PythonCwe611ScanErrorCode.INTEGRITY_FAILURE)
        output.append((input_range, sink, operation))
        if len(output) > limits.max_signals:
            raise PythonCwe611ScanError(PythonCwe611ScanErrorCode.SIGNAL_LIMIT)


def _input_nodes(call: ast.Call, operation: PythonCwe611Operation) -> tuple[ast.expr, ...]:
    if operation in {
        PythonCwe611Operation.LXML_PARSE,
        PythonCwe611Operation.ELEMENTTREE_PARSE,
        PythonCwe611Operation.MINIDOM_PARSE,
        PythonCwe611Operation.SAX_PARSE,
        PythonCwe611Operation.PULLDOM_PARSE,
    }:
        names = {"source", "file", "filename", "fileobj"}
    elif operation in {
        PythonCwe611Operation.LXML_XML_PARSER,
        PythonCwe611Operation.ELEMENTTREE_XML_PARSER,
    }:
        return ()
    else:
        names = {"text", "xml", "data", "source", "string"}
    nodes = list(call.args[:1])
    nodes.extend(keyword.value for keyword in call.keywords if keyword.arg in names)
    return tuple(nodes)


def _unsafe_parser_options(call: ast.Call) -> bool:
    for keyword in call.keywords:
        if keyword.arg in {"resolve_entities", "load_dtd"} and _literal_bool(keyword.value, True):
            return True
        if keyword.arg == "no_network" and _literal_bool(keyword.value, False):
            return True
    return False


def _uses_inline_safe_parser(
    call: ast.Call, aliases: dict[str, str | None], max_depth: int
) -> bool:
    """Exclude an XML parse call whose parser argument is explicitly safe."""

    parser: ast.expr | None = None
    for keyword in call.keywords:
        if keyword.arg == "parser":
            parser = keyword.value
            break
    if parser is None and len(call.args) > 1:
        parser = call.args[1]
    if not isinstance(parser, ast.Call):
        return False
    canonical = _canonical_reference(parser.func, aliases, max_depth)
    if canonical not in {
        "lxml.etree.XMLParser",
        "etree.XMLParser",
        "xml.etree.ElementTree.XMLParser",
    }:
        return False
    return not _unsafe_parser_options(parser)


def _literal_bool(node: ast.expr, expected: bool) -> bool:
    return isinstance(node, ast.Constant) and type(node.value) is bool and node.value is expected


def _is_known_safe_expression(
    node: ast.expr, aliases: dict[str, str | None], max_depth: int
) -> bool:
    canonical = _canonical_reference(node, aliases, max_depth)
    return canonical in _SAFE_NAMES or bool(canonical and canonical.startswith("defusedxml."))


def _resolve_source(
    subject: ast.expr,
    *,
    call: ast.Call,
    tree: ast.AST,
    source: bytes,
    aliases: dict[str, str | None],
    max_depth: int,
    seen: frozenset[str],
    before: tuple[int, int] | None = None,
    depth: int = 0,
) -> ast.expr | None:
    if depth > max_depth:
        raise PythonCwe611ScanError(PythonCwe611ScanErrorCode.SIGNAL_LIMIT)
    if _direct_source_node(subject, source) is not None:
        return subject
    if isinstance(subject, ast.Name):
        if subject.id in seen:
            return None
        assignment = _latest_assignment(tree, call, subject.id, before)
        if assignment is not None and assignment.value is not None:
            return _resolve_source(
                assignment.value,
                call=call,
                tree=tree,
                source=source,
                aliases=aliases,
                max_depth=max_depth,
                seen=seen | {subject.id},
                before=(assignment.lineno, assignment.col_offset),
                depth=depth + 1,
            )
        if _is_parameter_source(subject.id, call, tree):
            return subject
    if isinstance(subject, ast.Call):
        canonical = _canonical_reference(subject.func, aliases, max_depth)
        if canonical in _FLOW_CALLS or (canonical and canonical.rsplit(".", 1)[-1] in _FLOW_CALLS):
            for argument in (*subject.args, *(keyword.value for keyword in subject.keywords)):
                resolved = _resolve_source(
                    argument,
                    call=call,
                    tree=tree,
                    source=source,
                    aliases=aliases,
                    max_depth=max_depth,
                    seen=seen,
                    before=before,
                    depth=depth + 1,
                )
                if resolved is not None:
                    return resolved
    for child in ast.iter_child_nodes(subject):
        if isinstance(child, ast.expr):
            resolved = _resolve_source(
                child,
                call=call,
                tree=tree,
                source=source,
                aliases=aliases,
                max_depth=max_depth,
                seen=seen,
                before=before,
                depth=depth + 1,
            )
            if resolved is not None:
                return resolved
    return None


def _direct_source_node(subject: ast.expr, source: bytes) -> ast.expr | None:
    stack: list[ast.AST] = [subject]
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Call) and _source_call(node, source):
            return node
        if isinstance(node, ast.Attribute) and _source_attribute(node):
            return node
        if isinstance(node, ast.Subscript) and _source_subscript(node):
            return node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return None


def _source_call(node: ast.Call, source: bytes) -> bool:
    name = _dotted_name(node.func)
    if name in _SOURCE_CALLS:
        return True
    compact = _compact(source, node)
    return bool(
        re.match(
            r"(?:request|req|http_request|flask_request)(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])*\.(?:get|pop|setdefault)\(",
            compact,
        )
        or re.match(r"(?:event|context)\.get\(", compact)
    )


def _source_attribute(node: ast.Attribute) -> bool:
    if node.attr not in _SOURCE_ATTRIBUTES:
        return False
    root: ast.expr = node.value
    while isinstance(root, ast.Attribute):
        root = root.value
    return isinstance(root, ast.Name) and root.id in _SOURCE_ROOTS


def _source_subscript(node: ast.Subscript) -> bool:
    if isinstance(node.value, ast.Attribute) and _source_attribute(node.value):
        return True
    return isinstance(node.value, ast.Name) and node.value.id in {"argv", "environ"}


def _is_parameter_source(name: str, call: ast.Call, tree: ast.AST) -> bool:
    if name.lower() not in _PARAMETER_NAMES:
        return False
    scope = _enclosing_function(call, tree)
    if scope is None:
        return False
    parameters = (*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs)
    return any(parameter.arg == name for parameter in parameters) or (
        scope.args.vararg is not None and scope.args.vararg.arg == name
    ) or (scope.args.kwarg is not None and scope.args.kwarg.arg == name)


def _enclosing_function(call: ast.Call, tree: ast.AST) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    call_line = getattr(call, "lineno", -1)
    candidates: list[tuple[int, int, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    for item in ast.walk(tree):
        if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end_line = getattr(item, "end_lineno", None)
        if type(end_line) is int and item.lineno <= call_line <= end_line:
            candidates.append((end_line - item.lineno, item.col_offset, item))
    return min(candidates, default=(0, 0, None))[2]


def _latest_assignment(
    tree: ast.AST, call: ast.Call, name: str, before: tuple[int, int] | None
) -> ast.Assign | ast.AnnAssign | None:
    scope = _enclosing_function(call, tree)
    root: ast.AST = scope if scope is not None else tree
    boundary = before or (getattr(call, "lineno", 0), getattr(call, "col_offset", 0))
    candidates: list[ast.Assign | ast.AnnAssign] = []
    stack: list[ast.AST] = [root]
    while stack:
        node = stack.pop()
        if node is not root and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            position = (node.lineno, node.col_offset)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if position < boundary and any(_target_has_name(target, name) for target in targets):
                candidates.append(node)
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return max(candidates, key=lambda item: (item.lineno, item.col_offset), default=None)


def _record_imports(statement: ast.Import, aliases: dict[str, str | None]) -> None:
    for imported in statement.names:
        root = imported.name.split(".", 1)[0]
        aliases[imported.asname or root] = imported.name if imported.name in _MODULES else None
        if imported.asname is None and root in {"xml", "lxml"}:
            aliases[root] = root


def _record_import_from(statement: ast.ImportFrom, aliases: dict[str, str | None]) -> None:
    module = statement.module or ""
    for imported in statement.names:
        if imported.name == "*":
            continue
        name = imported.asname or imported.name
        canonical = f"{module}.{imported.name}"
        aliases[name] = (
            canonical
            if canonical in _DIRECT_OPERATIONS or canonical in _SAFE_NAMES or canonical in _MODULES
            else None
        )


def _record_assignments(
    statement: ast.stmt, aliases: dict[str, str | None], max_depth: int
) -> None:
    values: list[tuple[ast.expr, ast.expr]] = []
    if isinstance(statement, ast.Assign) and statement.targets:
        values.extend((target, statement.value) for target in statement.targets)
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        values.append((statement.target, statement.value))
    for target, value in values:
        if isinstance(target, ast.Name):
            aliases[target.id] = _canonical_reference(value, aliases, max_depth)


def _canonical_reference(
    node: ast.expr, aliases: dict[str, str | None], max_depth: int, depth: int = 0
) -> str | None:
    if depth > max_depth:
        raise PythonCwe611ScanError(PythonCwe611ScanErrorCode.SIGNAL_LIMIT)
    if isinstance(node, ast.Name):
        return aliases.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _canonical_reference(node.value, aliases, max_depth, depth + 1)
        return None if base is None else f"{base}.{node.attr}"
    if isinstance(node, ast.Call) and _dotted_name(node.func) in {"getattr", "builtins.getattr"}:
        if len(node.args) < 2 or node.keywords:
            return None
        base = _canonical_reference(node.args[0], aliases, max_depth, depth + 1)
        member = _literal_string(node.args[1])
        return None if base is None or member is None else f"{base}.{member}"
    return None


def _is_safe_reference(canonical: str | None) -> bool:
    return bool(canonical and (canonical in _SAFE_NAMES or canonical.startswith("defusedxml.")))


def _merge_aliases(
    target: dict[str, str | None], left: dict[str, str | None], right: dict[str, str | None]
) -> None:
    target.clear()
    for name in left.keys() | right.keys():
        target[name] = left.get(name) if left.get(name) == right.get(name) else None


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


def _target_has_name(target: ast.expr, name: str) -> bool:
    return any(item.id == name for item in ast.walk(target) if isinstance(item, ast.Name))


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
        raise PythonCwe611ScanError(PythonCwe611ScanErrorCode.INTEGRITY_FAILURE) from None
    values = (start_line, end_line, start_column, end_column)
    if (
        any(type(value) is not int for value in values)
        or start_line < 0
        or end_line < start_line
        or start_line + 1 >= len(line_starts)
        or end_line + 1 >= len(line_starts)
    ):
        raise PythonCwe611ScanError(PythonCwe611ScanErrorCode.INTEGRITY_FAILURE)
    start = line_starts[start_line] + start_column
    end = line_starts[end_line] + end_column
    if start < line_starts[start_line] or end > line_starts[end_line + 1] or end < start or end > len(source):
        raise PythonCwe611ScanError(PythonCwe611ScanErrorCode.INTEGRITY_FAILURE)
    return SourceRange(start, end, SourcePoint(start_line, start_column), SourcePoint(end_line, end_column))


def _compact(source: bytes, node: ast.AST) -> str:
    location = _node_range(node, source, _line_starts(source))
    return b"".join(source[location.start_byte : location.end_byte].split()).decode("ascii", "ignore")


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
    operation: PythonCwe611Operation,
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
    signals: tuple[PythonCwe611Signal, ...],
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


Cwe611ScanErrorCode = PythonCwe611ScanErrorCode
Cwe611ScanError = PythonCwe611ScanError
Cwe611ScanLimits = PythonCwe611ScanLimits
Cwe611ScanResult = PythonCwe611ScanResult
Cwe611Signal = PythonCwe611Signal


__all__ = [
    "DEFAULT_PYTHON_CWE611_SCAN_LIMITS",
    "Cwe611ScanError",
    "Cwe611ScanErrorCode",
    "Cwe611ScanLimits",
    "Cwe611ScanResult",
    "Cwe611Signal",
    "PythonCwe611Operation",
    "PythonCwe611ScanError",
    "PythonCwe611ScanErrorCode",
    "PythonCwe611ScanLimits",
    "PythonCwe611ScanResult",
    "PythonCwe611Signal",
    "scan_python_cwe611",
]
