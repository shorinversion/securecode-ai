"""Bounded Go facts for CWE-327 use of weak cryptographic algorithms.

The scanner recognises a narrow, explicit set of standard-library APIs for
MD5, SHA-1, DES, 3DES, and RC4.  It accepts only a sealed :class:`SymbolIndex`
and rebuilds that index before walking the tree-sitter CST.  Findings carry
immutable identity, exact source ranges, and content-addressed identifiers;
source text and parser diagnostics never leave this module.

Files that are clearly tests, examples, fixtures, documentation, or generated
test data are ignored.  Package-level initialisers and test-like function
scopes are also ignored, which keeps constants and demonstration code from
turning into product findings.  Dynamic imports, dot imports, malformed trees,
and unresolved flow are handled conservatively by emitting no fact.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import (
    ParseHealth,
    RepositoryFile,
    SourcePoint,
    SourceRange,
    SymbolIndex,
)
from tree_sitter import Language, Node, Parser

from .cst import build_go_symbol_index
from .cst_go import _go_language

_MAX_LIMITS = (2_000_000, 2_048, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-go-cwe327"
_DETECTOR = "securecode-go-cwe327@1.0"
_DETAIL = "weak_cryptographic_algorithm"

_WEAK_PACKAGES = frozenset(
    {
        "crypto/des",
        "crypto/md5",
        "crypto/rc4",
        "crypto/sha1",
    }
)
_WEAK_OPERATIONS: dict[tuple[str, str], GoCwe327Operation] = {}
_IGNORED_PATH_PARTS = frozenset(
    {
        "doc",
        "docs",
        "example",
        "examples",
        "fixture",
        "fixtures",
        "test",
        "testdata",
        "tests",
    }
)
_IGNORED_SCOPE_PREFIXES = ("test", "benchmark", "example", "fuzz", "fixture", "golden")


class GoCwe327ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-327 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe327ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe327ScanErrorCode) -> None:
        if type(code) is not GoCwe327ScanErrorCode:
            raise TypeError("Go CWE-327 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-327 cryptographic algorithm scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe327ScanLimits:
    """Hard ceilings applied before and during structural analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("Go CWE-327 scan limits are invalid")


DEFAULT_GO_CWE327_SCAN_LIMITS = GoCwe327ScanLimits()


class GoCwe327Operation(StrEnum):
    """Recognised weak cryptographic constructors and digest operations."""

    DES_NEW_CIPHER = "crypto/des.NewCipher"
    DES_NEW_TRIPLE_DES_CIPHER = "crypto/des.NewTripleDESCipher"
    MD5_NEW = "crypto/md5.New"
    MD5_SUM = "crypto/md5.Sum"
    RC4_NEW_CIPHER = "crypto/rc4.NewCipher"
    SHA1_NEW = "crypto/sha1.New"
    SHA1_SUM = "crypto/sha1.Sum"

    # Compatibility names for generic scanner consumers.
    DES_CIPHER = "crypto/des.NewCipher"
    TRIPLE_DES_CIPHER = "crypto/des.NewTripleDESCipher"
    MD5 = "crypto/md5.New"
    SHA1 = "crypto/sha1.New"
    RC4 = "crypto/rc4.NewCipher"


_WEAK_OPERATIONS.update(
    {
        ("crypto/des", "NewCipher"): GoCwe327Operation.DES_NEW_CIPHER,
        ("crypto/des", "NewTripleDESCipher"): GoCwe327Operation.DES_NEW_TRIPLE_DES_CIPHER,
        ("crypto/md5", "New"): GoCwe327Operation.MD5_NEW,
        ("crypto/md5", "Sum"): GoCwe327Operation.MD5_SUM,
        ("crypto/rc4", "NewCipher"): GoCwe327Operation.RC4_NEW_CIPHER,
        ("crypto/sha1", "New"): GoCwe327Operation.SHA1_NEW,
        ("crypto/sha1", "Sum"): GoCwe327Operation.SHA1_SUM,
    }
)


@dataclass(frozen=True, slots=True)
class GoCwe327Signal:
    """One immutable weak-cryptography fact without source text."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe327Operation
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
            if valid_identity and valid_ranges and type(self.operation) is GoCwe327Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not GoCwe327Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-327"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-327 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", expected_id)

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
class GoCwe327ScanResult:
    """Deterministic, source-free CWE-327 output for one Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe327Signal, ...]
    scan_sha256: str

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
        order = tuple(
            (
                signal.sink.start_byte,
                signal.sink.end_byte,
                signal.source.start_byte,
                signal.source.end_byte,
                signal.operation.value,
            )
            for signal in self.signals
        )
        same_identity = all(
            signal.repository_id == self.repository_id
            and signal.revision == self.revision
            and signal.path == self.path
            and signal.content_sha256 == self.content_sha256
            and signal.source_size_bytes == self.source_size_bytes
            for signal in self.signals
        )
        if (
            not valid_identity
            or type(self.signals) is not tuple
            or any(type(signal) is not GoCwe327Signal for signal in self.signals)
            or not same_identity
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
            or len({signal.signal_id for signal in self.signals}) != len(self.signals)
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
            raise ValueError("Go CWE-327 scan result is invalid")


def scan_go_cwe327(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe327ScanLimits = DEFAULT_GO_CWE327_SCAN_LIMITS,
) -> GoCwe327ScanResult:
    """Find standard-library calls that select weak cryptographic algorithms."""

    _validate_request(symbol_index, limits)
    source = symbol_index.source
    try:
        rebuilt = build_go_symbol_index(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source=source,
        )
        if rebuilt != symbol_index:
            raise ValueError("index mismatch")
        root = Parser(Language(_go_language())).parse(source).root_node
        if root.has_error:
            raise ValueError("parse error")
        source.decode("utf-8", errors="strict")
    except Exception:
        raise GoCwe327ScanError(GoCwe327ScanErrorCode.INTEGRITY_FAILURE) from None

    if _is_nonproduction_path(symbol_index.path):
        return _empty_result(symbol_index)

    imports = _import_aliases(root, source)
    raw: set[tuple[SourceRange, SourceRange, GoCwe327Operation]] = set()
    try:
        for scope in _scopes(root):
            if _is_ignored_scope(scope, source):
                continue
            depth = 0
            stack: list[tuple[Node, int]] = [(scope, 0)]
            while stack:
                node, depth = stack.pop()
                if depth > limits.max_expression_depth:
                    raise GoCwe327ScanError(GoCwe327ScanErrorCode.ANALYSIS_UNAVAILABLE)
                if node.type == "call_expression":
                    operation = _operation_for_call(node, source, imports)
                    if operation is not None:
                        function = node.child_by_field_name("function")
                        if function is not None:
                            raw.add((_range(function), _range(node), operation))
                            if len(raw) > limits.max_signals:
                                raise GoCwe327ScanError(GoCwe327ScanErrorCode.SIGNAL_LIMIT)
                stack.extend((child, depth + 1) for child in reversed(node.named_children))
    except GoCwe327ScanError:
        raise
    except Exception:
        raise GoCwe327ScanError(GoCwe327ScanErrorCode.INTEGRITY_FAILURE) from None

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
        raise GoCwe327ScanError(GoCwe327ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe327Signal(
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
    return GoCwe327ScanResult(
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


def scan_go_weak_crypto(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe327ScanLimits = DEFAULT_GO_CWE327_SCAN_LIMITS,
) -> GoCwe327ScanResult:
    """Descriptive alias for :func:`scan_go_cwe327`."""

    return scan_go_cwe327(symbol_index, limits=limits)


def scan_go_weak_cryptography(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe327ScanLimits = DEFAULT_GO_CWE327_SCAN_LIMITS,
) -> GoCwe327ScanResult:
    """Compatibility alias for callers grouping cryptographic scans."""

    return scan_go_cwe327(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe327ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe327ScanLimits:
        raise GoCwe327ScanError(GoCwe327ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe327ScanError(GoCwe327ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe327ScanError(GoCwe327ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe327ScanError(GoCwe327ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        package = _text(source, path_node).strip('"`')
        if package not in _WEAK_PACKAGES:
            continue
        name_node = node.child_by_field_name("name")
        alias = _text(source, name_node) if name_node is not None else package.rsplit("/", 1)[-1]
        if alias not in {".", "_"}:
            aliases[alias] = package
    return aliases


def _operation_for_call(
    node: Node, source: bytes, imports: dict[str, str]
) -> GoCwe327Operation | None:
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    package = imports.get(_text(source, operand))
    if package is None:
        return None
    return _WEAK_OPERATIONS.get((package, _text(source, field)))


def _scopes(root: Node) -> tuple[Node, ...]:
    return tuple(
        node
        for node in _preorder(root)
        if node.type in {"function_declaration", "method_declaration", "func_literal"}
    )


def _is_ignored_scope(scope: Node, source: bytes) -> bool:
    name = scope.child_by_field_name("name")
    if name is None:
        return False
    normalized = _text(source, name).casefold()
    return normalized.startswith(_IGNORED_SCOPE_PREFIXES)


def _is_nonproduction_path(path: str) -> bool:
    normalized = path.replace("\\", "/").casefold()
    basename = normalized.rsplit("/", 1)[-1]
    if basename.endswith("_test.go") or basename.endswith("_testdata.go"):
        return True
    return any(part in _IGNORED_PATH_PARTS for part in normalized.split("/"))


def _empty_result(symbol_index: SymbolIndex) -> GoCwe327ScanResult:
    signals: tuple[GoCwe327Signal, ...] = ()
    return GoCwe327ScanResult(
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


def _preorder(root: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        output.append(node)
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _text(source: bytes, node: Node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")


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
    operation: GoCwe327Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "sink": _range_value(sink),
        "source": _range_value(source),
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe327Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "cwe": signal.cwe,
                "detail": signal.detail,
                "detector": signal.detector,
                "operation": signal.operation.value,
                "sink": _range_value(signal.sink),
                "source": _range_value(signal.source),
            }
            for signal in signals
        ],
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


__all__ = [
    "DEFAULT_GO_CWE327_SCAN_LIMITS",
    "GoCwe327Operation",
    "GoCwe327ScanError",
    "GoCwe327ScanErrorCode",
    "GoCwe327ScanLimits",
    "GoCwe327ScanResult",
    "GoCwe327Signal",
    "scan_go_cwe327",
    "scan_go_weak_crypto",
    "scan_go_weak_cryptography",
]
