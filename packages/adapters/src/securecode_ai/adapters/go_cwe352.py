"""Bounded production-only Go CWE-352 scanner facts.

The scanner consumes a sealed Go CST index and emits source-free locations for
request handlers with state-changing operations and no evident CSRF control.
It never executes or imports repository code.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import (
    CONTRACT_SCHEMA_VERSION,
    DataClass,
    ParseHealth,
    ProducerRef,
    RawSignal,
    RepositoryFile,
    SourceLocation,
    SourcePoint,
    SourcePosition,
    SourceRange,
    SymbolIndex,
)
from tree_sitter import Language, Node, Parser

from .cst import build_go_symbol_index
from .cst_go import _go_language
from .cst_models import CstAdapterError

_MAX_SOURCE_BYTES = 2_000_000
_MAX_SIGNALS = 2_048
_MAX_NODES = 100_000
_MAX_EXPRESSION_DEPTH = 64
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = "securecode-go-cwe352"
_DETECTOR = "securecode-go-cwe352@1.0"
_DETAIL = "mutating_http_handler_without_csrf_protection"
_HTTP_PACKAGE = "net/http"
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_HTTP_METHOD_CONSTANTS = {
    "MethodPost": "POST",
    "MethodPut": "PUT",
    "MethodPatch": "PATCH",
    "MethodDelete": "DELETE",
}
_MUTATION_CALLS = frozenset(
    {
        "Create",
        "CreateInBatches",
        "Delete",
        "Exec",
        "ExecContext",
        "Insert",
        "InsertOne",
        "Remove",
        "Save",
        "Update",
        "UpdateColumn",
        "UpdateColumns",
        "UpdateContext",
        "Updates",
        "WriteFile",
    }
)
_CSRF_MIDDLEWARE: dict[str, frozenset[str]] = {
    "github.com/gorilla/csrf": frozenset({"Protect"}),
    "github.com/justinas/nosurf": frozenset({"New", "NewPure", "NewWithBaseURL", "Handler"}),
    "github.com/go-chi/chi/middleware": frozenset({"CSRF"}),
    "github.com/go-chi/chi/v5/middleware": frozenset({"CSRF"}),
    "github.com/labstack/echo/v4/middleware": frozenset({"CSRF", "CSRFWithConfig"}),
    "github.com/utrack/gin-csrf": frozenset({"Middleware"}),
    "github.com/gofiber/fiber/v2/middleware/csrf": frozenset({"New"}),
}
_CSRF_VALIDATION: dict[str, frozenset[str]] = {
    "github.com/gorilla/csrf": frozenset({"ValidToken", "VerifyToken"}),
    "github.com/justinas/nosurf": frozenset({"VerifyToken", "Validate"}),
}
_FUNCTION_TYPES = _GO_SCOPES


class GoCwe352ScanErrorCode(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe352ScanError(RuntimeError):
    """Fixed, non-echoing Go CWE-352 analysis failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe352ScanErrorCode) -> None:
        if type(code) is not GoCwe352ScanErrorCode:
            raise TypeError("Go CWE-352 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-352 scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe352ScanLimits:
    """Hard ceilings applied before and during structural analysis."""

    max_source_bytes: int = _MAX_SOURCE_BYTES
    max_signals: int = _MAX_SIGNALS
    max_expression_depth: int = _MAX_EXPRESSION_DEPTH
    max_nodes: int = _MAX_NODES

    def __post_init__(self) -> None:
        values = (
            self.max_source_bytes,
            self.max_signals,
            self.max_expression_depth,
            self.max_nodes,
        )
        ceilings = (
            _MAX_SOURCE_BYTES,
            _MAX_SIGNALS,
            _MAX_EXPRESSION_DEPTH,
            _MAX_NODES,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, ceilings, strict=True)
        ):
            raise ValueError("Go CWE-352 scan limits are invalid")


DEFAULT_GO_CWE352_SCAN_LIMITS = GoCwe352ScanLimits()


class GoCwe352Operation(StrEnum):
    """Recognized mutation without a local CSRF control."""

    MUTATING_HANDLER_WITHOUT_CSRF = "mutating_http_handler_without_csrf"


@dataclass(frozen=True, slots=True)
class GoCwe352Signal:
    """One immutable, source-free CSRF fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe352Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-352"
    detector: str = _DETECTOR
    detail: str = _DETAIL

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
            and 0 <= self.source.start_byte <= self.source.end_byte
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
            if identity_valid and ranges_valid and type(self.operation) is GoCwe352Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not GoCwe352Operation
            or expected_id is None
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-352"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("Go CWE-352 signal is invalid")
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

    @property
    def handler(self) -> SourceRange:
        """Compatibility alias for older adapter consumers."""
        return self.sink

    @property
    def mutation(self) -> SourceRange:
        """Compatibility alias for older adapter consumers."""
        return self.source


@dataclass(frozen=True, slots=True)
class GoCwe352ScanResult:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe352Signal, ...]
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
        if type(self.signals) is not tuple or any(
            type(signal) is not GoCwe352Signal for signal in self.signals
        ):
            raise ValueError("Go CWE-352 scan result is invalid")
        ordering = tuple(
            (
                signal.sink.start_byte,
                signal.sink.end_byte,
                signal.source.start_byte,
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
            not identity_valid
            or ordering != tuple(sorted(ordering))
            or len(ordering) != len(set(ordering))
            or not same_identity
            or type(self.scan_sha256) is not str
            or _SHA256.fullmatch(self.scan_sha256) is None
            or self.scan_sha256
            != _scan_digest(
                self.repository_id,
                self.revision,
                self.path,
                self.content_sha256,
                self.source_size_bytes,
                self.signals,
            )
        ):
            raise ValueError("Go CWE-352 scan result is invalid")


def scan_go_cwe352(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe352ScanLimits = DEFAULT_GO_CWE352_SCAN_LIMITS,
) -> GoCwe352ScanResult:
    """Find production Go HTTP handlers with mutations and no CSRF control."""
    _validate_request(symbol_index, limits)
    try:
        rebuilt = build_go_symbol_index(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source=symbol_index.source,
        )
        if rebuilt != symbol_index:
            raise ValueError("sealed index mismatch")
        root = Parser(Language(_go_language())).parse(symbol_index.source).root_node
        if root.has_error:
            raise ValueError("parse error")
        symbol_index.source.decode("utf-8", errors="strict")
    except (CstAdapterError, TypeError, ValueError):
        raise GoCwe352ScanError(GoCwe352ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise GoCwe352ScanError(GoCwe352ScanErrorCode.INTEGRITY_FAILURE) from None

    nodes = _preorder(root, limits.max_nodes)
    if _is_nonproduction_path(symbol_index.path):
        return _result(symbol_index, ())
    source = symbol_index.source
    imports = _import_aliases(root, source)
    candidates: set[tuple[SourceRange, SourceRange, GoCwe352Operation]] = set()
    for function in nodes:
        if function.type not in _FUNCTION_TYPES:
            continue
        if not _has_http_request_parameter(function, source, imports):
            continue
        scope_nodes = _scope_preorder(function, limits.max_nodes, limits.max_expression_depth)
        for node in scope_nodes:
            if node.type != "call_expression":
                continue
            callee = node.child_by_field_name("function")
            if callee is None or _terminal_name(source, callee) not in _MUTATION_CALLS:
                continue
            if not _has_mutating_method_evidence(function, node, scope_nodes, source, imports):
                continue
            if _has_protection_for_mutation(function, node, scope_nodes, source, imports):
                continue
            candidates.add(
                (
                    _range(node),
                    _range(function),
                    GoCwe352Operation.MUTATING_HANDLER_WITHOUT_CSRF,
                )
            )
            if len(candidates) > limits.max_signals:
                raise GoCwe352ScanError(GoCwe352ScanErrorCode.SIGNAL_LIMIT)
    unique = sorted(
        candidates,
        key=lambda item: (
            item[1].start_byte,
            item[1].end_byte,
            item[0].start_byte,
            item[0].end_byte,
            item[2].value,
        ),
    )
    if len(unique) > limits.max_signals:
        raise GoCwe352ScanError(GoCwe352ScanErrorCode.SIGNAL_LIMIT)
    return _result(
        symbol_index,
        tuple(
            GoCwe352Signal(
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
            for source_range, sink_range, operation in unique
        ),
    )


def scan_go_csrf(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe352ScanLimits = DEFAULT_GO_CWE352_SCAN_LIMITS,
) -> GoCwe352ScanResult:
    """Descriptive alias for :func:`scan_go_cwe352`."""

    return scan_go_cwe352(symbol_index, limits=limits)


def scan_go_cwe352_csrf(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe352ScanLimits = DEFAULT_GO_CWE352_SCAN_LIMITS,
) -> GoCwe352ScanResult:
    """Compatibility alias for callers grouping CSRF scans."""

    return scan_go_cwe352(symbol_index, limits=limits)


def go_cwe352_signals_to_raw_signals(
    symbol_index: SymbolIndex,
    result: GoCwe352ScanResult,
    *,
    tenant_id: str,
    producer: ProducerRef,
) -> tuple[RawSignal, ...]:
    """Recompute production scan facts and bind source-free metadata to ingress."""
    if (
        type(symbol_index) is not SymbolIndex
        or type(result) is not GoCwe352ScanResult
        or type(tenant_id) is not str
        or not tenant_id
        or type(producer) is not ProducerRef
    ):
        raise GoCwe352ScanError(GoCwe352ScanErrorCode.REQUEST_INVALID)
    try:
        validated_producer = ProducerRef.model_validate(producer.model_dump(mode="python"))
        if (
            validated_producer.producer_id != "securecode-go-cwe352"
            or validated_producer.producer_version != "1.0.0"
            or scan_go_cwe352(symbol_index) != result
        ):
            raise ValueError("scan binding mismatch")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", tenant_id) is None:
            raise ValueError("tenant invalid")
        output = []
        for ordinal, signal in enumerate(result.signals):
            binding = {
                "ordinal": ordinal,
                "producer": validated_producer.model_dump(mode="json"),
                "scan_sha256": result.scan_sha256,
                "tenant_id": tenant_id,
            }
            digest = hashlib.sha256(
                json.dumps(binding, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            output.append(
                RawSignal(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    raw_signal_id=f"cwe352-go-{digest}",
                    tenant_id=tenant_id,
                    head_sha=signal.revision,
                    producer=validated_producer,
                    rule_id="cwe-352-csrf",
                    location=SourceLocation(
                        schema_version=CONTRACT_SCHEMA_VERSION,
                        path=signal.path,
                        start=SourcePosition(
                            schema_version=CONTRACT_SCHEMA_VERSION,
                            line=signal.mutation.start_point.row + 1,
                            column=signal.mutation.start_point.column + 1,
                        ),
                        end=SourcePosition(
                            schema_version=CONTRACT_SCHEMA_VERSION,
                            line=signal.mutation.end_point.row + 1,
                            column=signal.mutation.end_point.column + 1,
                        ),
                        content_sha256=signal.content_sha256,
                    ),
                    payload_classification=DataClass.INTERNAL_METADATA,
                    signal_sha256=digest,
                )
            )
        return tuple(output)
    except GoCwe352ScanError:
        raise
    except (ValueError, TypeError, AttributeError):
        raise GoCwe352ScanError(GoCwe352ScanErrorCode.INTEGRITY_FAILURE) from None


def _result(index: SymbolIndex, signals: tuple[GoCwe352Signal, ...]) -> GoCwe352ScanResult:
    return GoCwe352ScanResult(
        repository_id=index.repository_id,
        revision=index.revision,
        path=index.path,
        content_sha256=index.content_sha256,
        source_size_bytes=index.source_byte_length,
        signals=signals,
        scan_sha256=_scan_digest(
            index.repository_id,
            index.revision,
            index.path,
            index.content_sha256,
            index.source_byte_length,
            signals,
        ),
    )


def _scan_digest(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe352Signal, ...],
) -> str:
    body = {
        "content_sha256": content_sha256,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "detail": signal.detail,
                "detector": signal.detector,
                "operation": signal.operation.value,
                "signal_id": signal.signal_id,
                "sink": _range_value(signal.sink),
                "source": _range_value(signal.source),
            }
            for signal in signals
        ],
        "cwe": "CWE-352",
        "detector": _DETECTOR,
        "rule_id": _RULE_ID,
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
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


def _preorder(root: Node, max_nodes: int) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        output.append(node)
        if len(output) > max_nodes:
            raise GoCwe352ScanError(GoCwe352ScanErrorCode.NODE_LIMIT)
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe352ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe352ScanLimits:
        raise GoCwe352ScanError(GoCwe352ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go" or not symbol_index.path.casefold().endswith(".go"):
        raise GoCwe352ScanError(GoCwe352ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe352ScanError(GoCwe352ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe352ScanError(GoCwe352ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _scope_preorder(scope: Node, max_nodes: int, max_depth: int) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(scope, 0)]
    while stack:
        node, depth = stack.pop()
        output.append(node)
        if len(output) > max_nodes:
            raise GoCwe352ScanError(GoCwe352ScanErrorCode.NODE_LIMIT)
        if depth > max_depth:
            raise GoCwe352ScanError(GoCwe352ScanErrorCode.ANALYSIS_UNAVAILABLE)
        if node != scope and node.type in _FUNCTION_TYPES:
            continue
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _is_nonproduction_path(path: str) -> bool:
    normalized = path.replace("\\", "/").casefold()
    parts = set(normalized.split("/"))
    return (
        normalized.endswith("_test.go")
        or normalized.endswith("_testdata.go")
        or bool(
            parts.intersection(
                {
                    "doc",
                    "docs",
                    "example",
                    "examples",
                    "fixture",
                    "fixtures",
                    "test",
                    "tests",
                    "testdata",
                }
            )
        )
    )


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    relevant = {
        _HTTP_PACKAGE,
        *tuple(_CSRF_MIDDLEWARE),
        *tuple(_CSRF_VALIDATION),
    }
    for node in _preorder(root, _MAX_NODES):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None and node.named_children:
            path_node = node.named_children[-1]
        if path_node is None or path_node.type not in {
            "interpreted_string_literal",
            "raw_string_literal",
        }:
            continue
        package = _text(source, path_node).strip('"`')
        if package not in relevant:
            continue
        name_node = node.child_by_field_name("name")
        alias = _text(source, name_node) if name_node is not None else package.rsplit("/", 1)[-1]
        if alias not in {".", "_"}:
            aliases[alias] = package
    return aliases


def _has_http_request_parameter(
    function: Node,
    source: bytes,
    imports: dict[str, str],
) -> bool:
    http_aliases = {alias for alias, package in imports.items() if package == _HTTP_PACKAGE}
    if not http_aliases:
        return False
    parameters = function.child_by_field_name("parameters")
    if parameters is None:
        return False
    request = False
    response = False
    for parameter in _preorder(parameters, _MAX_NODES):
        if parameter.type != "parameter_declaration":
            continue
        type_node = parameter.child_by_field_name("type")
        if type_node is None:
            continue
        compact = _compact(source, type_node)
        if _is_http_type(compact, http_aliases, "Request"):
            request = True
        elif _is_http_type(compact, http_aliases, "ResponseWriter"):
            response = True
    return request and response


def _is_http_type(value: str, aliases: set[str], name: str) -> bool:
    return value.removeprefix("*") in {f"{alias}.{name}" for alias in aliases}


def _has_protection_for_mutation(
    function: Node,
    mutation: Node,
    scope_nodes: tuple[Node, ...],
    source: bytes,
    imports: dict[str, str],
) -> bool:
    if _has_ancestor_protection(function, source, imports):
        return True
    for node in scope_nodes:
        if node.type != "call_expression" or node.start_byte > mutation.start_byte:
            continue
        if _is_protection_call(node, source, imports):
            return True
    return False


def _has_ancestor_protection(
    function: Node,
    source: bytes,
    imports: dict[str, str],
) -> bool:
    parent = function.parent
    while parent is not None:
        if parent.type == "call_expression" and _is_protection_call(parent, source, imports):
            return True
        parent = parent.parent
    return False


def _is_protection_call(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    callee = node.child_by_field_name("function")
    if callee is None or callee.type != "selector_expression":
        return False
    method_node = callee.child_by_field_name("field")
    receiver_node = callee.child_by_field_name("operand")
    if method_node is None or receiver_node is None:
        return False
    method = _compact(source, method_node)
    package, alias = _receiver_package(receiver_node, source, imports)
    if package is None:
        return False
    if method in _CSRF_MIDDLEWARE.get(package, frozenset()):
        return True
    if method in _CSRF_VALIDATION.get(package, frozenset()):
        return True
    return package == _HTTP_PACKAGE and method == "Handler" and alias == "NewCrossOriginProtection"


def _receiver_package(
    node: Node,
    source: bytes,
    imports: dict[str, str],
) -> tuple[str | None, str | None]:
    if node.type == "identifier":
        alias = _compact(source, node)
        return imports.get(alias), alias
    if node.type == "selector_expression":
        field = node.child_by_field_name("field")
        operand = node.child_by_field_name("operand")
        if field is None or operand is None:
            return None, None
        package, _ = _receiver_package(operand, source, imports)
        return package, _compact(source, field)
    if node.type == "call_expression":
        callee = node.child_by_field_name("function")
        if callee is None or callee.type != "selector_expression":
            return None, None
        method = callee.child_by_field_name("field")
        receiver = callee.child_by_field_name("operand")
        if method is None or receiver is None:
            return None, None
        package, _ = _receiver_package(receiver, source, imports)
        return package, _compact(source, method)
    return None, None


def _has_mutating_method_evidence(
    function: Node,
    mutation: Node,
    scope_nodes: tuple[Node, ...],
    source: bytes,
    imports: dict[str, str],
) -> bool:
    parent = mutation.parent
    while parent is not None:
        if parent == function:
            break
        if parent.type == "if_statement":
            consequence = parent.child_by_field_name("consequence")
            condition = parent.child_by_field_name("condition")
            if (
                consequence is not None
                and condition is not None
                and consequence.start_byte <= mutation.start_byte
                and mutation.end_byte <= consequence.end_byte
                and _method_predicate(_compact(source, condition), imports)
            ):
                return True
        if parent.type == "expression_case" and _case_has_mutating_method(parent, source, imports):
            return True
        parent = parent.parent
    for node in scope_nodes:
        if node.type != "call_expression" or node.start_byte >= mutation.start_byte:
            continue
        if _route_method_call(node, source):
            return True
    return False


def _route_method_call(node: Node, source: bytes) -> bool:
    callee = node.child_by_field_name("function")
    if callee is None or callee.type != "selector_expression":
        return False
    field = callee.child_by_field_name("field")
    arguments = node.child_by_field_name("arguments")
    if field is None or arguments is None:
        return False
    method = _compact(source, field).upper()
    if method not in _MUTATING_METHODS or not arguments.named_children:
        return False
    first = arguments.named_children[0]
    return first.type in {"interpreted_string_literal", "raw_string_literal"}


def _method_predicate(condition: str, imports: dict[str, str]) -> bool:
    value = _strip_outer_parentheses(condition)
    alternatives = _split_top_level(value, "||")
    if len(alternatives) > 1:
        return all(_method_predicate(item, imports) for item in alternatives)
    conjunction = _split_top_level(value, "&&")
    if len(conjunction) > 1:
        method_parts = [item for item in conjunction if _is_method_comparison(item)]
        return bool(method_parts) and all(_method_predicate(item, imports) for item in method_parts)
    match = re.fullmatch(r"(.+?)(==|!=)(.+)", value)
    if match is None or match.group(2) != "==":
        return False
    left, right = match.group(1), match.group(3)
    return (_is_request_method(left) and _is_mutating_method(right, imports)) or (
        _is_request_method(right) and _is_mutating_method(left, imports)
    )


def _is_method_comparison(value: str) -> bool:
    match = re.fullmatch(r"(.+?)(==|!=)(.+)", _strip_outer_parentheses(value))
    return match is not None and (
        _is_request_method(match.group(1)) or _is_request_method(match.group(3))
    )


def _is_request_method(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.Method", value))


def _is_mutating_method(value: str, imports: dict[str, str]) -> bool:
    literal = value.strip('"`')
    if literal in _MUTATING_METHODS and value[:1] in {'"', "`"}:
        return True
    if "." not in value:
        return False
    alias, constant = value.rsplit(".", 1)
    return (
        imports.get(alias) == _HTTP_PACKAGE
        and _HTTP_METHOD_CONSTANTS.get(constant) in _MUTATING_METHODS
    )


def _case_has_mutating_method(node: Node, source: bytes, imports: dict[str, str]) -> bool:
    body_start = min(
        (child.start_byte for child in node.named_children if child.type == "block"),
        default=node.end_byte,
    )
    for child in _preorder(node, _MAX_NODES):
        if child.start_byte >= body_start:
            continue
        if _is_mutating_method(_compact(source, child), imports):
            return True
    return False


def _strip_outer_parentheses(value: str) -> str:
    while value.startswith("(") and value.endswith(")") and _balanced_parentheses(value[1:-1]):
        value = value[1:-1]
    return value


def _balanced_parentheses(value: str) -> bool:
    depth = 0
    for char in value:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _split_top_level(value: str, token: str) -> list[str]:
    depth = 0
    start = 0
    output: list[str] = []
    index = 0
    while index <= len(value) - len(token):
        char = value[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if depth == 0 and value.startswith(token, index):
            output.append(value[start:index])
            start = index + len(token)
            index += len(token)
            continue
        index += 1
    if output:
        output.append(value[start:])
        return [item for item in output if item]
    return [value]


def _terminal_name(source: bytes, node: Node) -> str:
    text = _compact(source, node)
    return re.split(r"[./]", text)[-1]


def _compact(source: bytes, node: Node) -> str:
    return b"".join(source[node.start_byte : node.end_byte].split()).decode(
        "ascii", errors="ignore"
    )


def _text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def _range(node: Node) -> SourceRange:
    return SourceRange(
        node.start_byte,
        node.end_byte,
        SourcePoint(node.start_point.row, node.start_point.column),
        SourcePoint(node.end_point.row, node.end_point.column),
    )


def _signal_id(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    source: SourceRange,
    sink: SourceRange,
    operation: GoCwe352Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-352",
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
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


Cwe352ScanErrorCode = GoCwe352ScanErrorCode
Cwe352ScanError = GoCwe352ScanError
Cwe352ScanLimits = GoCwe352ScanLimits
Cwe352ScanResult = GoCwe352ScanResult
Cwe352Signal = GoCwe352Signal


__all__ = [
    "DEFAULT_GO_CWE352_SCAN_LIMITS",
    "Cwe352ScanError",
    "Cwe352ScanErrorCode",
    "Cwe352ScanLimits",
    "Cwe352ScanResult",
    "Cwe352Signal",
    "GoCwe352Operation",
    "GoCwe352ScanError",
    "GoCwe352ScanErrorCode",
    "GoCwe352ScanLimits",
    "GoCwe352ScanResult",
    "GoCwe352Signal",
    "go_cwe352_signals_to_raw_signals",
    "scan_go_csrf",
    "scan_go_cwe352",
    "scan_go_cwe352_csrf",
]
