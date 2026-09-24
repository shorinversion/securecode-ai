"""Bounded Go source-to-sink facts for CWE-502 unsafe deserialization.

The scanner consumes one sealed Go :class:`~securecode_ai.core.SymbolIndex` and
reparses the exact bytes before inspecting the CST.  It recognises the standard
``encoding/gob`` and ``encoding/json`` decoders together with the v2 and v3
``gopkg.in/yaml`` packages.  JSON is reported only when the destination is
polymorphic (``interface{}``, ``any``, or a container containing one); a normal
``json.Unmarshal`` into a statically typed structure is intentionally ignored.
Gob and YAML decoder calls are retained as deserialization boundaries because
their format and custom decoding hooks can materialize polymorphic values.

Results are immutable and source-free.  Source bytes are used only to rebuild
the sealed index and to calculate exact ranges; parser details and source text
never leave this module.
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
_RULE_ID = "securecode-go-cwe502"
_DETECTOR = "securecode-go-cwe502@1.0"

_GOB_PACKAGE = "encoding/gob"
_JSON_PACKAGE = "encoding/json"
_YAML_PACKAGES = frozenset({"gopkg.in/yaml.v2", "gopkg.in/yaml.v3"})
_DESERIALIZATION_PACKAGES = frozenset({_GOB_PACKAGE, _JSON_PACKAGE}) | _YAML_PACKAGES
_DECODER_CONSTRUCTORS = frozenset({"NewDecoder"})
_DYNAMIC_WORDS = frozenset({"any", "interface{}", "interface { }"})
_GO_SCOPES = frozenset({"function_declaration", "method_declaration", "func_literal"})


class GoCwe502ScanErrorCode(StrEnum):
    """Closed, source-free reasons a Go deserialization scan can fail."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class GoCwe502ScanError(RuntimeError):
    """Fixed scanner failure that never includes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GoCwe502ScanErrorCode) -> None:
        if type(code) is not GoCwe502ScanErrorCode:
            raise TypeError("Go CWE-502 scan error code is invalid")
        self.code = code
        self.safe_message = "Go CWE-502 deserialization scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GoCwe502ScanLimits:
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
            raise ValueError("Go CWE-502 scan limits are invalid")


DEFAULT_GO_CWE502_SCAN_LIMITS = GoCwe502ScanLimits()


class GoCwe502Operation(StrEnum):
    """Recognised Go deserialization operations."""

    GOB_DECODER_DECODE = "encoding/gob.Decoder.Decode"
    JSON_UNMARSHAL = "encoding/json.Unmarshal"
    JSON_DECODER_DECODE = "encoding/json.Decoder.Decode"
    YAML_UNMARSHAL = "gopkg.in/yaml.Unmarshal"
    YAML_UNMARSHAL_STRICT = "gopkg.in/yaml.UnmarshalStrict"
    YAML_DECODER_DECODE = "gopkg.in/yaml.Decoder.Decode"

    # Compatibility names used by generic scanner consumers.
    GOB_DECODE = "encoding/gob.Decoder.Decode"
    JSON_DECODE = "encoding/json.Decoder.Decode"
    YAML_DECODE = "gopkg.in/yaml.Decoder.Decode"


_DIRECT_OPERATIONS: dict[tuple[str, str], GoCwe502Operation] = {
    (_JSON_PACKAGE, "Unmarshal"): GoCwe502Operation.JSON_UNMARSHAL,
}
for _yaml_package in _YAML_PACKAGES:
    _DIRECT_OPERATIONS[(_yaml_package, "Unmarshal")] = GoCwe502Operation.YAML_UNMARSHAL
    _DIRECT_OPERATIONS[(_yaml_package, "UnmarshalStrict")] = (
        GoCwe502Operation.YAML_UNMARSHAL_STRICT
    )


@dataclass(frozen=True, slots=True)
class GoCwe502Signal:
    """One immutable deserialization-boundary fact without source text."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: GoCwe502Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-502"
    detector: str = _DETECTOR
    detail: str = "unsafe_deserialization_boundary"

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
            and 0 <= self.source.start_byte <= self.source.end_byte
            and self.source.end_byte <= self.sink.end_byte
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
            if valid_identity and valid_ranges and type(self.operation) is GoCwe502Operation
            else None
        )
        signal_id = self.signal_id or expected_id
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not GoCwe502Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected_id
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-502"
            or self.detector != _DETECTOR
            or self.detail != "unsafe_deserialization_boundary"
        ):
            raise ValueError("Go CWE-502 signal is invalid")
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
class GoCwe502ScanResult:
    """Deterministic, source-free CWE-502 output for one Go file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[GoCwe502Signal, ...]
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
            type(item) is GoCwe502Signal for item in self.signals
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
        same_identity = all(
            item.repository_id == self.repository_id
            and item.revision == self.revision
            and item.path == self.path
            and item.content_sha256 == self.content_sha256
            and item.source_size_bytes == self.source_size_bytes
            for item in self.signals
        )
        if (
            not identity_valid
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
                self.signals,
            )
        ):
            raise ValueError("Go CWE-502 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _DecoderBinding:
    package: str
    source: SourceRange


def scan_go_cwe502(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe502ScanLimits = DEFAULT_GO_CWE502_SCAN_LIMITS,
) -> GoCwe502ScanResult:
    """Find bounded Go gob, JSON, and YAML deserialization boundaries."""

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
        raise GoCwe502ScanError(GoCwe502ScanErrorCode.INTEGRITY_FAILURE) from None

    imports = _import_aliases(root, source)
    dynamic_types = _dynamic_type_names(root, source)
    raw: set[tuple[SourceRange, SourceRange, GoCwe502Operation]] = set()
    try:
        for scope in _scopes(root):
            dynamic_names: set[str] = set()
            decoders: dict[str, _DecoderBinding] = {}
            callable_aliases: dict[str, tuple[str, str]] = {}
            for node in _scope_preorder(scope):
                if node.type in {"short_var_declaration", "assignment_statement", "var_spec"}:
                    _capture_bindings(
                        node,
                        source,
                        imports,
                        dynamic_types,
                        dynamic_names,
                        decoders,
                        callable_aliases,
                        limits,
                    )
                if node.type != "call_expression":
                    continue
                detected = _operation_for_call(
                    node,
                    source,
                    imports,
                    decoders,
                    callable_aliases,
                )
                if detected is None:
                    continue
                operation, target, source_node = detected
                if operation in {
                    GoCwe502Operation.JSON_UNMARSHAL,
                    GoCwe502Operation.JSON_DECODER_DECODE,
                } and not _dynamic_target(target, source, dynamic_names, dynamic_types):
                    continue
                sink_range = _range(node)
                input_range = _range(source_node if source_node is not None else target)
                if not sink_range.contains(input_range):
                    raise GoCwe502ScanError(GoCwe502ScanErrorCode.INTEGRITY_FAILURE)
                raw.add((input_range, sink_range, operation))
                if len(raw) > limits.max_signals:
                    raise GoCwe502ScanError(GoCwe502ScanErrorCode.SIGNAL_LIMIT)
    except GoCwe502ScanError:
        raise
    except Exception:
        raise GoCwe502ScanError(GoCwe502ScanErrorCode.INTEGRITY_FAILURE) from None

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
        raise GoCwe502ScanError(GoCwe502ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        GoCwe502Signal(
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
    return GoCwe502ScanResult(
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


def scan_go_cwe502_unsafe_deserialization(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe502ScanLimits = DEFAULT_GO_CWE502_SCAN_LIMITS,
) -> GoCwe502ScanResult:
    """Descriptive alias for :func:`scan_go_cwe502`."""

    return scan_go_cwe502(symbol_index, limits=limits)


def scan_go_unsafe_deserialization(
    symbol_index: SymbolIndex,
    *,
    limits: GoCwe502ScanLimits = DEFAULT_GO_CWE502_SCAN_LIMITS,
) -> GoCwe502ScanResult:
    """Compatibility alias for callers grouping Go deserialization scans."""

    return scan_go_cwe502(symbol_index, limits=limits)


def _validate_request(symbol_index: SymbolIndex, limits: GoCwe502ScanLimits) -> None:
    if type(symbol_index) is not SymbolIndex or type(limits) is not GoCwe502ScanLimits:
        raise GoCwe502ScanError(GoCwe502ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != "go":
        raise GoCwe502ScanError(GoCwe502ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise GoCwe502ScanError(GoCwe502ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise GoCwe502ScanError(GoCwe502ScanErrorCode.ANALYSIS_UNAVAILABLE)


def _import_aliases(root: Node, source: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in _preorder(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        package = _text(source, path_node).strip('"`')
        if package not in _DESERIALIZATION_PACKAGES:
            continue
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            alias = _text(source, name_node)
        else:
            alias = "yaml" if package in _YAML_PACKAGES else package.rsplit("/", 1)[-1]
        if alias not in {".", "_"}:
            aliases[alias] = package
    return aliases


def _operation_for_call(
    node: Node,
    source: bytes,
    imports: dict[str, str],
    decoders: dict[str, _DecoderBinding],
    callable_aliases: dict[str, tuple[str, str]],
) -> tuple[GoCwe502Operation, Node, Node | None] | None:
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None:
        return None
    values = arguments.named_children
    if not values:
        return None

    direct = _qualified_function(function, source, imports, callable_aliases)
    if direct is not None:
        package, name = direct
        operation = _DIRECT_OPERATIONS.get((package, name))
        if operation is None:
            return None
        if operation is GoCwe502Operation.JSON_UNMARSHAL:
            if len(values) < 2:
                return None
            return operation, values[1], values[0]
        if operation in {
            GoCwe502Operation.YAML_UNMARSHAL,
            GoCwe502Operation.YAML_UNMARSHAL_STRICT,
        }:
            if len(values) < 2:
                return None
            return operation, values[1], values[0]

    if function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    name = _text(source, field)
    receiver = _compact_text(source, operand)
    package = imports.get(receiver)
    if package in _DESERIALIZATION_PACKAGES and name in _DECODER_CONSTRUCTORS:
        return None
    binding = decoders.get(receiver)
    if binding is None and name == "Decode":
        binding_package = _inline_decoder_package(operand, source, imports)
        if binding_package is not None:
            binding = _DecoderBinding(binding_package, _range(operand))
    if binding is None or name != "Decode":
        return None
    operation = {
        _GOB_PACKAGE: GoCwe502Operation.GOB_DECODER_DECODE,
        _JSON_PACKAGE: GoCwe502Operation.JSON_DECODER_DECODE,
        **{package_name: GoCwe502Operation.YAML_DECODER_DECODE for package_name in _YAML_PACKAGES},
    }.get(binding.package)
    if operation is None:
        return None
    return operation, values[-1], operand


def _inline_decoder_package(
    node: Node, source: bytes, imports: dict[str, str]
) -> str | None:
    """Return the package for an inline ``pkg.NewDecoder(...).Decode`` call."""

    if node.type != "call_expression":
        return None
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None or _text(source, field) != "NewDecoder":
        return None
    package = imports.get(_text(source, operand))
    return package if package in _DESERIALIZATION_PACKAGES else None


def _qualified_function(
    function: Node,
    source: bytes,
    imports: dict[str, str],
    callable_aliases: dict[str, tuple[str, str]],
) -> tuple[str, str] | None:
    if function.type == "identifier":
        return callable_aliases.get(_text(source, function))
    if function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    package = imports.get(_text(source, operand))
    return None if package is None else (package, _text(source, field))


def _capture_bindings(
    node: Node,
    source: bytes,
    imports: dict[str, str],
    dynamic_types: set[str],
    dynamic_names: set[str],
    decoders: dict[str, _DecoderBinding],
    callable_aliases: dict[str, tuple[str, str]],
    limits: GoCwe502ScanLimits,
) -> None:
    if node.type == "var_spec":
        name_node = node.child_by_field_name("name")
        type_node = node.child_by_field_name("type")
        value_node = node.child_by_field_name("value")
        names = name_node.named_children if name_node is not None else ()
        if name_node is not None and not names:
            names = (name_node,)
        declared_dynamic = type_node is not None and _is_dynamic_type(
            _compact_text(source, type_node), dynamic_types
        )
        for name in names:
            if name.type == "identifier" and declared_dynamic:
                dynamic_names.add(_text(source, name))
        if name_node is not None and value_node is not None:
            _capture_value_bindings(
                names,
                (value_node,),
                source,
                imports,
                dynamic_types,
                dynamic_names,
                decoders,
                callable_aliases,
                limits,
            )
        return
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return
    names = left.named_children if left.type == "expression_list" else (left,)
    values = right.named_children if right.type == "expression_list" else (right,)
    if len(values) == 1 and len(names) > 1:
        values = values * len(names)
    _capture_value_bindings(
        names,
        values,
        source,
        imports,
        dynamic_types,
        dynamic_names,
        decoders,
        callable_aliases,
        limits,
    )


def _capture_value_bindings(
    names: tuple[Node, ...],
    values: tuple[Node, ...],
    source: bytes,
    imports: dict[str, str],
    dynamic_types: set[str],
    dynamic_names: set[str],
    decoders: dict[str, _DecoderBinding],
    callable_aliases: dict[str, tuple[str, str]],
    limits: GoCwe502ScanLimits,
) -> None:
    if len(names) > limits.max_signals or len(values) > limits.max_signals:
        raise GoCwe502ScanError(GoCwe502ScanErrorCode.SIGNAL_LIMIT)
    for name, value in zip(names, values, strict=False):
        if name.type != "identifier":
            continue
        identifier = _text(source, name)
        if _is_dynamic_expression(value, source, dynamic_types, depth=0, limit=limits):
            dynamic_names.add(identifier)
        binding = _decoder_binding(value, source, imports)
        if binding is not None:
            decoders[identifier] = binding
        function = _qualified_function_from_value(value, source, imports)
        if function is not None:
            callable_aliases[identifier] = function


def _decoder_binding(node: Node, source: bytes, imports: dict[str, str]) -> _DecoderBinding | None:
    if node.type != "call_expression":
        return None
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None or _text(source, field) != "NewDecoder":
        return None
    package = imports.get(_text(source, operand))
    if package not in _DESERIALIZATION_PACKAGES:
        return None
    values = arguments.named_children
    source_node = values[0] if values else node
    return _DecoderBinding(package, _range(source_node))


def _qualified_function_from_value(
    node: Node, source: bytes, imports: dict[str, str]
) -> tuple[str, str] | None:
    if node.type != "selector_expression":
        return None
    operand = node.child_by_field_name("operand")
    field = node.child_by_field_name("field")
    if operand is None or field is None:
        return None
    package = imports.get(_text(source, operand))
    name = _text(source, field)
    if package in _DESERIALIZATION_PACKAGES and (
        (package == _JSON_PACKAGE and name == "Unmarshal")
        or package in _YAML_PACKAGES
        and name in {"Unmarshal", "UnmarshalStrict"}
    ):
        return package, name
    return None


def _dynamic_type_names(root: Node, source: bytes) -> set[str]:
    dynamic: set[str] = set()
    for node in _preorder(root):
        if node.type != "type_spec":
            continue
        name_node = node.child_by_field_name("name")
        type_node = node.child_by_field_name("type")
        if name_node is None or type_node is None:
            continue
        if _is_dynamic_type(_compact_text(source, type_node), dynamic):
            dynamic.add(_text(source, name_node))
    return dynamic


def _dynamic_target(
    node: Node,
    source: bytes,
    dynamic_names: set[str],
    dynamic_types: set[str],
) -> bool:
    current = node
    while current.type in {
        "parenthesized_expression",
        "unary_expression",
        "pointer_expression",
        "address_expression",
    }:
        children = current.named_children
        if not children:
            return False
        current = children[-1]
    if current.type == "identifier":
        return _text(source, current) in dynamic_names
    return _is_dynamic_expression(current, source, dynamic_types, depth=0)


def _is_dynamic_expression(
    node: Node,
    source: bytes,
    dynamic_types: set[str],
    *,
    depth: int,
    limit: GoCwe502ScanLimits | None = None,
) -> bool:
    if limit is not None and depth > limit.max_expression_depth:
        raise GoCwe502ScanError(GoCwe502ScanErrorCode.SIGNAL_LIMIT)
    if node.type in {"parenthesized_expression", "unary_expression", "pointer_expression"}:
        return any(
            _is_dynamic_expression(child, source, dynamic_types, depth=depth + 1, limit=limit)
            for child in node.named_children
        )
    compact = _compact_text(source, node)
    if not compact:
        return False
    if any(word in compact for word in ("interface{}", "interface{", "[]interface{}", "map[string]interface{}")):
        return True
    if re.search(r"(?:^|\W)any(?:$|\W)", compact):
        return True
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        if function is not None and _compact_text(source, function) == "new":
            arguments = node.child_by_field_name("arguments")
            values = arguments.named_children if arguments is not None else ()
            return bool(values) and _is_dynamic_expression(
                values[0], source, dynamic_types, depth=depth + 1, limit=limit
            )
    if node.type in {"type_identifier", "identifier"}:
        return compact in dynamic_types
    if node.type in {"composite_literal", "type_conversion_expression"}:
        type_node = node.child_by_field_name("type")
        if type_node is not None and _is_dynamic_type(
            _compact_text(source, type_node), dynamic_types
        ):
            return True
    return False


def _is_dynamic_type(type_text: str, dynamic_types: set[str]) -> bool:
    compact = "".join(type_text.split())
    if not compact:
        return False
    if compact in _DYNAMIC_WORDS or compact.endswith("interface{}"):  # map and slice forms
        return True
    if "interface{}" in compact or "[]interface{}" in compact:
        return True
    if re.search(r"(?:^|[\[\]{},])any(?:$|[\[\]{},])", compact):
        return True
    if compact in dynamic_types:
        return True
    if compact.startswith("struct{") and ("interface{}" in compact or "any" in compact):
        return True
    return False


def _scopes(root: Node) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node is root or node.type in _GO_SCOPES)


def _scope_preorder(scope: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    while stack:
        node = stack.pop()
        output.append(node)
        if node is not scope and node.type in _GO_SCOPES:
            continue
        stack.extend(reversed(node.named_children))
    return tuple(output)


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


def _compact_text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
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
    operation: GoCwe502Operation,
) -> str:
    material = {
        "content_sha256": content_sha256,
        "cwe": "CWE-502",
        "detector": _DETECTOR,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "sink": _range_value(sink),
        "source": _range_value(source),
        "source_size_bytes": source_size_bytes,
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    return "go-cwe502-" + digest


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[GoCwe502Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "detector": _DETECTOR,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "cwe": item.cwe,
                "detail": item.detail,
                "detector": item.detector,
                "operation": item.operation.value,
                "signal_id": item.signal_id,
                "sink": _range_value(item.sink),
                "source": _range_value(item.source),
            }
            for item in signals
        ],
        "source_size_bytes": source_size_bytes,
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


# Compatibility aliases keep this adapter usable beside existing CWE scanners.
Cwe502ScanErrorCode = GoCwe502ScanErrorCode
Cwe502ScanError = GoCwe502ScanError
Cwe502ScanLimits = GoCwe502ScanLimits
Cwe502ScanResult = GoCwe502ScanResult
Cwe502Signal = GoCwe502Signal


__all__ = [
    "Cwe502ScanError",
    "Cwe502ScanErrorCode",
    "Cwe502ScanLimits",
    "Cwe502ScanResult",
    "Cwe502Signal",
    "DEFAULT_GO_CWE502_SCAN_LIMITS",
    "GoCwe502Operation",
    "GoCwe502ScanError",
    "GoCwe502ScanErrorCode",
    "GoCwe502ScanLimits",
    "GoCwe502ScanResult",
    "GoCwe502Signal",
    "scan_go_cwe502",
    "scan_go_cwe502_unsafe_deserialization",
    "scan_go_unsafe_deserialization",
]
