"""Bounded JavaScript and TypeScript CWE-1333 ReDoS facts.

The scanner consumes a sealed ECMAScript :class:`~securecode_ai.core.SymbolIndex`
and reparses the exact admitted bytes before inspecting the CST.  It recognizes
regular-expression literals, ``RegExp`` construction, and the common
``match``/``test``/``exec`` invocation forms.  Only patterns with an
unbounded nested or overlapping quantifier are admitted as facts.  The small
pattern parser is intentionally conservative: an unknown construct is
ignored instead of being promoted to a finding.

Returned signals contain immutable ranges and content-addressed metadata only.
Pattern text is used transiently while scanning and is never retained in a
signal or an error.  This module is a scanner primitive, not a finding or a
verdict.
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

_MAX_LIMITS = (2_000_000, 250_000, 512, 10_000, 16_384, 50_000)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_QUANTIFIER = re.compile(r"\{([0-9]{1,6})(?:,([0-9]{1,6})?)?\}")
_RULE_ID = "securecode-ecmascript-cwe1333"
_DETECTOR = "securecode-ecmascript-cwe1333@1.0"


class EcmaScriptCwe1333ScanErrorCode(StrEnum):
    """Closed, source-free reasons a CWE-1333 scan cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    PATTERN_LIMIT = "PATTERN_LIMIT"
    ALIAS_LIMIT = "ALIAS_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe1333ScanError(RuntimeError):
    """Fixed scanner failure that never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe1333ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe1333ScanErrorCode:
            raise TypeError("ECMAScript CWE-1333 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-1333 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class EcmaScriptCwe1333Operation(StrEnum):
    """Recognized regular-expression construction and invocation operations."""

    REGEX_LITERAL = "regex_literal"
    REGEXP_CONSTRUCTOR = "regexp_constructor"
    REGEXP_CALL = "regexp_call"
    STRING_MATCH = "string_match"
    REGEXP_TEST = "regexp_test"
    REGEXP_EXEC = "regexp_exec"

    # Compatibility names used by callers that group APIs by operation kind.
    REGEXP = "regexp_constructor"
    REGEXP_FUNCTION = "regexp_call"
    CONSTRUCTOR = "regexp_constructor"
    MATCH = "string_match"
    TEST = "regexp_test"
    EXEC = "regexp_exec"


class EcmaScriptCwe1333Risk(StrEnum):
    """Structural reason a pattern may cause catastrophic backtracking."""

    NESTED_QUANTIFIER = "nested_quantifier"
    AMBIGUOUS_QUANTIFIER = "ambiguous_quantifier"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe1333ScanLimits:
    """Hard ceilings applied before and during structural analysis."""

    max_source_bytes: int = _MAX_LIMITS[0]
    max_nodes: int = _MAX_LIMITS[1]
    max_depth: int = _MAX_LIMITS[2]
    max_signals: int = _MAX_LIMITS[3]
    max_pattern_bytes: int = _MAX_LIMITS[4]
    max_aliases: int = _MAX_LIMITS[5]

    def __post_init__(self) -> None:
        values = (
            self.max_source_bytes,
            self.max_nodes,
            self.max_depth,
            self.max_signals,
            self.max_pattern_bytes,
            self.max_aliases,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("ECMAScript CWE-1333 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE1333_SCAN_LIMITS = EcmaScriptCwe1333ScanLimits()


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe1333Signal:
    """One immutable regular-expression-to-API ReDoS fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe1333Operation
    signal_id: str = ""
    risk: EcmaScriptCwe1333Risk = EcmaScriptCwe1333Risk.NESTED_QUANTIFIER
    rule_id: str = _RULE_ID
    cwe: str = "CWE-1333"
    detector: str = _DETECTOR
    detail: str = "catastrophic_backtracking"

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
                self.risk,
            )
            if valid_identity
            and valid_ranges
            and type(self.operation) is EcmaScriptCwe1333Operation
            and type(self.risk) is EcmaScriptCwe1333Risk
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not valid_identity
            or not valid_ranges
            or type(self.operation) is not EcmaScriptCwe1333Operation
            or type(self.risk) is not EcmaScriptCwe1333Risk
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-1333"
            or self.detector != _DETECTOR
            or self.detail != "catastrophic_backtracking"
        ):
            raise ValueError("ECMAScript CWE-1333 signal is invalid")
        if not self.signal_id:
            object.__setattr__(self, "signal_id", signal_id)

    @property
    def deterministic_id(self) -> str:
        """Compatibility name used by generic scanner consumers."""

        return self.signal_id

    @property
    def location(self) -> SourceRange:
        """Return the API or literal range used by generic consumers."""

        return self.sink

    @property
    def source_range(self) -> SourceRange:
        return self.source

    @property
    def sink_range(self) -> SourceRange:
        return self.sink


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe1333ScanResult:
    """Source-free, deterministic result for one ECMAScript file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe1333Signal, ...]
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
            type(item) is EcmaScriptCwe1333Signal for item in self.signals
        )
        order = (
            tuple(
                (
                    item.sink.start_byte,
                    item.sink.end_byte,
                    item.source.start_byte,
                    item.source.end_byte,
                    item.operation.value,
                    item.risk.value,
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
            raise ValueError("ECMAScript CWE-1333 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _RegexDescriptor:
    source: Node
    sink: Node
    operation: EcmaScriptCwe1333Operation
    risk: EcmaScriptCwe1333Risk


@dataclass(frozen=True, slots=True)
class _PatternAtom:
    """Small internal regular-expression syntax summary."""

    key: str
    start: int
    end: int
    branches: tuple[tuple["_PatternAtom", ...], ...] = ()
    minimum: int = 1
    maximum: int | None = 1


def scan_javascript_cwe1333(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe1333ScanLimits = DEFAULT_ECMASCRIPT_CWE1333_SCAN_LIMITS,
) -> EcmaScriptCwe1333ScanResult:
    """Find bounded JavaScript ReDoS regular-expression facts."""

    return _scan_ecmascript_cwe1333(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe1333(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe1333ScanLimits = DEFAULT_ECMASCRIPT_CWE1333_SCAN_LIMITS,
) -> EcmaScriptCwe1333ScanResult:
    """Find bounded TypeScript ReDoS regular-expression facts."""

    return _scan_ecmascript_cwe1333(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe1333(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe1333ScanLimits = DEFAULT_ECMASCRIPT_CWE1333_SCAN_LIMITS,
) -> EcmaScriptCwe1333ScanResult:
    """Dispatch a CWE-1333 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe1333(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe1333(symbol_index, limits=limits)
    raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe1333(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe1333ScanLimits,
) -> EcmaScriptCwe1333ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe1333ScanLimits:
        raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.ANALYSIS_UNAVAILABLE)

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
        raise EcmaScriptCwe1333ScanError(
            EcmaScriptCwe1333ScanErrorCode.INTEGRITY_FAILURE
        ) from None
    except Exception:
        raise EcmaScriptCwe1333ScanError(
            EcmaScriptCwe1333ScanErrorCode.INTEGRITY_FAILURE
        ) from None

    nodes = _bounded_nodes(root, limits)
    if any(node.type == "ERROR" or node.is_missing for node in nodes):
        raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.ANALYSIS_UNAVAILABLE)
    try:
        aliases, string_aliases = _collect_aliases(nodes, source, limits)
        raw: set[
            tuple[SourceRange, SourceRange, EcmaScriptCwe1333Operation, EcmaScriptCwe1333Risk]
        ] = set()
        for node in nodes:
            if node.type == "regex":
                descriptor = _descriptor_from_node(
                    node, source, aliases, string_aliases, limits, frozenset()
                )
                if descriptor is not None and not _is_regex_api_operand(node):
                    _add_fact(raw, node, node, descriptor, limits)
            elif node.type in {"call_expression", "new_expression"}:
                for source_node, sink_node, operation, risk in _node_facts(
                    node, source, aliases, string_aliases, limits
                ):
                    _add_fact(
                        raw,
                        source_node,
                        sink_node,
                        _RegexDescriptor(source_node, sink_node, operation, risk),
                        limits,
                    )
        ordered = sorted(
            raw,
            key=lambda item: (
                item[1].start_byte,
                item[1].end_byte,
                item[0].start_byte,
                item[0].end_byte,
                item[2].value,
                item[3].value,
            ),
        )
    except EcmaScriptCwe1333ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe1333ScanError(
            EcmaScriptCwe1333ScanErrorCode.INTEGRITY_FAILURE
        ) from None

    if len(ordered) > limits.max_signals:
        raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        EcmaScriptCwe1333Signal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            source=source_range,
            sink=sink_range,
            operation=operation,
            risk=risk,
            signal_id=_signal_id(
                symbol_index.repository_id,
                symbol_index.revision,
                symbol_index.path,
                symbol_index.content_sha256,
                symbol_index.source_byte_length,
                source_range,
                sink_range,
                operation,
                risk,
            ),
        )
        for source_range, sink_range, operation, risk in ordered
    )
    return EcmaScriptCwe1333ScanResult(
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


def _node_facts(
    node: Node,
    source: bytes,
    aliases: dict[str, str | _RegexDescriptor],
    string_aliases: dict[str, str],
    limits: EcmaScriptCwe1333ScanLimits,
) -> tuple[tuple[Node, Node, EcmaScriptCwe1333Operation, EcmaScriptCwe1333Risk], ...]:
    values: list[Node] = []
    if node.type == "new_expression":
        constructor = node.child_by_field_name("constructor")
        arguments = node.child_by_field_name("arguments")
        if constructor is None or arguments is None:
            return ()
        canonical = _canonical_expression(constructor, source, aliases)
        if canonical not in {"RegExp", "globalThis.RegExp", "window.RegExp"}:
            return ()
        values = list(arguments.named_children)
        if not values:
            return ()
        descriptor = _descriptor_from_constructor(
            node, values[0], source, aliases, string_aliases, limits, new=True
        )
        if descriptor is None:
            return ()
        return ((_source_for_use(values[0], node, descriptor, source), node, descriptor.operation, descriptor.risk),)

    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None:
        return ()
    canonical = _canonical_expression(function, source, aliases)
    values = list(arguments.named_children)
    facts: list[tuple[Node, Node, EcmaScriptCwe1333Operation, EcmaScriptCwe1333Risk]] = []
    if canonical in {"RegExp", "globalThis.RegExp", "window.RegExp"} and values:
        descriptor = _descriptor_from_constructor(
            node, values[0], source, aliases, string_aliases, limits, new=False
        )
        if descriptor is not None:
            facts.append(
                (
                    _source_for_use(values[0], node, descriptor, source),
                    node,
                    descriptor.operation,
                    descriptor.risk,
                )
            )
    elif _is_string_match(canonical):
        regex_node = _match_regex_argument(canonical, values)
        if regex_node is not None:
            descriptor = _descriptor_from_node(
                regex_node, source, aliases, string_aliases, limits, frozenset()
            )
            if descriptor is not None:
                facts.append(
                    (
                        _source_for_use(regex_node, node, descriptor, source),
                        node,
                        EcmaScriptCwe1333Operation.STRING_MATCH,
                        descriptor.risk,
                    )
                )
    elif _is_regexp_method(canonical, "test"):
        regex_node = _receiver_or_call_argument(function, values, "test", canonical)
        if regex_node is not None:
            descriptor = _descriptor_from_node(
                regex_node, source, aliases, string_aliases, limits, frozenset()
            )
            if descriptor is not None:
                facts.append(
                    (
                        _source_for_use(regex_node, node, descriptor, source),
                        node,
                        EcmaScriptCwe1333Operation.REGEXP_TEST,
                        descriptor.risk,
                    )
                )
    elif _is_regexp_method(canonical, "exec"):
        regex_node = _receiver_or_call_argument(function, values, "exec", canonical)
        if regex_node is not None:
            descriptor = _descriptor_from_node(
                regex_node, source, aliases, string_aliases, limits, frozenset()
            )
            if descriptor is not None:
                facts.append(
                    (
                        _source_for_use(regex_node, node, descriptor, source),
                        node,
                        EcmaScriptCwe1333Operation.REGEXP_EXEC,
                        descriptor.risk,
                    )
                )
    return tuple(facts)


def _add_fact(
    raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe1333Operation, EcmaScriptCwe1333Risk]],
    source_node: Node,
    sink_node: Node,
    descriptor: _RegexDescriptor,
    limits: EcmaScriptCwe1333ScanLimits,
) -> None:
    source_range = _range(source_node)
    sink_range = _range(sink_node)
    if not sink_range.contains(source_range):
        raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.INTEGRITY_FAILURE)
    raw.add((source_range, sink_range, descriptor.operation, descriptor.risk))
    if len(raw) > limits.max_signals:
        raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.SIGNAL_LIMIT)


def _descriptor_from_constructor(
    sink: Node,
    pattern_node: Node,
    source: bytes,
    aliases: dict[str, str | _RegexDescriptor],
    string_aliases: dict[str, str],
    limits: EcmaScriptCwe1333ScanLimits,
    *,
    new: bool,
) -> _RegexDescriptor | None:
    pattern = _pattern_for_node(pattern_node, source, string_aliases, limits, frozenset())
    if pattern is None:
        return None
    risk = _pattern_risk(pattern, limits)
    if risk is None:
        return None
    return _RegexDescriptor(
        source=pattern_node,
        sink=sink,
        operation=(
            EcmaScriptCwe1333Operation.REGEXP_CONSTRUCTOR
            if new
            else EcmaScriptCwe1333Operation.REGEXP_CALL
        ),
        risk=risk,
    )


def _descriptor_from_node(
    node: Node,
    source: bytes,
    aliases: dict[str, str | _RegexDescriptor],
    string_aliases: dict[str, str],
    limits: EcmaScriptCwe1333ScanLimits,
    visited: frozenset[str],
) -> _RegexDescriptor | None:
    if node.type == "identifier":
        name = _node_text(source, node)
        if name in visited:
            return None
        # ``aliases`` stores canonical names, while regex values are kept in a
        # private attribute populated by the scan pass.  A direct binding is
        # resolved by looking at its declaration instead of retaining source.
        return _descriptor_from_identifier(
            name, node, source, aliases, string_aliases, limits, visited
        )
    if node.type == "regex":
        pattern = _regex_literal_pattern(node, source, limits)
        risk = _pattern_risk(pattern, limits) if pattern is not None else None
        if risk is None:
            return None
        return _RegexDescriptor(
            source=node,
            sink=node,
            operation=EcmaScriptCwe1333Operation.REGEX_LITERAL,
            risk=risk,
        )
    if node.type in {"call_expression", "new_expression"}:
        function = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or not arguments.named_children:
            return None
        canonical = _canonical_expression(function, source, aliases)
        if canonical not in {"RegExp", "globalThis.RegExp", "window.RegExp"}:
            return None
        return _descriptor_from_constructor(
            node,
            arguments.named_children[0],
            source,
            aliases,
            string_aliases,
            limits,
            new=node.type == "new_expression",
        )
    if node.type in {
        "parenthesized_expression",
        "as_expression",
        "type_assertion",
        "non_null_expression",
    }:
        children = node.named_children
        return (
            _descriptor_from_node(
                children[-1], source, aliases, string_aliases, limits, visited
            )
            if children
            else None
        )
    return None


def _descriptor_from_identifier(
    name: str,
    use: Node,
    source: bytes,
    aliases: dict[str, str | _RegexDescriptor],
    string_aliases: dict[str, str],
    limits: EcmaScriptCwe1333ScanLimits,
    visited: frozenset[str],
) -> _RegexDescriptor | None:
    # Alias declarations are indexed once per scan in ``_REGEX_BINDINGS``.
    # Keeping this lookup local to the call avoids adding source text to a
    # result; the dictionary is passed through the alias map under a reserved
    # canonical key.
    binding = aliases.get(f"__securecode_regex__:{name}")
    if not isinstance(binding, _RegexDescriptor):
        return None
    if name in visited:
        return None
    return binding


def _source_for_use(
    candidate: Node, sink: Node, descriptor: _RegexDescriptor, source: bytes
) -> Node:
    candidate_range = _range(candidate)
    sink_range = _range(sink)
    if sink_range.contains(candidate_range):
        return candidate
    if sink_range.contains(_range(descriptor.source)):
        return descriptor.source
    raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.INTEGRITY_FAILURE)


def _collect_aliases(
    nodes: tuple[Node, ...],
    source: bytes,
    limits: EcmaScriptCwe1333ScanLimits,
) -> tuple[dict[str, str | _RegexDescriptor], dict[str, str]]:
    aliases: dict[str, str | _RegexDescriptor] = {}
    string_aliases: dict[str, str] = {}
    for node in nodes:
        if node.type == "import_statement":
            _collect_import_aliases(node, source, aliases)
            continue
        if node.type not in {"variable_declarator", "assignment_expression"}:
            continue
        left = node.child_by_field_name("name") if node.type == "variable_declarator" else node.child_by_field_name("left")
        right = node.child_by_field_name("value") if node.type == "variable_declarator" else node.child_by_field_name("right")
        if left is None or right is None or left.type != "identifier":
            continue
        name = _node_text(source, left)
        static_string = _pattern_for_node(right, source, string_aliases, limits, frozenset())
        if static_string is not None and _static_string_node(right, source, string_aliases) is not None:
            string_aliases[name] = static_string
        descriptor = _descriptor_from_node(
            right, source, aliases, string_aliases, limits, frozenset()
        )
        if descriptor is not None:
            aliases[f"__securecode_regex__:{name}"] = descriptor
        canonical = _canonical_expression(right, source, aliases)
        if canonical is not None:
            aliases[name] = canonical
        if len(aliases) + len(string_aliases) > limits.max_aliases:
            raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.ALIAS_LIMIT)
    return aliases, string_aliases


def _collect_import_aliases(
    node: Node, source: bytes, aliases: dict[str, str | _RegexDescriptor]
) -> None:
    module_node = node.child_by_field_name("source")
    if module_node is None:
        return
    module = _static_string_node(module_node, source, {})
    if module is None:
        return
    for child in node.named_children:
        if child.type != "import_clause":
            continue
        for item in child.named_children:
            if item.type in {"identifier", "namespace_import"}:
                identifier = item if item.type == "identifier" else item.named_children[0]
                aliases[_node_text(source, identifier)] = module
            elif item.type in {"named_imports", "named_import"}:
                for specifier in item.named_children:
                    if specifier.type != "import_specifier":
                        continue
                    names = list(specifier.named_children)
                    if not names:
                        continue
                    imported = _node_text(source, names[0])
                    local = _node_text(source, names[-1])
                    aliases[local] = f"{module}.{imported}"


def _canonical_expression(
    node: Node, source: bytes, aliases: dict[str, str | _RegexDescriptor]
) -> str | None:
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or _compact_text(source, function) != "require":
            return None
        values = list(arguments.named_children)
        if len(values) != 1:
            return None
        return _static_string_node(values[0], source, {})
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


def _canonical_name(value: str, aliases: dict[str, str | _RegexDescriptor]) -> str:
    parts = value.split(".")
    if not parts or not _IDENTIFIER.fullmatch(parts[0]):
        return value
    alias = aliases.get(parts[0], parts[0])
    base = alias if isinstance(alias, str) else parts[0]
    return ".".join((base, *parts[1:])) if len(parts) > 1 else base


def _is_string_match(canonical: str | None) -> bool:
    return canonical is not None and (
        canonical.endswith(".match")
        or canonical.endswith(".match.call")
        or canonical in {"match", "String.match", "String.prototype.match"}
    )


def _match_regex_argument(canonical: str, values: list[Node]) -> Node | None:
    if not values:
        return None
    if canonical.endswith(".match.call") or canonical in {"String.match", "String.prototype.match"}:
        return values[-1] if len(values) >= 2 else None
    return values[0]


def _is_regexp_method(canonical: str | None, name: str) -> bool:
    return canonical is not None and (
        canonical.endswith(f".{name}")
        or canonical.endswith(f".{name}.call")
        or canonical == name
    )


def _receiver_or_call_argument(
    function: Node, values: list[Node], name: str, canonical: str | None
) -> Node | None:
    if canonical is not None and canonical.endswith(f".{name}.call"):
        return values[0] if values else None
    if function.type in {"member_expression", "subscript_expression"}:
        object_node = function.child_by_field_name("object")
        if object_node is not None:
            return object_node
    return values[0] if values else None


def _is_regex_api_operand(node: Node) -> bool:
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "arguments":
        call = parent.parent
        return call is not None and call.type in {"call_expression", "new_expression"}
    if parent.type in {"member_expression", "subscript_expression"}:
        call = parent.parent
        return call is not None and call.type == "call_expression"
    return False


def _pattern_for_node(
    node: Node,
    source: bytes,
    string_aliases: dict[str, str],
    limits: EcmaScriptCwe1333ScanLimits,
    visited: frozenset[str],
) -> str | None:
    if node.type == "regex":
        return _regex_literal_pattern(node, source, limits)
    static = _static_string_node(node, source, string_aliases)
    if static is not None:
        if len(static.encode("utf-8")) > limits.max_pattern_bytes:
            raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.PATTERN_LIMIT)
        return static
    if node.type == "identifier":
        name = _node_text(source, node)
        if name in visited:
            return None
        return string_aliases.get(name)
    if node.type == "binary_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        operator = node.child_by_field_name("operator")
        if left is None or right is None or operator is None or _compact_text(source, operator) != "+":
            return None
        left_value = _pattern_for_node(left, source, string_aliases, limits, visited)
        right_value = _pattern_for_node(right, source, string_aliases, limits, visited)
        if left_value is None or right_value is None:
            return None
        value = left_value + right_value
        if len(value.encode("utf-8")) > limits.max_pattern_bytes:
            raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.PATTERN_LIMIT)
        return value
    if node.type in {"parenthesized_expression", "as_expression", "type_assertion"}:
        children = node.named_children
        return (
            _pattern_for_node(children[-1], source, string_aliases, limits, visited)
            if children
            else None
        )
    return None


def _static_string_node(
    node: Node, source: bytes, aliases: dict[str, str]
) -> str | None:
    if node.type == "identifier":
        return aliases.get(_node_text(source, node))
    if node.type not in {"string", "string_fragment", "template_string"}:
        return None
    value = source[node.start_byte : node.end_byte]
    if node.type == "template_string":
        if b"${" in value:
            return None
        if len(value) < 2 or value[:1] != b"`" or value[-1:] != b"`":
            return None
        value = value[1:-1]
        return _decode_js_string(value)
    if node.type == "string":
        if len(value) < 2 or value[:1] not in {b"'", b'"', b"`"} or value[-1:] != value[:1]:
            return None
        value = value[1:-1]
    return _decode_js_string(value)


def _decode_js_string(value: bytes) -> str | None:
    try:
        text = value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe1333ScanError(
            EcmaScriptCwe1333ScanErrorCode.INTEGRITY_FAILURE
        ) from None
    output: list[str] = []
    index = 0
    while index < len(text):
        character = text[index]
        if character != "\\":
            output.append(character)
            index += 1
            continue
        index += 1
        if index >= len(text):
            return None
        escaped = text[index]
        simple = {
            "b": "\b",
            "f": "\f",
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "v": "\v",
            "0": "\0",
            "\\": "\\",
            "'": "'",
            '"': '"',
            "/": "/",
            "`": "`",
        }
        if escaped in simple:
            output.append(simple[escaped])
            index += 1
            continue
        if escaped == "x" and index + 2 < len(text):
            digits = text[index + 1 : index + 3]
            if re.fullmatch(r"[0-9A-Fa-f]{2}", digits):
                output.append(chr(int(digits, 16)))
                index += 3
                continue
        if escaped == "u":
            if index + 1 < len(text) and text[index + 1] == "{" :
                closing = text.find("}", index + 2)
                if closing > index + 2 and re.fullmatch(r"[0-9A-Fa-f]{1,6}", text[index + 2 : closing]):
                    output.append(chr(int(text[index + 2 : closing], 16)))
                    index = closing + 1
                    continue
            digits = text[index + 1 : index + 5]
            if len(digits) == 4 and re.fullmatch(r"[0-9A-Fa-f]{4}", digits):
                output.append(chr(int(digits, 16)))
                index += 5
                continue
        # Unknown escapes are rejected so a transformed pattern is never
        # treated as a trusted static value by accident.
        return None
    return "".join(output)


def _regex_literal_pattern(
    node: Node, source: bytes, limits: EcmaScriptCwe1333ScanLimits
) -> str | None:
    value = _node_text(source, node)
    if len(value.encode("utf-8")) > limits.max_pattern_bytes:
        raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.PATTERN_LIMIT)
    if not value.startswith("/"):
        return None
    escaped = False
    in_class = False
    closing = -1
    for index, character in enumerate(value[1:], start=1):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == "[":
            in_class = True
        elif character == "]":
            in_class = False
        elif character == "/" and not in_class:
            closing = index
            break
    if closing <= 0:
        return None
    flags = value[closing + 1 :]
    if flags and not re.fullmatch(r"[A-Za-z]+", flags):
        return None
    return value[1:closing]


class _PatternParser:
    def __init__(self, pattern: str, max_depth: int) -> None:
        self.pattern = pattern
        self.position = 0
        self.max_depth = max_depth

    def parse(self) -> tuple[tuple[_PatternAtom, ...], ...] | None:
        branches = self._alternatives(None, 0)
        if branches is None or self.position != len(self.pattern):
            return None
        return branches

    def _alternatives(
        self, closing: str | None, depth: int
    ) -> tuple[tuple[_PatternAtom, ...], ...] | None:
        if depth > self.max_depth:
            return None
        branches: list[tuple[_PatternAtom, ...]] = []
        sequence = self._sequence(closing, depth)
        if sequence is None:
            return None
        branches.append(sequence)
        while self.position < len(self.pattern) and self.pattern[self.position] == "|":
            self.position += 1
            sequence = self._sequence(closing, depth)
            if sequence is None:
                return None
            branches.append(sequence)
        if closing is not None:
            if self.position >= len(self.pattern) or self.pattern[self.position] != closing:
                return None
            self.position += 1
        return tuple(branches)

    def _sequence(self, closing: str | None, depth: int) -> tuple[_PatternAtom, ...] | None:
        atoms: list[_PatternAtom] = []
        while self.position < len(self.pattern):
            character = self.pattern[self.position]
            if character == "|" or (closing is not None and character == closing):
                break
            atom = self._atom(depth)
            if atom is None:
                # Anchors and unsupported assertions are ignored as zero-width
                # syntax.  A malformed closing token remains unanalysable.
                if character in "^$":
                    self.position += 1
                    continue
                return None
            atom = self._quantify(atom)
            atoms.append(atom)
        return tuple(atoms)

    def _atom(self, depth: int) -> _PatternAtom | None:
        start = self.position
        character = self.pattern[self.position]
        if character == "\\":
            if self.position + 1 >= len(self.pattern):
                return None
            token = self.pattern[self.position : self.position + 2]
            self.position += 2
            key = {
                "\\b": "zero",
                "\\B": "zero",
                "\\A": "zero",
                "\\Z": "zero",
                "\\d": "digit",
                "\\D": "any",
                "\\w": "word",
                "\\W": "any",
                "\\s": "space",
                "\\S": "any",
            }.get(token, token)
            return _PatternAtom(key, start, self.position)
        if character == "[":
            self.position += 1
            escaped = False
            while self.position < len(self.pattern):
                current = self.pattern[self.position]
                self.position += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == "]":
                    return _PatternAtom("class", start, self.position)
            return None
        if character == "(":
            self.position += 1
            if self.position < len(self.pattern) and self.pattern[self.position] == "?":
                self.position += 1
                if self.position < len(self.pattern) and self.pattern[self.position] in {"=", "!"}:
                    self.position += 1
                elif self.position < len(self.pattern) and self.pattern[self.position] == "<":
                    self.position += 1
                    if self.position < len(self.pattern) and self.pattern[self.position] in {"=", "!"}:
                        self.position += 1
                    else:
                        end_name = self.pattern.find(">", self.position)
                        if end_name < 0:
                            return None
                        self.position = end_name + 1
            branches = self._alternatives(")", depth + 1)
            if branches is None:
                return None
            return _PatternAtom("group", start, self.position, branches=branches)
        if character == ".":
            self.position += 1
            return _PatternAtom("any", start, self.position)
        if character in ")}" or character == "{":
            return None
        self.position += 1
        return _PatternAtom(character, start, self.position)

    def _quantify(self, atom: _PatternAtom) -> _PatternAtom:
        if self.position >= len(self.pattern):
            return atom
        character = self.pattern[self.position]
        minimum = maximum = 1
        consumed = 0
        if character == "*":
            minimum, maximum, consumed = 0, None, 1
        elif character == "+":
            minimum, maximum, consumed = 1, None, 1
        elif character == "?":
            minimum, maximum, consumed = 0, 1, 1
        elif character == "{":
            match = _QUANTIFIER.match(self.pattern, self.position)
            if match is not None:
                minimum = int(match.group(1))
                upper = match.group(2)
                maximum = minimum if upper is None else (int(upper) if upper else None)
                consumed = len(match.group(0))
        if not consumed:
            return atom
        self.position += consumed
        if self.position < len(self.pattern) and self.pattern[self.position] == "?":
            self.position += 1
        return _PatternAtom(
            atom.key,
            atom.start,
            self.position,
            branches=atom.branches,
            minimum=minimum,
            maximum=maximum,
        )


def _pattern_risk(
    pattern: str, limits: EcmaScriptCwe1333ScanLimits
) -> EcmaScriptCwe1333Risk | None:
    if len(pattern.encode("utf-8")) > limits.max_pattern_bytes:
        raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.PATTERN_LIMIT)
    parsed = _PatternParser(pattern, limits.max_depth).parse()
    if parsed is None:
        return None
    if any(_has_nested(branch) for branch in parsed):
        return EcmaScriptCwe1333Risk.NESTED_QUANTIFIER
    if any(_has_ambiguous(branch) for branch in parsed):
        return EcmaScriptCwe1333Risk.AMBIGUOUS_QUANTIFIER
    return None


def _has_nested(branch: tuple[_PatternAtom, ...]) -> bool:
    return any(_atom_has_nested(atom) for atom in branch)


def _atom_has_nested(atom: _PatternAtom) -> bool:
    if _unbounded(atom) and any(_has_unbounded_descendant(child) for branch in atom.branches for child in branch):
        return True
    return any(_has_nested(branch) for branch in atom.branches)


def _has_unbounded_descendant(atom: _PatternAtom) -> bool:
    return _unbounded(atom) or any(
        _has_unbounded_descendant(child) for branch in atom.branches for child in branch
    )


def _has_ambiguous(branch: tuple[_PatternAtom, ...]) -> bool:
    for left, right in zip(branch, branch[1:]):
        if _unbounded(left) and _unbounded(right) and _atom_overlap(left, right):
            return True
    for atom in branch:
        if _unbounded(atom) and len(atom.branches) > 1:
            if _branches_overlap(atom.branches):
                return True
        if any(_has_ambiguous(child_branch) for child_branch in atom.branches):
            return True
    return False


def _unbounded(atom: _PatternAtom) -> bool:
    return atom.maximum is None


def _branches_overlap(branches: tuple[tuple[_PatternAtom, ...], ...]) -> bool:
    firsts = [_first_atom(branch) for branch in branches]
    for index, left in enumerate(firsts):
        if left is None:
            continue
        if any(right is not None and _atom_overlap(left, right) for right in firsts[index + 1 :]):
            return True
    return False


def _first_atom(branch: tuple[_PatternAtom, ...]) -> _PatternAtom | None:
    for atom in branch:
        if atom.key != "zero":
            return atom
        if atom.minimum > 0:
            return atom
    return None


def _atom_overlap(left: _PatternAtom, right: _PatternAtom) -> bool:
    if left.key == "zero" or right.key == "zero":
        return False
    if left.key == right.key or "any" in {left.key, right.key}:
        return True
    if "class" in {left.key, right.key}:
        return True
    if {left.key, right.key} == {"digit", "word"}:
        return True
    return False


def _bounded_nodes(root: Node, limits: EcmaScriptCwe1333ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe1333ScanError(EcmaScriptCwe1333ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


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
        return _static_string_node(node, source, {})
    return None


def _node_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EcmaScriptCwe1333ScanError(
            EcmaScriptCwe1333ScanErrorCode.INTEGRITY_FAILURE
        ) from None


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
    operation: EcmaScriptCwe1333Operation,
    risk: EcmaScriptCwe1333Risk,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-1333",
        "detector": _DETECTOR,
        "operation": operation.value,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "risk": risk.value,
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
    signals: tuple[EcmaScriptCwe1333Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-1333",
        "detector": _DETECTOR,
        "language": language,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "rule_id": _RULE_ID,
        "signals": [
            {
                "operation": signal.operation.value,
                "risk": signal.risk.value,
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


# Discoverable aliases for language-neutral callers.
scan_javascript_redos = scan_javascript_cwe1333
scan_typescript_redos = scan_typescript_cwe1333
scan_ecmascript_redos = scan_ecmascript_cwe1333
scan_javascript_regex_dos = scan_javascript_cwe1333
scan_typescript_regex_dos = scan_typescript_cwe1333


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE1333_SCAN_LIMITS",
    "EcmaScriptCwe1333Operation",
    "EcmaScriptCwe1333Risk",
    "EcmaScriptCwe1333ScanError",
    "EcmaScriptCwe1333ScanErrorCode",
    "EcmaScriptCwe1333ScanLimits",
    "EcmaScriptCwe1333ScanResult",
    "EcmaScriptCwe1333Signal",
    "scan_ecmascript_cwe1333",
    "scan_ecmascript_redos",
    "scan_javascript_cwe1333",
    "scan_javascript_redos",
    "scan_javascript_regex_dos",
    "scan_typescript_cwe1333",
    "scan_typescript_redos",
    "scan_typescript_regex_dos",
]
