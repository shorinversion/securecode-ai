"""Bounded JavaScript and TypeScript CWE-521 password-policy facts.

The scanner recognises explicit password validators and policy objects.  It
reports only a small, high-confidence set of weaknesses: a configured
minimum or maximum below the accepted password floor, or an explicit password
validator which contains no length policy at all.  Strong minimums are kept
clean and ambiguous identifiers are ignored.

The implementation reparses the exact bytes admitted by ``SymbolIndex`` and
returns immutable, source-free signals.  Parser failures, malformed identity,
and resource-limit failures use fixed error codes without echoing source.
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
_MIN_ACCEPTED_LENGTH = 8
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_RULE_ID = "securecode-ecmascript-cwe521"
_DETECTOR = "securecode-ecmascript-cwe521@1.0"
_DETAIL = "weak_password_requirement"

_PASSWORD_NAME = re.compile(
    r"(?:password|passwd|passphrase|passcode|credential|credentials|pwd)", re.IGNORECASE
)
_POLICY_NAME = re.compile(
    r"(?:password|credential).{0,24}(?:policy|policies|requirement|requirements|rule|rules|"
    r"schema|validator)|(?:policy|policies|requirement|requirements|rule|rules|schema|"
    r"validator).{0,24}(?:password|credential)",
    re.IGNORECASE,
)
_LENGTH_NAME = re.compile(
    r"(?:^|[_-])(?:min(?:imum)?|max(?:imum)?)(?:[_-]?password)?[_-]?length$|"
    r"^(?:min(?:imum)?|max(?:imum)?)(?:password)?length$",
    re.IGNORECASE,
)
_MIN_KEYS = frozenset(
    {
        "min",
        "minlength",
        "minimum",
        "minimumlength",
        "minpasswordlength",
        "minimumpasswordlength",
        "atleast",
        "at_least",
    }
)
_MAX_KEYS = frozenset(
    {
        "max",
        "maxlength",
        "maximum",
        "maximumlength",
        "maxpasswordlength",
        "maximumpasswordlength",
        "atmost",
        "at_most",
    }
)
_MIN_METHODS = frozenset({"min", "minlength", "minimum", "atleast"})
_MAX_METHODS = frozenset({"max", "maxlength", "maximum", "atmost"})
_VALIDATOR_METHODS = frozenset(
    {
        "checkpassword",
        "isvalidpassword",
        "validatepassword",
        "passwordvalidator",
        "validpassword",
        "validatecredentials",
        "checkcredentials",
        "islength",
        "required",
        "matches",
        "regex",
        "refine",
        "superrefine",
        "validate",
    }
)
_SCHEMA_METHODS = frozenset({"string", "password", "passwordschema"})
_POLICY_FIELDS = frozenset(
    {
        "requireuppercase",
        "requirelowercase",
        "requirenumber",
        "requirenumbers",
        "requirespecial",
        "requirespecialcharacters",
        "requiresymbol",
        "complexity",
        "pattern",
        "regex",
        "strength",
        "minscore",
        "score",
        "entropy",
        "dictionary",
        "blockcommon",
        "allowpassphrases",
    }
)
_WRAPPER_TYPES = frozenset(
    {
        "as_expression",
        "parenthesized_expression",
        "non_null_expression",
        "type_assertion",
        "satisfies_expression",
    }
)


class EcmaScriptCwe521ScanErrorCode(StrEnum):
    """Closed, source-free reasons a password-policy analysis cannot complete."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EcmaScriptCwe521ScanError(RuntimeError):
    """Fixed scanner failure which never exposes source or parser details."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EcmaScriptCwe521ScanErrorCode) -> None:
        if type(code) is not EcmaScriptCwe521ScanErrorCode:
            raise TypeError("ECMAScript CWE-521 scan error code is invalid")
        self.code = code
        self.safe_message = "ECMAScript CWE-521 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe521ScanLimits:
    """Hard ceilings applied before and during CST analysis."""

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
            raise ValueError("ECMAScript CWE-521 scan limits are invalid")


DEFAULT_ECMASCRIPT_CWE521_SCAN_LIMITS = EcmaScriptCwe521ScanLimits()


class EcmaScriptCwe521Operation(StrEnum):
    """Password-policy weakness recognized by the scanner."""

    MINIMUM_LENGTH = "minimum_length"
    MAXIMUM_LENGTH = "maximum_length"
    MISSING_LENGTH_POLICY = "missing_length_policy"

    # Compatibility aliases for generic CWE consumers.
    WEAK_MINIMUM_LENGTH = "minimum_length"
    WEAK_MAXIMUM_LENGTH = "maximum_length"
    POLICY_MISSING_LENGTH = "missing_length_policy"


@dataclass(frozen=True, slots=True)
class EcmaScriptCwe521Signal:
    """One immutable source-to-password-policy fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    sink: SourceRange
    operation: EcmaScriptCwe521Operation
    signal_id: str = ""
    rule_id: str = _RULE_ID
    cwe: str = "CWE-521"
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
            if identity_valid
            and ranges_valid
            and type(self.operation) is EcmaScriptCwe521Operation
            else None
        )
        signal_id = self.signal_id or expected
        if (
            not identity_valid
            or not ranges_valid
            or type(self.operation) is not EcmaScriptCwe521Operation
            or type(signal_id) is not str
            or _SHA256.fullmatch(signal_id) is None
            or signal_id != expected
            or self.rule_id != _RULE_ID
            or self.cwe != "CWE-521"
            or self.detector != _DETECTOR
            or self.detail != _DETAIL
        ):
            raise ValueError("ECMAScript CWE-521 signal is invalid")
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
class EcmaScriptCwe521ScanResult:
    """Deterministic and source-free CWE-521 output for one source file."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[EcmaScriptCwe521Signal, ...]
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
            and self.language in {"javascript", "typescript"}
        )
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity_valid = False
        valid_signals = type(self.signals) is tuple and all(
            type(item) is EcmaScriptCwe521Signal for item in self.signals
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
            raise ValueError("ECMAScript CWE-521 scan result is invalid")


def scan_javascript_cwe521(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe521ScanLimits = DEFAULT_ECMASCRIPT_CWE521_SCAN_LIMITS,
) -> EcmaScriptCwe521ScanResult:
    """Find bounded JavaScript CWE-521 facts."""

    return _scan_ecmascript_cwe521(symbol_index, expected_language="javascript", limits=limits)


def scan_typescript_cwe521(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe521ScanLimits = DEFAULT_ECMASCRIPT_CWE521_SCAN_LIMITS,
) -> EcmaScriptCwe521ScanResult:
    """Find bounded TypeScript CWE-521 facts."""

    return _scan_ecmascript_cwe521(symbol_index, expected_language="typescript", limits=limits)


def scan_ecmascript_cwe521(
    symbol_index: SymbolIndex,
    *,
    limits: EcmaScriptCwe521ScanLimits = DEFAULT_ECMASCRIPT_CWE521_SCAN_LIMITS,
) -> EcmaScriptCwe521ScanResult:
    """Dispatch a CWE-521 scan according to the sealed index language."""

    if type(symbol_index) is not SymbolIndex:
        raise EcmaScriptCwe521ScanError(EcmaScriptCwe521ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language == "javascript":
        return scan_javascript_cwe521(symbol_index, limits=limits)
    if symbol_index.language == "typescript":
        return scan_typescript_cwe521(symbol_index, limits=limits)
    raise EcmaScriptCwe521ScanError(EcmaScriptCwe521ScanErrorCode.REQUEST_INVALID)


def _scan_ecmascript_cwe521(
    symbol_index: SymbolIndex,
    *,
    expected_language: str,
    limits: EcmaScriptCwe521ScanLimits,
) -> EcmaScriptCwe521ScanResult:
    if type(symbol_index) is not SymbolIndex or type(limits) is not EcmaScriptCwe521ScanLimits:
        raise EcmaScriptCwe521ScanError(EcmaScriptCwe521ScanErrorCode.REQUEST_INVALID)
    if symbol_index.language != expected_language:
        raise EcmaScriptCwe521ScanError(EcmaScriptCwe521ScanErrorCode.REQUEST_INVALID)
    if len(symbol_index.source) > limits.max_source_bytes:
        raise EcmaScriptCwe521ScanError(EcmaScriptCwe521ScanErrorCode.SOURCE_LIMIT)
    if symbol_index.parse_health is not ParseHealth.HEALTHY:
        raise EcmaScriptCwe521ScanError(EcmaScriptCwe521ScanErrorCode.ANALYSIS_UNAVAILABLE)
    builder = build_javascript_symbol_index if expected_language == "javascript" else build_typescript_symbol_index
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
        raise EcmaScriptCwe521ScanError(EcmaScriptCwe521ScanErrorCode.INTEGRITY_FAILURE) from None
    except Exception:
        raise EcmaScriptCwe521ScanError(EcmaScriptCwe521ScanErrorCode.INTEGRITY_FAILURE) from None

    try:
        nodes = _bounded_nodes(root, limits)
        if any(node.type == "ERROR" or node.is_missing for node in nodes):
            raise EcmaScriptCwe521ScanError(EcmaScriptCwe521ScanErrorCode.ANALYSIS_UNAVAILABLE)
        raw: set[tuple[SourceRange, SourceRange, EcmaScriptCwe521Operation]] = set()
        for node in nodes:
            if node.type == "binary_expression":
                fact = _comparison_fact(node, source)
                if fact is not None:
                    raw.add(fact)
            elif node.type == "call_expression":
                raw.update(_call_facts(node, source))
            elif node.type in {"object", "object_pattern"}:
                raw.update(_object_facts(node, source))
            if len(raw) > limits.max_signals:
                raise EcmaScriptCwe521ScanError(EcmaScriptCwe521ScanErrorCode.SIGNAL_LIMIT)
        ordered = tuple(
            sorted(
                raw,
                key=lambda item: (
                    item[1].start_byte,
                    item[1].end_byte,
                    item[0].start_byte,
                    item[0].end_byte,
                    item[2].value,
                ),
            )
        )
    except EcmaScriptCwe521ScanError:
        raise
    except Exception:
        raise EcmaScriptCwe521ScanError(EcmaScriptCwe521ScanErrorCode.INTEGRITY_FAILURE) from None

    signals = tuple(
        EcmaScriptCwe521Signal(
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
    return EcmaScriptCwe521ScanResult(
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


def _bounded_nodes(root: Node, limits: EcmaScriptCwe521ScanLimits) -> tuple[Node, ...]:
    output: list[Node] = []
    stack: list[tuple[Node, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            raise EcmaScriptCwe521ScanError(EcmaScriptCwe521ScanErrorCode.DEPTH_LIMIT)
        output.append(node)
        if len(output) > limits.max_nodes:
            raise EcmaScriptCwe521ScanError(EcmaScriptCwe521ScanErrorCode.NODE_LIMIT)
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
    return tuple(output)


def _comparison_fact(
    node: Node, source: bytes
) -> tuple[SourceRange, SourceRange, EcmaScriptCwe521Operation] | None:
    operator = node.child_by_field_name("operator")
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if operator is None or left is None or right is None:
        return None
    operator_text = _compact_text(source, operator)
    if operator_text not in {"<", "<=", ">", ">="}:
        return None
    length_node: Node | None = None
    value_node: Node | None = None
    if _is_password_length(left, source):
        length_node, value_node = left, right
        direction = "left"
    elif _is_password_length(right, source):
        length_node, value_node = right, left
        direction = "right"
    else:
        return None
    del length_node
    value = _static_number(value_node, source)
    if value is None:
        return None
    if direction == "left":
        operation = (
            EcmaScriptCwe521Operation.WEAK_MINIMUM_LENGTH
            if operator_text in {"<", "<="}
            else EcmaScriptCwe521Operation.WEAK_MAXIMUM_LENGTH
        )
        effective = value + 1 if operator_text in {"<=", ">"} else value
    else:
        operation = (
            EcmaScriptCwe521Operation.WEAK_MAXIMUM_LENGTH
            if operator_text in {"<", "<="}
            else EcmaScriptCwe521Operation.WEAK_MINIMUM_LENGTH
        )
        effective = value + 1 if operator_text in {"<=", ">"} else value
    if effective >= _MIN_ACCEPTED_LENGTH:
        return None
    return _range(value_node), _range(node), operation


def _call_facts(
    node: Node, source: bytes
) -> tuple[tuple[SourceRange, SourceRange, EcmaScriptCwe521Operation], ...]:
    if not _looks_password_context(node, source):
        return ()
    method = _call_method(node, source)
    if method is None:
        return ()
    method_lower = method.lower()
    root_text = _expression_root_text(node, source).lower()
    facts: list[tuple[SourceRange, SourceRange, EcmaScriptCwe521Operation]] = []
    if method_lower in _MIN_METHODS:
        value = _first_numeric_argument(node, source, _MIN_KEYS)
        if (
            value is not None
            and value < _MIN_ACCEPTED_LENGTH
            and not _has_strong_method_policy(root_text, _MIN_METHODS)
        ):
            number_node = _first_numeric_node(node, source, _MIN_KEYS)
            if number_node is not None:
                facts.append(
                    (
                        _range(number_node),
                        _range(node),
                        EcmaScriptCwe521Operation.WEAK_MINIMUM_LENGTH,
                    )
                )
        return tuple(facts)
    if method_lower in _MAX_METHODS:
        value = _first_numeric_argument(node, source, _MAX_KEYS)
        if (
            value is not None
            and value < _MIN_ACCEPTED_LENGTH
            and not _has_strong_method_policy(root_text, _MAX_METHODS)
        ):
            number_node = _first_numeric_node(node, source, _MAX_KEYS)
            if number_node is not None:
                facts.append(
                    (
                        _range(number_node),
                        _range(node),
                        EcmaScriptCwe521Operation.WEAK_MAXIMUM_LENGTH,
                    )
                )
        return tuple(facts)
    if method_lower == "islength":
        min_value, min_node = _option_number(node, source, _MIN_KEYS)
        max_value, max_node = _option_number(node, source, _MAX_KEYS)
        if (
            min_value is not None
            and min_value < _MIN_ACCEPTED_LENGTH
            and min_node is not None
        ):
            facts.append(
                (_range(min_node), _range(node), EcmaScriptCwe521Operation.WEAK_MINIMUM_LENGTH)
            )
        if (
            max_value is not None
            and max_value < _MIN_ACCEPTED_LENGTH
            and max_node is not None
        ):
            facts.append(
                (_range(max_node), _range(node), EcmaScriptCwe521Operation.WEAK_MAXIMUM_LENGTH)
            )
        if min_value is None and max_value is not None and _has_explicit_password_validator(node, source):
            facts.append(
                (_range(node), _range(node), EcmaScriptCwe521Operation.MISSING_LENGTH_POLICY)
            )
        return tuple(facts)
    if method_lower in _VALIDATOR_METHODS or (
        method_lower in _SCHEMA_METHODS and _has_password_validator_name(node, source)
    ):
        if _is_nested_validator_call(node):
            return ()
        if _has_length_policy(root_text):
            return ()
        return (
            (_range(node), _range(node), EcmaScriptCwe521Operation.MISSING_LENGTH_POLICY),
        )
    return ()


def _object_facts(
    node: Node, source: bytes
) -> tuple[tuple[SourceRange, SourceRange, EcmaScriptCwe521Operation], ...]:
    if not _looks_password_context(node, source):
        return ()
    options: list[tuple[str, Node, Node | None]] = []
    for child in node.named_children:
        if child.type not in {"pair", "property_signature", "object_pattern_property"}:
            continue
        key = child.child_by_field_name("key") or child.child_by_field_name("name")
        value = child.child_by_field_name("value") or child.child_by_field_name("type")
        if key is None:
            continue
        key_name = _property_name(key, source)
        if key_name is None:
            continue
        options.append((_normalise_key(key_name), key, value))
    if not options:
        return ()
    min_options = [item for item in options if item[0] in _MIN_KEYS]
    max_options = [item for item in options if item[0] in _MAX_KEYS]
    facts: list[tuple[SourceRange, SourceRange, EcmaScriptCwe521Operation]] = []
    for _, key, value_node in min_options:
        number = _static_number(value_node, source) if value_node is not None else None
        if (
            number is not None
            and number < _MIN_ACCEPTED_LENGTH
            and value_node is not None
            and not _object_has_strong_policy(min_options, source)
        ):
            facts.append(
                (
                    _range(value_node),
                    _range(node),
                    EcmaScriptCwe521Operation.WEAK_MINIMUM_LENGTH,
                )
            )
    for _, key, value_node in max_options:
        number = _static_number(value_node, source) if value_node is not None else None
        if (
            number is not None
            and number < _MIN_ACCEPTED_LENGTH
            and value_node is not None
            and not _object_has_strong_policy(max_options, source)
        ):
            facts.append(
                (
                    _range(value_node),
                    _range(node),
                    EcmaScriptCwe521Operation.WEAK_MAXIMUM_LENGTH,
                )
            )
    has_policy_field = any(key in _POLICY_FIELDS for key, _, _ in options)
    if not min_options and (max_options or has_policy_field) and _has_explicit_policy_name(node, source):
        facts.append(
            (_range(node), _range(node), EcmaScriptCwe521Operation.MISSING_LENGTH_POLICY)
        )
    return tuple(facts)


def _looks_password_context(node: Node, source: bytes) -> bool:
    current: Node | None = node
    for _ in range(8):
        if current is None:
            break
        if current.type in {"variable_declarator", "pair", "property_signature", "object_pattern_property"}:
            name = current.child_by_field_name("name") or current.child_by_field_name("key")
            if name is not None and _PASSWORD_NAME.search(_compact_text(source, name)):
                return True
        if current.type == "call_expression":
            function = current.child_by_field_name("function")
            if function is not None and _PASSWORD_NAME.search(_compact_text(source, function)):
                return True
            arguments = current.child_by_field_name("arguments")
            if arguments is not None and _PASSWORD_NAME.search(_compact_text(source, arguments)):
                return True
        current_text = _compact_text(source, current)
        if len(current_text) <= 512 and _PASSWORD_NAME.search(current_text):
            return True
        current = current.parent
    return False


def _has_explicit_password_validator(node: Node, source: bytes) -> bool:
    return _has_password_validator_name(node, source) or _has_explicit_policy_name(node, source)


def _has_password_validator_name(node: Node, source: bytes) -> bool:
    text = _expression_root_text(node, source)
    compact = text.replace(" ", "").lower()
    return bool(
        _PASSWORD_NAME.search(compact)
        or any(token in compact for token in ("z.string", "yup.string", "joi.string", "passwordschema"))
    )


def _has_explicit_policy_name(node: Node, source: bytes) -> bool:
    current: Node | None = node
    for _ in range(8):
        if current is None:
            break
        if current.type in {"variable_declarator", "pair", "property_signature"}:
            name = current.child_by_field_name("name") or current.child_by_field_name("key")
            if name is not None and _POLICY_NAME.search(_compact_text(source, name)):
                return True
        current = current.parent
    return False


def _has_length_policy(text: str) -> bool:
    compact = text.replace(" ", "").lower()
    return any(
        token in compact
        for token in (
            ".min(",
            ".max(",
            ".minlength(",
            ".maxlength(",
            "minlength:",
            "maxlength:",
            "minimumlength:",
            "maximumlength:",
            "minpasswordlength:",
            "maxpasswordlength:",
            "islength(",
        )
    )


def _is_nested_validator_call(node: Node) -> bool:
    current = node
    while current.parent is not None and current.parent.type in {
        "member_expression",
        "subscript_expression",
        "parenthesized_expression",
    }:
        current = current.parent
    parent = current.parent
    if parent is None or parent.type != "call_expression":
        return False
    function = parent.child_by_field_name("function")
    if function is None:
        return False
    return function.start_byte <= current.start_byte and function.end_byte >= current.end_byte


def _normalise_key(value: str) -> str:
    return value.lower().replace("-", "").replace("_", "").replace(" ", "")


def _call_method(node: Node, source: bytes) -> str | None:
    function = node.child_by_field_name("function")
    if function is None:
        return None
    if function.type in {"member_expression", "subscript_expression"}:
        property_node = function.child_by_field_name("property") or function.child_by_field_name("index")
        if property_node is not None:
            return _property_name(property_node, source)
    compact = _compact_text(source, function)
    return compact.rsplit(".", 1)[-1] if compact else None


def _expression_root_text(node: Node, source: bytes) -> str:
    current = node
    while current.parent is not None and current.parent.type in {
        "call_expression",
        "member_expression",
        "subscript_expression",
        "parenthesized_expression",
        "arguments",
    }:
        current = current.parent
    return _compact_text(source, current)


def _first_numeric_argument(node: Node, source: bytes, keys: frozenset[str]) -> int | None:
    number_node = _first_numeric_node(node, source, keys)
    return _static_number(number_node, source) if number_node is not None else None


def _first_numeric_node(node: Node, source: bytes, keys: frozenset[str]) -> Node | None:
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return None
    values = arguments.named_children
    if values and _static_number(values[0], source) is not None:
        return values[0]
    _, value_node = _option_number(node, source, keys)
    return value_node


def _option_number(node: Node, source: bytes, keys: frozenset[str]) -> tuple[int | None, Node | None]:
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return None, None
    for child in _walk_nodes(arguments):
        if child.type not in {"pair", "property_signature", "object_pattern_property"}:
            continue
        key = child.child_by_field_name("key") or child.child_by_field_name("name")
        value = child.child_by_field_name("value") or child.child_by_field_name("type")
        if key is None or value is None:
            continue
        key_name = _property_name(key, source)
        if key_name is None or _normalise_key(key_name) not in keys:
            continue
        number = _static_number(value, source)
        if number is not None:
            return number, value
    return None, None


def _is_password_length(node: Node, source: bytes) -> bool:
    compact = _compact_text(source, node).replace("?.", ".").lower()
    if not compact.endswith(".length"):
        return False
    return bool(_PASSWORD_NAME.search(compact))


def _static_number(node: Node | None, source: bytes) -> int | None:
    if node is None:
        return None
    text = _compact_text(source, node)
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", text):
        return None
    try:
        value = int(text)
    except ValueError:
        return None
    return value if 0 <= value <= 1_000_000 else None


def _walk_nodes(root: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        output.append(node)
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _property_name(node: Node, source: bytes) -> str | None:
    value = _compact_text(source, node).strip("'\"")
    return value if value and _IDENTIFIER.fullmatch(value) else None


def _compact_text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict").replace("\n", "")
    except UnicodeDecodeError:
        raise EcmaScriptCwe521ScanError(EcmaScriptCwe521ScanErrorCode.INTEGRITY_FAILURE) from None


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
    operation: EcmaScriptCwe521Operation,
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-521",
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
    signals: tuple[EcmaScriptCwe521Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "cwe": "CWE-521",
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


scan_javascript_weak_password_requirements = scan_javascript_cwe521
scan_typescript_weak_password_requirements = scan_typescript_cwe521
scan_ecmascript_weak_password_requirements = scan_ecmascript_cwe521


__all__ = [
    "DEFAULT_ECMASCRIPT_CWE521_SCAN_LIMITS",
    "EcmaScriptCwe521Operation",
    "EcmaScriptCwe521ScanError",
    "EcmaScriptCwe521ScanErrorCode",
    "EcmaScriptCwe521ScanLimits",
    "EcmaScriptCwe521ScanResult",
    "EcmaScriptCwe521Signal",
    "scan_ecmascript_cwe521",
    "scan_ecmascript_weak_password_requirements",
    "scan_javascript_cwe521",
    "scan_javascript_weak_password_requirements",
    "scan_typescript_cwe521",
    "scan_typescript_weak_password_requirements",
]
