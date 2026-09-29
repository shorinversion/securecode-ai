"""Bounded JavaScript, TypeScript, and Go CWE-89 scanner facts.

The adapter consumes a sealed CST index and never executes, imports, or reads
the analysed program.  It intentionally emits deterministic source-to-sink
facts only; normalization, interpretation, verdict, and report construction
remain owned by the existing common Core pipeline.
"""

from __future__ import annotations

import hashlib
import json
import re

from securecode_ai.core import (
    CONTRACT_SCHEMA_VERSION,
    DataClass,
    ProducerRef,
    RawSignal,
    RepositoryFile,
    SourceLocation,
    SourcePoint,
    SourcePosition,
    SourceRange,
    SymbolIndex,
)
from tree_sitter import Node

from .cwe89_multilanguage_models import (
    DEFAULT_MULTILANGUAGE_CWE89_SCAN_LIMITS,
    MultilanguageCwe89ScanError,
    MultilanguageCwe89ScanErrorCode,
    MultilanguageCwe89ScanResult,
    MultilanguageCwe89Signal,
)

_ECMASCRIPT_CALLABLES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "function",
        "arrow_function",
        "method_definition",
        "generator_function",
        "generator_function_declaration",
    }
)
_GO_CALLABLES = frozenset({"function_declaration", "method_declaration", "func_literal"})


def _preorder(root: Node) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        output.append(node)
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _lexical_scopes(root: Node, callable_types: frozenset[str]) -> tuple[Node, ...]:
    return tuple(node for node in _preorder(root) if node == root or node.type in callable_types)


def _scope_preorder(scope: Node, callable_types: frozenset[str]) -> tuple[Node, ...]:
    output: list[Node] = []
    stack = [scope]
    while stack:
        node = stack.pop()
        output.append(node)
        if node != scope and node.type in callable_types:
            continue
        stack.extend(reversed(node.named_children))
    return tuple(output)


def _range(node: Node) -> SourceRange:
    return SourceRange(
        node.start_byte,
        node.end_byte,
        SourcePoint(node.start_point.row, node.start_point.column),
        SourcePoint(node.end_point.row, node.end_point.column),
    )


def _text(source: bytes, node: Node) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise MultilanguageCwe89ScanError(
            MultilanguageCwe89ScanErrorCode.INTEGRITY_FAILURE
        ) from None


def _compact_text(source: bytes, node: Node) -> str:
    return "".join(_text(source, node).split())


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    language: str,
    signals: tuple[MultilanguageCwe89Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
        "language": language,
        "path": path,
        "repository_id": repository_id,
        "revision": revision,
        "signals": [
            {
                "cwe": signal.cwe,
                "detector": signal.detector,
                "interpolation": _range_value(signal.interpolation),
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


def multilanguage_cwe89_signals_to_raw_signals(
    symbol_index: SymbolIndex,
    result: MultilanguageCwe89ScanResult,
    *,
    tenant_id: str,
    producer: ProducerRef,
) -> tuple[RawSignal, ...]:
    """Revalidate scanner facts and bind them to common source-free ingress.

    The caller supplies its trusted deployment artifact digest in ``producer``;
    this adapter checks the scanner name/version, but does not authenticate a
    deployment. Repository identity is covered by the scan and signal digests.
    No source, verdict, or confidence is put in the wire payload.
    """
    from .cwe89_multilanguage_scanner import (
        scan_go_cwe89,
        scan_javascript_cwe89,
        scan_typescript_cwe89,
    )

    if (
        type(symbol_index) is not SymbolIndex
        or type(result) is not MultilanguageCwe89ScanResult
        or type(tenant_id) is not str
        or not tenant_id
        or type(producer) is not ProducerRef
        or type(result.signals) is not tuple
        or len(result.signals) > DEFAULT_MULTILANGUAGE_CWE89_SCAN_LIMITS.max_signals
    ):
        raise MultilanguageCwe89ScanError(MultilanguageCwe89ScanErrorCode.REQUEST_INVALID)
    try:
        validated_producer = ProducerRef.model_validate(producer.model_dump(mode="python"))
        if (
            validated_producer.producer_id != f"securecode-{symbol_index.language}-cwe89"
            or validated_producer.producer_version != "1.0.0"
        ):
            raise ValueError("producer mismatch")
        scanner = {
            "javascript": scan_javascript_cwe89,
            "typescript": scan_typescript_cwe89,
            "go": scan_go_cwe89,
        }.get(symbol_index.language)
        if scanner is None or scanner(symbol_index) != result:
            raise ValueError("scanner facts mismatch")
        # Validate tenant even on the zero-signal path, without generating a fact.
        RepositoryFile(result.path, result.source_size_bytes, result.content_sha256)
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", tenant_id) is None:
            raise ValueError("tenant invalid")
        output: list[RawSignal] = []
        for ordinal, signal in enumerate(result.signals):
            binding = {
                "scan_sha256": result.scan_sha256,
                "ordinal": ordinal,
                "tenant_id": tenant_id,
                "producer": validated_producer.model_dump(mode="json"),
                "rule_id": "cwe-89-sql-interpolation",
            }
            digest = hashlib.sha256(
                json.dumps(binding, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            output.append(
                RawSignal(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    raw_signal_id=f"cwe89-{signal.language}-{digest}",
                    tenant_id=tenant_id,
                    head_sha=signal.revision,
                    producer=validated_producer,
                    rule_id="cwe-89-sql-interpolation",
                    location=SourceLocation(
                        schema_version=CONTRACT_SCHEMA_VERSION,
                        path=signal.path,
                        start=SourcePosition(
                            schema_version=CONTRACT_SCHEMA_VERSION,
                            line=signal.sink.start_point.row + 1,
                            column=signal.sink.start_point.column + 1,
                        ),
                        end=SourcePosition(
                            schema_version=CONTRACT_SCHEMA_VERSION,
                            line=signal.sink.end_point.row + 1,
                            column=signal.sink.end_point.column + 1,
                        ),
                        content_sha256=signal.content_sha256,
                    ),
                    payload_classification=DataClass.INTERNAL_METADATA,
                    signal_sha256=digest,
                )
            )
        return tuple(output)
    except (ValueError, TypeError, AttributeError):
        raise MultilanguageCwe89ScanError(
            MultilanguageCwe89ScanErrorCode.INTEGRITY_FAILURE
        ) from None
