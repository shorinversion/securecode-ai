"""Conservative multi-language CWE portfolio facts.

This module consumes only a sealed ``SymbolIndex`` and structural parsers.  It
does not import, execute, retain, or expose analysed source.  The rules are
deliberately narrow: a result is a deterministic source-to-sink *fact*, not a
finding or verdict.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import (
    CONTRACT_SCHEMA_VERSION,
    DataClass,
    ProducerRef,
    RawSignal,
    RepositoryFile,
    SourceLocation,
    SourcePosition,
    SourceRange,
    SymbolIndex,
)

_MAX_LIMITS = (2_000_000, 2_048)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CWES = frozenset({"CWE-78", "CWE-22", "CWE-918", "CWE-862"})


class CwePortfolioScanErrorCode(StrEnum):
    """Closed reasons a portfolio fact cannot be produced."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class CwePortfolioScanError(RuntimeError):
    """Fixed source-free scanner failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: CwePortfolioScanErrorCode) -> None:
        if type(code) is not CwePortfolioScanErrorCode:
            raise TypeError("CWE portfolio scan error code is invalid")
        self.code = code
        self.safe_message = "CWE portfolio semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class CwePortfolioScanLimits:
    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("CWE portfolio scan limits are invalid")


DEFAULT_CWE_PORTFOLIO_SCAN_LIMITS = CwePortfolioScanLimits()


@dataclass(frozen=True, slots=True)
class CwePortfolioSignal:
    """A source-free, bounded recognised-flow fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    cwe: str
    source: SourceRange
    sink: SourceRange
    detector: str

    def __post_init__(self) -> None:
        expected = f"securecode-{self.language}-{self.cwe.lower()}@1.0"
        valid = (
            type(self.repository_id) is str
            and bool(self.repository_id)
            and type(self.revision) is str
            and _SHA1.fullmatch(self.revision) is not None
            and type(self.path) is str
            and type(self.content_sha256) is str
            and _SHA256.fullmatch(self.content_sha256) is not None
            and type(self.source_size_bytes) is int
            and self.source_size_bytes >= 0
            and self.language in {"python", "javascript", "typescript", "go"}
            and self.cwe in _CWES
            and self.detector == expected
            and type(self.source) is SourceRange
            and type(self.sink) is SourceRange
            and self.source.end_byte <= self.source_size_bytes
            and self.sink.end_byte <= self.source_size_bytes
        )
        if valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid = False
        if not valid:
            raise ValueError("CWE portfolio signal is invalid")


@dataclass(frozen=True, slots=True)
class CwePortfolioScanResult:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[CwePortfolioSignal, ...]
    scan_sha256: str

    def __post_init__(self) -> None:
        from .cwe_portfolio_helpers import _scan_sha256

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
            and self.language in {"python", "javascript", "typescript", "go"}
        )
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity_valid = False
        order = tuple(
            (item.cwe, item.sink.start_byte, item.sink.end_byte, item.source.start_byte)
            for item in self.signals
        )
        same_identity = all(
            item.repository_id == self.repository_id
            and item.revision == self.revision
            and item.path == self.path
            and item.content_sha256 == self.content_sha256
            and item.source_size_bytes == self.source_size_bytes
            and item.language == self.language
            for item in self.signals
        )
        if (
            not identity_valid
            or type(self.signals) is not tuple
            or any(type(item) is not CwePortfolioSignal for item in self.signals)
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
            or not same_identity
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
            raise ValueError("CWE portfolio scan result is invalid")


def scan_cwe_portfolio(
    symbol_index: SymbolIndex,
    *,
    limits: CwePortfolioScanLimits = DEFAULT_CWE_PORTFOLIO_SCAN_LIMITS,
) -> CwePortfolioScanResult:
    """Return only direct, recognized source-to-sink facts for four CWEs."""

    from .cwe_portfolio_helpers import (
        _python_facts,
        _scan_sha256,
        _tree_facts,
        _validate_index,
    )

    _validate_index(symbol_index, limits)
    if symbol_index.language == "python":
        facts = _python_facts(symbol_index.source)
    else:
        facts = _tree_facts(symbol_index.language, symbol_index.source)
    unique = sorted(
        set(facts),
        key=lambda item: (item[0], item[2].start_byte, item[2].end_byte, item[1].start_byte),
    )
    if len(unique) > limits.max_signals:
        raise CwePortfolioScanError(CwePortfolioScanErrorCode.SIGNAL_LIMIT)
    signals = tuple(
        CwePortfolioSignal(
            repository_id=symbol_index.repository_id,
            revision=symbol_index.revision,
            path=symbol_index.path,
            content_sha256=symbol_index.content_sha256,
            source_size_bytes=symbol_index.source_byte_length,
            language=symbol_index.language,
            cwe=cwe,
            source=source,
            sink=sink,
            detector=f"securecode-{symbol_index.language}-{cwe.lower()}@1.0",
        )
        for cwe, source, sink in unique
    )
    return CwePortfolioScanResult(
        repository_id=symbol_index.repository_id,
        revision=symbol_index.revision,
        path=symbol_index.path,
        content_sha256=symbol_index.content_sha256,
        source_size_bytes=symbol_index.source_byte_length,
        language=symbol_index.language,
        signals=signals,
        scan_sha256=_scan_sha256(
            symbol_index.repository_id,
            symbol_index.revision,
            symbol_index.path,
            symbol_index.content_sha256,
            symbol_index.source_byte_length,
            symbol_index.language,
            signals,
        ),
    )


def portfolio_signals_to_raw_signals(
    result: CwePortfolioScanResult,
    *,
    tenant_id: str,
    producer: ProducerRef,
) -> tuple[RawSignal, ...]:
    """Translate scanner facts to the existing source-free RawSignal boundary."""

    if (
        type(result) is not CwePortfolioScanResult
        or type(tenant_id) is not str
        or not tenant_id
        or type(producer) is not ProducerRef
    ):
        raise CwePortfolioScanError(CwePortfolioScanErrorCode.REQUEST_INVALID)
    output: list[RawSignal] = []
    for ordinal, signal in enumerate(result.signals, start=1):
        location = SourceLocation(
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
        )
        stable = hashlib.sha256(f"{result.scan_sha256}:{ordinal}".encode("ascii")).hexdigest()
        output.append(
            RawSignal(
                schema_version=CONTRACT_SCHEMA_VERSION,
                raw_signal_id=(
                    f"portfolio-{signal.language}-{signal.cwe.lower()}-"
                    f"{ordinal}-{result.scan_sha256}"
                ),
                tenant_id=tenant_id,
                head_sha=signal.revision,
                producer=producer,
                rule_id=f"portfolio-{signal.cwe.lower()}",
                location=location,
                payload_classification=DataClass.INTERNAL_METADATA,
                signal_sha256=stable,
            )
        )
    return tuple(output)
