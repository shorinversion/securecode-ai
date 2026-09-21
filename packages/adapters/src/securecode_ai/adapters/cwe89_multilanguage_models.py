"""Bounded JavaScript, TypeScript, and Go CWE-89 scanner facts.

The adapter consumes a sealed CST index and never executes, imports, or reads
the analysed program.  It intentionally emits deterministic source-to-sink
facts only; normalization, interpretation, verdict, and report construction
remain owned by the existing common Core pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import (
    RepositoryFile,
    SourceRange,
)

_MAX_LIMITS = (2_000_000, 10_000, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HTTP_MEMBER = re.compile(r"(?:request|req)\.(?:query|params)\.[A-Za-z_$][A-Za-z0-9_$]*\Z")
_GO_HTTP_QUERY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\.URL\.Query\(\)\.Get\([^()]*\)\Z")
_GO_SQL_SINK = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\.(?:Query|Exec|Raw)\Z")


class MultilanguageCwe89ScanErrorCode(StrEnum):
    """Closed reasons a supported-language semantic fact cannot be emitted."""

    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class MultilanguageCwe89ScanError(RuntimeError):
    """Fixed, source-free semantic analysis failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: MultilanguageCwe89ScanErrorCode) -> None:
        if type(code) is not MultilanguageCwe89ScanErrorCode:
            raise TypeError("multilanguage CWE-89 scan error code is invalid")
        self.code = code
        self.safe_message = "CWE-89 semantic scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class MultilanguageCwe89ScanLimits:
    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_expression_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_expression_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("multilanguage CWE-89 scan limits are invalid")


DEFAULT_MULTILANGUAGE_CWE89_SCAN_LIMITS = MultilanguageCwe89ScanLimits()


@dataclass(frozen=True, slots=True)
class MultilanguageCwe89Signal:
    """One supported-language HTTP-to-interpolation-to-SQL fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    source: SourceRange
    interpolation: SourceRange
    sink: SourceRange
    detector: str
    cwe: str = "CWE-89"

    def __post_init__(self) -> None:
        expected_detector = {
            "javascript": "securecode-javascript-cwe89@1.0",
            "typescript": "securecode-typescript-cwe89@1.0",
            "go": "securecode-go-cwe89@1.0",
        }.get(self.language)
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
        locations = (self.source, self.interpolation, self.sink)
        if (
            not identity_valid
            or expected_detector is None
            or self.detector != expected_detector
            or self.cwe != "CWE-89"
            or any(type(location) is not SourceRange for location in locations)
            or any(location.end_byte > self.source_size_bytes for location in locations)
            or self.source.end_byte > self.interpolation.end_byte
            or self.interpolation.end_byte > self.sink.end_byte
        ):
            raise ValueError("multilanguage CWE-89 signal is invalid")


@dataclass(frozen=True, slots=True)
class MultilanguageCwe89ScanResult:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    language: str
    signals: tuple[MultilanguageCwe89Signal, ...]
    scan_sha256: str

    def __post_init__(self) -> None:
        from .cwe89_multilanguage_utilities import _scan_sha256

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
            and self.language in {"javascript", "typescript", "go"}
        )
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity_valid = False
        order = tuple(
            (
                item.sink.start_byte,
                item.sink.end_byte,
                item.interpolation.start_byte,
                item.source.start_byte,
            )
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
            or any(type(item) is not MultilanguageCwe89Signal for item in self.signals)
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
            raise ValueError("multilanguage CWE-89 scan result is invalid")


@dataclass(frozen=True, slots=True)
class _Flow:
    source: SourceRange
    interpolation: SourceRange | None
