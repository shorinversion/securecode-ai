"""Validated data contracts for deterministic Python CWE-89 analysis."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import RepositoryFile, SourceRange

_MAX_LIMITS = (2_000_000, 10_000, 64)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class Cwe89EvidenceKind(StrEnum):
    """The fixed evidence chain emitted by this first semantic rule."""

    HTTP_SOURCE = "http_source"
    INTERPOLATION = "interpolation"
    SQL_EXECUTE_SINK = "sql_execute_sink"


class Cwe89ScanErrorCode(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    SIGNAL_LIMIT = "SIGNAL_LIMIT"
    ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class Cwe89ScanError(RuntimeError):
    """Fixed non-echoing semantic-analysis boundary failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: Cwe89ScanErrorCode) -> None:
        if type(code) is not Cwe89ScanErrorCode:
            raise TypeError("CWE-89 scan error code is invalid")
        self.code = code
        self.safe_message = "CWE-89 semantic scan failed"
        super().__init__(self.safe_message)


@dataclass(frozen=True, slots=True)
class Cwe89ScanLimits:
    max_source_bytes: int = _MAX_LIMITS[0]
    max_signals: int = _MAX_LIMITS[1]
    max_call_depth: int = _MAX_LIMITS[2]

    def __post_init__(self) -> None:
        values = (self.max_source_bytes, self.max_signals, self.max_call_depth)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("CWE-89 scan limits are invalid")


DEFAULT_CWE89_SCAN_LIMITS = Cwe89ScanLimits()


@dataclass(frozen=True, slots=True)
class Cwe89Signal:
    """One source → interpolation → SQL execution scanner fact."""

    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    source: SourceRange
    interpolation: SourceRange
    sink: SourceRange
    detector: str = "securecode-python-cwe89@1.0"
    cwe: str = "CWE-89"

    def __post_init__(self) -> None:
        valid_identity = (
            type(self.repository_id) is str
            and bool(self.repository_id)
            and len(self.repository_id.encode("utf-8")) <= 1024
            and type(self.revision) is str
            and _SHA1.fullmatch(self.revision) is not None
            and type(self.path) is str
            and _SHA256.fullmatch(self.content_sha256) is not None
            and type(self.source_size_bytes) is int
            and self.source_size_bytes >= 0
        )
        if valid_identity:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                valid_identity = False
        locations = (self.source, self.interpolation, self.sink)
        if (
            not valid_identity
            or any(type(location) is not SourceRange for location in locations)
            or any(location.end_byte > self.source_size_bytes for location in locations)
            or self.source.end_byte > self.interpolation.end_byte
            or self.interpolation.end_byte > self.sink.end_byte
            or self.detector != "securecode-python-cwe89@1.0"
            or self.cwe != "CWE-89"
        ):
            raise ValueError("CWE-89 signal is invalid")


@dataclass(frozen=True, slots=True)
class Cwe89ScanResult:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    signals: tuple[Cwe89Signal, ...]
    scan_sha256: str

    def __post_init__(self) -> None:
        valid_identity = (
            type(self.repository_id) is str
            and bool(self.repository_id)
            and type(self.revision) is str
            and _SHA1.fullmatch(self.revision) is not None
            and type(self.path) is str
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
                item.sink.start_byte,
                item.sink.end_byte,
                item.interpolation.start_byte,
                item.source.start_byte,
            )
            for item in self.signals
        )
        identities_match = all(
            item.repository_id == self.repository_id
            and item.revision == self.revision
            and item.path == self.path
            and item.content_sha256 == self.content_sha256
            and item.source_size_bytes == self.source_size_bytes
            for item in self.signals
        )
        if (
            not valid_identity
            or type(self.signals) is not tuple
            or any(type(item) is not Cwe89Signal for item in self.signals)
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
            or not identities_match
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
            raise ValueError("CWE-89 scan result is invalid")


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    signals: tuple[Cwe89Signal, ...],
) -> str:
    value = {
        "content_sha256": content_sha256,
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


__all__ = [
    "DEFAULT_CWE89_SCAN_LIMITS",
    "Cwe89EvidenceKind",
    "Cwe89ScanError",
    "Cwe89ScanErrorCode",
    "Cwe89ScanLimits",
    "Cwe89ScanResult",
    "Cwe89Signal",
]
