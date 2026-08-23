"""Immutable structural source locations and symbol-index values."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import unicodedata
from bisect import bisect_right
from dataclasses import dataclass, field
from enum import StrEnum

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_REPOSITORY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\Z")
_INDEX_AUTHORITY_KEY = secrets.token_bytes(32)


def _valid_path(path: str) -> bool:
    parts = path.split("/")
    return bool(
        path
        and len(path.encode("utf-8")) <= 4096
        and not path.startswith("/")
        and "\\" not in path
        and not (len(parts[0]) >= 2 and parts[0][0].isalpha() and parts[0][1] == ":")
        and all(
            part
            and part not in {".", ".."}
            and len(part.encode("utf-8")) <= 255
            and unicodedata.normalize("NFC", part) == part
            and not any(ord(character) < 32 or ord(character) == 127 for character in part)
            for part in parts
        )
    )


def _valid_repository_id(repository_id: str) -> bool:
    parts = repository_id.split("/")
    return bool(
        _REPOSITORY_ID.fullmatch(repository_id)
        and all(part and part not in {".", ".."} for part in parts)
        and not repository_id.endswith("/")
    )


def _module_name(path: str) -> str:
    value = path[:-4] if path.endswith(".pyi") else path[:-3]
    parts = value.split("/")
    if parts[-1] == "__init__" and len(parts) > 1:
        parts.pop()
    return ".".join(parts)


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True, order=True)
class SourcePoint:
    row: int
    column: int

    def __post_init__(self) -> None:
        if (
            type(self.row) is not int
            or self.row < 0
            or type(self.column) is not int
            or self.column < 0
        ):
            raise ValueError("source point is invalid")


@dataclass(frozen=True, slots=True)
class SourceRange:
    start_byte: int
    end_byte: int
    start_point: SourcePoint
    end_point: SourcePoint

    def __post_init__(self) -> None:
        if (
            type(self.start_byte) is not int
            or type(self.end_byte) is not int
            or self.start_byte < 0
            or self.end_byte < self.start_byte
            or type(self.start_point) is not SourcePoint
            or type(self.end_point) is not SourcePoint
            or self.end_point < self.start_point
        ):
            raise ValueError("source range is invalid")

    def contains(self, other: SourceRange) -> bool:
        return (
            self.start_byte <= other.start_byte
            and other.end_byte <= self.end_byte
            and self.start_point <= other.start_point
            and other.end_point <= self.end_point
        )


class SymbolKind(StrEnum):
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    ASYNC_FUNCTION = "async_function"
    METHOD = "method"
    ASYNC_METHOD = "async_method"


class ParseHealth(StrEnum):
    HEALTHY = "healthy"
    RECOVERED_WITH_ERRORS = "recovered_with_errors"


class ParseDiagnosticCode(StrEnum):
    ERROR_NODE = "ERROR_NODE"
    MISSING_NODE = "MISSING_NODE"


@dataclass(frozen=True, slots=True)
class ParseDiagnostic:
    code: ParseDiagnosticCode
    location: SourceRange

    def __post_init__(self) -> None:
        if type(self.code) is not ParseDiagnosticCode or type(self.location) is not SourceRange:
            raise ValueError("parse diagnostic is invalid")


@dataclass(frozen=True, slots=True)
class Symbol:
    symbol_id: str
    kind: SymbolKind
    name: str
    qualified_name: str
    occurrence: int
    declaration: SourceRange
    name_location: SourceRange
    parent_symbol_id: str | None

    def __post_init__(self) -> None:
        if (
            type(self.symbol_id) is not str
            or not _SHA256.fullmatch(self.symbol_id)
            or type(self.kind) is not SymbolKind
            or type(self.name) is not str
            or not self.name
            or len(self.name.encode("utf-8")) > 1024
            or unicodedata.normalize("NFC", self.name) != self.name
            or type(self.qualified_name) is not str
            or not self.qualified_name
            or len(self.qualified_name.encode("utf-8")) > 8192
            or type(self.occurrence) is not int
            or self.occurrence < 0
            or type(self.declaration) is not SourceRange
            or type(self.name_location) is not SourceRange
            or not self.declaration.contains(self.name_location)
            or (
                self.parent_symbol_id is not None
                and (
                    type(self.parent_symbol_id) is not str
                    or not _SHA256.fullmatch(self.parent_symbol_id)
                )
            )
        ):
            raise ValueError("symbol is invalid")


def stable_symbol_id(
    repository_id: str,
    path: str,
    kind: SymbolKind,
    qualified_name: str,
    occurrence: int,
) -> str:
    return _canonical_hash(
        {
            "kind": kind.value,
            "occurrence": occurrence,
            "path": path,
            "qualified_name": qualified_name,
            "repository_id": repository_id,
        }
    )


@dataclass(frozen=True, slots=True)
class SymbolIndex:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source: bytes = field(repr=False)
    source_byte_length: int
    source_end_point: SourcePoint
    language: str
    parser_id: str
    parse_health: ParseHealth
    symbols: tuple[Symbol, ...]
    diagnostics: tuple[ParseDiagnostic, ...]
    node_count: int
    max_depth: int
    index_sha256: str
    _authority_seal: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        valid = (
            type(self.repository_id) is str
            and _valid_repository_id(self.repository_id)
            and type(self.revision) is str
            and _REVISION.fullmatch(self.revision) is not None
            and type(self.path) is str
            and _valid_path(self.path)
            and type(self.content_sha256) is str
            and _SHA256.fullmatch(self.content_sha256) is not None
            and type(self.source) is bytes
            and hashlib.sha256(self.source).hexdigest() == self.content_sha256
            and type(self.source_byte_length) is int
            and self.source_byte_length == len(self.source)
            and type(self.source_end_point) is SourcePoint
            and self.language == "python"
            and self.parser_id == "tree-sitter-python@0.25"
            and type(self.parse_health) is ParseHealth
            and type(self.symbols) is tuple
            and all(type(symbol) is Symbol for symbol in self.symbols)
            and type(self.diagnostics) is tuple
            and all(type(item) is ParseDiagnostic for item in self.diagnostics)
            and type(self.node_count) is int
            and self.node_count >= 1
            and type(self.max_depth) is int
            and self.max_depth >= 0
            and type(self.index_sha256) is str
            and _SHA256.fullmatch(self.index_sha256) is not None
        )
        if not valid:
            raise ValueError("symbol index is invalid")
        try:
            self.source.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise ValueError("symbol index is invalid") from None
        line_starts = (0, *(index + 1 for index, value in enumerate(self.source) if value == 10))
        if self.source_end_point != _point_at(self.source, len(self.source), line_starts):
            raise ValueError("symbol index is invalid")
        if tuple(symbol.declaration.start_byte for symbol in self.symbols) != tuple(
            sorted(symbol.declaration.start_byte for symbol in self.symbols)
        ):
            raise ValueError("symbol index is invalid")
        if not self.symbols or (
            self.symbols[0].kind is not SymbolKind.MODULE
            or self.symbols[0].parent_symbol_id is not None
            or self.symbols[0].declaration
            != SourceRange(0, self.source_byte_length, SourcePoint(0, 0), self.source_end_point)
            or self.symbols[0].name_location.start_byte != 0
            or self.symbols[0].name_location.end_byte != 0
            or any(symbol.kind is SymbolKind.MODULE for symbol in self.symbols[1:])
        ):
            raise ValueError("symbol index is invalid")
        by_id: dict[str, Symbol] = {}
        occurrences: dict[tuple[SymbolKind, str], int] = {}
        sibling_ends: dict[str, int] = {}
        module = self.symbols[0]
        expected_module_name = _module_name(self.path)
        if (
            module.name != expected_module_name.rsplit(".", 1)[-1]
            or module.qualified_name != expected_module_name
            or module.occurrence != 0
        ):
            raise ValueError("symbol index is invalid")
        for symbol in self.symbols:
            if not _range_matches_source(self.source, symbol.declaration, line_starts) or not (
                _range_matches_source(self.source, symbol.name_location, line_starts)
            ):
                raise ValueError("symbol index is invalid")
            occurrence_key = (symbol.kind, symbol.qualified_name)
            expected_occurrence = occurrences.get(occurrence_key, 0)
            expected_id = stable_symbol_id(
                self.repository_id,
                self.path,
                symbol.kind,
                symbol.qualified_name,
                expected_occurrence,
            )
            if (
                symbol.symbol_id in by_id
                or symbol.occurrence != expected_occurrence
                or symbol.symbol_id != expected_id
            ):
                raise ValueError("symbol index is invalid")
            occurrences[occurrence_key] = expected_occurrence + 1
            if symbol is not module:
                parent = by_id.get(symbol.parent_symbol_id or "")
                if (
                    parent is None
                    or not parent.declaration.contains(symbol.declaration)
                    or symbol.qualified_name != f"{parent.qualified_name}.{symbol.name}"
                    or symbol.declaration.start_byte
                    < sibling_ends.get(parent.symbol_id, symbol.declaration.start_byte)
                ):
                    raise ValueError("symbol index is invalid")
                sibling_ends[parent.symbol_id] = symbol.declaration.end_byte
                try:
                    encoded_name = self.source[
                        symbol.name_location.start_byte : symbol.name_location.end_byte
                    ].decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    raise ValueError("symbol index is invalid") from None
                if encoded_name != symbol.name:
                    raise ValueError("symbol index is invalid")
            by_id[symbol.symbol_id] = symbol
        if tuple(item.location.start_byte for item in self.diagnostics) != tuple(
            sorted(item.location.start_byte for item in self.diagnostics)
        ) or any(
            not module.declaration.contains(item.location)
            or not _range_matches_source(self.source, item.location, line_starts)
            for item in self.diagnostics
        ):
            raise ValueError("symbol index is invalid")
        if self.parse_health is ParseHealth.HEALTHY and self.diagnostics:
            raise ValueError("symbol index is invalid")
        if self.parse_health is ParseHealth.RECOVERED_WITH_ERRORS and not self.diagnostics:
            raise ValueError("symbol index is invalid")
        if self.index_sha256 != symbol_index_sha256(self):
            raise ValueError("symbol index is invalid")
        if type(self._authority_seal) is not bytes or not hmac.compare_digest(
            self._authority_seal, _index_authority_seal(self.index_sha256)
        ):
            raise ValueError("symbol index is invalid")


def symbol_index_sha256(index: SymbolIndex) -> str:
    return _canonical_hash(
        {
            "content_sha256": index.content_sha256,
            "source_byte_length": index.source_byte_length,
            "source_end_point": [index.source_end_point.row, index.source_end_point.column],
            "diagnostics": [
                {
                    "code": item.code.value,
                    "range": _range_value(item.location),
                }
                for item in index.diagnostics
            ],
            "language": index.language,
            "max_depth": index.max_depth,
            "node_count": index.node_count,
            "parse_health": index.parse_health.value,
            "parser_id": index.parser_id,
            "path": index.path,
            "repository_id": index.repository_id,
            "revision": index.revision,
            "symbols": [
                {
                    "declaration": _range_value(symbol.declaration),
                    "kind": symbol.kind.value,
                    "name": symbol.name,
                    "name_location": _range_value(symbol.name_location),
                    "occurrence": symbol.occurrence,
                    "parent_symbol_id": symbol.parent_symbol_id,
                    "qualified_name": symbol.qualified_name,
                    "symbol_id": symbol.symbol_id,
                }
                for symbol in index.symbols
            ],
        }
    )


def _build_symbol_index(
    *,
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source: bytes,
    source_byte_length: int,
    source_end_point: SourcePoint,
    language: str,
    parser_id: str,
    parse_health: ParseHealth,
    symbols: tuple[Symbol, ...],
    diagnostics: tuple[ParseDiagnostic, ...],
    node_count: int,
    max_depth: int,
) -> SymbolIndex:
    """Create a validated index whose digest covers every supplied field."""

    values = {
        "repository_id": repository_id,
        "revision": revision,
        "path": path,
        "content_sha256": content_sha256,
        "source": source,
        "source_byte_length": source_byte_length,
        "source_end_point": source_end_point,
        "language": language,
        "parser_id": parser_id,
        "parse_health": parse_health,
        "symbols": symbols,
        "diagnostics": diagnostics,
        "node_count": node_count,
        "max_depth": max_depth,
    }
    provisional = object.__new__(SymbolIndex)
    for key, value in values.items():
        object.__setattr__(provisional, key, value)
    object.__setattr__(provisional, "index_sha256", "0" * 64)
    object.__setattr__(provisional, "_authority_seal", b"")
    index_sha256 = symbol_index_sha256(provisional)
    return SymbolIndex(
        repository_id=repository_id,
        revision=revision,
        path=path,
        content_sha256=content_sha256,
        source=source,
        source_byte_length=source_byte_length,
        source_end_point=source_end_point,
        language=language,
        parser_id=parser_id,
        parse_health=parse_health,
        symbols=symbols,
        diagnostics=diagnostics,
        node_count=node_count,
        max_depth=max_depth,
        index_sha256=index_sha256,
        _authority_seal=_index_authority_seal(index_sha256),
    )


def _index_authority_seal(index_sha256: str) -> bytes:
    return hmac.digest(_INDEX_AUTHORITY_KEY, index_sha256.encode("ascii"), "sha256")


def _range_value(location: SourceRange) -> dict[str, object]:
    return {
        "end_byte": location.end_byte,
        "end_point": [location.end_point.row, location.end_point.column],
        "start_byte": location.start_byte,
        "start_point": [location.start_point.row, location.start_point.column],
    }


def _point_at(source: bytes, offset: int, line_starts: tuple[int, ...]) -> SourcePoint:
    row = bisect_right(line_starts, offset) - 1
    return SourcePoint(row=row, column=offset - line_starts[row])


def _range_matches_source(
    source: bytes, location: SourceRange, line_starts: tuple[int, ...]
) -> bool:
    if location.end_byte > len(source):
        return False
    for offset in (location.start_byte, location.end_byte):
        if offset < len(source) and source[offset] & 0xC0 == 0x80:
            return False
    return location.start_point == _point_at(
        source, location.start_byte, line_starts
    ) and location.end_point == _point_at(source, location.end_byte, line_starts)


__all__ = [
    "ParseDiagnostic",
    "ParseDiagnosticCode",
    "ParseHealth",
    "SourcePoint",
    "SourceRange",
    "Symbol",
    "SymbolIndex",
    "SymbolKind",
    "stable_symbol_id",
    "symbol_index_sha256",
]
