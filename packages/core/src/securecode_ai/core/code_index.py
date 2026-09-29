"""Immutable read-only code-index metadata interface for evaluation experiments."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from .repository import _valid_repository_path
from .symbols import SymbolIndex, SymbolReference, SymbolResolution, resolve_symbol_reference

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_.+-]{0,63}\Z")
_QUERY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MAX_ENTRIES = 4_096
_MAX_PATH_BYTES = 4_096
_MAX_ENTRY_BYTES = 1_048_576


def _valid_index_path(path: str) -> bool:
    try:
        return _valid_repository_path(path) and len(path.encode("utf-8")) <= _MAX_PATH_BYTES
    except UnicodeEncodeError:
        return False


@dataclass(frozen=True, slots=True)
class CodeIndexEntry:
    path: str
    content_sha256: str
    byte_length: int
    language: str

    def __post_init__(self) -> None:
        if (
            type(self.path) is not str
            or not _valid_index_path(self.path)
            or type(self.content_sha256) is not str
            or _SHA256.fullmatch(self.content_sha256) is None
            or type(self.byte_length) is not int
            or not 0 <= self.byte_length <= _MAX_ENTRY_BYTES
            or type(self.language) is not str
            or _IDENTIFIER.fullmatch(self.language) is None
        ):
            raise ValueError("index entry is invalid")


@dataclass(frozen=True, slots=True)
class CodeIndexResult:
    entries: tuple[CodeIndexEntry, ...]
    result_bytes: int

    def __post_init__(self) -> None:
        if (
            type(self.entries) is not tuple
            or len(self.entries) > _MAX_ENTRIES
            or any(type(item) is not CodeIndexEntry for item in self.entries)
            or tuple(item.path for item in self.entries)
            != tuple(sorted(item.path for item in self.entries))
            or len({item.path for item in self.entries}) != len(self.entries)
            or type(self.result_bytes) is not int
            or self.result_bytes != sum(item.byte_length for item in self.entries)
            or self.result_bytes < 0
        ):
            raise ValueError("index result is invalid")


class CodeIndex(Protocol):
    def query(self, query_id: str, *, limit: int) -> CodeIndexResult: ...


class StaticCodeIndex:
    def __init__(self, entries: tuple[CodeIndexEntry, ...]) -> None:
        if (
            type(entries) is not tuple
            or len(entries) > _MAX_ENTRIES
            or any(type(item) is not CodeIndexEntry for item in entries)
        ):
            raise ValueError("index entries are invalid")
        ordered = tuple(sorted(entries, key=lambda value: value.path))
        if len({item.path for item in ordered}) != len(ordered):
            raise ValueError("index entries are invalid")
        self._entries = ordered

    def query(self, query_id: str, *, limit: int) -> CodeIndexResult:
        if (
            type(query_id) is not str
            or _QUERY_ID.fullmatch(query_id) is None
            or type(limit) is not int
            or not 0 <= limit <= _MAX_ENTRIES
        ):
            raise ValueError("index query is invalid")
        values = self._entries[:limit]
        return CodeIndexResult(values, sum(value.byte_length for value in values))


class RepositoryCodeIndex(StaticCodeIndex):
    """Read-only code and symbol index built from admitted, sealed source indexes."""

    def __init__(self, indexes: tuple[SymbolIndex, ...]) -> None:
        if (
            type(indexes) is not tuple
            or not indexes
            or len(indexes) > _MAX_ENTRIES
            or any(type(index) is not SymbolIndex for index in indexes)
        ):
            raise ValueError("repository code index is invalid")
        identity: tuple[str, str] | None = None
        by_path: dict[str, SymbolIndex] = {}
        entries: list[CodeIndexEntry] = []
        total = 0
        for index in indexes:
            index.__post_init__()
            current = (index.repository_id, index.revision)
            if (identity is not None and identity != current) or index.path in by_path:
                raise ValueError("repository code index identity is invalid")
            identity = current
            by_path[index.path] = index
            total += index.source_byte_length
            if total > 64 * 1024 * 1024:
                raise ValueError("repository code index exceeds budget")
            entries.append(
                CodeIndexEntry(
                    path=index.path,
                    content_sha256=index.content_sha256,
                    byte_length=index.source_byte_length,
                    language=index.language,
                )
            )
        self._indexes = by_path
        super().__init__(tuple(entries))

    def query(self, query_id: str, *, limit: int) -> CodeIndexResult:
        if type(query_id) is not str or not _valid_index_path(query_id):
            raise ValueError("code index query is invalid")
        if type(limit) is not int or not 0 <= limit <= _MAX_ENTRIES:
            raise ValueError("code index query is invalid")
        index = self._indexes.get(query_id)
        entries = (
            ()
            if index is None
            else (
                CodeIndexEntry(
                    path=index.path,
                    content_sha256=index.content_sha256,
                    byte_length=index.source_byte_length,
                    language=index.language,
                ),
            )
        )
        return CodeIndexResult(entries, sum(entry.byte_length for entry in entries))

    def resolve_reference(self, reference: SymbolReference) -> SymbolResolution:
        return resolve_symbol_reference(
            reference, tuple(self._indexes[path] for path in sorted(self._indexes))
        )
