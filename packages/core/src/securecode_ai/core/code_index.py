"""Immutable read-only code-index metadata interface for evaluation experiments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class CodeIndexEntry:
    path: str
    content_sha256: str
    byte_length: int
    language: str

    def __post_init__(self) -> None:
        if (
            not self.path
            or ".." in self.path.split("/")
            or len(self.content_sha256) != 64
            or not 0 <= self.byte_length <= 1_048_576
        ):
            raise ValueError("index entry is invalid")


@dataclass(frozen=True, slots=True)
class CodeIndexResult:
    entries: tuple[CodeIndexEntry, ...]
    result_bytes: int


class CodeIndex(Protocol):
    def query(self, query_id: str, *, limit: int) -> CodeIndexResult: ...


class StaticCodeIndex:
    def __init__(self, entries: tuple[CodeIndexEntry, ...]) -> None:
        self._entries = tuple(sorted(entries, key=lambda value: value.path))

    def query(self, query_id: str, *, limit: int) -> CodeIndexResult:
        values = self._entries[:limit]
        return CodeIndexResult(values, sum(value.byte_length for value in values))
