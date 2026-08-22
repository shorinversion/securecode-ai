"""Framework-independent contracts for bounded repository intake."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_INVENTORY_DEPTH = 256


class RepositoryIntakeErrorCode(StrEnum):
    ROOT_INVALID = "ROOT_INVALID"
    ROOT_CHANGED = "ROOT_CHANGED"
    PATH_INVALID = "PATH_INVALID"
    PATH_LIMIT = "PATH_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    DIRECTORY_LIMIT = "DIRECTORY_LIMIT"
    ENTRY_LIMIT = "ENTRY_LIMIT"
    FILE_LIMIT = "FILE_LIMIT"
    FILE_SIZE_LIMIT = "FILE_SIZE_LIMIT"
    TOTAL_SIZE_LIMIT = "TOTAL_SIZE_LIMIT"
    LINK_UNSUPPORTED = "LINK_UNSUPPORTED"
    NESTED_REPOSITORY = "NESTED_REPOSITORY"
    ENTRY_TYPE_UNSUPPORTED = "ENTRY_TYPE_UNSUPPORTED"
    CONTENT_CHANGED = "CONTENT_CHANGED"
    IO_FAILURE = "IO_FAILURE"


class RepositoryIntakeError(RuntimeError):
    """Fixed, non-echoing repository intake failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: RepositoryIntakeErrorCode) -> None:
        if type(code) is not RepositoryIntakeErrorCode:
            raise TypeError("repository intake error code is invalid")
        self.code = code
        self.safe_message = "repository intake failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class InventoryLimits:
    max_files: int
    max_directories: int
    max_depth: int
    max_path_bytes: int
    max_file_bytes: int
    max_total_bytes: int

    def __post_init__(self) -> None:
        values = (
            self.max_files,
            self.max_directories,
            self.max_depth,
            self.max_path_bytes,
            self.max_file_bytes,
            self.max_total_bytes,
        )
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError("inventory limits are invalid")
        if self.max_depth > _MAX_INVENTORY_DEPTH:
            raise ValueError("inventory limits are invalid")


@dataclass(frozen=True, slots=True)
class RepositoryFile:
    path: str
    size_bytes: int
    content_sha256: str

    def __post_init__(self) -> None:
        if type(self.path) is not str or not _valid_repository_path(self.path):
            raise ValueError("repository file is invalid")
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            raise ValueError("repository file is invalid")
        if type(self.content_sha256) is not str or not _SHA256.fullmatch(self.content_sha256):
            raise ValueError("repository file is invalid")


def _valid_repository_path(path: str) -> bool:
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or (len(path) >= 2 and path[0].isascii() and path[0].isalpha() and path[1] == ":")
    ):
        return False
    parts = path.split("/")
    return all(
        part
        and part not in {".", ".."}
        and unicodedata.normalize("NFC", part) == part
        and not any(ord(character) < 32 or ord(character) == 127 for character in part)
        for part in parts
    )


def repository_tree_sha256(files: tuple[RepositoryFile, ...]) -> str:
    digest = hashlib.sha256()
    for item in files:
        path = item.path.encode("utf-8")
        digest.update(len(path).to_bytes(8, "big"))
        digest.update(path)
        digest.update(item.size_bytes.to_bytes(8, "big"))
        digest.update(bytes.fromhex(item.content_sha256))
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class RepositoryInventory:
    files: tuple[RepositoryFile, ...]
    total_bytes: int
    tree_sha256: str

    def __post_init__(self) -> None:
        if type(self.files) is not tuple or any(
            type(item) is not RepositoryFile for item in self.files
        ):
            raise ValueError("repository inventory is invalid")
        paths = tuple(item.path for item in self.files)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ValueError("repository inventory is invalid")
        if type(self.total_bytes) is not int or self.total_bytes != sum(
            item.size_bytes for item in self.files
        ):
            raise ValueError("repository inventory is invalid")
        if type(self.tree_sha256) is not str or self.tree_sha256 != repository_tree_sha256(
            self.files
        ):
            raise ValueError("repository inventory is invalid")


__all__ = [
    "InventoryLimits",
    "RepositoryFile",
    "RepositoryIntakeError",
    "RepositoryIntakeErrorCode",
    "RepositoryInventory",
    "repository_tree_sha256",
]
