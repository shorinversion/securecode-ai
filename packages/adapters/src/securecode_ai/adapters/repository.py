"""Bounded, no-execution local filesystem repository intake."""

from __future__ import annotations

import hashlib
import os
import stat
import unicodedata
from pathlib import Path

from securecode_ai.core import (
    InventoryLimits,
    RepositoryFile,
    RepositoryIntakeError,
    RepositoryIntakeErrorCode,
    RepositoryInventory,
    repository_tree_sha256,
)

_REPARSE_POINT = 0x400
_READ_SIZE = 64 * 1024


def _fail(code: RepositoryIntakeErrorCode) -> RepositoryIntakeError:
    return RepositoryIntakeError(code)


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _is_reparse(value: os.stat_result) -> bool:
    return bool(getattr(value, "st_file_attributes", 0) & _REPARSE_POINT)


def _validate_relative(parts: tuple[str, ...], limits: InventoryLimits) -> str:
    if not parts or len(parts) > limits.max_depth:
        raise _fail(RepositoryIntakeErrorCode.DEPTH_LIMIT)
    for part in parts:
        if (
            not part
            or part in {".", ".."}
            or unicodedata.normalize("NFC", part) != part
            or "/" in part
            or "\\" in part
            or any(ord(character) < 32 or ord(character) == 127 for character in part)
        ):
            raise _fail(RepositoryIntakeErrorCode.PATH_INVALID)
    relative = "/".join(parts)
    if len(relative.encode("utf-8")) > limits.max_path_bytes:
        raise _fail(RepositoryIntakeErrorCode.PATH_LIMIT)
    return relative


def _directory_state(path: Path, expected: tuple[int, int]) -> os.stat_result:
    value = path.lstat()
    if _is_reparse(value) or stat.S_ISLNK(value.st_mode):
        raise _fail(RepositoryIntakeErrorCode.LINK_UNSUPPORTED)
    if not stat.S_ISDIR(value.st_mode) or _identity(value) != expected:
        raise _fail(RepositoryIntakeErrorCode.ROOT_CHANGED)
    return value


class FileSystemRepositoryIntake:
    """Read one local tree as opaque regular files under closed budgets."""

    __slots__ = ("_limit_values",)

    def __init__(self, limits: InventoryLimits) -> None:
        if type(limits) is not InventoryLimits:
            raise TypeError("inventory limits are invalid")
        self._limit_values = (
            limits.max_files,
            limits.max_directories,
            limits.max_depth,
            limits.max_path_bytes,
            limits.max_file_bytes,
            limits.max_total_bytes,
        )

    def _limits(self) -> InventoryLimits:
        return InventoryLimits(*self._limit_values)

    def inventory(self, root: Path) -> RepositoryInventory:
        if not isinstance(root, Path):
            raise _fail(RepositoryIntakeErrorCode.ROOT_INVALID)
        try:
            absolute = root.absolute()
            root_state = absolute.lstat()
            if _is_reparse(root_state) or stat.S_ISLNK(root_state.st_mode):
                raise _fail(RepositoryIntakeErrorCode.LINK_UNSUPPORTED)
            if not stat.S_ISDIR(root_state.st_mode):
                raise _fail(RepositoryIntakeErrorCode.ROOT_INVALID)
            root_identity = _identity(root_state)
            files = self._walk(absolute, root_identity, self._limits())
            _directory_state(absolute, root_identity)
            result = tuple(sorted(files, key=lambda item: item.path))
            return RepositoryInventory(
                files=result,
                total_bytes=sum(item.size_bytes for item in result),
                tree_sha256=repository_tree_sha256(result),
            )
        except RepositoryIntakeError:
            raise
        except (OSError, UnicodeError, ValueError):
            pass
        raise _fail(RepositoryIntakeErrorCode.IO_FAILURE)

    def _walk(
        self,
        root: Path,
        root_identity: tuple[int, int],
        limits: InventoryLimits,
    ) -> list[RepositoryFile]:
        pending: list[tuple[Path, tuple[str, ...], tuple[int, int]]] = [(root, (), root_identity)]
        files: list[RepositoryFile] = []
        directories = 0
        total_bytes = 0
        folded_paths: set[str] = set()
        while pending:
            directory, parent_parts, expected = pending.pop()
            _directory_state(directory, expected)
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
            for entry in entries:
                parts = (*parent_parts, entry.name)
                if not parent_parts and entry.name == ".git":
                    continue
                relative = _validate_relative(parts, limits)
                folded = relative.casefold()
                if folded in folded_paths:
                    raise _fail(RepositoryIntakeErrorCode.PATH_INVALID)
                folded_paths.add(folded)
                entry_path = Path(entry.path)
                entry_state = entry_path.lstat()
                if _is_reparse(entry_state) or stat.S_ISLNK(entry_state.st_mode):
                    raise _fail(RepositoryIntakeErrorCode.LINK_UNSUPPORTED)
                if entry.name == ".git":
                    raise _fail(RepositoryIntakeErrorCode.NESTED_REPOSITORY)
                if stat.S_ISDIR(entry_state.st_mode):
                    directories += 1
                    if directories > limits.max_directories:
                        raise _fail(RepositoryIntakeErrorCode.DIRECTORY_LIMIT)
                    pending.append((entry_path, parts, _identity(entry_state)))
                    continue
                if not stat.S_ISREG(entry_state.st_mode):
                    raise _fail(RepositoryIntakeErrorCode.ENTRY_TYPE_UNSUPPORTED)
                if len(files) >= limits.max_files:
                    raise _fail(RepositoryIntakeErrorCode.FILE_LIMIT)
                if entry_state.st_size > limits.max_file_bytes:
                    raise _fail(RepositoryIntakeErrorCode.FILE_SIZE_LIMIT)
                if total_bytes + entry_state.st_size > limits.max_total_bytes:
                    raise _fail(RepositoryIntakeErrorCode.TOTAL_SIZE_LIMIT)
                item = self._read_file(entry_path, relative, entry_state, limits)
                total_bytes += item.size_bytes
                if total_bytes > limits.max_total_bytes:
                    raise _fail(RepositoryIntakeErrorCode.TOTAL_SIZE_LIMIT)
                files.append(item)
            _directory_state(directory, expected)
        return files

    def _read_file(
        self,
        path: Path,
        relative: str,
        expected: os.stat_result,
        limits: InventoryLimits,
    ) -> RepositoryFile:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or _identity(before) != _identity(expected):
                raise _fail(RepositoryIntakeErrorCode.CONTENT_CHANGED)
            digest = hashlib.sha256()
            size = 0
            while chunk := os.read(descriptor, _READ_SIZE):
                size += len(chunk)
                if size > limits.max_file_bytes:
                    raise _fail(RepositoryIntakeErrorCode.FILE_SIZE_LIMIT)
                digest.update(chunk)
            after = os.fstat(descriptor)
            if (
                _identity(after) != _identity(before)
                or after.st_size != before.st_size
                or after.st_mtime_ns != before.st_mtime_ns
                or size != after.st_size
            ):
                raise _fail(RepositoryIntakeErrorCode.CONTENT_CHANGED)
            return RepositoryFile(relative, size, digest.hexdigest())
        finally:
            os.close(descriptor)


__all__ = ["FileSystemRepositoryIntake"]
