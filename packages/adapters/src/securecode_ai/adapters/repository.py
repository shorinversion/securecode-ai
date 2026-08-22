"""Bounded, no-execution local filesystem repository intake."""

from __future__ import annotations

import ctypes
import hashlib
import os
import stat
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

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


def _platform_attribute(target: object, name: str) -> Any:
    return getattr(target, name)


def _fail(code: RepositoryIntakeErrorCode) -> RepositoryIntakeError:
    return RepositoryIntakeError(code)


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _validate_relative(parts: tuple[str, ...], limits: InventoryLimits) -> str:
    if not parts or len(parts) > limits.max_depth:
        raise _fail(RepositoryIntakeErrorCode.DEPTH_LIMIT)
    for index, part in enumerate(parts):
        if (
            not part
            or part in {".", ".."}
            or unicodedata.normalize("NFC", part) != part
            or "/" in part
            or "\\" in part
            or (
                index == 0
                and len(part) >= 2
                and part[0].isascii()
                and part[0].isalpha()
                and part[1] == ":"
            )
            or any(ord(character) < 32 or ord(character) == 127 for character in part)
        ):
            raise _fail(RepositoryIntakeErrorCode.PATH_INVALID)
    relative = "/".join(parts)
    if len(relative.encode("utf-8")) > limits.max_path_bytes:
        raise _fail(RepositoryIntakeErrorCode.PATH_LIMIT)
    return relative


class _NamedEntry(Protocol):
    name: str


def _bounded_entries(target: object, limit: int) -> tuple[_NamedEntry, ...]:
    entries: list[_NamedEntry] = []
    with os.scandir(target) as iterator:  # type: ignore[call-overload]
        for entry in iterator:
            entries.append(entry)
            if len(entries) > limit:
                raise _fail(RepositoryIntakeErrorCode.ENTRY_LIMIT)
    return tuple(sorted(entries, key=lambda item: item.name))


def _entry_budget(limits: InventoryLimits, *, root: bool) -> int:
    return limits.max_files + limits.max_directories + (1 if root else 0)


def _digest_pass(descriptor: int, maximum: int) -> tuple[int, str]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    size = 0
    while chunk := os.read(descriptor, _READ_SIZE):
        size += len(chunk)
        if size > maximum:
            raise _fail(RepositoryIntakeErrorCode.FILE_SIZE_LIMIT)
        digest.update(chunk)
    return size, digest.hexdigest()


@dataclass(slots=True)
class _PosixState:
    limits: InventoryLimits
    files: list[RepositoryFile] = field(default_factory=list)
    directories: int = 0
    total_bytes: int = 0
    folded_paths: set[str] = field(default_factory=set)
    descriptors: list[int] = field(default_factory=list)
    directory_snapshots: list[tuple[int, tuple[str, ...], tuple[int, int], bool]] = field(
        default_factory=list
    )
    path_bindings: list[tuple[int, str, tuple[int, int], int, int]] = field(default_factory=list)
    root_binding: tuple[Path, tuple[int, int]] | None = None


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", ctypes.c_uint32),
        ("creation_time", _FileTime),
        ("access_time", _FileTime),
        ("write_time", _FileTime),
        ("volume_serial", ctypes.c_uint32),
        ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32),
        ("links", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    ]


@dataclass(frozen=True, slots=True)
class _WindowsInfo:
    identity: tuple[int, int]
    attributes: int
    size: int
    mtime_ticks: int
    links: int

    @property
    def is_directory(self) -> bool:
        return bool(self.attributes & 0x10)

    @property
    def is_reparse(self) -> bool:
        return bool(self.attributes & _REPARSE_POINT)


@dataclass(slots=True)
class _WindowsState:
    limits: InventoryLimits
    files: list[RepositoryFile] = field(default_factory=list)
    directories: int = 0
    total_bytes: int = 0
    folded_paths: set[str] = field(default_factory=set)
    handles: list[int] = field(default_factory=list)
    descriptors: list[int] = field(default_factory=list)
    directory_snapshots: list[tuple[Path, _WindowsInfo, tuple[str, ...], bool]] = field(
        default_factory=list
    )
    path_bindings: list[tuple[Path, _WindowsInfo]] = field(default_factory=list)


_INVALID_HANDLE = ctypes.c_void_p(-1).value
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
_FILE_TYPE_DISK = 0x0001


def _kernel32() -> object:
    factory = _platform_attribute(ctypes, "WinDLL")
    return factory("kernel32", use_last_error=True)


def _win_last_error() -> int:
    return int(_platform_attribute(ctypes, "get_last_error")())


def _win_open(path: Path, *, directory_hint: bool) -> int:
    kernel = _kernel32()
    create_file = kernel.CreateFileW  # type: ignore[attr-defined]
    create_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    flags = _FILE_FLAG_OPEN_REPARSE_POINT
    flags |= _FILE_FLAG_BACKUP_SEMANTICS if directory_hint else _FILE_FLAG_SEQUENTIAL_SCAN
    handle = create_file(
        str(path),
        _GENERIC_READ,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        flags,
        None,
    )
    if handle == _INVALID_HANDLE or handle is None:
        raise OSError(_win_last_error(), "filesystem object open failed")
    return int(handle)


def _win_close(handle: int) -> None:
    kernel = _kernel32()
    close_handle = kernel.CloseHandle  # type: ignore[attr-defined]
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    if not close_handle(ctypes.c_void_p(handle)):
        raise OSError(_win_last_error(), "filesystem object close failed")


def _win_info(handle: int) -> _WindowsInfo:
    kernel = _kernel32()
    file_type = kernel.GetFileType  # type: ignore[attr-defined]
    file_type.argtypes = [ctypes.c_void_p]
    file_type.restype = ctypes.c_uint32
    if file_type(ctypes.c_void_p(handle)) != _FILE_TYPE_DISK:
        raise _fail(RepositoryIntakeErrorCode.ENTRY_TYPE_UNSUPPORTED)
    get_info = kernel.GetFileInformationByHandle  # type: ignore[attr-defined]
    get_info.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ByHandleFileInformation)]
    get_info.restype = ctypes.c_int
    raw = _ByHandleFileInformation()
    if not get_info(ctypes.c_void_p(handle), ctypes.byref(raw)):
        raise OSError(_win_last_error(), "filesystem object inspection failed")
    return _WindowsInfo(
        identity=(
            int(raw.volume_serial),
            (int(raw.file_index_high) << 32) | int(raw.file_index_low),
        ),
        attributes=int(raw.attributes),
        size=(int(raw.size_high) << 32) | int(raw.size_low),
        mtime_ticks=(int(raw.write_time.high) << 32) | int(raw.write_time.low),
        links=int(raw.links),
    )


def _win_reopen_info(path: Path, expected: _WindowsInfo) -> None:
    handle = _win_open(path, directory_hint=expected.is_directory)
    try:
        current = _win_info(handle)
    finally:
        _win_close(handle)
    if current != expected:
        raise _fail(RepositoryIntakeErrorCode.CONTENT_CHANGED)


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
            limits = self._limits()
            files = (
                self._inventory_windows(absolute, limits)
                if os.name == "nt"
                else self._inventory_posix(absolute, limits)
            )
            result = tuple(sorted(files, key=lambda item: item.path))
            return RepositoryInventory(
                files=result,
                total_bytes=sum(item.size_bytes for item in result),
                tree_sha256=repository_tree_sha256(result),
            )
        except RepositoryIntakeError:
            raise
        except (OSError, UnicodeError, ValueError, RecursionError):
            pass
        raise _fail(RepositoryIntakeErrorCode.IO_FAILURE)

    def _inventory_posix(self, root: Path, limits: InventoryLimits) -> list[RepositoryFile]:
        state = _PosixState(limits)
        root_lstat = root.lstat()
        if stat.S_ISLNK(root_lstat.st_mode):
            raise _fail(RepositoryIntakeErrorCode.LINK_UNSUPPORTED)
        if not stat.S_ISDIR(root_lstat.st_mode):
            raise _fail(RepositoryIntakeErrorCode.ROOT_INVALID)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        root_fd = os.open(root, flags)
        state.descriptors.append(root_fd)
        try:
            root_state = os.fstat(root_fd)
            if not stat.S_ISDIR(root_state.st_mode) or _identity(root_state) != _identity(
                root_lstat
            ):
                raise _fail(RepositoryIntakeErrorCode.ROOT_CHANGED)
            state.root_binding = (root, _identity(root_state))
            self._walk_posix(root_fd, (), state, root=True)
            self._validate_posix_snapshot(state)
            return state.files
        finally:
            for descriptor in reversed(state.descriptors):
                os.close(descriptor)

    def _walk_posix(
        self,
        directory_fd: int,
        parent_parts: tuple[str, ...],
        state: _PosixState,
        *,
        root: bool = False,
    ) -> None:
        entries = _bounded_entries(directory_fd, _entry_budget(state.limits, root=root))
        names = tuple(entry.name for entry in entries)
        state.directory_snapshots.append(
            (directory_fd, names, _identity(os.fstat(directory_fd)), root)
        )
        for entry in entries:
            parts = (*parent_parts, entry.name)
            relative = _validate_relative(parts, state.limits)
            folded = relative.casefold()
            if folded in state.folded_paths:
                raise _fail(RepositoryIntakeErrorCode.PATH_INVALID)
            state.folded_paths.add(folded)
            entry_state = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(entry_state.st_mode):
                raise _fail(RepositoryIntakeErrorCode.LINK_UNSUPPORTED)
            if root and entry.name == ".git":
                if not (stat.S_ISDIR(entry_state.st_mode) or stat.S_ISREG(entry_state.st_mode)):
                    raise _fail(RepositoryIntakeErrorCode.ENTRY_TYPE_UNSUPPORTED)
                state.path_bindings.append(
                    (
                        directory_fd,
                        entry.name,
                        _identity(entry_state),
                        entry_state.st_size,
                        entry_state.st_mtime_ns,
                    )
                )
                continue
            if entry.name == ".git":
                raise _fail(RepositoryIntakeErrorCode.NESTED_REPOSITORY)
            if stat.S_ISDIR(entry_state.st_mode):
                state.directories += 1
                if state.directories > state.limits.max_directories:
                    raise _fail(RepositoryIntakeErrorCode.DIRECTORY_LIMIT)
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                )
                child_fd = os.open(entry.name, flags, dir_fd=directory_fd)
                state.descriptors.append(child_fd)
                current = os.fstat(child_fd)
                if _identity(current) != _identity(entry_state) or not stat.S_ISDIR(
                    current.st_mode
                ):
                    raise _fail(RepositoryIntakeErrorCode.ROOT_CHANGED)
                state.path_bindings.append(
                    (
                        directory_fd,
                        entry.name,
                        _identity(current),
                        current.st_size,
                        current.st_mtime_ns,
                    )
                )
                self._walk_posix(child_fd, parts, state)
                continue
            if not stat.S_ISREG(entry_state.st_mode):
                raise _fail(RepositoryIntakeErrorCode.ENTRY_TYPE_UNSUPPORTED)
            self._accept_posix_file(directory_fd, entry.name, relative, entry_state, state)

    def _accept_posix_file(
        self,
        directory_fd: int,
        name: str,
        relative: str,
        expected: os.stat_result,
        state: _PosixState,
    ) -> None:
        if len(state.files) >= state.limits.max_files:
            raise _fail(RepositoryIntakeErrorCode.FILE_LIMIT)
        if expected.st_size > state.limits.max_file_bytes:
            raise _fail(RepositoryIntakeErrorCode.FILE_SIZE_LIMIT)
        if state.total_bytes + expected.st_size > state.limits.max_total_bytes:
            raise _fail(RepositoryIntakeErrorCode.TOTAL_SIZE_LIMIT)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        state.descriptors.append(descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or _identity(before) != _identity(expected):
            raise _fail(RepositoryIntakeErrorCode.CONTENT_CHANGED)
        if expected.st_nlink != 1 or before.st_nlink != 1:
            raise _fail(RepositoryIntakeErrorCode.LINK_UNSUPPORTED)
        first = _digest_pass(descriptor, state.limits.max_file_bytes)
        middle = os.fstat(descriptor)
        second = _digest_pass(descriptor, state.limits.max_file_bytes)
        after = os.fstat(descriptor)
        if (
            first != second
            or _identity(before) != _identity(middle)
            or _identity(before) != _identity(after)
            or before.st_size != middle.st_size
            or before.st_size != after.st_size
            or before.st_mtime_ns != middle.st_mtime_ns
            or before.st_mtime_ns != after.st_mtime_ns
            or first[0] != before.st_size
        ):
            raise _fail(RepositoryIntakeErrorCode.CONTENT_CHANGED)
        state.total_bytes += first[0]
        if state.total_bytes > state.limits.max_total_bytes:
            raise _fail(RepositoryIntakeErrorCode.TOTAL_SIZE_LIMIT)
        state.files.append(RepositoryFile(relative, first[0], first[1]))
        state.path_bindings.append(
            (directory_fd, name, _identity(before), before.st_size, before.st_mtime_ns)
        )

    def _validate_posix_snapshot(self, state: _PosixState) -> None:
        if state.root_binding is None:
            raise _fail(RepositoryIntakeErrorCode.ROOT_CHANGED)
        root_path, root_identity = state.root_binding
        root_state = root_path.lstat()
        if stat.S_ISLNK(root_state.st_mode) or _identity(root_state) != root_identity:
            raise _fail(RepositoryIntakeErrorCode.ROOT_CHANGED)
        for directory_fd, names, identity, root in state.directory_snapshots:
            current = os.fstat(directory_fd)
            if not stat.S_ISDIR(current.st_mode) or _identity(current) != identity:
                raise _fail(RepositoryIntakeErrorCode.ROOT_CHANGED)
            observed = tuple(
                entry.name
                for entry in _bounded_entries(directory_fd, _entry_budget(state.limits, root=root))
            )
            if observed != names:
                raise _fail(RepositoryIntakeErrorCode.ROOT_CHANGED)
        for directory_fd, name, identity, size, mtime_ns in state.path_bindings:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                stat.S_ISLNK(current.st_mode)
                or _identity(current) != identity
                or current.st_size != size
                or current.st_mtime_ns != mtime_ns
            ):
                raise _fail(RepositoryIntakeErrorCode.CONTENT_CHANGED)

    def _inventory_windows(self, root: Path, limits: InventoryLimits) -> list[RepositoryFile]:
        state = _WindowsState(limits)
        root_handle = _win_open(root, directory_hint=True)
        state.handles.append(root_handle)
        try:
            root_info = _win_info(root_handle)
            if root_info.is_reparse:
                raise _fail(RepositoryIntakeErrorCode.LINK_UNSUPPORTED)
            if not root_info.is_directory:
                raise _fail(RepositoryIntakeErrorCode.ROOT_INVALID)
            self._walk_windows(root, (), root_info, state, root=True)
            self._validate_windows_snapshot(state)
            return state.files
        finally:
            for descriptor in reversed(state.descriptors):
                os.close(descriptor)
            for handle in reversed(state.handles):
                _win_close(handle)

    def _walk_windows(
        self,
        directory: Path,
        parent_parts: tuple[str, ...],
        directory_info: _WindowsInfo,
        state: _WindowsState,
        *,
        root: bool = False,
    ) -> None:
        entries = _bounded_entries(directory, _entry_budget(state.limits, root=root))
        names = tuple(entry.name for entry in entries)
        state.directory_snapshots.append((directory, directory_info, names, root))
        for entry in entries:
            parts = (*parent_parts, entry.name)
            relative = _validate_relative(parts, state.limits)
            folded = relative.casefold()
            if folded in state.folded_paths:
                raise _fail(RepositoryIntakeErrorCode.PATH_INVALID)
            state.folded_paths.add(folded)
            path = directory / entry.name
            handle = _win_open(path, directory_hint=True)
            state.handles.append(handle)
            info = _win_info(handle)
            if info.is_reparse:
                raise _fail(RepositoryIntakeErrorCode.LINK_UNSUPPORTED)
            if root and entry.name == ".git":
                state.path_bindings.append((path, info))
                continue
            if entry.name == ".git":
                raise _fail(RepositoryIntakeErrorCode.NESTED_REPOSITORY)
            if info.is_directory:
                state.directories += 1
                if state.directories > state.limits.max_directories:
                    raise _fail(RepositoryIntakeErrorCode.DIRECTORY_LIMIT)
                self._walk_windows(path, parts, info, state)
                continue
            self._accept_windows_file(path, relative, handle, info, state)

    def _accept_windows_file(
        self,
        path: Path,
        relative: str,
        handle: int,
        info: _WindowsInfo,
        state: _WindowsState,
    ) -> None:
        if len(state.files) >= state.limits.max_files:
            raise _fail(RepositoryIntakeErrorCode.FILE_LIMIT)
        if info.size > state.limits.max_file_bytes:
            raise _fail(RepositoryIntakeErrorCode.FILE_SIZE_LIMIT)
        if state.total_bytes + info.size > state.limits.max_total_bytes:
            raise _fail(RepositoryIntakeErrorCode.TOTAL_SIZE_LIMIT)
        if info.links != 1:
            raise _fail(RepositoryIntakeErrorCode.LINK_UNSUPPORTED)
        import msvcrt

        try:
            descriptor = _platform_attribute(msvcrt, "open_osfhandle")(
                handle, os.O_RDONLY | getattr(os, "O_BINARY", 0)
            )
        except (OSError, ValueError):
            state.handles.remove(handle)
            _win_close(handle)
            raise
        state.handles.remove(handle)
        state.descriptors.append(descriptor)
        first = _digest_pass(descriptor, state.limits.max_file_bytes)
        middle = _win_info(_platform_attribute(msvcrt, "get_osfhandle")(descriptor))
        second = _digest_pass(descriptor, state.limits.max_file_bytes)
        after = _win_info(_platform_attribute(msvcrt, "get_osfhandle")(descriptor))
        if first != second or info != middle or info != after or first[0] != info.size:
            raise _fail(RepositoryIntakeErrorCode.CONTENT_CHANGED)
        state.total_bytes += first[0]
        if state.total_bytes > state.limits.max_total_bytes:
            raise _fail(RepositoryIntakeErrorCode.TOTAL_SIZE_LIMIT)
        state.files.append(RepositoryFile(relative, first[0], first[1]))
        state.path_bindings.append((path, info))

    def _validate_windows_snapshot(self, state: _WindowsState) -> None:
        for directory, info, names, root in state.directory_snapshots:
            _win_reopen_info(directory, info)
            observed = tuple(
                entry.name
                for entry in _bounded_entries(directory, _entry_budget(state.limits, root=root))
            )
            if observed != names:
                raise _fail(RepositoryIntakeErrorCode.ROOT_CHANGED)
        for path, info in state.path_bindings:
            _win_reopen_info(path, info)


__all__ = ["FileSystemRepositoryIntake"]
