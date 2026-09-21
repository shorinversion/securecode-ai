"""Descriptor-bound durable file operations for private local state."""

from __future__ import annotations

import os
import stat
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Any

_REVOKED = b"SECURECODE_ARTIFACT_REVOKED\n"


def _platform_attribute(target: object, name: str) -> Any:
    return getattr(target, name)


def durable_write_new(path: Path, content: bytes) -> None:
    """Create one regular file, flush its bytes, and durably publish its name."""

    if os.name == "nt":
        descriptor = _windows_open(path, disposition=1, write_through=True)
        try:
            _write_flush(descriptor, content)
            _require_regular(descriptor)
        finally:
            os.close(descriptor)
        return
    directory = _open_directory(path.parent)
    descriptor = -1
    try:
        descriptor = os.open(
            path.name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
        _write_flush(descriptor, content)
        fchmod = getattr(os, "fchmod", None)
        if fchmod is None:
            raise OSError("durable permissions are unavailable")
        fchmod(descriptor, 0o600)
        _require_regular(descriptor)
        os.fsync(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


def durable_replace(path: Path, content: bytes) -> None:
    """Replace a regular file atomically and durably in its existing directory."""

    _require_existing_regular(path)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    durable_write_new(temporary, content)
    try:
        if os.name == "nt":
            _windows_move_replace(temporary, path)
            descriptor = _windows_open(path, disposition=3, write_through=False)
            try:
                _require_regular(descriptor)
            finally:
                os.close(descriptor)
            return
        directory = _open_directory(path.parent)
        try:
            os.replace(
                temporary.name,
                path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with suppress(OSError):
            durable_delete(temporary)


def durable_delete(path: Path) -> bool:
    """Revoke and remove the exact no-follow regular object currently named by path."""

    if os.name == "nt":
        try:
            descriptor = _windows_open(path, disposition=3, write_through=True)
        except FileNotFoundError:
            return False
        try:
            _require_regular(descriptor)
            _revoke(descriptor)
            _windows_delete_handle(descriptor)
        finally:
            os.close(descriptor)
        return True
    directory = _open_directory(path.parent)
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
        except FileNotFoundError:
            return False
        expected = _identity(descriptor)
        _revoke(descriptor)
        quarantine = f".{path.name}.{uuid.uuid4().hex}.revoked"
        os.rename(
            path.name,
            quarantine,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        actual = os.stat(quarantine, dir_fd=directory, follow_symlinks=False)
        if (actual.st_dev, actual.st_ino) != expected or not stat.S_ISREG(actual.st_mode):
            raise OSError("durable deletion identity changed")
        os.unlink(quarantine, dir_fd=directory)
        os.fsync(directory)
        return True
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


def _open_directory(path: Path) -> int:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise OSError("durable parent is not a directory")
    return descriptor


def _require_existing_regular(path: Path) -> None:
    if os.name == "nt":
        descriptor = _windows_open(path, disposition=3, write_through=False)
        os.close(descriptor)
        return
    directory = _open_directory(path.parent)
    descriptor = -1
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
        expected = _identity(descriptor)
        actual = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if (actual.st_dev, actual.st_ino) != expected or not stat.S_ISREG(actual.st_mode):
            raise OSError("durable replacement identity changed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


def _write_flush(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise OSError("durable write was incomplete")
        written += count
    os.fsync(descriptor)


def _require_regular(descriptor: int) -> None:
    info = os.fstat(descriptor)
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if not stat.S_ISREG(info.st_mode) or (reparse and attributes & reparse):
        raise OSError("durable object is not a regular file")


def _identity(descriptor: int) -> tuple[int, int]:
    _require_regular(descriptor)
    info = os.fstat(descriptor)
    return info.st_dev, info.st_ino


def _revoke(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    _write_flush(descriptor, _REVOKED)


def _windows_open(path: Path, *, disposition: int, write_through: bool) -> int:
    import ctypes
    import msvcrt

    kernel32 = _platform_attribute(ctypes, "WinDLL")("kernel32", use_last_error=True)
    create = kernel32.CreateFileW
    create.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
    )
    create.restype = ctypes.c_void_p
    flags = 0x00200000 | (0x80000000 if write_through else 0)
    handle = create(
        str(path),
        0x80000000 | 0x40000000 | 0x00010000,
        0x1 | 0x2 | 0x4,
        None,
        disposition,
        flags,
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        error = int(_platform_attribute(ctypes, "get_last_error")())
        if error in {2, 3}:
            raise FileNotFoundError(error, "durable object was not found")
        if error in {80, 183}:
            raise FileExistsError(error, "durable object already exists")
        raise OSError(error, "durable object could not be opened")
    try:
        descriptor = int(
            _platform_attribute(msvcrt, "open_osfhandle")(
                handle, os.O_RDWR | getattr(os, "O_BINARY", 0)
            )
        )
    except OSError:
        kernel32.CloseHandle(handle)
        raise
    try:
        _require_regular(descriptor)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _windows_move_replace(source: Path, destination: Path) -> None:
    import ctypes

    kernel32 = _platform_attribute(ctypes, "WinDLL")("kernel32", use_last_error=True)
    move = kernel32.MoveFileExW
    move.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong)
    move.restype = ctypes.c_int
    if not move(str(source), str(destination), 0x1 | 0x8):
        raise OSError(
            int(_platform_attribute(ctypes, "get_last_error")()),
            "durable replacement failed",
        )


def _windows_delete_handle(descriptor: int) -> None:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class FileDispositionInfo(ctypes.Structure):
        _fields_ = (("delete_file", wintypes.BOOL),)

    kernel32 = _platform_attribute(ctypes, "WinDLL")("kernel32", use_last_error=True)
    operation = kernel32.SetFileInformationByHandle
    operation.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong)
    operation.restype = wintypes.BOOL
    value = FileDispositionInfo(True)
    if not operation(
        _platform_attribute(msvcrt, "get_osfhandle")(descriptor),
        4,
        ctypes.byref(value),
        ctypes.sizeof(value),
    ):
        raise OSError(
            int(_platform_attribute(ctypes, "get_last_error")()),
            "durable handle deletion failed",
        )


__all__ = ["durable_delete", "durable_replace", "durable_write_new"]
