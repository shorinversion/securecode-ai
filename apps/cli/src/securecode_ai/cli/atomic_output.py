"""Crash-safe create-if-absent publication for bounded CLI output."""

from __future__ import annotations

import os
import re
import stat
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import cast

_REVOKED = b"SECURECODE_OUTPUT_REVOKED\n"


class OutputRollbackError(OSError):
    """Publication failed and rollback could not prove complete revocation."""


def write_new_output(
    destination: Path,
    rendered: bytes,
    *,
    before_publish: Callable[[], None] | None = None,
    after_publish: Callable[[], None] | None = None,
) -> None:
    """Publish complete bytes atomically without replacing an existing path."""

    if not isinstance(destination, Path) or type(rendered) is not bytes:
        raise TypeError("output publication input is invalid")
    parent = destination.parent.resolve(strict=True)
    name = destination.name
    if not name or name in {".", ".."}:
        raise ValueError("output destination is invalid")
    directory = _open_directory(parent)
    temporary_name = f".{name}.{uuid.uuid4().hex}.tmp"
    descriptor = -1
    published = False
    try:
        _cleanup_stale_temporaries(parent, directory, name)
        descriptor = _create_temporary(parent, directory, temporary_name)
        _write_all(descriptor, rendered)
        os.fsync(descriptor)
        if before_publish is not None:
            before_publish()
        _publish_new(parent, directory, temporary_name, name)
        published = True
        _require_name_matches(parent, directory, name, descriptor)
        if after_publish is not None:
            after_publish()
        _fsync_directory(directory)
    except BaseException as error:
        if published and descriptor >= 0:
            try:
                _revoke_and_remove(parent, directory, name, descriptor)
            except Exception as rollback_error:
                raise OutputRollbackError(
                    "output publication failed and rollback was incomplete"
                ) from rollback_error
        raise error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        _remove_temporary(parent, directory, temporary_name)
        if directory >= 0:
            os.close(directory)


def _open_directory(parent: Path) -> int:
    if os.name == "nt":
        if not parent.is_dir() or parent.is_symlink():
            raise OSError("output parent is not a directory")
        return -1
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(parent, flags)
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != _effective_user_id()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        os.close(descriptor)
        raise OSError("output parent is not a directory")
    return descriptor


def _create_temporary(parent: Path, directory: int, name: str) -> int:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if os.name == "nt":
        return _windows_create_new(parent / name)
    return os.open(name, flags, 0o600, dir_fd=directory)


def _windows_create_new(path: Path) -> int:
    return _windows_open(path, disposition=1)


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise OSError("output publication was incomplete")
        written += count


def _publish_new(parent: Path, directory: int, source: str, destination: str) -> None:
    if os.name == "nt":
        _windows_move_new(parent / source, parent / destination)
    else:
        os.link(
            source,
            destination,
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )


def _windows_move_new(source: Path, destination: Path) -> None:
    import ctypes

    kernel32 = vars(ctypes)["WinDLL"]("kernel32", use_last_error=True)
    move = kernel32.MoveFileExW
    move.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong)
    move.restype = ctypes.c_int
    if not move(str(source), str(destination), 0x8):
        error = vars(ctypes)["get_last_error"]()
        raise FileExistsError(error, "output destination could not be created")


def _identity_from_descriptor(descriptor: int) -> tuple[int, int]:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        raise OSError("output is not a regular file")
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if reparse and attributes & reparse:
        raise OSError("output is a reparse point")
    return info.st_dev, info.st_ino


def _identity_from_name(parent: Path, directory: int, name: str) -> tuple[int, int]:
    if os.name == "nt":
        info = (parent / name).stat(follow_symlinks=False)
    else:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise OSError("output is not a regular file")
    return info.st_dev, info.st_ino


def _require_name_matches(parent: Path, directory: int, name: str, descriptor: int) -> None:
    if _identity_from_name(parent, directory, name) != _identity_from_descriptor(descriptor):
        raise OSError("output destination identity changed")


def _revoke_and_remove(parent: Path, directory: int, name: str, descriptor: int) -> None:
    expected = _identity_from_descriptor(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    _write_all(descriptor, _REVOKED)
    os.fsync(descriptor)
    try:
        if os.name == "nt":
            _windows_delete_handle(descriptor)
        elif _identity_from_name(parent, directory, name) == expected:
            os.unlink(name, dir_fd=directory)
    except FileNotFoundError:
        pass
    try:
        actual = _identity_from_name(parent, directory, name)
    except FileNotFoundError:
        _fsync_directory(directory)
        return
    if actual == expected:
        raise OutputRollbackError("revoked output remains published")
    _fsync_directory(directory)


def _windows_delete_handle(descriptor: int) -> None:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class FileDispositionInfo(ctypes.Structure):
        _fields_ = (("delete_file", wintypes.BOOL),)

    kernel32 = vars(ctypes)["WinDLL"]("kernel32", use_last_error=True)
    operation = kernel32.SetFileInformationByHandle
    operation.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong)
    operation.restype = wintypes.BOOL
    value = FileDispositionInfo(True)
    handle = vars(msvcrt)["get_osfhandle"](descriptor)
    if not operation(handle, 4, ctypes.byref(value), ctypes.sizeof(value)):
        raise OSError(vars(ctypes)["get_last_error"](), "output handle deletion failed")


def _cleanup_stale_temporaries(parent: Path, directory: int, destination_name: str) -> None:
    cutoff = time.time() - 86_400
    prefix = f".{destination_name}."
    removed = 0
    try:
        names = os.listdir(parent if os.name == "nt" else directory)  # noqa: PTH208
    except OSError:
        return
    for name in names:
        if removed >= 32 or not name.startswith(prefix) or not name.endswith(".tmp"):
            continue
        if re.fullmatch(r"[0-9a-f]{32}", name[len(prefix) : -4]) is None:
            continue
        descriptor = -1
        try:
            descriptor = _open_existing(parent, directory, name)
            info = os.fstat(descriptor)
            if (
                stat.S_ISREG(info.st_mode)
                and info.st_mtime <= cutoff
                and (
                    os.name == "nt"
                    or (info.st_uid == _effective_user_id() and stat.S_IMODE(info.st_mode) == 0o600)
                )
                and _identity_from_name(parent, directory, name)
                == _identity_from_descriptor(descriptor)
            ):
                if os.name == "nt":
                    _windows_delete_handle(descriptor)
                else:
                    os.unlink(name, dir_fd=directory)
                removed += 1
        except OSError:
            continue
        finally:
            if descriptor >= 0:
                os.close(descriptor)


def _open_existing(parent: Path, directory: int, name: str) -> int:
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    if os.name == "nt":
        return _windows_open_existing(parent / name)
    return os.open(name, flags | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)


def _windows_open_existing(path: Path) -> int:
    return _windows_open(path, disposition=3)


def _windows_open(path: Path, *, disposition: int) -> int:
    import ctypes
    import msvcrt

    kernel32 = vars(ctypes)["WinDLL"]("kernel32", use_last_error=True)
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
    handle = create(
        str(path),
        0x80000000 | 0x40000000 | 0x00010000,
        0x1 | 0x2 | 0x4,
        None,
        disposition,
        0x02000000,
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(vars(ctypes)["get_last_error"](), "output could not be opened")
    try:
        descriptor = cast(
            int,
            vars(msvcrt)["open_osfhandle"](handle, os.O_RDWR | getattr(os, "O_BINARY", 0)),
        )
    except OSError:
        kernel32.CloseHandle(handle)
        raise
    try:
        _identity_from_descriptor(descriptor)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _remove_temporary(parent: Path, directory: int, name: str) -> None:
    try:
        descriptor = _open_existing(parent, directory, name)
    except OSError:
        return
    try:
        if os.name == "nt":
            _windows_delete_handle(descriptor)
        elif _identity_from_name(parent, directory, name) == _identity_from_descriptor(descriptor):
            os.unlink(name, dir_fd=directory)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _fsync_directory(directory: int) -> None:
    if directory >= 0:
        os.fsync(directory)


def _effective_user_id() -> int:
    return cast(int, vars(os)["geteuid"]())


__all__ = ["OutputRollbackError", "write_new_output"]
