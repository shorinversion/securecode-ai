"""Process-death-safe locking for durable local patch status files."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from importlib import import_module
from pathlib import Path
from typing import Any


def _platform_attribute(target: object, name: str) -> Any:
    return getattr(target, name)


class StatusFileLockBusy(OSError):
    pass


class StatusFileLockError(OSError):
    pass


@contextmanager
def status_file_lock(path: Path) -> Iterator[None]:
    """Hold a kernel lock; the persistent file is not a lock ownership token."""

    descriptor = _open_lock(path)
    locked = False
    try:
        _lock_descriptor(descriptor)
        locked = True
        yield
    finally:
        if locked:
            _unlock_descriptor(descriptor)
        os.close(descriptor)


def _open_lock(path: Path) -> int:
    if os.name == "nt":
        return _open_windows(path)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != int(_platform_attribute(os, "geteuid")())
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 1
        ):
            raise StatusFileLockError
        return descriptor
    except Exception as error:
        if "descriptor" in locals():
            os.close(descriptor)
        if isinstance(error, StatusFileLockError):
            raise
        raise StatusFileLockError from None


def _open_windows(path: Path) -> int:
    import ctypes
    import msvcrt

    kernel32 = _platform_attribute(ctypes, "WinDLL")("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    handle = create_file(
        str(path),
        0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
        0x1 | 0x2,  # FILE_SHARE_READ | FILE_SHARE_WRITE; deny rename/delete
        None,
        4,  # OPEN_ALWAYS
        0x02000000 | 0x80,  # FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise StatusFileLockError
    try:
        descriptor = int(
            _platform_attribute(msvcrt, "open_osfhandle")(
                handle, os.O_RDWR | getattr(os, "O_BINARY", 0)
            )
        )
    except OSError:
        kernel32.CloseHandle(handle)
        raise StatusFileLockError from None
    try:
        info = os.fstat(descriptor)
        attributes = getattr(info, "st_file_attributes", 0)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size > 1
            or attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise StatusFileLockError
        return descriptor
    except Exception:
        os.close(descriptor)
        raise StatusFileLockError from None


def _lock_descriptor(descriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        try:
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
        except OSError:
            raise StatusFileLockError from None
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            _platform_attribute(msvcrt, "locking")(
                descriptor, _platform_attribute(msvcrt, "LK_NBLCK"), 1
            )
        except OSError:
            raise StatusFileLockBusy from None
    else:
        try:
            fcntl = import_module("fcntl")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StatusFileLockBusy from None
        except OSError:
            raise StatusFileLockError from None


def _unlock_descriptor(descriptor: int) -> None:
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            _platform_attribute(msvcrt, "locking")(
                descriptor, _platform_attribute(msvcrt, "LK_UNLCK"), 1
            )
        else:
            fcntl = import_module("fcntl")
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError:
        pass


__all__ = ["StatusFileLockBusy", "StatusFileLockError", "status_file_lock"]
