"""Pinned local Git executable verification."""

from __future__ import annotations

import ctypes
import hashlib
import os
import sys
from pathlib import Path

from .local_product_host_linux import (
    _assert_linux_object_protected as _assert_linux_object_protected,
)
from .local_product_host_linux import (
    _posix_constant,
)
from .local_product_host_primitives import (
    _SHA256,
    LocalProductHostError,
    _reject,
)
from .local_product_host_windows import (
    _assert_windows_key_protected as _assert_windows_key_protected,
)


def verify_local_git_executable(expected_digest: str) -> Path:
    """Verify the fixed platform executable, independent of PATH or selectors."""
    if type(expected_digest) is not str or _SHA256.fullmatch(expected_digest) is None:
        _reject()
    path = Path("C:/Program Files/Git/mingw64/bin/git.exe" if os.name == "nt" else "/usr/bin/git")
    descriptors: list[int] = []
    handles: list[int] = []
    try:
        if os.name == "posix" and sys.platform == "linux":
            flags = os.O_RDONLY | _posix_constant("O_CLOEXEC") | _posix_constant("O_NOFOLLOW")
            parent = os.open("/", flags | _posix_constant("O_DIRECTORY"))
            descriptors.append(parent)
            _assert_linux_object_protected(parent, directory=True)
            for name in ("usr", "bin"):
                parent = os.open(name, flags | _posix_constant("O_DIRECTORY"), dir_fd=parent)
                descriptors.append(parent)
                _assert_linux_object_protected(parent, directory=True)
            leaf = os.open("git", flags | _posix_constant("O_NONBLOCK"), dir_fd=parent)
            descriptors.append(leaf)
            _assert_linux_object_protected(leaf, directory=False)
        elif os.name == "nt":
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            opener = kernel.CreateFileW
            opener.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
            ]
            opener.restype = ctypes.c_void_p
            attribute = kernel.GetFileInformationByHandleEx
            attribute.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
            attribute.restype = ctypes.c_int
            for current in (*reversed(path.parents), path):
                # Retain handles without FILE_SHARE_DELETE or FILE_SHARE_WRITE.
                handle = opener(
                    str(current), 0x80000000 | 0x00020000, 1, None, 3, 0x02000000 | 0x00200000, None
                )
                if not handle or handle == ctypes.c_void_p(-1).value:
                    _reject()
                handles.append(int(handle))
                information = (ctypes.c_uint32 * 2)()
                if not attribute(
                    ctypes.c_void_p(handle), 9, information, ctypes.sizeof(information)
                ):
                    _reject()
                flags_value = information[0]
                if flags_value & 0x400 or ((current != path) != bool(flags_value & 0x10)):
                    _reject()
                _assert_windows_key_protected(
                    int(handle),
                    object_type=1,
                    allow_ancestor_directory_creation=current != path and current != path.parent,
                )
        else:
            _reject()
        # Protection was established first; administrators are the trusted writers.
        digest = hashlib.sha256()
        with path.open("rb") as executable:
            total = 0
            while chunk := executable.read(65536):
                total += len(chunk)
                if total > 64 * 1024 * 1024:
                    _reject()
                digest.update(chunk)
        if digest.hexdigest() != expected_digest:
            _reject()
        return path
    except LocalProductHostError:
        raise
    except Exception:
        _reject()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        if handles:
            closer = kernel.CloseHandle
            closer.argtypes = [ctypes.c_void_p]
            closer.restype = ctypes.c_int
            for handle in reversed(handles):
                closer(ctypes.c_void_p(handle))
