"""Descriptor-bound secret file reads for the Linux worker."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Final, cast

_O_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK: Final = getattr(os, "O_NONBLOCK", 0)


def read_ascii_secret(path: Path, *, minimum: int, maximum: int) -> str:
    """Open, validate, and read one regular secret through the same descriptor."""

    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or ".." in path.parts
        or type(minimum) is not int
        or type(maximum) is not int
        or minimum < 1
        or maximum < minimum
        or os.name != "posix"
        or _O_NOFOLLOW == 0
    ):
        raise ValueError("worker secret file is invalid")
    directory_flags = (
        os.O_RDONLY
        | _O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | _O_NOFOLLOW
    )
    descriptor = -1
    directory_descriptors: list[int] = []
    try:
        directory_descriptor = os.open(path.anchor, directory_flags)
        directory_descriptors.append(directory_descriptor)
        for component in path.parent.parts[1:]:
            if component in {"", ".", ".."}:
                raise ValueError("worker secret file is invalid")
            directory_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=directory_descriptor,
            )
            directory_descriptors.append(directory_descriptor)
        details_before = os.stat(
            path.name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        descriptor = os.open(
            path.name,
            os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
            dir_fd=directory_descriptor,
        )
        details = os.fstat(descriptor)
        if (
            details_before.st_dev != details.st_dev
            or details_before.st_ino != details.st_ino
            or details_before.st_mode != details.st_mode
            or not stat.S_ISREG(details.st_mode)
            or not minimum <= details.st_size <= maximum
            or details.st_mode & 0o077
            or details.st_nlink != 1
            or details.st_uid not in {0, cast(Callable[[], int], vars(os)["geteuid"])()}
        ):
            raise ValueError("worker secret file is invalid")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        final_details = os.fstat(descriptor)
        if (
            len(raw) > maximum
            or len(raw) != details.st_size
            or not _same_file_state(details, final_details)
        ):
            raise ValueError("worker secret file is invalid")
        if raw.endswith(b"\r\n"):
            raw = raw[:-2]
        elif raw.endswith((b"\r", b"\n")):
            raw = raw[:-1]
        value = raw.decode("ascii")
    except (OSError, UnicodeDecodeError):
        raise ValueError("worker secret file is invalid") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        for directory_descriptor in reversed(directory_descriptors):
            os.close(directory_descriptor)
    if not minimum <= len(value) <= maximum or any(
        ord(character) < 33 or ord(character) > 126 for character in value
    ):
        raise ValueError("worker secret file is invalid")
    return value


def _same_file_state(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and before.st_mode == after.st_mode
        and before.st_nlink == after.st_nlink
        and before.st_uid == after.st_uid
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )


__all__ = ["read_ascii_secret"]
