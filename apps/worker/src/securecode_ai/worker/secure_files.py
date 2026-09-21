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
        or type(minimum) is not int
        or type(maximum) is not int
        or minimum < 1
        or maximum < minimum
        or os.name != "posix"
        or _O_NOFOLLOW == 0
    ):
        raise ValueError("worker secret file is invalid")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
        )
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
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
            or final_details.st_size != details.st_size
            or final_details.st_mtime_ns != details.st_mtime_ns
        ):
            raise ValueError("worker secret file is invalid")
        value = raw.rstrip(b"\r\n").decode("ascii")
    except (OSError, UnicodeDecodeError):
        raise ValueError("worker secret file is invalid") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not minimum <= len(value) <= maximum or any(
        ord(character) < 33 or ord(character) > 126 for character in value
    ):
        raise ValueError("worker secret file is invalid")
    return value


__all__ = ["read_ascii_secret"]
