"""Bounded worker liveness heartbeat used by the container health check."""

from __future__ import annotations

import os
import stat
import time
from math import isfinite
from pathlib import Path
from typing import Final

HEARTBEAT_FILE: Final = "worker.heartbeat"


def heartbeat_path(data_dir: Path) -> Path:
    if (
        type(data_dir) is not type(Path())
        or not data_dir.is_absolute()
        or any(part in {"", ".", ".."} for part in data_dir.parts[1:])
        or data_dir.is_symlink()
        or not data_dir.is_dir()
    ):
        raise ValueError("worker liveness directory is invalid")
    try:
        if data_dir.resolve(strict=True) != data_dir:
            raise ValueError("worker liveness directory is invalid")
    except OSError:
        raise ValueError("worker liveness directory is invalid") from None
    return data_dir / HEARTBEAT_FILE


def touch(data_dir: Path, *, now: float | None = None) -> None:
    """Atomically refresh the liveness timestamp without recording workload data."""

    target = heartbeat_path(data_dir)
    timestamp = time.time() if now is None else now
    if type(timestamp) is not float or not isfinite(timestamp) or timestamp < 0:
        raise ValueError("worker liveness clock is invalid")
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise ValueError("worker liveness file is invalid")
        if os.name == "posix":
            geteuid = getattr(os, "geteuid", None)
            if not callable(geteuid) or details.st_uid != geteuid():
                raise ValueError("worker liveness file is invalid")
            fchmod = getattr(os, "fchmod", None)
            if callable(fchmod):
                fchmod(descriptor, 0o600)
            elif details.st_mode & 0o077:
                raise ValueError("worker liveness file is invalid")
        # POSIX updates the opened inode directly, so a replacement between
        # validation and the timestamp update cannot redirect the heartbeat.
        # Windows versions without descriptor support retain the private-path
        # fallback used by the container entrypoint.
        if os.utime in getattr(os, "supports_fd", ()):
            os.utime(descriptor, (timestamp, timestamp))
        else:
            if target.is_symlink():
                raise ValueError("worker liveness file is invalid")
            os.utime(target, (timestamp, timestamp))
    finally:
        os.close(descriptor)


__all__ = ["HEARTBEAT_FILE", "heartbeat_path", "touch"]
