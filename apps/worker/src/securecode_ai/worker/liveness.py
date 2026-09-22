"""Bounded worker liveness heartbeat used by the container health check."""

from __future__ import annotations

import os
import time
from math import isfinite
from pathlib import Path
from typing import Final

HEARTBEAT_FILE: Final = "worker.heartbeat"


def heartbeat_path(data_dir: Path) -> Path:
    if not data_dir.is_absolute() or data_dir.is_symlink() or not data_dir.is_dir():
        raise ValueError("worker liveness directory is invalid")
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
        # Windows does not accept a file descriptor in os.utime. The enclosing
        # data directory is private and opened by the container entrypoint.
        os.utime(target, (timestamp, timestamp))
    finally:
        os.close(descriptor)


__all__ = ["HEARTBEAT_FILE", "heartbeat_path", "touch"]
