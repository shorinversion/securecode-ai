"""Fail a container health check when the worker event loop stops heartbeating."""

from __future__ import annotations

import os
import stat
import sys
import time

MAX_AGE_SECONDS = 30.0
_HEARTBEAT_NAME = "worker.heartbeat"


def main() -> int:
    data_dir = os.environ.get("SECURECODE_DATA_DIR")
    if data_dir is None:
        return 1
    descriptor = -1
    try:
        if not data_dir.startswith("/") or "\x00" in data_dir:
            return 1
        descriptor = os.open(
            os.path.join(data_dir, _HEARTBEAT_NAME),
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_mode & 0o077
        ):
            return 1
        modified = details.st_mtime
    except OSError:
        return 1
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    age = time.time() - modified
    return 0 if 0 <= age <= MAX_AGE_SECONDS else 1


if __name__ == "__main__":
    sys.exit(main())
