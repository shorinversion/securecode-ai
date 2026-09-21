"""Fail-closed container directory preparation and process handoff."""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast


def prepare() -> None:
    for name in ("SECURECODE_DATA_DIR", "SECURECODE_TMP_DIR"):
        value = os.environ.get(name)
        if value is None or not value.startswith("/"):
            raise SystemExit(64)
        directory = Path(value)
        descriptor = -1
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            if getattr(os, "O_DIRECTORY", 0) == 0 or getattr(os, "O_NOFOLLOW", 0) == 0:
                raise OSError
            descriptor = os.open(directory, flags)
            details = os.fstat(descriptor)
            geteuid = cast(Callable[[], int], vars(os)["geteuid"])
            fchmod = cast(Callable[[int, int], None], vars(os)["fchmod"])
            if not stat.S_ISDIR(details.st_mode) or details.st_uid != geteuid():
                raise OSError
            fchmod(descriptor, 0o700)
        except OSError:
            raise SystemExit(64) from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)


if __name__ == "__main__":
    prepare()
    if len(sys.argv) < 2:
        raise SystemExit(64)
    os.execvp(sys.argv[1], sys.argv[1:])
