"""Fail a container health check when the worker event loop stops heartbeating."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

MAX_AGE_SECONDS = 30.0


def main() -> int:
    data_dir = os.environ.get("SECURECODE_DATA_DIR")
    if data_dir is None:
        return 1
    try:
        modified = (Path(data_dir) / "worker.heartbeat").stat().st_mtime
    except OSError:
        return 1
    return 0 if 0 <= time.time() - modified <= MAX_AGE_SECONDS else 1


if __name__ == "__main__":
    sys.exit(main())
