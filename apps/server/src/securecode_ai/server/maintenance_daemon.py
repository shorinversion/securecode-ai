"""Run bounded lifecycle maintenance passes inside the server deployment."""

from __future__ import annotations

import os
import signal
import threading
from collections.abc import Mapping
from typing import Final

from .maintenance_cli import run as run_maintenance

_DEFAULT_INTERVAL_SECONDS: Final = 60
_MIN_INTERVAL_SECONDS: Final = 5
_MAX_INTERVAL_SECONDS: Final = 86_400


def main() -> None:
    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        status = run(stop=stop)
    except ValueError:
        raise SystemExit(64) from None
    raise SystemExit(status)


def run(
    *,
    environment: Mapping[str, str] | None = None,
    stop: threading.Event | None = None,
) -> int:
    """Repeat the existing bounded planner and approved-deletion executor."""

    values = os.environ if environment is None else environment
    stop_event = stop if stop is not None else threading.Event()
    arguments = _maintenance_arguments(values)
    interval = _interval(values)
    while not stop_event.is_set():
        result = run_maintenance(arguments)
        if result not in {0, 2}:
            return result
        if stop_event.wait(interval):
            break
    return 0


def _maintenance_arguments(values: Mapping[str, str]) -> list[str]:
    required = {
        "--tenant-id": "SECURECODE_MAINTENANCE_TENANT_ID",
        "--owner-id": "SECURECODE_MAINTENANCE_OWNER_ID",
        "--metadata-days": "SECURECODE_RETENTION_METADATA_DAYS",
        "--artifact-days": "SECURECODE_RETENTION_ARTIFACT_DAYS",
        "--audit-days": "SECURECODE_RETENTION_AUDIT_DAYS",
    }
    arguments: list[str] = []
    for option, name in required.items():
        value = values.get(name)
        if type(value) is not str or not value:
            raise ValueError("maintenance configuration is incomplete")
        arguments.extend((option, value))
    for option, name in (
        ("--plan-limit", "SECURECODE_RETENTION_PLAN_LIMIT"),
        ("--execute-limit", "SECURECODE_RETENTION_EXECUTE_LIMIT"),
    ):
        value = values.get(name)
        if value is not None:
            arguments.extend((option, value))
    return arguments


def _interval(values: Mapping[str, str]) -> int:
    raw = values.get("SECURECODE_MAINTENANCE_INTERVAL_SECONDS")
    if raw is None:
        return _DEFAULT_INTERVAL_SECONDS
    if type(raw) is not str or not raw.isascii() or not raw.isdecimal():
        raise ValueError("maintenance interval is invalid")
    interval = int(raw)
    if not _MIN_INTERVAL_SECONDS <= interval <= _MAX_INTERVAL_SECONDS:
        raise ValueError("maintenance interval is invalid")
    return interval


if __name__ == "__main__":
    main()


__all__ = ["main", "run"]
