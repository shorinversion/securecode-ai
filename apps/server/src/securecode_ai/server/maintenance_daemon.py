"""Run bounded lifecycle maintenance passes inside the server deployment."""

from __future__ import annotations

import os
import re
import signal
import threading
from collections.abc import Mapping
from typing import Final

from .maintenance_cli import run as run_maintenance

_DEFAULT_INTERVAL_SECONDS: Final = 60
_MIN_INTERVAL_SECONDS: Final = 5
_MAX_INTERVAL_SECONDS: Final = 86_400
_MAX_TENANTS_PER_PASS: Final = 64
_TENANT_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


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
    arguments = tuple(
        _maintenance_arguments(values, tenant_id=tenant_id)
        for tenant_id in _tenant_ids(values)
    )
    interval = _interval(values)
    while not stop_event.is_set():
        pass_status = 0
        for tenant_arguments in arguments:
            result = run_maintenance(tenant_arguments)
            if result not in {0, 1, 2}:
                return result
            if result == 1:
                # A failed pass is not a degraded success.  Keep the daemon
                # from reporting a healthy long-lived process while every
                # iteration fails; the supervisor can restart it and surface
                # the failure instead of hiding it behind the next sleep.
                return 1
            elif result == 2 and pass_status == 0:
                pass_status = 2
        retention_days = values.get("SECURECODE_SYSTEM_BACKUP_RETENTION_DAYS", "90")
        max_items = values.get("SECURECODE_RETENTION_EXECUTE_LIMIT", "32")
        result = run_maintenance(
            (
                "system-backup-prune",
                "--retention-days",
                retention_days,
                "--max-items",
                max_items,
            )
        )
        if result not in {0, 1, 2}:
            return result
        if result == 1:
            return 1
        if result == 2 and pass_status == 0:
            pass_status = 2
        if stop_event.wait(interval):
            return pass_status
    return 0


def _tenant_ids(values: Mapping[str, str]) -> tuple[str, ...]:
    configured_list = values.get("SECURECODE_MAINTENANCE_TENANT_IDS")
    configured_single = values.get("SECURECODE_MAINTENANCE_TENANT_ID")
    if configured_list:
        if configured_single:
            raise ValueError("maintenance tenant configuration is ambiguous")
        raw_ids = configured_list.split(",")
        if (
            len(configured_list) > 8192
            or len(raw_ids) > _MAX_TENANTS_PER_PASS
            or any(not value or value != value.strip() for value in raw_ids)
            or any(_TENANT_ID.fullmatch(value) is None for value in raw_ids)
            or len(set(raw_ids)) != len(raw_ids)
        ):
            raise ValueError("maintenance tenant configuration is invalid")
        return tuple(raw_ids)
    if (
        type(configured_single) is not str
        or _TENANT_ID.fullmatch(configured_single) is None
    ):
        raise ValueError("maintenance tenant configuration is incomplete")
    return (configured_single,)


def _maintenance_arguments(values: Mapping[str, str], *, tenant_id: str) -> list[str]:
    required = {
        "--owner-id": "SECURECODE_MAINTENANCE_OWNER_ID",
        "--metadata-days": "SECURECODE_RETENTION_METADATA_DAYS",
        "--artifact-days": "SECURECODE_RETENTION_ARTIFACT_DAYS",
        "--audit-days": "SECURECODE_RETENTION_AUDIT_DAYS",
    }
    arguments = ["--tenant-id", tenant_id]
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
