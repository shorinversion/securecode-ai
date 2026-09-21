"""One-shot maintenance entrypoint for lifecycle planning and execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final, NoReturn, TextIO

from .data_lifecycle import LifecycleLedger
from .data_lifecycle_models import RetentionProfile
from .filesystem_paths import lexical_absolute_path
from .lifecycle_scheduler import ApprovedDeletionScheduler, ScheduledDeletionResult
from .migrations import SchemaVersionError, require_schema_version
from .retention_planner import ArtifactRetentionPlanner, PlannedArtifactDeletion
from .runtime import load_settings
from .sqlite_database import open_private_sqlite
from .storage_executor import LocalArtifactStorageExecutor

_SCHEMA_VERSION: Final = 1
_REPARSE_POINT: Final = 0x400


class _MaintenanceParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError("maintenance arguments are invalid")


def main() -> None:
    raise SystemExit(run())


def run(arguments: Sequence[str] | None = None) -> int:
    try:
        options = _parser().parse_args(arguments)
        profile = RetentionProfile(
            tenant_id=options.tenant_id,
            metadata_days=options.metadata_days,
            artifact_days=options.artifact_days,
            audit_days=options.audit_days,
        )
        settings = load_settings()
        database_path, artifact_root = _existing_paths(Path(settings.data_dir))
        connection = _open_existing_database(database_path)
        try:
            _require_schema(connection)
            storage = LocalArtifactStorageExecutor(connection, artifact_root)
            ledger = LifecycleLedger(connection, storage=storage)
            planner = ArtifactRetentionPlanner(
                connection,
                requested_by=options.owner_id,
            )
            scheduler = ApprovedDeletionScheduler(
                connection,
                ledger,
                owner_id=options.owner_id,
            )
            planned = planner.run_once(
                profile=profile,
                max_items=options.plan_limit,
            )
            executed = scheduler.run_once(
                tenant_id=profile.tenant_id,
                max_items=options.execute_limit,
            )
        finally:
            connection.close()
        conflict_count = sum(item.outcome == "CONFLICT" for item in executed)
        output = {
            "schema_version": _SCHEMA_VERSION,
            "status": "partial" if conflict_count else "ok",
            "tenant_sha256": _text_hash(profile.tenant_id),
            "owner_sha256": _text_hash(options.owner_id),
            "profile_sha256": _profile_hash(profile),
            "planned_count": len(planned),
            "planned_receipt_sha256": _planned_hash(planned),
            "executed_count": sum(item.outcome == "EXECUTED" for item in executed),
            "conflict_count": conflict_count,
            "execution_receipt_sha256": _execution_hash(executed),
        }
        _write_json(sys.stdout, output)
        return 2 if conflict_count else 0
    except SystemExit:
        raise
    except Exception:
        _write_json(
            sys.stderr,
            {
                "schema_version": _SCHEMA_VERSION,
                "status": "error",
                "error_code": "MAINTENANCE_FAILED",
            },
        )
        return 1


def _parser() -> argparse.ArgumentParser:
    parser = _MaintenanceParser(
        prog="securecode-maintenance",
        description="Run one bounded lifecycle maintenance pass and exit.",
    )
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--metadata-days", required=True, type=_bounded_days)
    parser.add_argument("--artifact-days", required=True, type=_bounded_days)
    parser.add_argument("--audit-days", required=True, type=_bounded_days)
    parser.add_argument("--plan-limit", type=_bounded_batch, default=32)
    parser.add_argument("--execute-limit", type=_bounded_batch, default=32)
    return parser


def _bounded_days(value: str) -> int:
    if not value.isascii() or not value.isdigit():
        raise argparse.ArgumentTypeError("retention days must be an integer")
    parsed = int(value)
    if not 0 <= parsed <= 36_500:
        raise argparse.ArgumentTypeError("retention days are out of range")
    return parsed


def _bounded_batch(value: str) -> int:
    if not value.isascii() or not value.isdigit():
        raise argparse.ArgumentTypeError("batch size must be an integer")
    parsed = int(value)
    if not 1 <= parsed <= 256:
        raise argparse.ArgumentTypeError("batch size is out of range")
    return parsed


def _existing_paths(data_dir: Path) -> tuple[Path, Path]:
    root = lexical_absolute_path(data_dir)
    _require_directory_chain(root)
    database_path = root / "control-plane.sqlite3"
    artifact_root = root / "artifacts"
    _require_regular_file(database_path)
    _require_plain_directory(artifact_root)
    return database_path, artifact_root


def _open_existing_database(path: Path) -> sqlite3.Connection:
    connection: sqlite3.Connection | None = None
    try:
        connection = open_private_sqlite(path, create=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA synchronous = FULL")
        return connection
    except sqlite3.Error as error:
        if connection is not None:
            connection.close()
        raise RuntimeError("maintenance database is unavailable") from error
    except Exception:
        if connection is not None:
            connection.close()
        raise


def _require_schema(connection: sqlite3.Connection) -> None:
    try:
        require_schema_version(connection)
    except (sqlite3.DatabaseError, SchemaVersionError):
        raise RuntimeError("maintenance schema is unavailable") from None


def _require_plain_directory(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise RuntimeError("maintenance directory is unavailable") from error
    if _link_like(details) or not stat.S_ISDIR(details.st_mode):
        raise RuntimeError("maintenance directory is unsafe")


def _require_directory_chain(path: Path) -> None:
    if not path.is_absolute() or not path.anchor:
        raise RuntimeError("maintenance directory is unsafe")
    current = Path(path.anchor)
    _require_plain_directory(current)
    for part in path.parts[1:]:
        current /= part
        _require_plain_directory(current)


def _require_regular_file(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise RuntimeError("maintenance database is unavailable") from error
    if _link_like(details) or not stat.S_ISREG(details.st_mode):
        raise RuntimeError("maintenance database is unsafe")


def _link_like(details: os.stat_result) -> bool:
    attributes = getattr(details, "st_file_attributes", 0)
    return stat.S_ISLNK(details.st_mode) or bool(attributes & _REPARSE_POINT)


def _profile_hash(profile: RetentionProfile) -> str:
    return _document_hash(
        {
            "artifact_days": profile.artifact_days,
            "audit_days": profile.audit_days,
            "metadata_days": profile.metadata_days,
            "tenant_id": profile.tenant_id,
        }
    )


def _planned_hash(values: tuple[PlannedArtifactDeletion, ...]) -> str:
    return _document_hash(
        [
            {
                "content_sha256": item.content_sha256,
                "deletion_id": item.deletion_id,
                "eligible_at": item.eligible_at,
                "execution_identity_hash": item.execution_identity_hash,
                "profile_sha256": item.profile_sha256,
                "repository_id": item.repository_id,
                "requested_at": item.requested_at,
                "tenant_id": item.tenant_id,
            }
            for item in values
        ]
    )


def _execution_hash(values: tuple[ScheduledDeletionResult, ...]) -> str:
    return _document_hash(
        [
            {
                "deletion_id": item.deletion_id,
                "execution_identity_hash": item.execution_identity_hash,
                "outcome": item.outcome,
                "resulting_version": item.resulting_version,
            }
            for item in values
        ]
    )


def _text_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document_hash(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _write_json(stream: TextIO, value: object) -> None:
    stream.write(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


__all__ = ["main", "run"]


if __name__ == "__main__":
    main()
