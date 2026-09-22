"""Durable tenant-scoped backup state with optimistic concurrency."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import Final

_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_STATES: Final = frozenset({"PLANNED", "BACKED_UP", "RESTORED"})


class BackupConflict(RuntimeError):
    """Backup state is invalid, stale, cross-tenant or contradictory."""


@dataclass(frozen=True, slots=True)
class BackupRecord:
    tenant_id: str
    backup_id: str
    component_hashes: tuple[str, ...]
    region: str
    encryption_key_ref: str
    version: int
    state: str
    rpo_seconds: int | None = None
    rto_seconds: int | None = None
    manifest_sha256: str | None = None
    backup_verified: bool = False
    restore_verified: bool = False
    created_at: int = 0
    completed_at: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "component_hashes", _component_tuple(self.component_hashes))


def _component_tuple(value: object) -> tuple[object, ...]:
    if not isinstance(value, Iterable):
        raise TypeError("component hashes must be iterable")
    return tuple(value)


BACKUP_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS backups (
        tenant_id TEXT NOT NULL,
        backup_id TEXT NOT NULL,
        body_json TEXT NOT NULL,
        version INTEGER NOT NULL,
        state TEXT NOT NULL,
        manifest_sha256 TEXT,
        PRIMARY KEY (tenant_id, backup_id)
    )""",
    """CREATE INDEX IF NOT EXISTS backups_state_idx
       ON backups (tenant_id, state, backup_id)""",
    """CREATE TABLE IF NOT EXISTS backup_idempotency (
        tenant_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        operation TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        backup_id TEXT NOT NULL,
        result_json TEXT NOT NULL,
        PRIMARY KEY (tenant_id, idempotency_key),
        FOREIGN KEY (tenant_id, backup_id)
            REFERENCES backups (tenant_id, backup_id)
    )""",
)


class BackupRepository:
    """SQLite repository that never performs an unscoped backup lookup."""

    def __init__(self, db: sqlite3.Connection) -> None:
        if not isinstance(db, sqlite3.Connection):
            raise TypeError("db must be a sqlite3 connection")
        self.db = db
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute("PRAGMA busy_timeout = 5000")
        try:
            for statement in BACKUP_SCHEMA_STATEMENTS:
                self.db.execute(statement)
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    @classmethod
    def in_memory(cls) -> BackupRepository:
        return cls(sqlite3.connect(":memory:"))

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        cursor = self.db.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            yield cursor
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        finally:
            cursor.close()

    def save(
        self,
        value: BackupRecord,
        expected: int | None,
        *,
        idempotency_key: str | None = None,
        operation: str | None = None,
        request_sha256: str | None = None,
    ) -> BackupRecord:
        _validate_record(value)
        _validate_operation_fields(idempotency_key, operation, request_sha256)
        with self._transaction() as cursor:
            replay = self._replay_cursor(
                cursor,
                tenant_id=value.tenant_id,
                idempotency_key=idempotency_key,
                operation=operation,
                request_sha256=request_sha256,
            )
            if replay is not None:
                return replay
            row = cursor.execute(
                """SELECT version, body_json FROM backups
                   WHERE tenant_id=? AND backup_id=?""",
                (value.tenant_id, value.backup_id),
            ).fetchone()
            body = _serialize(value)
            if row is None:
                if expected is not None or value.version != 1:
                    raise BackupConflict("backup create precondition failed")
                try:
                    cursor.execute(
                        """INSERT INTO backups (
                            tenant_id, backup_id, body_json, version, state,
                            manifest_sha256
                        ) VALUES (?, ?, ?, ?, ?, ?)""",
                        (
                            value.tenant_id,
                            value.backup_id,
                            body,
                            value.version,
                            value.state,
                            value.manifest_sha256,
                        ),
                    )
                except sqlite3.IntegrityError as error:
                    raise BackupConflict("backup create conflict") from error
            else:
                prior_version = int(row["version"])
                if expected != prior_version or value.version != prior_version + 1:
                    raise BackupConflict("backup version precondition failed")
                cursor.execute(
                    """UPDATE backups
                       SET body_json=?, version=?, state=?, manifest_sha256=?
                       WHERE tenant_id=? AND backup_id=? AND version=?""",
                    (
                        body,
                        value.version,
                        value.state,
                        value.manifest_sha256,
                        value.tenant_id,
                        value.backup_id,
                        prior_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise BackupConflict("backup update lost a race")
            self._remember_cursor(
                cursor,
                value=value,
                idempotency_key=idempotency_key,
                operation=operation,
                request_sha256=request_sha256,
            )
            return value

    def get(self, tenant: str, backup: str) -> BackupRecord:
        _require_identifier(tenant, "tenant_id")
        _require_identifier(backup, "backup_id")
        row = self.db.execute(
            """SELECT body_json FROM backups
               WHERE tenant_id=? AND backup_id=?""",
            (tenant, backup),
        ).fetchone()
        if row is None:
            raise BackupConflict("backup is unknown")
        return _deserialize(row["body_json"])

    def replay(
        self,
        *,
        tenant_id: str,
        idempotency_key: str | None,
        operation: str,
        request_sha256: str,
    ) -> BackupRecord | None:
        _require_identifier(tenant_id, "tenant_id")
        if idempotency_key is None:
            return None
        _validate_operation_fields(idempotency_key, operation, request_sha256)
        row = self.db.execute(
            """SELECT operation, request_sha256, result_json
               FROM backup_idempotency
               WHERE tenant_id=? AND idempotency_key=?""",
            (tenant_id, idempotency_key),
        ).fetchone()
        if row is None:
            return None
        if (row["operation"], row["request_sha256"]) != (
            operation,
            request_sha256,
        ):
            raise BackupConflict("idempotency key has another request")
        return _deserialize(row["result_json"])

    @staticmethod
    def _replay_cursor(
        cursor: sqlite3.Cursor,
        *,
        tenant_id: str,
        idempotency_key: str | None,
        operation: str | None,
        request_sha256: str | None,
    ) -> BackupRecord | None:
        if idempotency_key is None:
            return None
        row = cursor.execute(
            """SELECT operation, request_sha256, result_json
               FROM backup_idempotency
               WHERE tenant_id=? AND idempotency_key=?""",
            (tenant_id, idempotency_key),
        ).fetchone()
        if row is None:
            return None
        if (row["operation"], row["request_sha256"]) != (
            operation,
            request_sha256,
        ):
            raise BackupConflict("idempotency key has another request")
        return _deserialize(row["result_json"])

    @staticmethod
    def _remember_cursor(
        cursor: sqlite3.Cursor,
        *,
        value: BackupRecord,
        idempotency_key: str | None,
        operation: str | None,
        request_sha256: str | None,
    ) -> None:
        if idempotency_key is None:
            return
        cursor.execute(
            """INSERT INTO backup_idempotency (
                tenant_id, idempotency_key, operation, request_sha256,
                backup_id, result_json
            ) VALUES (?, ?, ?, ?, ?, ?)""",
            (
                value.tenant_id,
                idempotency_key,
                operation,
                request_sha256,
                value.backup_id,
                _serialize(value),
            ),
        )


def _validate_record(value: BackupRecord) -> None:
    if not isinstance(value, BackupRecord):
        raise BackupConflict("backup record is invalid")
    _require_identifier(value.tenant_id, "tenant_id")
    _require_identifier(value.backup_id, "backup_id")
    _require_identifier(value.region, "region")
    if (
        type(value.encryption_key_ref) is not str
        or not value.encryption_key_ref
        or len(value.encryption_key_ref) > 512
    ):
        raise BackupConflict("encryption_key_ref is invalid")
    if value.state not in _STATES:
        raise BackupConflict("backup state is invalid")
    if type(value.version) is not int or value.version < 1:
        raise BackupConflict("backup version is invalid")
    if not value.component_hashes or len(value.component_hashes) > 10000:
        raise BackupConflict("backup components are invalid")
    if len(set(value.component_hashes)) != len(value.component_hashes):
        raise BackupConflict("backup components contain duplicates")
    for digest in value.component_hashes:
        _require_sha256(digest, "component_hash")
    if value.manifest_sha256 is not None:
        _require_sha256(value.manifest_sha256, "manifest_sha256")
    for duration in (value.rpo_seconds, value.rto_seconds):
        if duration is not None and (
            type(duration) is not int or duration < 0 or duration > 315360000
        ):
            raise BackupConflict("backup duration is invalid")
    if type(value.backup_verified) is not bool or type(value.restore_verified) is not bool:
        raise BackupConflict("backup verification flags are invalid")
    if value.restore_verified and not value.backup_verified:
        raise BackupConflict("restore cannot be verified before backup")
    if type(value.created_at) is not int or value.created_at < 0:
        raise BackupConflict("created_at is invalid")
    if value.completed_at is not None and (
        type(value.completed_at) is not int or value.completed_at < value.created_at
    ):
        raise BackupConflict("completed_at is invalid")


def validate_backup_record(value: BackupRecord) -> None:
    """Validate an entire record before an adjacent scope write."""

    _validate_record(value)


def _validate_operation_fields(key: str | None, operation: str | None, digest: str | None) -> None:
    values = (key, operation, digest)
    if all(value is None for value in values):
        return
    if any(value is None for value in values):
        raise BackupConflict("idempotency metadata is incomplete")
    assert key is not None and operation is not None and digest is not None
    _require_identifier(key, "idempotency_key")
    _require_identifier(operation, "operation")
    _require_sha256(digest, "request_sha256")


def _serialize(value: BackupRecord) -> str:
    document = asdict(value)
    document["component_hashes"] = list(value.component_hashes)
    return json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _deserialize(payload: str) -> BackupRecord:
    try:
        document = json.loads(payload)
        document["component_hashes"] = tuple(document["component_hashes"])
        record = BackupRecord(**document)
        _validate_record(record)
        return record
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise BackupConflict("stored backup record is invalid") from error


def _require_identifier(value: str, field: str) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise BackupConflict(f"{field} is invalid")


def _require_sha256(value: str, field: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise BackupConflict(f"{field} is invalid")


__all__ = [
    "BACKUP_SCHEMA_STATEMENTS",
    "BackupConflict",
    "BackupRecord",
    "BackupRepository",
    "validate_backup_record",
]
