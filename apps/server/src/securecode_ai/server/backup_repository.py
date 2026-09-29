"""Durable tenant-scoped backup state with optimistic concurrency."""

from __future__ import annotations

import hashlib
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


@dataclass(frozen=True, slots=True)
class BackupRecoveryRecord:
    """Immutable administrative resolution of one interrupted restore."""

    tenant_id: str
    backup_id: str
    expected_version: int
    restore_request_sha256: str
    resolution_request_sha256: str
    idempotency_key: str
    actor_id: str
    reason: str
    evidence_ref: str
    resolution: str
    resolved_at: int
    audit_sha256: str


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
    """CREATE TABLE IF NOT EXISTS backup_transition_journal (
        tenant_id TEXT NOT NULL,
        backup_id TEXT NOT NULL,
        operation TEXT NOT NULL CHECK (operation IN ('backup', 'restore')),
        expected_version INTEGER NOT NULL,
        request_sha256 TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('RUNNING', 'COMMITTED')),
        result_json TEXT,
        PRIMARY KEY (tenant_id, backup_id, operation, expected_version),
        FOREIGN KEY (tenant_id, backup_id)
            REFERENCES backups (tenant_id, backup_id),
        CHECK ((status = 'RUNNING' AND result_json IS NULL)
            OR (status = 'COMMITTED' AND result_json IS NOT NULL))
    )""",
    """CREATE TABLE IF NOT EXISTS backup_restore_phases (
        tenant_id TEXT NOT NULL,
        backup_id TEXT NOT NULL,
        expected_version INTEGER NOT NULL,
        request_sha256 TEXT NOT NULL,
        phase TEXT NOT NULL CHECK (phase IN ('IN_PROGRESS', 'APPLIED')),
        manifest_sha256 TEXT NOT NULL,
        component_hashes_json TEXT NOT NULL,
        rpo_seconds INTEGER NOT NULL CHECK (rpo_seconds >= 0),
        rto_seconds INTEGER,
        applied_at INTEGER,
        PRIMARY KEY (tenant_id, backup_id, expected_version),
        FOREIGN KEY (tenant_id, backup_id)
            REFERENCES backups (tenant_id, backup_id),
        CHECK ((phase = 'IN_PROGRESS' AND rto_seconds IS NULL AND applied_at IS NULL)
             OR (phase = 'APPLIED' AND rto_seconds IS NOT NULL AND applied_at IS NOT NULL))
    )""",
    """CREATE TABLE IF NOT EXISTS backup_restore_recovery_audit (
        tenant_id TEXT NOT NULL,
        backup_id TEXT NOT NULL,
        expected_version INTEGER NOT NULL CHECK (expected_version >= 1),
        restore_request_sha256 TEXT NOT NULL,
        resolution_request_sha256 TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        reason TEXT NOT NULL,
        evidence_ref TEXT NOT NULL,
        resolution TEXT NOT NULL CHECK (resolution = 'ABORTED'),
        resolved_at INTEGER NOT NULL CHECK (resolved_at >= 0),
        audit_sha256 TEXT NOT NULL,
        PRIMARY KEY (tenant_id, backup_id, expected_version),
        FOREIGN KEY (tenant_id, backup_id) REFERENCES backups (tenant_id, backup_id)
    )""",
    """CREATE TRIGGER IF NOT EXISTS backup_restore_recovery_audit_no_update
       BEFORE UPDATE ON backup_restore_recovery_audit
       BEGIN
           SELECT RAISE(ABORT, 'backup recovery audit is immutable');
       END""",
    """CREATE TRIGGER IF NOT EXISTS backup_restore_recovery_audit_no_delete
       BEFORE DELETE ON backup_restore_recovery_audit
       BEGIN
           SELECT RAISE(ABORT, 'backup recovery audit is immutable');
       END""",
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
        transition_operation: str | None = None,
        transition_expected: int | None = None,
        transition_request_sha256: str | None = None,
    ) -> BackupRecord:
        _validate_record(value)
        _validate_operation_fields(idempotency_key, operation, request_sha256)
        transition_values = (
            transition_operation,
            transition_expected,
            transition_request_sha256,
        )
        if all(item is None for item in transition_values):
            pass
        elif (
            transition_operation not in {"backup", "restore"}
            or type(transition_expected) is not int
            or transition_expected < 1
            or type(transition_request_sha256) is not str
            or _SHA256.fullmatch(transition_request_sha256) is None
        ):
            raise BackupConflict("backup transition metadata is invalid")
        with self._transaction() as cursor:
            replay = self._replay_cursor(
                cursor,
                tenant_id=value.tenant_id,
                idempotency_key=idempotency_key,
                operation=operation,
                request_sha256=request_sha256,
            )
            if replay is not None:
                if replay.tenant_id != value.tenant_id or replay.backup_id != value.backup_id:
                    raise BackupConflict("idempotency key has another backup")
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
            if transition_operation is not None:
                self._complete_transition_cursor(
                    cursor,
                    value=value,
                    operation=transition_operation,
                    expected=transition_expected,
                    request_sha256=transition_request_sha256,
                )
            return value

    def transition(
        self,
        *,
        tenant_id: str,
        backup_id: str,
        operation: str,
        expected_version: int,
        request_sha256: str,
    ) -> tuple[str, BackupRecord | None] | None:
        _validate_transition_key(tenant_id, backup_id, operation, expected_version, request_sha256)
        row = self.db.execute(
            """SELECT request_sha256, status, result_json
               FROM backup_transition_journal
               WHERE tenant_id=? AND backup_id=? AND operation=? AND expected_version=?""",
            (tenant_id, backup_id, operation, expected_version),
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_sha256:
            raise BackupConflict("backup transition has another request")
        status = str(row["status"])
        if status == "RUNNING":
            if row["result_json"] is not None:
                raise BackupConflict("backup transition journal is corrupt")
            return status, None
        if status != "COMMITTED" or row["result_json"] is None:
            raise BackupConflict("backup transition journal is corrupt")
        return status, _deserialize(row["result_json"])

    def claim_transition(
        self,
        *,
        tenant_id: str,
        backup_id: str,
        operation: str,
        expected_version: int,
        request_sha256: str,
    ) -> bool:
        _validate_transition_key(tenant_id, backup_id, operation, expected_version, request_sha256)
        with self._transaction() as cursor:
            row = cursor.execute(
                """SELECT request_sha256 FROM backup_transition_journal
                   WHERE tenant_id=? AND backup_id=? AND operation=? AND expected_version=?""",
                (tenant_id, backup_id, operation, expected_version),
            ).fetchone()
            if row is not None:
                if row["request_sha256"] != request_sha256:
                    raise BackupConflict("backup transition has another request")
                return False
            cursor.execute(
                """INSERT INTO backup_transition_journal (
                       tenant_id, backup_id, operation, expected_version,
                       request_sha256, status, result_json
                   ) VALUES (?, ?, ?, ?, ?, 'RUNNING', NULL)""",
                (tenant_id, backup_id, operation, expected_version, request_sha256),
            )
            return True

    @staticmethod
    def _complete_transition_cursor(
        cursor: sqlite3.Cursor,
        *,
        value: BackupRecord,
        operation: str,
        expected: int | None,
        request_sha256: str | None,
    ) -> None:
        if type(expected) is not int or type(request_sha256) is not str:
            raise BackupConflict("backup transition metadata is invalid")
        target_state = "BACKED_UP" if operation == "backup" else "RESTORED"
        if value.version != expected + 1 or value.state != target_state:
            raise BackupConflict("backup transition result is inconsistent")
        row = cursor.execute(
            """SELECT request_sha256, status FROM backup_transition_journal
               WHERE tenant_id=? AND backup_id=? AND operation=? AND expected_version=?""",
            (value.tenant_id, value.backup_id, operation, expected),
        ).fetchone()
        if row is None or row["request_sha256"] != request_sha256 or row["status"] != "RUNNING":
            raise BackupConflict("backup transition claim is missing")
        cursor.execute(
            """UPDATE backup_transition_journal
               SET status='COMMITTED', result_json=?
               WHERE tenant_id=? AND backup_id=? AND operation=? AND expected_version=?
                 AND request_sha256=? AND status='RUNNING'""",
            (
                _serialize(value),
                value.tenant_id,
                value.backup_id,
                operation,
                expected,
                request_sha256,
            ),
        )
        if cursor.rowcount != 1:
            raise BackupConflict("backup transition completion lost a race")

    def resolve_stuck_restore(
        self,
        *,
        tenant_id: str,
        backup_id: str,
        expected_version: int,
        restore_request_sha256: str,
        resolution_request_sha256: str,
        idempotency_key: str,
        actor_id: str,
        reason: str,
        evidence_ref: str,
        resolved_at: int,
    ) -> BackupRecoveryRecord:
        """Record an explicit fail-closed resolution for a running restore.

        This never deletes or rewrites the phase marker.  The immutable audit
        row is the separate authorization to stop treating the transition as
        retryable; it cannot be used to apply the restore a second time.
        """

        _validate_recovery_inputs(
            tenant_id=tenant_id,
            backup_id=backup_id,
            expected_version=expected_version,
            restore_request_sha256=restore_request_sha256,
            resolution_request_sha256=resolution_request_sha256,
            idempotency_key=idempotency_key,
            actor_id=actor_id,
            reason=reason,
            evidence_ref=evidence_ref,
            resolved_at=resolved_at,
        )
        with self._transaction() as cursor:
            existing_row = cursor.execute(
                """SELECT tenant_id, backup_id, expected_version,
                          restore_request_sha256, resolution_request_sha256,
                          idempotency_key, actor_id, reason, evidence_ref,
                          resolution, resolved_at, audit_sha256
                   FROM backup_restore_recovery_audit
                   WHERE tenant_id=? AND backup_id=? AND expected_version=?""",
                (tenant_id, backup_id, expected_version),
            ).fetchone()
            if existing_row is not None:
                existing = _recovery_from_row(existing_row)
                if existing.resolution_request_sha256 != resolution_request_sha256:
                    raise BackupConflict("backup recovery resolution conflicts")
                return existing
            # Recovery resolutions are stored outside ``backup_idempotency``
            # because their result is an immutable audit row.  Bind the key
            # before inserting that row so a durable retry cannot reuse the
            # same tenant-scoped key for another backup or operation after a
            # process restart.
            conflicting_operation = cursor.execute(
                """SELECT operation, request_sha256
                   FROM backup_idempotency
                   WHERE tenant_id=? AND idempotency_key=?""",
                (tenant_id, idempotency_key),
            ).fetchone()
            if conflicting_operation is not None:
                raise BackupConflict("idempotency key has another request")
            conflicting_recovery = cursor.execute(
                """SELECT backup_id, expected_version
                   FROM backup_restore_recovery_audit
                   WHERE tenant_id=? AND idempotency_key=?""",
                (tenant_id, idempotency_key),
            ).fetchone()
            if conflicting_recovery is not None:
                raise BackupConflict("idempotency key has another request")
            transition = cursor.execute(
                """SELECT request_sha256, status, result_json
                   FROM backup_transition_journal
                   WHERE tenant_id=? AND backup_id=? AND operation='restore'
                     AND expected_version=?""",
                (tenant_id, backup_id, expected_version),
            ).fetchone()
            if (
                transition is None
                or transition[0] != restore_request_sha256
                or transition[1] != "RUNNING"
                or transition[2] is not None
            ):
                raise BackupConflict("backup restore transition is not unresolved")
            phase = cursor.execute(
                """SELECT request_sha256, phase
                   FROM backup_restore_phases
                   WHERE tenant_id=? AND backup_id=? AND expected_version=?""",
                (tenant_id, backup_id, expected_version),
            ).fetchone()
            if phase is None or phase[0] != restore_request_sha256 or phase[1] != "IN_PROGRESS":
                raise BackupConflict("backup restore phase is not unresolved")
            audit_sha256 = recovery_audit_sha256(
                tenant_id=tenant_id,
                backup_id=backup_id,
                expected_version=expected_version,
                restore_request_sha256=restore_request_sha256,
                resolution_request_sha256=resolution_request_sha256,
                idempotency_key=idempotency_key,
                actor_id=actor_id,
                reason=reason,
                evidence_ref=evidence_ref,
                resolution="ABORTED",
                resolved_at=resolved_at,
            )
            cursor.execute(
                """INSERT INTO backup_restore_recovery_audit (
                       tenant_id, backup_id, expected_version,
                       restore_request_sha256, resolution_request_sha256,
                       idempotency_key, actor_id, reason, evidence_ref,
                       resolution, resolved_at, audit_sha256
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ABORTED', ?, ?)""",
                (
                    tenant_id,
                    backup_id,
                    expected_version,
                    restore_request_sha256,
                    resolution_request_sha256,
                    idempotency_key,
                    actor_id,
                    reason,
                    evidence_ref,
                    resolved_at,
                    audit_sha256,
                ),
            )
            return BackupRecoveryRecord(
                tenant_id=tenant_id,
                backup_id=backup_id,
                expected_version=expected_version,
                restore_request_sha256=restore_request_sha256,
                resolution_request_sha256=resolution_request_sha256,
                idempotency_key=idempotency_key,
                actor_id=actor_id,
                reason=reason,
                evidence_ref=evidence_ref,
                resolution="ABORTED",
                resolved_at=resolved_at,
                audit_sha256=audit_sha256,
            )

    def restore_recovery(
        self, *, tenant_id: str, backup_id: str, expected_version: int
    ) -> BackupRecoveryRecord | None:
        _require_identifier(tenant_id, "tenant_id")
        _require_identifier(backup_id, "backup_id")
        if type(expected_version) is not int or expected_version < 1:
            raise BackupConflict("backup recovery version is invalid")
        row = self.db.execute(
            """SELECT tenant_id, backup_id, expected_version,
                      restore_request_sha256, resolution_request_sha256,
                      idempotency_key, actor_id, reason, evidence_ref,
                      resolution, resolved_at, audit_sha256
               FROM backup_restore_recovery_audit
               WHERE tenant_id=? AND backup_id=? AND expected_version=?""",
            (tenant_id, backup_id, expected_version),
        ).fetchone()
        return None if row is None else _recovery_from_row(row)

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
    if type(value) is not BackupRecord:
        raise BackupConflict("backup record is invalid")
    _require_identifier(value.tenant_id, "tenant_id")
    _require_identifier(value.backup_id, "backup_id")
    _require_identifier(value.region, "region")
    if (
        type(value.encryption_key_ref) is not str
        or not value.encryption_key_ref
        or len(value.encryption_key_ref) > 512
        or not value.encryption_key_ref.isascii()
        or any(
            ord(character) < 0x20 or ord(character) > 0x7E for character in value.encryption_key_ref
        )
    ):
        raise BackupConflict("encryption_key_ref is invalid")
    if type(value.state) is not str or value.state not in _STATES:
        raise BackupConflict("backup state is invalid")
    if type(value.version) is not int or value.version < 1:
        raise BackupConflict("backup version is invalid")
    expected_version = {"PLANNED": 1, "BACKED_UP": 2, "RESTORED": 3}[value.state]
    if value.version != expected_version:
        raise BackupConflict("backup state and version are inconsistent")
    if (
        type(value.component_hashes) is not tuple
        or not value.component_hashes
        or len(value.component_hashes) > 10000
    ):
        raise BackupConflict("backup components are invalid")
    for digest in value.component_hashes:
        _require_sha256(digest, "component_hash")
    if len(set(value.component_hashes)) != len(value.component_hashes):
        raise BackupConflict("backup components contain duplicates")
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
    if value.state == "PLANNED":
        if (
            value.backup_verified
            or value.restore_verified
            or value.rpo_seconds is not None
            or value.rto_seconds is not None
            or value.completed_at is not None
        ):
            raise BackupConflict("planned backup contains completion evidence")
    elif value.state == "BACKED_UP":
        if (
            not value.backup_verified
            or value.restore_verified
            or value.manifest_sha256 is None
            or value.rpo_seconds is None
            or value.rto_seconds is not None
            or value.completed_at is None
        ):
            raise BackupConflict("backed up state is incomplete")
    elif (
        not value.backup_verified
        or not value.restore_verified
        or value.manifest_sha256 is None
        or value.rpo_seconds is None
        or value.rto_seconds is None
        or value.completed_at is None
    ):
        raise BackupConflict("restored state is incomplete")
    if type(value.created_at) is not int or value.created_at < 0:
        raise BackupConflict("created_at is invalid")
    if value.completed_at is not None and (
        type(value.completed_at) is not int or value.completed_at < value.created_at
    ):
        raise BackupConflict("completed_at is invalid")


def validate_backup_record(value: BackupRecord) -> None:
    """Validate an entire record before an adjacent scope write."""

    _validate_record(value)


def serialize_backup_record(value: BackupRecord) -> str:
    """Return the canonical persisted representation of one validated record."""

    _validate_record(value)
    return _serialize(value)


def deserialize_backup_record(payload: str) -> BackupRecord:
    """Load and validate one canonical record from serialized storage."""

    if type(payload) is not str:
        raise BackupConflict("stored backup record is invalid")
    return _deserialize(payload)


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


def _validate_transition_key(
    tenant_id: str,
    backup_id: str,
    operation: str,
    expected_version: int,
    request_sha256: str,
) -> None:
    _require_identifier(tenant_id, "tenant_id")
    _require_identifier(backup_id, "backup_id")
    if operation not in {"backup", "restore"}:
        raise BackupConflict("backup transition operation is invalid")
    if type(expected_version) is not int or expected_version < 1:
        raise BackupConflict("backup transition version is invalid")
    _require_sha256(request_sha256, "request_sha256")


def _validate_recovery_inputs(
    *,
    tenant_id: object,
    backup_id: object,
    expected_version: object,
    restore_request_sha256: object,
    resolution_request_sha256: object,
    idempotency_key: object,
    actor_id: object,
    reason: object,
    evidence_ref: object,
    resolved_at: object,
) -> None:
    _require_identifier(tenant_id, "tenant_id")
    _require_identifier(backup_id, "backup_id")
    if type(expected_version) is not int or expected_version < 1:
        raise BackupConflict("backup recovery version is invalid")
    _require_sha256(restore_request_sha256, "restore_request_sha256")
    _require_sha256(resolution_request_sha256, "resolution_request_sha256")
    _require_text(idempotency_key, "idempotency_key", maximum=128)
    _require_text(actor_id, "actor_id", maximum=256)
    _require_text(reason, "reason", maximum=512)
    _require_identifier(evidence_ref, "evidence_ref")
    if type(resolved_at) is not int or resolved_at < 0:
        raise BackupConflict("backup recovery timestamp is invalid")


def _require_text(value: object, field: str, *, maximum: int) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise BackupConflict(f"{field} is invalid")
    return value


def _recovery_from_row(row: object) -> BackupRecoveryRecord:
    if not isinstance(row, (tuple, sqlite3.Row)) or len(row) != 12:
        raise BackupConflict("stored backup recovery audit is invalid")
    values = tuple(row)
    if not all(type(values[index]) is str for index in (0, 1, 3, 4, 5, 6, 7, 8, 9, 11)):
        raise BackupConflict("stored backup recovery audit is invalid")
    if type(values[2]) is not int or type(values[10]) is not int or values[9] != "ABORTED":
        raise BackupConflict("stored backup recovery audit is invalid")
    record = BackupRecoveryRecord(
        tenant_id=values[0],
        backup_id=values[1],
        expected_version=values[2],
        restore_request_sha256=values[3],
        resolution_request_sha256=values[4],
        idempotency_key=values[5],
        actor_id=values[6],
        reason=values[7],
        evidence_ref=values[8],
        resolution=values[9],
        resolved_at=values[10],
        audit_sha256=values[11],
    )
    _validate_recovery_inputs(
        tenant_id=record.tenant_id,
        backup_id=record.backup_id,
        expected_version=record.expected_version,
        restore_request_sha256=record.restore_request_sha256,
        resolution_request_sha256=record.resolution_request_sha256,
        idempotency_key=record.idempotency_key,
        actor_id=record.actor_id,
        reason=record.reason,
        evidence_ref=record.evidence_ref,
        resolved_at=record.resolved_at,
    )
    if (
        recovery_audit_sha256(
            tenant_id=record.tenant_id,
            backup_id=record.backup_id,
            expected_version=record.expected_version,
            restore_request_sha256=record.restore_request_sha256,
            resolution_request_sha256=record.resolution_request_sha256,
            idempotency_key=record.idempotency_key,
            actor_id=record.actor_id,
            reason=record.reason,
            evidence_ref=record.evidence_ref,
            resolution=record.resolution,
            resolved_at=record.resolved_at,
        )
        != record.audit_sha256
    ):
        raise BackupConflict("stored backup recovery audit hash is invalid")
    if (
        recovery_request_sha256(
            tenant_id=record.tenant_id,
            backup_id=record.backup_id,
            expected_version=record.expected_version,
            restore_request_sha256=record.restore_request_sha256,
            idempotency_key=record.idempotency_key,
            actor_id=record.actor_id,
            reason=record.reason,
            evidence_ref=record.evidence_ref,
        )
        != record.resolution_request_sha256
    ):
        raise BackupConflict("stored backup recovery request is invalid")
    return record


def recovery_request_sha256(
    *,
    tenant_id: str,
    backup_id: str,
    expected_version: int,
    restore_request_sha256: str,
    idempotency_key: str,
    actor_id: str,
    reason: str,
    evidence_ref: str,
) -> str:
    document = {
        "actor_id": actor_id,
        "backup_id": backup_id,
        "evidence_ref": evidence_ref,
        "expected_version": expected_version,
        "idempotency_key": idempotency_key,
        "reason": reason,
        "restore_request_sha256": restore_request_sha256,
        "tenant_id": tenant_id,
    }
    payload = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def recovery_audit_sha256(
    *,
    tenant_id: str,
    backup_id: str,
    expected_version: int,
    restore_request_sha256: str,
    resolution_request_sha256: str,
    idempotency_key: str,
    actor_id: str,
    reason: str,
    evidence_ref: str,
    resolution: str,
    resolved_at: int,
) -> str:
    document = {
        "actor_id": actor_id,
        "backup_id": backup_id,
        "evidence_ref": evidence_ref,
        "expected_version": expected_version,
        "idempotency_key": idempotency_key,
        "reason": reason,
        "resolution": resolution,
        "resolution_request_sha256": resolution_request_sha256,
        "resolved_at": resolved_at,
        "restore_request_sha256": restore_request_sha256,
        "tenant_id": tenant_id,
    }
    payload = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


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


def _require_identifier(value: object, field: str) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise BackupConflict(f"{field} is invalid")


def _require_sha256(value: object, field: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise BackupConflict(f"{field} is invalid")


__all__ = [
    "BACKUP_SCHEMA_STATEMENTS",
    "BackupConflict",
    "BackupRecord",
    "BackupRecoveryRecord",
    "BackupRepository",
    "deserialize_backup_record",
    "recovery_audit_sha256",
    "recovery_request_sha256",
    "serialize_backup_record",
    "validate_backup_record",
]
