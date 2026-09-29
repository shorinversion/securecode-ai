"""Durable retention, legal-hold and two-person deletion controls."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Final

from .data_lifecycle_models import (
    DATA_CLASSES,
    LIFECYCLE_SCHEMA,
    DeletionReceipt,
    DeletionRequest,
    LifecycleConflict,
    RetentionProfile,
    StorageExecutor,
    require_identifier,
    require_sha256,
    require_version,
)
from .residency_registry import ResidencyConflict, ResidencyDecision, ResidencyGuard

_TERMINAL_RUN_STATES: Final = frozenset(
    {"SUCCEEDED", "FAILED", "INDETERMINATE", "CANCELLED", "SUPERSEDED"}
)
_RETENTION_METADATA_TABLES: Final = (
    "audit_runs",
    "findings",
    "finding_occurrences",
    "finding_decisions",
    "run_events",
    "workflow_checkpoints",
    "artifact_upload_authorizations",
    "run_artifacts",
)
_WORKER_PERSISTENCE_TABLES: Final = (
    "worker_sessions",
    "worker_session_idempotency",
    "worker_session_events",
    "worker_session_artifacts",
    "worker_run_queue",
    "worker_queue_idempotency",
)
_REDACTED_WORKER_ID: Final = "redacted-worker"


class LifecycleLedger:
    """SQLite-backed lifecycle ledger with tenant predicates and CAS updates."""

    def __init__(
        self,
        connection: sqlite3.Connection | None = None,
        *,
        storage: StorageExecutor | None = None,
        clock: Callable[[], datetime] | None = None,
        residency_guard: ResidencyGuard | None = None,
        residency_region: str | None = None,
    ) -> None:
        self._connection = connection or sqlite3.connect(":memory:")
        if not isinstance(self._connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._storage = storage
        self._clock = clock or (lambda: datetime.now(UTC))
        if (residency_guard is None) != (residency_region is None):
            raise TypeError("lifecycle residency configuration is incomplete")
        if residency_guard is not None and not callable(
            getattr(residency_guard, "require_region", None)
        ):
            raise TypeError("lifecycle residency guard is invalid")
        self._residency_guard = residency_guard
        self._residency_region = residency_region
        try:
            for statement in LIFECYCLE_SCHEMA:
                self._connection.execute(statement)
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    @classmethod
    def in_memory(cls, *, storage: StorageExecutor | None = None) -> LifecycleLedger:
        connection = sqlite3.connect(":memory:")
        # Lifecycle requests bind a deletion to its repository scope, which is
        # shared with the server schema rather than this module's local tables.
        # The in-memory factory must therefore create the same complete schema.
        from .migrations import apply_schema

        apply_schema(connection)
        return cls(connection, storage=storage)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        cursor = self._connection.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            yield cursor
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        finally:
            cursor.close()

    def request(
        self,
        value: DeletionRequest,
        *,
        repository_id: str,
        idempotency_key: str,
    ) -> DeletionRequest:
        require_identifier(repository_id, "repository_id")
        self._require_residency(value.tenant_id)
        return self._request(value, idempotency_key=idempotency_key, repository_id=repository_id)

    def _request(
        self,
        value: DeletionRequest,
        *,
        idempotency_key: str,
        repository_id: str | None,
    ) -> DeletionRequest:
        require_identifier(idempotency_key, "idempotency_key")
        if (
            value.version != 1
            or value.approved_by is not None
            or value.executed
            or value.legal_hold
        ):
            raise LifecycleConflict("new deletion must be unapproved and active")
        fingerprint = _request_hash(value)
        with self._transaction() as cursor:
            replay = self._replay(
                cursor,
                tenant_id=value.tenant_id,
                idempotency_key=idempotency_key,
                operation="request",
                request_sha256=fingerprint,
            )
            if replay is not None:
                if repository_id is not None:
                    self._bind_scope(cursor, replay, repository_id)
                return replay
            existing = cursor.execute(
                """SELECT * FROM lifecycle_deletions
                   WHERE tenant_id=? AND deletion_id=?""",
                (value.tenant_id, value.deletion_id),
            ).fetchone()
            if existing is not None:
                prior = _from_row(existing)
                if prior != value:
                    raise LifecycleConflict("deletion_id already has another request")
            else:
                now = _utc_text(self._clock())
                try:
                    cursor.execute(
                        """INSERT INTO lifecycle_deletions (
                            deletion_id, tenant_id, content_sha256, data_class,
                            identity_hash, requested_by, version, approved_by,
                            executed, legal_hold, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0, 0, ?)""",
                        (
                            value.deletion_id,
                            value.tenant_id,
                            value.content_sha256,
                            value.data_class,
                            value.identity_hash,
                            value.requested_by,
                            value.version,
                            now,
                        ),
                    )
                except sqlite3.IntegrityError as error:
                    raise LifecycleConflict("deletion request conflicts") from error
            if repository_id is not None:
                self._bind_scope(cursor, value, repository_id)
            self._remember(
                cursor,
                tenant_id=value.tenant_id,
                idempotency_key=idempotency_key,
                operation="request",
                request_sha256=fingerprint,
                deletion_id=value.deletion_id,
                resulting_version=1,
            )
            return value

    def get(self, *, tenant_id: str, deletion_id: str) -> DeletionRequest:
        require_identifier(tenant_id, "tenant_id")
        require_identifier(deletion_id, "deletion_id")
        self._require_residency(tenant_id)
        row = self._connection.execute(
            """SELECT * FROM lifecycle_deletions
               WHERE tenant_id=? AND deletion_id=?""",
            (tenant_id, deletion_id),
        ).fetchone()
        if row is None:
            raise LifecycleConflict("deletion request is unknown")
        return _from_row(row)

    def require_residency(self, tenant_id: str) -> None:
        """Check the configured placement policy before maintenance work."""

        require_identifier(tenant_id, "tenant_id")
        self._require_residency(tenant_id)

    def approve(
        self,
        *,
        deletion_id: str,
        actor_id: str,
        expected_version: int,
        tenant_id: str,
        idempotency_key: str | None = None,
    ) -> DeletionRequest:
        require_identifier(deletion_id, "deletion_id")
        require_identifier(actor_id, "actor_id")
        require_version(expected_version)
        require_identifier(tenant_id, "tenant_id")
        self._require_residency(tenant_id)
        with self._transaction() as cursor:
            row = self._load_for_update(cursor, deletion_id, tenant_id)
            value = _from_row(row)
            fingerprint = _operation_hash(
                "approve", value.tenant_id, deletion_id, actor_id, expected_version
            )
            replay = self._optional_replay(
                cursor, value.tenant_id, idempotency_key, "approve", fingerprint
            )
            if replay is not None:
                return replay
            if (
                value.requested_by == actor_id
                or value.legal_hold
                or value.approved_by is not None
                or value.executed
                or value.version != expected_version
            ):
                raise LifecycleConflict("deletion cannot be approved")
            now = _utc_text(self._clock())
            cursor.execute(
                """UPDATE lifecycle_deletions
                   SET approved_by=?, approved_at=?, version=version+1
                   WHERE deletion_id=? AND tenant_id=? AND version=?
                     AND approved_by IS NULL AND legal_hold=0 AND executed=0""",
                (actor_id, now, deletion_id, value.tenant_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise LifecycleConflict("deletion approval lost a race")
            updated = replace(value, approved_by=actor_id, version=expected_version + 1)
            self._optional_remember(
                cursor,
                value.tenant_id,
                idempotency_key,
                "approve",
                fingerprint,
                deletion_id,
                updated.version,
            )
            return updated

    def set_legal_hold(
        self,
        *,
        deletion_id: str,
        tenant_id: str,
        identity_hash: str,
        actor_id: str,
        enabled: bool,
        reason: str,
        expected_version: int,
        idempotency_key: str | None = None,
    ) -> DeletionRequest:
        require_identifier(deletion_id, "deletion_id")
        require_identifier(tenant_id, "tenant_id")
        require_identifier(actor_id, "actor_id")
        require_sha256(identity_hash, "identity_hash")
        require_version(expected_version)
        self._require_residency(tenant_id)
        if type(enabled) is not bool or not reason or len(reason) > 1024:
            raise LifecycleConflict("legal hold request is invalid")
        reason_hash = hashlib.sha256(reason.encode("utf-8")).hexdigest()
        fingerprint = _operation_hash(
            "hold",
            tenant_id,
            deletion_id,
            identity_hash,
            actor_id,
            enabled,
            reason_hash,
            expected_version,
        )
        with self._transaction() as cursor:
            replay = self._optional_replay(cursor, tenant_id, idempotency_key, "hold", fingerprint)
            if replay is not None:
                return replay
            row = self._load_for_update(cursor, deletion_id, tenant_id)
            value = _from_row(row)
            if (
                value.identity_hash != identity_hash
                or value.executed
                or value.version != expected_version
                or value.legal_hold == enabled
            ):
                raise LifecycleConflict("legal hold transition is invalid")
            cursor.execute(
                """UPDATE lifecycle_deletions
                   SET legal_hold=?, hold_actor=?, hold_reason_sha256=?,
                       approved_by=CASE WHEN ? THEN NULL ELSE approved_by END,
                       approved_at=CASE WHEN ? THEN NULL ELSE approved_at END,
                       version=version+1
                   WHERE tenant_id=? AND deletion_id=? AND version=?""",
                (
                    int(enabled),
                    actor_id,
                    reason_hash,
                    int(enabled),
                    int(enabled),
                    tenant_id,
                    deletion_id,
                    expected_version,
                ),
            )
            if cursor.rowcount != 1:
                raise LifecycleConflict("legal hold transition lost a race")
            updated = replace(
                value,
                legal_hold=enabled,
                approved_by=None if enabled else value.approved_by,
                version=expected_version + 1,
            )
            self._optional_remember(
                cursor,
                tenant_id,
                idempotency_key,
                "hold",
                fingerprint,
                deletion_id,
                updated.version,
            )
            return updated

    def execute(
        self,
        *,
        deletion_id: str,
        tenant_id: str,
        identity_hash: str,
        expected_version: int,
        actor_id: str = "lifecycle-executor",
        idempotency_key: str | None = None,
    ) -> DeletionRequest:
        require_identifier(deletion_id, "deletion_id")
        require_identifier(tenant_id, "tenant_id")
        require_identifier(actor_id, "actor_id")
        require_sha256(identity_hash, "identity_hash")
        require_version(expected_version)
        self._require_residency(tenant_id)
        if self._storage is None and self._requires_external_storage(deletion_id, tenant_id):
            raise LifecycleConflict("storage executor is unavailable")
        fingerprint = _operation_hash(
            "execute",
            tenant_id,
            deletion_id,
            identity_hash,
            actor_id,
            expected_version,
        )
        with self._transaction() as cursor:
            replay = self._optional_replay(
                cursor, tenant_id, idempotency_key, "execute", fingerprint
            )
            if replay is not None:
                if replay.executed and replay.data_class == "audit":
                    if replay.identity_hash != identity_hash:
                        raise LifecycleConflict("deletion identity does not match")
                    _reconcile_legacy_audit_deletion(cursor, replay)
                return replay
            row = self._load_for_update(cursor, deletion_id, tenant_id)
            value = _from_row(row)
            if value.executed:
                if value.data_class == "audit":
                    if value.identity_hash != identity_hash:
                        raise LifecycleConflict("deletion identity does not match")
                    _reconcile_legacy_audit_deletion(cursor, value)
                    return value
                raise LifecycleConflict("deletion is already executed")
            if (
                value.identity_hash != identity_hash
                or value.approved_by is None
                or value.legal_hold
                or value.version != expected_version
            ):
                raise LifecycleConflict("deletion cannot be executed")
            repository_id = self._scope_repository(
                cursor,
                tenant_id=tenant_id,
                deletion_id=deletion_id,
            )
            # The first residency check happens before the transaction is
            # acquired.  Re-check while the deletion row is locked so a
            # profile update between admission and this destructive step
            # cannot authorize a purge under stale placement policy.
            self._require_residency(tenant_id)
            now = _utc_text(self._clock())
            if value.data_class == "artifact":
                if self._storage is None:
                    raise LifecycleConflict("storage executor is unavailable")
                self._storage.execute_tombstone(
                    tenant_id=tenant_id,
                    content_sha256=value.content_sha256,
                    deletion_id=deletion_id,
                    repository_id=repository_id,
                    identity_hash=identity_hash,
                )
            elif value.data_class == "metadata":
                run_id = _retention_run_id(
                    cursor,
                    tenant_id=tenant_id,
                    repository_id=repository_id,
                    identity_hash=identity_hash,
                    data_class=value.data_class,
                    content_sha256=value.content_sha256,
                )
                _redact_run_metadata(cursor, tenant_id=tenant_id, run_id=run_id)
            elif value.data_class == "audit":
                run_id = _retention_run_id(
                    cursor,
                    tenant_id=tenant_id,
                    repository_id=repository_id,
                    identity_hash=identity_hash,
                    data_class=value.data_class,
                    content_sha256=value.content_sha256,
                )
                _erase_audit_run(
                    cursor,
                    tenant_id=tenant_id,
                    repository_id=repository_id,
                    run_id=run_id,
                    identity_hash=identity_hash,
                    deletion_id=deletion_id,
                    deleted_at=now,
                )
            else:
                raise LifecycleConflict("data_class is invalid")
            cursor.execute(
                """UPDATE lifecycle_deletions
                   SET executed=1, executed_at=?, version=version+1
                   WHERE tenant_id=? AND deletion_id=? AND version=?
                     AND approved_by IS NOT NULL AND legal_hold=0 AND executed=0""",
                (now, tenant_id, deletion_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise LifecycleConflict("deletion execution lost a race")
            updated = replace(value, executed=True, version=expected_version + 1)
            self._optional_remember(
                cursor,
                tenant_id,
                idempotency_key,
                "execute",
                fingerprint,
                deletion_id,
                updated.version,
            )
            return updated

    def reconcile_legacy_audit_deletions(
        self,
        *,
        tenant_id: str,
        max_items: int = 100,
    ) -> int:
        """Replay old logical-only audit deletions into durable tombstones."""

        require_identifier(tenant_id, "tenant_id")
        if type(max_items) is not int or not 1 <= max_items <= 1000:
            raise LifecycleConflict("legacy audit reconciliation limit is invalid")
        self._require_residency(tenant_id)
        reconciled = 0
        with self._transaction() as cursor:
            self._require_residency(tenant_id)
            rows = cursor.execute(
                """SELECT d.* FROM lifecycle_deletions AS d
                           WHERE d.tenant_id=? AND d.data_class='audit'
                             AND d.executed=1
                             AND NOT EXISTS (
                                 SELECT 1 FROM audit_retention_tombstones AS t
                                 WHERE t.tenant_id=d.tenant_id
                                   AND t.deletion_id=d.deletion_id
                             )
                           ORDER BY d.deletion_id
                           LIMIT ?""",
                (tenant_id, max_items),
            ).fetchall()
            for row in rows:
                value = _from_row(row)
                if _reconcile_legacy_audit_deletion(cursor, value):
                    reconciled += 1
        return reconciled

    def has_unreconciled_legacy_audit_deletions(self, *, tenant_id: str) -> bool:
        """Report whether bounded maintenance still has audit rows to reconcile."""

        require_identifier(tenant_id, "tenant_id")
        self._require_residency(tenant_id)
        try:
            row = self._connection.execute(
                """SELECT 1 FROM lifecycle_deletions AS d
                   WHERE d.tenant_id=? AND d.data_class='audit' AND d.executed=1
                     AND NOT EXISTS (
                         SELECT 1 FROM audit_retention_tombstones AS t
                         WHERE t.tenant_id=d.tenant_id
                           AND t.deletion_id=d.deletion_id
                     )
                   LIMIT 1""",
                (tenant_id,),
            ).fetchone()
        except sqlite3.Error as error:
            raise LifecycleConflict("legacy audit reconciliation state is unavailable") from error
        return row is not None

    def _requires_external_storage(self, deletion_id: str, tenant_id: str) -> bool:
        row = self._connection.execute(
            """SELECT data_class FROM lifecycle_deletions
               WHERE tenant_id=? AND deletion_id=?""",
            (tenant_id, deletion_id),
        ).fetchone()
        return row is None or row[0] == "artifact"

    def _require_residency(self, tenant_id: str) -> None:
        guard = self._residency_guard
        if guard is None:
            return
        region = self._residency_region
        if region is None:
            raise LifecycleConflict("lifecycle residency configuration is incomplete")
        try:
            decision = guard.require_region(tenant_id=tenant_id, region=region)
        except ResidencyConflict as error:
            raise LifecycleConflict("lifecycle residency policy denied") from error
        except Exception as error:
            raise LifecycleConflict("lifecycle residency check failed") from error
        if (
            type(decision) is not ResidencyDecision
            or decision.tenant_id != tenant_id
            or decision.source_region != region
            or decision.destination_region != region
            or not decision.same_region
        ):
            raise LifecycleConflict("lifecycle residency decision is invalid")

    @staticmethod
    def _scope_repository(
        cursor: sqlite3.Cursor,
        *,
        tenant_id: str,
        deletion_id: str,
    ) -> str:
        try:
            row = cursor.execute(
                """SELECT repository_id FROM lifecycle_repository_scopes
                   WHERE tenant_id=? AND deletion_id=?""",
                (tenant_id, deletion_id),
            ).fetchone()
        except sqlite3.Error as error:
            raise LifecycleConflict("deletion scope is unavailable") from error
        if row is None or type(row[0]) is not str:
            raise LifecycleConflict("deletion scope is unavailable")
        require_identifier(row[0], "repository_id")
        return row[0]

    def receipt(self, *, tenant_id: str, deletion_id: str) -> DeletionReceipt:
        require_identifier(tenant_id, "tenant_id")
        require_identifier(deletion_id, "deletion_id")
        self._require_residency(tenant_id)
        row = self._connection.execute(
            """SELECT * FROM lifecycle_deletions
               WHERE tenant_id=? AND deletion_id=?""",
            (tenant_id, deletion_id),
        ).fetchone()
        if row is None:
            raise LifecycleConflict("deletion request is unknown")
        value = _from_row(row)
        state = (
            "EXECUTED"
            if value.executed
            else (
                "HELD"
                if value.legal_hold
                else ("APPROVED" if value.approved_by is not None else "REQUESTED")
            )
        )
        occurred_at = row["executed_at"] or row["approved_at"] or row["created_at"]
        if type(occurred_at) is not str or not occurred_at:
            raise LifecycleConflict("deletion receipt is inconsistent")
        actor = row["hold_actor"] if state == "HELD" else (value.approved_by or value.requested_by)
        if type(actor) is not str:
            raise LifecycleConflict("deletion receipt is inconsistent")
        return DeletionReceipt(
            deletion_id=value.deletion_id,
            tenant_id=value.tenant_id,
            content_sha256=value.content_sha256,
            identity_hash=value.identity_hash,
            state=state,
            version=value.version,
            occurred_at=occurred_at,
            actor_id_hash=hashlib.sha256(actor.encode("utf-8")).hexdigest(),
        )

    def expired(
        self,
        *,
        profile: RetentionProfile,
        created_at: datetime,
        now: datetime,
        data_class: str,
        legal_hold: bool = False,
    ) -> bool:
        if data_class not in DATA_CLASSES:
            raise LifecycleConflict("data_class is invalid")
        if not _aware_datetime(created_at) or not _aware_datetime(now):
            raise LifecycleConflict("retention timestamps must be timezone-aware")
        if type(legal_hold) is not bool:
            raise LifecycleConflict("legal_hold is invalid")
        if legal_hold:
            return False
        days = {
            "metadata": profile.metadata_days,
            "artifact": profile.artifact_days,
            "audit": profile.audit_days,
        }[data_class]
        return created_at.astimezone(UTC) + timedelta(days=days) <= now.astimezone(UTC)

    @staticmethod
    def _bind_scope(
        cursor: sqlite3.Cursor,
        value: DeletionRequest,
        repository_id: str,
    ) -> None:
        row = cursor.execute(
            """SELECT repository_id FROM lifecycle_repository_scopes
               WHERE tenant_id=? AND deletion_id=?""",
            (value.tenant_id, value.deletion_id),
        ).fetchone()
        if row is not None:
            if str(row["repository_id"]) != repository_id:
                raise LifecycleConflict("deletion scope conflicts")
            return
        cursor.execute(
            """INSERT INTO lifecycle_repository_scopes (
                   deletion_id, tenant_id, repository_id
               ) VALUES (?, ?, ?)""",
            (value.deletion_id, value.tenant_id, repository_id),
        )

    @staticmethod
    def _load_for_update(cursor: sqlite3.Cursor, deletion_id: str, tenant_id: str) -> sqlite3.Row:
        row: sqlite3.Row | None = cursor.execute(
            """SELECT * FROM lifecycle_deletions
               WHERE tenant_id=? AND deletion_id=?""",
            (tenant_id, deletion_id),
        ).fetchone()
        if row is None:
            raise LifecycleConflict("deletion request is unknown")
        return row

    @staticmethod
    def _replay(
        cursor: sqlite3.Cursor,
        *,
        tenant_id: str,
        idempotency_key: str,
        operation: str,
        request_sha256: str,
    ) -> DeletionRequest | None:
        row = cursor.execute(
            """SELECT operation, request_sha256, deletion_id
               FROM lifecycle_idempotency
               WHERE tenant_id=? AND idempotency_key=?""",
            (tenant_id, idempotency_key),
        ).fetchone()
        if row is None:
            return None
        if (row["operation"], row["request_sha256"]) != (
            operation,
            request_sha256,
        ):
            raise LifecycleConflict("idempotency key has another request")
        value = cursor.execute(
            """SELECT * FROM lifecycle_deletions
               WHERE tenant_id=? AND deletion_id=?""",
            (tenant_id, row["deletion_id"]),
        ).fetchone()
        if value is None:
            raise LifecycleConflict("idempotency record is inconsistent")
        return _from_row(value)

    @classmethod
    def _optional_replay(
        cls,
        cursor: sqlite3.Cursor,
        tenant_id: str,
        key: str | None,
        operation: str,
        fingerprint: str,
    ) -> DeletionRequest | None:
        if key is None:
            return None
        require_identifier(key, "idempotency_key")
        return cls._replay(
            cursor,
            tenant_id=tenant_id,
            idempotency_key=key,
            operation=operation,
            request_sha256=fingerprint,
        )

    @staticmethod
    def _remember(
        cursor: sqlite3.Cursor,
        *,
        tenant_id: str,
        idempotency_key: str,
        operation: str,
        request_sha256: str,
        deletion_id: str,
        resulting_version: int,
    ) -> None:
        cursor.execute(
            """INSERT INTO lifecycle_idempotency (
                tenant_id, idempotency_key, operation, request_sha256,
                deletion_id, resulting_version
            ) VALUES (?, ?, ?, ?, ?, ?)""",
            (
                tenant_id,
                idempotency_key,
                operation,
                request_sha256,
                deletion_id,
                resulting_version,
            ),
        )

    @classmethod
    def _optional_remember(
        cls,
        cursor: sqlite3.Cursor,
        tenant_id: str,
        key: str | None,
        operation: str,
        fingerprint: str,
        deletion_id: str,
        version: int,
    ) -> None:
        if key is None:
            return
        cls._remember(
            cursor,
            tenant_id=tenant_id,
            idempotency_key=key,
            operation=operation,
            request_sha256=fingerprint,
            deletion_id=deletion_id,
            resulting_version=version,
        )


def retention_content_sha256(
    *,
    data_class: str,
    tenant_id: str,
    repository_id: str,
    run_id: str,
    identity_hash: str,
) -> str:
    """Derive the stable content identity for a run-level retention target."""

    if data_class not in {"metadata", "audit"}:
        raise LifecycleConflict("retention data class is invalid")
    require_identifier(tenant_id, "tenant_id")
    require_identifier(repository_id, "repository_id")
    require_identifier(run_id, "run_id")
    require_sha256(identity_hash, "identity_hash")
    return hashlib.sha256(
        json.dumps(
            {
                "data_class": data_class,
                "identity_hash": identity_hash,
                "repository_id": repository_id,
                "run_id": run_id,
                "tenant_id": tenant_id,
                "version": 1,
            },
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


def _retention_run_id(
    cursor: sqlite3.Cursor,
    *,
    tenant_id: str,
    repository_id: str,
    identity_hash: str,
    data_class: str,
    content_sha256: str,
) -> str:
    try:
        rows = cursor.execute(
            """SELECT run_id, repository_id, execution_identity_hash, state
               FROM audit_runs
               WHERE tenant_id=? AND repository_id=?
                 AND execution_identity_hash=?
               ORDER BY run_id""",
            (tenant_id, repository_id, identity_hash),
        ).fetchall()
    except sqlite3.Error as error:
        raise LifecycleConflict("retention run state is unavailable") from error
    matching_run_ids: list[str] = []
    for row in rows:
        run_id = row[0]
        stored_repository = row[1]
        stored_identity = row[2]
        state = row[3]
        if (
            type(run_id) is not str
            or type(stored_repository) is not str
            or type(stored_identity) is not str
            or type(state) is not str
        ):
            raise LifecycleConflict("retention run state is invalid")
        require_identifier(run_id, "run_id")
        require_identifier(stored_repository, "repository_id")
        require_sha256(stored_identity, "identity_hash")
        if stored_repository != repository_id or stored_identity != identity_hash:
            raise LifecycleConflict("retention run identity changed")
        expected_content = retention_content_sha256(
            data_class=data_class,
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            identity_hash=identity_hash,
        )
        if expected_content == content_sha256:
            if state not in _TERMINAL_RUN_STATES:
                raise LifecycleConflict("retention run is not terminal")
            matching_run_ids.append(run_id)
    if len(matching_run_ids) != 1:
        if not matching_run_ids:
            raise LifecycleConflict("retention target identity changed")
        raise LifecycleConflict("retention run target is ambiguous")
    return matching_run_ids[0]


def _redact_run_metadata(cursor: sqlite3.Cursor, *, tenant_id: str, run_id: str) -> None:
    for table in _RETENTION_METADATA_TABLES:
        if not _table_exists(cursor, table):
            raise LifecycleConflict("retention metadata schema is incomplete")
    statements = (
        "UPDATE audit_runs SET metadata_json='{}' WHERE tenant_id=? AND run_id=?",
        "UPDATE findings SET metadata_json='{}' WHERE tenant_id=? AND run_id=?",
        "UPDATE finding_occurrences SET metadata_json='{}' WHERE tenant_id=? AND run_id=?",
        "UPDATE finding_decisions SET metadata_json='{}' WHERE tenant_id=? AND run_id=?",
        "UPDATE run_events SET metadata_json='{}' WHERE tenant_id=? AND run_id=?",
        "UPDATE workflow_checkpoints SET metadata_json='{}' WHERE tenant_id=? AND run_id=?",
        "UPDATE artifact_upload_authorizations SET headers_json='{}' WHERE tenant_id=? AND run_id=?",
        "UPDATE run_artifacts SET metadata_json='{}' WHERE tenant_id=? AND run_id=?",
    )
    for statement in statements:
        cursor.execute(statement, (tenant_id, run_id))
    _redact_worker_persistence(cursor, tenant_id=tenant_id, run_id=run_id)


def _erase_audit_run(
    cursor: sqlite3.Cursor,
    *,
    tenant_id: str,
    repository_id: str,
    run_id: str,
    identity_hash: str,
    deletion_id: str,
    deleted_at: str,
) -> None:
    # Import lazily because audit_log imports retention_content_sha256 from
    # this module.  The call executes inside the lifecycle transaction, so the
    # tombstone and deletion state commit or roll back together.
    from .audit_log import AuditConflict, erase_audit_run

    try:
        erase_audit_run(
            cursor,
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            identity_hash=identity_hash,
            deletion_id=deletion_id,
            deleted_at=deleted_at,
        )
    except AuditConflict as error:
        raise LifecycleConflict("audit retention erasure failed") from error


def _reconcile_legacy_audit_deletion(
    cursor: sqlite3.Cursor,
    value: DeletionRequest,
) -> bool:
    """Finish an executed audit deletion with logical row deletion.

    A durable tombstone records the verified binding after the rows are removed.
    """

    if value.data_class != "audit" or not value.executed:
        return False
    row = cursor.execute(
        """SELECT executed_at FROM lifecycle_deletions
                   WHERE tenant_id=? AND deletion_id=?""",
        (value.tenant_id, value.deletion_id),
    ).fetchone()
    if row is None or type(row[0]) is not str:
        raise LifecycleConflict("lifecycle deletion state is unavailable")
    executed_at = row[0]
    _require_persisted_utc(executed_at)
    repository_id = LifecycleLedger._scope_repository(
        cursor,
        tenant_id=value.tenant_id,
        deletion_id=value.deletion_id,
    )
    run_id = _retention_run_id(
        cursor,
        tenant_id=value.tenant_id,
        repository_id=repository_id,
        identity_hash=value.identity_hash,
        data_class=value.data_class,
        content_sha256=value.content_sha256,
    )
    if not _table_exists(cursor, "audit_retention_tombstones"):
        raise LifecycleConflict("audit retention schema is incomplete")
    marker = cursor.execute(
        """SELECT tenant_id, run_id, repository_id,
                          execution_identity_hash, deletion_id, deleted_at,
                          head_sequence, head_hash, tombstone_hash
                     FROM audit_retention_tombstones
                    WHERE tenant_id=? AND run_id=?""",
        (value.tenant_id, run_id),
    ).fetchone()
    if marker is not None:
        from .audit_log import AuditConflict, _validate_retention_tombstone

        try:
            marker_deletion_id = _validate_retention_tombstone(
                tuple(marker),
                tenant_id=value.tenant_id,
                repository_id=repository_id,
                run_id=run_id,
                identity_hash=value.identity_hash,
            )
        except AuditConflict as error:
            raise LifecycleConflict("audit retention state is invalid") from error
        if marker_deletion_id != value.deletion_id:
            raise LifecycleConflict("audit retention state is invalid")
        remaining = cursor.execute(
            """SELECT
                         (SELECT COUNT(*) FROM audit_chain_events
                           WHERE tenant_id=? AND run_id=?),
                         (SELECT COUNT(*) FROM audit_chain_idempotency
                           WHERE tenant_id=? AND run_id=?)""",
            (value.tenant_id, run_id, value.tenant_id, run_id),
        ).fetchone()
        if remaining is None or any(type(item) is not int for item in remaining):
            raise LifecycleConflict("audit retention state is invalid")
        if any(item != 0 for item in remaining):
            raise LifecycleConflict("audit retention state is inconsistent")
        return False
    _erase_audit_run(
        cursor,
        tenant_id=value.tenant_id,
        repository_id=repository_id,
        run_id=run_id,
        identity_hash=value.identity_hash,
        deletion_id=value.deletion_id,
        deleted_at=executed_at,
    )
    return True


def _redact_worker_persistence(
    cursor: sqlite3.Cursor,
    *,
    tenant_id: str,
    run_id: str,
) -> None:
    """Redact only terminal worker fields that do not carry replay identity."""

    tables = {table: _table_exists(cursor, table) for table in _WORKER_PERSISTENCE_TABLES}
    if tables["worker_sessions"]:
        active_session = cursor.execute(
            """SELECT 1 FROM worker_sessions
               WHERE tenant_id=? AND run_id=? AND terminal=0 LIMIT 1""",
            (tenant_id, run_id),
        ).fetchone()
        if active_session is not None:
            raise LifecycleConflict("worker session is not terminal")
        # The live server route uses worker_run_queue.  Legacy worker_sessions
        # has no database consumer, so its direct worker principal can be
        # redacted while session, version, command and outcome remain intact.
        cursor.execute(
            """UPDATE worker_sessions
               SET worker_id=?
               WHERE tenant_id=? AND run_id=? AND terminal=1""",
            (_REDACTED_WORKER_ID, tenant_id, run_id),
        )

    if tables["worker_run_queue"]:
        queue = cursor.execute(
            """SELECT terminal FROM worker_run_queue
               WHERE tenant_id=? AND run_id=?""",
            (tenant_id, run_id),
        ).fetchone()
        if queue is not None and queue["terminal"] != 1:
            raise LifecycleConflict("worker queue state is not terminal")
        # Terminal completion already releases the lease.  Clearing a stale
        # timestamp is safe, while lease owner and identity JSON are required
        # by terminal replay and evidence verification and remain unchanged.
        cursor.execute(
            """UPDATE worker_run_queue
               SET lease_expires_at=NULL
               WHERE tenant_id=? AND run_id=? AND terminal=1""",
            (tenant_id, run_id),
        )

    # Idempotency keys, request hashes, response JSON, event identities and
    # content hashes are retained to preserve replay and immutable history.
    # Their child rows are tenant/session scoped and require no rewrite.


def _table_exists(cursor: sqlite3.Cursor, name: str) -> bool:
    row = cursor.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return row is not None


def _from_row(row: sqlite3.Row) -> DeletionRequest:
    executed = _persisted_flag(row["executed"], "executed")
    legal_hold = _persisted_flag(row["legal_hold"], "legal_hold")
    approved_by = row["approved_by"]
    approved_at = row["approved_at"]
    executed_at = row["executed_at"]
    _require_persisted_utc(row["created_at"])
    if approved_at is not None:
        _require_persisted_utc(approved_at)
    if executed_at is not None:
        _require_persisted_utc(executed_at)
    if (approved_by is None) != (approved_at is None):
        raise LifecycleConflict("lifecycle state is inconsistent")
    if (executed_at is None) != (not executed):
        raise LifecycleConflict("lifecycle state is inconsistent")
    if legal_hold and (approved_by is not None or approved_at is not None):
        raise LifecycleConflict("lifecycle state is inconsistent")
    if executed and (legal_hold or approved_by is None):
        raise LifecycleConflict("lifecycle state is inconsistent")
    return DeletionRequest(
        deletion_id=row["deletion_id"],
        tenant_id=row["tenant_id"],
        content_sha256=row["content_sha256"],
        data_class=row["data_class"],
        identity_hash=row["identity_hash"],
        requested_by=row["requested_by"],
        version=row["version"],
        approved_by=approved_by,
        executed=executed,
        legal_hold=legal_hold,
    )


def _persisted_flag(value: object, field: str) -> bool:
    if type(value) is not int or value not in (0, 1):
        raise LifecycleConflict(f"{field} is invalid")
    return value == 1


def _require_persisted_utc(value: object) -> None:
    if type(value) is not str:
        raise LifecycleConflict("lifecycle timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise LifecycleConflict("lifecycle timestamp is invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise LifecycleConflict("lifecycle timestamp is invalid")


def _request_hash(value: DeletionRequest) -> str:
    return _operation_hash(
        value.deletion_id,
        value.tenant_id,
        value.content_sha256,
        value.data_class,
        value.identity_hash,
        value.requested_by,
        value.version,
        value.approved_by,
        value.executed,
        value.legal_hold,
    )


def _operation_hash(*values: object) -> str:
    payload = json.dumps(
        values,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _utc_text(value: datetime) -> str:
    if not _aware_datetime(value):
        raise LifecycleConflict("clock returned a naive timestamp")
    return value.astimezone(UTC).isoformat()


def _aware_datetime(value: object) -> bool:
    return isinstance(value, datetime) and value.utcoffset() is not None


__all__ = [
    "DeletionReceipt",
    "DeletionRequest",
    "LifecycleConflict",
    "LifecycleLedger",
    "RetentionProfile",
    "StorageExecutor",
    "retention_content_sha256",
]
