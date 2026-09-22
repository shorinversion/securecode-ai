"""Durable retention, legal-hold and two-person deletion controls."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta

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


class LifecycleLedger:
    """SQLite-backed lifecycle ledger with tenant predicates and CAS updates."""

    def __init__(
        self,
        connection: sqlite3.Connection | None = None,
        *,
        storage: StorageExecutor | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._connection = connection or sqlite3.connect(":memory:")
        if not isinstance(self._connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._storage = storage
        self._clock = clock or (lambda: datetime.now(UTC))
        try:
            for statement in LIFECYCLE_SCHEMA:
                self._connection.execute(statement)
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    @classmethod
    def in_memory(cls, *, storage: StorageExecutor | None = None) -> LifecycleLedger:
        return cls(sqlite3.connect(":memory:"), storage=storage)

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
        row = self._connection.execute(
            """SELECT * FROM lifecycle_deletions
               WHERE tenant_id=? AND deletion_id=?""",
            (tenant_id, deletion_id),
        ).fetchone()
        if row is None:
            raise LifecycleConflict("deletion request is unknown")
        return _from_row(row)

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
                       version=version+1
                   WHERE tenant_id=? AND deletion_id=? AND version=?""",
                (
                    int(enabled),
                    actor_id,
                    reason_hash,
                    tenant_id,
                    deletion_id,
                    expected_version,
                ),
            )
            if cursor.rowcount != 1:
                raise LifecycleConflict("legal hold transition lost a race")
            updated = replace(value, legal_hold=enabled, version=expected_version + 1)
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
                return replay
            row = self._load_for_update(cursor, deletion_id, tenant_id)
            value = _from_row(row)
            if value.executed:
                raise LifecycleConflict("deletion is already executed")
            if (
                value.identity_hash != identity_hash
                or value.approved_by is None
                or value.legal_hold
                or value.version != expected_version
            ):
                raise LifecycleConflict("deletion cannot be executed")
            if self._storage is not None:
                self._storage.execute_tombstone(
                    tenant_id=tenant_id,
                    content_sha256=value.content_sha256,
                )
            now = _utc_text(self._clock())
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

    def receipt(self, *, tenant_id: str, deletion_id: str) -> DeletionReceipt:
        require_identifier(tenant_id, "tenant_id")
        require_identifier(deletion_id, "deletion_id")
        row = self._connection.execute(
            """SELECT * FROM lifecycle_deletions
               WHERE tenant_id=? AND deletion_id=?""",
            (tenant_id, deletion_id),
        ).fetchone()
        if row is None:
            raise LifecycleConflict("deletion request is unknown")
        state = (
            "EXECUTED"
            if row["executed"]
            else (
                "HELD"
                if row["legal_hold"]
                else ("APPROVED" if row["approved_by"] is not None else "REQUESTED")
            )
        )
        occurred_at = row["executed_at"] or row["approved_at"] or row["created_at"]
        actor = row["approved_by"] or row["requested_by"]
        return DeletionReceipt(
            deletion_id=row["deletion_id"],
            tenant_id=row["tenant_id"],
            content_sha256=row["content_sha256"],
            identity_hash=row["identity_hash"],
            state=state,
            version=row["version"],
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
        if created_at.tzinfo is None or now.tzinfo is None:
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


def _from_row(row: sqlite3.Row) -> DeletionRequest:
    return DeletionRequest(
        deletion_id=row["deletion_id"],
        tenant_id=row["tenant_id"],
        content_sha256=row["content_sha256"],
        data_class=row["data_class"],
        identity_hash=row["identity_hash"],
        requested_by=row["requested_by"],
        version=row["version"],
        approved_by=row["approved_by"],
        executed=bool(row["executed"]),
        legal_hold=bool(row["legal_hold"]),
    )


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
    if value.tzinfo is None:
        raise LifecycleConflict("clock returned a naive timestamp")
    return value.astimezone(UTC).isoformat()


__all__ = [
    "DeletionReceipt",
    "DeletionRequest",
    "LifecycleConflict",
    "LifecycleLedger",
    "RetentionProfile",
    "StorageExecutor",
]
