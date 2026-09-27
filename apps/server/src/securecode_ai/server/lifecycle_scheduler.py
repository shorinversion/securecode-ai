"""Bounded scheduler for already-approved lifecycle deletions."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from .data_lifecycle import LifecycleLedger
from .data_lifecycle_models import (
    LifecycleConflict,
    require_identifier,
    require_sha256,
    require_version,
)

LIFECYCLE_SCHEDULER_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS lifecycle_scheduler_claims (
        tenant_id TEXT NOT NULL,
        deletion_id TEXT NOT NULL,
        expected_version INTEGER NOT NULL,
        owner_id TEXT NOT NULL,
        claim_token TEXT NOT NULL,
        lease_expires_at TEXT NOT NULL,
        outcome TEXT,
        resulting_version INTEGER,
        PRIMARY KEY (tenant_id, deletion_id)
    )""",
)
_CLAIM_PURGE_SAVEPOINT: Final = "securecode_scheduler_claim_purge"
_MAX_PURGE_ITEMS: Final = 256


@dataclass(frozen=True, slots=True)
class ScheduledDeletionResult:
    """Source-free result for one scheduler attempt."""

    deletion_id: str
    execution_identity_hash: str
    outcome: str
    resulting_version: int | None


class ApprovedDeletionScheduler:
    """Claim and execute approved deletions without granting approval itself."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        ledger: LifecycleLedger,
        *,
        owner_id: str,
        clock: Callable[[], datetime] | None = None,
        lease_seconds: int = 300,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        if type(ledger) is not LifecycleLedger:
            raise TypeError("ledger must be a LifecycleLedger")
        if getattr(ledger, "_connection", None) is not connection:
            raise ValueError("scheduler and lifecycle ledger must share a connection")
        require_identifier(owner_id, "owner_id")
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 3600:
            raise ValueError("scheduler lease is invalid")
        self._db = connection
        self._ledger = ledger
        self._owner_id = owner_id
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lease_seconds = lease_seconds
        self._initialize_schema()

    def run_once(
        self,
        *,
        tenant_id: str,
        max_items: int = 32,
    ) -> tuple[ScheduledDeletionResult, ...]:
        require_identifier(tenant_id, "tenant_id")
        if type(max_items) is not int or not 1 <= max_items <= 256:
            raise ValueError("scheduler batch size is invalid")
        self._ledger.require_residency(tenant_id)
        rows = self._db.execute(
            """SELECT d.deletion_id, d.identity_hash, d.version
               FROM lifecycle_deletions AS d
               JOIN lifecycle_repository_scopes AS s
                 ON s.deletion_id=d.deletion_id AND s.tenant_id=d.tenant_id
               WHERE d.tenant_id=?
                 AND d.approved_by IS NOT NULL
                 AND d.executed=0
                 AND d.legal_hold=0
               ORDER BY d.created_at, d.deletion_id
               LIMIT ?""",
            (tenant_id, max_items),
        ).fetchall()
        outcomes: list[ScheduledDeletionResult] = []
        for row in rows:
            deletion_id = row["deletion_id"]
            identity_hash = row["identity_hash"]
            version = row["version"]
            require_identifier(deletion_id, "deletion_id")
            require_sha256(identity_hash, "identity_hash")
            require_version(version)
            token = self._claim(
                tenant_id=tenant_id,
                deletion_id=deletion_id,
                expected_version=version,
            )
            if token is None:
                continue
            try:
                updated = self._ledger.execute(
                    deletion_id=deletion_id,
                    tenant_id=tenant_id,
                    identity_hash=identity_hash,
                    expected_version=version,
                    actor_id=self._owner_id,
                    idempotency_key=_idempotency_key(
                        tenant_id,
                        deletion_id,
                        identity_hash,
                        version,
                    ),
                )
            except (LifecycleConflict, TypeError, ValueError):
                self._finish_claim(
                    tenant_id=tenant_id,
                    deletion_id=deletion_id,
                    claim_token=token,
                    outcome="CONFLICT",
                    resulting_version=None,
                )
                outcomes.append(
                    ScheduledDeletionResult(
                        deletion_id=deletion_id,
                        execution_identity_hash=identity_hash,
                        outcome="CONFLICT",
                        resulting_version=None,
                    )
                )
                continue
            self._finish_claim(
                tenant_id=tenant_id,
                deletion_id=deletion_id,
                claim_token=token,
                outcome="EXECUTED",
                resulting_version=updated.version,
            )
            outcomes.append(
                ScheduledDeletionResult(
                    deletion_id=deletion_id,
                    execution_identity_hash=identity_hash,
                    outcome="EXECUTED",
                    resulting_version=updated.version,
                )
            )
        return tuple(outcomes)

    def purge_completed(
        self,
        *,
        tenant_id: str,
        max_items: int = 32,
    ) -> int:
        """Drop bounded operational claims after the durable deletion completed.

        The lifecycle deletion row and its idempotency record remain the source
        of truth for replay and audit.  Scheduler claims only coordinate an
        in-flight worker, so completed claims can be reclaimed safely.
        """

        require_identifier(tenant_id, "tenant_id")
        if type(max_items) is not int or not 1 <= max_items <= _MAX_PURGE_ITEMS:
            raise ValueError("scheduler cleanup batch is invalid")
        self._ledger.require_residency(tenant_id)
        cursor = self._db.cursor()
        active = False
        try:
            cursor.execute(f"SAVEPOINT {_CLAIM_PURGE_SAVEPOINT}")
            active = True
            changed = cursor.execute(
                """DELETE FROM lifecycle_scheduler_claims
                   WHERE rowid IN (
                       SELECT c.rowid
                       FROM lifecycle_scheduler_claims AS c
                       JOIN lifecycle_deletions AS d
                         ON d.tenant_id=c.tenant_id
                        AND d.deletion_id=c.deletion_id
                       WHERE c.tenant_id=?
                         AND d.executed=1
                       ORDER BY c.lease_expires_at, c.deletion_id
                       LIMIT ?
                   )""",
                (tenant_id, max_items),
            ).rowcount
            cursor.execute(f"RELEASE SAVEPOINT {_CLAIM_PURGE_SAVEPOINT}")
            active = False
            return changed
        except sqlite3.Error as error:
            if active:
                _rollback_savepoint(cursor, _CLAIM_PURGE_SAVEPOINT)
            raise LifecycleConflict("scheduler cleanup is unavailable") from error
        finally:
            cursor.close()

    def has_completed_claims(self, *, tenant_id: str) -> bool:
        require_identifier(tenant_id, "tenant_id")
        self._ledger.require_residency(tenant_id)
        try:
            row = self._db.execute(
                """SELECT 1
                   FROM lifecycle_scheduler_claims AS c
                   JOIN lifecycle_deletions AS d
                     ON d.tenant_id=c.tenant_id
                    AND d.deletion_id=c.deletion_id
                   WHERE c.tenant_id=?
                     AND d.executed=1
                   LIMIT 1""",
                (tenant_id,),
            ).fetchone()
        except sqlite3.Error as error:
            raise LifecycleConflict("scheduler cleanup state is unavailable") from error
        return row is not None

    def _initialize_schema(self) -> None:
        try:
            for statement in LIFECYCLE_SCHEDULER_SCHEMA_STATEMENTS:
                self._db.execute(statement)
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

    def _claim(
        self,
        *,
        tenant_id: str,
        deletion_id: str,
        expected_version: int,
    ) -> str | None:
        now = _utc(self._clock())
        expires_at = now + timedelta(seconds=self._lease_seconds)
        token = secrets.token_hex(32)
        cursor = self._db.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            row = cursor.execute(
                """SELECT expected_version, lease_expires_at, outcome
                   FROM lifecycle_scheduler_claims
                   WHERE tenant_id=? AND deletion_id=?""",
                (tenant_id, deletion_id),
            ).fetchone()
            if row is not None:
                stored_version = row["expected_version"]
                require_version(stored_version)
                lease_expires_at = row["lease_expires_at"]
                if type(lease_expires_at) is not str:
                    raise LifecycleConflict("scheduler lease is invalid")
                active = _parse_utc(lease_expires_at) > now
                outcome = row["outcome"]
                if outcome is not None and outcome not in {"CONFLICT", "EXECUTED"}:
                    raise LifecycleConflict("scheduler outcome is invalid")
                if outcome == "EXECUTED" or (active and stored_version == expected_version):
                    self._db.commit()
                    return None
            cursor.execute(
                """INSERT INTO lifecycle_scheduler_claims (
                       tenant_id, deletion_id, expected_version, owner_id,
                       claim_token, lease_expires_at, outcome, resulting_version
                   ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
                   ON CONFLICT (tenant_id, deletion_id) DO UPDATE SET
                       expected_version=excluded.expected_version,
                       owner_id=excluded.owner_id,
                       claim_token=excluded.claim_token,
                       lease_expires_at=excluded.lease_expires_at,
                       outcome=NULL,
                       resulting_version=NULL""",
                (
                    tenant_id,
                    deletion_id,
                    expected_version,
                    self._owner_id,
                    token,
                    expires_at.isoformat(),
                ),
            )
            self._db.commit()
            return token
        except Exception:
            self._db.rollback()
            raise
        finally:
            cursor.close()

    def _finish_claim(
        self,
        *,
        tenant_id: str,
        deletion_id: str,
        claim_token: str,
        outcome: str,
        resulting_version: int | None,
    ) -> None:
        if outcome not in {"CONFLICT", "EXECUTED"}:
            raise LifecycleConflict("scheduler outcome is invalid")
        if resulting_version is not None:
            require_version(resulting_version)
        cursor = self._db.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            cursor.execute(
                """UPDATE lifecycle_scheduler_claims
                   SET outcome=?, resulting_version=?, lease_expires_at=?
                   WHERE tenant_id=? AND deletion_id=?
                     AND owner_id=? AND claim_token=?""",
                (
                    outcome,
                    resulting_version,
                    _utc(self._clock()).isoformat(),
                    tenant_id,
                    deletion_id,
                    self._owner_id,
                    claim_token,
                ),
            )
            if cursor.rowcount != 1:
                raise LifecycleConflict("scheduler claim was superseded")
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise
        finally:
            cursor.close()


def _idempotency_key(
    tenant_id: str,
    deletion_id: str,
    identity_hash: str,
    version: int,
) -> str:
    material = "\x00".join((tenant_id, deletion_id, identity_hash, str(version))).encode("utf-8")
    return f"scheduler:{hashlib.sha256(material).hexdigest()}"


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise LifecycleConflict("scheduler clock returned an invalid timestamp")
    result = value.astimezone(UTC)
    if result.utcoffset() != timedelta(0):
        raise LifecycleConflict("scheduler clock returned an invalid timestamp")
    return result


def _parse_utc(value: str) -> datetime:
    if type(value) is not str:
        raise LifecycleConflict("scheduler lease is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise LifecycleConflict("scheduler lease is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise LifecycleConflict("scheduler lease is invalid")
    return parsed


def _rollback_savepoint(cursor: sqlite3.Cursor, name: str) -> None:
    try:
        cursor.execute(f"ROLLBACK TO SAVEPOINT {name}")
        cursor.execute(f"RELEASE SAVEPOINT {name}")
    except sqlite3.Error:
        pass


__all__ = [
    "LIFECYCLE_SCHEDULER_SCHEMA_STATEMENTS",
    "ApprovedDeletionScheduler",
    "ScheduledDeletionResult",
]
