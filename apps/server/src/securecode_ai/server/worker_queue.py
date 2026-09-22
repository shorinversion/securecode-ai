"""Durable queue claims for connected workers."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta

from securecode_ai.contracts import RunExecutionIdentity

from .ports import ServiceRequest, ServiceResponse, ServiceUnavailableError
from .worker_findings import WorkerFindingRecord
from .worker_findings_store import complete_worker_run
from .worker_queue_models import (
    TERMINAL_STATES as _TERMINAL_STATES,
)
from .worker_queue_models import (
    WorkerQueueConflict,
    WorkerQueueLease,
)
from .worker_queue_models import (
    canonical as _canonical,
)
from .worker_queue_models import (
    canonical_sha256 as _canonical_sha256,
)
from .worker_queue_models import (
    command as _command,
)
from .worker_queue_models import (
    idempotency_key as _idempotency_key,
)
from .worker_queue_models import (
    identifier as _identifier,
)
from .worker_queue_models import (
    identity as _identity,
)
from .worker_queue_models import (
    identity_document as _identity_document,
)
from .worker_queue_models import (
    lease_arguments as _lease_arguments,
)
from .worker_queue_models import (
    lease_document as _lease_document,
)
from .worker_queue_models import (
    replayed_lease as _replayed_lease,
)
from .worker_queue_models import (
    session_id as _session_id,
)
from .worker_queue_models import (
    timestamp as _timestamp,
)
from .worker_queue_models import (
    utc as _utc,
)
from .worker_resource_models import WorkerResourceSettlement


class SqliteWorkerQueue:
    """Claim pending audit runs with restart-safe leases and replay."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        lease_seconds: int = 30,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if type(lease_seconds) is not int or not 5 <= lease_seconds <= 3600:
            raise ValueError("worker lease duration is invalid")
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._lease_seconds = lease_seconds
        self._now = now

    def enqueue(
        self,
        *,
        tenant_id: str,
        run_id: str,
        execution_identity: RunExecutionIdentity,
    ) -> None:
        _identifier(tenant_id)
        _identifier(run_id)
        identity = _identity(execution_identity)
        revision = identity.repository_revision
        if revision.tenant_id != tenant_id:
            raise WorkerQueueConflict()
        identity_json = _canonical(identity.model_dump(mode="json"))
        cursor = self._connection.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            run = cursor.execute(
                """SELECT repository_id, execution_identity_hash
                   FROM audit_runs WHERE tenant_id=? AND run_id=?""",
                (tenant_id, run_id),
            ).fetchone()
            if run is None or (
                run["repository_id"],
                run["execution_identity_hash"],
            ) != (revision.repository_id, identity.execution_identity_hash):
                raise WorkerQueueConflict()
            existing = cursor.execute(
                """SELECT execution_identity_json FROM worker_run_queue
                   WHERE tenant_id=? AND run_id=?""",
                (tenant_id, run_id),
            ).fetchone()
            if existing is None:
                cursor.execute(
                    """INSERT INTO worker_run_queue
                       (tenant_id, run_id, execution_identity_json, lease_owner,
                        lease_expires_at, session_id, version, terminal, outcome)
                       VALUES (?, ?, ?, NULL, NULL, NULL, 0, 0, NULL)""",
                    (tenant_id, run_id, identity_json),
                )
            elif existing["execution_identity_json"] != identity_json:
                raise WorkerQueueConflict()
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        finally:
            cursor.close()

    def claim(
        self,
        *,
        tenant_id: str,
        worker_id: str,
        idempotency_key: str,
        allowed_repository_ids: frozenset[str],
        requested_run_id: str | None = None,
    ) -> WorkerQueueLease | None:
        _identifier(tenant_id)
        _identifier(worker_id)
        _idempotency_key(idempotency_key)
        if not isinstance(allowed_repository_ids, frozenset) or not allowed_repository_ids:
            raise WorkerQueueConflict()
        for repository_id in allowed_repository_ids:
            _identifier(repository_id)
        if requested_run_id is not None:
            _identifier(requested_run_id)
        request_sha256 = _canonical_sha256(
            {
                "worker_id": worker_id,
                "requested_run_id": requested_run_id,
                "allowed_repository_ids": sorted(allowed_repository_ids),
                "lease_seconds": self._lease_seconds,
            }
        )
        cursor = self._connection.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            replay = cursor.execute(
                """SELECT request_sha256, response_json
                   FROM worker_queue_idempotency
                   WHERE tenant_id=? AND idempotency_key=?""",
                (tenant_id, idempotency_key),
            ).fetchone()
            if replay is not None:
                if replay["request_sha256"] != request_sha256:
                    raise WorkerQueueConflict()
                self._connection.commit()
                return _replayed_lease(replay["response_json"], self._lease_seconds)

            now = _utc(self._now())
            repositories = tuple(sorted(allowed_repository_ids))
            parameters: list[object] = [tenant_id, now.isoformat(), *repositories]
            repository_clause = ",".join("?" for _ in repositories)
            requested_clause = ""
            if requested_run_id is not None:
                requested_clause = " AND q.run_id=?"
                parameters.append(requested_run_id)
            query = (
                """SELECT q.*, r.state, r.created_at,
                          r.execution_identity_hash
                   FROM worker_run_queue AS q
                   JOIN audit_runs AS r
                     ON r.tenant_id=q.tenant_id AND r.run_id=q.run_id
                   WHERE q.tenant_id=? AND q.terminal=0
                     AND (q.lease_expires_at IS NULL OR q.lease_expires_at<=?)
                     AND r.repository_id IN ("""
                + repository_clause
                + """)
                     AND r.state IN
                         ('REQUESTED','RUNNING','CANCEL_REQUESTED','SUPERSEDE_REQUESTED')"""
                + requested_clause
                + " ORDER BY r.created_at ASC, q.run_id ASC LIMIT 1"
            )
            row = cursor.execute(query, tuple(parameters)).fetchone()
            if row is None:
                cursor.execute(
                    """INSERT INTO worker_queue_idempotency
                       (tenant_id, idempotency_key, request_sha256, response_json)
                       VALUES (?, ?, ?, 'null')""",
                    (tenant_id, idempotency_key, request_sha256),
                )
                self._connection.commit()
                return None

            identity = _identity_document(row["execution_identity_json"])
            if identity.execution_identity_hash != row["execution_identity_hash"]:
                raise WorkerQueueConflict()
            next_version = int(row["version"]) + 1
            session_id = _session_id(
                tenant_id, row["run_id"], worker_id, idempotency_key, next_version
            )
            expires = now + timedelta(seconds=self._lease_seconds)
            cursor.execute(
                """UPDATE worker_run_queue
                   SET lease_owner=?, lease_expires_at=?, session_id=?, version=?
                   WHERE tenant_id=? AND run_id=? AND version=? AND terminal=0""",
                (
                    worker_id,
                    expires.isoformat(),
                    session_id,
                    next_version,
                    tenant_id,
                    row["run_id"],
                    row["version"],
                ),
            )
            if cursor.rowcount != 1:
                raise WorkerQueueConflict()
            if row["state"] == "REQUESTED":
                cursor.execute(
                    """UPDATE audit_runs
                       SET state='RUNNING', version=version+1, updated_at=?
                       WHERE tenant_id=? AND run_id=? AND state='REQUESTED'""",
                    (now.isoformat(), tenant_id, row["run_id"]),
                )
                if cursor.rowcount != 1:
                    raise WorkerQueueConflict()
            lease = WorkerQueueLease(
                tenant_id=tenant_id,
                run_id=row["run_id"],
                worker_id=worker_id,
                session_id=session_id,
                version=next_version,
                lease_seconds=self._lease_seconds,
                lease_expires_at=expires,
                command=_command(row["state"]),
                execution_identity=identity,
            )
            cursor.execute(
                """INSERT INTO worker_queue_idempotency
                   (tenant_id, idempotency_key, request_sha256, response_json)
                   VALUES (?, ?, ?, ?)""",
                (
                    tenant_id,
                    idempotency_key,
                    request_sha256,
                    _canonical(_lease_document(lease)),
                ),
            )
            self._connection.commit()
            return lease
        except Exception:
            self._connection.rollback()
            raise
        finally:
            cursor.close()

    def heartbeat(
        self,
        *,
        tenant_id: str,
        session_id: str,
        worker_id: str,
        execution_identity_hash: str,
        run_id: str,
        expected_version: int,
    ) -> WorkerQueueLease:
        return self.advance(
            tenant_id=tenant_id,
            session_id=session_id,
            worker_id=worker_id,
            execution_identity_hash=execution_identity_hash,
            run_id=run_id,
            expected_version=expected_version,
            renew_lease=True,
        )

    def advance(
        self,
        *,
        tenant_id: str,
        session_id: str,
        worker_id: str,
        execution_identity_hash: str,
        run_id: str,
        expected_version: int,
        renew_lease: bool = False,
        events: tuple[Mapping[str, object], ...] = (),
        artifact: Mapping[str, object] | None = None,
    ) -> WorkerQueueLease:
        _lease_arguments(
            tenant_id,
            session_id,
            worker_id,
            execution_identity_hash,
            expected_version,
        )
        cursor = self._connection.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            row = _current(cursor, tenant_id, session_id)
            now = _utc(self._now())
            _require_current(
                row,
                worker_id=worker_id,
                identity_hash=execution_identity_hash,
                run_id=run_id,
                expected_version=expected_version,
                now=now,
            )
            next_version = expected_version + 1
            expires = (
                now + timedelta(seconds=self._lease_seconds)
                if renew_lease
                else _timestamp(row["lease_expires_at"])
            )
            cursor.execute(
                """UPDATE worker_run_queue
                   SET version=?, lease_expires_at=?
                   WHERE tenant_id=? AND session_id=? AND version=? AND terminal=0""",
                (
                    next_version,
                    expires.isoformat(),
                    tenant_id,
                    session_id,
                    expected_version,
                ),
            )
            if cursor.rowcount != 1:
                raise WorkerQueueConflict()
            next_sequence = cursor.execute(
                """SELECT COALESCE(MAX(sequence), 0) + 1 FROM run_events
                   WHERE tenant_id=? AND run_id=?""",
                (tenant_id, run_id),
            ).fetchone()[0]
            for event in events:
                cursor.execute(
                    """INSERT INTO run_events
                       (tenant_id, run_id, sequence, event_id, metadata_json)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        tenant_id,
                        run_id,
                        next_sequence,
                        event["event_id"],
                        _canonical(
                            {
                                "event_hash": event["event_hash"],
                                "kind": event["kind"],
                                "worker_sequence": event["sequence"],
                            }
                        ),
                    ),
                )
                next_sequence += 1
            if artifact is not None:
                cursor.execute(
                    """INSERT INTO run_artifacts
                       (tenant_id, run_id, content_sha256, authorization_id,
                        purpose, metadata_json, committed_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        tenant_id,
                        run_id,
                        artifact["content_sha256"],
                        artifact["authorization_id"],
                        artifact["purpose"],
                        _canonical(dict(artifact)),
                        now.isoformat(),
                    ),
                )
            updated = _current(cursor, tenant_id, session_id)
            self._connection.commit()
            return _row_lease(updated, self._lease_seconds)
        except Exception:
            self._connection.rollback()
            raise
        finally:
            cursor.close()

    def complete(
        self,
        *,
        tenant_id: str,
        session_id: str,
        worker_id: str,
        execution_identity_hash: str,
        run_id: str,
        expected_version: int,
        outcome: str,
        findings: tuple[WorkerFindingRecord, ...] = (),
        resource_settlement: WorkerResourceSettlement | None = None,
        resource_clock: Callable[[], int] | None = None,
    ) -> WorkerQueueLease:
        return complete_worker_run(
            self._connection,
            lease_seconds=self._lease_seconds,
            now=self._now,
            tenant_id=tenant_id,
            session_id=session_id,
            worker_id=worker_id,
            execution_identity_hash=execution_identity_hash,
            run_id=run_id,
            expected_version=expected_version,
            outcome=outcome,
            findings=findings,
            resource_settlement=resource_settlement,
            resource_clock=resource_clock,
        )

    def request_command(
        self,
        *,
        tenant_id: str,
        run_id: str,
        command: str,
        expected_run_version: int,
    ) -> None:
        if command not in {"CANCEL", "SUPERSEDE"}:
            raise WorkerQueueConflict()
        _identifier(tenant_id)
        _identifier(run_id)
        if type(expected_run_version) is not int or expected_run_version < 1:
            raise WorkerQueueConflict()
        cursor = self._connection.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            row = cursor.execute(
                "SELECT state, version FROM audit_runs WHERE tenant_id=? AND run_id=?",
                (tenant_id, run_id),
            ).fetchone()
            if row is None or row["version"] != expected_run_version:
                raise WorkerQueueConflict()
            if row["state"] in _TERMINAL_STATES:
                if command == "SUPERSEDE" and row["state"] == "SUPERSEDED":
                    self._connection.commit()
                    return
                raise WorkerQueueConflict()
            target = "CANCEL_REQUESTED" if command == "CANCEL" else "SUPERSEDE_REQUESTED"
            cursor.execute(
                """UPDATE audit_runs SET state=?, version=version+1, updated_at=?
                   WHERE tenant_id=? AND run_id=? AND version=?""",
                (
                    target,
                    _utc(self._now()).isoformat(),
                    tenant_id,
                    run_id,
                    expected_run_version,
                ),
            )
            if cursor.rowcount != 1:
                raise WorkerQueueConflict()
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        finally:
            cursor.close()


class WorkerQueueClaimHandler:
    """Handler-compatible adapter for the worker session claim route."""

    def __init__(self, queue: SqliteWorkerQueue) -> None:
        self._queue = queue

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.action != "worker_sessions.create":
            raise ServiceUnavailableError()
        document = request.document
        if document is None or request.idempotency_key is None:
            return _conflict_response()
        worker_id = document.get("worker_id")
        requested_run_id = document.get("run_id")
        if not isinstance(worker_id, str) or (
            requested_run_id is not None and not isinstance(requested_run_id, str)
        ):
            return _conflict_response()
        try:
            lease = self._queue.claim(
                tenant_id=request.identity.tenant_id,
                worker_id=worker_id,
                idempotency_key=request.idempotency_key,
                allowed_repository_ids=request.identity.repository_ids,
                requested_run_id=requested_run_id,
            )
        except WorkerQueueConflict:
            return _conflict_response()
        if lease is None:
            return ServiceResponse(204, {})
        return ServiceResponse(
            201,
            lease.job_document(),
            {"etag": f'"{lease.version}"'},
        )


def _current(cursor: sqlite3.Cursor, tenant_id: str, session_id: str) -> sqlite3.Row:
    row: sqlite3.Row | None = cursor.execute(
        """SELECT q.*, r.state, r.execution_identity_hash
           FROM worker_run_queue AS q
           JOIN audit_runs AS r
             ON r.tenant_id=q.tenant_id AND r.run_id=q.run_id
           WHERE q.tenant_id=? AND q.session_id=?""",
        (tenant_id, session_id),
    ).fetchone()
    if row is None:
        raise WorkerQueueConflict()
    return row


def _require_current(
    row: sqlite3.Row,
    *,
    worker_id: str,
    identity_hash: str,
    run_id: str,
    expected_version: int,
    now: datetime,
) -> None:
    if (
        bool(row["terminal"])
        or row["lease_owner"] != worker_id
        or row["execution_identity_hash"] != identity_hash
        or row["run_id"] != run_id
        or row["version"] != expected_version
        or _timestamp(row["lease_expires_at"]) <= now
    ):
        raise WorkerQueueConflict()


def _row_lease(row: sqlite3.Row, lease_seconds: int) -> WorkerQueueLease:
    return WorkerQueueLease(
        tenant_id=row["tenant_id"],
        run_id=row["run_id"],
        worker_id=row["lease_owner"] or "released",
        session_id=row["session_id"],
        version=row["version"],
        lease_seconds=lease_seconds,
        lease_expires_at=(
            _timestamp(row["lease_expires_at"])
            if row["lease_expires_at"] is not None
            else datetime.fromtimestamp(0, UTC)
        ),
        command=_command(row["state"]),
        execution_identity=_identity_document(row["execution_identity_json"]),
        terminal=bool(row["terminal"]),
        outcome=row["outcome"],
    )


def _conflict_response() -> ServiceResponse:
    return ServiceResponse(
        409,
        {
            "error": {
                "code": "WORKER_CONFLICT",
                "message": "worker lease conflicts with current state",
            }
        },
    )


__all__ = [
    "SqliteWorkerQueue",
    "WorkerQueueClaimHandler",
    "WorkerQueueConflict",
    "WorkerQueueLease",
]
