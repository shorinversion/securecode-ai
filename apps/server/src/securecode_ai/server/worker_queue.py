"""Durable queue claims for connected workers."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from securecode_ai.contracts import RunExecutionIdentity
from securecode_ai.core.resource_governor import ReservationState, ResourceUsage

from .ports import ServiceRequest, ServiceResponse, ServiceUnavailableError
from .run_admission_models import RunOperation
from .worker_findings import WorkerFindingRecord
from .worker_findings_store import complete_worker_run
from .worker_queue_models import _MAX_VERSION as _QUEUE_MAX_VERSION
from .worker_queue_models import (
    TERMINAL_STATES as _TERMINAL_STATES,
)
from .worker_queue_models import (
    WorkerQueueConflict,
    WorkerQueueLease,
    WorkerResourceBudget,
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
from .worker_queue_models import contribution_trust as _contribution_trust
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

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_SEQUENCE = 2_147_483_647
_MAX_ARTIFACT_BYTES = 16_777_216
_EVENT_KINDS = frozenset(
    {"RUN_STARTED", "RUN_COMPLETED", "RUN_CANCELLED", "RUN_SUPERSEDED", "RUN_FAILED"}
)
_ARTIFACT_PURPOSES = frozenset(
    {
        "audit-report",
        "audit-run",
        "evidence-graph",
        "repair-patch",
        "repair-report",
        "sarif-report",
    }
)
_DATA_CLASSES = frozenset(
    {
        "DC0_PUBLIC",
        "DC1_INTERNAL_METADATA",
        "DC2_CONFIDENTIAL_SECURITY",
        "DC3_CONFIDENTIAL_SOURCE",
        "DC4_RESTRICTED",
    }
)


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
                """SELECT r.repository_id, r.execution_identity_hash, r.state,
                          a.state AS admission_state
                   FROM audit_runs AS r
                   LEFT JOIN run_admissions AS a
                     ON a.tenant_id=r.tenant_id AND a.run_id=r.run_id
                   WHERE r.tenant_id=? AND r.run_id=?""",
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
            admission_pending = (
                run["admission_state"] == "RESERVED" and run["state"] == "ADMISSION_PENDING"
            )
            admitted_active = (
                run["admission_state"] == "ADMITTED"
                and run["state"]
                in {"REQUESTED", "RUNNING", "CANCEL_REQUESTED", "SUPERSEDE_REQUESTED"}
                and existing is not None
            )
            if not admission_pending and not admitted_active:
                raise WorkerQueueConflict()
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
            now = _utc(self._now())
            now_ms = _datetime_ms(now)
            replay = cursor.execute(
                """SELECT request_sha256, response_json
                   FROM worker_queue_idempotency
                   WHERE tenant_id=? AND idempotency_key=?""",
                (tenant_id, idempotency_key),
            ).fetchone()
            if replay is not None:
                if replay["request_sha256"] != request_sha256:
                    raise WorkerQueueConflict()
                lease = _replayed_lease(replay["response_json"], self._lease_seconds)
                if lease is not None and not _active_replay_lease(
                    cursor,
                    lease=lease,
                    now=now,
                    tenant_id=tenant_id,
                    worker_id=worker_id,
                    requested_run_id=requested_run_id,
                    allowed_repository_ids=allowed_repository_ids,
                ):
                    # A queue replay is valid only while the exact durable
                    # session lease is still active.  Once it expires, remove
                    # the old response inside this transaction so the same
                    # retry key can either reclaim the row or receive a
                    # current no-work result, never the stale job document.
                    cursor.execute(
                        """DELETE FROM worker_queue_idempotency
                           WHERE tenant_id=? AND idempotency_key=?""",
                        (tenant_id, idempotency_key),
                    )
                else:
                    if lease is not None:
                        current_budget = _resource_budget_for_run(
                            cursor,
                            tenant_id=tenant_id,
                            run_id=lease.run_id,
                            execution_identity_hash=lease.execution_identity.execution_identity_hash,
                            require_reserved=True,
                            now_ms=now_ms,
                        )
                        if lease.resource_budget != current_budget:
                            raise WorkerQueueConflict()
                        lease = replace(
                            lease,
                            next_event_sequence=_next_event_sequence(
                                cursor, tenant_id=tenant_id, run_id=lease.run_id
                            ),
                        )
                    self._connection.commit()
                    return lease

            repositories = tuple(sorted(allowed_repository_ids))
            parameters: list[object] = [tenant_id, now.isoformat(), *repositories]
            repository_clause = ",".join("?" for _ in repositories)
            requested_clause = ""
            if requested_run_id is not None:
                requested_clause = " AND q.run_id=?"
                parameters.append(requested_run_id)
            query = (
                """SELECT q.*, r.state, r.version AS audit_version, r.created_at,
                          r.execution_identity_hash, r.metadata_json
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
            resource_budget = _resource_budget_for_run(
                cursor,
                tenant_id=tenant_id,
                run_id=row["run_id"],
                execution_identity_hash=identity.execution_identity_hash,
                require_reserved=True,
                now_ms=now_ms,
                require_full_wall=True,
                required_lease_seconds=self._lease_seconds,
            )
            next_version = int(row["version"]) + 1
            if next_version > _QUEUE_MAX_VERSION:
                raise WorkerQueueConflict()
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
                if row["audit_version"] >= _QUEUE_MAX_VERSION:
                    raise WorkerQueueConflict()
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
                contribution_trust=_run_contribution_trust(row["metadata_json"]),
                operation=_run_operation(row["metadata_json"]),
                next_event_sequence=_next_event_sequence(
                    cursor, tenant_id=tenant_id, run_id=row["run_id"]
                ),
                resource_budget=resource_budget,
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

    def authorize_session(
        self,
        *,
        tenant_id: str,
        session_id: str,
        worker_id: str,
        execution_identity_hash: str,
        run_id: str,
    ) -> None:
        """Authorize a bounded read-only worker side operation.

        The check is intentionally version-independent so a heartbeat can renew
        the same lease while a bounded metadata request is in flight.
        """

        _identifier(tenant_id)
        _identifier(session_id)
        _identifier(worker_id)
        _identifier(run_id)
        if _SHA256.fullmatch(execution_identity_hash) is None:
            raise WorkerQueueConflict()
        cursor = self._connection.cursor()
        try:
            row = _current(cursor, tenant_id, session_id)
            now = _utc(self._now())
            if row["state"] != "RUNNING":
                raise WorkerQueueConflict()
            _require_current(
                row,
                worker_id=worker_id,
                identity_hash=execution_identity_hash,
                run_id=run_id,
                expected_version=int(row["version"]),
                now=now,
            )
            # A lease is usable only while its admission reservation remains
            # active.  Resource expiry can race a long running worker after
            # claim; authorizing a session in that state would let it keep
            # heartbeating and append work that can never be settled.
            _resource_budget_for_run(
                cursor,
                tenant_id=tenant_id,
                run_id=run_id,
                execution_identity_hash=execution_identity_hash,
                require_reserved=True,
                now_ms=_datetime_ms(now),
            )
        finally:
            cursor.close()

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
        if type(events) is not tuple or len(events) > 64:
            raise WorkerQueueConflict()
        if expected_version >= _QUEUE_MAX_VERSION:
            raise WorkerQueueConflict()
        for event in events:
            _validate_event(
                event,
                run_id=run_id,
                execution_identity_hash=execution_identity_hash,
            )
        if artifact is not None:
            _validate_artifact(artifact)
        cursor = self._connection.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            row = _current(cursor, tenant_id, session_id)
            now = _utc(self._now())
            if (
                artifact is not None
                and "expires_at" in artifact
                and _timestamp(artifact["expires_at"]) <= now
            ):
                raise WorkerQueueConflict()
            _require_current(
                row,
                worker_id=worker_id,
                identity_hash=execution_identity_hash,
                run_id=run_id,
                expected_version=expected_version,
                now=now,
            )
            # The resource reservation is part of the worker lease contract,
            # not merely an admission-time hint.  Refuse heartbeats, events,
            # and artifact commits after expiry so a stale worker cannot
            # continue producing durable effects without a chargeable budget.
            _resource_budget_for_run(
                cursor,
                tenant_id=tenant_id,
                run_id=run_id,
                execution_identity_hash=execution_identity_hash,
                require_reserved=True,
                now_ms=_datetime_ms(now),
                required_lease_seconds=self._lease_seconds if renew_lease else None,
            )
            requested_command = _command(row["state"])
            if requested_command != "CONTINUE":
                terminal_kind = (
                    "RUN_SUPERSEDED" if requested_command == "SUPERSEDE" else "RUN_CANCELLED"
                )
                if artifact is not None or (renew_lease and events):
                    raise WorkerQueueConflict()
                if events:
                    if len(events) != 1 or events[0]["kind"] != terminal_kind:
                        raise WorkerQueueConflict()
                elif not renew_lease:
                    raise WorkerQueueConflict()
                else:
                    expires = now + timedelta(seconds=self._lease_seconds)
                    cursor.execute(
                        """UPDATE worker_run_queue
                           SET lease_expires_at=?
                           WHERE tenant_id=? AND session_id=? AND version=? AND terminal=0""",
                        (expires.isoformat(), tenant_id, session_id, expected_version),
                    )
                    if cursor.rowcount != 1:
                        raise WorkerQueueConflict()
                    updated = _current(cursor, tenant_id, session_id)
                    self._connection.commit()
                    return _row_lease(cursor, updated, self._lease_seconds)
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
                metadata_json = _canonical(
                    {
                        "event_hash": event["event_hash"],
                        "kind": event["kind"],
                        "worker_sequence": event["sequence"],
                    }
                )
                previous = cursor.execute(
                    """SELECT metadata_json FROM run_events
                       WHERE tenant_id=? AND run_id=? AND event_id=?""",
                    (tenant_id, run_id, event["event_id"]),
                ).fetchone()
                if previous is not None:
                    if previous["metadata_json"] != metadata_json:
                        raise WorkerQueueConflict()
                    continue
                if event["sequence"] != next_sequence:
                    raise WorkerQueueConflict()
                cursor.execute(
                    """INSERT INTO run_events
                       (tenant_id, run_id, sequence, event_id, metadata_json)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        tenant_id,
                        run_id,
                        next_sequence,
                        event["event_id"],
                        metadata_json,
                    ),
                )
                next_sequence += 1
            # The handler has verified this upload; keep the first committed
            # receipt for an exact run, purpose, and digest replay.
            if artifact is not None and not _reuse_committed_artifact(
                cursor,
                tenant_id=tenant_id,
                run_id=run_id,
                execution_identity_hash=execution_identity_hash,
                repository_id=_identity_document(
                    row["execution_identity_json"]
                ).repository_revision.repository_id,
                artifact=artifact,
            ):
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
            return _row_lease(cursor, updated, self._lease_seconds)
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
        if (
            type(expected_run_version) is not int
            or not 1 <= expected_run_version <= _QUEUE_MAX_VERSION
        ):
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
                if (command == "SUPERSEDE" and row["state"] == "SUPERSEDED") or (
                    command == "CANCEL" and row["state"] == "CANCELLED"
                ):
                    self._connection.commit()
                    return
                raise WorkerQueueConflict()
            if row["state"] == "SUPERSEDE_REQUESTED" and command == "CANCEL":
                raise WorkerQueueConflict()
            target = "CANCEL_REQUESTED" if command == "CANCEL" else "SUPERSEDE_REQUESTED"
            if row["state"] == target:
                self._connection.commit()
                return
            if expected_run_version >= _QUEUE_MAX_VERSION:
                raise WorkerQueueConflict()
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
        if not isinstance(document, Mapping) or request.idempotency_key is None:
            return _conflict_response()
        if (
            set(document) - {"schema_version", "worker_id", "run_id"}
            or document.get("schema_version") != "0.2.0"
        ):
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
        """SELECT q.*, r.state, r.execution_identity_hash, r.metadata_json
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


def _active_replay_lease(
    cursor: sqlite3.Cursor,
    *,
    lease: WorkerQueueLease,
    now: datetime,
    tenant_id: str,
    worker_id: str,
    requested_run_id: str | None,
    allowed_repository_ids: frozenset[str],
) -> bool:
    if (
        lease.lease_expires_at <= now
        or lease.tenant_id != tenant_id
        or lease.worker_id != worker_id
        or (requested_run_id is not None and lease.run_id != requested_run_id)
    ):
        return False
    row = cursor.execute(
        """SELECT q.lease_owner, q.lease_expires_at, q.session_id,
                  q.version, q.terminal, r.state, r.repository_id,
                  r.execution_identity_hash
           FROM worker_run_queue AS q
           JOIN audit_runs AS r
             ON r.tenant_id=q.tenant_id AND r.run_id=q.run_id
           WHERE q.tenant_id=? AND q.run_id=?""",
        (lease.tenant_id, lease.run_id),
    ).fetchone()
    if row is None or bool(row["terminal"]):
        return False
    if row["state"] not in {
        "REQUESTED",
        "RUNNING",
        "CANCEL_REQUESTED",
        "SUPERSEDE_REQUESTED",
    }:
        return False
    if row["repository_id"] not in allowed_repository_ids:
        return False
    if row["lease_expires_at"] is None:
        return False
    current_expires_at = _timestamp(row["lease_expires_at"])
    return (
        current_expires_at > now
        and current_expires_at == lease.lease_expires_at
        and row["lease_owner"] == lease.worker_id
        and row["session_id"] == lease.session_id
        and row["version"] == lease.version
        and row["execution_identity_hash"] == lease.execution_identity.execution_identity_hash
    )


def _row_lease(cursor: sqlite3.Cursor, row: sqlite3.Row, lease_seconds: int) -> WorkerQueueLease:
    identity_value = _identity_document(row["execution_identity_json"])
    resource_budget = _resource_budget_for_run(
        cursor,
        tenant_id=row["tenant_id"],
        run_id=row["run_id"],
        execution_identity_hash=identity_value.execution_identity_hash,
        require_reserved=False,
    )
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
        execution_identity=identity_value,
        terminal=bool(row["terminal"]),
        outcome=row["outcome"],
        contribution_trust=_run_contribution_trust(row["metadata_json"]),
        operation=_run_operation(row["metadata_json"]),
        next_event_sequence=_next_event_sequence(
            cursor, tenant_id=row["tenant_id"], run_id=row["run_id"]
        ),
        resource_budget=resource_budget,
    )


def _resource_budget_for_run(
    cursor: sqlite3.Cursor,
    *,
    tenant_id: str,
    run_id: str,
    execution_identity_hash: str,
    require_reserved: bool,
    now_ms: int | None = None,
    require_full_wall: bool = False,
    required_lease_seconds: int | None = None,
) -> WorkerResourceBudget:
    if (
        (now_ms is not None and (type(now_ms) is not int or now_ms < 0))
        or (require_full_wall and now_ms is None)
        or (
            required_lease_seconds is not None
            and (
                type(required_lease_seconds) is not int
                or not 5 <= required_lease_seconds <= 3600
                or now_ms is None
            )
        )
    ):
        raise WorkerQueueConflict()
    row = cursor.execute(
        """SELECT r.profile_sha256, r.reservation_id, r.state_version, r.state,
                  r.requested_tokens, r.requested_cost_microunits, r.requested_cpu_ms,
                  r.requested_memory_bytes, r.requested_wall_ms, r.lease_expires_at_ms,
                  a.state AS admission_state,
                  a.reservation_id AS admission_reservation_id,
                  a.reservation_version AS admission_reservation_version
           FROM resource_reservations AS r
           LEFT JOIN run_admissions AS a
             ON a.tenant_id=r.tenant_id AND a.run_id=r.run_id
           WHERE r.tenant_id=? AND r.run_id=? AND r.execution_identity_hash=?""",
        (tenant_id, run_id, execution_identity_hash),
    ).fetchone()
    if (
        row is None
        or row["admission_state"] != "ADMITTED"
        or row["admission_reservation_id"] != row["reservation_id"]
        or type(row["admission_reservation_version"]) is not int
        or row["admission_reservation_version"] < 1
        or row["state"] not in {state.value for state in ReservationState}
        or row["state_version"]
        != row["admission_reservation_version"]
        + (0 if row["state"] == ReservationState.RESERVED.value else 1)
        or (require_reserved and row["state"] != ReservationState.RESERVED.value)
    ):
        raise WorkerQueueConflict()
    if require_reserved and now_ms is not None:
        expires_at_ms = row["lease_expires_at_ms"]
        if type(expires_at_ms) is not int or expires_at_ms <= now_ms:
            raise WorkerQueueConflict()
        if require_full_wall:
            requested_wall_ms = row["requested_wall_ms"]
            if (
                type(requested_wall_ms) is not int
                or requested_wall_ms < 0
                or expires_at_ms - now_ms < requested_wall_ms
            ):
                raise WorkerQueueConflict()
        if required_lease_seconds is not None and (
            expires_at_ms - now_ms <= required_lease_seconds * 1000
        ):
            raise WorkerQueueConflict()
    try:
        return WorkerResourceBudget(
            profile_sha256=row["profile_sha256"],
            reservation_id=row["reservation_id"],
            reservation_version=row["state_version"],
            reserved=ResourceUsage(
                tokens=row["requested_tokens"],
                cost_microunits=row["requested_cost_microunits"],
                cpu_ms=row["requested_cpu_ms"],
                peak_memory_bytes=row["requested_memory_bytes"],
                wall_ms=row["requested_wall_ms"],
            ),
        )
    except (TypeError, ValueError):
        raise WorkerQueueConflict() from None


def _datetime_ms(value: datetime) -> int:
    try:
        milliseconds = int(value.timestamp() * 1000)
    except (OverflowError, OSError, ValueError):
        raise WorkerQueueConflict() from None
    if not 0 <= milliseconds <= 9_223_372_036_854_775_807:
        raise WorkerQueueConflict()
    return milliseconds


def _next_event_sequence(cursor: sqlite3.Cursor, *, tenant_id: str, run_id: str) -> int:
    value = cursor.execute(
        """SELECT COALESCE(MAX(sequence), 0) + 1 FROM run_events
           WHERE tenant_id=? AND run_id=?""",
        (tenant_id, run_id),
    ).fetchone()[0]
    if type(value) is not int or not 1 <= value <= _MAX_SEQUENCE:
        raise WorkerQueueConflict()
    return value


def _run_contribution_trust(value: str) -> str:
    try:
        metadata = json.loads(value, object_pairs_hook=_closed_object)
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise WorkerQueueConflict() from None
    if not isinstance(metadata, Mapping):
        raise WorkerQueueConflict()
    return _contribution_trust(metadata.get("contribution_trust", "NOT_SCM"))


def _run_operation(value: str) -> RunOperation:
    try:
        metadata = json.loads(value, object_pairs_hook=_closed_object)
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise WorkerQueueConflict() from None
    if not isinstance(metadata, Mapping):
        raise WorkerQueueConflict()
    try:
        return RunOperation(metadata.get("operation", RunOperation.SCAN.value))
    except (TypeError, ValueError):
        raise WorkerQueueConflict() from None


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


def _validate_event(
    value: Mapping[str, object], *, run_id: str, execution_identity_hash: str
) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "event_hash",
        "event_id",
        "kind",
        "sequence",
    }:
        raise WorkerQueueConflict()
    sequence = value["sequence"]
    event_id = value["event_id"]
    event_hash = value["event_hash"]
    kind = value["kind"]
    if (
        type(sequence) is not int
        or not 1 <= sequence <= _MAX_SEQUENCE
        or type(event_id) is not str
        or type(event_hash) is not str
        or _SHA256.fullmatch(event_hash) is None
        or type(kind) is not str
        or kind not in _EVENT_KINDS
    ):
        raise WorkerQueueConflict()
    _identifier(event_id)
    digest = _canonical_sha256(
        {
            "execution_identity_hash": execution_identity_hash,
            "kind": kind,
            "run_id": run_id,
            "sequence": sequence,
        }
    )
    if event_hash != digest or event_id != f"worker-{sequence}-{digest[:32]}":
        raise WorkerQueueConflict()


def _validate_artifact(value: Mapping[str, object]) -> None:
    base_keys = {
        "authorization_id",
        "content_id",
        "content_sha256",
        "data_class",
        "purpose",
        "size_bytes",
    }
    if not isinstance(value, Mapping):
        raise WorkerQueueConflict()
    keys = frozenset(value)
    if keys in {frozenset(base_keys), frozenset(base_keys | {"expires_at"})}:
        if value.get("purpose") == "repair-patch":
            raise WorkerQueueConflict()
    elif keys in {
        frozenset(base_keys | {"binding"}),
        frozenset(base_keys | {"binding", "expires_at"}),
    }:
        if value.get("purpose") != "repair-patch":
            raise WorkerQueueConflict()
        _validate_repair_binding(value.get("binding"))
    else:
        raise WorkerQueueConflict()
    for name in ("authorization_id", "content_id", "purpose", "data_class"):
        if type(value[name]) is not str:
            raise WorkerQueueConflict()
    authorization_id = value["authorization_id"]
    content_id = value["content_id"]
    if type(authorization_id) is not str or type(content_id) is not str:
        raise WorkerQueueConflict()
    _identifier(authorization_id)
    _identifier(content_id)
    digest = value["content_sha256"]
    if type(digest) is not str or _SHA256.fullmatch(digest) is None:
        raise WorkerQueueConflict()
    if value["data_class"] not in _DATA_CLASSES or value["purpose"] not in _ARTIFACT_PURPOSES:
        raise WorkerQueueConflict()
    size = value["size_bytes"]
    if type(size) is not int or not 1 <= size <= _MAX_ARTIFACT_BYTES:
        raise WorkerQueueConflict()
    if "expires_at" in value:
        _timestamp(value["expires_at"])


def _validate_repair_binding(value: object) -> None:
    keys = {
        "execution_identity_hash",
        "finding_id",
        "head_sha",
        "manifest_sha256",
        "patch_size_bytes",
        "patch_sha256",
        "patch_status_sha256",
        "repository_id",
        "run_id",
        "tenant_id",
        "validation_result_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != keys:
        raise WorkerQueueConflict()
    for name in (
        "execution_identity_hash",
        "manifest_sha256",
        "patch_sha256",
        "patch_status_sha256",
        "validation_result_sha256",
    ):
        digest = value.get(name)
        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            raise WorkerQueueConflict()
    head_sha = value.get("head_sha")
    if type(head_sha) is not str or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise WorkerQueueConflict()
    for name in ("tenant_id", "repository_id", "run_id", "finding_id"):
        if type(value.get(name)) is not str:
            raise WorkerQueueConflict()
        _identifier(value[name])
    size = value.get("patch_size_bytes")
    if type(size) is not int or not 1 <= size <= 131_072:
        raise WorkerQueueConflict()


def _reuse_committed_artifact(
    cursor: sqlite3.Cursor,
    *,
    tenant_id: str,
    run_id: str,
    execution_identity_hash: str,
    repository_id: str,
    artifact: Mapping[str, object],
) -> bool:
    row = cursor.execute(
        """SELECT a.authorization_id, a.metadata_json,
                  z.repository_id AS authorization_repository_id,
                  z.run_id AS authorization_run_id,
                  z.execution_identity_hash AS authorization_identity_hash,
                  z.content_id AS authorization_content_id,
                  z.content_sha256 AS authorization_content_sha256,
                  z.size_bytes AS authorization_size_bytes,
                  z.data_class AS authorization_data_class,
                  z.purpose AS authorization_purpose,
                  z.method AS authorization_method
           FROM run_artifacts AS a
           JOIN artifact_upload_authorizations AS z
             ON z.tenant_id=a.tenant_id AND z.authorization_id=a.authorization_id
           WHERE a.tenant_id=? AND a.run_id=?
             AND a.content_sha256=? AND a.purpose=?""",
        (tenant_id, run_id, artifact["content_sha256"], artifact["purpose"]),
    ).fetchone()
    if row is None:
        return False

    try:
        committed = json.loads(row["metadata_json"], object_pairs_hook=_closed_object)
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise WorkerQueueConflict() from None
    if type(committed) is not dict:
        raise WorkerQueueConflict()
    _validate_artifact(committed)
    if committed["authorization_id"] != row["authorization_id"]:
        raise WorkerQueueConflict()

    committed_scope = dict(committed)
    committed_scope.pop("authorization_id")
    requested_scope = dict(artifact)
    requested_scope.pop("authorization_id")
    if committed_scope != requested_scope:
        raise WorkerQueueConflict()

    authorization_scope = (
        row["authorization_repository_id"],
        row["authorization_run_id"],
        row["authorization_identity_hash"],
        row["authorization_content_id"],
        row["authorization_content_sha256"],
        row["authorization_size_bytes"],
        row["authorization_data_class"],
        row["authorization_purpose"],
        row["authorization_method"],
    )
    expected_scope = (
        repository_id,
        run_id,
        execution_identity_hash,
        artifact["content_id"],
        artifact["content_sha256"],
        artifact["size_bytes"],
        artifact["data_class"],
        artifact["purpose"],
        "PUT",
    )
    if authorization_scope != expected_scope:
        raise WorkerQueueConflict()
    return True


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, item in pairs:
        if key in document:
            raise ValueError("duplicate worker metadata field")
        document[key] = item
    return document


__all__ = [
    "SqliteWorkerQueue",
    "WorkerQueueClaimHandler",
    "WorkerQueueConflict",
    "WorkerQueueLease",
]
