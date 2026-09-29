"""Durable tenant resource admission and usage accounting for SQLite."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import NoReturn

from securecode_ai.core.resource_governor import (
    ReservationState,
    ResourceGovernorError,
    ResourceGovernorErrorCode,
    ResourceReservationReceipt,
    ResourceReservationRequest,
    ResourceUsage,
    TenantResourceLimits,
)

from .resource_storage import (
    SCHEMA_STATEMENTS,
    actual_usage,
    bounded_nonnegative,
    identifier,
    limit_values,
    limits_from_row,
    receipt_from_row,
    request_hash,
    validate_binding,
    validate_limits,
    validate_request,
    validate_transition,
    validate_usage,
)

_MAX_QUEUE_VERSION = 2_147_483_647
_ACTIVE_AUDIT_STATES = frozenset(
    {"REQUESTED", "RUNNING", "CANCEL_REQUESTED", "SUPERSEDE_REQUESTED"}
)


class ResourceRepository:
    """Store immutable limit profiles and reservation transitions atomically."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        cursor = self._connection.cursor()
        try:
            for statement in SCHEMA_STATEMENTS:
                cursor.execute(statement)
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        finally:
            cursor.close()

    @classmethod
    def in_memory(cls) -> ResourceRepository:
        return cls(sqlite3.connect(":memory:"))

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        cursor = self._connection.cursor()
        savepoint = f"securecode_resource_{id(cursor):x}"
        active = False
        try:
            # A resource operation can be part of the admission transaction on
            # the shared control-plane connection.  BEGIN IMMEDIATE would
            # reject that valid composition and commit/rollback unrelated
            # writes.  A uniquely named savepoint preserves atomicity while
            # allowing the outer owner to decide when the transaction commits.
            cursor.execute(f"SAVEPOINT {savepoint}")
            active = True
            yield cursor
            cursor.execute(f"RELEASE SAVEPOINT {savepoint}")
            active = False
        except Exception:
            if active:
                try:
                    cursor.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                    cursor.execute(f"RELEASE SAVEPOINT {savepoint}")
                except sqlite3.Error:
                    pass
            raise
        finally:
            cursor.close()

    def configure(self, limits: TenantResourceLimits) -> None:
        validate_limits(limits)
        values = limit_values(limits)
        with self._transaction() as cursor:
            existing = cursor.execute(
                """SELECT * FROM resource_limit_profiles
                   WHERE tenant_id=? AND profile_sha256=?""",
                (limits.tenant_id, limits.profile_sha256),
            ).fetchone()
            if existing is not None:
                if limits_from_row(existing) != limits:
                    _reject(ResourceGovernorErrorCode.CONFLICT)
            else:
                try:
                    cursor.execute(
                        """INSERT INTO resource_limit_profiles (
                            tenant_id, profile_id, profile_sha256,
                            max_concurrent_runs, max_admissions_per_window,
                            admission_window_ms, max_tokens_per_window,
                            max_cost_microunits_per_window, max_cpu_ms_per_run,
                            max_memory_bytes_per_run, max_wall_ms_per_run
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        values,
                    )
                except sqlite3.IntegrityError as error:
                    raise ResourceGovernorError(ResourceGovernorErrorCode.CONFLICT) from error

            current = cursor.execute(
                "SELECT profile_sha256 FROM resource_tenant_limits WHERE tenant_id=?",
                (limits.tenant_id,),
            ).fetchone()
            if current is None:
                cursor.execute(
                    """INSERT INTO resource_tenant_limits (tenant_id, profile_sha256)
                       VALUES (?, ?)""",
                    (limits.tenant_id, limits.profile_sha256),
                )
            elif current["profile_sha256"] != limits.profile_sha256:
                cursor.execute(
                    """UPDATE resource_tenant_limits SET profile_sha256=?
                       WHERE tenant_id=?""",
                    (limits.profile_sha256, limits.tenant_id),
                )

    def reserve(self, request: ResourceReservationRequest) -> ResourceReservationReceipt:
        validate_request(request)
        fingerprint = request_hash(request)
        reservation_id = "reservation-" + fingerprint[:40]
        reserved = ResourceUsage(
            tokens=request.requested_tokens,
            cost_microunits=request.requested_cost_microunits,
            cpu_ms=request.requested_cpu_ms,
            peak_memory_bytes=request.requested_memory_bytes,
            wall_ms=request.requested_wall_ms,
        )
        with self._transaction() as cursor:
            replay = cursor.execute(
                """SELECT reservation_id, request_sha256
                   FROM resource_reservations
                   WHERE tenant_id=? AND request_id=?""",
                (request.tenant_id, request.request_id),
            ).fetchone()
            if replay is not None:
                if replay["request_sha256"] != fingerprint:
                    _reject(ResourceGovernorErrorCode.CONFLICT)
                row = self._load(
                    cursor,
                    tenant_id=request.tenant_id,
                    repository_id=request.repository_id,
                    run_id=request.run_id,
                    execution_identity_hash=request.execution_identity_hash,
                    reservation_id=replay["reservation_id"],
                )
                return receipt_from_row(row, idempotent=True)

            limits_row = cursor.execute(
                """SELECT p.* FROM resource_tenant_limits AS c
                   JOIN resource_limit_profiles AS p
                     ON p.tenant_id=c.tenant_id
                    AND p.profile_sha256=c.profile_sha256
                   WHERE c.tenant_id=?""",
                (request.tenant_id,),
            ).fetchone()
            if limits_row is None or limits_row["profile_sha256"] != request.profile_sha256:
                _reject(ResourceGovernorErrorCode.INVALID_REQUEST)
            limits = limits_from_row(limits_row)

            self._expire(cursor, request.tenant_id, request.now_ms)
            active = cursor.execute(
                """SELECT COUNT(*) FROM resource_reservations
                   WHERE tenant_id=? AND state=? AND lease_expires_at_ms>?""",
                (
                    request.tenant_id,
                    ReservationState.RESERVED.value,
                    request.now_ms,
                ),
            ).fetchone()[0]
            if active >= limits.max_concurrent_runs:
                _reject(ResourceGovernorErrorCode.CONCURRENCY_EXCEEDED)

            lower = request.now_ms - limits.admission_window_ms
            events = cursor.execute(
                """SELECT reserved_tokens AS budget_tokens,
                          reserved_cost_microunits AS budget_cost_microunits
                   FROM resource_admissions
                   WHERE tenant_id=? AND admitted_at_ms>?
                   ORDER BY admitted_at_ms, reservation_id""",
                (request.tenant_id, lower),
            ).fetchall()
            if len(events) >= limits.max_admissions_per_window:
                _reject(ResourceGovernorErrorCode.RATE_LIMITED)
            if (
                reserved.tokens > limits.max_tokens_per_window
                or reserved.cost_microunits > limits.max_cost_microunits_per_window
                or reserved.cpu_ms > limits.max_cpu_ms_per_run
                or reserved.peak_memory_bytes > limits.max_memory_bytes_per_run
                or reserved.wall_ms > limits.max_wall_ms_per_run
            ):
                _reject(ResourceGovernorErrorCode.QUOTA_EXCEEDED)
            window_tokens = 0
            window_cost = 0
            for event in events:
                window_tokens += event["budget_tokens"]
                window_cost += event["budget_cost_microunits"]
                if (
                    window_tokens > limits.max_tokens_per_window - reserved.tokens
                    or window_cost
                    > limits.max_cost_microunits_per_window - reserved.cost_microunits
                ):
                    _reject(ResourceGovernorErrorCode.QUOTA_EXCEEDED)

            try:
                cursor.execute(
                    """INSERT INTO resource_reservations (
                        tenant_id, reservation_id, request_id, request_sha256,
                        repository_id, run_id, execution_identity_hash,
                        profile_sha256, requested_tokens,
                        requested_cost_microunits, requested_cpu_ms,
                        requested_memory_bytes, requested_wall_ms, admitted_at_ms,
                        lease_expires_at_ms, state, actual_tokens,
                        actual_cost_microunits, actual_cpu_ms,
                        actual_peak_memory_bytes, actual_wall_ms, state_version,
                        terminal_at_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              NULL, NULL, NULL, NULL, NULL, 1, NULL)""",
                    (
                        request.tenant_id,
                        reservation_id,
                        request.request_id,
                        fingerprint,
                        request.repository_id,
                        request.run_id,
                        request.execution_identity_hash,
                        request.profile_sha256,
                        reserved.tokens,
                        reserved.cost_microunits,
                        reserved.cpu_ms,
                        reserved.peak_memory_bytes,
                        reserved.wall_ms,
                        request.now_ms,
                        request.lease_expires_at_ms,
                        ReservationState.RESERVED.value,
                    ),
                )
                cursor.execute(
                    """INSERT INTO resource_admissions (
                        tenant_id, reservation_id, admitted_at_ms,
                        reserved_tokens, reserved_cost_microunits
                    ) VALUES (?, ?, ?, ?, ?)""",
                    (
                        request.tenant_id,
                        reservation_id,
                        request.now_ms,
                        reserved.tokens,
                        reserved.cost_microunits,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ResourceGovernorError(ResourceGovernorErrorCode.CONFLICT) from error
            row = self._load(
                cursor,
                tenant_id=request.tenant_id,
                repository_id=request.repository_id,
                run_id=request.run_id,
                execution_identity_hash=request.execution_identity_hash,
                reservation_id=reservation_id,
            )
            return receipt_from_row(row, idempotent=False)

    def is_active(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        execution_identity_hash: str,
        reservation_id: str,
        expected_version: int,
        now_ms: int,
    ) -> bool:
        """Check the exact admission reservation without changing it."""

        validate_binding(
            tenant_id,
            repository_id,
            run_id,
            execution_identity_hash,
            reservation_id,
        )
        validate_transition(expected_version, now_ms)
        with self._transaction() as cursor:
            try:
                row = self._load(
                    cursor,
                    tenant_id=tenant_id,
                    repository_id=repository_id,
                    run_id=run_id,
                    execution_identity_hash=execution_identity_hash,
                    reservation_id=reservation_id,
                )
            except ResourceGovernorError as error:
                if error.code is ResourceGovernorErrorCode.RESERVATION_UNKNOWN:
                    return False
                raise
            return (
                ReservationState(row["state"]) is ReservationState.RESERVED
                and row["state_version"] == expected_version
                and now_ms >= row["admitted_at_ms"]
                and now_ms < row["lease_expires_at_ms"]
            )

    def commit(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        execution_identity_hash: str,
        reservation_id: str,
        usage: ResourceUsage,
        expected_version: int,
        now_ms: int,
    ) -> ResourceReservationReceipt:
        validate_binding(
            tenant_id,
            repository_id,
            run_id,
            execution_identity_hash,
            reservation_id,
        )
        validate_usage(usage)
        validate_transition(expected_version, now_ms)
        with self._transaction() as cursor:
            row = self._load(
                cursor,
                tenant_id=tenant_id,
                repository_id=repository_id,
                run_id=run_id,
                execution_identity_hash=execution_identity_hash,
                reservation_id=reservation_id,
            )
            state = ReservationState(row["state"])
            if state is ReservationState.COMMITTED:
                if actual_usage(row) != usage:
                    _reject(ResourceGovernorErrorCode.CONFLICT)
                return receipt_from_row(row, idempotent=True)
            self._require_active(row, expected_version, now_ms)
            if (
                usage.tokens > row["requested_tokens"]
                or usage.cost_microunits > row["requested_cost_microunits"]
                or usage.cpu_ms > row["requested_cpu_ms"]
                or usage.peak_memory_bytes > row["requested_memory_bytes"]
                or usage.wall_ms > row["requested_wall_ms"]
            ):
                _reject(ResourceGovernorErrorCode.QUOTA_EXCEEDED)
            cursor.execute(
                """UPDATE resource_reservations
                   SET state=?, actual_tokens=?, actual_cost_microunits=?,
                       actual_cpu_ms=?, actual_peak_memory_bytes=?,
                       actual_wall_ms=?, state_version=state_version+1,
                       terminal_at_ms=?
                   WHERE tenant_id=? AND reservation_id=?
                     AND state=? AND state_version=?""",
                (
                    ReservationState.COMMITTED.value,
                    usage.tokens,
                    usage.cost_microunits,
                    usage.cpu_ms,
                    usage.peak_memory_bytes,
                    usage.wall_ms,
                    now_ms,
                    tenant_id,
                    reservation_id,
                    ReservationState.RESERVED.value,
                    expected_version,
                ),
            )
            if cursor.rowcount != 1:
                _reject(ResourceGovernorErrorCode.CONFLICT)
            updated = self._load(
                cursor,
                tenant_id=tenant_id,
                repository_id=repository_id,
                run_id=run_id,
                execution_identity_hash=execution_identity_hash,
                reservation_id=reservation_id,
            )
            return receipt_from_row(updated, idempotent=False)

    def release(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        execution_identity_hash: str,
        reservation_id: str,
        expected_version: int,
        now_ms: int,
        cancelled: bool = False,
    ) -> ResourceReservationReceipt:
        validate_binding(
            tenant_id,
            repository_id,
            run_id,
            execution_identity_hash,
            reservation_id,
        )
        cancelled = _validated_boolean(cancelled)
        validate_transition(expected_version, now_ms)
        target = ReservationState.CANCELLED if cancelled else ReservationState.RELEASED
        with self._transaction() as cursor:
            row = self._load(
                cursor,
                tenant_id=tenant_id,
                repository_id=repository_id,
                run_id=run_id,
                execution_identity_hash=execution_identity_hash,
                reservation_id=reservation_id,
            )
            if ReservationState(row["state"]) is target:
                return receipt_from_row(row, idempotent=True)
            self._require_active(row, expected_version, now_ms)
            cursor.execute(
                """UPDATE resource_reservations
                   SET state=?, state_version=state_version+1, terminal_at_ms=?
                   WHERE tenant_id=? AND reservation_id=?
                     AND state=? AND state_version=?""",
                (
                    target.value,
                    now_ms,
                    tenant_id,
                    reservation_id,
                    ReservationState.RESERVED.value,
                    expected_version,
                ),
            )
            if cursor.rowcount != 1:
                _reject(ResourceGovernorErrorCode.CONFLICT)
            updated = self._load(
                cursor,
                tenant_id=tenant_id,
                repository_id=repository_id,
                run_id=run_id,
                execution_identity_hash=execution_identity_hash,
                reservation_id=reservation_id,
            )
            return receipt_from_row(updated, idempotent=False)

    def expire(
        self,
        *,
        tenant_id: str,
        now_ms: int,
        max_items: int = 100,
    ) -> int:
        if (
            not identifier(tenant_id)
            or not bounded_nonnegative(now_ms)
            or type(max_items) is not int
            or not 1 <= max_items <= 10_000
        ):
            _reject(ResourceGovernorErrorCode.INVALID_REQUEST)
        with self._transaction() as cursor:
            return self._expire_all(cursor, now_ms, max_items, tenant_id=tenant_id)

    def expire_all(
        self,
        *,
        now_ms: int,
        max_items: int = 100,
        tenant_id: str | None = None,
    ) -> int:
        """Reconcile and release a bounded batch of expired reservations."""

        if (
            not bounded_nonnegative(now_ms)
            or type(max_items) is not int
            or not 1 <= max_items <= 10_000
            or (tenant_id is not None and not identifier(tenant_id))
        ):
            _reject(ResourceGovernorErrorCode.INVALID_REQUEST)
        with self._transaction() as cursor:
            return self._expire_all(cursor, now_ms, max_items, tenant_id=tenant_id)

    @staticmethod
    def _expire(
        cursor: sqlite3.Cursor,
        tenant_id: str,
        now_ms: int,
        max_items: int = 100,
    ) -> int:
        cursor.execute(
            """UPDATE resource_reservations
               SET state=?, state_version=state_version+1,
                   terminal_at_ms=lease_expires_at_ms
               WHERE tenant_id=? AND reservation_id IN (
                   SELECT reservation_id FROM resource_reservations
                   WHERE tenant_id=? AND state=? AND lease_expires_at_ms<=?
                   ORDER BY lease_expires_at_ms, reservation_id LIMIT ?
               )""",
            (
                ReservationState.RELEASED.value,
                tenant_id,
                tenant_id,
                ReservationState.RESERVED.value,
                now_ms,
                max_items,
            ),
        )
        return cursor.rowcount

    def _expire_all(
        self,
        cursor: sqlite3.Cursor,
        now_ms: int,
        max_items: int = 100,
        *,
        tenant_id: str | None = None,
    ) -> int:
        parameters: list[object] = [ReservationState.RESERVED.value, now_ms]
        tenant_clause = ""
        if tenant_id is not None:
            tenant_clause = " AND r.tenant_id=?"
            parameters.append(tenant_id)
        parameters.append(max_items)
        required_tables = {
            row["name"]
            for row in cursor.execute(
                """SELECT name FROM sqlite_master
                   WHERE type='table' AND name IN
                     ('run_admissions', 'audit_runs', 'worker_run_queue')"""
            ).fetchall()
        }
        if not required_tables:
            return self._expire_without_reconciliation(
                cursor,
                now_ms,
                max_items,
                tenant_id=tenant_id,
            )
        if required_tables != {"run_admissions", "audit_runs", "worker_run_queue"}:
            return 0
        rows = cursor.execute(
            """SELECT r.rowid, r.tenant_id, r.reservation_id,
                      r.run_id, r.state_version, a.state AS admission_state,
                      u.state AS audit_state, u.version AS audit_version,
                      q.rowid AS queue_rowid, q.version AS queue_version,
                      q.terminal AS queue_terminal,
                      q.outcome AS queue_outcome
               FROM resource_reservations AS r
               LEFT JOIN run_admissions AS a
                 ON a.tenant_id=r.tenant_id AND a.run_id=r.run_id
               LEFT JOIN audit_runs AS u
                 ON u.tenant_id=r.tenant_id AND u.run_id=r.run_id
               LEFT JOIN worker_run_queue AS q
                 ON q.tenant_id=r.tenant_id AND q.run_id=r.run_id
               WHERE r.state=? AND r.lease_expires_at_ms<=?"""
            + tenant_clause
            + " ORDER BY r.lease_expires_at_ms, r.tenant_id, r.reservation_id LIMIT ?",
            tuple(parameters),
        ).fetchall()
        expired = 0
        for row in rows:
            if not self._reconcile_expired_active(cursor, row, now_ms):
                continue
            cursor.execute(
                """UPDATE resource_reservations
                   SET state=?, state_version=state_version+1,
                       terminal_at_ms=lease_expires_at_ms
                   WHERE rowid=? AND state=? AND lease_expires_at_ms<=?""",
                (
                    ReservationState.RELEASED.value,
                    row["rowid"],
                    ReservationState.RESERVED.value,
                    now_ms,
                ),
            )
            if cursor.rowcount != 1:
                _reject(ResourceGovernorErrorCode.CONFLICT)
            expired += 1
        return expired

    @staticmethod
    def _expire_without_reconciliation(
        cursor: sqlite3.Cursor,
        now_ms: int,
        max_items: int,
        *,
        tenant_id: str | None,
    ) -> int:
        parameters: list[object] = [
            ReservationState.RELEASED.value,
            ReservationState.RESERVED.value,
            now_ms,
        ]
        tenant_clause = ""
        if tenant_id is not None:
            tenant_clause = " AND tenant_id=?"
            parameters.append(tenant_id)
        parameters.append(max_items)
        cursor.execute(
            """UPDATE resource_reservations
               SET state=?, state_version=state_version+1,
                   terminal_at_ms=lease_expires_at_ms
               WHERE rowid IN (
                   SELECT rowid FROM resource_reservations
                   WHERE state=? AND lease_expires_at_ms<=?"""
            + tenant_clause
            + " ORDER BY lease_expires_at_ms, tenant_id, reservation_id LIMIT ?)",
            tuple(parameters),
        )
        return cursor.rowcount

    @staticmethod
    def _reconcile_expired_active(
        cursor: sqlite3.Cursor,
        row: sqlite3.Row,
        now_ms: int,
    ) -> bool:
        if row["admission_state"] == "RESERVED" and row["audit_state"] == "ADMISSION_PENDING":
            return ResourceRepository._reconcile_expired_pending(cursor, row, now_ms)
        if row["admission_state"] != "ADMITTED" or row["audit_state"] not in _ACTIVE_AUDIT_STATES:
            return True
        queue_terminal = row["queue_terminal"]
        if queue_terminal is not None and queue_terminal not in (0, 1):
            return False
        if queue_terminal is not None and bool(queue_terminal):
            if row["queue_outcome"] != "INDETERMINATE":
                return False
        else:
            queue_version = row["queue_version"]
            if queue_version is not None and (
                type(queue_version) is not int or not 0 <= queue_version < _MAX_QUEUE_VERSION
            ):
                return False
        audit_version = row["audit_version"]
        if type(audit_version) is not int or not 0 <= audit_version < _MAX_QUEUE_VERSION:
            return False
        try:
            timestamp = datetime.fromtimestamp(now_ms / 1000, UTC).isoformat()
        except (OverflowError, OSError, ValueError):
            _reject(ResourceGovernorErrorCode.INVALID_REQUEST)
        if queue_terminal is not None and not bool(queue_terminal):
            cursor.execute(
                """UPDATE worker_run_queue
                   SET terminal=1, outcome='INDETERMINATE',
                       lease_owner=NULL, lease_expires_at=NULL, version=version+1
                   WHERE tenant_id=? AND rowid=? AND terminal=0
                     AND version=?""",
                (
                    row["tenant_id"],
                    row["queue_rowid"],
                    row["queue_version"],
                ),
            )
            if cursor.rowcount != 1:
                _reject(ResourceGovernorErrorCode.CONFLICT)
        cursor.execute(
            """UPDATE audit_runs
               SET state='INDETERMINATE', version=version+1, updated_at=?
               WHERE tenant_id=? AND run_id=? AND state=? AND version=?""",
            (
                timestamp,
                row["tenant_id"],
                row["run_id"],
                row["audit_state"],
                audit_version,
            ),
        )
        if cursor.rowcount != 1:
            _reject(ResourceGovernorErrorCode.CONFLICT)
        return True

    @staticmethod
    def _reconcile_expired_pending(
        cursor: sqlite3.Cursor,
        row: sqlite3.Row,
        now_ms: int,
    ) -> bool:
        queue_terminal = row["queue_terminal"]
        if queue_terminal is not None and queue_terminal not in (0, 1):
            return False
        if queue_terminal is not None and bool(queue_terminal):
            if row["queue_outcome"] != "INDETERMINATE":
                return False
        else:
            queue_version = row["queue_version"]
            if queue_version is not None and (
                type(queue_version) is not int or not 0 <= queue_version < _MAX_QUEUE_VERSION
            ):
                return False
        audit_version = row["audit_version"]
        if type(audit_version) is not int or not 0 <= audit_version < _MAX_QUEUE_VERSION:
            return False
        try:
            timestamp = datetime.fromtimestamp(now_ms / 1000, UTC).isoformat()
        except (OverflowError, OSError, ValueError):
            _reject(ResourceGovernorErrorCode.INVALID_REQUEST)
        if queue_terminal is not None and not bool(queue_terminal):
            cursor.execute(
                """UPDATE worker_run_queue
                   SET terminal=1, outcome='INDETERMINATE',
                       lease_owner=NULL, lease_expires_at=NULL, version=version+1
                   WHERE tenant_id=? AND rowid=? AND terminal=0
                     AND version=?""",
                (
                    row["tenant_id"],
                    row["queue_rowid"],
                    row["queue_version"],
                ),
            )
            if cursor.rowcount != 1:
                _reject(ResourceGovernorErrorCode.CONFLICT)
        cursor.execute(
            """UPDATE audit_runs
               SET state='ADMISSION_BLOCKED', version=version+1, updated_at=?
               WHERE tenant_id=? AND run_id=?
                 AND state='ADMISSION_PENDING' AND version=?""",
            (
                timestamp,
                row["tenant_id"],
                row["run_id"],
                audit_version,
            ),
        )
        if cursor.rowcount != 1:
            _reject(ResourceGovernorErrorCode.CONFLICT)
        cursor.execute(
            """UPDATE run_admissions
               SET state='RECOVERY_REQUIRED', failure_code=?, updated_at_ms=?
               WHERE tenant_id=? AND run_id=? AND state='RESERVED'""",
            (
                "SERVICE_UNAVAILABLE",
                now_ms,
                row["tenant_id"],
                row["run_id"],
            ),
        )
        if cursor.rowcount != 1:
            _reject(ResourceGovernorErrorCode.CONFLICT)
        return True

    def has_expired(self, *, tenant_id: str, now_ms: int) -> bool:
        if not identifier(tenant_id) or not bounded_nonnegative(now_ms):
            _reject(ResourceGovernorErrorCode.INVALID_REQUEST)
        row = self._connection.execute(
            """SELECT 1 FROM resource_reservations
               WHERE tenant_id=? AND state=? AND lease_expires_at_ms<=?
               LIMIT 1""",
            (tenant_id, ReservationState.RESERVED.value, now_ms),
        ).fetchone()
        return row is not None

    def has_expired_any(self, *, now_ms: int, tenant_id: str | None = None) -> bool:
        if not bounded_nonnegative(now_ms) or (tenant_id is not None and not identifier(tenant_id)):
            _reject(ResourceGovernorErrorCode.INVALID_REQUEST)
        query = """SELECT 1 FROM resource_reservations
                   WHERE state=? AND lease_expires_at_ms<=?"""
        parameters: list[object] = [ReservationState.RESERVED.value, now_ms]
        if tenant_id is not None:
            query += " AND tenant_id=?"
            parameters.append(tenant_id)
        query += " LIMIT 1"
        row = self._connection.execute(query, tuple(parameters)).fetchone()
        return row is not None

    @staticmethod
    def _require_active(row: sqlite3.Row, expected_version: int, now_ms: int) -> None:
        if row["state_version"] != expected_version:
            _reject(ResourceGovernorErrorCode.CONFLICT)
        if (
            ReservationState(row["state"]) is not ReservationState.RESERVED
            or now_ms < row["admitted_at_ms"]
            or now_ms >= row["lease_expires_at_ms"]
        ):
            _reject(ResourceGovernorErrorCode.RESERVATION_TERMINAL)

    @staticmethod
    def _load(
        cursor: sqlite3.Cursor,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        execution_identity_hash: str,
        reservation_id: str,
    ) -> sqlite3.Row:
        row: sqlite3.Row | None = cursor.execute(
            """SELECT * FROM resource_reservations
               WHERE tenant_id=? AND reservation_id=?""",
            (tenant_id, reservation_id),
        ).fetchone()
        if row is None or (
            row["repository_id"],
            row["run_id"],
            row["execution_identity_hash"],
        ) != (repository_id, run_id, execution_identity_hash):
            _reject(ResourceGovernorErrorCode.RESERVATION_UNKNOWN)
        return row


def _validated_boolean(value: object) -> bool:
    if type(value) is not bool:
        _reject(ResourceGovernorErrorCode.INVALID_REQUEST)
    return value


def _reject(code: ResourceGovernorErrorCode) -> NoReturn:
    raise ResourceGovernorError(code)


__all__ = ["ResourceRepository"]
