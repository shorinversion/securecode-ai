"""Durable tenant resource admission and usage accounting for SQLite."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
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
        try:
            cursor.execute("BEGIN IMMEDIATE")
            yield cursor
            self._connection.commit()
        except Exception:
            self._connection.rollback()
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
                   WHERE tenant_id=? AND state=?""",
                (request.tenant_id, ReservationState.RESERVED.value),
            ).fetchone()[0]
            if active >= limits.max_concurrent_runs:
                _reject(ResourceGovernorErrorCode.CONCURRENCY_EXCEEDED)

            lower = request.now_ms - limits.admission_window_ms
            events = cursor.execute(
                """SELECT reserved_tokens, reserved_cost_microunits
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
                window_tokens += event["reserved_tokens"]
                window_cost += event["reserved_cost_microunits"]
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

    def expire(self, *, tenant_id: str, now_ms: int) -> int:
        if not identifier(tenant_id) or not bounded_nonnegative(now_ms):
            _reject(ResourceGovernorErrorCode.INVALID_REQUEST)
        with self._transaction() as cursor:
            return self._expire(cursor, tenant_id, now_ms)

    @staticmethod
    def _expire(cursor: sqlite3.Cursor, tenant_id: str, now_ms: int) -> int:
        cursor.execute(
            """UPDATE resource_reservations
               SET state=?, state_version=state_version+1,
                   terminal_at_ms=lease_expires_at_ms
               WHERE tenant_id=? AND state=? AND lease_expires_at_ms<=?""",
            (
                ReservationState.RELEASED.value,
                tenant_id,
                ReservationState.RESERVED.value,
                now_ms,
            ),
        )
        return cursor.rowcount

    @staticmethod
    def _require_active(row: sqlite3.Row, expected_version: int, now_ms: int) -> None:
        if row["state_version"] != expected_version:
            _reject(ResourceGovernorErrorCode.CONFLICT)
        if (
            ReservationState(row["state"]) is not ReservationState.RESERVED
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
