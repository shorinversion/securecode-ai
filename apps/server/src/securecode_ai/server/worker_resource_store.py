"""Read-only stable reservation binding for terminal worker accounting."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from typing import NoReturn

from securecode_ai.core.resource_governor import (
    ReservationState,
    ResourceReservationRequest,
    ResourceUsage,
)

from .worker_resource_models import (
    WorkerReservationBinding,
    WorkerResourceError,
    WorkerResourceErrorCode,
)

_REQUEST_KEYS = frozenset(
    {
        "request_id",
        "tenant_id",
        "repository_id",
        "run_id",
        "execution_identity_hash",
        "profile_sha256",
        "requested_tokens",
        "requested_cost_microunits",
        "requested_cpu_ms",
        "requested_memory_bytes",
        "requested_wall_ms",
        "now_ms",
        "lease_expires_at_ms",
    }
)


class SqliteWorkerReservationBindingStore:
    """Load the immutable admission binding and its durable resource state."""

    __slots__ = ("_connection",)

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        self._connection = connection
        self._connection.row_factory = sqlite3.Row

    def load(
        self,
        *,
        tenant_id: str,
        run_id: str,
        execution_identity_hash: str,
    ) -> WorkerReservationBinding:
        try:
            row = self._connection.execute(
                """SELECT
                       a.tenant_id AS admission_tenant_id,
                       a.run_id AS admission_run_id,
                       a.repository_id AS admission_repository_id,
                       a.execution_identity_hash AS admission_identity_hash,
                       a.resource_request_json,
                       a.state AS admission_state,
                       a.reservation_id AS admission_reservation_id,
                       a.reservation_version AS admission_reservation_version,
                       r.request_id,
                       r.repository_id,
                       r.run_id,
                       r.execution_identity_hash,
                       r.profile_sha256,
                       r.requested_tokens,
                       r.requested_cost_microunits,
                       r.requested_cpu_ms,
                       r.requested_memory_bytes,
                       r.requested_wall_ms,
                       r.admitted_at_ms,
                       r.lease_expires_at_ms,
                       r.state AS reservation_state,
                       r.actual_tokens,
                       r.actual_cost_microunits,
                       r.actual_cpu_ms,
                       r.actual_peak_memory_bytes,
                       r.actual_wall_ms,
                       r.state_version
                   FROM run_admissions AS a
                   JOIN resource_reservations AS r
                     ON r.tenant_id=a.tenant_id
                    AND r.reservation_id=a.reservation_id
                   WHERE a.tenant_id=? AND a.run_id=?""",
                (tenant_id, run_id),
            ).fetchone()
            return _binding(row, tenant_id, run_id, execution_identity_hash)
        except WorkerResourceError:
            raise
        except Exception:
            raise WorkerResourceError(WorkerResourceErrorCode.BINDING_UNAVAILABLE, 503) from None


def _binding(
    row: sqlite3.Row | None,
    tenant_id: str,
    run_id: str,
    execution_identity_hash: str,
) -> WorkerReservationBinding:
    if row is None:
        _unavailable()
    request = _request(row["resource_request_json"])
    try:
        state = ReservationState(row["reservation_state"])
        reservation_version = row["admission_reservation_version"]
        current_version = row["state_version"]
        reserved = ResourceUsage(
            tokens=row["requested_tokens"],
            cost_microunits=row["requested_cost_microunits"],
            cpu_ms=row["requested_cpu_ms"],
            peak_memory_bytes=row["requested_memory_bytes"],
            wall_ms=row["requested_wall_ms"],
        )
        actual = _actual(row, state)
    except Exception:
        _unavailable()
    if (
        row["admission_state"] != "ADMITTED"
        or row["admission_tenant_id"] != tenant_id
        or row["admission_run_id"] != run_id
        or row["admission_identity_hash"] != execution_identity_hash
        or row["repository_id"] != row["admission_repository_id"]
        or row["run_id"] != run_id
        or row["execution_identity_hash"] != execution_identity_hash
        or row["admission_reservation_id"] is None
        or type(reservation_version) is not int
        or reservation_version < 1
        or type(current_version) is not int
        or current_version != reservation_version + (0 if state is ReservationState.RESERVED else 1)
        or row["request_id"] != request.request_id
        or row["repository_id"] != request.repository_id
        or row["run_id"] != request.run_id
        or row["execution_identity_hash"] != request.execution_identity_hash
        or row["profile_sha256"] != request.profile_sha256
        or row["admitted_at_ms"] != request.now_ms
        or row["lease_expires_at_ms"] != request.lease_expires_at_ms
        or reserved
        != ResourceUsage(
            tokens=request.requested_tokens,
            cost_microunits=request.requested_cost_microunits,
            cpu_ms=request.requested_cpu_ms,
            peak_memory_bytes=request.requested_memory_bytes,
            wall_ms=request.requested_wall_ms,
        )
    ):
        _unavailable()
    return WorkerReservationBinding(
        tenant_id=tenant_id,
        repository_id=row["repository_id"],
        run_id=run_id,
        execution_identity_hash=execution_identity_hash,
        profile_sha256=row["profile_sha256"],
        reservation_id=row["admission_reservation_id"],
        reservation_version=reservation_version,
        reserved=reserved,
        state=state,
        actual=actual,
    )


def _request(value: object) -> ResourceReservationRequest:
    try:
        if type(value) is not str:
            _unavailable()
        document = json.loads(value)
        if not isinstance(document, Mapping) or set(document) != _REQUEST_KEYS:
            _unavailable()
        return ResourceReservationRequest(**dict(document))
    except WorkerResourceError:
        raise
    except Exception:
        _unavailable()


def _actual(row: sqlite3.Row, state: ReservationState) -> ResourceUsage | None:
    values = (
        row["actual_tokens"],
        row["actual_cost_microunits"],
        row["actual_cpu_ms"],
        row["actual_peak_memory_bytes"],
        row["actual_wall_ms"],
    )
    if state is ReservationState.COMMITTED:
        if any(type(value) is not int or value < 0 for value in values):
            _unavailable()
        return ResourceUsage(*values)
    if any(value is not None for value in values):
        _unavailable()
    return None


def _unavailable() -> NoReturn:
    raise WorkerResourceError(WorkerResourceErrorCode.BINDING_UNAVAILABLE, 503)


__all__ = ["SqliteWorkerReservationBindingStore"]
