"""SQLite schema, validation, and serialization for resource accounting."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from typing import Final

from securecode_ai.core.resource_governor import (
    ReservationState,
    ResourceGovernorError,
    ResourceGovernorErrorCode,
    ResourceReservationReceipt,
    ResourceReservationRequest,
    ResourceUsage,
    TenantResourceLimits,
)

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/resource-governor/v1\x00"
_SQLITE_INTEGER_MAX: Final = 9_223_372_036_854_775_807

SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS resource_limit_profiles (
        tenant_id TEXT NOT NULL,
        profile_id TEXT NOT NULL,
        profile_sha256 TEXT NOT NULL,
        max_concurrent_runs INTEGER NOT NULL CHECK (max_concurrent_runs > 0),
        max_admissions_per_window INTEGER NOT NULL
            CHECK (max_admissions_per_window > 0),
        admission_window_ms INTEGER NOT NULL CHECK (admission_window_ms > 0),
        max_tokens_per_window INTEGER NOT NULL CHECK (max_tokens_per_window > 0),
        max_cost_microunits_per_window INTEGER NOT NULL
            CHECK (max_cost_microunits_per_window > 0),
        max_cpu_ms_per_run INTEGER NOT NULL CHECK (max_cpu_ms_per_run > 0),
        max_memory_bytes_per_run INTEGER NOT NULL CHECK (max_memory_bytes_per_run > 0),
        max_wall_ms_per_run INTEGER NOT NULL CHECK (max_wall_ms_per_run > 0),
        PRIMARY KEY (tenant_id, profile_sha256),
        UNIQUE (tenant_id, profile_id)
    )""",
    """CREATE TABLE IF NOT EXISTS resource_tenant_limits (
        tenant_id TEXT NOT NULL PRIMARY KEY,
        profile_sha256 TEXT NOT NULL,
        FOREIGN KEY (tenant_id, profile_sha256)
            REFERENCES resource_limit_profiles (tenant_id, profile_sha256)
    )""",
    """CREATE TABLE IF NOT EXISTS resource_reservations (
        tenant_id TEXT NOT NULL,
        reservation_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        execution_identity_hash TEXT NOT NULL,
        profile_sha256 TEXT NOT NULL,
        requested_tokens INTEGER NOT NULL CHECK (requested_tokens >= 0),
        requested_cost_microunits INTEGER NOT NULL
            CHECK (requested_cost_microunits >= 0),
        requested_cpu_ms INTEGER NOT NULL CHECK (requested_cpu_ms >= 0),
        requested_memory_bytes INTEGER NOT NULL CHECK (requested_memory_bytes >= 0),
        requested_wall_ms INTEGER NOT NULL CHECK (requested_wall_ms >= 0),
        admitted_at_ms INTEGER NOT NULL CHECK (admitted_at_ms >= 0),
        lease_expires_at_ms INTEGER NOT NULL CHECK (lease_expires_at_ms >= 0),
        state TEXT NOT NULL
            CHECK (state IN ('RESERVED', 'COMMITTED', 'RELEASED', 'CANCELLED')),
        actual_tokens INTEGER CHECK (actual_tokens >= 0),
        actual_cost_microunits INTEGER CHECK (actual_cost_microunits >= 0),
        actual_cpu_ms INTEGER CHECK (actual_cpu_ms >= 0),
        actual_peak_memory_bytes INTEGER CHECK (actual_peak_memory_bytes >= 0),
        actual_wall_ms INTEGER CHECK (actual_wall_ms >= 0),
        state_version INTEGER NOT NULL CHECK (state_version > 0),
        terminal_at_ms INTEGER CHECK (terminal_at_ms >= 0),
        PRIMARY KEY (tenant_id, reservation_id),
        UNIQUE (tenant_id, request_id),
        UNIQUE (tenant_id, repository_id, run_id, execution_identity_hash),
        FOREIGN KEY (tenant_id, profile_sha256)
            REFERENCES resource_limit_profiles (tenant_id, profile_sha256),
        CHECK (
            (state = 'COMMITTED'
                AND actual_tokens IS NOT NULL
                AND actual_cost_microunits IS NOT NULL
                AND actual_cpu_ms IS NOT NULL
                AND actual_peak_memory_bytes IS NOT NULL
                AND actual_wall_ms IS NOT NULL
                AND terminal_at_ms IS NOT NULL)
            OR
            (state != 'COMMITTED'
                AND actual_tokens IS NULL
                AND actual_cost_microunits IS NULL
                AND actual_cpu_ms IS NULL
                AND actual_peak_memory_bytes IS NULL
                AND actual_wall_ms IS NULL)
        ),
        CHECK ((state = 'RESERVED') = (terminal_at_ms IS NULL))
    )""",
    """CREATE TABLE IF NOT EXISTS resource_admissions (
        tenant_id TEXT NOT NULL,
        reservation_id TEXT NOT NULL,
        admitted_at_ms INTEGER NOT NULL CHECK (admitted_at_ms >= 0),
        reserved_tokens INTEGER NOT NULL CHECK (reserved_tokens >= 0),
        reserved_cost_microunits INTEGER NOT NULL
            CHECK (reserved_cost_microunits >= 0),
        PRIMARY KEY (tenant_id, reservation_id),
        FOREIGN KEY (tenant_id, reservation_id)
            REFERENCES resource_reservations (tenant_id, reservation_id)
    )""",
    """CREATE INDEX IF NOT EXISTS resource_active_reservations_idx
       ON resource_reservations (tenant_id, state, lease_expires_at_ms)""",
    """CREATE INDEX IF NOT EXISTS resource_admission_window_idx
       ON resource_admissions (tenant_id, admitted_at_ms)""",
)


def validate_limits(limits: TenantResourceLimits) -> None:
    if type(limits) is not TenantResourceLimits:
        _reject(ResourceGovernorErrorCode.INVALID_REQUEST)
    for value in limit_values(limits)[3:]:
        if not bounded_positive(value):
            _reject(ResourceGovernorErrorCode.INVALID_REQUEST)


def validate_request(request: ResourceReservationRequest) -> None:
    if type(request) is not ResourceReservationRequest:
        _reject(ResourceGovernorErrorCode.INVALID_REQUEST)
    for value in (
        request.requested_tokens,
        request.requested_cost_microunits,
        request.requested_cpu_ms,
        request.requested_memory_bytes,
        request.requested_wall_ms,
        request.now_ms,
        request.lease_expires_at_ms,
    ):
        if not bounded_nonnegative(value):
            _reject(ResourceGovernorErrorCode.INVALID_REQUEST)


def validate_usage(usage: ResourceUsage) -> None:
    if type(usage) is not ResourceUsage:
        _reject(ResourceGovernorErrorCode.INVALID_REQUEST)
    for value in (
        usage.tokens,
        usage.cost_microunits,
        usage.cpu_ms,
        usage.peak_memory_bytes,
        usage.wall_ms,
    ):
        if not bounded_nonnegative(value):
            _reject(ResourceGovernorErrorCode.INVALID_REQUEST)


def validate_binding(
    tenant_id: str,
    repository_id: str,
    run_id: str,
    execution_identity_hash: str,
    reservation_id: str,
) -> None:
    if (
        not identifier(tenant_id)
        or not identifier(repository_id)
        or not identifier(run_id)
        or not identifier(reservation_id)
        or not sha256(execution_identity_hash)
    ):
        _reject(ResourceGovernorErrorCode.INVALID_REQUEST)


def validate_transition(expected_version: int, now_ms: int) -> None:
    if not bounded_positive(expected_version) or not bounded_nonnegative(now_ms):
        _reject(ResourceGovernorErrorCode.INVALID_REQUEST)


def bounded_positive(value: object) -> bool:
    return type(value) is int and 0 < value <= _SQLITE_INTEGER_MAX


def bounded_nonnegative(value: object) -> bool:
    return type(value) is int and 0 <= value <= _SQLITE_INTEGER_MAX


def identifier(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def limit_values(limits: TenantResourceLimits) -> tuple[object, ...]:
    return (
        limits.tenant_id,
        limits.profile_id,
        limits.profile_sha256,
        limits.max_concurrent_runs,
        limits.max_admissions_per_window,
        limits.admission_window_ms,
        limits.max_tokens_per_window,
        limits.max_cost_microunits_per_window,
        limits.max_cpu_ms_per_run,
        limits.max_memory_bytes_per_run,
        limits.max_wall_ms_per_run,
    )


def limits_from_row(row: sqlite3.Row) -> TenantResourceLimits:
    return TenantResourceLimits(
        tenant_id=row["tenant_id"],
        profile_id=row["profile_id"],
        profile_sha256=row["profile_sha256"],
        max_concurrent_runs=row["max_concurrent_runs"],
        max_admissions_per_window=row["max_admissions_per_window"],
        admission_window_ms=row["admission_window_ms"],
        max_tokens_per_window=row["max_tokens_per_window"],
        max_cost_microunits_per_window=row["max_cost_microunits_per_window"],
        max_cpu_ms_per_run=row["max_cpu_ms_per_run"],
        max_memory_bytes_per_run=row["max_memory_bytes_per_run"],
        max_wall_ms_per_run=row["max_wall_ms_per_run"],
    )


def request_hash(request: ResourceReservationRequest) -> str:
    material = {
        "execution_identity_hash": request.execution_identity_hash,
        "lease_expires_at_ms": request.lease_expires_at_ms,
        "now_ms": request.now_ms,
        "profile_sha256": request.profile_sha256,
        "repository_id": request.repository_id,
        "requested_cost_microunits": request.requested_cost_microunits,
        "requested_cpu_ms": request.requested_cpu_ms,
        "requested_memory_bytes": request.requested_memory_bytes,
        "requested_tokens": request.requested_tokens,
        "requested_wall_ms": request.requested_wall_ms,
        "run_id": request.run_id,
        "tenant_id": request.tenant_id,
    }
    payload = json.dumps(
        material,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(_HASH_DOMAIN + payload).hexdigest()


def reserved_usage(row: sqlite3.Row) -> ResourceUsage:
    return ResourceUsage(
        tokens=row["requested_tokens"],
        cost_microunits=row["requested_cost_microunits"],
        cpu_ms=row["requested_cpu_ms"],
        peak_memory_bytes=row["requested_memory_bytes"],
        wall_ms=row["requested_wall_ms"],
    )


def actual_usage(row: sqlite3.Row) -> ResourceUsage | None:
    if row["actual_tokens"] is None:
        return None
    return ResourceUsage(
        tokens=row["actual_tokens"],
        cost_microunits=row["actual_cost_microunits"],
        cpu_ms=row["actual_cpu_ms"],
        peak_memory_bytes=row["actual_peak_memory_bytes"],
        wall_ms=row["actual_wall_ms"],
    )


def receipt_from_row(row: sqlite3.Row, *, idempotent: bool) -> ResourceReservationReceipt:
    return ResourceReservationReceipt(
        reservation_id=row["reservation_id"],
        tenant_id=row["tenant_id"],
        repository_id=row["repository_id"],
        run_id=row["run_id"],
        execution_identity_hash=row["execution_identity_hash"],
        profile_sha256=row["profile_sha256"],
        state=ReservationState(row["state"]),
        reserved=reserved_usage(row),
        actual=actual_usage(row),
        lease_expires_at_ms=row["lease_expires_at_ms"],
        state_version=row["state_version"],
        idempotent=idempotent,
    )


def _reject(code: ResourceGovernorErrorCode) -> None:
    raise ResourceGovernorError(code)


__all__ = [
    "SCHEMA_STATEMENTS",
    "actual_usage",
    "bounded_nonnegative",
    "identifier",
    "limit_values",
    "limits_from_row",
    "receipt_from_row",
    "request_hash",
    "validate_binding",
    "validate_limits",
    "validate_request",
    "validate_transition",
    "validate_usage",
]
