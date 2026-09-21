"""Restart-safe SQLite journal for the run-admission saga."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Final, NoReturn

from securecode_ai.contracts import RunExecutionIdentity
from securecode_ai.core.resource_governor import (
    ReservationState,
    ResourceReservationReceipt,
    ResourceReservationRequest,
)

from .run_admission_models import (
    AdmissionError,
    AdmissionErrorCode,
    AdmissionRecord,
    AdmissionState,
    canonical,
)

RUN_ADMISSION_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS run_admissions (
        tenant_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        run_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        execution_identity_hash TEXT NOT NULL,
        execution_identity_json TEXT NOT NULL,
        resource_request_json TEXT NOT NULL,
        state TEXT NOT NULL CHECK (
            state IN ('PERSISTED', 'RESERVED', 'ADMITTED', 'FAILED',
                      'RECOVERY_REQUIRED')
        ),
        reservation_id TEXT,
        reservation_version INTEGER,
        failure_code TEXT,
        created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
        updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
        PRIMARY KEY (tenant_id, idempotency_key),
        UNIQUE (tenant_id, run_id),
        FOREIGN KEY (tenant_id, run_id)
            REFERENCES audit_runs (tenant_id, run_id),
        CHECK (
            (state = 'PERSISTED' AND reservation_id IS NULL
                AND reservation_version IS NULL)
            OR
            (state IN ('RESERVED', 'ADMITTED') AND reservation_id IS NOT NULL
                AND reservation_version IS NOT NULL)
            OR
            (state IN ('FAILED', 'RECOVERY_REQUIRED'))
        ),
        CHECK ((failure_code IS NULL) =
               (state NOT IN ('FAILED', 'RECOVERY_REQUIRED')))
    )""",
    """CREATE INDEX IF NOT EXISTS run_admissions_state_idx
       ON run_admissions (tenant_id, state, updated_at_ms)""",
)


class SqliteRunAdmissionStore:
    """Persist run intent before any resource or queue side effect."""

    __slots__ = ("_connection",)

    def __init__(self, connection: sqlite3.Connection, *, initialize: bool = False) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        if initialize:
            self.install_schema(connection)

    @staticmethod
    def install_schema(connection: sqlite3.Connection) -> None:
        """Development helper; production bootstrap should run these as migrations."""

        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        cursor = connection.cursor()
        try:
            for statement in RUN_ADMISSION_SCHEMA_STATEMENTS:
                cursor.execute(statement)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            cursor.close()

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

    def find(
        self, *, tenant_id: str, idempotency_key: str, request_sha256: str
    ) -> AdmissionRecord | None:
        row = self._connection.execute(
            """SELECT * FROM run_admissions
               WHERE tenant_id=? AND idempotency_key=?""",
            (tenant_id, idempotency_key),
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_sha256:
            _reject(AdmissionErrorCode.IDEMPOTENCY_CONFLICT, 409)
        return _record(row)

    def begin(
        self,
        *,
        tenant_id: str,
        idempotency_key: str,
        request_sha256: str,
        run_id: str,
        execution_identity: RunExecutionIdentity,
        resource_request: ResourceReservationRequest,
        metadata: Mapping[str, object],
        now_ms: int,
    ) -> AdmissionRecord:
        identity_json = canonical(execution_identity.model_dump(mode="json"))
        revision = execution_identity.repository_revision
        request_json = canonical(_request_document(resource_request))
        if (
            revision.tenant_id != tenant_id
            or resource_request.tenant_id != tenant_id
            or resource_request.repository_id != revision.repository_id
            or resource_request.run_id != run_id
            or resource_request.now_ms != now_ms
            or resource_request.execution_identity_hash
            != execution_identity.execution_identity_hash
        ):
            _reject(AdmissionErrorCode.INVALID_REQUEST, 400)
        with self._transaction() as cursor:
            existing = cursor.execute(
                """SELECT * FROM run_admissions
                   WHERE tenant_id=? AND idempotency_key=?""",
                (tenant_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                if existing["request_sha256"] != request_sha256:
                    _reject(AdmissionErrorCode.IDEMPOTENCY_CONFLICT, 409)
                if (
                    existing["run_id"],
                    existing["repository_id"],
                    existing["execution_identity_hash"],
                    existing["execution_identity_json"],
                ) != (
                    run_id,
                    revision.repository_id,
                    execution_identity.execution_identity_hash,
                    identity_json,
                ):
                    _reject(AdmissionErrorCode.RUN_CONFLICT, 409)
                return _record(existing)

            conflicting = cursor.execute(
                """SELECT execution_identity_hash FROM audit_runs
                   WHERE tenant_id=? AND run_id=?""",
                (tenant_id, run_id),
            ).fetchone()
            if conflicting is not None:
                _reject(AdmissionErrorCode.RUN_CONFLICT, 409)
            cursor.execute(
                """INSERT OR IGNORE INTO scm_repositories
                   (tenant_id, repository_id, created_at) VALUES (?, ?, ?)""",
                (tenant_id, revision.repository_id, _timestamp(now_ms)),
            )
            try:
                cursor.execute(
                    """INSERT INTO audit_runs (
                        tenant_id, run_id, repository_id,
                        execution_identity_hash, base_sha, head_sha, state,
                        version, metadata_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'ADMISSION_PENDING', 1, ?, ?, ?)""",
                    (
                        tenant_id,
                        run_id,
                        revision.repository_id,
                        execution_identity.execution_identity_hash,
                        revision.base_sha,
                        revision.head_sha,
                        canonical(dict(metadata)),
                        _timestamp(now_ms),
                        _timestamp(now_ms),
                    ),
                )
                cursor.execute(
                    """INSERT INTO run_admissions (
                        tenant_id, idempotency_key, request_sha256, run_id,
                        repository_id, execution_identity_hash,
                        execution_identity_json, resource_request_json, state,
                        reservation_id, reservation_version, failure_code,
                        created_at_ms, updated_at_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PERSISTED',
                              NULL, NULL, NULL, ?, ?)""",
                    (
                        tenant_id,
                        idempotency_key,
                        request_sha256,
                        run_id,
                        revision.repository_id,
                        execution_identity.execution_identity_hash,
                        identity_json,
                        request_json,
                        now_ms,
                        now_ms,
                    ),
                )
            except sqlite3.IntegrityError:
                _reject(AdmissionErrorCode.RUN_CONFLICT, 409)
            row = _load(cursor, tenant_id, idempotency_key)
            return _record(row)

    def reserved(
        self,
        record: AdmissionRecord,
        receipt: ResourceReservationReceipt,
        *,
        now_ms: int,
    ) -> AdmissionRecord:
        _require_receipt(record, receipt)
        with self._transaction() as cursor:
            current = _load(cursor, record.tenant_id, record.idempotency_key)
            current_record = _record(current)
            _require_same(record, current_record)
            if current_record.state in {AdmissionState.RESERVED, AdmissionState.ADMITTED}:
                if (
                    current_record.reservation_id,
                    current_record.reservation_version,
                ) != (receipt.reservation_id, receipt.state_version):
                    _reject(AdmissionErrorCode.RESOURCE_CONFLICT, 409)
                return current_record
            if current_record.state is not AdmissionState.PERSISTED:
                _reject(_terminal_code(current_record), _terminal_status(current_record))
            cursor.execute(
                """UPDATE run_admissions
                   SET state='RESERVED', reservation_id=?,
                       reservation_version=?, updated_at_ms=?
                   WHERE tenant_id=? AND idempotency_key=? AND state='PERSISTED'""",
                (
                    receipt.reservation_id,
                    receipt.state_version,
                    now_ms,
                    record.tenant_id,
                    record.idempotency_key,
                ),
            )
            if cursor.rowcount != 1:
                _reject(AdmissionErrorCode.RUN_CONFLICT, 409)
            return _record(_load(cursor, record.tenant_id, record.idempotency_key))

    def admitted(self, record: AdmissionRecord, *, now_ms: int) -> AdmissionRecord:
        with self._transaction() as cursor:
            current_record = _record(_load(cursor, record.tenant_id, record.idempotency_key))
            _require_same(record, current_record)
            if current_record.state is AdmissionState.ADMITTED:
                return current_record
            if current_record.state is not AdmissionState.RESERVED:
                _reject(_terminal_code(current_record), _terminal_status(current_record))
            cursor.execute(
                """UPDATE audit_runs
                   SET state='REQUESTED', version=version+1, updated_at=?
                   WHERE tenant_id=? AND run_id=? AND state='ADMISSION_PENDING'
                     AND execution_identity_hash=?""",
                (
                    _timestamp(now_ms),
                    record.tenant_id,
                    record.run_id,
                    record.execution_identity_hash,
                ),
            )
            if cursor.rowcount != 1:
                _reject(AdmissionErrorCode.RUN_CONFLICT, 409)
            cursor.execute(
                """UPDATE run_admissions
                   SET state='ADMITTED', updated_at_ms=?
                   WHERE tenant_id=? AND idempotency_key=? AND state='RESERVED'""",
                (now_ms, record.tenant_id, record.idempotency_key),
            )
            if cursor.rowcount != 1:
                _reject(AdmissionErrorCode.RUN_CONFLICT, 409)
            return _record(_load(cursor, record.tenant_id, record.idempotency_key))

    def failed(
        self,
        record: AdmissionRecord,
        *,
        code: AdmissionErrorCode,
        recovery_required: bool,
        now_ms: int,
    ) -> AdmissionRecord:
        target = AdmissionState.RECOVERY_REQUIRED if recovery_required else AdmissionState.FAILED
        run_state = "ADMISSION_BLOCKED" if recovery_required else "ADMISSION_FAILED"
        with self._transaction() as cursor:
            current_record = _record(_load(cursor, record.tenant_id, record.idempotency_key))
            _require_same(record, current_record)
            if current_record.state is AdmissionState.ADMITTED:
                _reject(AdmissionErrorCode.RUN_CONFLICT, 409)
            if current_record.state in {
                AdmissionState.FAILED,
                AdmissionState.RECOVERY_REQUIRED,
            }:
                return current_record
            cursor.execute(
                """UPDATE audit_runs
                   SET state=?, version=version+1, updated_at=?
                   WHERE tenant_id=? AND run_id=? AND state='ADMISSION_PENDING'
                     AND execution_identity_hash=?""",
                (
                    run_state,
                    _timestamp(now_ms),
                    record.tenant_id,
                    record.run_id,
                    record.execution_identity_hash,
                ),
            )
            if cursor.rowcount != 1:
                _reject(AdmissionErrorCode.RUN_CONFLICT, 409)
            cursor.execute(
                """UPDATE run_admissions
                   SET state=?, failure_code=?, updated_at_ms=?
                   WHERE tenant_id=? AND idempotency_key=?
                     AND state IN ('PERSISTED', 'RESERVED')""",
                (
                    target.value,
                    code.value,
                    now_ms,
                    record.tenant_id,
                    record.idempotency_key,
                ),
            )
            if cursor.rowcount != 1:
                _reject(AdmissionErrorCode.RUN_CONFLICT, 409)
            return _record(_load(cursor, record.tenant_id, record.idempotency_key))

    def run_document(self, record: AdmissionRecord) -> dict[str, object]:
        row = self._connection.execute(
            """SELECT tenant_id, run_id, repository_id,
                      execution_identity_hash, base_sha, head_sha, state, version
               FROM audit_runs WHERE tenant_id=? AND run_id=?""",
            (record.tenant_id, record.run_id),
        ).fetchone()
        if row is None:
            _reject(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503)
        return dict(row)


def _load(cursor: sqlite3.Cursor, tenant_id: str, idempotency_key: str) -> sqlite3.Row:
    row: sqlite3.Row | None = cursor.execute(
        """SELECT * FROM run_admissions
           WHERE tenant_id=? AND idempotency_key=?""",
        (tenant_id, idempotency_key),
    ).fetchone()
    if row is None:
        _reject(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503)
    return row


def _record(row: sqlite3.Row) -> AdmissionRecord:
    try:
        request_document = json.loads(row["resource_request_json"])
        resource_request = ResourceReservationRequest(**request_document)
        state = AdmissionState(row["state"])
        failure_code = (
            AdmissionErrorCode(row["failure_code"]) if row["failure_code"] is not None else None
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        _reject(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503)
    return AdmissionRecord(
        tenant_id=row["tenant_id"],
        idempotency_key=row["idempotency_key"],
        request_sha256=row["request_sha256"],
        run_id=row["run_id"],
        repository_id=row["repository_id"],
        execution_identity_hash=row["execution_identity_hash"],
        identity_json=row["execution_identity_json"],
        resource_request=resource_request,
        state=state,
        reservation_id=row["reservation_id"],
        reservation_version=row["reservation_version"],
        failure_code=failure_code,
    )


def _request_document(request: ResourceReservationRequest) -> dict[str, object]:
    return {
        "request_id": request.request_id,
        "tenant_id": request.tenant_id,
        "repository_id": request.repository_id,
        "run_id": request.run_id,
        "execution_identity_hash": request.execution_identity_hash,
        "profile_sha256": request.profile_sha256,
        "requested_tokens": request.requested_tokens,
        "requested_cost_microunits": request.requested_cost_microunits,
        "requested_cpu_ms": request.requested_cpu_ms,
        "requested_memory_bytes": request.requested_memory_bytes,
        "requested_wall_ms": request.requested_wall_ms,
        "now_ms": request.now_ms,
        "lease_expires_at_ms": request.lease_expires_at_ms,
    }


def _require_receipt(record: AdmissionRecord, receipt: ResourceReservationReceipt) -> None:
    request = record.resource_request
    if (
        receipt.state is not ReservationState.RESERVED
        or receipt.tenant_id != record.tenant_id
        or receipt.repository_id != record.repository_id
        or receipt.run_id != record.run_id
        or receipt.execution_identity_hash != record.execution_identity_hash
        or receipt.profile_sha256 != request.profile_sha256
        or receipt.lease_expires_at_ms != request.lease_expires_at_ms
        or receipt.reserved.tokens != request.requested_tokens
        or receipt.reserved.cost_microunits != request.requested_cost_microunits
        or receipt.reserved.cpu_ms != request.requested_cpu_ms
        or receipt.reserved.peak_memory_bytes != request.requested_memory_bytes
        or receipt.reserved.wall_ms != request.requested_wall_ms
        or receipt.actual is not None
        or receipt.state_version < 1
    ):
        _reject(AdmissionErrorCode.RESOURCE_CONFLICT, 409)


def _require_same(expected: AdmissionRecord, actual: AdmissionRecord) -> None:
    if (
        expected.tenant_id,
        expected.idempotency_key,
        expected.request_sha256,
        expected.run_id,
        expected.repository_id,
        expected.execution_identity_hash,
        expected.identity_json,
    ) != (
        actual.tenant_id,
        actual.idempotency_key,
        actual.request_sha256,
        actual.run_id,
        actual.repository_id,
        actual.execution_identity_hash,
        actual.identity_json,
    ):
        _reject(AdmissionErrorCode.RUN_CONFLICT, 409)


def _terminal_code(record: AdmissionRecord) -> AdmissionErrorCode:
    return record.failure_code or AdmissionErrorCode.RUN_CONFLICT


def _terminal_status(record: AdmissionRecord) -> int:
    if record.state is AdmissionState.RECOVERY_REQUIRED:
        return 503
    if record.failure_code in {
        AdmissionErrorCode.RESOURCE_QUOTA_EXCEEDED,
        AdmissionErrorCode.RESOURCE_RATE_LIMITED,
        AdmissionErrorCode.RESOURCE_CONCURRENCY_EXCEEDED,
    }:
        return 429
    if record.failure_code in {
        AdmissionErrorCode.IDEMPOTENCY_CONFLICT,
        AdmissionErrorCode.RUN_CONFLICT,
        AdmissionErrorCode.RESOURCE_CONFLICT,
    }:
        return 409
    return 503


def _timestamp(now_ms: int) -> str:
    try:
        return datetime.fromtimestamp(now_ms / 1000, UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        _reject(AdmissionErrorCode.INVALID_REQUEST, 400)


def _reject(code: AdmissionErrorCode, status: int) -> NoReturn:
    raise AdmissionError(code, status)


__all__ = ["RUN_ADMISSION_SCHEMA_STATEMENTS", "SqliteRunAdmissionStore"]
