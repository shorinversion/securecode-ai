"""Authenticated backup and restore control-plane operations."""

from __future__ import annotations

import sqlite3
from dataclasses import asdict
from threading import RLock
from typing import Final

from .backup_repository import BackupConflict, BackupRecord, validate_backup_record
from .backup_service import BackupExecutorUnavailable, BackupReceipt, BackupService
from .operations_handler_common import (
    CONFLICT,
    FORBIDDEN,
    INVALID_REQUEST,
    NOT_FOUND,
    PRECONDITION_FAILED,
    document,
    error,
    expected_version,
    matches_tenant,
    path_identifier,
    path_value,
    repository_allowed,
    response,
    string,
)
from .ports import ServiceRequest, ServiceResponse

BACKUP_SCOPE_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS backup_repository_scopes (
        tenant_id TEXT NOT NULL,
        backup_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        PRIMARY KEY (tenant_id, backup_id)
    )""",
)


class BackupScopeRepository:
    """Bind each backup to one tenant and repository."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        self._db = connection
        self._lock = RLock()
        for statement in BACKUP_SCOPE_SCHEMA_STATEMENTS:
            self._db.execute(statement)
        self._db.commit()

    def bind(self, *, tenant_id: str, backup_id: str, repository_id: str) -> None:
        with self._lock:
            row = self._db.execute(
                """SELECT repository_id FROM backup_repository_scopes
                   WHERE tenant_id=? AND backup_id=?""",
                (tenant_id, backup_id),
            ).fetchone()
            if row is not None:
                if str(row[0]) != repository_id:
                    raise BackupConflict("backup scope conflicts")
                return
            try:
                self._db.execute(
                    """INSERT INTO backup_repository_scopes (
                           tenant_id, backup_id, repository_id
                       ) VALUES (?, ?, ?)""",
                    (tenant_id, backup_id, repository_id),
                )
                self._db.commit()
            except sqlite3.IntegrityError as failure:
                self._db.rollback()
                raise BackupConflict("backup scope conflicts") from failure

    def repository(self, *, tenant_id: str, backup_id: str) -> str | None:
        with self._lock:
            row = self._db.execute(
                """SELECT repository_id FROM backup_repository_scopes
                   WHERE tenant_id=? AND backup_id=?""",
                (tenant_id, backup_id),
            ).fetchone()
        return None if row is None else str(row[0])


class BackupOperationsHandler:
    """Expose verified receipts while keeping encryption key references private."""

    def __init__(
        self,
        service: BackupService,
        scopes: BackupScopeRepository,
        *,
        executor_available: bool,
    ) -> None:
        if not isinstance(service, BackupService) or not isinstance(scopes, BackupScopeRepository):
            raise TypeError("backup operation dependencies are invalid")
        if type(executor_available) is not bool:
            raise TypeError("executor_available must be a bool")
        self._service = service
        self._scopes = scopes
        self._executor_available = executor_available

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if "admin" not in request.identity.roles:
            return FORBIDDEN
        handlers = {
            "backups.create": self._create,
            "backups.read": self._read,
            "backups.execute": self._execute,
            "backups.restore": self._restore,
        }
        handler = handlers.get(request.action)
        if handler is None:
            return error(503, "HANDLER_UNAVAILABLE", "requested handler is unavailable")
        return handler(request)

    def _create(self, request: ServiceRequest) -> ServiceResponse:
        value = document(
            request,
            required=frozenset(
                {
                    "backup_id",
                    "repository_id",
                    "component_hashes",
                    "region",
                    "encryption_key_ref",
                }
            ),
            optional=frozenset({"tenant_id"}),
        )
        if value is None or not matches_tenant(value, request.identity):
            return INVALID_REQUEST
        backup_id = path_identifier(value, "backup_id")
        repository_id = string(value, "repository_id")
        region = string(value, "region", maximum=128)
        key_ref = string(value, "encryption_key_ref", maximum=512)
        component_hashes = _component_hashes(value.get("component_hashes"))
        if None in (backup_id, repository_id, region, key_ref, component_hashes):
            return INVALID_REQUEST
        assert backup_id and repository_id and region and key_ref
        assert component_hashes is not None
        if not repository_allowed(request.identity, repository_id):
            return FORBIDDEN
        try:
            scoped_repository = self._scopes.repository(
                tenant_id=request.identity.tenant_id,
                backup_id=backup_id,
            )
            if scoped_repository is not None and scoped_repository != repository_id:
                raise BackupConflict("backup scope conflicts")
            record = BackupRecord(
                tenant_id=request.identity.tenant_id,
                backup_id=backup_id,
                component_hashes=component_hashes,
                region=region,
                encryption_key_ref=key_ref,
                version=1,
                state="PLANNED",
            )
            validate_backup_record(record)
            planned = self._service.plan(
                record,
                idempotency_key=request.idempotency_key,
            )
            self._scopes.bind(
                tenant_id=planned.tenant_id,
                backup_id=planned.backup_id,
                repository_id=repository_id,
            )
            receipt = self._service.receipt(
                tenant_id=planned.tenant_id,
                backup_id=planned.backup_id,
            )
        except (BackupConflict, TypeError, ValueError):
            return CONFLICT
        return response(
            201,
            _receipt_document(receipt, repository_id),
            version=receipt.version,
        )

    def _read(self, request: ServiceRequest) -> ServiceResponse:
        scoped = self._scoped_backup(request)
        if isinstance(scoped, ServiceResponse):
            return scoped
        backup_id, repository_id = scoped
        try:
            receipt = self._service.receipt(
                tenant_id=request.identity.tenant_id,
                backup_id=backup_id,
            )
        except (BackupConflict, TypeError, ValueError):
            return NOT_FOUND
        return response(
            200,
            _receipt_document(receipt, repository_id),
            version=receipt.version,
        )

    def _execute(self, request: ServiceRequest) -> ServiceResponse:
        return self._transition(request, restore=False)

    def _restore(self, request: ServiceRequest) -> ServiceResponse:
        return self._transition(request, restore=True)

    def _transition(self, request: ServiceRequest, *, restore: bool) -> ServiceResponse:
        if not self._executor_available:
            return error(
                503,
                "BACKUP_EXECUTOR_UNAVAILABLE",
                "backup executor is unavailable",
            )
        if document(request, required=frozenset()) is None:
            return INVALID_REQUEST
        version = expected_version(request)
        if version is None:
            return PRECONDITION_FAILED
        scoped = self._scoped_backup(request)
        if isinstance(scoped, ServiceResponse):
            return scoped
        backup_id, repository_id = scoped
        try:
            if restore:
                record = self._service.complete_restore(
                    request.identity.tenant_id,
                    backup_id,
                    version,
                    idempotency_key=request.idempotency_key,
                )
            else:
                record = self._service.complete_backup(
                    request.identity.tenant_id,
                    backup_id,
                    version,
                    idempotency_key=request.idempotency_key,
                )
            receipt = self._service.receipt(
                tenant_id=record.tenant_id,
                backup_id=record.backup_id,
            )
        except BackupExecutorUnavailable:
            return error(
                503,
                "BACKUP_EXECUTOR_UNAVAILABLE",
                "backup executor is unavailable",
            )
        except (BackupConflict, TypeError, ValueError):
            return CONFLICT
        return response(
            200,
            _receipt_document(receipt, repository_id),
            version=receipt.version,
        )

    def _scoped_backup(self, request: ServiceRequest) -> tuple[str, str] | ServiceResponse:
        backup_id = path_value(request, "backup_id")
        if backup_id is None:
            return INVALID_REQUEST
        repository_id = self._scopes.repository(
            tenant_id=request.identity.tenant_id,
            backup_id=backup_id,
        )
        if repository_id is None:
            return NOT_FOUND
        if not repository_allowed(request.identity, repository_id):
            return FORBIDDEN
        return backup_id, repository_id


def _component_hashes(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list) or not 1 <= len(value) <= 10_000:
        return None
    if any(
        type(item) is not str
        or len(item) != 64
        or any(character not in "0123456789abcdef" for character in item)
        for item in value
    ):
        return None
    result = tuple(value)
    return result if len(set(result)) == len(result) else None


def _receipt_document(receipt: BackupReceipt, repository_id: str) -> dict[str, object]:
    value = asdict(receipt)
    value["repository_id"] = repository_id
    return value


__all__ = [
    "BACKUP_SCOPE_SCHEMA_STATEMENTS",
    "BackupOperationsHandler",
    "BackupScopeRepository",
]
