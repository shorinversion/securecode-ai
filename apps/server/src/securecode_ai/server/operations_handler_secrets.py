"""Authenticated control-plane operations for ephemeral secret grants."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import asdict
from threading import RLock
from typing import Final

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
    path_value,
    repository_allowed,
    response,
    string,
)
from .ports import ServiceRequest, ServiceResponse
from .secret_service import SecretDenied, SecretReceipt, SecretService

SECRET_GRANT_SCOPE_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS secret_grant_repository_scopes (
        tenant_id TEXT NOT NULL,
        grant_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        PRIMARY KEY (tenant_id, grant_id)
    )""",
)
_SCOPE_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}\Z")


class SecretGrantScopeRepository:
    """Bind a source-free grant receipt to its authorized repository."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        self._db = connection
        self._lock = RLock()
        for statement in SECRET_GRANT_SCOPE_SCHEMA_STATEMENTS:
            self._db.execute(statement)
        self._db.commit()

    def bind(self, *, tenant_id: str, grant_id: str, repository_id: str) -> None:
        _validate_scope_identity(tenant_id, "tenant_id")
        _validate_scope_identity(grant_id, "grant_id")
        _validate_scope_identity(repository_id, "repository_id")
        with self._lock:
            grant = self._db.execute(
                """SELECT 1 FROM secret_grants
                   WHERE tenant_id=? AND grant_id=?""",
                (tenant_id, grant_id),
            ).fetchone()
            if grant is None:
                raise SecretDenied("GRANT_UNKNOWN")
            row = self._db.execute(
                """SELECT repository_id FROM secret_grant_repository_scopes
                   WHERE tenant_id=? AND grant_id=?""",
                (tenant_id, grant_id),
            ).fetchone()
            if row is not None:
                if str(row[0]) != repository_id:
                    raise SecretDenied("GRANT_SCOPE_CONFLICT")
                return
            try:
                self._db.execute(
                    """INSERT INTO secret_grant_repository_scopes (
                           tenant_id, grant_id, repository_id
                       ) VALUES (?, ?, ?)""",
                    (tenant_id, grant_id, repository_id),
                )
                self._db.commit()
            except sqlite3.IntegrityError as failure:
                self._db.rollback()
                raise SecretDenied("GRANT_SCOPE_CONFLICT") from failure

    def repository(self, *, tenant_id: str, grant_id: str) -> str | None:
        _validate_scope_identity(tenant_id, "tenant_id")
        _validate_scope_identity(grant_id, "grant_id")
        with self._lock:
            row = self._db.execute(
                """SELECT repository_id FROM secret_grant_repository_scopes
                   WHERE tenant_id=? AND grant_id=?""",
                (tenant_id, grant_id),
            ).fetchone()
        if row is None:
            return None
        repository_id = row[0]
        if type(repository_id) is not str or _SCOPE_IDENTIFIER.fullmatch(repository_id) is None:
            raise SecretDenied("GRANT_SCOPE_INVALID")
        return repository_id


class SecretOperationsHandler:
    """Issue and manage leases without exposing handles or provider references."""

    def __init__(
        self,
        service: SecretService,
        scopes: SecretGrantScopeRepository,
        *,
        provider_available: bool,
    ) -> None:
        if not isinstance(service, SecretService) or not isinstance(
            scopes, SecretGrantScopeRepository
        ):
            raise TypeError("secret operation dependencies are invalid")
        if type(provider_available) is not bool:
            raise TypeError("provider_available must be a bool")
        self._service = service
        self._scopes = scopes
        self._provider_available = provider_available

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if "admin" not in request.identity.roles:
            return FORBIDDEN
        if not self._provider_available and request.action in {"secrets.grant", "secrets.rotate"}:
            return _provider_unavailable()
        if self._provider_available and request.action.startswith("secrets."):
            try:
                self._service.expire(tenant_id=request.identity.tenant_id)
            except SecretDenied as failure:
                if request.action != "secrets.read" and failure.code != "PROVIDER_UNAVAILABLE":
                    return _provider_unavailable()
        handlers = {
            "secrets.grant": self._grant,
            "secrets.read": self._read,
            "secrets.rotate": self._rotate,
            "secrets.revoke": self._revoke,
        }
        handler = handlers.get(request.action)
        if handler is None:
            return error(503, "HANDLER_UNAVAILABLE", "requested handler is unavailable")
        return handler(request)

    def _grant(self, request: ServiceRequest) -> ServiceResponse:
        value = document(
            request,
            required=frozenset({"repository_id", "workload_id", "reference", "purpose"}),
            optional=frozenset({"tenant_id"}),
        )
        if value is None or not matches_tenant(value, request.identity):
            return INVALID_REQUEST
        repository_id = string(value, "repository_id")
        workload_id = string(value, "workload_id")
        reference = string(value, "reference", maximum=2048)
        purpose = string(value, "purpose", maximum=64)
        if None in (repository_id, workload_id, reference, purpose):
            return INVALID_REQUEST
        assert repository_id and workload_id and reference and purpose
        if not repository_allowed(request.identity, repository_id):
            return FORBIDDEN
        try:
            _grant, receipt = self._service.grant(
                tenant_id=request.identity.tenant_id,
                workload_id=workload_id,
                reference=reference,
                purpose=purpose,
                idempotency_key=request.idempotency_key or "",
            )
        except SecretDenied as failure:
            return _secret_failure(failure)
        if receipt.state != "ACTIVE":
            return CONFLICT
        try:
            self._scopes.bind(
                tenant_id=request.identity.tenant_id,
                grant_id=receipt.grant_id,
                repository_id=repository_id,
            )
        except SecretDenied:
            if _grant is not None:
                try:
                    self._service.revoke(
                        receipt.grant_id,
                        tenant_id=request.identity.tenant_id,
                        expected_version=receipt.version,
                    )
                except SecretDenied:
                    return _provider_unavailable()
            return CONFLICT
        return response(
            201,
            _receipt_document(receipt, repository_id),
            version=receipt.version,
        )

    def _read(self, request: ServiceRequest) -> ServiceResponse:
        scoped = self._scoped_grant(request)
        if isinstance(scoped, ServiceResponse):
            return scoped
        grant_id, repository_id = scoped
        try:
            receipt = self._service.receipt(
                tenant_id=request.identity.tenant_id,
                grant_id=grant_id,
            )
        except SecretDenied:
            return NOT_FOUND
        return response(
            200,
            _receipt_document(receipt, repository_id),
            version=receipt.version,
        )

    def _rotate(self, request: ServiceRequest) -> ServiceResponse:
        value = document(
            request,
            required=frozenset({"workload_id", "reference", "purpose"}),
        )
        version = expected_version(request)
        if value is None:
            return INVALID_REQUEST
        if version is None:
            return PRECONDITION_FAILED
        workload_id = string(value, "workload_id")
        reference = string(value, "reference", maximum=2048)
        purpose = string(value, "purpose", maximum=64)
        if None in (workload_id, reference, purpose):
            return INVALID_REQUEST
        scoped = self._scoped_grant(request)
        if isinstance(scoped, ServiceResponse):
            return scoped
        grant_id, repository_id = scoped
        try:
            _grant, receipt = self._service.rotate(
                tenant_id=request.identity.tenant_id,
                workload_id=workload_id or "",
                reference=reference or "",
                purpose=purpose or "",
                previous_grant_id=grant_id,
                expected_version=version,
                idempotency_key=request.idempotency_key or "",
            )
        except SecretDenied as failure:
            return _secret_failure(failure)
        if receipt.state != "ACTIVE":
            return CONFLICT
        try:
            self._scopes.bind(
                tenant_id=request.identity.tenant_id,
                grant_id=receipt.grant_id,
                repository_id=repository_id,
            )
        except SecretDenied:
            if _grant is not None:
                try:
                    self._service.revoke(
                        receipt.grant_id,
                        tenant_id=request.identity.tenant_id,
                        expected_version=receipt.version,
                    )
                except SecretDenied:
                    return _provider_unavailable()
            return CONFLICT
        return response(
            201,
            _receipt_document(receipt, repository_id),
            version=receipt.version,
        )

    def _revoke(self, request: ServiceRequest) -> ServiceResponse:
        if document(request, required=frozenset()) is None:
            return INVALID_REQUEST
        version = expected_version(request)
        if version is None:
            return PRECONDITION_FAILED
        scoped = self._scoped_grant(request)
        if isinstance(scoped, ServiceResponse):
            return scoped
        grant_id, repository_id = scoped
        try:
            receipt = self._service.revoke(
                grant_id,
                tenant_id=request.identity.tenant_id,
                expected_version=version,
                idempotency_key=request.idempotency_key,
            )
        except SecretDenied as failure:
            return _secret_failure(failure)
        return response(
            200,
            _receipt_document(receipt, repository_id),
            version=receipt.version,
        )

    def _scoped_grant(self, request: ServiceRequest) -> tuple[str, str] | ServiceResponse:
        grant_id = path_value(request, "grant_id")
        if grant_id is None:
            return INVALID_REQUEST
        repository_id = self._scopes.repository(
            tenant_id=request.identity.tenant_id,
            grant_id=grant_id,
        )
        if repository_id is None:
            return NOT_FOUND
        if not repository_allowed(request.identity, repository_id):
            return FORBIDDEN
        return grant_id, repository_id


def _receipt_document(receipt: SecretReceipt, repository_id: str) -> dict[str, object]:
    value = asdict(receipt)
    value["repository_id"] = repository_id
    return value


def _secret_failure(failure: SecretDenied) -> ServiceResponse:
    if failure.code in {
        "PROVIDER_UNAVAILABLE",
        "INVALID_PROVIDER_LEASE",
        "EXPIRED_PROVIDER_LEASE",
    }:
        return _provider_unavailable()
    if failure.code in {"VERSION_CONFLICT", "ROTATION_PRECONDITION_FAILED"}:
        return PRECONDITION_FAILED
    if failure.code in {"GRANT_UNKNOWN", "GRANT_NOT_ACTIVE"}:
        return NOT_FOUND
    return CONFLICT


def _provider_unavailable() -> ServiceResponse:
    return error(
        503,
        "SECRET_PROVIDER_UNAVAILABLE",
        "secret provider is unavailable",
    )


def _validate_scope_identity(value: object, field: str) -> None:
    if type(value) is not str or _SCOPE_IDENTIFIER.fullmatch(value) is None:
        raise SecretDenied(f"INVALID_{field.upper()}")


__all__ = [
    "SECRET_GRANT_SCOPE_SCHEMA_STATEMENTS",
    "SecretGrantScopeRepository",
    "SecretOperationsHandler",
]
