"""HTTP handlers for approvals and tenant-scoped data lifecycle controls."""

from __future__ import annotations

import sqlite3
from threading import RLock
from typing import Final, cast

from .approvals import (
    ApprovalConflict,
    ApprovalLedger,
    ApprovalRequest,
)
from .data_lifecycle import LifecycleLedger
from .data_lifecycle_models import DeletionRequest, LifecycleConflict
from .operations_handler_common import (
    CONFLICT,
    FORBIDDEN,
    INVALID_REQUEST,
    NOT_FOUND,
    PRECONDITION_FAILED,
    boolean,
    document,
    error,
    expected_version,
    matches_tenant,
    path_identifier,
    path_value,
    repository_allowed,
    response,
    string,
    utc_datetime,
)
from .ports import ServiceRequest, ServiceResponse

LIFECYCLE_SCOPE_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS lifecycle_repository_scopes (
        deletion_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        PRIMARY KEY (tenant_id, deletion_id),
        UNIQUE (tenant_id, repository_id, deletion_id),
        FOREIGN KEY (tenant_id, deletion_id)
            REFERENCES lifecycle_deletions (tenant_id, deletion_id)
    )""",
)


class LifecycleScopeRepository:
    """Bind deletion controls to a repository without widening lifecycle storage."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        self._db = connection
        self._lock = RLock()
        for statement in LIFECYCLE_SCOPE_SCHEMA_STATEMENTS:
            self._db.execute(statement)
        self._db.commit()

    def bind(self, *, deletion_id: str, tenant_id: str, repository_id: str) -> None:
        with self._lock:
            row = self._db.execute(
                """SELECT tenant_id, repository_id
                   FROM lifecycle_repository_scopes
                   WHERE tenant_id=? AND deletion_id=?""",
                (tenant_id, deletion_id),
            ).fetchone()
            if row is not None:
                if (str(row[0]), str(row[1])) != (tenant_id, repository_id):
                    raise LifecycleConflict("deletion scope conflicts")
                return
            try:
                self._db.execute(
                    """INSERT INTO lifecycle_repository_scopes (
                           deletion_id, tenant_id, repository_id
                       ) VALUES (?, ?, ?)""",
                    (deletion_id, tenant_id, repository_id),
                )
                self._db.commit()
            except sqlite3.IntegrityError as failure:
                self._db.rollback()
                raise LifecycleConflict("deletion scope conflicts") from failure

    def repository(self, *, deletion_id: str, tenant_id: str) -> str | None:
        with self._lock:
            row = self._db.execute(
                """SELECT repository_id FROM lifecycle_repository_scopes
                   WHERE deletion_id=? AND tenant_id=?""",
                (deletion_id, tenant_id),
            ).fetchone()
        return None if row is None else str(row[0])


class ApprovalOperationsHandler:
    def __init__(self, ledger: ApprovalLedger) -> None:
        if type(ledger) is not ApprovalLedger:
            raise TypeError("ledger must be an ApprovalLedger")
        self._ledger = ledger

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.action == "approvals.create":
            return self._create(request)
        if request.action == "approvals.read":
            return self._read(request)
        if request.action == "approvals.decide":
            return self._decide(request)
        return error(503, "HANDLER_UNAVAILABLE", "requested handler is unavailable")

    def _create(self, request: ServiceRequest) -> ServiceResponse:
        value = document(
            request,
            required=frozenset(
                {
                    "approval_id",
                    "repository_id",
                    "run_id",
                    "finding_id",
                    "execution_identity_hash",
                    "expires_at",
                }
            ),
            optional=frozenset({"tenant_id"}),
        )
        if value is None or not matches_tenant(value, request.identity):
            return INVALID_REQUEST
        fields = (
            path_identifier(value, "approval_id"),
            string(value, "repository_id"),
            string(value, "run_id"),
            string(value, "finding_id"),
            string(value, "execution_identity_hash"),
        )
        expires_at = utc_datetime(value, "expires_at")
        if any(item is None for item in fields) or expires_at is None:
            return INVALID_REQUEST
        approval_id, repository_id, run_id, finding_id, identity_hash = (
            cast(str, item) for item in fields
        )
        if not repository_allowed(request.identity, repository_id):
            return FORBIDDEN
        try:
            stored = self._ledger.request(
                ApprovalRequest(
                    approval_id=approval_id,
                    tenant_id=request.identity.tenant_id,
                    repository_id=repository_id,
                    run_id=run_id,
                    finding_id=finding_id,
                    execution_identity_hash=identity_hash,
                    requester_id=request.identity.subject_id,
                    expires_at=expires_at,
                    version=1,
                ),
                idempotency_key=request.idempotency_key or "",
            )
        except (ApprovalConflict, TypeError, ValueError):
            return CONFLICT
        return response(
            201,
            self._ledger.projection(
                stored.approval_id,
                tenant_id=request.identity.tenant_id,
            ),
            version=stored.version,
        )

    def _read(self, request: ServiceRequest) -> ServiceResponse:
        approval_id = path_value(request, "approval_id")
        if approval_id is None:
            return INVALID_REQUEST
        try:
            value = self._ledger.projection(
                approval_id,
                tenant_id=request.identity.tenant_id,
            )
        except (ApprovalConflict, TypeError, ValueError):
            return NOT_FOUND
        repository_id = value.get("repository_id")
        if type(repository_id) is not str or not repository_allowed(
            request.identity,
            repository_id,
        ):
            return FORBIDDEN
        version = value.get("version")
        return response(200, value, version=version if type(version) is int else None)

    def _decide(self, request: ServiceRequest) -> ServiceResponse:
        approval_id = path_value(request, "approval_id")
        value = document(
            request,
            required=frozenset({"approve", "reason_code", "rationale"}),
        )
        version = expected_version(request)
        if approval_id is None or value is None:
            return INVALID_REQUEST
        if version is None:
            return PRECONDITION_FAILED
        approve = boolean(value, "approve")
        reason = string(value, "reason_code", maximum=64)
        rationale = string(value, "rationale", maximum=1024)
        if approve is None or reason is None or rationale is None:
            return INVALID_REQUEST
        current = self._read(request)
        if current.status != 200:
            return current
        current_version = current.document.get("version")
        if current_version != version:
            return PRECONDITION_FAILED
        try:
            decision = self._ledger.decide(
                approval_id=approval_id,
                tenant_id=request.identity.tenant_id,
                actor_id=request.identity.subject_id,
                approver_granted=bool(request.identity.roles.intersection({"approver", "admin"})),
                expected_version=version,
                approve=approve,
                reason_code=reason,
                rationale=rationale,
                idempotency_key=request.idempotency_key or "",
            )
            projection = self._ledger.projection(
                approval_id,
                tenant_id=request.identity.tenant_id,
            )
        except (ApprovalConflict, TypeError, ValueError):
            return CONFLICT
        projection["decision"] = {
            "state": decision.state.value,
            "reason_code": decision.reason_code,
            "rationale_sha256": decision.rationale_sha256,
            "created_at": decision.created_at.isoformat(),
        }
        return response(200, projection, version=decision.version)


class LifecycleOperationsHandler:
    def __init__(
        self,
        ledger: LifecycleLedger,
        scopes: LifecycleScopeRepository,
        *,
        execute_available: bool = False,
    ) -> None:
        if type(ledger) is not LifecycleLedger or type(scopes) is not LifecycleScopeRepository:
            raise TypeError("lifecycle dependencies are invalid")
        self._ledger = ledger
        self._scopes = scopes
        self._execute_available = execute_available

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        actions = {
            "lifecycle.deletions.create": self._create,
            "lifecycle.deletions.read": self._read,
            "lifecycle.deletions.approve": self._approve,
            "lifecycle.deletions.legal_hold": self._legal_hold,
            "lifecycle.deletions.execute": self._execute,
        }
        handler = actions.get(request.action)
        if handler is None:
            return error(503, "HANDLER_UNAVAILABLE", "requested handler is unavailable")
        return handler(request)

    def _create(self, request: ServiceRequest) -> ServiceResponse:
        value = document(
            request,
            required=frozenset(
                {
                    "deletion_id",
                    "repository_id",
                    "content_sha256",
                    "data_class",
                    "identity_hash",
                }
            ),
            optional=frozenset({"tenant_id"}),
        )
        if value is None or not matches_tenant(value, request.identity):
            return INVALID_REQUEST
        fields = (
            path_identifier(value, "deletion_id"),
            string(value, "repository_id"),
            string(value, "content_sha256"),
            string(value, "data_class"),
            string(value, "identity_hash"),
        )
        if any(item is None for item in fields):
            return INVALID_REQUEST
        deletion_id, repository_id, content_hash, data_class, identity_hash = (
            cast(str, item) for item in fields
        )
        if data_class != "artifact":
            return INVALID_REQUEST
        if not repository_allowed(request.identity, repository_id):
            return FORBIDDEN
        try:
            deletion = DeletionRequest(
                deletion_id=deletion_id,
                tenant_id=request.identity.tenant_id,
                content_sha256=content_hash,
                data_class=data_class,
                identity_hash=identity_hash,
                requested_by=request.identity.subject_id,
                version=1,
            )
            stored = self._ledger.request(
                deletion,
                repository_id=repository_id,
                idempotency_key=request.idempotency_key or "",
            )
        except (LifecycleConflict, TypeError, ValueError):
            return CONFLICT
        return response(201, self._view(stored, repository_id), version=stored.version)

    def _read(self, request: ServiceRequest) -> ServiceResponse:
        deletion_id = path_value(request, "deletion_id")
        if deletion_id is None:
            return INVALID_REQUEST
        repository_id = self._scopes.repository(
            deletion_id=deletion_id,
            tenant_id=request.identity.tenant_id,
        )
        if repository_id is None:
            return NOT_FOUND
        if not repository_allowed(request.identity, repository_id):
            return FORBIDDEN
        try:
            value = self._ledger.get(
                tenant_id=request.identity.tenant_id,
                deletion_id=deletion_id,
            )
        except (LifecycleConflict, TypeError, ValueError):
            return NOT_FOUND
        return response(200, self._view(value, repository_id), version=value.version)

    def _approve(self, request: ServiceRequest) -> ServiceResponse:
        if document(request, required=frozenset()) is None:
            return INVALID_REQUEST
        current, version = self._current_for_transition(request)
        if isinstance(current, ServiceResponse):
            return current
        assert version is not None
        try:
            updated = self._ledger.approve(
                deletion_id=current.deletion_id,
                tenant_id=request.identity.tenant_id,
                actor_id=request.identity.subject_id,
                expected_version=version,
                idempotency_key=request.idempotency_key,
            )
        except (LifecycleConflict, TypeError, ValueError):
            return CONFLICT
        repository_id = self._repository(request, current.deletion_id)
        return response(200, self._view(updated, repository_id), version=updated.version)

    def _legal_hold(self, request: ServiceRequest) -> ServiceResponse:
        value = document(
            request,
            required=frozenset({"enabled", "identity_hash", "reason"}),
        )
        enabled = None if value is None else boolean(value, "enabled")
        identity_hash = None if value is None else string(value, "identity_hash")
        reason = None if value is None else string(value, "reason", maximum=1024)
        if value is None or enabled is None or identity_hash is None or reason is None:
            return INVALID_REQUEST
        current, version = self._current_for_transition(request)
        if isinstance(current, ServiceResponse):
            return current
        assert version is not None
        try:
            updated = self._ledger.set_legal_hold(
                deletion_id=current.deletion_id,
                tenant_id=request.identity.tenant_id,
                identity_hash=identity_hash,
                actor_id=request.identity.subject_id,
                enabled=enabled,
                reason=reason,
                expected_version=version,
                idempotency_key=request.idempotency_key,
            )
        except (LifecycleConflict, TypeError, ValueError):
            return CONFLICT
        repository_id = self._repository(request, current.deletion_id)
        return response(200, self._view(updated, repository_id), version=updated.version)

    def _execute(self, request: ServiceRequest) -> ServiceResponse:
        if not self._execute_available:
            return error(
                503,
                "STORAGE_EXECUTOR_UNAVAILABLE",
                "destructive storage executor is unavailable",
            )
        value = document(request, required=frozenset({"identity_hash"}))
        identity_hash = None if value is None else string(value, "identity_hash")
        if value is None or identity_hash is None:
            return INVALID_REQUEST
        current, version = self._current_for_transition(request)
        if isinstance(current, ServiceResponse):
            return current
        assert version is not None
        try:
            updated = self._ledger.execute(
                deletion_id=current.deletion_id,
                tenant_id=request.identity.tenant_id,
                identity_hash=identity_hash,
                expected_version=version,
                actor_id=request.identity.subject_id,
                idempotency_key=request.idempotency_key,
            )
        except (LifecycleConflict, TypeError, ValueError):
            return CONFLICT
        repository_id = self._repository(request, current.deletion_id)
        return response(200, self._view(updated, repository_id), version=updated.version)

    def _current_for_transition(
        self,
        request: ServiceRequest,
    ) -> tuple[DeletionRequest, int] | tuple[ServiceResponse, None]:
        version = expected_version(request)
        deletion_id = path_value(request, "deletion_id")
        if deletion_id is None:
            return INVALID_REQUEST, None
        if version is None:
            return PRECONDITION_FAILED, None
        read = self._read(request)
        if read.status != 200:
            return read, None
        try:
            current = self._ledger.get(
                tenant_id=request.identity.tenant_id,
                deletion_id=deletion_id,
            )
        except (LifecycleConflict, TypeError, ValueError):
            return NOT_FOUND, None
        if current.version != version:
            return PRECONDITION_FAILED, None
        return current, version

    def _repository(self, request: ServiceRequest, deletion_id: str) -> str:
        repository_id = self._scopes.repository(
            deletion_id=deletion_id,
            tenant_id=request.identity.tenant_id,
        )
        if repository_id is None:
            raise LifecycleConflict("deletion scope is unavailable")
        return repository_id

    @staticmethod
    def _view(value: DeletionRequest, repository_id: str) -> dict[str, object]:
        state = (
            "EXECUTED"
            if value.executed
            else "HELD"
            if value.legal_hold
            else "APPROVED"
            if value.approved_by is not None
            else "REQUESTED"
        )
        return {
            "deletion_id": value.deletion_id,
            "tenant_id": value.tenant_id,
            "repository_id": repository_id,
            "content_sha256": value.content_sha256,
            "data_class": value.data_class,
            "identity_hash": value.identity_hash,
            "state": state,
            "version": value.version,
            "legal_hold": value.legal_hold,
            "executed": value.executed,
        }


__all__ = [
    "LIFECYCLE_SCOPE_SCHEMA_STATEMENTS",
    "ApprovalOperationsHandler",
    "LifecycleOperationsHandler",
    "LifecycleScopeRepository",
]
