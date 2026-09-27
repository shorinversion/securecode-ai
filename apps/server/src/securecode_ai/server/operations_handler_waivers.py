"""Tenant-scoped waiver lifecycle operations backed by approved findings."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Mapping
from typing import cast

from .approvals import ApprovalConflict, ApprovalLedger
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
    optional_string,
    path_identifier,
    repository_allowed,
    response,
    string,
    utc_datetime,
)
from .ports import ServiceRequest, ServiceResponse
from .scm_completion_models import SCMCompletionDisposition
from .waivers import WaiverConflict, WaiverLedger, WaiverRecord, WaiverScope
from .worker_findings_store import load_worker_findings_for_run
from .worker_queue_models import WorkerQueueConflict


class WaiverOperationsHandler:
    def __init__(
        self,
        ledger: WaiverLedger,
        approvals: ApprovalLedger,
        *,
        connection: sqlite3.Connection,
        refresh_verdict: Callable[[str, str, str], object] | None = None,
    ) -> None:
        if (
            type(ledger) is not WaiverLedger
            or type(approvals) is not ApprovalLedger
            or type(connection) is not sqlite3.Connection
            or (refresh_verdict is not None and not callable(refresh_verdict))
        ):
            raise TypeError("waiver handler configuration is invalid")
        self._ledger = ledger
        self._approvals = approvals
        self._connection = connection
        self._refresh_verdict = refresh_verdict

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.action == "waivers.create":
            return self._create(request)
        if request.action == "waivers.read":
            return self._read(request)
        if request.action == "waivers.revoke":
            return self._revoke(request)
        return error(503, "HANDLER_UNAVAILABLE", "requested handler is unavailable")

    def _create(self, request: ServiceRequest) -> ServiceResponse:
        finding_id = (
            path_identifier(request.path_params, "finding_id")
            if isinstance(request.path_params, Mapping)
            else None
        )
        value = document(
            request,
            required=frozenset(
                {
                    "waiver_id",
                    "approval_id",
                    "repository_id",
                    "run_id",
                    "execution_identity_hash",
                    "expires_at",
                }
            ),
            optional=frozenset({"policy_scope", "tenant_id"}),
        )
        if finding_id is None or value is None or not matches_tenant(value, request.identity):
            return INVALID_REQUEST
        fields = tuple(
            string(value, name)
            for name in (
                "waiver_id",
                "approval_id",
                "repository_id",
                "run_id",
                "execution_identity_hash",
            )
        )
        expires_at = utc_datetime(value, "expires_at")
        policy_scope = optional_string(value, "policy_scope")
        if (
            any(item is None for item in fields)
            or expires_at is None
            or (value.get("policy_scope") is not None and policy_scope is None)
        ):
            return INVALID_REQUEST
        # Keep the authorization boundary local to the handler as well as the
        # outer route matrix.  A caller must already be an AppSec approver (or
        # an administrator) before an approved decision can become a waiver.
        if request.identity.workload or not request.identity.roles.intersection(
            {"approver", "admin"}
        ):
            return FORBIDDEN
        waiver_id, approval_id, repository_id, run_id, identity_hash = (
            cast(str, item) for item in fields
        )
        if not repository_allowed(request.identity, repository_id):
            return FORBIDDEN
        if self._refresh_verdict is None:
            return error(
                503,
                "WAIVER_VERDICT_UNAVAILABLE",
                "waiver policy integration is unavailable",
            )
        try:
            approval_request, decision = self._approvals.approved_request(
                approval_id,
                tenant_id=request.identity.tenant_id,
            )
            if (
                approval_request.repository_id,
                approval_request.run_id,
                approval_request.finding_id,
                approval_request.execution_identity_hash,
            ) != (repository_id, run_id, finding_id, identity_hash):
                return CONFLICT
            findings = load_worker_findings_for_run(
                self._connection,
                tenant_id=request.identity.tenant_id,
                run_id=run_id,
            )
            matches = tuple(item for item in findings if item.finding_id == finding_id)
            if len(matches) != 1:
                return CONFLICT
            record = WaiverRecord(
                waiver_id=waiver_id,
                scope=WaiverScope(
                    tenant_id=request.identity.tenant_id,
                    repository_id=repository_id,
                    run_id=run_id,
                    execution_identity_hash=identity_hash,
                    finding_fingerprint=matches[0].root_cause_fingerprint,
                    policy_scope=policy_scope,
                ),
                expires_at=expires_at,
                approval_id=approval_id,
                rationale_sha256=decision.rationale_sha256,
            )
            stored = self._ledger.grant(
                record,
                approval=decision,
                approval_request=approval_request,
                idempotency_key=request.idempotency_key or "",
            )
        except (
            ApprovalConflict,
            WaiverConflict,
            WorkerQueueConflict,
            sqlite3.Error,
            TypeError,
            ValueError,
        ):
            return CONFLICT
        if not self._refresh(
            stored.scope.tenant_id,
            stored.scope.run_id,
            stored.scope.execution_identity_hash,
        ):
            return error(
                503,
                "WAIVER_VERDICT_UNAVAILABLE",
                "waiver is stored but the policy verdict could not be refreshed",
            )
        try:
            active = self._ledger.is_active(request.identity.tenant_id, stored.waiver_id)
        except (WaiverConflict, TypeError, ValueError):
            return error(
                503,
                "WAIVER_STATE_UNAVAILABLE",
                "waiver state could not be verified",
            )
        return response(
            201,
            self._view(stored, active=active),
            version=stored.version,
        )

    def _read(self, request: ServiceRequest) -> ServiceResponse:
        if request.identity.workload or not request.identity.roles.intersection(
            {"viewer", "auditor", "approver", "admin"}
        ):
            return FORBIDDEN
        waiver_id = (
            path_identifier(request.path_params, "waiver_id")
            if isinstance(request.path_params, Mapping)
            else None
        )
        if waiver_id is None:
            return INVALID_REQUEST
        try:
            record = self._ledger.get(request.identity.tenant_id, waiver_id)
            if record is None:
                return NOT_FOUND
            if not repository_allowed(request.identity, record.scope.repository_id):
                return FORBIDDEN
            return response(
                200,
                self._view(
                    record,
                    active=self._ledger.is_active(request.identity.tenant_id, waiver_id),
                ),
                version=record.version,
            )
        except (WaiverConflict, TypeError, ValueError):
            return CONFLICT

    def _revoke(self, request: ServiceRequest) -> ServiceResponse:
        waiver_id = (
            path_identifier(request.path_params, "waiver_id")
            if isinstance(request.path_params, Mapping)
            else None
        )
        version = expected_version(request)
        if waiver_id is None:
            return INVALID_REQUEST
        if version is None:
            return PRECONDITION_FAILED
        if request.identity.workload or not request.identity.roles.intersection(
            {"approver", "admin"}
        ):
            return FORBIDDEN
        try:
            current = self._ledger.get(request.identity.tenant_id, waiver_id)
            if current is None:
                return NOT_FOUND
            if not repository_allowed(request.identity, current.scope.repository_id):
                return FORBIDDEN
            stored = self._ledger.revoke(
                tenant_id=request.identity.tenant_id,
                waiver_id=waiver_id,
                expected_version=version,
                idempotency_key=request.idempotency_key or "",
            )
        except (WaiverConflict, TypeError, ValueError):
            return CONFLICT
        if not self._refresh(
            stored.scope.tenant_id,
            stored.scope.run_id,
            stored.scope.execution_identity_hash,
        ):
            return error(
                503,
                "WAIVER_VERDICT_UNAVAILABLE",
                "waiver revocation is stored but the policy verdict could not be refreshed",
            )
        return response(200, self._view(stored, active=False), version=stored.version)

    def _refresh(self, tenant_id: str, run_id: str, identity_hash: str) -> bool:
        if self._refresh_verdict is None:
            return False
        try:
            receipt = self._refresh_verdict(tenant_id, run_id, identity_hash)
            return getattr(receipt, "disposition", None) in {
                SCMCompletionDisposition.PUBLISHED,
                SCMCompletionDisposition.REPLAYED,
            }
        except Exception:
            return False

    @staticmethod
    def _view(record: WaiverRecord, *, active: bool) -> dict[str, object]:
        return {
            "waiver_id": record.waiver_id,
            "tenant_id": record.scope.tenant_id,
            "repository_id": record.scope.repository_id,
            "run_id": record.scope.run_id,
            "execution_identity_hash": record.scope.execution_identity_hash,
            "finding_fingerprint": record.scope.finding_fingerprint,
            "policy_scope": record.scope.policy_scope,
            "expires_at": record.expires_at.isoformat(),
            "approval_id": record.approval_id,
            "rationale_sha256": record.rationale_sha256,
            "version": record.version,
            "active": active,
        }


__all__ = ["WaiverOperationsHandler"]
