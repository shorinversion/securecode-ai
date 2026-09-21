"""Fail-closed enterprise composition without claiming external publication."""

from __future__ import annotations

import re
from typing import Final

from .audit_log import AuditLog
from .enterprise import EnterpriseOutcome, EnterpriseReceipt
from .evidence_egress import EgressPolicy, authorize
from .evidence_packages import EvidenceItem, EvidencePackageRegistry
from .identity import Principal
from .policy_store import PolicyStore
from .workflow import DurableWorkflow, WorkflowConflict, WorkflowState


class EnterpriseService:
    def __init__(
        self,
        *,
        profiles: PolicyStore,
        workflow: DurableWorkflow,
        audit: AuditLog,
        packages: EvidencePackageRegistry,
        egress: EgressPolicy,
    ) -> None:
        self._profiles = profiles
        self._workflow = workflow
        self._audit = audit
        self._packages = packages
        self._egress = egress

    def admit(
        self,
        *,
        principal: Principal,
        repository_id: str,
        run_id: str,
        identity_hash: str,
        idempotency_key: str,
    ) -> EnterpriseReceipt:
        _validate_request(
            principal=principal,
            repository_id=repository_id,
            run_id=run_id,
            identity_hash=identity_hash,
            idempotency_key=idempotency_key,
        )
        if not principal.allows(
            action="runs.create",
            repository_id=repository_id,
        ):
            return self._denied(
                principal.tenant_id,
                repository_id,
                run_id,
                identity_hash,
            )
        profile = self._profiles.resolve(
            tenant_id=principal.tenant_id,
            repository_id=repository_id,
        )
        try:
            workflow = self._workflow.start(
                tenant_id=principal.tenant_id,
                repository_id=repository_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
                idempotency_key=idempotency_key,
            )
        except WorkflowConflict:
            return self._denied(
                principal.tenant_id,
                repository_id,
                run_id,
                identity_hash,
            )
        if workflow.repository_id != repository_id:
            return self._denied(
                principal.tenant_id,
                repository_id,
                run_id,
                identity_hash,
            )
        self._audit.append(
            tenant_id=principal.tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            actor_id=principal.subject_id,
            action="runs.create",
            identity_hash=identity_hash,
            expected_sequence=0,
            attributes={"outcome": "ACCEPTED"},
            idempotency_key=idempotency_key,
        )
        return EnterpriseReceipt(
            tenant_id=principal.tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=identity_hash,
            outcome=EnterpriseOutcome.ACCEPTED,
            profile_sha256=_profile_hash(profile),
            workflow_version=workflow.version,
            published=False,
        )

    def prepare_evidence(
        self,
        *,
        principal: Principal,
        repository_id: str,
        run_id: str,
        identity_hash: str,
        items: tuple[EvidenceItem, ...],
        idempotency_key: str,
    ) -> EnterpriseReceipt:
        _validate_request(
            principal=principal,
            repository_id=repository_id,
            run_id=run_id,
            identity_hash=identity_hash,
            idempotency_key=idempotency_key,
        )
        if type(items) is not tuple or any(type(item) is not EvidenceItem for item in items):
            raise EnterpriseServiceError()
        if not principal.allows(
            action="artifacts.authorize",
            repository_id=repository_id,
        ):
            return self._denied(
                principal.tenant_id,
                repository_id,
                run_id,
                identity_hash,
            )
        profile = self._profiles.resolve(
            tenant_id=principal.tenant_id,
            repository_id=repository_id,
        )
        try:
            flow = self._workflow.resume(
                tenant_id=principal.tenant_id,
                run_id=run_id,
                identity_hash=identity_hash,
            )
        except WorkflowConflict:
            return self._denied(
                principal.tenant_id,
                repository_id,
                run_id,
                identity_hash,
            )
        if flow.repository_id != repository_id:
            return self._denied(
                principal.tenant_id,
                repository_id,
                run_id,
                identity_hash,
            )
        terminal = _terminal_outcome(flow.state)
        if terminal is not None:
            return EnterpriseReceipt(
                tenant_id=principal.tenant_id,
                repository_id=repository_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
                outcome=terminal,
                profile_sha256=_profile_hash(profile),
                workflow_version=flow.version,
                published=False,
            )
        authorization = authorize(
            self._egress,
            tenant_id=principal.tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=identity_hash,
            destination_id=self._egress.destination_id,
            profile_id=self._egress.profile_id,
            capability_id=self._egress.capability_id,
        )
        package = self._packages.prepare(
            idempotency_key=idempotency_key,
            authorization=authorization,
            policy=self._egress,
            items=items,
        )
        return EnterpriseReceipt(
            tenant_id=principal.tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=identity_hash,
            outcome=EnterpriseOutcome.INDETERMINATE,
            profile_sha256=_profile_hash(profile),
            workflow_version=flow.version,
            published=False,
            evidence_manifest_sha256=package.manifest_sha256,
        )

    def publication_allowed(
        self,
        *,
        tenant_id: str,
        run_id: str,
        identity_hash: str,
        current_head_sha: str,
        stored_head_sha: str,
    ) -> bool:
        if (
            not _identifier(tenant_id)
            or not _identifier(run_id)
            or not _sha256(identity_hash)
            or not _commit_sha(current_head_sha)
            or not _commit_sha(stored_head_sha)
        ):
            return False
        try:
            return self._workflow.publication_allowed(
                tenant_id=tenant_id,
                run_id=run_id,
                identity_hash=identity_hash,
                current_head_sha=current_head_sha,
                stored_head_sha=stored_head_sha,
            )
        except WorkflowConflict:
            return False

    def _denied(
        self,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        identity_hash: str,
    ) -> EnterpriseReceipt:
        return EnterpriseReceipt(
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=identity_hash,
            outcome=EnterpriseOutcome.DENIED,
            profile_sha256="0" * 64,
            workflow_version=0,
            published=False,
        )


_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")


class EnterpriseServiceError(ValueError):
    """A source-free rejection for malformed enterprise requests."""


def _validate_request(
    *,
    principal: Principal,
    repository_id: str,
    run_id: str,
    identity_hash: str,
    idempotency_key: str,
) -> None:
    if (
        type(principal) is not Principal
        or not _identifier(principal.subject_id)
        or not _identifier(principal.tenant_id)
        or not _identifier(repository_id)
        or not _identifier(run_id)
        or not _sha256(identity_hash)
        or not _identifier(idempotency_key)
    ):
        raise EnterpriseServiceError()


def _profile_hash(profile: dict[str, object]) -> str:
    value = profile.get("content_sha256")
    if not isinstance(value, str) or not _sha256(value):
        raise EnterpriseServiceError()
    return value


def _terminal_outcome(state: WorkflowState) -> EnterpriseOutcome | None:
    if state is WorkflowState.CANCELLED:
        return EnterpriseOutcome.CANCELLED
    if state is WorkflowState.SUPERSEDED:
        return EnterpriseOutcome.SUPERSEDED
    if state in {
        WorkflowState.CANCEL_REQUESTED,
        WorkflowState.FAILED,
        WorkflowState.INDETERMINATE,
    }:
        return EnterpriseOutcome.INDETERMINATE
    return None


def _identifier(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _commit_sha(value: object) -> bool:
    return type(value) is str and _COMMIT_SHA.fullmatch(value) is not None


__all__ = ["EnterpriseService", "EnterpriseServiceError"]
