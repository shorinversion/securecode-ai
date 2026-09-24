"""Server facade for durable per-tenant resource governance."""

from __future__ import annotations

from securecode_ai.core.resource_governor import (
    ResourceReservationReceipt,
    ResourceReservationRequest,
    ResourceUsage,
    TenantResourceLimits,
)

from .resource_repository import ResourceRepository


class ResourceService:
    """Expose run admission and worker terminal accounting operations."""

    def __init__(self, repository: ResourceRepository) -> None:
        if not isinstance(repository, ResourceRepository):
            raise TypeError("repository must be a ResourceRepository")
        self._repository = repository

    def configure(self, limits: TenantResourceLimits) -> None:
        self._repository.configure(limits)

    def reserve(self, request: ResourceReservationRequest) -> ResourceReservationReceipt:
        return self._repository.reserve(request)

    def reserve_run(
        self,
        *,
        request_id: str,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        execution_identity_hash: str,
        profile_sha256: str,
        requested_tokens: int,
        requested_cost_microunits: int,
        requested_cpu_ms: int,
        requested_memory_bytes: int,
        requested_wall_ms: int,
        now_ms: int,
        lease_expires_at_ms: int,
    ) -> ResourceReservationReceipt:
        request = ResourceReservationRequest(
            request_id=request_id,
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=execution_identity_hash,
            profile_sha256=profile_sha256,
            requested_tokens=requested_tokens,
            requested_cost_microunits=requested_cost_microunits,
            requested_cpu_ms=requested_cpu_ms,
            requested_memory_bytes=requested_memory_bytes,
            requested_wall_ms=requested_wall_ms,
            now_ms=now_ms,
            lease_expires_at_ms=lease_expires_at_ms,
        )
        return self.reserve(request)

    def commit_run(
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
        return self.commit(
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=execution_identity_hash,
            reservation_id=reservation_id,
            usage=usage,
            expected_version=expected_version,
            now_ms=now_ms,
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
        return self._repository.commit(
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=execution_identity_hash,
            reservation_id=reservation_id,
            usage=usage,
            expected_version=expected_version,
            now_ms=now_ms,
        )

    def release_run(
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
        return self.release(
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=execution_identity_hash,
            reservation_id=reservation_id,
            expected_version=expected_version,
            now_ms=now_ms,
            cancelled=cancelled,
        )

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
        return self._repository.release(
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=execution_identity_hash,
            reservation_id=reservation_id,
            expected_version=expected_version,
            now_ms=now_ms,
            cancelled=cancelled,
        )

    def expire(
        self,
        *,
        tenant_id: str,
        now_ms: int,
        max_items: int = 100,
    ) -> int:
        return self._repository.expire(
            tenant_id=tenant_id,
            now_ms=now_ms,
            max_items=max_items,
        )

    def has_expired(self, *, tenant_id: str, now_ms: int) -> bool:
        return self._repository.has_expired(tenant_id=tenant_id, now_ms=now_ms)


__all__ = ["ResourceService"]
