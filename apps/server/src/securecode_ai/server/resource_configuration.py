"""Validated host-owned resource limits and per-run reservation defaults."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, replace

from securecode_ai.core.resource_governor import (
    ResourceReservationReceipt,
    ResourceReservationRequest,
    ResourceUsage,
    TenantResourceLimits,
)

from .resource_service import ResourceService
from .run_admission_models import RunResourceDefaults


@dataclass(frozen=True, slots=True)
class ConfiguredResources:
    limits: TenantResourceLimits
    run_defaults: RunResourceDefaults


class TenantProvisioningResourceService:
    """Apply one host-owned limit profile independently to admitted tenants."""

    def __init__(self, service: ResourceService, template: TenantResourceLimits) -> None:
        self._service = service
        self._template = template

    def reserve(self, request: ResourceReservationRequest) -> ResourceReservationReceipt:
        self._service.configure(replace(self._template, tenant_id=request.tenant_id))
        return self._service.reserve(request)

    def is_active(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        execution_identity_hash: str,
        reservation_id: str,
        expected_version: int,
        now_ms: int,
    ) -> bool:
        return self._service.is_active(
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=execution_identity_hash,
            reservation_id=reservation_id,
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
        return self._service.commit(
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=execution_identity_hash,
            reservation_id=reservation_id,
            usage=usage,
            expected_version=expected_version,
            now_ms=now_ms,
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
        return self._service.release(
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=execution_identity_hash,
            reservation_id=reservation_id,
            expected_version=expected_version,
            now_ms=now_ms,
            cancelled=cancelled,
        )

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
        return self._service.commit_run(
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
        return self._service.release_run(
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=execution_identity_hash,
            reservation_id=reservation_id,
            expected_version=expected_version,
            now_ms=now_ms,
            cancelled=cancelled,
        )


def load_resource_configuration(
    values: Mapping[str, str],
    *,
    tenant_id: str,
) -> ConfiguredResources:
    profile_id = values.get("SECURECODE_RESOURCE_PROFILE_ID", "default-v1")
    profile = {
        "max_concurrent_runs": _integer(values, "SECURECODE_MAX_CONCURRENT_RUNS", 4),
        "max_admissions_per_window": _integer(values, "SECURECODE_MAX_ADMISSIONS_PER_WINDOW", 100),
        "admission_window_ms": _integer(values, "SECURECODE_ADMISSION_WINDOW_MS", 3_600_000),
        "max_tokens_per_window": _integer(values, "SECURECODE_MAX_TOKENS_PER_WINDOW", 2_000_000),
        "max_cost_microunits_per_window": _integer(
            values, "SECURECODE_MAX_COST_MICROUNITS_PER_WINDOW", 100_000_000
        ),
        "max_cpu_ms_per_run": _integer(values, "SECURECODE_MAX_CPU_MS_PER_RUN", 600_000),
        "max_memory_bytes_per_run": _integer(
            values, "SECURECODE_MAX_MEMORY_BYTES_PER_RUN", 8_589_934_592
        ),
        "max_wall_ms_per_run": _integer(values, "SECURECODE_MAX_WALL_MS_PER_RUN", 600_000),
    }
    profile_sha256 = hashlib.sha256(
        json.dumps(
            {"profile_id": profile_id, **profile}, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
    ).hexdigest()
    limits = TenantResourceLimits(
        tenant_id=tenant_id,
        profile_id=profile_id,
        profile_sha256=profile_sha256,
        **profile,
    )
    defaults = RunResourceDefaults(
        profile_sha256=profile_sha256,
        requested_tokens=_integer(values, "SECURECODE_RUN_TOKENS", 64_000, minimum=0),
        requested_cost_microunits=_integer(
            values, "SECURECODE_RUN_COST_MICROUNITS", 5_000_000, minimum=0
        ),
        requested_cpu_ms=_integer(
            values, "SECURECODE_RUN_CPU_MS", profile["max_cpu_ms_per_run"], minimum=0
        ),
        requested_memory_bytes=_integer(
            values,
            "SECURECODE_RUN_MEMORY_BYTES",
            profile["max_memory_bytes_per_run"],
            minimum=0,
        ),
        requested_wall_ms=_integer(
            values, "SECURECODE_RUN_WALL_MS", profile["max_wall_ms_per_run"], minimum=0
        ),
        lease_duration_ms=_integer(values, "SECURECODE_RUN_LEASE_MS", 900_000),
    )
    if (
        defaults.requested_tokens > limits.max_tokens_per_window
        or defaults.requested_cost_microunits > limits.max_cost_microunits_per_window
        or defaults.requested_cpu_ms > limits.max_cpu_ms_per_run
        or defaults.requested_memory_bytes > limits.max_memory_bytes_per_run
        or defaults.requested_wall_ms > limits.max_wall_ms_per_run
    ):
        raise ValueError("run resource defaults exceed tenant limits")
    return ConfiguredResources(limits=limits, run_defaults=defaults)


def _integer(
    values: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int = 1,
) -> int:
    raw = values.get(name)
    if raw is None:
        return default
    if type(raw) is not str or not 1 <= len(raw) <= 19 or not raw.isascii() or not raw.isdigit():
        raise ValueError("resource configuration is invalid")
    value = int(raw)
    if not minimum <= value <= 9_223_372_036_854_775_807:
        raise ValueError("resource configuration is invalid")
    return value


__all__ = [
    "ConfiguredResources",
    "TenantProvisioningResourceService",
    "load_resource_configuration",
]
