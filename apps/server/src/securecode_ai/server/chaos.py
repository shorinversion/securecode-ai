"""Closed source-free chaos scenario catalogue."""

from __future__ import annotations

from enum import StrEnum


class ChaosScenario(StrEnum):
    RESTART = "restart"
    LEASE_EXPIRY = "lease_expiry"
    DUPLICATE = "duplicate_delivery"
    CANCEL = "cancellation"
    STALE_SHA = "stale_sha"
    STORAGE = "storage_failure"
    PROVIDER = "provider_failure"
    NETWORK = "network_failure"
    WORKER_LOSS = "worker_loss"


SCENARIOS = tuple(ChaosScenario)

__all__ = ["SCENARIOS", "ChaosScenario"]
