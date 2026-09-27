"""Closed source-free chaos scenario catalogue."""

from __future__ import annotations

from enum import StrEnum


class ChaosScenario(StrEnum):
    HEALTH_LIVE = "health_live"
    HEALTH_READY = "health_ready"
    SOAK = "soak"
    WORKER_LIFECYCLE = "worker_lifecycle"
    RESTART = "restart"
    LEASE_EXPIRY = "lease_expiry"
    DUPLICATE = "duplicate_delivery"
    CANCEL = "cancellation"
    STALE_SHA = "stale_sha"
    STORAGE = "storage_failure"
    PROVIDER = "provider_failure"
    NETWORK = "network_failure"
    WORKER_LOSS = "worker_loss"


# ``SOAK`` is an executable capacity profile, rather than an injected fault
# scenario. Keep it out of the legacy resilience default plan so callers that
# construct a plan without an explicit scenario list do not silently start a
# duration-bound workload.
SCENARIOS = tuple(
    item
    for item in ChaosScenario
    if item not in {ChaosScenario.SOAK, ChaosScenario.WORKER_LIFECYCLE}
)

__all__ = ["SCENARIOS", "ChaosScenario"]
