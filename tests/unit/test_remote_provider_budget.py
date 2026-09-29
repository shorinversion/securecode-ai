from __future__ import annotations

import pytest
from securecode_ai.adapters.remote_provider_budget import (
    InMemoryRemoteProviderBudget,
    RemoteProviderBudgetError,
    RemoteProviderSpendPolicy,
    RemoteProviderSpendRequest,
)


def _policy(max_concurrent_calls: int) -> RemoteProviderSpendPolicy:
    return RemoteProviderSpendPolicy(
        tenant_id="tenant-a",
        model_id="model-a",
        window_ms=60_000,
        max_calls_per_window=10,
        max_concurrent_calls=max_concurrent_calls,
        max_tokens_per_window=1_000_000,
        max_cost_microunits_per_window=1_000_000_000,
        input_cost_microunits_per_million_tokens=1,
        output_cost_microunits_per_million_tokens=1,
    )


def _request(request_id: str) -> RemoteProviderSpendRequest:
    return RemoteProviderSpendRequest(
        run_id="run-a",
        tenant_id="tenant-a",
        model_id="model-a",
        request_id=request_id,
        attempt=1,
        max_input_tokens=10,
        max_output_tokens=10,
    )


def test_in_memory_budget_enforces_max_concurrent_calls() -> None:
    budget = InMemoryRemoteProviderBudget((_policy(max_concurrent_calls=1),))
    lease = budget.reserve(_request("request-1"))

    with pytest.raises(RemoteProviderBudgetError):
        budget.reserve(_request("request-2"))

    budget.release(lease)
    budget.reserve(_request("request-3"))
