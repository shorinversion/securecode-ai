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


def test_a_small_cost_cap_admits_calls_reserved_by_actual_prompt_size() -> None:
    from securecode_ai.adapters.openai_compatible_remote import spend_request
    from securecode_ai.adapters.remote_provider_budget import (
        RemoteProviderCallContext,
        RemoteProviderSpendUsage,
    )

    # DeepSeek Flash prices with a 0.20 USD cap, as in an E2E run that saw the Skeptic
    # refused after one cent of real spending.
    policy = RemoteProviderSpendPolicy(
        tenant_id="tenant-a",
        model_id="model-a",
        window_ms=3_600_000,
        max_calls_per_window=200,
        max_concurrent_calls=4,
        max_tokens_per_window=20_000_000,
        max_cost_microunits_per_window=200_000,
        input_cost_microunits_per_million_tokens=150_000,
        output_cost_microunits_per_million_tokens=600_000,
    )
    budget = InMemoryRemoteProviderBudget((policy,))
    for index in range(12):
        context = RemoteProviderCallContext(
            run_id="run-a",
            tenant_id="tenant-a",
            request_id=f"skeptic-{index}",
            attempt=1,
            max_input_tokens=983_040,
            max_output_tokens=65_536,
        )
        request = spend_request(
            context, model_id="model-a", input_token_upper_bound=24_000, slot_timeout_ms=1000
        )
        assert request.max_input_tokens == 24_000
        lease = budget.reserve(request)
        budget.settle(lease, RemoteProviderSpendUsage(input_tokens=6_000, output_tokens=1_500))
