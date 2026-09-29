"""Bounded, secret-free environment configuration for remote spend limits."""

from __future__ import annotations

import re
from collections.abc import Mapping
from threading import RLock

from .remote_provider_budget import (
    InMemoryRemoteProviderBudget,
    RemoteProviderBudgetPort,
    RemoteProviderSpendPolicy,
)

_ENV_PREFIX = "SECURECODE_REMOTE_SPEND_"
_ENV_FIELDS = {
    "WINDOW_MS": "window_ms",
    "MAX_CALLS": "max_calls_per_window",
    "MAX_CONCURRENT_CALLS": "max_concurrent_calls",
    "MAX_TOKENS": "max_tokens_per_window",
    "MAX_COST_MICROUNITS": "max_cost_microunits_per_window",
    "INPUT_MICROUNITS_PER_MILLION_TOKENS": "input_cost_microunits_per_million_tokens",
    "OUTPUT_MICROUNITS_PER_MILLION_TOKENS": "output_cost_microunits_per_million_tokens",
}
_DECIMAL_INTEGER = re.compile(r"(?:0|[1-9][0-9]{0,17})\Z")
_MAX_BUDGETS = 256
_BUDGET_LOCK = RLock()
_BUDGETS: dict[tuple[str, str], tuple[RemoteProviderSpendPolicy, InMemoryRemoteProviderBudget]] = {}


def build_remote_provider_budget_from_environment(
    environment: Mapping[str, str], *, tenant_id: str, model_id: str
) -> RemoteProviderBudgetPort | None:
    """Return a single-tenant/model budget only from a complete valid rate card.

    Missing, partial, malformed, or out-of-range configuration returns None so
    the remote connector can reject the call before sending HTTP bytes. Values
    are numeric caps and rates only; this parser never reads credentials.
    """
    try:
        raw_values = {field: environment.get(_ENV_PREFIX + field) for field in _ENV_FIELDS}
        parsed: dict[str, int] = {}
        for field, value in raw_values.items():
            if value is None or type(value) is not str:
                return None
            if len(value) > 18 or _DECIMAL_INTEGER.fullmatch(value) is None:
                return None
            parsed[_ENV_FIELDS[field]] = int(value)
        policy = RemoteProviderSpendPolicy(
            tenant_id=tenant_id,
            model_id=model_id,
            **parsed,
        )
        key = (tenant_id, model_id)
        with _BUDGET_LOCK:
            existing = _BUDGETS.get(key)
            if existing is not None:
                previous_policy, budget = existing
                return budget if previous_policy == policy else None
            if len(_BUDGETS) >= _MAX_BUDGETS:
                return None
            budget = InMemoryRemoteProviderBudget((policy,))
            _BUDGETS[key] = (policy, budget)
            return budget
    except Exception:
        return None


__all__ = ["build_remote_provider_budget_from_environment"]
