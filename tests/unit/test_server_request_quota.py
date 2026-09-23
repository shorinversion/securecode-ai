"""P8.7 request quota: window accounting, cost ceilings and fail-closed edges."""

from __future__ import annotations

import pytest
from securecode_ai.server.request_quota import (
    MAX_REQUESTS_PER_WINDOW,
    MAX_SPEND_MICROUNITS,
    MAX_TENANTS,
    QuotaError,
    QuotaErrorCode,
    QuotaLedger,
    QuotaPolicy,
)

TENANT = "tenant-1"


def _policy(**overrides: object) -> QuotaPolicy:
    values: dict[str, object] = {
        "tenant_id": TENANT,
        "window_seconds": 60,
        "max_requests": 3,
        "max_spend_microunits": 1_000,
    }
    values.update(overrides)
    return QuotaPolicy(**values)  # type: ignore[arg-type]


def test_policy_rejects_invalid_configuration() -> None:
    for overrides in (
        {"tenant_id": ""},
        {"tenant_id": "-leading"},
        {"tenant_id": "tenant 1"},
        {"window_seconds": 0},
        {"window_seconds": MAX_REQUESTS_PER_WINDOW + 1},
        {"max_requests": 0},
        {"max_requests": MAX_REQUESTS_PER_WINDOW + 1},
        {"max_spend_microunits": -1},
        {"max_spend_microunits": MAX_SPEND_MICROUNITS + 1},
    ):
        with pytest.raises(QuotaError) as error:
            _policy(**overrides)
        assert error.value.code is QuotaErrorCode.INVALID_CONFIGURATION


def test_ledger_rejects_duplicate_or_malformed_policies() -> None:
    with pytest.raises(QuotaError):
        QuotaLedger((_policy(), _policy()))
    with pytest.raises(QuotaError):
        QuotaLedger(("not-a-policy",))  # type: ignore[arg-type]


def test_requests_are_charged_until_the_ceiling() -> None:
    ledger = QuotaLedger((_policy(max_requests=2, max_spend_microunits=0),))
    first = ledger.check(tenant_id=TENANT, now_ms=0)
    second = ledger.check(tenant_id=TENANT, now_ms=10)
    third = ledger.check(tenant_id=TENANT, now_ms=20)
    assert first.allowed and first.remaining_requests == 1
    assert second.allowed and second.remaining_requests == 0
    assert not third.allowed
    assert third.retry_after_seconds == 60


def test_window_rolls_over_and_allows_again() -> None:
    ledger = QuotaLedger((_policy(max_requests=1, max_spend_microunits=0),))
    assert ledger.check(tenant_id=TENANT, now_ms=0).allowed
    assert not ledger.check(tenant_id=TENANT, now_ms=59_999).allowed
    fresh = ledger.check(tenant_id=TENANT, now_ms=60_000)
    assert fresh.allowed
    assert fresh.remaining_requests == 0


def test_spend_ceiling_refuses_before_the_request_ceiling() -> None:
    ledger = QuotaLedger((_policy(max_requests=10, max_spend_microunits=500),))
    assert ledger.check(tenant_id=TENANT, now_ms=0, cost_microunits=500).allowed
    refused = ledger.check(tenant_id=TENANT, now_ms=1, cost_microunits=1)
    assert not refused.allowed
    assert refused.remaining_spend_microunits == 0


def test_spend_is_accumulated_across_requests() -> None:
    ledger = QuotaLedger((_policy(max_requests=10, max_spend_microunits=900),))
    assert ledger.check(tenant_id=TENANT, now_ms=0, cost_microunits=400).allowed
    second = ledger.check(tenant_id=TENANT, now_ms=1, cost_microunits=400)
    assert second.allowed
    assert second.remaining_spend_microunits == 100
    assert not ledger.check(tenant_id=TENANT, now_ms=2, cost_microunits=200).allowed


def test_tenant_without_a_policy_is_not_limited() -> None:
    ledger = QuotaLedger((_policy(),))
    for index in range(5):
        decision = ledger.check(tenant_id="other-tenant", now_ms=index)
        assert decision.allowed
        assert decision.remaining_requests == MAX_REQUESTS_PER_WINDOW


def test_tenants_are_accounted_separately() -> None:
    ledger = QuotaLedger(
        (
            _policy(tenant_id="tenant-a", max_requests=1, max_spend_microunits=0),
            _policy(tenant_id="tenant-b", max_requests=1, max_spend_microunits=0),
        )
    )
    assert ledger.check(tenant_id="tenant-a", now_ms=0).allowed
    assert not ledger.check(tenant_id="tenant-a", now_ms=1).allowed
    assert ledger.check(tenant_id="tenant-b", now_ms=1).allowed
    assert ledger.tenants == 2


def test_check_rejects_invalid_arguments() -> None:
    ledger = QuotaLedger((_policy(),))
    for arguments in (
        {"tenant_id": 1, "now_ms": 0},
        {"tenant_id": TENANT, "now_ms": -1},
        {"tenant_id": TENANT, "now_ms": 0, "cost_microunits": -1},
        {"tenant_id": TENANT, "now_ms": 0, "cost_microunits": MAX_SPEND_MICROUNITS + 1},
    ):
        with pytest.raises(QuotaError) as error:
            ledger.check(**arguments)
        assert error.value.code is QuotaErrorCode.INVALID_CONFIGURATION


def test_tenant_capacity_is_bounded_at_configuration() -> None:
    """The declared tenant bound is enforced where it can actually be violated."""

    with pytest.raises(QuotaError) as error:
        QuotaLedger(tuple(_policy(tenant_id=f"tenant-{index}") for index in range(MAX_TENANTS + 1)))
    assert error.value.code is QuotaErrorCode.INVALID_CONFIGURATION


def test_decision_document_is_metadata_only() -> None:
    ledger = QuotaLedger((_policy(),))
    document = ledger.check(tenant_id=TENANT, now_ms=0).document()
    assert set(document) == {
        "allowed",
        "remaining_requests",
        "remaining_spend_microunits",
        "retry_after_seconds",
    }
    assert all(type(value) in {bool, int} for value in document.values())
