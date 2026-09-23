"""Strict ETag parsing for durable control-plane mutations."""

from __future__ import annotations

import pytest
from securecode_ai.server.persistence import PreconditionError
from securecode_ai.server.ports import ServiceRequest, VerifiedIdentity
from securecode_ai.server.service import _precondition


def _request(precondition: str | None) -> ServiceRequest:
    return ServiceRequest(
        method="POST",
        route="/api/v1/runs/{run_id}:cancel",
        action="runs.cancel",
        identity=VerifiedIdentity("user", "tenant", frozenset({"operator"})),
        idempotency_key="request-key",
        precondition=precondition,
        path_params={"run_id": "run-1"},
        query={},
        document={},
        raw_body=b"{}",
    )


@pytest.mark.parametrize("value", ('"1"', "1"))
def test_precondition_accepts_current_decimal_version(value: str) -> None:
    assert _precondition(_request(value)) == 1


@pytest.mark.parametrize(
    "value",
    (
        '""1""',
        '"\u0661"',
        "9" * 5000,
        '"2147483648"',
        "0",
        None,
    ),
    ids=("nested-quotes", "unicode-digit", "oversized", "outside-range", "zero", "missing"),
)
def test_precondition_rejects_noncanonical_or_unbounded_versions(value: str | None) -> None:
    with pytest.raises(PreconditionError):
        _precondition(_request(value))
