from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from securecode_ai.adapters.product_audit_types import _AuditObstacle
from securecode_ai.adapters.product_audit_validation import _repair_requested_candidate_ids


def _call(requested: tuple[str, ...]) -> tuple[str, ...]:
    flow: Any = SimpleNamespace(
        graph=SimpleNamespace(
            candidates=(SimpleNamespace(candidate_id="candidate-a", candidate_version=1),)
        )
    )
    review: Any = SimpleNamespace(
        outcomes=(SimpleNamespace(candidate_id="candidate-a", has_known_blocking_finding=True),)
    )
    host: Any = SimpleNamespace(
        operation="repair",
        repair_requested_candidate_ids=requested,
        repair_coverage_units=(),
    )
    return _repair_requested_candidate_ids(flow, review, host)


def test_repair_request_for_current_blocking_candidate_reaches_coverage_check() -> None:
    # A request naming a current, blocking candidate ID must be accepted as a
    # target; with no receipts the failure is missing coverage, not a bad target.
    with pytest.raises(_AuditObstacle) as raised:
        _call(("candidate-a",))
    assert raised.value.code == "PRODUCT_REPAIR_COVERAGE_INCOMPLETE"


def test_repair_request_for_unknown_candidate_is_rejected() -> None:
    with pytest.raises(_AuditObstacle) as raised:
        _call(("candidate-z",))
    assert raised.value.code == "PRODUCT_REPAIR_INPUT_INVALID"
