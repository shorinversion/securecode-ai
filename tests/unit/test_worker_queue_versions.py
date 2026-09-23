"""Strict parsing for optimistic worker-state versions."""

from __future__ import annotations

import pytest
from securecode_ai.server.worker_queue_handler import _version
from securecode_ai.server.worker_queue_models import WorkerQueueConflict


@pytest.mark.parametrize("value", ("1", '"1"'))
def test_worker_version_accepts_current_decimal(value: str) -> None:
    assert _version(value) == 1


@pytest.mark.parametrize(
    "value",
    ('""1""', '"\u0661"', "9" * 5000, '"2147483648"', "0", None),
    ids=("nested-quotes", "unicode-digit", "oversized", "outside-range", "zero", "missing"),
)
def test_worker_version_rejects_malformed_or_unbounded_values(value: str | None) -> None:
    with pytest.raises(WorkerQueueConflict):
        _version(value)
