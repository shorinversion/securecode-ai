from __future__ import annotations

import sqlite3

import pytest
from securecode_ai.server.baseline_store import BaselineStoreError, DurableBaselineStore


def test_baseline_store_rejects_non_audit_runs() -> None:
    store = DurableBaselineStore(sqlite3.connect(":memory:"))

    with pytest.raises(BaselineStoreError, match="baseline audit run is invalid"):
        store.record(object())  # type: ignore[arg-type]


def test_missing_baseline_is_not_treated_as_empty_baseline() -> None:
    store = DurableBaselineStore(sqlite3.connect(":memory:"))

    with pytest.raises(BaselineStoreError, match="baseline revision is unavailable"):
        store.load(tenant_id="tenant", repository_id="repository", revision_sha="a" * 40)
