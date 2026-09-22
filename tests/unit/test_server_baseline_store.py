from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest
from securecode_ai.contracts import AuditRun
from securecode_ai.server.baseline_store import BaselineStoreError, DurableBaselineStore


def test_baseline_store_rejects_non_audit_runs() -> None:
    store = DurableBaselineStore(sqlite3.connect(":memory:"))

    with pytest.raises(BaselineStoreError, match="baseline audit run is invalid"):
        store.record(object())  # type: ignore[arg-type]


def test_missing_baseline_is_not_treated_as_empty_baseline() -> None:
    store = DurableBaselineStore(sqlite3.connect(":memory:"))

    with pytest.raises(BaselineStoreError, match="baseline revision is unavailable"):
        store.load(tenant_id="tenant", repository_id="repository", revision_sha="a" * 40)


def test_recorded_empty_baseline_replays_and_is_loadable() -> None:
    store = DurableBaselineStore(sqlite3.connect(":memory:"))
    revision = SimpleNamespace(tenant_id="tenant", repository_id="repository", head_sha="a" * 40)
    audit = AuditRun.model_construct(
        execution_identity=SimpleNamespace(repository_revision=revision),
        coverage_manifest=SimpleNamespace(discovery_candidates=()),
    )

    first = store.record(audit)
    second = store.record(audit)

    assert (
        first
        == second
        == store.load(tenant_id="tenant", repository_id="repository", revision_sha="a" * 40)
    )


def test_compare_uses_the_exact_persisted_base_and_trusted_lineage() -> None:
    store = DurableBaselineStore(sqlite3.connect(":memory:"))
    base = "a" * 40
    head = "b" * 40
    base_audit = AuditRun.model_construct(
        execution_identity=SimpleNamespace(
            repository_revision=SimpleNamespace(
                tenant_id="tenant", repository_id="repository", head_sha=base
            )
        ),
        coverage_manifest=SimpleNamespace(discovery_candidates=()),
    )
    head_audit = AuditRun.model_construct(
        execution_identity=SimpleNamespace(
            repository_revision=SimpleNamespace(
                tenant_id="tenant", repository_id="repository", base_sha=base, head_sha=head
            )
        ),
        coverage_manifest=SimpleNamespace(discovery_candidates=()),
        current_head_sha=head,
    )
    store.record(base_audit)

    comparison = store.compare_for_audit(head_audit, commit_lineage=(base, head))

    assert comparison.base_sha == base
    assert comparison.head_sha == head
    assert comparison.new_fingerprints == ()
