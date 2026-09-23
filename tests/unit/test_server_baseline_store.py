from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest
from securecode_ai.contracts import AnalysisHealth, AuditRun, AuditRunOutcome
from securecode_ai.server.baseline_store import BaselineStoreError, DurableBaselineStore


def _audit(
    *,
    tenant_id: str = "tenant",
    repository_id: str = "repository",
    head_sha: str = "a" * 40,
    base_sha: str | None = None,
    current_head_sha: str | None = None,
    audit_outcome: AuditRunOutcome = AuditRunOutcome.PASS,
    analysis_health: AnalysisHealth = AnalysisHealth.HEALTHY,
    coverage_complete: bool = True,
) -> AuditRun:
    revision = SimpleNamespace(
        tenant_id=tenant_id,
        repository_id=repository_id,
        head_sha=head_sha,
        base_sha=base_sha,
    )
    return AuditRun.model_construct(
        execution_identity=SimpleNamespace(repository_revision=revision),
        current_head_sha=head_sha if current_head_sha is None else current_head_sha,
        audit_outcome=audit_outcome,
        analysis_health=analysis_health,
        coverage_manifest=SimpleNamespace(
            coverage_complete=coverage_complete,
            discovery_candidates=(),
        ),
    )


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
    audit = _audit()

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
    base_audit = _audit(head_sha=base)
    head_audit = _audit(head_sha=head, base_sha=base)
    store.record(base_audit)

    comparison = store.compare_for_audit(head_audit, commit_lineage=(base, head))

    assert comparison.base_sha == base
    assert comparison.head_sha == head
    assert comparison.new_fingerprints == ()


def test_record_in_transaction_is_rolled_back_with_terminal_transition() -> None:
    connection = sqlite3.connect(":memory:")
    store = DurableBaselineStore(connection)
    audit = _audit()
    cursor = connection.cursor()
    try:
        cursor.execute("BEGIN IMMEDIATE")
        store.record_in_transaction(cursor, audit)
        connection.rollback()
    finally:
        cursor.close()

    with pytest.raises(BaselineStoreError, match="baseline revision is unavailable"):
        store.load(tenant_id="tenant", repository_id="repository", revision_sha="a" * 40)


def test_record_in_transaction_commits_with_terminal_transition() -> None:
    connection = sqlite3.connect(":memory:")
    store = DurableBaselineStore(connection)
    audit = _audit()
    cursor = connection.cursor()
    try:
        cursor.execute("BEGIN IMMEDIATE")
        store.record_in_transaction(cursor, audit)
        connection.commit()
    finally:
        cursor.close()

    assert store.load(tenant_id="tenant", repository_id="repository", revision_sha="a" * 40)


@pytest.mark.parametrize(
    ("audit_outcome", "analysis_health", "coverage_complete", "current_head_sha"),
    (
        (AuditRunOutcome.INDETERMINATE, AnalysisHealth.HEALTHY, False, "a" * 40),
        (AuditRunOutcome.ERROR, AnalysisHealth.UNAVAILABLE, True, "a" * 40),
        (AuditRunOutcome.CANCELLED, AnalysisHealth.HEALTHY, True, "a" * 40),
        (AuditRunOutcome.SUPERSEDED, AnalysisHealth.HEALTHY, True, "b" * 40),
    ),
)
def test_incomplete_terminal_run_cannot_become_a_reusable_baseline(
    audit_outcome: AuditRunOutcome,
    analysis_health: AnalysisHealth,
    coverage_complete: bool,
    current_head_sha: str,
) -> None:
    store = DurableBaselineStore(sqlite3.connect(":memory:"))

    with pytest.raises(BaselineStoreError, match="baseline audit run is incomplete"):
        store.record(
            _audit(
                audit_outcome=audit_outcome,
                analysis_health=analysis_health,
                coverage_complete=coverage_complete,
                current_head_sha=current_head_sha,
            )
        )
