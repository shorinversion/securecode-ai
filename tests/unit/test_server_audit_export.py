"""P6.10 immutable audit exports."""

from __future__ import annotations

import pytest
from securecode_ai.server.audit_export import MAX_AUDIT_EXPORT_EVENTS, export_audit
from securecode_ai.server.audit_log import AuditConflict, AuditLog


def test_audit_chain_replays_exactly_and_exports_without_authority() -> None:
    log = AuditLog()
    event = log.append(
        tenant_id="t",
        repository_id="r",
        run_id="run",
        actor_id="actor",
        action="runs.create",
        identity_hash="a" * 64,
        expected_sequence=0,
        attributes={"outcome": "PASS"},
        idempotency_key="key",
    )
    assert (
        log.append(
            tenant_id="t",
            repository_id="r",
            run_id="run",
            actor_id="actor",
            action="runs.create",
            identity_hash="a" * 64,
            expected_sequence=0,
            attributes={"outcome": "PASS"},
            idempotency_key="key",
        )
        == event
    )
    document = export_audit(log, tenant_id="t", run_id="run")["document"]
    assert isinstance(document, dict)
    assert document["authority"] == "NONE"


def test_divergent_replay_and_unallowlisted_data_fail_closed() -> None:
    log = AuditLog()
    with pytest.raises(AuditConflict):
        log.append(
            tenant_id="t",
            repository_id="r",
            run_id="run",
            actor_id="actor",
            action="runs.create",
            identity_hash="a" * 64,
            expected_sequence=0,
            attributes={"source": "no"},
            idempotency_key="key",
        )


def test_corrupted_chain_cannot_be_exported_as_valid_evidence() -> None:
    log = AuditLog()
    log.append(
        tenant_id="t",
        repository_id="r",
        run_id="run",
        actor_id="actor",
        action="runs.create",
        identity_hash="a" * 64,
        expected_sequence=0,
        attributes={"outcome": "PASS"},
        idempotency_key="key",
    )
    log._db.execute(
        "UPDATE audit_chain_events SET event_hash = ? WHERE tenant_id = ? AND run_id = ?",
        ("b" * 64, "t", "run"),
    )

    with pytest.raises(AuditConflict, match="hash chain"):
        export_audit(log, tenant_id="t", run_id="run")


def test_audit_export_range_is_bounded_and_can_be_paged() -> None:
    log = AuditLog()
    for index in range(MAX_AUDIT_EXPORT_EVENTS + 1):
        log.append(
            tenant_id="t",
            repository_id="r",
            run_id="run",
            actor_id="actor",
            action="runs.create",
            identity_hash="a" * 64,
            expected_sequence=index,
            attributes={"outcome": "PASS"},
            idempotency_key=f"key-{index}",
        )

    with pytest.raises(ValueError, match="event limit"):
        export_audit(log, tenant_id="t", run_id="run")

    page = export_audit(
        log,
        tenant_id="t",
        run_id="run",
        start=MAX_AUDIT_EXPORT_EVENTS,
        end=MAX_AUDIT_EXPORT_EVENTS + 1,
    )
    document = page["document"]
    assert isinstance(document, dict)
    assert len(document["events"]) == 2
