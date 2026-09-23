"""Persistence contracts for connected-run advisory policy decisions."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace

import pytest
from securecode_ai.contracts import AuditRunOutcome
from securecode_ai.core.scm_policy import (
    SCM_POLICY_SCHEMA_VERSION,
    ScmPolicyDecision,
    ScmPolicyEnforcement,
    ScmPolicyErrorCode,
    ScmPolicyInputHashes,
    ScmPolicyMode,
)
from securecode_ai.server.scm_completion_models import (
    SCMCompletionError,
    scm_publication_outcome,
)
from securecode_ai.server.worker_scm_policy import (
    ScmPolicyReceiptConflict,
    load_run_scm_policy_decision,
    record_advisory_policy_decision,
    record_scm_policy_decision,
)

_DIGEST = "a" * 64


def _decision() -> ScmPolicyDecision:
    hashes = ScmPolicyInputHashes(
        policy_document_sha256=_DIGEST,
        audit_run_sha256="b" * 64,
        execution_identity_sha256="c" * 64,
        baseline_comparison_sha256=None,
    )
    material = {
        "blocks_merge": False,
        "enforcement": ScmPolicyEnforcement.ADVISORY.value,
        "error_code": None,
        "input_hashes": {
            "policy_document_sha256": hashes.policy_document_sha256,
            "audit_run_sha256": hashes.audit_run_sha256,
            "execution_identity_sha256": hashes.execution_identity_sha256,
            "baseline_comparison_sha256": None,
        },
        "is_passing": False,
        "matched_rule_ids": ("advisory_non_blocking",),
        "mode": ScmPolicyMode.ADVISORY.value,
        "observed_audit_outcome": AuditRunOutcome.FAIL.value,
        "policy_id": "policy-v1",
        "policy_version": "1.0.0",
        "publication_permitted": True,
        "schema_version": SCM_POLICY_SCHEMA_VERSION,
    }
    digest = hashlib.sha256(
        json.dumps(
            material, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    ).hexdigest()
    return ScmPolicyDecision(
        schema_version=SCM_POLICY_SCHEMA_VERSION,
        policy_id="policy-v1",
        policy_version="1.0.0",
        mode=ScmPolicyMode.ADVISORY,
        observed_audit_outcome=AuditRunOutcome.FAIL,
        enforcement=ScmPolicyEnforcement.ADVISORY,
        is_passing=False,
        blocks_merge=False,
        publication_permitted=True,
        input_hashes=hashes,
        matched_rule_ids=("advisory_non_blocking",),
        error_code=None,
        decision_sha256=digest,
    )


def _strict_non_pass_decision() -> ScmPolicyDecision:
    hashes = ScmPolicyInputHashes(
        policy_document_sha256=_DIGEST,
        audit_run_sha256="b" * 64,
        execution_identity_sha256="c" * 64,
        baseline_comparison_sha256=None,
    )
    material = {
        "blocks_merge": False,
        "enforcement": ScmPolicyEnforcement.NON_PASS.value,
        "error_code": ScmPolicyErrorCode.PRECALIBRATION_BLOCKING.value,
        "input_hashes": {
            "policy_document_sha256": hashes.policy_document_sha256,
            "audit_run_sha256": hashes.audit_run_sha256,
            "execution_identity_sha256": hashes.execution_identity_sha256,
            "baseline_comparison_sha256": None,
        },
        "is_passing": False,
        "matched_rule_ids": ("precalibration_blocking_rejected",),
        "mode": ScmPolicyMode.STRICT.value,
        "observed_audit_outcome": AuditRunOutcome.PASS.value,
        "policy_id": "policy-v1",
        "policy_version": "1.0.0",
        "publication_permitted": False,
        "schema_version": SCM_POLICY_SCHEMA_VERSION,
    }
    digest = hashlib.sha256(
        json.dumps(
            material, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    ).hexdigest()
    return ScmPolicyDecision(
        schema_version=SCM_POLICY_SCHEMA_VERSION,
        policy_id="policy-v1",
        policy_version="1.0.0",
        mode=ScmPolicyMode.STRICT,
        observed_audit_outcome=AuditRunOutcome.PASS,
        enforcement=ScmPolicyEnforcement.NON_PASS,
        is_passing=False,
        blocks_merge=False,
        publication_permitted=False,
        input_hashes=hashes,
        matched_rule_ids=("precalibration_blocking_rejected",),
        error_code=ScmPolicyErrorCode.PRECALIBRATION_BLOCKING,
        decision_sha256=digest,
    )


def _rehash(
    decision: ScmPolicyDecision,
    *,
    mode: ScmPolicyMode,
    enforcement: ScmPolicyEnforcement,
    blocks_merge: bool,
    matched_rule_ids: tuple[str, ...],
) -> ScmPolicyDecision:
    updated = replace(
        decision,
        mode=mode,
        enforcement=enforcement,
        blocks_merge=blocks_merge,
        matched_rule_ids=matched_rule_ids,
    )
    material = updated.metadata()
    material.pop("decision_sha256")
    digest = hashlib.sha256(
        json.dumps(
            material, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    ).hexdigest()
    return replace(updated, decision_sha256=digest)


def _connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        """CREATE TABLE run_events (
            tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, sequence INTEGER NOT NULL,
            event_id TEXT NOT NULL, metadata_json TEXT NOT NULL,
            PRIMARY KEY (tenant_id, run_id, sequence), UNIQUE (tenant_id, run_id, event_id)
        )"""
    )
    return connection


def test_advisory_decision_is_source_free_and_idempotent() -> None:
    connection = _connection()
    decision = _decision()

    with connection:
        first = record_advisory_policy_decision(
            connection.cursor(), tenant_id="tenant-1", run_id="run-1", decision=decision
        )
        replay = record_advisory_policy_decision(
            connection.cursor(), tenant_id="tenant-1", run_id="run-1", decision=decision
        )

    rows = connection.execute("SELECT * FROM run_events").fetchall()
    assert first == replay == 1
    assert len(rows) == 1
    assert rows[0][0:3] == ("tenant-1", "run-1", 1)
    document = json.loads(rows[0][4])
    assert document["kind"] == "SCM_POLICY_DECISION"
    assert document["policy_decision"]["mode"] == "advisory"
    assert document["policy_decision"]["enforcement"] == "ADVISORY"
    assert document["policy_decision"]["blocks_merge"] is False
    assert set(document["policy_decision"]) == {
        "blocks_merge",
        "decision_sha256",
        "enforcement",
        "error_code",
        "input_hashes",
        "is_passing",
        "matched_rule_ids",
        "mode",
        "observed_audit_outcome",
        "policy_id",
        "policy_version",
        "publication_permitted",
        "schema_version",
    }


def test_policy_receipt_is_scoped_by_tenant_and_run() -> None:
    connection = _connection()
    decision = _decision()

    with connection:
        first = record_advisory_policy_decision(
            connection.cursor(), tenant_id="tenant-1", run_id="run-1", decision=decision
        )
        second = record_advisory_policy_decision(
            connection.cursor(), tenant_id="tenant-2", run_id="run-1", decision=decision
        )

    assert first == second == 1
    assert connection.execute("SELECT COUNT(*) FROM run_events").fetchone()[0] == 2


def test_non_pass_rollout_decision_can_be_persisted_idempotently() -> None:
    connection = _connection()
    decision = _strict_non_pass_decision()

    with connection:
        first = record_scm_policy_decision(
            connection.cursor(), tenant_id="tenant-1", run_id="run-1", decision=decision
        )
        replay = record_scm_policy_decision(
            connection.cursor(), tenant_id="tenant-1", run_id="run-1", decision=decision
        )

    row = connection.execute("SELECT metadata_json FROM run_events").fetchone()
    assert first == replay == 1
    assert json.loads(row[0])["policy_decision"]["error_code"] == "PRECALIBRATION_BLOCKING"


def test_policy_decision_loader_binds_receipt_to_exact_identity() -> None:
    connection = _connection()
    decision = _decision()
    with connection:
        record_scm_policy_decision(
            connection.cursor(), tenant_id="tenant-1", run_id="run-1", decision=decision
        )

    loaded = load_run_scm_policy_decision(
        connection,
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity_hash="c" * 64,
    )
    assert loaded == decision
    with pytest.raises(ScmPolicyReceiptConflict):
        load_run_scm_policy_decision(
            connection,
            tenant_id="tenant-1",
            run_id="run-1",
            execution_identity_hash="d" * 64,
        )


def test_scm_policy_modes_control_only_the_published_outcome() -> None:
    advisory = _decision()
    strict_block = _rehash(
        advisory,
        mode=ScmPolicyMode.STRICT,
        enforcement=ScmPolicyEnforcement.BLOCK,
        blocks_merge=True,
        matched_rule_ids=("confirmed_finding",),
    )
    new_code_legacy = _rehash(
        advisory,
        mode=ScmPolicyMode.NEW_CODE,
        enforcement=ScmPolicyEnforcement.ALLOW,
        blocks_merge=False,
        matched_rule_ids=("legacy_debt_non_blocking",),
    )

    assert (
        scm_publication_outcome(AuditRunOutcome.FAIL, advisory, execution_identity_hash="c" * 64)
        is AuditRunOutcome.FAIL
    )
    assert (
        scm_publication_outcome(
            AuditRunOutcome.FAIL, strict_block, execution_identity_hash="c" * 64
        )
        is AuditRunOutcome.FAIL
    )
    assert (
        scm_publication_outcome(
            AuditRunOutcome.FAIL, new_code_legacy, execution_identity_hash="c" * 64
        )
        is AuditRunOutcome.PASS
    )
    assert (
        scm_publication_outcome(
            AuditRunOutcome.PASS,
            _strict_non_pass_decision(),
            execution_identity_hash="c" * 64,
        )
        is AuditRunOutcome.INDETERMINATE
    )
    with pytest.raises(SCMCompletionError):
        scm_publication_outcome(
            AuditRunOutcome.FAIL, strict_block, execution_identity_hash="d" * 64
        )


def test_run_cannot_record_a_second_policy_decision() -> None:
    connection = _connection()

    with connection:
        record_scm_policy_decision(
            connection.cursor(),
            tenant_id="tenant-1",
            run_id="run-1",
            decision=_decision(),
        )
        with pytest.raises(ScmPolicyReceiptConflict):
            record_scm_policy_decision(
                connection.cursor(),
                tenant_id="tenant-1",
                run_id="run-1",
                decision=_strict_non_pass_decision(),
            )

    assert connection.execute("SELECT COUNT(*) FROM run_events").fetchone()[0] == 1


@pytest.mark.parametrize(
    "invalid",
    (
        lambda decision: replace(decision, decision_sha256="0" * 64),
        lambda decision: replace(decision, mode=ScmPolicyMode.STRICT),
    ),
)
def test_non_advisory_or_forged_decisions_are_rejected(invalid: object) -> None:
    connection = _connection()
    decision = invalid(_decision())  # type: ignore[operator]

    with pytest.raises(ScmPolicyReceiptConflict):
        record_advisory_policy_decision(
            connection.cursor(), tenant_id="tenant-1", run_id="run-1", decision=decision
        )

    assert connection.execute("SELECT COUNT(*) FROM run_events").fetchone()[0] == 0
