"""Resolve whether active waivers cover a persisted SCM policy decision."""

from __future__ import annotations

import sqlite3

from securecode_ai.contracts import AuditRunOutcome
from securecode_ai.core.scm_policy import ScmPolicyDecision, ScmPolicyEnforcement

from .waivers import WaiverLedger
from .worker_findings_store import load_worker_findings_for_run


def waivers_cover_run_policy(
    connection: sqlite3.Connection,
    waivers: WaiverLedger,
    *,
    tenant_id: str,
    run_id: str,
    identity_hash: str,
    decision: ScmPolicyDecision,
) -> bool:
    if (
        type(connection) is not sqlite3.Connection
        or type(decision) is not ScmPolicyDecision
        or decision.observed_audit_outcome is not AuditRunOutcome.FAIL
        or decision.enforcement is not ScmPolicyEnforcement.BLOCK
        or decision.error_code is not None
        or not decision.publication_permitted
        or decision.input_hashes is None
        or decision.input_hashes.execution_identity_sha256 != identity_hash
    ):
        return False
    row = connection.execute(
        "SELECT repository_id, execution_identity_hash, head_sha, state FROM audit_runs "
        "WHERE tenant_id=? AND run_id=?",
        (tenant_id, run_id),
    ).fetchone()
    if (
        row is None
        or row[1] != identity_hash
        or type(row[0]) is not str
        or type(row[2]) is not str
        or row[3] != AuditRunOutcome.FAIL.value
    ):
        return False
    findings = load_worker_findings_for_run(
        connection,
        tenant_id=tenant_id,
        run_id=run_id,
    )
    blocking = tuple(item for item in findings if item.blocking)
    if not blocking or any(item.revision_sha != row[2] for item in blocking):
        return False
    return waivers.covers_blocking_findings(
        tenant_id=tenant_id,
        repository_id=row[0],
        run_id=run_id,
        identity_hash=identity_hash,
        findings=tuple(
            (item.finding_id, item.root_cause_fingerprint) for item in blocking
        ),
        policy_scope=decision.policy_id,
    )


__all__ = ["waivers_cover_run_policy"]
