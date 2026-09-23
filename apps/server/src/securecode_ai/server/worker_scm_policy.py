"""Persist source-free advisory policy decisions in a run's event stream."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from typing import Final

from securecode_ai.contracts import AuditRun
from securecode_ai.core.baseline_fingerprints import BaselineFingerprintComparison
from securecode_ai.core.scm_policy import (
    ScmPolicyDecision,
    ScmPolicyDocument,
    ScmPolicyEnforcement,
    ScmPolicyMode,
    ScmPolicyRequest,
    evaluate_scm_policy,
)

_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class ScmPolicyReceiptConflict(ValueError):
    """Raised when a replay conflicts with an immutable stored policy decision."""


def record_run_advisory_policy(
    cursor: sqlite3.Cursor,
    *,
    audit_run: AuditRun,
    baseline_comparison: BaselineFingerprintComparison | None = None,
) -> int:
    """Evaluate the immutable identity policy pin in advisory mode and persist it."""

    if type(audit_run) is not AuditRun:
        raise ScmPolicyReceiptConflict("advisory policy input is invalid")
    pin = audit_run.execution_identity.policy
    policy = ScmPolicyDocument(
        policy_id=pin.component_id,
        policy_version=pin.component_version,
        content_sha256=pin.content_sha256,
    )
    decision = evaluate_scm_policy(
        ScmPolicyRequest(
            policy=policy,
            mode=ScmPolicyMode.ADVISORY,
            audit_run=audit_run,
            baseline_comparison=baseline_comparison,
        )
    )
    return record_advisory_policy_decision(
        cursor,
        tenant_id=audit_run.execution_identity.repository_revision.tenant_id,
        run_id=audit_run.run_id,
        decision=decision,
    )


def record_advisory_policy_decision(
    cursor: sqlite3.Cursor,
    *,
    tenant_id: str,
    run_id: str,
    decision: ScmPolicyDecision,
) -> int:
    """Store one idempotent advisory decision in the existing run event stream."""

    if (
        not isinstance(cursor, sqlite3.Cursor)
        or type(tenant_id) is not str
        or _IDENTIFIER.fullmatch(tenant_id) is None
        or type(run_id) is not str
        or _IDENTIFIER.fullmatch(run_id) is None
        or type(decision) is not ScmPolicyDecision
        or decision.mode is not ScmPolicyMode.ADVISORY
        or decision.enforcement is not ScmPolicyEnforcement.ADVISORY
        or decision.blocks_merge
        or not decision.publication_permitted
        or not _decision_digest_is_valid(decision)
    ):
        raise ScmPolicyReceiptConflict("advisory policy receipt is invalid")

    metadata = {
        "kind": "SCM_POLICY_DECISION",
        "policy_decision": decision.metadata(),
    }
    encoded = json.dumps(
        metadata, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    )
    event_id = f"securecode-policy-{decision.decision_sha256}"
    existing = cursor.execute(
        """SELECT sequence, metadata_json FROM run_events
           WHERE tenant_id=? AND run_id=? AND event_id=?""",
        (tenant_id, run_id, event_id),
    ).fetchone()
    if existing is not None:
        if existing[1] != encoded:
            raise ScmPolicyReceiptConflict("advisory policy replay conflicts")
        sequence = existing[0]
        if type(sequence) is not int or sequence < 1:
            raise ScmPolicyReceiptConflict("advisory policy replay is invalid")
        return sequence

    sequence = cursor.execute(
        """SELECT COALESCE(MAX(sequence), 0) + 1 FROM run_events
           WHERE tenant_id=? AND run_id=?""",
        (tenant_id, run_id),
    ).fetchone()[0]
    if type(sequence) is not int or sequence < 1:
        raise ScmPolicyReceiptConflict("advisory policy event sequence is invalid")
    cursor.execute(
        """INSERT INTO run_events
           (tenant_id, run_id, sequence, event_id, metadata_json)
           VALUES (?, ?, ?, ?, ?)""",
        (tenant_id, run_id, sequence, event_id, encoded),
    )
    return sequence


def _decision_digest_is_valid(decision: ScmPolicyDecision) -> bool:
    material = decision.metadata()
    declared = material.pop("decision_sha256", None)
    encoded = json.dumps(
        material, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    )
    return type(declared) is str and hashlib.sha256(encoded.encode("ascii")).hexdigest() == declared


__all__ = [
    "ScmPolicyReceiptConflict",
    "record_advisory_policy_decision",
    "record_run_advisory_policy",
]
