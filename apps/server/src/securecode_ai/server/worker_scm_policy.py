"""Persist source-free advisory policy decisions in a run's event stream."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from typing import Final

from securecode_ai.contracts import AuditRun, AuditRunOutcome
from securecode_ai.core.baseline_fingerprints import BaselineFingerprintComparison
from securecode_ai.core.scm_policy import (
    ScmPolicyDecision,
    ScmPolicyDocument,
    ScmPolicyEnforcement,
    ScmPolicyErrorCode,
    ScmPolicyInputHashes,
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
        type(decision) is not ScmPolicyDecision
        or decision.mode is not ScmPolicyMode.ADVISORY
        or decision.enforcement is not ScmPolicyEnforcement.ADVISORY
        or decision.blocks_merge
        or not decision.publication_permitted
    ):
        raise ScmPolicyReceiptConflict("advisory policy receipt is invalid")
    return record_scm_policy_decision(
        cursor,
        tenant_id=tenant_id,
        run_id=run_id,
        decision=decision,
    )


def record_scm_policy_decision(
    cursor: sqlite3.Cursor,
    *,
    tenant_id: str,
    run_id: str,
    decision: ScmPolicyDecision,
) -> int:
    """Store one verified policy decision idempotently in the run event stream."""

    if (
        not isinstance(cursor, sqlite3.Cursor)
        or type(tenant_id) is not str
        or _IDENTIFIER.fullmatch(tenant_id) is None
        or type(run_id) is not str
        or _IDENTIFIER.fullmatch(run_id) is None
        or type(decision) is not ScmPolicyDecision
        or decision.input_hashes is None
        or not _decision_digest_is_valid(decision)
    ):
        raise ScmPolicyReceiptConflict("SCM policy receipt is invalid")

    metadata = {
        "kind": "SCM_POLICY_DECISION",
        "policy_decision": decision.metadata(),
    }
    encoded = json.dumps(
        metadata, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    )
    existing_rows = cursor.execute(
        """SELECT sequence, metadata_json FROM run_events
           WHERE tenant_id=? AND run_id=? AND event_id LIKE 'securecode-policy-%'
           ORDER BY sequence""",
        (tenant_id, run_id),
    ).fetchall()
    if existing_rows:
        if len(existing_rows) != 1 or existing_rows[0][1] != encoded:
            raise ScmPolicyReceiptConflict("SCM policy replay conflicts")
        sequence = existing_rows[0][0]
        if type(sequence) is not int or sequence < 1:
            raise ScmPolicyReceiptConflict("SCM policy replay is invalid")
        return sequence

    sequence = cursor.execute(
        """SELECT COALESCE(MAX(sequence), 0) + 1 FROM run_events
           WHERE tenant_id=? AND run_id=?""",
        (tenant_id, run_id),
    ).fetchone()[0]
    if type(sequence) is not int or sequence < 1:
        raise ScmPolicyReceiptConflict("SCM policy event sequence is invalid")
    event_id = "securecode-policy-decision-v1"
    cursor.execute(
        """INSERT INTO run_events
           (tenant_id, run_id, sequence, event_id, metadata_json)
           VALUES (?, ?, ?, ?, ?)""",
        (tenant_id, run_id, sequence, event_id, encoded),
    )
    return sequence


def load_run_scm_policy_decision(
    connection: sqlite3.Connection,
    *,
    tenant_id: str,
    run_id: str,
    execution_identity_hash: str,
) -> ScmPolicyDecision | None:
    """Read and revalidate the single policy receipt pinned to one run identity."""

    if (
        not isinstance(connection, sqlite3.Connection)
        or type(tenant_id) is not str
        or _IDENTIFIER.fullmatch(tenant_id) is None
        or type(run_id) is not str
        or _IDENTIFIER.fullmatch(run_id) is None
        or type(execution_identity_hash) is not str
        or not _sha256(execution_identity_hash)
    ):
        raise ScmPolicyReceiptConflict("SCM policy lookup is invalid")
    rows = connection.execute(
        """SELECT metadata_json FROM run_events
           WHERE tenant_id=? AND run_id=? AND event_id LIKE 'securecode-policy-%'
           ORDER BY sequence""",
        (tenant_id, run_id),
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1 or type(rows[0][0]) is not str:
        raise ScmPolicyReceiptConflict("SCM policy receipt is ambiguous")
    try:
        envelope = json.loads(rows[0][0])
        if (
            type(envelope) is not dict
            or set(envelope) != {"kind", "policy_decision"}
            or envelope["kind"] != "SCM_POLICY_DECISION"
        ):
            raise ValueError
        raw = envelope["policy_decision"]
        if type(raw) is not dict or set(raw) != {
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
        }:
            raise ValueError
        hashes_raw = raw["input_hashes"]
        if type(hashes_raw) is not dict or set(hashes_raw) != {
            "audit_run_sha256",
            "baseline_comparison_sha256",
            "execution_identity_sha256",
            "policy_document_sha256",
        }:
            raise ValueError
        hashes = ScmPolicyInputHashes(**hashes_raw)
        if hashes.execution_identity_sha256 != execution_identity_hash:
            raise ValueError
        decision = ScmPolicyDecision(
            schema_version=raw["schema_version"],
            policy_id=raw["policy_id"],
            policy_version=raw["policy_version"],
            mode=None if raw["mode"] is None else ScmPolicyMode(raw["mode"]),
            observed_audit_outcome=(
                None
                if raw["observed_audit_outcome"] is None
                else AuditRunOutcome(raw["observed_audit_outcome"])
            ),
            enforcement=ScmPolicyEnforcement(raw["enforcement"]),
            is_passing=raw["is_passing"],
            blocks_merge=raw["blocks_merge"],
            publication_permitted=raw["publication_permitted"],
            input_hashes=hashes,
            matched_rule_ids=tuple(raw["matched_rule_ids"]),
            error_code=(
                None if raw["error_code"] is None else ScmPolicyErrorCode(raw["error_code"])
            ),
            decision_sha256=raw["decision_sha256"],
        )
        if not _decision_digest_is_valid(decision):
            raise ValueError
        return decision
    except (KeyError, TypeError, ValueError):
        raise ScmPolicyReceiptConflict("SCM policy receipt is invalid") from None


def _decision_digest_is_valid(decision: ScmPolicyDecision) -> bool:
    material = decision.metadata()
    declared = material.pop("decision_sha256", None)
    encoded = json.dumps(
        material, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    )
    return type(declared) is str and hashlib.sha256(encoded.encode("ascii")).hexdigest() == declared


def _sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


__all__ = [
    "ScmPolicyReceiptConflict",
    "load_run_scm_policy_decision",
    "record_advisory_policy_decision",
    "record_run_advisory_policy",
    "record_scm_policy_decision",
]
