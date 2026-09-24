"""Atomic terminal queue transition and durable finding ingestion."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime

from securecode_ai.contracts import ArtifactRef

from .worker_findings import WorkerFindingRecord, parse_worker_findings
from .worker_queue_models import (
    OUTCOME_STATES,
    WorkerQueueConflict,
    WorkerQueueLease,
    canonical,
    command,
    identity_document,
    lease_arguments,
    timestamp,
    utc,
)
from .worker_resource_accounting import settle_worker_resources
from .worker_resource_models import WorkerResourceSettlement


def complete_worker_run(
    connection: sqlite3.Connection,
    *,
    lease_seconds: int,
    now: Callable[[], datetime],
    tenant_id: str,
    session_id: str,
    worker_id: str,
    execution_identity_hash: str,
    run_id: str,
    expected_version: int,
    outcome: str,
    findings: tuple[WorkerFindingRecord, ...],
    resource_settlement: WorkerResourceSettlement | None = None,
    resource_clock: Callable[[], int] | None = None,
    terminal_transaction_effect: Callable[[sqlite3.Cursor], None] | None = None,
) -> WorkerQueueLease:
    if (
        outcome not in OUTCOME_STATES
        or type(findings) is not tuple
        or any(type(item) is not WorkerFindingRecord for item in findings)
        or type(resource_settlement) is not WorkerResourceSettlement
        or not callable(resource_clock)
        or (terminal_transaction_effect is not None and not callable(terminal_transaction_effect))
        or (outcome in {"CANCELLED", "SUPERSEDED"} and findings)
        or (
            outcome in {"PASS", "FAIL", "INDETERMINATE"}
            and (outcome == "FAIL") is not any(item.blocking for item in findings)
        )
    ):
        raise WorkerQueueConflict()
    lease_arguments(
        tenant_id,
        session_id,
        worker_id,
        execution_identity_hash,
        expected_version,
    )
    cursor = connection.cursor()
    try:
        cursor.execute("BEGIN IMMEDIATE")
        resource_now_ms = resource_clock()
        if type(resource_now_ms) is not int:
            raise WorkerQueueConflict()
        row = _current(cursor, tenant_id, session_id)
        _require_finding_bindings(cursor, row, tenant_id, run_id, findings)
        if bool(row["terminal"]):
            _require_terminal_replay(
                cursor,
                row,
                tenant_id=tenant_id,
                run_id=run_id,
                worker_id=worker_id,
                identity_hash=execution_identity_hash,
                expected_version=expected_version,
                outcome=outcome,
                findings=findings,
            )
            settle_worker_resources(cursor, resource_settlement, now_ms=resource_now_ms)
            if terminal_transaction_effect is not None:
                terminal_transaction_effect(cursor)
            connection.commit()
            return _lease(row, lease_seconds)

        observed_at = utc(now())
        _require_current(
            row,
            worker_id=worker_id,
            identity_hash=execution_identity_hash,
            run_id=run_id,
            expected_version=expected_version,
            now=observed_at,
        )
        requested = command(row["state"])
        if requested == "CANCEL" and outcome != "CANCELLED":
            raise WorkerQueueConflict()
        if requested == "SUPERSEDE" and outcome != "SUPERSEDED":
            raise WorkerQueueConflict()
        if requested == "CONTINUE" and outcome in {"CANCELLED", "SUPERSEDED"}:
            raise WorkerQueueConflict()

        settle_worker_resources(cursor, resource_settlement, now_ms=resource_now_ms)
        _insert_findings(cursor, tenant_id, run_id, findings)
        next_version = expected_version + 1
        cursor.execute(
            """UPDATE worker_run_queue
               SET version=?, terminal=1, outcome=?, lease_expires_at=NULL
               WHERE tenant_id=? AND session_id=? AND version=? AND terminal=0""",
            (next_version, outcome, tenant_id, session_id, expected_version),
        )
        if cursor.rowcount != 1:
            raise WorkerQueueConflict()
        cursor.execute(
            """UPDATE audit_runs
               SET state=?, version=version+1, updated_at=?
               WHERE tenant_id=? AND run_id=?""",
            (
                OUTCOME_STATES[outcome],
                observed_at.isoformat(),
                tenant_id,
                run_id,
            ),
        )
        if cursor.rowcount != 1:
            raise WorkerQueueConflict()
        if terminal_transaction_effect is not None:
            terminal_transaction_effect(cursor)
        updated = _current(cursor, tenant_id, session_id)
        connection.commit()
        return _lease(updated, lease_seconds)
    except WorkerQueueConflict:
        connection.rollback()
        raise
    except sqlite3.IntegrityError:
        connection.rollback()
        raise WorkerQueueConflict() from None
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()


def _require_finding_bindings(
    cursor: sqlite3.Cursor,
    row: sqlite3.Row,
    tenant_id: str,
    run_id: str,
    findings: tuple[WorkerFindingRecord, ...],
) -> None:
    identity = identity_document(row["execution_identity_json"])
    revision = identity.repository_revision
    if (
        revision.tenant_id != tenant_id
        or row["run_id"] != run_id
        or revision.repository_id != row["current_repository_id"]
        or revision.head_sha != row["current_head_sha"]
        or identity.execution_identity_hash != row["execution_identity_hash"]
    ):
        raise WorkerQueueConflict()
    for finding in findings:
        reference = finding.evidence_graph_ref
        if finding.revision_sha != revision.head_sha or reference.tenant_id != tenant_id:
            raise WorkerQueueConflict()
        artifact = cursor.execute(
            """SELECT a.metadata_json, a.content_sha256,
                      z.content_id, z.size_bytes, z.data_class
               FROM run_artifacts AS a
               JOIN artifact_upload_authorizations AS z
                 ON z.tenant_id=a.tenant_id
                AND z.authorization_id=a.authorization_id
               WHERE a.tenant_id=? AND a.run_id=? AND a.content_sha256=?
                 AND a.purpose='evidence-graph'""",
            (tenant_id, run_id, reference.content_sha256),
        ).fetchone()
        if artifact is None or not _artifact_matches(artifact, reference):
            raise WorkerQueueConflict()


def _artifact_matches(row: sqlite3.Row, reference: ArtifactRef) -> bool:
    try:
        value = row["metadata_json"]
        if type(value) is not str:
            return False
        document = json.loads(value)
        return (
            isinstance(document, dict)
            and row["content_id"] == reference.content_id
            and row["content_sha256"] == reference.content_sha256
            and row["size_bytes"] == reference.size_bytes
            and row["data_class"] == reference.data_class.value
            and document.get("content_sha256") == reference.content_sha256
            and document.get("size_bytes") == reference.size_bytes
            and document.get("purpose") == "evidence-graph"
        )
    except (AttributeError, json.JSONDecodeError, TypeError, ValueError):
        return False


def _insert_findings(
    cursor: sqlite3.Cursor,
    tenant_id: str,
    run_id: str,
    findings: tuple[WorkerFindingRecord, ...],
) -> None:
    repository = cursor.execute(
        "SELECT repository_id FROM audit_runs WHERE tenant_id=? AND run_id=?",
        (tenant_id, run_id),
    ).fetchone()
    if repository is None:
        raise WorkerQueueConflict()
    for finding in findings:
        metadata = canonical(finding.metadata_document())
        canonical_row = cursor.execute(
            """SELECT f.metadata_json, r.repository_id
               FROM findings AS f
               JOIN audit_runs AS r
                 ON r.tenant_id=f.tenant_id AND r.run_id=f.run_id
               WHERE f.tenant_id=? AND f.finding_id=?""",
            (tenant_id, finding.finding_id),
        ).fetchone()
        if canonical_row is None:
            cursor.execute(
                """INSERT INTO findings
                   (tenant_id, finding_id, run_id, revision_sha, metadata_json)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    tenant_id,
                    finding.finding_id,
                    run_id,
                    finding.revision_sha,
                    metadata,
                ),
            )
        elif canonical_row["repository_id"] != repository[
            "repository_id"
        ] or not _same_finding_identity(canonical_row["metadata_json"], finding):
            raise WorkerQueueConflict()
        cursor.execute(
            """INSERT INTO finding_occurrences
               (tenant_id, finding_id, run_id, revision_sha, metadata_json)
               VALUES (?, ?, ?, ?, ?)""",
            (
                tenant_id,
                finding.finding_id,
                run_id,
                finding.revision_sha,
                metadata,
            ),
        )


def _same_finding_identity(value: object, finding: WorkerFindingRecord) -> bool:
    try:
        if type(value) is not str:
            return False
        document = json.loads(value)
        return (
            isinstance(document, dict)
            and document.get("cwe_id") == finding.cwe_id
            and document.get("root_cause_fingerprint") == finding.root_cause_fingerprint
        )
    except (json.JSONDecodeError, TypeError, ValueError):
        return False


def _require_terminal_replay(
    cursor: sqlite3.Cursor,
    row: sqlite3.Row,
    *,
    tenant_id: str,
    run_id: str,
    worker_id: str,
    identity_hash: str,
    expected_version: int,
    outcome: str,
    findings: tuple[WorkerFindingRecord, ...],
) -> None:
    if (
        row["outcome"] != outcome
        or row["lease_owner"] != worker_id
        or row["execution_identity_hash"] != identity_hash
        or row["run_id"] != run_id
        or row["version"] != expected_version + 1
    ):
        raise WorkerQueueConflict()
    stored = cursor.execute(
        """SELECT finding_id, revision_sha, metadata_json FROM finding_occurrences
           WHERE tenant_id=? AND run_id=? ORDER BY finding_id""",
        (tenant_id, run_id),
    ).fetchall()
    expected = tuple(
        (
            finding.finding_id,
            finding.revision_sha,
            canonical(finding.metadata_document()),
        )
        for finding in findings
    )
    actual = tuple(
        (item["finding_id"], item["revision_sha"], item["metadata_json"]) for item in stored
    )
    if actual != expected:
        raise WorkerQueueConflict()


def _current(cursor: sqlite3.Cursor, tenant_id: str, session_id: str) -> sqlite3.Row:
    row: sqlite3.Row | None = cursor.execute(
        """SELECT q.*, r.state, r.execution_identity_hash,
                  r.repository_id AS current_repository_id,
                  r.head_sha AS current_head_sha
           FROM worker_run_queue AS q
           JOIN audit_runs AS r
             ON r.tenant_id=q.tenant_id AND r.run_id=q.run_id
           WHERE q.tenant_id=? AND q.session_id=?""",
        (tenant_id, session_id),
    ).fetchone()
    if row is None:
        raise WorkerQueueConflict()
    return row


def _require_current(
    row: sqlite3.Row,
    *,
    worker_id: str,
    identity_hash: str,
    run_id: str,
    expected_version: int,
    now: datetime,
) -> None:
    if (
        bool(row["terminal"])
        or row["lease_owner"] != worker_id
        or row["execution_identity_hash"] != identity_hash
        or row["run_id"] != run_id
        or row["version"] != expected_version
        or timestamp(row["lease_expires_at"]) <= now
    ):
        raise WorkerQueueConflict()


def _lease(row: sqlite3.Row, lease_seconds: int) -> WorkerQueueLease:
    return WorkerQueueLease(
        tenant_id=row["tenant_id"],
        run_id=row["run_id"],
        worker_id=row["lease_owner"] or "released",
        session_id=row["session_id"],
        version=row["version"],
        lease_seconds=lease_seconds,
        lease_expires_at=(
            timestamp(row["lease_expires_at"])
            if row["lease_expires_at"] is not None
            else datetime.fromtimestamp(0, UTC)
        ),
        command=command(row["state"]),
        execution_identity=identity_document(row["execution_identity_json"]),
        terminal=bool(row["terminal"]),
        outcome=row["outcome"],
    )


def load_worker_findings_for_run(
    connection: sqlite3.Connection,
    *,
    tenant_id: str,
    run_id: str,
) -> tuple[WorkerFindingRecord, ...]:
    """Load durable finding metadata for a previously completed run."""

    if not isinstance(connection, sqlite3.Connection):
        raise WorkerQueueConflict()
    try:
        rows = connection.execute(
            """SELECT finding_id, revision_sha, metadata_json
               FROM finding_occurrences
               WHERE tenant_id=? AND run_id=?
               ORDER BY finding_id""",
            (tenant_id, run_id),
        ).fetchall()
        documents: list[dict[str, object]] = []
        for row in rows:
            metadata = json.loads(row["metadata_json"])
            if type(metadata) is not dict:
                raise ValueError
            documents.append(
                {
                    **metadata,
                    "finding_id": row["finding_id"],
                    "revision_sha": row["revision_sha"],
                }
            )
        return parse_worker_findings(documents, required=True, supplied=True)
    except (KeyError, sqlite3.Error, TypeError, ValueError):
        raise WorkerQueueConflict() from None


__all__ = ["complete_worker_run", "load_worker_findings_for_run"]
