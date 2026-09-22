"""Verified loading of durable terminal AuditRun artifacts."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pytest
from securecode_ai.contracts import AuditRun
from securecode_ai.core.evidence_graph import EvidenceGraph
from securecode_ai.core.reports import ReportFormat, build_deterministic_report, render_report
from securecode_ai.server.worker_completion_evidence import (
    load_verified_terminal_audit_run,
    verify_terminal_evidence,
)
from securecode_ai.server.worker_queue_models import WorkerQueueConflict

from tests.unit.test_reports import _run


@dataclass(frozen=True, slots=True)
class _TerminalArtifacts:
    connection: sqlite3.Connection
    artifact_root: Path
    audit_run: AuditRun


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _terminal_artifacts(tmp_path: Path) -> _TerminalArtifacts:
    audit_run = _run(complete=True, with_candidate=False)
    report = render_report(
        build_deterministic_report(audit_run, (), ()),
        ReportFormat.JSON,
    )
    graph = EvidenceGraph(
        graph_id="completion-fixture",
        tenant_id=audit_run.execution_identity.repository_revision.tenant_id,
        head_sha=audit_run.current_head_sha,
        candidates=(),
        evidence=(),
        edges=(),
    )
    graph_bytes = _canonical(graph.canonical_payload)
    run_bytes = _canonical(audit_run.model_dump(mode="json"))
    contents = {
        "audit-report": report,
        "audit-run": run_bytes,
        "evidence-graph": graph_bytes,
    }

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE worker_run_queue (
            tenant_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            execution_identity_json TEXT NOT NULL
        );
        CREATE TABLE run_artifacts (
            tenant_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            purpose TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            metadata_json TEXT NOT NULL
        );
        """
    )
    tenant_id = audit_run.execution_identity.repository_revision.tenant_id
    connection.execute(
        "INSERT INTO worker_run_queue VALUES (?, ?, ?)",
        (
            tenant_id,
            audit_run.run_id,
            _canonical(audit_run.execution_identity.model_dump(mode="json")).decode("utf-8"),
        ),
    )
    root = tmp_path / "artifacts"
    for purpose, content in contents.items():
        digest = hashlib.sha256(content).hexdigest()
        payload = root / tenant_id / digest[:2] / digest / "payload"
        payload.parent.mkdir(parents=True, exist_ok=True)
        payload.write_bytes(content)
        metadata = _canonical(
            {"content_sha256": digest, "purpose": purpose, "size_bytes": len(content)}
        ).decode("utf-8")
        connection.execute(
            "INSERT INTO run_artifacts VALUES (?, ?, ?, ?, ?)",
            (tenant_id, audit_run.run_id, purpose, digest, metadata),
        )
    connection.commit()
    return _TerminalArtifacts(connection, root, audit_run)


def _load(artifacts: _TerminalArtifacts) -> AuditRun | None:
    run = artifacts.audit_run
    return load_verified_terminal_audit_run(
        connection=artifacts.connection,
        artifact_root=artifacts.artifact_root,
        tenant_id=run.execution_identity.repository_revision.tenant_id,
        run_id=run.run_id,
        execution_identity_hash=run.execution_identity.execution_identity_hash,
        outcome=run.audit_outcome.value,
        findings=(),
    )


def test_loader_returns_only_the_verified_audit_run(tmp_path: Path) -> None:
    artifacts = _terminal_artifacts(tmp_path)

    assert _load(artifacts) == artifacts.audit_run


def test_compatibility_verifier_keeps_none_return_after_same_validation(
    tmp_path: Path,
) -> None:
    artifacts = _terminal_artifacts(tmp_path)
    run = artifacts.audit_run

    verify_terminal_evidence(
        connection=artifacts.connection,
        artifact_root=artifacts.artifact_root,
        tenant_id=run.execution_identity.repository_revision.tenant_id,
        run_id=run.run_id,
        execution_identity_hash=run.execution_identity.execution_identity_hash,
        outcome=run.audit_outcome.value,
        findings=(),
    )


def test_loader_rejects_payload_modified_after_metadata_was_written(tmp_path: Path) -> None:
    artifacts = _terminal_artifacts(tmp_path)
    run_bytes = _canonical(artifacts.audit_run.model_dump(mode="json"))
    digest = hashlib.sha256(run_bytes).hexdigest()
    payload = artifacts.artifact_root / "tenant-1" / digest[:2] / digest / "payload"
    payload.write_bytes(run_bytes + b" ")

    with pytest.raises(WorkerQueueConflict):
        _load(artifacts)


def test_loader_rejects_noncanonical_audit_run_even_with_matching_hash(tmp_path: Path) -> None:
    artifacts = _terminal_artifacts(tmp_path)
    run = artifacts.audit_run
    raw = _canonical(run.model_dump(mode="json")) + b"\n"
    digest = hashlib.sha256(raw).hexdigest()
    payload = artifacts.artifact_root / "tenant-1" / digest[:2] / digest / "payload"
    payload.parent.mkdir(parents=True, exist_ok=True)
    payload.write_bytes(raw)
    artifacts.connection.execute(
        "UPDATE run_artifacts SET metadata_json=? WHERE tenant_id=? AND run_id=? AND purpose=?",
        (
            _canonical(
                {
                    "content_sha256": digest,
                    "purpose": "audit-run",
                    "size_bytes": len(raw),
                }
            ).decode("utf-8"),
            "tenant-1",
            run.run_id,
            "audit-run",
        ),
    )
    artifacts.connection.commit()

    with pytest.raises(WorkerQueueConflict):
        _load(artifacts)
