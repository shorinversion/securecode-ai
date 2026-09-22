"""Durable, source-free baseline snapshots for SCM policy evaluation."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from securecode_ai.contracts import AuditRun, DiscoveryCandidate
from securecode_ai.core.baseline_fingerprints import (
    BASELINE_FINGERPRINT_SCHEMA_VERSION,
    BaselineFingerprintComparison,
    BaselineFingerprintSnapshot,
    compare_baseline_fingerprints,
)


class BaselineStoreError(RuntimeError):
    """The requested immutable baseline is missing or does not validate."""


_SCHEMA = """CREATE TABLE IF NOT EXISTS scm_baseline_snapshots (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    revision_sha TEXT NOT NULL,
    candidates_json TEXT NOT NULL,
    PRIMARY KEY (tenant_id, repository_id, revision_sha)
)"""


@dataclass(frozen=True, slots=True)
class DurableBaselineStore:
    """Persist only normalized candidate metadata needed for baseline comparison."""

    connection: sqlite3.Connection

    def __post_init__(self) -> None:
        if not isinstance(self.connection, sqlite3.Connection):
            raise TypeError("baseline store requires a SQLite connection")
        self.connection.execute(_SCHEMA)
        self.connection.commit()

    def record(self, audit_run: AuditRun) -> BaselineFingerprintSnapshot:
        if type(audit_run) is not AuditRun:
            raise BaselineStoreError("baseline audit run is invalid")
        revision = audit_run.execution_identity.repository_revision
        snapshot = BaselineFingerprintSnapshot(
            schema_version=BASELINE_FINGERPRINT_SCHEMA_VERSION,
            tenant_id=revision.tenant_id,
            revision_sha=revision.head_sha,
            findings=audit_run.coverage_manifest.discovery_candidates,
        )
        document = json.dumps(
            [item.model_dump(mode="json") for item in snapshot.findings],
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        with self.connection:
            existing = self.connection.execute(
                """SELECT candidates_json FROM scm_baseline_snapshots
                   WHERE tenant_id=? AND repository_id=? AND revision_sha=?""",
                (revision.tenant_id, revision.repository_id, revision.head_sha),
            ).fetchone()
            if existing is not None:
                if existing[0] != document:
                    raise BaselineStoreError("baseline revision conflicts")
                return snapshot
            self.connection.execute(
                """INSERT INTO scm_baseline_snapshots
                   (tenant_id, repository_id, revision_sha, candidates_json)
                   VALUES (?, ?, ?, ?)""",
                (revision.tenant_id, revision.repository_id, revision.head_sha, document),
            )
        return snapshot

    def load(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        revision_sha: str,
    ) -> BaselineFingerprintSnapshot:
        row = self.connection.execute(
            """SELECT candidates_json FROM scm_baseline_snapshots
               WHERE tenant_id=? AND repository_id=? AND revision_sha=?""",
            (tenant_id, repository_id, revision_sha),
        ).fetchone()
        if row is None:
            raise BaselineStoreError("baseline revision is unavailable")
        try:
            document = json.loads(row[0])
            if not isinstance(document, list):
                raise ValueError
            findings = tuple(DiscoveryCandidate.model_validate(item) for item in document)
            return BaselineFingerprintSnapshot(
                schema_version=BASELINE_FINGERPRINT_SCHEMA_VERSION,
                tenant_id=tenant_id,
                revision_sha=revision_sha,
                findings=findings,
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            raise BaselineStoreError("stored baseline is invalid") from None

    def compare_for_audit(
        self,
        audit_run: AuditRun,
        *,
        commit_lineage: tuple[str, ...],
    ) -> BaselineFingerprintComparison:
        """Compare one verified head run with its exact persisted base revision."""

        if type(audit_run) is not AuditRun:
            raise BaselineStoreError("baseline audit run is invalid")
        revision = audit_run.execution_identity.repository_revision
        if revision.base_sha is None:
            raise BaselineStoreError("baseline revision is unavailable")
        baseline = self.load(
            tenant_id=revision.tenant_id,
            repository_id=revision.repository_id,
            revision_sha=revision.base_sha,
        )
        head = BaselineFingerprintSnapshot(
            schema_version=BASELINE_FINGERPRINT_SCHEMA_VERSION,
            tenant_id=revision.tenant_id,
            revision_sha=revision.head_sha,
            findings=audit_run.coverage_manifest.discovery_candidates,
        )
        return compare_baseline_fingerprints(
            baseline=baseline,
            head=head,
            current_head_sha=audit_run.current_head_sha,
            commit_lineage=commit_lineage,
        )
