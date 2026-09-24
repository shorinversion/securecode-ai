"""Durable, source-free baseline snapshots for SCM policy evaluation."""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass

from securecode_ai.contracts import AnalysisHealth, AuditRun, AuditRunOutcome, DiscoveryCandidate
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
    verification_version INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, repository_id, revision_sha)
)"""
_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")
_VERIFICATION_VERSION = 1


@dataclass(frozen=True, slots=True)
class DurableBaselineStore:
    """Persist only normalized candidate metadata needed for baseline comparison."""

    connection: sqlite3.Connection

    def __post_init__(self) -> None:
        if not isinstance(self.connection, sqlite3.Connection):
            raise TypeError("baseline store requires a SQLite connection")
        self.connection.execute(_SCHEMA)
        columns = {
            row[1]
            for row in self.connection.execute("PRAGMA table_info(scm_baseline_snapshots)")
        }
        if "verification_version" not in columns:
            self.connection.execute(
                "ALTER TABLE scm_baseline_snapshots "
                "ADD COLUMN verification_version INTEGER NOT NULL DEFAULT 0"
            )
        self.connection.commit()

    def record(
        self,
        audit_run: AuditRun,
        *,
        verified_finding_fingerprints: tuple[str, ...],
    ) -> BaselineFingerprintSnapshot:
        cursor = self.connection.cursor()
        try:
            with self.connection:
                return self.record_in_transaction(
                    cursor,
                    audit_run,
                    verified_finding_fingerprints=verified_finding_fingerprints,
                )
        finally:
            cursor.close()

    def record_in_transaction(
        self,
        cursor: sqlite3.Cursor,
        audit_run: AuditRun,
        *,
        verified_finding_fingerprints: tuple[str, ...],
    ) -> BaselineFingerprintSnapshot:
        """Persist a snapshot inside the caller's terminal-run transaction."""

        if not isinstance(cursor, sqlite3.Cursor):
            raise BaselineStoreError("baseline transaction cursor is invalid")
        if type(audit_run) is not AuditRun:
            raise BaselineStoreError("baseline audit run is invalid")
        revision = audit_run.execution_identity.repository_revision
        if (
            audit_run.current_head_sha != revision.head_sha
            or audit_run.audit_outcome not in {AuditRunOutcome.PASS, AuditRunOutcome.FAIL}
            or audit_run.analysis_health is not AnalysisHealth.HEALTHY
            or not audit_run.coverage_manifest.coverage_complete
        ):
            raise BaselineStoreError("baseline audit run is incomplete")
        candidates = _verified_finding_candidates(
            audit_run,
            verified_finding_fingerprints,
        )
        snapshot = BaselineFingerprintSnapshot(
            schema_version=BASELINE_FINGERPRINT_SCHEMA_VERSION,
            tenant_id=revision.tenant_id,
            revision_sha=revision.head_sha,
            findings=candidates,
        )
        document = json.dumps(
            [item.model_dump(mode="json") for item in snapshot.findings],
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        existing = cursor.execute(
            """SELECT candidates_json, verification_version FROM scm_baseline_snapshots
               WHERE tenant_id=? AND repository_id=? AND revision_sha=?""",
            (revision.tenant_id, revision.repository_id, revision.head_sha),
        ).fetchone()
        if existing is not None:
            if existing[1] != _VERIFICATION_VERSION or existing[0] != document:
                raise BaselineStoreError("baseline revision conflicts")
            return snapshot
        cursor.execute(
            """INSERT INTO scm_baseline_snapshots
               (tenant_id, repository_id, revision_sha, candidates_json, verification_version)
               VALUES (?, ?, ?, ?, ?)""",
            (
                revision.tenant_id,
                revision.repository_id,
                revision.head_sha,
                document,
                _VERIFICATION_VERSION,
            ),
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
            """SELECT candidates_json, verification_version FROM scm_baseline_snapshots
               WHERE tenant_id=? AND repository_id=? AND revision_sha=?""",
            (tenant_id, repository_id, revision_sha),
        ).fetchone()
        if row is None:
            raise BaselineStoreError("baseline revision is unavailable")
        if row[1] != _VERIFICATION_VERSION:
            raise BaselineStoreError("baseline revision requires a verified rebuild")
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
        verified_finding_fingerprints: tuple[str, ...],
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
            findings=_verified_finding_candidates(
                audit_run,
                verified_finding_fingerprints,
            ),
        )
        return compare_baseline_fingerprints(
            baseline=baseline,
            head=head,
            current_head_sha=audit_run.current_head_sha,
            commit_lineage=commit_lineage,
        )


def _verified_finding_candidates(
    audit_run: AuditRun,
    fingerprints: tuple[str, ...],
) -> tuple[DiscoveryCandidate, ...]:
    """Keep only candidates bound to independently verified findings."""

    if type(fingerprints) is not tuple or len(fingerprints) > 100_000:
        raise BaselineStoreError("verified baseline findings are invalid")
    if any(
        type(item) is not str or _FINGERPRINT.fullmatch(item) is None
        for item in fingerprints
    ):
        raise BaselineStoreError("verified baseline findings are invalid")
    if fingerprints != tuple(sorted(set(fingerprints))):
        raise BaselineStoreError("verified baseline findings are invalid")
    candidates = audit_run.coverage_manifest.discovery_candidates
    available = {item.root_cause_fingerprint for item in candidates}
    if not set(fingerprints).issubset(available):
        raise BaselineStoreError("verified baseline findings do not match the audit run")
    selected = set(fingerprints)
    result = tuple(item for item in candidates if item.root_cause_fingerprint in selected)
    if len(result) != len(selected):
        raise BaselineStoreError("verified baseline findings are ambiguous")
    return result
