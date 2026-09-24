"""Build fail-closed GitHub inline comments from verified durable findings."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Protocol

from securecode_ai.adapters.github_annotations import (
    GithubAnnotationCandidate,
    GithubAnnotationPublisher,
    GithubAnnotationReceipt,
    GithubAnnotationRequest,
    GithubChangedLine,
)
from securecode_ai.contracts import AuditRun, AuditRunOutcome, FindingCase
from securecode_ai.core.baseline_fingerprints import BaselineFingerprintComparison
from securecode_ai.core.scm_run_state import SCMRunPublicationReceipt

from .baseline_store import DurableBaselineStore
from .scm_publication_store import SCMPublicationTarget
from .worker_completion_evidence import load_verified_terminal_audit_run
from .worker_findings import WorkerFindingRecord
from .worker_findings_store import load_worker_findings_for_run


class CommitLineageResolver(Protocol):
    def __call__(
        self,
        *,
        run_id: str,
        execution_identity_hash: str,
        base_sha: str,
        head_sha: str,
    ) -> tuple[str, ...]: ...


class ChangedLinesResolver(Protocol):
    def __call__(
        self,
        *,
        run_id: str,
        execution_identity_hash: str,
        base_sha: str,
        head_sha: str,
    ) -> tuple[tuple[str, int], ...]: ...


class GithubAnnotationAuthorizer(Protocol):
    def authorize_publication(self, run_id: str) -> SCMRunPublicationReceipt: ...


class GithubAnnotationReceiptResolver:
    """Project inline comments only from exact, verified, new-code findings."""

    __slots__ = (
        "_artifact_root",
        "_authorizer",
        "_baseline_store",
        "_changed_lines",
        "_connection",
        "_lineage",
    )

    def __init__(
        self,
        *,
        connection: sqlite3.Connection,
        artifact_root: Path,
        baseline_store: DurableBaselineStore,
        lineage_resolver: CommitLineageResolver,
        changed_lines_resolver: ChangedLinesResolver,
        authorizer: GithubAnnotationAuthorizer,
    ) -> None:
        if (
            not isinstance(connection, sqlite3.Connection)
            or not isinstance(artifact_root, Path)
            or baseline_store is None
            or not callable(lineage_resolver)
            or not callable(changed_lines_resolver)
            or not callable(getattr(authorizer, "authorize_publication", None))
        ):
            raise TypeError("GitHub annotation dependencies are incomplete")
        self._connection = connection
        self._artifact_root = artifact_root
        self._baseline_store = baseline_store
        self._lineage = lineage_resolver
        self._changed_lines = changed_lines_resolver
        self._authorizer = authorizer

    def __call__(
        self,
        target: SCMPublicationTarget,
        outcome: AuditRunOutcome,
    ) -> GithubAnnotationReceipt | None:
        if (
            type(target) is not SCMPublicationTarget
            or target.provider != "github"
            or outcome not in {AuditRunOutcome.PASS, AuditRunOutcome.FAIL}
        ):
            return None
        try:
            return self._project(target, outcome)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            return None

    def _project(
        self,
        target: SCMPublicationTarget,
        outcome: AuditRunOutcome,
    ) -> GithubAnnotationReceipt:
        findings = load_worker_findings_for_run(
            self._connection,
            tenant_id=target.tenant_id,
            run_id=target.run_id,
        )
        verified = load_verified_terminal_audit_run(
            connection=self._connection,
            artifact_root=self._artifact_root,
            tenant_id=target.tenant_id,
            run_id=target.run_id,
            execution_identity_hash=target.execution_identity_hash,
            outcome=outcome.value,
            findings=findings,
            include_graph=True,
            include_findings=True,
        )
        if type(verified) is not tuple or len(verified) != 3:
            raise ValueError
        audit_run, _, report_findings = verified
        if type(audit_run) is not AuditRun or type(report_findings) is not tuple:
            raise ValueError
        identity = audit_run.execution_identity
        revision = identity.repository_revision
        if (
            audit_run.run_id != target.run_id
            or identity.execution_identity_hash != target.execution_identity_hash
            or revision.tenant_id != target.tenant_id
            or revision.repository_id != target.repository_id
            or revision.head_sha != target.head_sha
            or revision.base_sha is None
        ):
            raise ValueError

        confirmed_fingerprints = tuple(
            sorted(
                {
                    finding.root_cause_fingerprint
                    for finding in findings
                    if finding.verdict == "CONFIRMED"
                }
            )
        )
        lineage = self._lineage(
            run_id=target.run_id,
            execution_identity_hash=target.execution_identity_hash,
            base_sha=revision.base_sha,
            head_sha=revision.head_sha,
        )
        comparison: BaselineFingerprintComparison = self._baseline_store.compare_for_audit(
            audit_run,
            commit_lineage=lineage,
            verified_finding_fingerprints=confirmed_fingerprints,
        )
        changed_pathlines = self._changed_lines(
            run_id=target.run_id,
            execution_identity_hash=target.execution_identity_hash,
            base_sha=revision.base_sha,
            head_sha=revision.head_sha,
        )
        changed_set = set(changed_pathlines)
        changed_by_pathline: dict[tuple[str, int], GithubChangedLine] = {}
        record_by_id = {item.finding_id: item for item in findings}
        candidates: list[GithubAnnotationCandidate] = []
        new_fingerprints = set(comparison.new_fingerprints)
        for finding in report_findings:
            if type(finding) is not FindingCase:
                raise ValueError
            record = record_by_id.get(finding.finding_id)
            if record is None or record.root_cause_fingerprint != finding.root_cause_fingerprint:
                raise ValueError
            candidates.append(
                GithubAnnotationCandidate(
                    finding=finding,
                    is_new_code=finding.root_cause_fingerprint in new_fingerprints,
                )
            )
            for location in finding.locations:
                key = (location.path, location.start.line)
                if key not in changed_set:
                    continue
                if location.start.line != location.end.line:
                    continue
                changed_line = GithubChangedLine(
                    path=location.path,
                    line=location.start.line,
                    content_sha256=location.content_sha256,
                )
                previous = changed_by_pathline.get(key)
                if previous is not None and previous != changed_line:
                    raise ValueError
                changed_by_pathline[key] = changed_line
        publisher = GithubAnnotationPublisher(self._authorizer)
        return publisher.project(
            GithubAnnotationRequest(
                scm_run_id=target.run_id,
                execution_identity=identity,
                candidates=tuple(candidates),
                changed_lines=tuple(
                    changed_by_pathline[key] for key in sorted(changed_by_pathline)
                ),
            )
        )


__all__ = ["GithubAnnotationReceiptResolver"]
