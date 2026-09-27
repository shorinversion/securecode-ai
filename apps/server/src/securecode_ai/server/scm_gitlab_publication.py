"""Project GitLab terminal notes and exact changed-line discussions."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from securecode_ai.adapters.gitlab_api import GitlabRestAPI
from securecode_ai.adapters.gitlab_discussions import (
    GitlabChangedLine,
    GitlabDiscussionCandidate,
    GitlabDiscussionPublisher,
    GitlabDiscussionRequest,
)
from securecode_ai.adapters.gitlab_summary import (
    GitlabSummaryAuthorizer,
    GitlabSummaryPublisher,
    GitlabSummaryRequest,
)
from securecode_ai.contracts import AuditRun, AuditRunOutcome, FindingCase
from securecode_ai.core.baseline_fingerprints import BaselineChangedScope
from securecode_ai.core.scm_run_state import SCMRunPublicationReceipt

from .artifact_read import LocalCommittedArtifactReader
from .baseline_store import DurableBaselineStore
from .scm_completion_models import GitlabTerminalPublication
from .scm_publication_store import SCMPublicationTarget
from .scm_runtime import SCMRunCommitLineageResolver
from .worker_completion_evidence import load_verified_terminal_audit_run
from .worker_findings import WorkerFindingRecord
from .worker_findings_store import load_worker_findings_for_run


class GitlabTerminalPublicationResolver:
    """Build exact-run summary and verified changed-line discussion projections."""

    __slots__ = (
        "_api",
        "_artifact_root",
        "_artifact_reader",
        "_baseline",
        "_connection",
        "_lineage",
        "_summary",
        "_discussions",
    )

    def __init__(
        self,
        *,
        connection: sqlite3.Connection,
        artifact_root: Path,
        baseline_store: DurableBaselineStore,
        lineage_resolver: SCMRunCommitLineageResolver,
        api: GitlabRestAPI,
        authorizer: GitlabSummaryAuthorizer,
        artifact_reader: LocalCommittedArtifactReader | None = None,
    ) -> None:
        if (
            not isinstance(connection, sqlite3.Connection)
            or not isinstance(artifact_root, Path)
            or not isinstance(baseline_store, DurableBaselineStore)
            or not callable(lineage_resolver)
            or type(api) is not GitlabRestAPI
            or not callable(getattr(authorizer, "authorize_publication", None))
            or (
                artifact_reader is not None
                and type(artifact_reader) is not LocalCommittedArtifactReader
            )
        ):
            raise TypeError("GitLab terminal publication dependencies are incomplete")
        self._connection = connection
        self._artifact_root = artifact_root
        self._artifact_reader = artifact_reader or LocalCommittedArtifactReader(
            connection,
            artifact_root,
        )
        self._baseline = baseline_store
        self._lineage = lineage_resolver
        self._api = api
        self._summary = GitlabSummaryPublisher(authorizer)
        self._discussions = GitlabDiscussionPublisher(authorizer)

    def __call__(
        self,
        target: SCMPublicationTarget,
        outcome: AuditRunOutcome,
        publication: SCMRunPublicationReceipt,
        *,
        publication_outcome: AuditRunOutcome,
    ) -> GitlabTerminalPublication | None:
        if (
            type(target) is not SCMPublicationTarget
            or target.provider != "gitlab"
            or type(outcome) is not AuditRunOutcome
            or type(publication_outcome) is not AuditRunOutcome
            or type(publication) is not SCMRunPublicationReceipt
            or publication.disposition.value not in {"COMPLETED", "DUPLICATE"}
            or publication.run_id != target.run_id
            or publication.execution_identity_hash != target.execution_identity_hash
            or publication.head_sha != target.head_sha
            or publication.current_head_sha != target.head_sha
            or publication.outcome not in {outcome, publication_outcome}
        ):
            raise ValueError
        findings = load_worker_findings_for_run(
            self._connection,
            tenant_id=target.tenant_id,
            run_id=target.run_id,
        )
        self._verify_committed_projection_artifacts(target)
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
        if verified is None:
            return None
        if type(verified) is not tuple or len(verified) != 3:
            raise ValueError
        audit_run, _, report_findings = verified
        if type(audit_run) is not AuditRun or type(report_findings) is not tuple:
            raise ValueError
        identity = audit_run.execution_identity
        revision = identity.repository_revision
        if (
            audit_run.run_id != target.run_id
            or audit_run.audit_outcome is not outcome
            or identity.execution_identity_hash != target.execution_identity_hash
            or revision.tenant_id != target.tenant_id
            or revision.scm_provider != "gitlab"
            or revision.repository_id != target.repository_id
            or revision.head_sha != target.head_sha
            or revision.base_sha is None
        ):
            raise ValueError

        summary = self._summary.project(
            GitlabSummaryRequest(target.run_id, audit_run),
            publication_receipt=publication,
            publication_outcome=publication_outcome,
        )
        if summary.projection is None:
            raise ValueError
        candidates: list[GitlabDiscussionCandidate] = []
        changed_lines: tuple[GitlabChangedLine, ...] = ()
        if outcome in {AuditRunOutcome.PASS, AuditRunOutcome.FAIL}:
            candidates, changed_lines = self._discussion_inputs(
                target=target,
                audit_run=audit_run,
                report_findings=report_findings,
                findings=findings,
            )
        discussion = self._discussions.project(
            GitlabDiscussionRequest(
                scm_run_id=target.run_id,
                execution_identity=identity,
                candidates=tuple(candidates),
                changed_lines=changed_lines,
            ),
            publication_receipt=publication,
        )
        return GitlabTerminalPublication(
            summary=summary.projection,
            discussions=discussion.discussions,
            authorized_run_id=publication.run_id,
            authorized_identity_hash=publication.execution_identity_hash,
            authorized_head_sha=publication.head_sha,
        )

    def _verify_committed_projection_artifacts(self, target: SCMPublicationTarget) -> None:
        """Apply lifecycle and source-free checks before provider projection."""

        try:
            rows = self._connection.execute(
                """SELECT a.content_sha256, a.purpose
                   FROM run_artifacts AS a
                   JOIN artifact_upload_authorizations AS z
                     ON z.tenant_id=a.tenant_id
                    AND z.authorization_id=a.authorization_id
                    AND z.run_id=a.run_id
                    AND z.content_sha256=a.content_sha256
                    AND z.purpose=a.purpose
                   WHERE a.tenant_id=? AND a.run_id=?
                     AND a.purpose IN ('audit-report', 'audit-run', 'evidence-graph')
                     AND a.rowid=(
                         SELECT latest.rowid FROM run_artifacts AS latest
                         WHERE latest.tenant_id=a.tenant_id
                           AND latest.run_id=a.run_id
                           AND latest.purpose=a.purpose
                         ORDER BY latest.rowid DESC LIMIT 1
                     )""",
                (target.tenant_id, target.run_id),
            ).fetchall()
        except sqlite3.Error:
            raise ValueError from None
        for row in rows:
            digest = row["content_sha256"]
            purpose = row["purpose"]
            if type(digest) is not str or type(purpose) is not str:
                raise ValueError
            content = self._artifact_reader.read_binary(
                tenant_id=target.tenant_id,
                run_id=target.run_id,
                content_sha256=digest,
            )
            if content.purpose != purpose:
                raise ValueError

    def _discussion_inputs(
        self,
        *,
        target: SCMPublicationTarget,
        audit_run: AuditRun,
        report_findings: tuple[FindingCase, ...],
        findings: tuple[WorkerFindingRecord, ...],
    ) -> tuple[list[GitlabDiscussionCandidate], tuple[GitlabChangedLine, ...]]:
        revision = audit_run.execution_identity.repository_revision
        base_sha = revision.base_sha
        if base_sha is None:
            raise ValueError
        live_base, start_sha, live_head = self._api.merge_request_diff_refs(
            project_id=target.repository_id,
            merge_request_iid=target.change_id,
        )
        if live_base != base_sha or live_head != target.head_sha:
            raise ValueError
        lineage = self._lineage(
            run_id=target.run_id,
            execution_identity_hash=target.execution_identity_hash,
            base_sha=base_sha,
            head_sha=target.head_sha,
        )
        changed = self._api.compare_commit_changed_line_paths(
            project_id=target.repository_id,
            base_sha=base_sha,
            head_sha=target.head_sha,
        )
        record_by_id = {item.finding_id: item for item in findings}
        locations_by_fingerprint: dict[str, set[tuple[str, int, int]]] = {}
        for finding in report_findings:
            if type(finding) is not FindingCase:
                raise ValueError
            finding_revision = finding.repository_revision
            if (
                finding_revision.tenant_id != target.tenant_id
                or finding_revision.scm_provider != "gitlab"
                or finding_revision.repository_id != target.repository_id
                or finding_revision.head_sha != target.head_sha
                or finding_revision.base_sha != base_sha
            ):
                # A finding with the same head but a different base belongs to
                # another diff topology.  Treat it as an invalid terminal
                # projection instead of allowing the discussion publisher to
                # classify it as new code for this merge request.
                raise ValueError
            record = record_by_id.get(finding.finding_id)
            if record is None or record.root_cause_fingerprint != finding.root_cause_fingerprint:
                raise ValueError
            if record.verdict == "CONFIRMED":
                spans = locations_by_fingerprint.setdefault(
                    finding.root_cause_fingerprint, set()
                )
                spans.update(
                    (location.path, location.start.line, location.end.line)
                    for location in finding.locations
                )
        changed_scope = BaselineChangedScope(
            tenant_id=revision.tenant_id,
            base_sha=base_sha,
            head_sha=target.head_sha,
            changed_lines=tuple(
                sorted({(path, line) for path, line, _old_path, _deleted in changed})
            ),
            finding_locations=tuple(
                (fingerprint, tuple(sorted(spans)))
                for fingerprint, spans in sorted(locations_by_fingerprint.items())
                if spans
            ),
        )
        comparison = self._baseline.compare_for_new_code_audit(
            audit_run,
            commit_lineage=lineage,
            verified_finding_fingerprints=tuple(
                sorted(
                    {
                        item.root_cause_fingerprint
                        for item in findings
                        if item.verdict == "CONFIRMED"
                    }
                )
            ),
            changed_scope=changed_scope,
        )
        new_fingerprints = set(comparison.new_code_fingerprints(changed_scope=changed_scope))
        candidates = [
            GitlabDiscussionCandidate(
                finding=item,
                is_new_code=item.root_cause_fingerprint in new_fingerprints,
            )
            for item in report_findings
        ]
        changed_map = {
            (path, line): (old_path if old_path != "/dev/null" else path)
            for path, line, old_path, deleted in changed
            if not deleted
        }
        projections: dict[tuple[str, int], GitlabChangedLine] = {}
        for finding in report_findings:
            for location in finding.locations:
                key = (location.path, location.start.line)
                old_path = changed_map.get(key)
                if old_path is None or location.start.line != location.end.line:
                    continue
                line = GitlabChangedLine(
                    path=location.path,
                    line=location.start.line,
                    content_sha256=location.content_sha256,
                    base_sha=base_sha,
                    start_sha=start_sha,
                    head_sha=target.head_sha,
                    old_path=old_path,
                )
                prior = projections.get(key)
                if prior is not None and prior != line:
                    raise ValueError
                projections[key] = line
        return candidates, tuple(projections[key] for key in sorted(projections))


__all__ = ["GitlabTerminalPublicationResolver"]
