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
from securecode_ai.core.baseline_fingerprints import (
    BaselineChangedScope,
    BaselineFingerprintComparison,
)
from securecode_ai.core.scm_run_state import (
    PublicationDisposition,
    SCMRunPublicationReceipt,
)

from .artifact_read import LocalCommittedArtifactReader
from .baseline_store import DurableBaselineStore
from .scm_publication_store import SCMPublicationTarget
from .worker_completion_evidence import load_verified_terminal_audit_run
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
        "_artifact_reader",
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
        artifact_reader: LocalCommittedArtifactReader | None = None,
    ) -> None:
        if (
            not isinstance(connection, sqlite3.Connection)
            or not isinstance(artifact_root, Path)
            or baseline_store is None
            or not callable(lineage_resolver)
            or not callable(changed_lines_resolver)
            or not callable(getattr(authorizer, "authorize_publication", None))
            or (
                artifact_reader is not None
                and type(artifact_reader) is not LocalCommittedArtifactReader
            )
        ):
            raise TypeError("GitHub annotation dependencies are incomplete")
        self._connection = connection
        self._artifact_root = artifact_root
        self._artifact_reader = artifact_reader or LocalCommittedArtifactReader(
            connection,
            artifact_root,
        )
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
        return self._project(target, outcome)

    def for_completed(
        self,
        target: SCMPublicationTarget,
        outcome: AuditRunOutcome,
        publication: SCMRunPublicationReceipt,
    ) -> GithubAnnotationReceipt | None:
        """Project verified findings from the receipt just persisted by completion."""

        if type(publication) is not SCMRunPublicationReceipt:
            raise ValueError
        if (
            publication.run_id != target.run_id
            or publication.execution_identity_hash != target.execution_identity_hash
            or publication.head_sha != target.head_sha
            or publication.current_head_sha != target.head_sha
            or publication.disposition
            not in {
                PublicationDisposition.COMPLETED,
                PublicationDisposition.DUPLICATE,
            }
        ):
            raise ValueError
        if target.provider != "github" or outcome not in {
            AuditRunOutcome.PASS,
            AuditRunOutcome.FAIL,
        }:
            return None
        return self._project(target, outcome, publication=publication)

    def _project(
        self,
        target: SCMPublicationTarget,
        outcome: AuditRunOutcome,
        *,
        publication: SCMRunPublicationReceipt | None = None,
    ) -> GithubAnnotationReceipt:
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
            or revision.scm_provider != "github"
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
        changed_pathlines = self._changed_lines(
            run_id=target.run_id,
            execution_identity_hash=target.execution_identity_hash,
            base_sha=revision.base_sha,
            head_sha=revision.head_sha,
        )
        record_by_id = {item.finding_id: item for item in findings}
        locations_by_fingerprint: dict[str, set[tuple[str, int, int]]] = {}
        for finding in report_findings:
            if type(finding) is not FindingCase:
                raise ValueError
            record = record_by_id.get(finding.finding_id)
            if record is None or record.root_cause_fingerprint != finding.root_cause_fingerprint:
                raise ValueError
            if record.verdict == "CONFIRMED":
                spans = locations_by_fingerprint.setdefault(
                    finding.root_cause_fingerprint,
                    set(),
                )
                spans.update(
                    (location.path, location.start.line, location.end.line)
                    for location in finding.locations
                )
        changed_scope = BaselineChangedScope(
            tenant_id=revision.tenant_id,
            base_sha=revision.base_sha,
            head_sha=revision.head_sha,
            changed_lines=changed_pathlines,
            finding_locations=tuple(
                (fingerprint, tuple(sorted(spans)))
                for fingerprint, spans in sorted(locations_by_fingerprint.items())
                if spans
            ),
        )
        comparison: BaselineFingerprintComparison = self._baseline_store.compare_for_new_code_audit(
            audit_run,
            commit_lineage=lineage,
            verified_finding_fingerprints=confirmed_fingerprints,
            changed_scope=changed_scope,
        )
        changed_set = set(changed_pathlines)
        changed_by_pathline: dict[tuple[str, int], GithubChangedLine] = {}
        candidates: list[GithubAnnotationCandidate] = []
        new_fingerprints = set(comparison.new_code_fingerprints(changed_scope=changed_scope))
        for finding in report_findings:
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
            ),
            publication_receipt=publication,
        )

    def _verify_committed_projection_artifacts(self, target: SCMPublicationTarget) -> None:
        """Apply the authorized artifact read policy before projection.

        The terminal evidence loader also verifies payload hashes, but it reads
        the filesystem directly because it is shared with the worker path.  A
        provider publication must additionally respect the server's committed
        artifact lifecycle and source-free data-class policy.
        """

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


__all__ = ["GithubAnnotationReceiptResolver"]
