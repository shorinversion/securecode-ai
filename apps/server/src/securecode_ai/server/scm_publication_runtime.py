"""Shared composition for durable SCM publication graphs."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from .artifact_read import LocalCommittedArtifactReader
from .baseline_store import DurableBaselineStore
from .persistence import DevelopmentRepository
from .scm_annotations import GithubAnnotationReceiptResolver
from .scm_completion import SCMCompletionPublicationService
from .scm_gitlab_publication import GitlabTerminalPublicationResolver
from .scm_policy_waivers import waivers_cover_run_policy
from .scm_publication_store import SCMPublicationTarget, SqliteSCMPublicationStore
from .scm_runtime import SCMHandlers
from .residency_registry import SqliteResidencyRegistry
from .waivers import WaiverLedger
from .worker_scm_policy import load_run_scm_policy_decision


def build_scm_publication_service(
    *,
    connection: sqlite3.Connection,
    repository: DevelopmentRepository,
    scm: SCMHandlers,
    publications: SqliteSCMPublicationStore,
    waiver_ledger: WaiverLedger,
    artifact_root: Path,
    residency_guard: SqliteResidencyRegistry | None,
    residency_region: str | None,
) -> SCMCompletionPublicationService:
    """Compose one publication service from one complete SQLite-backed graph."""

    if (
        not isinstance(connection, sqlite3.Connection)
        or type(repository) is not DevelopmentRepository
        or type(scm) is not SCMHandlers
        or type(publications) is not SqliteSCMPublicationStore
        or type(waiver_ledger) is not WaiverLedger
        or not isinstance(artifact_root, Path)
        or (residency_guard is None) is not (residency_region is None)
        or scm.run_state is None
    ):
        raise TypeError("SCM publication graph is invalid")
    artifact_reader = LocalCommittedArtifactReader(
        connection,
        artifact_root,
        residency_guard=residency_guard,
        residency_region=residency_region,
    )
    github_annotation_receipt = (
        GithubAnnotationReceiptResolver(
            connection=connection,
            artifact_root=artifact_root,
            baseline_store=DurableBaselineStore(connection),
            lineage_resolver=scm.lineage_resolver,
            changed_lines_resolver=scm.changed_lines_resolver,
            authorizer=scm.github,
            artifact_reader=artifact_reader,
        )
        if (
            scm.github is not None
            and scm.github_comments is not None
            and scm.lineage_resolver is not None
            and scm.changed_lines_resolver is not None
        )
        else None
    )
    gitlab_terminal_publication = (
        GitlabTerminalPublicationResolver(
            connection=connection,
            artifact_root=artifact_root,
            baseline_store=DurableBaselineStore(connection),
            lineage_resolver=scm.lineage_resolver,
            api=scm.gitlab_api,
            authorizer=scm.gitlab,
            artifact_reader=artifact_reader,
        )
        if (
            scm.gitlab is not None
            and scm.gitlab_api is not None
            and scm.lineage_resolver is not None
        )
        else None
    )
    return SCMCompletionPublicationService(
        publications=publications,
        run_state=scm.run_state,
        github_head=scm.github_head,
        github_writer=scm.github_writer,
        github_comment_writer=scm.github_comments,
        github_annotation_receipt=github_annotation_receipt,
        github_sarif_writer=scm.github_sarif,
        github_sarif_artifact=(
            _committed_github_sarif_artifact_reader(repository, artifact_reader)
            if scm.github_sarif is not None
            else None
        ),
        gitlab_head=scm.gitlab_head,
        gitlab_writer=scm.gitlab_writer,
        gitlab_terminal_publication=gitlab_terminal_publication,
        policy_decisions=lambda tenant_id, run_id, identity_hash: (
            load_run_scm_policy_decision(
                connection,
                tenant_id=tenant_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
            )
        ),
        waiver_exception_resolver=lambda tenant_id, run_id, identity_hash, decision: (
            waivers_cover_run_policy(
                connection,
                waiver_ledger,
                tenant_id=tenant_id,
                run_id=run_id,
                identity_hash=identity_hash,
                decision=decision,
            )
        ),
        waiver_revision_resolver=lambda tenant_id, run_id, identity_hash: (
            waiver_ledger.revision_hash(
                tenant_id=tenant_id,
                run_id=run_id,
                identity_hash=identity_hash,
            )
        ),
    )


def _committed_github_sarif_artifact_reader(
    repository: DevelopmentRepository,
    artifact_reader: LocalCommittedArtifactReader,
):
    def resolve(target: SCMPublicationTarget) -> tuple[str, bytes] | None:
        run = repository.get_run(target.tenant_id, target.run_id)
        if (
            run.get("execution_identity_hash") != target.execution_identity_hash
            or run.get("head_sha") != target.head_sha
            or run.get("repository_id") != target.repository_id
        ):
            raise ValueError("committed SARIF identity is invalid")
        artifact_reader.require_tenant_access(target.tenant_id)
        cursor: str | None = None
        matches: list[dict[str, object]] = []
        seen_cursors: set[str] = set()
        for _ in range(1024):
            page = repository.list_artifacts(
                target.tenant_id,
                target.run_id,
                cursor_token=cursor,
                limit=100,
            )
            if type(page) is not dict or "items" not in page or "next_cursor" not in page:
                raise ValueError("committed SARIF listing is invalid")
            items = page["items"]
            if type(items) is not list:
                raise ValueError("committed SARIF listing is invalid")
            for item in items:
                if type(item) is dict and item.get("purpose") == "sarif-report":
                    matches.append(item)
            next_cursor = page["next_cursor"]
            if next_cursor is None:
                break
            if (
                type(next_cursor) is not str
                or not next_cursor
                or next_cursor in seen_cursors
            ):
                raise ValueError("committed SARIF listing is invalid")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise ValueError("committed SARIF listing is invalid")
        if len(matches) != 1:
            return None
        item = matches[0]
        content_sha256 = item.get("content_sha256")
        if type(content_sha256) is not str:
            raise ValueError("committed SARIF identity is invalid")
        content = artifact_reader.read_binary(
            tenant_id=target.tenant_id,
            run_id=target.run_id,
            content_sha256=content_sha256,
        )
        if (
            content.purpose != "sarif-report"
            or content.content_sha256 != content_sha256
            or content.content_id != item.get("content_id")
            or content.data_class != item.get("data_class")
            or content.size_bytes != item.get("size_bytes")
        ):
            raise ValueError("committed SARIF content is invalid")
        if (
            len(content.content) != item.get("size_bytes")
            or hashlib.sha256(content.content).hexdigest() != content_sha256
        ):
            raise ValueError("committed SARIF content is invalid")
        return content_sha256, content.content

    return resolve


__all__ = ["build_scm_publication_service"]
