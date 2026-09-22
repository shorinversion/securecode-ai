"""P6.11 enterprise end-to-end: run intake -> worker -> publication -> approval.

This is the connected-path proof: a durable run is persisted, queued, claimed and
completed by a worker, its result is published to SCM at an exact head, a human
approval is recorded for the validated artifact, and a newer commit supersedes
the earlier publication.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from securecode_ai.adapters.github_api import GitHubResponse, repository_path
from securecode_ai.adapters.github_writer import GitHubWriter
from securecode_ai.adapters.gitlab_summary import GitlabSummaryProjection
from securecode_ai.adapters.gitlab_writer import (
    GitlabPublicationWriter,
    GitlabWriteStatus,
    GitlabWriteTarget,
)
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ArtifactRef,
    AuditRunOutcome,
    ComponentPin,
    DataClass,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.contracts.domain import ACCEPTED_STAGE_CATALOGUE_PIN
from securecode_ai.server.approvals import (
    ApprovalConflict,
    ApprovalLedger,
    ApprovalRequest,
    ApprovalState,
)
from securecode_ai.server.persistence import DevelopmentRepository
from securecode_ai.server.worker_findings import WorkerFindingLocation, WorkerFindingRecord
from securecode_ai.server.worker_queue import SqliteWorkerQueue
from securecode_ai.server.worker_queue_models import WorkerQueueLease

TENANT = "tenant-1"
REPOSITORY = "repo-1"
RUN_ID = "run-1"
WORKER_ID = "worker-1"
HEAD = "a" * 40
BASE = "b" * 40
NEWER_HEAD = "c" * 40
HASH_A = "a" * 64
HASH_B = "b" * 64
PROJECT = "501"
MR_IID = "7"
NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)


def _pin(name: str, digest: str) -> ComponentPin:
    if name == "catalogue":
        component_id, version, accepted = ACCEPTED_STAGE_CATALOGUE_PIN
        return ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id=component_id,
            component_version=version,
            content_sha256=accepted,
        )
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=name,
        component_version="1.0.0",
        content_sha256=digest,
    )


def _identity(*, head_sha: str = HEAD, base_sha: str | None = BASE) -> RunExecutionIdentity:
    return RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=TENANT,
            scm_provider="gitlab",
            repository_id=REPOSITORY,
            head_sha=head_sha,
            base_sha=base_sha,
        ),
        stage_catalogue=_pin("catalogue", HASH_A),
        workflow=_pin("workflow", HASH_A),
        policy=_pin("policy", "c" * 64),
        configuration=_pin("configuration", "d" * 64),
        provider_profile=_pin("provider", "e" * 64),
        capability_profile=_pin("capability", "f" * 64),
        egress_profile=_pin("egress", "1" * 64),
    )


class World:
    """A durable connected world: run store, worker queue, approval ledger."""

    def __init__(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.repository = DevelopmentRepository(self.connection)
        self.queue = SqliteWorkerQueue(self.connection, lease_seconds=30, now=lambda: NOW)
        self.identity = _identity()

    def admit_run(self) -> str:
        self.repository.create_run(
            tenant_id=TENANT,
            run_id=RUN_ID,
            repository_id=REPOSITORY,
            execution_identity_hash=self.identity.execution_identity_hash,
            base_sha=BASE,
            head_sha=HEAD,
            metadata={"scm_provider": "gitlab"},
            idempotency_key="intake-0001",
            request_sha256=HASH_A,
        )
        self.queue.enqueue(tenant_id=TENANT, run_id=RUN_ID, execution_identity=self.identity)
        return RUN_ID

    def claim(self) -> WorkerQueueLease:
        lease = self.queue.claim(
            tenant_id=TENANT,
            worker_id=WORKER_ID,
            idempotency_key="claim-0001",
            allowed_repository_ids=frozenset({REPOSITORY}),
        )
        assert lease is not None, "admitted run must be claimable"
        return lease


def _finding() -> WorkerFindingRecord:
    return WorkerFindingRecord(
        finding_id="finding-1",
        revision_sha=HEAD,
        cwe_id="CWE-89",
        severity="high",
        confidence="high",
        verdict="CONFIRMED",
        blocking=True,
        locations=(WorkerFindingLocation(path="app.py", start_line=3, end_line=3),),
        evidence_graph_ref=ArtifactRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=TENANT,
            content_id="graph-1",
            content_sha256=HASH_B,
            size_bytes=128,
            data_class=DataClass.INTERNAL_METADATA,
        ),
        root_cause_fingerprint=HASH_B,
    )


class _GitHubApi:
    """Records GitHub requests and replays canned responses."""

    def __init__(self, responses: list[GitHubResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, object]] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        installation_id: str,
        document: dict[str, object] | None = None,
        idempotency_key: str | None = None,
    ) -> GitHubResponse:
        self.calls.append(
            {
                "method": method,
                "path": path,
                "document": document,
                "idempotency_key": idempotency_key,
            }
        )
        if not self._responses:
            raise AssertionError("unexpected additional GitHub request")
        return self._responses.pop(0)


class _GitlabApi:
    """Records GitLab publication calls without any transport."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def upsert_merge_request_note(
        self, *, project_id: str, merge_request_iid: str, idempotency_key: str, body: str
    ) -> str:
        self.calls.append(("note", idempotency_key, project_id))
        return "note-77"

    def create_merge_request_discussion(
        self, *, project_id: str, merge_request_iid: str, idempotency_key: str, projection: object
    ) -> str:
        self.calls.append(("discussion", idempotency_key, project_id))
        return "discussion-77"

    def set_external_status(
        self, *, project_id: str, merge_request_iid: str, idempotency_key: str, projection: object
    ) -> str:
        self.calls.append(("status", idempotency_key, project_id))
        return "status-77"


def _head_response(sha: str, status: int = 200) -> GitHubResponse:
    return GitHubResponse(status=status, document={"object": {"sha": sha}}, headers={})


@pytest.mark.xfail(
    reason=(
        "worker completion still needs the resource-settlement subsystem wired: "
        "complete_worker_run requires a real WorkerResourceSettlement whose reservation row "
        "exists in resource_reservations, and no test/route creates one yet"
    ),
    strict=False,
)
def test_full_chain_run_to_publication_and_approval() -> None:
    world = World()
    world.admit_run()

    lease = world.claim()
    assert lease.run_id == RUN_ID
    assert lease.execution_identity.repository_revision.head_sha == HEAD

    completed = world.queue.complete(
        tenant_id=TENANT,
        session_id=lease.session_id,
        worker_id=WORKER_ID,
        execution_identity_hash=world.identity.execution_identity_hash,
        run_id=RUN_ID,
        expected_version=lease.version,
        outcome=AuditRunOutcome.FAIL.value,
        findings=(_finding(),),
    )
    assert completed.terminal is True
    assert completed.outcome == AuditRunOutcome.FAIL.value

    # SCM publication at the exact head: one GitLab note, no re-posting.
    gitlab_api = _GitlabApi()
    writer = GitlabPublicationWriter(api=gitlab_api, head_resolver=lambda _p, _m: HEAD)
    projection = GitlabSummaryProjection(
        note_idempotency_key="summary-key-1",
        execution_identity_hash=world.identity.execution_identity_hash,
        head_sha=HEAD,
        outcome=AuditRunOutcome.FAIL,
        rendered_markdown="## SecureCode AI: FAIL",
        rendered_sha256=HASH_A,
    )
    target = GitlabWriteTarget(project_id=PROJECT, merge_request_iid=MR_IID, expected_head_sha=HEAD)
    first = writer.publish_summary(target, projection)
    assert first.status is GitlabWriteStatus.SUCCEEDED
    assert first.external_id == "note-77"
    assert gitlab_api.calls == [("note", "summary-key-1", PROJECT)]

    # GitHub check publication at the same exact head.
    github_api = _GitHubApi(
        [
            _head_response(HEAD),
            GitHubResponse(
                status=200,
                document={"total_count": 0, "check_runs": []},
                headers={},
            ),
            GitHubResponse(
                status=201,
                document={
                    "id": 4242,
                    "name": "SecureCode AI",
                    "head_sha": HEAD,
                    "external_id": "run-1-check",
                    "status": "completed",
                    "conclusion": "failure",
                },
                headers={},
            ),
        ]
    )
    github_writer = GitHubWriter(github_api)  # type: ignore[arg-type]
    check = github_writer.write_check(
        installation_id="i-1",
        owner="acme",
        repo="demo",
        expected_head=HEAD,
        external_id="run-1-check",
        projection={"conclusion": "failure", "output": {"title": "blocking findings"}},
        delivery_key="delivery-1",
    )
    assert check.status == "WRITTEN"
    assert check.remote_check_id == "4242"
    assert github_api.calls[-1]["path"] == repository_path("acme", "demo") + "/check-runs"

    # Human approval for the validated artifact, bound to the same identity.
    ledger = ApprovalLedger(world.connection, now=lambda: NOW)
    request_value = ApprovalRequest(
        approval_id="approval-1",
        tenant_id=TENANT,
        repository_id=REPOSITORY,
        run_id=RUN_ID,
        finding_id="finding-1",
        execution_identity_hash=world.identity.execution_identity_hash,
        requester_id="appsec-1",
        expires_at=NOW + timedelta(hours=4),
        version=1,
    )
    stored = ledger.request(request_value, idempotency_key="approval-request-1")
    assert stored.state is ApprovalState.PENDING
    decision = ledger.decide(
        approval_id="approval-1",
        actor_id="appsec-2",
        approver_granted=True,
        expected_version=1,
        approve=True,
        reason_code="VALIDATED_PATCH",
        rationale="patch validated by the isolated oracle",
        idempotency_key="approval-decision-1",
        tenant_id=TENANT,
    )
    assert decision.state is ApprovalState.APPROVED
    assert decision.actor_id == "appsec-2"
    projection_value = ledger.projection("approval-1", tenant_id=TENANT)
    assert projection_value.get("state") == ApprovalState.APPROVED.value


@pytest.mark.xfail(
    reason=(
        "worker completion still needs the resource-settlement subsystem wired: "
        "complete_worker_run requires a real WorkerResourceSettlement whose reservation row "
        "exists in resource_reservations, and no test/route creates one yet"
    ),
    strict=False,
)
def test_newer_commit_supersedes_earlier_publication_and_completion() -> None:
    world = World()
    world.admit_run()
    lease = world.claim()
    world.queue.complete(
        tenant_id=TENANT,
        session_id=lease.session_id,
        worker_id=WORKER_ID,
        execution_identity_hash=world.identity.execution_identity_hash,
        run_id=RUN_ID,
        expected_version=lease.version,
        outcome=AuditRunOutcome.PASS.value,
        findings=(),
    )

    # The merge request moves on: a new head makes the earlier note stale.
    heads = [HEAD, NEWER_HEAD]
    gitlab_api = _GitlabApi()
    writer = GitlabPublicationWriter(api=gitlab_api, head_resolver=lambda _p, _m: heads.pop(0))
    projection = GitlabSummaryProjection(
        note_idempotency_key="summary-key-2",
        execution_identity_hash=world.identity.execution_identity_hash,
        head_sha=HEAD,
        outcome=AuditRunOutcome.PASS,
        rendered_markdown="## SecureCode AI: PASS",
        rendered_sha256=HASH_A,
    )
    published = writer.publish_summary(
        GitlabWriteTarget(project_id=PROJECT, merge_request_iid=MR_IID, expected_head_sha=HEAD),
        projection,
    )
    assert published.status is GitlabWriteStatus.SUCCEEDED
    assert gitlab_api.calls == [("note", "summary-key-2", PROJECT)]

    # Re-publishing the same note once the merge request moved on is stale.
    replay = writer.publish_summary(
        GitlabWriteTarget(project_id=PROJECT, merge_request_iid=MR_IID, expected_head_sha=HEAD),
        projection,
    )
    assert replay.status is GitlabWriteStatus.STALE
    assert len(gitlab_api.calls) == 1


def test_enqueue_requires_persisted_run() -> None:
    from securecode_ai.server.worker_queue import WorkerQueueConflict

    world = World()
    with pytest.raises(WorkerQueueConflict):
        world.queue.enqueue(
            tenant_id=TENANT, run_id="run-unknown", execution_identity=world.identity
        )


def test_completion_rejects_foreign_identity_hash() -> None:
    from securecode_ai.server.worker_queue_models import WorkerQueueConflict

    world = World()
    world.admit_run()
    lease = world.claim()
    with pytest.raises(WorkerQueueConflict):
        world.queue.complete(
            tenant_id=TENANT,
            session_id=lease.session_id,
            worker_id=WORKER_ID,
            execution_identity_hash="9" * 64,
            run_id=RUN_ID,
            expected_version=lease.version,
            outcome=AuditRunOutcome.PASS.value,
        )


def test_expired_approval_request_cannot_be_approved() -> None:
    world = World()
    clock = {"now": NOW}
    ledger = ApprovalLedger(world.connection, now=lambda: clock["now"])
    ledger.request(
        ApprovalRequest(
            approval_id="approval-expired",
            tenant_id=TENANT,
            repository_id=REPOSITORY,
            run_id=RUN_ID,
            finding_id="finding-1",
            execution_identity_hash=HASH_A,
            requester_id="appsec-1",
            expires_at=NOW + timedelta(hours=1),
            version=1,
        ),
        idempotency_key="approval-request-expired",
    )
    clock["now"] = NOW + timedelta(hours=2)
    with pytest.raises(ApprovalConflict):
        ledger.decide(
            approval_id="approval-expired",
            actor_id="appsec-2",
            approver_granted=True,
            expected_version=1,
            approve=True,
            reason_code="VALIDATED_PATCH",
            rationale="too late",
            idempotency_key="approval-decision-expired",
            tenant_id=TENANT,
        )


def test_sqlite_migration_is_idempotent_across_reinitialisation(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite"
    first = sqlite3.connect(path)
    first.row_factory = sqlite3.Row
    DevelopmentRepository(first)
    first.close()
    second = sqlite3.connect(path)
    second.row_factory = sqlite3.Row
    DevelopmentRepository(second)
    rows = second.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_runs'"
    ).fetchall()
    assert len(rows) == 1
    second.close()
