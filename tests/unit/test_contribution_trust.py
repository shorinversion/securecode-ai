from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime

import pytest
from securecode_ai.adapters.untrusted_contribution import ContributionTrust
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    ProviderKind,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.core.scm_run_state import (
    AdmissionDisposition,
    SCMRunAdmissionReceipt,
    SCMRunLifecycle,
)
from securecode_ai.server.persistence import DevelopmentRepository
from securecode_ai.server.ports import ServiceRequest, VerifiedIdentity
from securecode_ai.server.run_admission import _safe_server_context
from securecode_ai.server.scm_admission import _run_request
from securecode_ai.server.scm_webhooks import (
    SCMWebhookError,
    WebhookAdmissionReceipt,
    _github_metadata,
)
from securecode_ai.server.worker_queue import SqliteWorkerQueue, _run_contribution_trust
from securecode_ai.server.worker_queue_models import WorkerQueueConflict
from securecode_ai.worker.execution import (
    ProductExecutionError,
    _contribution_environment,
    _require_contribution_provider,
)
from securecode_ai.worker.protocol import (
    ProtocolError,
    WorkerCommand,
    WorkerContributionTrust,
    WorkerJob,
)


def _identity() -> RunExecutionIdentity:
    def pin(name: str, suffix: str) -> ComponentPin:
        return ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id=name,
            component_version="1.0.0",
            content_sha256=suffix * 64,
        )

    return RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-1",
            scm_provider="github",
            repository_id="501",
            head_sha="a" * 40,
            base_sha="b" * 40,
        ),
        stage_catalogue=pin("catalogue", "1"),
        workflow=pin("workflow", "2"),
        policy=pin("policy", "3"),
        configuration=pin("configuration", "4"),
        provider_profile=pin("provider", "5"),
        capability_profile=pin("capability", "6"),
        egress_profile=pin("egress", "7"),
    )


def _job(trust: WorkerContributionTrust) -> WorkerJob:
    identity = _identity()
    return WorkerJob(
        session_id="session-1",
        run_id="run-1",
        version=1,
        lease_seconds=30,
        command=WorkerCommand.CONTINUE,
        execution_identity=identity,
        contribution_trust=trust,
    )


def test_fork_trust_survives_worker_job_protocol() -> None:
    identity = _identity()
    job = WorkerJob.from_document(
        {
            "session_id": "session-1",
            "run_id": "run-1",
            "version": 1,
            "lease_seconds": 30,
            "command": "CONTINUE",
            "execution_identity": identity.model_dump(mode="json"),
            "execution_identity_hash": identity.execution_identity_hash,
            "contribution_trust": "UNTRUSTED_FORK",
        }
    )

    assert job.contribution_trust is WorkerContributionTrust.UNTRUSTED_FORK


def test_worker_protocol_rejects_unknown_trust_value() -> None:
    identity = _identity()
    with pytest.raises(ProtocolError):
        WorkerJob.from_document(
            {
                "session_id": "session-1",
                "run_id": "run-1",
                "version": 1,
                "lease_seconds": 30,
                "command": "CONTINUE",
                "execution_identity": identity.model_dump(mode="json"),
                "contribution_trust": "TRUST_ME",
            }
        )


def test_direct_worker_job_rejects_forged_trusted_label_before_environment_filtering() -> None:
    """A caller must not bypass the authenticated transport parser to inherit secrets."""

    with pytest.raises(ProtocolError):
        WorkerJob(
            session_id="session-1",
            run_id="run-1",
            version=1,
            lease_seconds=30,
            command=WorkerCommand.CONTINUE,
            execution_identity=_identity(),
            contribution_trust="TRUSTED_SAME_REPOSITORY",  # type: ignore[arg-type]
        )


def test_untrusted_contribution_filters_auth_environment() -> None:
    first_name = "_".join(("OPENAI", "API", "KEY"))
    second_name = "_".join(("GITLAB", "TOKEN"))
    environment = {
        "PATH": "safe-path",
        first_name: "canary-value",
        second_name: "canary-value",
        "SECURECODE_PROVIDER_PROFILE": "local@1.0.0",
        "SECURECODE_POLICY_PROFILE": "policy-default",
        "SECURECODE_EGRESS_PROFILE": "loopback-only",
    }

    sanitized = _contribution_environment(_job(WorkerContributionTrust.UNTRUSTED_FORK), environment)

    assert sanitized == {
        "SECURECODE_PROVIDER_PROFILE": "local@1.0.0",
        "SECURECODE_POLICY_PROFILE": "policy-default",
        "SECURECODE_EGRESS_PROFILE": "loopback-only",
    }


@pytest.mark.parametrize(
    "name",
    [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "SSH_AUTH_SOCK",
        "KUBECONFIG",
        "DOCKER_CONFIG",
    ],
)
def test_untrusted_contribution_filters_cloud_and_agent_credentials(name: str) -> None:
    sanitized = _contribution_environment(
        _job(WorkerContributionTrust.UNTRUSTED_FORK),
        {"PATH": "safe-path", name: "credential-material"},
    )

    assert sanitized == {}


def test_unknown_contribution_filters_every_environment_variable_except_selectors() -> None:
    sanitized = _contribution_environment(
        _job(WorkerContributionTrust.UNKNOWN),
        {
            "PATH": "host-path",
            "APP_CONFIG": "config-path",
            "SECURECODE_PROVIDER_PROFILE": "local@1.0.0",
        },
    )

    assert sanitized == {"SECURECODE_PROVIDER_PROFILE": "local@1.0.0"}


def test_untrusted_contribution_rejects_remote_provider() -> None:
    with pytest.raises(ProductExecutionError):
        _require_contribution_provider(
            _job(WorkerContributionTrust.UNTRUSTED_FORK), ProviderKind.OPENAI
        )


def test_untrusted_contribution_accepts_loopback_local_provider() -> None:
    _require_contribution_provider(
        _job(WorkerContributionTrust.UNTRUSTED_FORK), ProviderKind.OPENAI_COMPATIBLE_LOCAL
    )


def test_unknown_contribution_trust_also_rejects_remote_provider() -> None:
    with pytest.raises(ProductExecutionError):
        _require_contribution_provider(
            _job(WorkerContributionTrust.UNKNOWN), ProviderKind.ANTHROPIC
        )


def test_queue_reads_trust_from_durable_run_metadata() -> None:
    assert (
        _run_contribution_trust(json.dumps({"contribution_trust": "UNTRUSTED_FORK"}))
        == "UNTRUSTED_FORK"
    )


def test_untrusted_fork_context_survives_durable_queue_claim() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    repository = DevelopmentRepository(connection)
    queue = SqliteWorkerQueue(
        connection,
        now=lambda: datetime(2026, 9, 23, tzinfo=UTC),
    )
    identity = _identity()
    repository.create_run(
        tenant_id="tenant-1",
        run_id="run-1",
        repository_id="501",
        execution_identity_hash=identity.execution_identity_hash,
        base_sha="b" * 40,
        head_sha="a" * 40,
        metadata={"contribution_trust": "UNTRUSTED_FORK"},
        idempotency_key="delivery-1",
        request_sha256="8" * 64,
    )
    queue.enqueue(tenant_id="tenant-1", run_id="run-1", execution_identity=identity)

    lease = queue.claim(
        tenant_id="tenant-1",
        worker_id="worker-1",
        idempotency_key="claim-0001",
        allowed_repository_ids=frozenset({"501"}),
    )

    assert lease is not None
    assert lease.contribution_trust == "UNTRUSTED_FORK"
    assert lease.job_document()["contribution_trust"] == "UNTRUSTED_FORK"
    assert (
        WorkerJob.from_document(lease.job_document()).contribution_trust
        is WorkerContributionTrust.UNTRUSTED_FORK
    )


def test_queue_defaults_non_scm_runs_to_non_scm() -> None:
    assert _run_contribution_trust("{}") == "NOT_SCM"


def test_queue_fails_closed_on_corrupt_trust_metadata() -> None:
    with pytest.raises(WorkerQueueConflict):
        _run_contribution_trust('{"contribution_trust":"TRUST_ME"}')


def test_queue_fails_closed_on_non_string_trust_metadata() -> None:
    with pytest.raises(WorkerQueueConflict):
        _run_contribution_trust('{"contribution_trust":[]}')


def test_github_metadata_classifies_fork_from_repository_ids() -> None:
    metadata = _github_metadata(
        {
            "action": "opened",
            "repository": {"id": 501},
            "pull_request": {
                "number": 17,
                "author_association": "CONTRIBUTOR",
                "head": {"sha": "a" * 40, "repo": {"id": 777}},
                "base": {"sha": "b" * 40, "repo": {"id": 501}},
            },
            "installation": {"id": 1},
        }
    )

    assert metadata.contribution_trust.value == "UNTRUSTED_FORK"


def test_github_metadata_trusts_same_repository_collaborator() -> None:
    metadata = _github_metadata(
        {
            "action": "opened",
            "repository": {"id": "501"},
            "pull_request": {
                "number": 17,
                "author_association": "MEMBER",
                "head": {"sha": "a" * 40, "repo": {"id": "501"}},
                "base": {"sha": "b" * 40, "repo": {"id": 501}},
            },
            "installation": {"id": 1},
        }
    )

    assert metadata.contribution_trust is ContributionTrust.TRUSTED_SAME_REPOSITORY


def test_missing_github_repository_binding_is_unknown_trust() -> None:
    metadata = _github_metadata(
        {
            "action": "opened",
            "repository": {"id": 501},
            "pull_request": {
                "head": {"sha": "a" * 40},
                "base": {"sha": "b" * 40},
            },
            "installation": {"id": 1},
        }
    )

    assert metadata.contribution_trust is ContributionTrust.UNKNOWN


def test_github_metadata_requires_repository_binding_to_match() -> None:
    with pytest.raises(SCMWebhookError):
        _github_metadata(
            {
                "action": "opened",
                "repository": {"id": 501},
                "pull_request": {
                    "head": {"sha": "a" * 40, "repo": {"id": 777}},
                    "base": {"sha": "b" * 40, "repo": {"id": 999}},
                },
                "installation": {"id": 1},
            }
        )


def test_authenticated_webhook_trust_enters_only_internal_run_context() -> None:
    identity = _identity()
    admission = SCMRunAdmissionReceipt(
        disposition=AdmissionDisposition.ADMITTED,
        run_id="run-1",
        execution_identity_hash=identity.execution_identity_hash,
        head_sha="a" * 40,
        lifecycle=SCMRunLifecycle.ADMITTED,
        state_version=1,
    )
    receipt = WebhookAdmissionReceipt(
        provider="github",
        event="pull_request",
        delivery_id="delivery-1",
        installation_id="installation-1",
        repository_id="501",
        change_id="17",
        head_sha="a" * 40,
        base_sha="b" * 40,
        admission=admission,
        contribution_trust=ContributionTrust.UNTRUSTED_FORK,
    )
    request = ServiceRequest(
        method="POST",
        route="/webhooks/github",
        action="webhooks.github",
        identity=VerifiedIdentity("subject-1", "tenant-1", frozenset(), workload=True),
        idempotency_key="delivery-1",
        precondition=None,
        path_params={},
        query={},
        document=None,
        raw_body=b"{}",
    )

    run_request = _run_request(request, receipt, identity)

    assert run_request.server_context == {"contribution_trust": "UNTRUSTED_FORK"}
    assert json.loads(run_request.raw_body)["contribution_trust"] == "UNTRUSTED_FORK"
    assert _safe_server_context(run_request.server_context) == {
        "contribution_trust": "UNTRUSTED_FORK"
    }
    assert _safe_server_context({"contribution_trust": ["TRUSTED_SAME_REPOSITORY"]}) == {}
