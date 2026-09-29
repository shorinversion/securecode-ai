"""P7.5 GitLab summary note: advisory-only rendering and updateable idempotency."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest
from securecode_ai.adapters.gitlab_ci import (
    GitlabCIAdapter,
    GitlabCIAdmissionRequest,
    GitlabContributionTrust,
)
from securecode_ai.adapters.gitlab_summary import (
    GitlabSummaryDisposition,
    GitlabSummaryError,
    GitlabSummaryErrorCode,
    GitlabSummaryPublisher,
    GitlabSummaryRequest,
)
from securecode_ai.contracts import AuditRun, AuditRunOutcome
from securecode_ai.core.scm_run_state import SCMRunState

ROOT = Path(__file__).resolve().parents[2]


def _fixture() -> Any:
    spec = importlib.util.spec_from_file_location(
        "p75_worker_fixture", ROOT / "tests" / "unit" / "test_ci_worker.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("worker fixture unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Head:
    def __init__(self, sha: str) -> None:
        self.sha = sha

    def __call__(self, _project_id: str, _merge_request_iid: str) -> str:
        return self.sha


def _setup(outcome: AuditRunOutcome = AuditRunOutcome.PASS) -> tuple[Any, Any, str, str]:
    """Return (publisher, audit_run, run_id, head) for a gitlab-shaped run."""

    fixture = _fixture()
    audit_run: AuditRun = fixture._admitted_run(outcome=outcome)
    identity = audit_run.execution_identity
    revision = identity.repository_revision
    project = revision.repository_id
    head = revision.head_sha
    adapter = GitlabCIAdapter(run_state=SCMRunState(), head_resolver=_Head(head))
    admission = adapter.admit(
        GitlabCIAdmissionRequest(
            pipeline_id="9001",
            job_id="1",
            project_id=project,
            merge_request_iid="7",
            source_project_id=project,
            target_project_id=project,
            contribution_trust=GitlabContributionTrust.TRUSTED,
            execution_identity=identity,
        )
    )
    run_id = admission.admission.run_id
    # Production projects only an audit run whose run_id is the SCM run id.
    audit_run = audit_run.model_copy(update={"run_id": run_id})
    publisher = GitlabSummaryPublisher(adapter)
    return publisher, audit_run, run_id, head


def test_publisher_requires_a_gitlab_adapter() -> None:
    with pytest.raises(GitlabSummaryError) as error:
        GitlabSummaryPublisher(object())  # type: ignore[arg-type]
    assert error.value.code is GitlabSummaryErrorCode.INVALID_REQUEST


def test_request_rejects_malformed_input() -> None:
    with pytest.raises(GitlabSummaryError) as error:
        GitlabSummaryRequest(scm_run_id="", audit_run=object())  # type: ignore[arg-type]
    assert error.value.code is GitlabSummaryErrorCode.INVALID_REQUEST


def test_project_rejects_non_request_object() -> None:
    publisher, _audit_run, _run_id, _head = _setup()
    with pytest.raises(GitlabSummaryError) as error:
        publisher.project(object())
    assert error.value.code is GitlabSummaryErrorCode.INVALID_REQUEST


def test_unknown_run_is_authorization_rejected() -> None:
    publisher, audit_run, _run_id, _head = _setup()
    with pytest.raises(GitlabSummaryError) as error:
        publisher.project(GitlabSummaryRequest(scm_run_id="run-unknown", audit_run=audit_run))
    assert error.value.code is GitlabSummaryErrorCode.AUTHORIZATION_REJECTED


def test_first_projection_creates_then_repeats_idempotently() -> None:
    publisher, audit_run, run_id, head = _setup()
    first = publisher.project(GitlabSummaryRequest(scm_run_id=run_id, audit_run=audit_run))
    assert first.disposition is GitlabSummaryDisposition.CREATE
    projection = first.projection
    assert projection is not None
    assert projection.head_sha == head
    assert projection.outcome is AuditRunOutcome.PASS
    assert projection.merge_authority is False
    assert projection.rendered_markdown.startswith("<!-- securecode-ai-gitlab-summary:")
    assert "advisory" in projection.rendered_markdown
    # Without a completion receipt no policy outcome exists yet.
    assert "Published policy status: INDETERMINATE" in projection.rendered_markdown
    assert projection.note_idempotency_key.startswith("note-")

    second = publisher.project(GitlabSummaryRequest(scm_run_id=run_id, audit_run=audit_run))
    assert second.disposition is GitlabSummaryDisposition.IDEMPOTENT
    assert second.projection is not None
    assert second.projection.rendered_sha256 == projection.rendered_sha256


def test_changed_findings_update_the_same_note() -> None:
    publisher, audit_run, run_id, _head = _setup()
    publisher.project(GitlabSummaryRequest(scm_run_id=run_id, audit_run=audit_run))
    changed = audit_run.model_copy(update={"finding_ids": ("finding-extra",)})
    updated = publisher.project(GitlabSummaryRequest(scm_run_id=run_id, audit_run=changed))
    assert updated.disposition is GitlabSummaryDisposition.UPDATE
    assert updated.projection is not None


def test_stale_run_is_superseded_without_projection() -> None:
    publisher, audit_run, run_id, head = _setup()
    adapter = publisher._adapter
    adapter._head_resolver = _Head("d" * 40)
    receipt = publisher.project(GitlabSummaryRequest(scm_run_id=run_id, audit_run=audit_run))
    assert receipt.disposition is GitlabSummaryDisposition.SUPERSEDED
    assert receipt.projection is None
    assert receipt.publication.head_sha == head


def test_pass_with_incomplete_coverage_is_rejected() -> None:
    publisher, audit_run, run_id, _head = _setup()
    manifest = audit_run.coverage_manifest.model_copy(update={"coverage_complete": False})
    forged = audit_run.model_copy(update={"coverage_manifest": manifest})
    with pytest.raises(GitlabSummaryError) as error:
        publisher.project(GitlabSummaryRequest(scm_run_id=run_id, audit_run=forged))
    assert error.value.code is GitlabSummaryErrorCode.IDENTITY_MISMATCH


def test_foreign_identity_is_rejected() -> None:
    publisher, audit_run, run_id, _head = _setup()
    other_identity = audit_run.execution_identity.build(
        repository_revision=audit_run.execution_identity.repository_revision.model_copy(
            update={"base_sha": "e" * 40}
        ),
        stage_catalogue=audit_run.execution_identity.stage_catalogue,
        workflow=audit_run.execution_identity.workflow,
        policy=audit_run.execution_identity.policy,
        configuration=audit_run.execution_identity.configuration,
        provider_profile=audit_run.execution_identity.provider_profile,
        capability_profile=audit_run.execution_identity.capability_profile,
        egress_profile=audit_run.execution_identity.egress_profile,
    )
    forged = audit_run.model_copy(update={"execution_identity": other_identity})
    with pytest.raises(GitlabSummaryError) as error:
        publisher.project(GitlabSummaryRequest(scm_run_id=run_id, audit_run=forged))
    assert error.value.code is GitlabSummaryErrorCode.IDENTITY_MISMATCH


def test_non_pass_outcome_renders_without_claims() -> None:
    publisher, audit_run, run_id, _head = _setup(outcome=AuditRunOutcome.INDETERMINATE)
    receipt = publisher.project(GitlabSummaryRequest(scm_run_id=run_id, audit_run=audit_run))
    projection = receipt.projection
    assert projection is not None
    assert projection.outcome is AuditRunOutcome.INDETERMINATE
    assert "INDETERMINATE" in projection.rendered_markdown
    assert "advisory" in projection.rendered_markdown
