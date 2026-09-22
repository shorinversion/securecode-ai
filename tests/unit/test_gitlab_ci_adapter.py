"""P7.5 GitLab parity: admission policy, exact-head completion and fork safety."""

from __future__ import annotations

from typing import Any

import pytest
from securecode_ai.adapters.gitlab_ci import (
    GitlabCIAdapter,
    GitlabCIAdmissionRequest,
    GitlabCIError,
    GitlabCIErrorCode,
    GitlabContributionTrust,
    GitlabExternalStatus,
    GitlabJobConclusion,
)
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    AuditRunOutcome,
    ComponentPin,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.contracts.domain import ACCEPTED_STAGE_CATALOGUE_PIN
from securecode_ai.core.scm_run_state import (
    AdmissionDisposition,
    PublicationDisposition,
    SCMRunAdmissionRequest,
    SCMRunState,
)

HEAD = "a" * 40
BASE = "b" * 40
OTHER_HEAD = "c" * 40
PROJECT = "501"
FORK_PROJECT = "900"
MR = "7"


def _pin(name: str, digest: str) -> ComponentPin:
    if name == "catalogue":
        component_id, version, digest = ACCEPTED_STAGE_CATALOGUE_PIN
        return ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id=component_id,
            component_version=version,
            content_sha256=digest,
        )
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=name,
        component_version="1.0.0",
        content_sha256=digest,
    )


def _identity(
    *,
    provider: str = "gitlab",
    repository_id: str = PROJECT,
    head_sha: str = HEAD,
) -> RunExecutionIdentity:
    return RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-1",
            scm_provider=provider,
            repository_id=repository_id,
            head_sha=head_sha,
            base_sha=BASE,
        ),
        stage_catalogue=_pin("catalogue", "0" * 64),
        workflow=_pin("workflow", "b" * 64),
        policy=_pin("policy", "c" * 64),
        configuration=_pin("configuration", "d" * 64),
        provider_profile=_pin("provider", "e" * 64),
        capability_profile=_pin("capability", "f" * 64),
        egress_profile=_pin("egress", "1" * 64),
    )


def _request(
    *,
    pipeline_id: str = "9001",
    job_id: str = "1",
    project_id: str = PROJECT,
    merge_request_iid: str = MR,
    source_project_id: str = PROJECT,
    target_project_id: str = PROJECT,
    trust: GitlabContributionTrust = GitlabContributionTrust.TRUSTED,
    identity: RunExecutionIdentity | None = None,
) -> GitlabCIAdmissionRequest:
    return GitlabCIAdmissionRequest(
        pipeline_id=pipeline_id,
        job_id=job_id,
        project_id=project_id,
        merge_request_iid=merge_request_iid,
        source_project_id=source_project_id,
        target_project_id=target_project_id,
        contribution_trust=trust,
        execution_identity=identity or _identity(),
    )


class _Head:
    def __init__(self, sha: str = HEAD) -> None:
        self.sha = sha

    def __call__(self, _project_id: str, _merge_request_iid: str) -> str:
        return self.sha


class _BrokenHead:
    def __call__(self, _project_id: str, _merge_request_iid: str) -> str:
        raise OSError("resolver offline")


class _ProviderTarget:
    def __init__(
        self,
        *,
        provider: object = "gitlab",
        installation_id: object = PROJECT,
        repository_id: object = PROJECT,
        change_id: object = MR,
        execution_identity_hash: object = "a" * 64,
    ) -> None:
        self.provider = provider
        self.installation_id = installation_id
        self.repository_id = repository_id
        self.change_id = change_id
        self.execution_identity_hash = execution_identity_hash


class _RestoringState:
    """Durable-state stub: restores bindings, delegates transitions to real state."""

    def __init__(self, target: Any, inner: SCMRunState | None = None) -> None:
        self._target = target
        self._inner = inner if inner is not None else SCMRunState()
        self.calls: list[tuple[str, object]] = []

    def provider_target(self, run_id: str) -> object:
        self.calls.append(("provider_target", run_id))
        if isinstance(self._target, Exception):
            raise self._target
        return self._target

    def admit(self, request: Any, *, current_head_sha: str) -> Any:
        return self._inner.admit(request, current_head_sha=current_head_sha)

    def authorize_publication(self, run_id: str, *, current_head_sha: str) -> Any:
        return self._inner.authorize_publication(run_id, current_head_sha=current_head_sha)

    def complete(self, run_id: str, outcome: Any, *, current_head_sha: str) -> Any:
        return self._inner.complete(run_id, outcome, current_head_sha=current_head_sha)


def _adapter(
    *, head: str = HEAD, run_state: object | None = None, resolver: object | None = None
) -> tuple[GitlabCIAdapter, SCMRunState]:
    state = run_state if run_state is not None else SCMRunState()
    adapter = GitlabCIAdapter(
        run_state=state, head_resolver=resolver if resolver is not None else _Head(head)
    )
    return adapter, state  # type: ignore[return-value]


# --- configuration and request validation -------------------------------------


@pytest.mark.parametrize(
    ("run_state", "resolver"),
    [
        (object(), _Head()),
        (SCMRunState(), "not-callable"),
        ({}, _Head()),
    ],
)
def test_adapter_rejects_invalid_configuration(run_state: object, resolver: object) -> None:
    with pytest.raises(GitlabCIError) as error:
        GitlabCIAdapter(run_state=run_state, head_resolver=resolver)
    assert error.value.code is GitlabCIErrorCode.INVALID_CONFIGURATION


def test_adapter_rejects_non_request_object() -> None:
    adapter, _ = _adapter()
    with pytest.raises(GitlabCIError) as error:
        adapter.admit(object())  # type: ignore[arg-type]
    assert error.value.code is GitlabCIErrorCode.INVALID_REQUEST


def test_request_rejects_project_target_mismatch() -> None:
    with pytest.raises(GitlabCIError) as error:
        _request(project_id=PROJECT, target_project_id="502")
    assert error.value.code is GitlabCIErrorCode.INVALID_REQUEST


def test_request_rejects_identity_repository_mismatch() -> None:
    with pytest.raises(GitlabCIError) as error:
        _request(identity=_identity(repository_id="999"))
    assert error.value.code is GitlabCIErrorCode.INVALID_REQUEST


@pytest.mark.parametrize(
    "field",
    ["pipeline_id", "job_id", "project_id", "merge_request_iid", "source_project_id"],
)
def test_request_rejects_malformed_identifiers(field: str) -> None:
    kwargs: dict[str, object] = {field: ""}
    with pytest.raises(GitlabCIError) as error:
        _request(**kwargs)  # type: ignore[arg-type]
    assert error.value.code is GitlabCIErrorCode.INVALID_REQUEST


def test_request_rejects_declared_trust_that_contradicts_sources() -> None:
    with pytest.raises(GitlabCIError) as error:
        _request(
            source_project_id=FORK_PROJECT,
            trust=GitlabContributionTrust.TRUSTED,
            identity=_identity(),
        )
    assert error.value.code is GitlabCIErrorCode.IDENTITY_MISMATCH


def test_request_rejects_fork_trust_when_sources_match() -> None:
    with pytest.raises(GitlabCIError) as error:
        _request(trust=GitlabContributionTrust.UNTRUSTED_FORK)
    assert error.value.code is GitlabCIErrorCode.IDENTITY_MISMATCH


# --- admission and credential policy (P5.10) ----------------------------------


def test_trusted_admission_exposes_read_but_no_write_credentials() -> None:
    adapter, _ = _adapter()
    receipt = adapter.admit(_request())
    policy = receipt.execution_policy
    assert receipt.project_id == PROJECT
    assert receipt.merge_request_iid == MR
    assert receipt.head_sha == HEAD
    assert receipt.admission.disposition is AdmissionDisposition.ADMITTED
    assert policy.allow_repository_read_credential is True
    assert policy.allow_scm_write_credential is False
    assert policy.allow_backend_credential is False
    assert policy.allow_provider_credential is False


def test_fork_admission_denies_every_credential() -> None:
    adapter, _ = _adapter()
    receipt = adapter.admit(
        _request(
            project_id=PROJECT,
            source_project_id=FORK_PROJECT,
            target_project_id=PROJECT,
            trust=GitlabContributionTrust.UNTRUSTED_FORK,
            identity=_identity(repository_id=PROJECT),
        )
    )
    policy = receipt.execution_policy
    assert policy.contribution_trust is GitlabContributionTrust.UNTRUSTED_FORK
    assert policy.allow_repository_read_credential is False
    assert policy.allow_scm_write_credential is False
    assert policy.allow_backend_credential is False
    assert policy.allow_provider_credential is False


def test_stale_head_admission_is_superseded_and_leaves_no_binding() -> None:
    adapter, _ = _adapter(head=OTHER_HEAD)
    receipt = adapter.admit(_request())
    assert receipt.admission.disposition is AdmissionDisposition.SUPERSEDED
    with pytest.raises(GitlabCIError) as error:
        adapter.complete(receipt.admission.run_id, AuditRunOutcome.PASS)
    assert error.value.code is GitlabCIErrorCode.RUN_UNKNOWN


def test_repeated_delivery_is_idempotent() -> None:
    adapter, _ = _adapter()
    first = adapter.admit(_request())
    second = adapter.admit(_request())
    assert second.admission.disposition is AdmissionDisposition.DUPLICATE
    assert second.admission.run_id == first.admission.run_id


def test_conflicting_delivery_reuse_is_rejected() -> None:
    adapter, _ = _adapter()
    adapter.admit(_request())
    with pytest.raises(GitlabCIError) as error:
        adapter.admit(_request(identity=_identity(head_sha=OTHER_HEAD)))
    assert error.value.code is GitlabCIErrorCode.STATE_REJECTED


@pytest.mark.parametrize(
    "resolver",
    [_BrokenHead(), _Head("not-a-sha"), _Head("A" * 40)],
)
def test_unusable_head_is_reported_as_head_unavailable(resolver: object) -> None:
    adapter = GitlabCIAdapter(run_state=SCMRunState(), head_resolver=resolver)
    with pytest.raises(GitlabCIError) as error:
        adapter.admit(_request())
    assert error.value.code is GitlabCIErrorCode.HEAD_UNAVAILABLE


def test_authorize_publication_requires_known_run() -> None:
    adapter, _ = _adapter()
    with pytest.raises(GitlabCIError) as error:
        adapter.authorize_publication("run-unknown")
    assert error.value.code is GitlabCIErrorCode.RUN_UNKNOWN


def test_authorize_publication_returns_authorized_head() -> None:
    adapter, _ = _adapter()
    run_id = adapter.admit(_request()).admission.run_id
    publication = adapter.authorize_publication(run_id)
    assert publication.disposition is PublicationDisposition.AUTHORIZED
    assert publication.head_sha == HEAD


# --- completion projections ---------------------------------------------------


@pytest.mark.parametrize(
    ("outcome", "conclusion", "exit_code"),
    [
        (AuditRunOutcome.PASS, GitlabJobConclusion.SUCCESS, 0),
        (AuditRunOutcome.FAIL, GitlabJobConclusion.FAILED, 1),
        (AuditRunOutcome.INDETERMINATE, GitlabJobConclusion.ERROR, 2),
        (AuditRunOutcome.ERROR, GitlabJobConclusion.ERROR, 2),
        (AuditRunOutcome.CANCELLED, GitlabJobConclusion.CANCELLED, 3),
    ],
)
def test_completion_maps_outcome_to_nonzero_job_exit(
    outcome: AuditRunOutcome, conclusion: GitlabJobConclusion, exit_code: int
) -> None:
    adapter, _ = _adapter()
    run_id = adapter.admit(_request()).admission.run_id
    receipt = adapter.complete(run_id, outcome)
    assert receipt.job.conclusion is conclusion
    assert receipt.job.exit_code == exit_code
    assert receipt.job.publish is True
    assert receipt.job.head_sha == HEAD
    assert receipt.external_status is None


def test_completion_after_head_moved_is_superseded_and_unpublished() -> None:
    head = _Head(HEAD)
    adapter, _ = _adapter(resolver=head)
    run_id = adapter.admit(_request()).admission.run_id
    head.sha = OTHER_HEAD
    receipt = adapter.complete(run_id, AuditRunOutcome.PASS)
    assert receipt.job.conclusion is GitlabJobConclusion.SUPERSEDED
    assert receipt.job.exit_code == 4
    assert receipt.job.publish is False
    assert receipt.job.safe_summary == "SecureCode AI result belongs to an older commit"


def test_repeated_identical_completion_is_duplicate_but_still_publishable() -> None:
    adapter, _ = _adapter()
    run_id = adapter.admit(_request()).admission.run_id
    adapter.complete(run_id, AuditRunOutcome.PASS)
    second = adapter.complete(run_id, AuditRunOutcome.PASS)
    assert second.publication.disposition is PublicationDisposition.DUPLICATE
    assert second.job.conclusion is GitlabJobConclusion.SUCCESS
    assert second.job.publish is True


def test_conflicting_repeat_completion_is_rejected() -> None:
    adapter, _ = _adapter()
    run_id = adapter.admit(_request()).admission.run_id
    adapter.complete(run_id, AuditRunOutcome.PASS)
    with pytest.raises(GitlabCIError) as error:
        adapter.complete(run_id, AuditRunOutcome.FAIL)
    assert error.value.code is GitlabCIErrorCode.STATE_REJECTED


def test_superseded_outcome_is_rejected_by_state() -> None:
    adapter, _ = _adapter()
    run_id = adapter.admit(_request()).admission.run_id
    with pytest.raises(GitlabCIError) as error:
        adapter.complete(run_id, AuditRunOutcome.SUPERSEDED)
    assert error.value.code is GitlabCIErrorCode.STATE_REJECTED


def test_completion_rejects_unknown_run_and_bad_arguments() -> None:
    adapter, _ = _adapter()
    with pytest.raises(GitlabCIError) as error:
        adapter.complete("run-unknown", AuditRunOutcome.PASS)
    assert error.value.code is GitlabCIErrorCode.RUN_UNKNOWN
    run_id = adapter.admit(_request()).admission.run_id
    with pytest.raises(GitlabCIError) as error:
        adapter.complete(run_id, "PASS")  # type: ignore[arg-type]
    assert error.value.code is GitlabCIErrorCode.INVALID_REQUEST
    with pytest.raises(GitlabCIError) as error:
        adapter.complete(run_id, AuditRunOutcome.PASS, external_status_enabled="yes")  # type: ignore[arg-type]
    assert error.value.code is GitlabCIErrorCode.INVALID_REQUEST


def test_authorize_after_completion_is_rejected() -> None:
    adapter, _ = _adapter()
    run_id = adapter.admit(_request()).admission.run_id
    adapter.complete(run_id, AuditRunOutcome.PASS)
    with pytest.raises(GitlabCIError) as error:
        adapter.authorize_publication(run_id)
    assert error.value.code is GitlabCIErrorCode.STATE_REJECTED


# --- external status stays advisory until calibration -------------------------


def test_external_status_is_advisory_by_default() -> None:
    adapter, _ = _adapter()
    run_id = adapter.admit(_request()).admission.run_id
    receipt = adapter.complete(run_id, AuditRunOutcome.PASS, external_status_enabled=True)
    status = receipt.external_status
    assert status is not None
    assert status.status is GitlabExternalStatus.PASSED
    assert status.publish is True
    assert status.merge_authority is False
    assert status.safe_summary == "SecureCode AI passed"


def test_external_status_gains_merge_authority_only_when_calibrated() -> None:
    adapter, _ = _adapter()
    run_id = adapter.admit(_request()).admission.run_id
    receipt = adapter.complete(
        run_id,
        AuditRunOutcome.PASS,
        external_status_enabled=True,
        blocking_calibrated=True,
    )
    status = receipt.external_status
    assert status is not None
    assert status.merge_authority is True


@pytest.mark.parametrize(
    "outcome", [AuditRunOutcome.FAIL, AuditRunOutcome.INDETERMINATE, AuditRunOutcome.ERROR]
)
def test_non_pass_external_status_fails_and_never_authorizes_merge(
    outcome: AuditRunOutcome,
) -> None:
    adapter, _ = _adapter()
    run_id = adapter.admit(_request()).admission.run_id
    receipt = adapter.complete(
        run_id,
        outcome,
        external_status_enabled=True,
        blocking_calibrated=True,
    )
    status = receipt.external_status
    assert status is not None
    assert status.status is GitlabExternalStatus.FAILED
    assert status.merge_authority is True
    assert status.safe_summary == "SecureCode AI did not pass"


def test_superseded_completion_publishes_nothing() -> None:
    head = _Head(HEAD)
    adapter, _ = _adapter(resolver=head)
    run_id = adapter.admit(_request()).admission.run_id
    head.sha = OTHER_HEAD
    receipt = adapter.complete(
        run_id,
        AuditRunOutcome.PASS,
        external_status_enabled=True,
        blocking_calibrated=True,
    )
    status = receipt.external_status
    assert status is not None
    assert status.status is GitlabExternalStatus.FAILED
    assert status.publish is False
    assert status.merge_authority is False


def test_projection_keys_are_deterministic_and_run_scoped() -> None:
    first_adapter, _ = _adapter()
    first_run = first_adapter.admit(_request()).admission.run_id
    first = first_adapter.complete(first_run, AuditRunOutcome.PASS, external_status_enabled=True)

    second_adapter, _ = _adapter()
    second_run = second_adapter.admit(_request()).admission.run_id
    second = second_adapter.complete(second_run, AuditRunOutcome.PASS, external_status_enabled=True)

    assert first_run == second_run
    assert first.job.idempotency_key == second.job.idempotency_key
    assert first.job.idempotency_key.startswith("gitlab-")
    assert first.external_status is not None and second.external_status is not None
    assert first.external_status.idempotency_key == second.external_status.idempotency_key
    assert first.job.idempotency_key != first.external_status.idempotency_key

    other_head = _Head(OTHER_HEAD)
    other_adapter, _ = _adapter(resolver=other_head)
    other_run = other_adapter.admit(
        _request(identity=_identity(head_sha=OTHER_HEAD))
    ).admission.run_id
    other = other_adapter.complete(other_run, AuditRunOutcome.PASS)
    assert other_run != first_run
    assert other.job.idempotency_key != first.job.idempotency_key


# --- crash-recovery binding restoration --------------------------------------


def test_restore_requires_provider_target_capability() -> None:
    adapter = GitlabCIAdapter(run_state=SCMRunState(), head_resolver=_Head())
    with pytest.raises(GitlabCIError) as error:
        adapter.complete("run-1", AuditRunOutcome.PASS)
    assert error.value.code is GitlabCIErrorCode.RUN_UNKNOWN


@pytest.mark.parametrize(
    "target",
    [
        _ProviderTarget(provider="github"),
        _ProviderTarget(installation_id="999", repository_id=PROJECT),
        _ProviderTarget(repository_id="not valid!"),
        _ProviderTarget(change_id=""),
        _ProviderTarget(execution_identity_hash="short"),
        _ProviderTarget(execution_identity_hash="A" * 64),
        RuntimeError("store offline"),
    ],
)
def test_restore_rejects_invalid_provider_targets(target: object) -> None:
    state = _RestoringState(target)
    adapter = GitlabCIAdapter(run_state=state, head_resolver=_Head())
    with pytest.raises(GitlabCIError) as error:
        adapter.complete("run-1", AuditRunOutcome.PASS)
    assert error.value.code in {
        GitlabCIErrorCode.STATE_REJECTED,
        GitlabCIErrorCode.RUN_UNKNOWN,
    }


def test_restored_binding_drives_completion_for_durable_state() -> None:
    identity = _identity()
    inner = SCMRunState()
    admission = inner.admit(
        SCMRunAdmissionRequest(
            delivery_id="gl-9001-1",
            installation_id=f"gitlab:{PROJECT}:mr:{MR}",
            execution_identity=identity,
            authorized_head_sha=HEAD,
        ),
        current_head_sha=HEAD,
    )
    state = _RestoringState(
        _ProviderTarget(execution_identity_hash=identity.execution_identity_hash), inner
    )
    adapter = GitlabCIAdapter(run_state=state, head_resolver=_Head())
    receipt = adapter.complete(admission.run_id, AuditRunOutcome.PASS)
    assert receipt.publication.disposition is PublicationDisposition.COMPLETED
    assert receipt.job.conclusion is GitlabJobConclusion.SUCCESS
    assert state.calls == [("provider_target", admission.run_id)]


def test_restore_uses_target_for_head_read() -> None:
    """A restored binding reaches the state port; state errors surface as STATE_REJECTED."""

    state = _RestoringState(_ProviderTarget())
    adapter = GitlabCIAdapter(run_state=state, head_resolver=_Head())
    with pytest.raises(GitlabCIError) as error:
        adapter.authorize_publication("run-1")
    assert error.value.code is GitlabCIErrorCode.STATE_REJECTED
    assert state.calls == [("provider_target", "run-1")]


def test_restore_rejects_unknown_run_state_error() -> None:
    from securecode_ai.core.scm_run_state import SCMRunStateError, SCMRunStateErrorCode

    state = _RestoringState(SCMRunStateError(SCMRunStateErrorCode.RUN_UNKNOWN))
    adapter = GitlabCIAdapter(run_state=state, head_resolver=_Head())
    with pytest.raises(GitlabCIError) as error:
        adapter.complete("run-1", AuditRunOutcome.PASS)
    assert error.value.code is GitlabCIErrorCode.RUN_UNKNOWN
