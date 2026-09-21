"""GitLab CI admission and exact-revision publication projections.

The adapter is transport-neutral. It consumes already authenticated GitLab CI
metadata, obtains the current merge-request head through an injected trusted
resolver, and delegates lifecycle decisions to the common SCM run state.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final, Protocol, TypeGuard, cast

from securecode_ai.contracts import AuditRunOutcome, RunExecutionIdentity
from securecode_ai.core.scm_run_state import (
    AdmissionDisposition,
    PublicationDisposition,
    SCMRunAdmissionReceipt,
    SCMRunAdmissionRequest,
    SCMRunPublicationReceipt,
    SCMRunStateError,
    SCMRunStateErrorCode,
)

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/gitlab-ci/v1\x00"


class GitlabCIErrorCode(StrEnum):
    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    INVALID_REQUEST = "INVALID_REQUEST"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    HEAD_UNAVAILABLE = "HEAD_UNAVAILABLE"
    STATE_REJECTED = "STATE_REJECTED"
    RUN_UNKNOWN = "RUN_UNKNOWN"


class GitlabCIError(ValueError):
    """Bounded error that excludes source, tokens, and raw GitLab responses."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GitlabCIErrorCode) -> None:
        if type(code) is not GitlabCIErrorCode:
            raise TypeError("GitLab CI error code is invalid")
        self.code = code
        self.safe_message = "GitLab CI request was rejected"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class GitlabContributionTrust(StrEnum):
    TRUSTED = "TRUSTED"
    UNTRUSTED_FORK = "UNTRUSTED_FORK"


class GitlabJobConclusion(StrEnum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    ERROR = "ERROR"
    CANCELLED = "CANCELLED"
    SUPERSEDED = "SUPERSEDED"


class GitlabExternalStatus(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class GitlabCIAdmissionRequest:
    """Trusted CI metadata for one merge-request pipeline execution."""

    pipeline_id: str
    job_id: str
    project_id: str
    merge_request_iid: str
    source_project_id: str
    target_project_id: str
    contribution_trust: GitlabContributionTrust
    execution_identity: RunExecutionIdentity

    def __post_init__(self) -> None:
        identifiers = (
            self.pipeline_id,
            self.job_id,
            self.project_id,
            self.merge_request_iid,
            self.source_project_id,
            self.target_project_id,
        )
        if (
            any(type(value) is not str or _ID.fullmatch(value) is None for value in identifiers)
            or type(self.contribution_trust) is not GitlabContributionTrust
            or type(self.execution_identity) is not RunExecutionIdentity
            or self.project_id != self.target_project_id
            or self.execution_identity.repository_revision.repository_id != self.target_project_id
        ):
            raise GitlabCIError(GitlabCIErrorCode.INVALID_REQUEST)
        expected_trust = (
            GitlabContributionTrust.TRUSTED
            if self.source_project_id == self.target_project_id
            else GitlabContributionTrust.UNTRUSTED_FORK
        )
        if self.contribution_trust is not expected_trust:
            raise GitlabCIError(GitlabCIErrorCode.IDENTITY_MISMATCH)


@dataclass(frozen=True, slots=True)
class GitlabCIExecutionPolicy:
    """Credentials that may be exposed to the repository-controlled job."""

    contribution_trust: GitlabContributionTrust
    allow_repository_read_credential: bool
    allow_scm_write_credential: bool
    allow_backend_credential: bool
    allow_provider_credential: bool


@dataclass(frozen=True, slots=True)
class GitlabCIAdmissionReceipt:
    project_id: str
    merge_request_iid: str
    head_sha: str
    execution_policy: GitlabCIExecutionPolicy
    admission: SCMRunAdmissionReceipt


@dataclass(frozen=True, slots=True)
class GitlabCIJobProjection:
    """Universal GitLab CI result. Nonzero is required for every non-pass."""

    idempotency_key: str
    execution_identity_hash: str
    head_sha: str
    conclusion: GitlabJobConclusion
    exit_code: int
    publish: bool
    safe_summary: str


@dataclass(frozen=True, slots=True)
class GitlabExternalStatusProjection:
    """Optional tier-dependent status-check response bound to exact HEAD."""

    idempotency_key: str
    execution_identity_hash: str
    head_sha: str
    status: GitlabExternalStatus
    publish: bool
    merge_authority: bool
    safe_summary: str


@dataclass(frozen=True, slots=True)
class GitlabCICompletionReceipt:
    publication: SCMRunPublicationReceipt
    job: GitlabCIJobProjection
    external_status: GitlabExternalStatusProjection | None


@dataclass(frozen=True, slots=True)
class _RunBinding:
    project_id: str
    merge_request_iid: str
    execution_identity_hash: str


class _SCMRunStatePort(Protocol):
    def admit(
        self,
        request: SCMRunAdmissionRequest,
        *,
        current_head_sha: str,
    ) -> SCMRunAdmissionReceipt: ...

    def authorize_publication(
        self,
        run_id: str,
        *,
        current_head_sha: str,
    ) -> SCMRunPublicationReceipt: ...

    def complete(
        self,
        run_id: str,
        outcome: AuditRunOutcome,
        *,
        current_head_sha: str,
    ) -> SCMRunPublicationReceipt: ...


TrustedGitlabHeadResolver = Callable[[str, str], str]


class GitlabCIAdapter:
    """Admit GitLab CI runs and project exact-head completion projections."""

    __slots__ = ("_bindings", "_head_resolver", "_lock", "_run_state")

    def __init__(self, *, run_state: object, head_resolver: object) -> None:
        if not _is_run_state(run_state) or not callable(head_resolver):
            raise GitlabCIError(GitlabCIErrorCode.INVALID_CONFIGURATION)
        self._run_state = run_state
        self._head_resolver = cast(TrustedGitlabHeadResolver, head_resolver)
        self._bindings: dict[str, _RunBinding] = {}
        self._lock = RLock()

    def admit(self, request: GitlabCIAdmissionRequest) -> GitlabCIAdmissionReceipt:
        if type(request) is not GitlabCIAdmissionRequest:
            raise GitlabCIError(GitlabCIErrorCode.INVALID_REQUEST)
        identity = request.execution_identity
        revision = identity.repository_revision
        current_head_sha = self._current_head(request.project_id, request.merge_request_iid)
        delivery_id = f"gl-{request.pipeline_id}-{request.job_id}"
        try:
            admission = self._run_state.admit(
                SCMRunAdmissionRequest(
                    delivery_id=delivery_id,
                    installation_id=(f"gitlab:{request.project_id}:mr:{request.merge_request_iid}"),
                    execution_identity=identity,
                    authorized_head_sha=revision.head_sha,
                ),
                current_head_sha=current_head_sha,
            )
        except SCMRunStateError as error:
            raise GitlabCIError(GitlabCIErrorCode.STATE_REJECTED) from error
        if admission.disposition is not AdmissionDisposition.SUPERSEDED:
            with self._lock:
                self._bindings[admission.run_id] = _RunBinding(
                    project_id=request.project_id,
                    merge_request_iid=request.merge_request_iid,
                    execution_identity_hash=identity.execution_identity_hash,
                )
        return GitlabCIAdmissionReceipt(
            project_id=request.project_id,
            merge_request_iid=request.merge_request_iid,
            head_sha=revision.head_sha,
            execution_policy=_execution_policy(request.contribution_trust),
            admission=admission,
        )

    def authorize_publication(self, run_id: str) -> SCMRunPublicationReceipt:
        binding = self._binding(run_id)
        current_head_sha = self._current_head(binding.project_id, binding.merge_request_iid)
        try:
            return self._run_state.authorize_publication(
                run_id,
                current_head_sha=current_head_sha,
            )
        except SCMRunStateError as error:
            raise GitlabCIError(GitlabCIErrorCode.STATE_REJECTED) from error

    def complete(
        self,
        run_id: str,
        outcome: AuditRunOutcome,
        *,
        external_status_enabled: bool = False,
        blocking_calibrated: bool = False,
    ) -> GitlabCICompletionReceipt:
        if (
            type(outcome) is not AuditRunOutcome
            or type(external_status_enabled) is not bool
            or type(blocking_calibrated) is not bool
        ):
            raise GitlabCIError(GitlabCIErrorCode.INVALID_REQUEST)
        binding = self._binding(run_id)
        current_head_sha = self._current_head(binding.project_id, binding.merge_request_iid)
        try:
            publication = self._run_state.complete(
                run_id,
                outcome,
                current_head_sha=current_head_sha,
            )
        except SCMRunStateError as error:
            raise GitlabCIError(GitlabCIErrorCode.STATE_REJECTED) from error
        job = _job_projection(run_id, binding, publication)
        external_status = (
            _external_status_projection(
                run_id,
                binding,
                publication,
                blocking_calibrated=blocking_calibrated,
            )
            if external_status_enabled
            else None
        )
        return GitlabCICompletionReceipt(
            publication=publication,
            job=job,
            external_status=external_status,
        )

    def _binding(self, run_id: str) -> _RunBinding:
        if type(run_id) is not str or _ID.fullmatch(run_id) is None:
            raise GitlabCIError(GitlabCIErrorCode.RUN_UNKNOWN)
        with self._lock:
            binding = self._bindings.get(run_id)
        if binding is not None:
            return binding
        binding = self._restore_binding(run_id)
        with self._lock:
            return self._bindings.setdefault(run_id, binding)

    def _restore_binding(self, run_id: str) -> _RunBinding:
        provider_target = getattr(self._run_state, "provider_target", None)
        if not callable(provider_target):
            raise GitlabCIError(GitlabCIErrorCode.RUN_UNKNOWN)
        try:
            target = provider_target(run_id)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except SCMRunStateError as error:
            code = (
                GitlabCIErrorCode.RUN_UNKNOWN
                if error.code is SCMRunStateErrorCode.RUN_UNKNOWN
                else GitlabCIErrorCode.STATE_REJECTED
            )
            raise GitlabCIError(code) from error
        except Exception as error:
            raise GitlabCIError(GitlabCIErrorCode.STATE_REJECTED) from error
        provider = getattr(target, "provider", None)
        installation_id = getattr(target, "installation_id", None)
        repository_id = getattr(target, "repository_id", None)
        change_id = getattr(target, "change_id", None)
        execution_identity_hash = getattr(target, "execution_identity_hash", None)
        if (
            provider != "gitlab"
            or type(installation_id) is not str
            or _ID.fullmatch(installation_id) is None
            or type(repository_id) is not str
            or _ID.fullmatch(repository_id) is None
            or installation_id != repository_id
            or type(change_id) is not str
            or _ID.fullmatch(change_id) is None
            or type(execution_identity_hash) is not str
            or _SHA256.fullmatch(execution_identity_hash) is None
        ):
            raise GitlabCIError(GitlabCIErrorCode.STATE_REJECTED)
        return _RunBinding(
            project_id=repository_id,
            merge_request_iid=change_id,
            execution_identity_hash=execution_identity_hash,
        )

    def _current_head(self, project_id: str, merge_request_iid: str) -> str:
        try:
            head_sha = self._head_resolver(project_id, merge_request_iid)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception as error:
            raise GitlabCIError(GitlabCIErrorCode.HEAD_UNAVAILABLE) from error
        if type(head_sha) is not str or _COMMIT_SHA.fullmatch(head_sha) is None:
            raise GitlabCIError(GitlabCIErrorCode.HEAD_UNAVAILABLE)
        return head_sha


def _is_run_state(value: object) -> TypeGuard[_SCMRunStatePort]:
    return all(
        callable(getattr(value, method, None))
        for method in ("admit", "authorize_publication", "complete")
    )


def _execution_policy(trust: GitlabContributionTrust) -> GitlabCIExecutionPolicy:
    if trust is GitlabContributionTrust.UNTRUSTED_FORK:
        return GitlabCIExecutionPolicy(
            contribution_trust=trust,
            allow_repository_read_credential=False,
            allow_scm_write_credential=False,
            allow_backend_credential=False,
            allow_provider_credential=False,
        )
    return GitlabCIExecutionPolicy(
        contribution_trust=trust,
        allow_repository_read_credential=True,
        allow_scm_write_credential=False,
        allow_backend_credential=False,
        allow_provider_credential=False,
    )


def _job_projection(
    run_id: str,
    binding: _RunBinding,
    publication: SCMRunPublicationReceipt,
) -> GitlabCIJobProjection:
    _validate_publication(binding, publication)
    if publication.disposition is PublicationDisposition.SUPERSEDED:
        conclusion = GitlabJobConclusion.SUPERSEDED
        exit_code = 4
        publish = False
    else:
        conclusion, exit_code = _job_outcome(publication.outcome)
        publish = True
    return GitlabCIJobProjection(
        idempotency_key=_idempotency_key("job", run_id, binding.execution_identity_hash),
        execution_identity_hash=binding.execution_identity_hash,
        head_sha=publication.head_sha,
        conclusion=conclusion,
        exit_code=exit_code,
        publish=publish,
        safe_summary=_summary(conclusion),
    )


def _external_status_projection(
    run_id: str,
    binding: _RunBinding,
    publication: SCMRunPublicationReceipt,
    *,
    blocking_calibrated: bool,
) -> GitlabExternalStatusProjection:
    _validate_publication(binding, publication)
    superseded = publication.disposition is PublicationDisposition.SUPERSEDED
    passed = publication.outcome is AuditRunOutcome.PASS and not superseded
    status = GitlabExternalStatus.PASSED if passed else GitlabExternalStatus.FAILED
    return GitlabExternalStatusProjection(
        idempotency_key=_idempotency_key(
            "external-status", run_id, binding.execution_identity_hash
        ),
        execution_identity_hash=binding.execution_identity_hash,
        head_sha=publication.head_sha,
        status=status,
        publish=not superseded,
        merge_authority=blocking_calibrated and not superseded,
        safe_summary="SecureCode AI passed" if passed else "SecureCode AI did not pass",
    )


def _validate_publication(
    binding: _RunBinding,
    publication: SCMRunPublicationReceipt,
) -> None:
    if (
        type(publication) is not SCMRunPublicationReceipt
        or publication.execution_identity_hash != binding.execution_identity_hash
        or publication.disposition
        not in {
            PublicationDisposition.COMPLETED,
            PublicationDisposition.DUPLICATE,
            PublicationDisposition.SUPERSEDED,
        }
        or (
            publication.disposition is not PublicationDisposition.SUPERSEDED
            and publication.current_head_sha != publication.head_sha
        )
    ):
        raise GitlabCIError(GitlabCIErrorCode.IDENTITY_MISMATCH)


def _job_outcome(outcome: AuditRunOutcome | None) -> tuple[GitlabJobConclusion, int]:
    mapping = {
        AuditRunOutcome.PASS: (GitlabJobConclusion.SUCCESS, 0),
        AuditRunOutcome.FAIL: (GitlabJobConclusion.FAILED, 1),
        AuditRunOutcome.INDETERMINATE: (GitlabJobConclusion.ERROR, 2),
        AuditRunOutcome.ERROR: (GitlabJobConclusion.ERROR, 2),
        AuditRunOutcome.CANCELLED: (GitlabJobConclusion.CANCELLED, 3),
    }
    if outcome is None:
        raise GitlabCIError(GitlabCIErrorCode.IDENTITY_MISMATCH)
    return mapping[outcome]


def _summary(conclusion: GitlabJobConclusion) -> str:
    return {
        GitlabJobConclusion.SUCCESS: "SecureCode AI completed successfully",
        GitlabJobConclusion.FAILED: "SecureCode AI found blocking findings",
        GitlabJobConclusion.ERROR: "SecureCode AI could not complete mandatory analysis",
        GitlabJobConclusion.CANCELLED: "SecureCode AI analysis was cancelled",
        GitlabJobConclusion.SUPERSEDED: "SecureCode AI result belongs to an older commit",
    }[conclusion]


def _idempotency_key(kind: str, run_id: str, execution_identity_hash: str) -> str:
    material = json.dumps(
        {
            "execution_identity_hash": execution_identity_hash,
            "kind": kind,
            "run_id": run_id,
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "gitlab-" + hashlib.sha256(_HASH_DOMAIN + material).hexdigest()[:40]


__all__ = [
    "GitlabCIAdapter",
    "GitlabCIAdmissionReceipt",
    "GitlabCIAdmissionRequest",
    "GitlabCICompletionReceipt",
    "GitlabCIError",
    "GitlabCIErrorCode",
    "GitlabCIExecutionPolicy",
    "GitlabCIJobProjection",
    "GitlabContributionTrust",
    "GitlabExternalStatus",
    "GitlabExternalStatusProjection",
    "GitlabJobConclusion",
]
