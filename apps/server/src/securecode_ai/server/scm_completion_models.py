"""Source-free contracts for terminal SCM publication."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from securecode_ai.adapters.gitlab_ci import (
    GitlabExternalStatus,
    GitlabExternalStatusProjection,
)
from securecode_ai.adapters.gitlab_writer import GitlabWriteTarget
from securecode_ai.contracts import AuditRunOutcome
from securecode_ai.core.scm_run_state import SCMRunPublicationReceipt

from .scm_publication_store import SCMPublicationTarget

_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/scm-completion/v1\x00"


class SCMCompletionDisposition(StrEnum):
    """Safe terminal state visible to the worker-completion wrapper."""

    NOT_BOUND = "NOT_BOUND"
    PUBLISHED = "PUBLISHED"
    STALE = "STALE"
    REPLAYED = "REPLAYED"


class SCMCompletionError(RuntimeError):
    """Bounded publication failure without provider data or credentials."""


@dataclass(frozen=True, slots=True)
class SCMCompletionReceipt:
    run_id: str
    disposition: SCMCompletionDisposition
    outcome: AuditRunOutcome | None
    receipt_id: str | None


class SCMPublicationStorePort(Protocol):
    def bind(self, target: SCMPublicationTarget) -> None: ...

    def load(self, *, tenant_id: str, run_id: str) -> SCMPublicationTarget | None: ...

    def record(
        self,
        *,
        target: SCMPublicationTarget,
        outcome: str,
        stale: bool,
        receipt_id: str,
    ) -> SCMPublicationTarget: ...


class SCMRunStateCompletionPort(Protocol):
    def provider_target(self, run_id: str) -> object: ...

    def authorize_publication(
        self, run_id: str, *, current_head_sha: str
    ) -> SCMRunPublicationReceipt: ...

    def complete(
        self,
        run_id: str,
        outcome: AuditRunOutcome,
        *,
        current_head_sha: str,
    ) -> SCMRunPublicationReceipt: ...


class GitHubCheckWriterPort(Protocol):
    def write_pull_request_check(
        self,
        *,
        installation_id: str,
        repository_id: str,
        change_id: str,
        expected_head: str,
        external_id: str,
        projection: dict[str, object],
        delivery_key: str,
    ) -> object: ...


class GitlabStatusWriterPort(Protocol):
    def publish_external_status(
        self,
        target: GitlabWriteTarget,
        projection: GitlabExternalStatusProjection,
    ) -> object: ...


GithubHeadResolver = Callable[[str, str, str], str]
GitlabHeadResolver = Callable[[str, str], str]


def audit_outcome(worker_outcome: object) -> AuditRunOutcome:
    """Map the closed worker vocabulary to the domain enum."""

    if type(worker_outcome) is not str:
        raise SCMCompletionError("SCM completion outcome is invalid")
    try:
        outcome = AuditRunOutcome(worker_outcome)
    except ValueError:
        raise SCMCompletionError("SCM completion outcome is invalid") from None
    if outcome is AuditRunOutcome.ERROR:
        raise SCMCompletionError("SCM completion outcome is invalid")
    return outcome


def receipt_id(target: SCMPublicationTarget) -> str:
    return (
        "scm-"
        + _digest(
            {
                "execution_identity_hash": target.execution_identity_hash,
                "head_sha": target.head_sha,
                "provider": target.provider,
                "run_id": target.run_id,
            }
        )[:40]
    )


def github_projection(
    target: SCMPublicationTarget,
    outcome: AuditRunOutcome,
) -> dict[str, object]:
    conclusion = {
        AuditRunOutcome.PASS: "success",
        AuditRunOutcome.FAIL: "failure",
        AuditRunOutcome.INDETERMINATE: "action_required",
        AuditRunOutcome.CANCELLED: "cancelled",
    }.get(outcome)
    if conclusion is None:
        raise SCMCompletionError("SCM completion outcome is invalid")
    return {
        "conclusion": conclusion,
        "output": {
            "title": "SecureCode AI",
            "summary": _summary(outcome),
        },
    }


def gitlab_projection(
    target: SCMPublicationTarget,
    outcome: AuditRunOutcome,
) -> GitlabExternalStatusProjection:
    if outcome is AuditRunOutcome.SUPERSEDED:
        raise SCMCompletionError("SCM completion outcome is invalid")
    passed = outcome is AuditRunOutcome.PASS
    return GitlabExternalStatusProjection(
        idempotency_key="gitlab-status-"
        + _digest(
            {
                "execution_identity_hash": target.execution_identity_hash,
                "head_sha": target.head_sha,
                "run_id": target.run_id,
            }
        )[:40],
        execution_identity_hash=target.execution_identity_hash,
        head_sha=target.head_sha,
        status=(GitlabExternalStatus.PASSED if passed else GitlabExternalStatus.FAILED),
        publish=True,
        merge_authority=False,
        safe_summary=_summary(outcome),
    )


def gitlab_target(target: SCMPublicationTarget) -> GitlabWriteTarget:
    return GitlabWriteTarget(
        project_id=target.repository_id,
        merge_request_iid=target.change_id,
        expected_head_sha=target.head_sha,
    )


def validate_head(value: object) -> str:
    if type(value) is not str or _COMMIT_SHA.fullmatch(value) is None:
        raise SCMCompletionError("SCM current head is unavailable")
    return value


def _summary(outcome: AuditRunOutcome) -> str:
    return {
        AuditRunOutcome.PASS: "SecureCode AI completed mandatory coverage. Advisory only.",
        AuditRunOutcome.FAIL: "SecureCode AI found blocking findings. Advisory only.",
        AuditRunOutcome.INDETERMINATE: (
            "SecureCode AI mandatory analysis was incomplete. Advisory only."
        ),
        AuditRunOutcome.CANCELLED: ("SecureCode AI analysis was cancelled. Advisory only."),
    }[outcome]


def _digest(value: dict[str, str]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(_HASH_DOMAIN + encoded).hexdigest()


__all__ = [
    "GitHubCheckWriterPort",
    "GithubHeadResolver",
    "GitlabHeadResolver",
    "GitlabStatusWriterPort",
    "SCMCompletionDisposition",
    "SCMCompletionError",
    "SCMCompletionReceipt",
    "SCMPublicationStorePort",
    "SCMRunStateCompletionPort",
    "audit_outcome",
    "github_projection",
    "gitlab_projection",
    "gitlab_target",
    "receipt_id",
    "validate_head",
]
