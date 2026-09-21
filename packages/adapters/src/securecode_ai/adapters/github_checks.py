"""SHA-bound advisory GitHub Check projections with fail-closed outcome mapping."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final

from securecode_ai.contracts import AuditRun, AuditRunOutcome
from securecode_ai.core.scm_run_state import PublicationDisposition, SCMRunPublicationReceipt

from .github_app import GithubAppAdapter, GithubAppError

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/github-check/v1\x00"


class GithubCheckConclusion(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    ACTION_REQUIRED = "action_required"
    CANCELLED = "cancelled"


class GithubCheckReason(StrEnum):
    NONE = "NONE"
    MANDATORY_COVERAGE_INCOMPLETE = "MANDATORY_COVERAGE_INCOMPLETE"
    PROVIDER_MODEL_FAILURE = "PROVIDER_MODEL_FAILURE"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    CANCELLED = "CANCELLED"


class GithubCheckDisposition(StrEnum):
    CREATED = "CREATED"
    IDEMPOTENT = "IDEMPOTENT"
    UPDATED = "UPDATED"
    SUPERSEDED = "SUPERSEDED"


class GithubCheckError(ValueError):
    """Safe check-projection rejection without raw analysis material."""

    def __init__(self) -> None:
        super().__init__("GitHub check projection was rejected")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GithubCheckRequest:
    """Final run metadata in the only supported pre-calibration advisory mode."""

    scm_run_id: str
    audit_run: AuditRun
    reason: GithubCheckReason = GithubCheckReason.NONE
    pre_calibration: bool = True

    def __post_init__(self) -> None:
        if (
            type(self.scm_run_id) is not str
            or _ID.fullmatch(self.scm_run_id) is None
            or type(self.audit_run) is not AuditRun
            or type(self.reason) is not GithubCheckReason
            or self.pre_calibration is not True
            or not _reason_matches(self.audit_run.audit_outcome, self.reason)
        ):
            raise GithubCheckError()


@dataclass(frozen=True, slots=True)
class GithubCheckProjection:
    """Safe metadata-only Check Run body. It cannot act as merge authority."""

    check_idempotency_key: str
    head_sha: str
    execution_identity_hash: str
    conclusion: GithubCheckConclusion
    summary: str
    merge_authority: bool
    required_check: bool
    blocking: bool
    advisory: bool


@dataclass(frozen=True, slots=True)
class GithubCheckReceipt:
    disposition: GithubCheckDisposition
    projection: GithubCheckProjection | None
    publication: SCMRunPublicationReceipt


class GithubCheckPublisher:
    """Create one deterministic advisory check projection after fresh HEAD authorization."""

    __slots__ = ("_adapter", "_lock", "_published")

    def __init__(self, adapter: GithubAppAdapter) -> None:
        if type(adapter) is not GithubAppAdapter:
            raise GithubCheckError()
        self._adapter = adapter
        self._published: dict[str, str] = {}
        self._lock = RLock()

    def project(self, request: GithubCheckRequest) -> GithubCheckReceipt:
        if type(request) is not GithubCheckRequest:
            raise GithubCheckError()
        try:
            publication = self._adapter.authorize_publication(request.scm_run_id)
        except GithubAppError as error:
            raise GithubCheckError() from error
        if publication.disposition is PublicationDisposition.SUPERSEDED:
            return GithubCheckReceipt(GithubCheckDisposition.SUPERSEDED, None, publication)
        if publication.disposition is not PublicationDisposition.AUTHORIZED:
            raise GithubCheckError()
        if request.audit_run.audit_outcome is AuditRunOutcome.SUPERSEDED:
            return GithubCheckReceipt(GithubCheckDisposition.SUPERSEDED, None, publication)
        projection = _projection(request, publication)
        digest = _projection_digest(projection)
        with self._lock:
            previous = self._published.get(projection.check_idempotency_key)
            self._published[projection.check_idempotency_key] = digest
        disposition = (
            GithubCheckDisposition.CREATED
            if previous is None
            else GithubCheckDisposition.IDEMPOTENT
            if previous == digest
            else GithubCheckDisposition.UPDATED
        )
        return GithubCheckReceipt(disposition, projection, publication)


def _projection(
    request: GithubCheckRequest,
    publication: SCMRunPublicationReceipt,
) -> GithubCheckProjection:
    run = request.audit_run
    identity = run.execution_identity
    if (
        publication.execution_identity_hash != identity.execution_identity_hash
        or publication.head_sha != identity.repository_revision.head_sha
        or publication.current_head_sha != identity.repository_revision.head_sha
        or run.current_head_sha != identity.repository_revision.head_sha
    ):
        raise GithubCheckError()
    conclusion = _conclusion(run.audit_outcome)
    summary = _summary(run.audit_outcome, request.reason)
    if not _safe_text(summary):
        raise GithubCheckError()
    return GithubCheckProjection(
        check_idempotency_key=_idempotency_key(
            request.scm_run_id, identity.execution_identity_hash
        ),
        head_sha=identity.repository_revision.head_sha,
        execution_identity_hash=identity.execution_identity_hash,
        conclusion=conclusion,
        summary=summary,
        merge_authority=False,
        required_check=False,
        blocking=False,
        advisory=True,
    )


def _reason_matches(outcome: AuditRunOutcome, reason: GithubCheckReason) -> bool:
    if outcome is AuditRunOutcome.PASS:
        return reason is GithubCheckReason.NONE
    if outcome is AuditRunOutcome.FAIL:
        return reason is GithubCheckReason.NONE
    if outcome is AuditRunOutcome.CANCELLED:
        return reason is GithubCheckReason.CANCELLED
    if outcome is AuditRunOutcome.ERROR:
        return reason in {
            GithubCheckReason.EXECUTION_ERROR,
            GithubCheckReason.PROVIDER_MODEL_FAILURE,
        }
    if outcome is AuditRunOutcome.INDETERMINATE:
        return reason in {
            GithubCheckReason.MANDATORY_COVERAGE_INCOMPLETE,
            GithubCheckReason.PROVIDER_MODEL_FAILURE,
        }
    return outcome is AuditRunOutcome.SUPERSEDED and reason is GithubCheckReason.NONE


def _conclusion(outcome: AuditRunOutcome) -> GithubCheckConclusion:
    mapping = {
        AuditRunOutcome.PASS: GithubCheckConclusion.SUCCESS,
        AuditRunOutcome.FAIL: GithubCheckConclusion.FAILURE,
        AuditRunOutcome.INDETERMINATE: GithubCheckConclusion.ACTION_REQUIRED,
        AuditRunOutcome.ERROR: GithubCheckConclusion.ACTION_REQUIRED,
        AuditRunOutcome.CANCELLED: GithubCheckConclusion.CANCELLED,
    }
    try:
        return mapping[outcome]
    except KeyError as error:
        raise GithubCheckError() from error


def _summary(outcome: AuditRunOutcome, reason: GithubCheckReason) -> str:
    if outcome is AuditRunOutcome.PASS:
        return "SecureCode completed mandatory coverage. Advisory check only."
    if outcome is AuditRunOutcome.FAIL:
        return "SecureCode found confirmed blocking findings. Advisory check only."
    if reason is GithubCheckReason.MANDATORY_COVERAGE_INCOMPLETE:
        return "SecureCode mandatory coverage is incomplete. This is not a clean result."
    if reason is GithubCheckReason.PROVIDER_MODEL_FAILURE:
        return "SecureCode provider or model analysis failed. This is not a clean result."
    if reason is GithubCheckReason.CANCELLED:
        return "SecureCode analysis was cancelled. This is not a clean result."
    return "SecureCode execution failed. This is not a clean result."


def _idempotency_key(scm_run_id: str, execution_identity_hash: str) -> str:
    if _SHA256.fullmatch(execution_identity_hash) is None:
        raise GithubCheckError()
    material = json.dumps(
        {"execution_identity_hash": execution_identity_hash, "scm_run_id": scm_run_id},
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "check-" + hashlib.sha256(_HASH_DOMAIN + material).hexdigest()[:40]


def _projection_digest(projection: GithubCheckProjection) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "conclusion": projection.conclusion.value,
                "head_sha": projection.head_sha,
                "summary": projection.summary,
            },
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


def _safe_text(value: object) -> bool:
    return (
        type(value) is str
        and len(value) <= 512
        and value.isascii()
        and all(32 <= ord(character) <= 126 for character in value)
    )


__all__ = [
    "GithubCheckConclusion",
    "GithubCheckDisposition",
    "GithubCheckError",
    "GithubCheckProjection",
    "GithubCheckPublisher",
    "GithubCheckReason",
    "GithubCheckReceipt",
    "GithubCheckRequest",
]
