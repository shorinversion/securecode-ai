"""Safe single-note summary projection for GitLab merge requests."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final, Protocol

from securecode_ai.contracts import AuditRun, AuditRunOutcome, CoverageStatus, ModelCallStatus
from securecode_ai.core.scm_run_state import PublicationDisposition, SCMRunPublicationReceipt

from .gitlab_ci import GitlabCIError

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/gitlab-summary/v1\x00"
_MAX_FAILED_UNITS: Final = 12


class GitlabSummaryErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    AUTHORIZATION_REJECTED = "AUTHORIZATION_REJECTED"
    UNSAFE_RENDER_INPUT = "UNSAFE_RENDER_INPUT"


class GitlabSummaryError(ValueError):
    __slots__ = ("code", "safe_message")

    def __init__(self, code: GitlabSummaryErrorCode) -> None:
        if type(code) is not GitlabSummaryErrorCode:
            raise TypeError("GitLab summary error code is invalid")
        self.code = code
        self.safe_message = "GitLab summary projection was rejected"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class GitlabSummaryDisposition(StrEnum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    IDEMPOTENT = "IDEMPOTENT"
    SUPERSEDED = "SUPERSEDED"


@dataclass(frozen=True, slots=True)
class GitlabSummaryRequest:
    scm_run_id: str
    audit_run: AuditRun

    def __post_init__(self) -> None:
        if (
            type(self.scm_run_id) is not str
            or _ID.fullmatch(self.scm_run_id) is None
            or type(self.audit_run) is not AuditRun
        ):
            raise GitlabSummaryError(GitlabSummaryErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class GitlabSummaryProjection:
    note_idempotency_key: str
    execution_identity_hash: str
    head_sha: str
    outcome: AuditRunOutcome
    rendered_markdown: str
    rendered_sha256: str
    merge_authority: bool = False


@dataclass(frozen=True, slots=True)
class GitlabSummaryReceipt:
    disposition: GitlabSummaryDisposition
    projection: GitlabSummaryProjection | None
    publication: SCMRunPublicationReceipt


class GitlabSummaryAuthorizer(Protocol):
    def authorize_publication(self, run_id: str) -> SCMRunPublicationReceipt: ...


class GitlabSummaryPublisher:
    """Produce one updateable MR note after a fresh exact-head check."""

    __slots__ = ("_adapter", "_lock", "_published")

    def __init__(self, adapter: GitlabSummaryAuthorizer) -> None:
        if not callable(getattr(adapter, "authorize_publication", None)):
            raise GitlabSummaryError(GitlabSummaryErrorCode.INVALID_REQUEST)
        self._adapter = adapter
        self._lock = RLock()
        self._published: dict[str, str] = {}

    def project(
        self,
        request: GitlabSummaryRequest,
        *,
        publication_receipt: SCMRunPublicationReceipt | None = None,
        publication_outcome: AuditRunOutcome | None = None,
    ) -> GitlabSummaryReceipt:
        if type(request) is not GitlabSummaryRequest:
            raise GitlabSummaryError(GitlabSummaryErrorCode.INVALID_REQUEST)
        if publication_outcome is not None and type(publication_outcome) is not AuditRunOutcome:
            raise GitlabSummaryError(GitlabSummaryErrorCode.INVALID_REQUEST)
        if publication_receipt is None:
            try:
                publication = self._adapter.authorize_publication(request.scm_run_id)
            except GitlabCIError as error:
                raise GitlabSummaryError(GitlabSummaryErrorCode.AUTHORIZATION_REJECTED) from error
        else:
            publication = publication_receipt
            identity = request.audit_run.execution_identity
            if (
                type(publication) is not SCMRunPublicationReceipt
                or publication.disposition
                not in {PublicationDisposition.COMPLETED, PublicationDisposition.DUPLICATE}
                or publication.run_id != request.scm_run_id
                or publication.execution_identity_hash != identity.execution_identity_hash
                or publication.head_sha != identity.repository_revision.head_sha
                or publication.current_head_sha != publication.head_sha
            ):
                raise GitlabSummaryError(GitlabSummaryErrorCode.AUTHORIZATION_REJECTED)
        if publication.disposition is PublicationDisposition.SUPERSEDED:
            return GitlabSummaryReceipt(
                disposition=GitlabSummaryDisposition.SUPERSEDED,
                projection=None,
                publication=publication,
            )
        if publication.disposition not in {
            PublicationDisposition.AUTHORIZED,
            PublicationDisposition.COMPLETED,
            PublicationDisposition.DUPLICATE,
        }:
            raise GitlabSummaryError(GitlabSummaryErrorCode.AUTHORIZATION_REJECTED)
        projection = _build_projection(
            request,
            publication,
            publication_outcome=publication_outcome,
        )
        with self._lock:
            prior = self._published.get(projection.note_idempotency_key)
            self._published[projection.note_idempotency_key] = projection.rendered_sha256
        disposition = (
            GitlabSummaryDisposition.CREATE
            if prior is None
            else GitlabSummaryDisposition.IDEMPOTENT
            if prior == projection.rendered_sha256
            else GitlabSummaryDisposition.UPDATE
        )
        return GitlabSummaryReceipt(
            disposition=disposition,
            projection=projection,
            publication=publication,
        )


def _build_projection(
    request: GitlabSummaryRequest,
    publication: SCMRunPublicationReceipt,
    *,
    publication_outcome: AuditRunOutcome | None,
) -> GitlabSummaryProjection:
    audit_run = request.audit_run
    identity = audit_run.execution_identity
    revision = identity.repository_revision
    if (
        audit_run.run_id != request.scm_run_id
        or publication.run_id != request.scm_run_id
        or publication.execution_identity_hash != identity.execution_identity_hash
        or publication.head_sha != revision.head_sha
        or publication.current_head_sha != revision.head_sha
        or audit_run.current_head_sha != revision.head_sha
    ):
        raise GitlabSummaryError(GitlabSummaryErrorCode.IDENTITY_MISMATCH)
    missing_lanes = _missing_mandatory_lanes(audit_run)
    if audit_run.audit_outcome is AuditRunOutcome.PASS and (
        not audit_run.coverage_manifest.coverage_complete or missing_lanes
    ):
        raise GitlabSummaryError(GitlabSummaryErrorCode.IDENTITY_MISMATCH)
    note_key = _idempotency_key(request.scm_run_id, identity.execution_identity_hash)
    rendered = _render(
        audit_run,
        note_key,
        missing_lanes,
        published_outcome=(
            publication.outcome if publication_outcome is None else publication_outcome
        ),
    )
    if not _safe_markdown(rendered):
        raise GitlabSummaryError(GitlabSummaryErrorCode.UNSAFE_RENDER_INPUT)
    return GitlabSummaryProjection(
        note_idempotency_key=note_key,
        execution_identity_hash=identity.execution_identity_hash,
        head_sha=revision.head_sha,
        outcome=audit_run.audit_outcome,
        rendered_markdown=rendered,
        rendered_sha256=hashlib.sha256(rendered.encode("ascii")).hexdigest(),
    )


def _missing_mandatory_lanes(audit_run: AuditRun) -> tuple[str, ...]:
    units = audit_run.coverage_manifest.units
    deterministic = tuple(unit for unit in units if unit.stage_id == "deterministic_analysis")
    model_native = tuple(unit for unit in units if unit.stage_id == "model_native_discovery")
    missing: list[str] = []
    if not deterministic or any(
        unit.coverage_status is not CoverageStatus.COMPLETED for unit in deterministic
    ):
        missing.append("deterministic_analysis")
    receipts = audit_run.coverage_manifest.model_discovery_receipts
    if (
        not model_native
        or any(unit.coverage_status is not CoverageStatus.COMPLETED for unit in model_native)
        or not receipts
        or any(
            receipt.model_call_status is not ModelCallStatus.SUCCEEDED
            or not receipt.schema_valid_result
            for receipt in receipts
        )
    ):
        missing.append("model_native_discovery")
    return tuple(missing)


def _render(
    audit_run: AuditRun,
    note_key: str,
    missing_lanes: tuple[str, ...],
    *,
    published_outcome: AuditRunOutcome,
) -> str:
    failed_units = tuple(
        unit
        for unit in audit_run.coverage_manifest.units
        if unit.required
        and unit.coverage_status not in {CoverageStatus.COMPLETED, CoverageStatus.NOT_APPLICABLE}
    )
    lines = [
        f"<!-- securecode-ai-gitlab-summary:{note_key} -->",
        f"## SecureCode AI: {audit_run.audit_outcome.value}",
        f"- Published policy status: {published_outcome.value}",
        f"- Run: `{audit_run.run_id}`",
        f"- Commit: `{audit_run.current_head_sha}`",
        f"- Findings: {len(audit_run.finding_ids)} total; {len(audit_run.blocking_finding_ids)} blocking",
        "- Merge authority: pipeline/status only; this note is advisory",
    ]
    if audit_run.audit_outcome is AuditRunOutcome.PASS:
        lines.extend(("- Coverage: complete", "- Result: all mandatory analysis completed"))
    else:
        reasons = [
            f"{unit.stage_id}:{unit.reason_code or unit.coverage_status.value}"
            for unit in failed_units[:_MAX_FAILED_UNITS]
        ]
        reasons.extend(f"{lane}:INCOMPLETE" for lane in missing_lanes)
        detail = "; ".join(dict.fromkeys(reasons)) or "outcome requires review"
        lines.extend(
            (
                "- Result: non-passing; this is not a clean result",
                f"- Coverage: incomplete; required units: {detail}",
                f"- Recovery: {_recovery(audit_run.audit_outcome, bool(reasons))}",
            )
        )
    return "\n".join(lines) + "\n"


def _recovery(outcome: AuditRunOutcome, coverage_incomplete: bool) -> str:
    if coverage_incomplete:
        return "rerun mandatory analysis before accepting this revision"
    if outcome is AuditRunOutcome.FAIL:
        return "review blocking findings before accepting this revision"
    if outcome is AuditRunOutcome.CANCELLED:
        return "rerun the cancelled audit before accepting this revision"
    return "investigate the non-passing audit and rerun it"


def _idempotency_key(scm_run_id: str, execution_identity_hash: str) -> str:
    if _SHA256.fullmatch(execution_identity_hash) is None:
        raise GitlabSummaryError(GitlabSummaryErrorCode.IDENTITY_MISMATCH)
    material = json.dumps(
        {
            "execution_identity_hash": execution_identity_hash,
            "scm_run_id": scm_run_id,
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "note-" + hashlib.sha256(_HASH_DOMAIN + material).hexdigest()[:40]


def _safe_markdown(value: object) -> bool:
    return (
        type(value) is str
        and len(value) <= 8_192
        and value.isascii()
        and all(character == "\n" or 32 <= ord(character) <= 126 for character in value)
    )


__all__ = [
    "GitlabSummaryAuthorizer",
    "GitlabSummaryDisposition",
    "GitlabSummaryError",
    "GitlabSummaryErrorCode",
    "GitlabSummaryProjection",
    "GitlabSummaryPublisher",
    "GitlabSummaryReceipt",
    "GitlabSummaryRequest",
]
