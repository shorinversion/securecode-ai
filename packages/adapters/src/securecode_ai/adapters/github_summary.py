"""Safe, idempotent GitHub summary-comment projection for exact-SHA audit runs."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final

from securecode_ai.contracts import (
    AuditRun,
    AuditRunOutcome,
    CoverageStatus,
    CoverageUnit,
    ModelCallStatus,
)
from securecode_ai.core.scm_run_state import PublicationDisposition, SCMRunPublicationReceipt

from .github_app import GithubAppAdapter, GithubAppError

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_MAX_RECOVERY_UNITS: Final = 12
_HASH_DOMAIN: Final = b"securecode-ai/github-summary/v1\x00"


class GithubSummaryErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    AUTHORIZATION_REJECTED = "AUTHORIZATION_REJECTED"
    UNSAFE_RENDER_INPUT = "UNSAFE_RENDER_INPUT"


class GithubSummaryError(ValueError):
    """Safe boundary error that never contains source, prompts, or secrets."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GithubSummaryErrorCode) -> None:
        if type(code) is not GithubSummaryErrorCode:
            raise TypeError("GitHub summary error code is invalid")
        self.code = code
        self.safe_message = "GitHub summary projection was rejected"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class GithubSummaryDisposition(StrEnum):
    CREATED = "CREATED"
    UPDATED = "UPDATED"
    IDEMPOTENT = "IDEMPOTENT"
    SUPERSEDED = "SUPERSEDED"


@dataclass(frozen=True, slots=True)
class GithubSummaryRequest:
    """Final metadata-only audit material for one admitted SCM run."""

    scm_run_id: str
    audit_run: AuditRun

    def __post_init__(self) -> None:
        if (
            type(self.scm_run_id) is not str
            or _ID.fullmatch(self.scm_run_id) is None
            or type(self.audit_run) is not AuditRun
        ):
            raise GithubSummaryError(GithubSummaryErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class GithubSummaryProjection:
    """Safe rendering payload for a single updatable GitHub summary comment."""

    comment_idempotency_key: str
    execution_identity_hash: str
    head_sha: str
    outcome: AuditRunOutcome
    rendered_markdown: str
    rendered_sha256: str


@dataclass(frozen=True, slots=True)
class GithubSummaryReceipt:
    """Publication projection result; no SCM write is performed by this module."""

    disposition: GithubSummaryDisposition
    projection: GithubSummaryProjection | None
    publication: SCMRunPublicationReceipt


class GithubSummaryPublisher:
    """Project one comment per semantic SCM run after fresh exact-HEAD authorization."""

    __slots__ = ("_adapter", "_lock", "_published")

    def __init__(self, adapter: GithubAppAdapter) -> None:
        if type(adapter) is not GithubAppAdapter:
            raise GithubSummaryError(GithubSummaryErrorCode.INVALID_REQUEST)
        self._adapter = adapter
        self._published: dict[str, str] = {}
        self._lock = RLock()

    def project(self, request: GithubSummaryRequest) -> GithubSummaryReceipt:
        """Authorize, validate, and render a safe idempotent comment projection."""

        if type(request) is not GithubSummaryRequest:
            raise GithubSummaryError(GithubSummaryErrorCode.INVALID_REQUEST)
        try:
            publication = self._adapter.authorize_publication(request.scm_run_id)
        except GithubAppError as error:
            raise GithubSummaryError(GithubSummaryErrorCode.AUTHORIZATION_REJECTED) from error
        if publication.disposition is PublicationDisposition.SUPERSEDED:
            return GithubSummaryReceipt(
                disposition=GithubSummaryDisposition.SUPERSEDED,
                projection=None,
                publication=publication,
            )
        if publication.disposition is not PublicationDisposition.AUTHORIZED:
            raise GithubSummaryError(GithubSummaryErrorCode.AUTHORIZATION_REJECTED)
        projection = _build_projection(request, publication)
        with self._lock:
            prior_hash = self._published.get(projection.comment_idempotency_key)
            self._published[projection.comment_idempotency_key] = projection.rendered_sha256
        disposition = (
            GithubSummaryDisposition.CREATED
            if prior_hash is None
            else GithubSummaryDisposition.IDEMPOTENT
            if prior_hash == projection.rendered_sha256
            else GithubSummaryDisposition.UPDATED
        )
        return GithubSummaryReceipt(
            disposition=disposition,
            projection=projection,
            publication=publication,
        )


def _build_projection(
    request: GithubSummaryRequest,
    publication: SCMRunPublicationReceipt,
) -> GithubSummaryProjection:
    audit_run = request.audit_run
    identity = audit_run.execution_identity
    if (
        publication.execution_identity_hash != identity.execution_identity_hash
        or publication.head_sha != identity.repository_revision.head_sha
        or audit_run.current_head_sha != publication.current_head_sha
        or audit_run.current_head_sha != identity.repository_revision.head_sha
    ):
        raise GithubSummaryError(GithubSummaryErrorCode.IDENTITY_MISMATCH)
    lane_complete, missing_lanes = _mandatory_lanes(audit_run)
    if audit_run.audit_outcome is AuditRunOutcome.PASS and (
        not audit_run.coverage_manifest.coverage_complete or not lane_complete
    ):
        raise GithubSummaryError(GithubSummaryErrorCode.IDENTITY_MISMATCH)
    key = _idempotency_key(request.scm_run_id, identity.execution_identity_hash)
    rendered = _render_markdown(audit_run, key, missing_lanes)
    if not _safe_markdown(rendered):
        raise GithubSummaryError(GithubSummaryErrorCode.UNSAFE_RENDER_INPUT)
    rendered_sha256 = hashlib.sha256(rendered.encode("ascii")).hexdigest()
    return GithubSummaryProjection(
        comment_idempotency_key=key,
        execution_identity_hash=identity.execution_identity_hash,
        head_sha=identity.repository_revision.head_sha,
        outcome=audit_run.audit_outcome,
        rendered_markdown=rendered,
        rendered_sha256=rendered_sha256,
    )


def _mandatory_lanes(audit_run: AuditRun) -> tuple[bool, tuple[str, ...]]:
    units = audit_run.coverage_manifest.units
    deterministic = [unit for unit in units if unit.stage_id == "deterministic_analysis"]
    model_native = [unit for unit in units if unit.stage_id == "model_native_discovery"]
    deterministic_complete = bool(deterministic) and all(
        unit.coverage_status is CoverageStatus.COMPLETED for unit in deterministic
    )
    model_complete = bool(model_native) and all(
        unit.coverage_status is CoverageStatus.COMPLETED for unit in model_native
    )
    receipts_complete = bool(audit_run.coverage_manifest.model_discovery_receipts) and all(
        receipt.model_call_status is ModelCallStatus.SUCCEEDED and receipt.schema_valid_result
        for receipt in audit_run.coverage_manifest.model_discovery_receipts
    )
    missing: list[str] = []
    if not deterministic_complete:
        missing.append("deterministic_analysis")
    if not model_complete or not receipts_complete:
        missing.append("model_native_discovery")
    return (not missing, tuple(missing))


def _render_markdown(audit_run: AuditRun, key: str, missing_lanes: tuple[str, ...]) -> str:
    manifest = audit_run.coverage_manifest
    failed_units = tuple(
        unit
        for unit in manifest.units
        if unit.required
        and unit.coverage_status not in {CoverageStatus.COMPLETED, CoverageStatus.NOT_APPLICABLE}
    )
    lines = [
        f"<!-- securecode-ai-summary:{key} -->",
        f"## SecureCode AI: {audit_run.audit_outcome.value}",
        f"- Run: `{audit_run.run_id}`",
        f"- Commit: `{audit_run.current_head_sha}`",
        f"- Findings: {len(audit_run.finding_ids)} total; {len(audit_run.blocking_finding_ids)} blocking",
        "- Merge authority: status/check only; this comment is advisory",
    ]
    if audit_run.audit_outcome is AuditRunOutcome.PASS:
        lines.extend(("- Coverage: complete", "- Result: all mandatory coverage completed"))
    else:
        lines.append("- Result: non-passing; this is not a clean result")
        lines.append(_coverage_line(manifest.coverage_complete, failed_units, missing_lanes))
        lines.append(
            f"- Recovery: {_recovery_action(audit_run.audit_outcome, failed_units, missing_lanes)}"
        )
    return "\n".join(lines) + "\n"


def _coverage_line(
    coverage_complete: bool,
    failed_units: tuple[CoverageUnit, ...],
    missing_lanes: tuple[str, ...],
) -> str:
    reasons: list[str] = []
    for unit in failed_units[:_MAX_RECOVERY_UNITS]:
        stage_id = unit.stage_id
        reason_code = unit.reason_code or unit.coverage_status.value
        reasons.append(f"{stage_id}:{reason_code}")
    reasons.extend(f"{lane}:INCOMPLETE" for lane in missing_lanes)
    detail = "; ".join(dict.fromkeys(reasons)) if reasons else "outcome requires review"
    state = "complete" if coverage_complete and not missing_lanes else "incomplete"
    return f"- Coverage: {state}; required units: {detail}"


def _recovery_action(
    outcome: AuditRunOutcome,
    failed_units: tuple[CoverageUnit, ...],
    missing_lanes: tuple[str, ...],
) -> str:
    if failed_units or missing_lanes:
        return "rerun the listed required analysis before treating this revision as clean"
    if outcome is AuditRunOutcome.FAIL:
        return "review blocking findings before accepting this revision"
    if outcome is AuditRunOutcome.CANCELLED:
        return "rerun the cancelled analysis before accepting this revision"
    return "investigate the recorded non-passing outcome and rerun the analysis"


def _idempotency_key(scm_run_id: str, execution_identity_hash: str) -> str:
    if _SHA256.fullmatch(execution_identity_hash) is None:
        raise GithubSummaryError(GithubSummaryErrorCode.IDENTITY_MISMATCH)
    material = json.dumps(
        {"execution_identity_hash": execution_identity_hash, "scm_run_id": scm_run_id},
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "summary-" + hashlib.sha256(_HASH_DOMAIN + material).hexdigest()[:40]


def _safe_markdown(value: object) -> bool:
    return (
        type(value) is str
        and len(value) <= 8_192
        and value.isascii()
        and all(character == "\n" or 32 <= ord(character) <= 126 for character in value)
    )


__all__ = [
    "GithubSummaryDisposition",
    "GithubSummaryError",
    "GithubSummaryErrorCode",
    "GithubSummaryProjection",
    "GithubSummaryPublisher",
    "GithubSummaryReceipt",
    "GithubSummaryRequest",
]
