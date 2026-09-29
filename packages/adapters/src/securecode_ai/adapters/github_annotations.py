"""Bounded, metadata-only GitHub annotation projections for new confirmed findings."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from securecode_ai.contracts import FindingCase, FindingVerdict, RunExecutionIdentity
from securecode_ai.core.scm_run_state import PublicationDisposition, SCMRunPublicationReceipt

from .github_app import GithubAppError

MAX_GITHUB_ANNOTATIONS: Final = 50
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_PATH: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}\Z")


class GithubAnnotationSuppression(StrEnum):
    STALE_RUN = "STALE_RUN"
    LEGACY = "LEGACY"
    UNCONFIRMED = "UNCONFIRMED"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    AMBIGUOUS_LOCATION = "AMBIGUOUS_LOCATION"
    IMPRECISE_LOCATION = "IMPRECISE_LOCATION"
    UNCHANGED_LINE = "UNCHANGED_LINE"
    UNSAFE_PATH = "UNSAFE_PATH"
    VOLUME_LIMIT = "VOLUME_LIMIT"


class GithubAnnotationError(ValueError):
    """Safe rejection with no source or prompt content."""

    def __init__(self) -> None:
        super().__init__("GitHub annotation projection was rejected")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GithubChangedLine:
    """One exact changed line and its trusted HEAD content hash."""

    path: str
    line: int
    content_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.path) is not str
            or not _is_safe_path(self.path)
            or type(self.line) is not int
            or self.line < 1
            or type(self.content_sha256) is not str
            or _SHA256.fullmatch(self.content_sha256) is None
        ):
            raise GithubAnnotationError()


@dataclass(frozen=True, slots=True)
class GithubAnnotationCandidate:
    """P5.2 classification plus a normalized FindingCase; no raw source slots."""

    finding: FindingCase
    is_new_code: bool

    def __post_init__(self) -> None:
        if type(self.finding) is not FindingCase or type(self.is_new_code) is not bool:
            raise GithubAnnotationError()


@dataclass(frozen=True, slots=True)
class GithubAnnotationRequest:
    scm_run_id: str
    execution_identity: RunExecutionIdentity
    candidates: tuple[GithubAnnotationCandidate, ...]
    changed_lines: tuple[GithubChangedLine, ...]

    def __post_init__(self) -> None:
        if (
            type(self.scm_run_id) is not str
            or _ID.fullmatch(self.scm_run_id) is None
            or type(self.execution_identity) is not RunExecutionIdentity
            or type(self.candidates) is not tuple
            or type(self.changed_lines) is not tuple
            or any(type(item) is not GithubAnnotationCandidate for item in self.candidates)
            or any(type(item) is not GithubChangedLine for item in self.changed_lines)
            or len({item.finding.finding_id for item in self.candidates}) != len(self.candidates)
            or len({(item.path, item.line) for item in self.changed_lines})
            != len(self.changed_lines)
        ):
            raise GithubAnnotationError()


@dataclass(frozen=True, slots=True)
class GithubAnnotationProjection:
    tenant_id: str
    repository_id: str
    head_sha: str
    execution_identity_hash: str
    finding_id: str
    cwe_id: str
    path: str
    start_line: int
    end_line: int
    title: str
    message: str
    merge_authority: bool = False


@dataclass(frozen=True, slots=True)
class GithubAnnotationSuppressionReceipt:
    finding_id: str
    reason: GithubAnnotationSuppression


@dataclass(frozen=True, slots=True)
class GithubAnnotationReceipt:
    publication: SCMRunPublicationReceipt
    annotations: tuple[GithubAnnotationProjection, ...]
    suppressions: tuple[GithubAnnotationSuppressionReceipt, ...]


class GithubPublicationAuthorizer(Protocol):
    def authorize_publication(self, run_id: str) -> SCMRunPublicationReceipt: ...


class GithubAnnotationPublisher:
    """Filter and project high-signal annotations after P5.5 current-HEAD authorization."""

    __slots__ = ("_authorize",)

    def __init__(self, authorizer: GithubPublicationAuthorizer) -> None:
        authorize = getattr(authorizer, "authorize_publication", None)
        if not callable(authorize):
            raise GithubAnnotationError()
        self._authorize: Callable[[str], SCMRunPublicationReceipt] = authorize

    def project(
        self,
        request: GithubAnnotationRequest,
        *,
        publication_receipt: SCMRunPublicationReceipt | None = None,
    ) -> GithubAnnotationReceipt:
        if type(request) is not GithubAnnotationRequest:
            raise GithubAnnotationError()
        if publication_receipt is None:
            try:
                publication = self._authorize(request.scm_run_id)
            except GithubAppError as error:
                raise GithubAnnotationError() from error
        elif type(publication_receipt) is SCMRunPublicationReceipt:
            publication = publication_receipt
        else:
            raise GithubAnnotationError()
        if publication.disposition is PublicationDisposition.SUPERSEDED:
            return GithubAnnotationReceipt(
                publication=publication,
                annotations=(),
                suppressions=tuple(
                    GithubAnnotationSuppressionReceipt(
                        candidate.finding.finding_id,
                        GithubAnnotationSuppression.STALE_RUN,
                    )
                    for candidate in request.candidates
                ),
            )
        identity = request.execution_identity
        if (
            publication.disposition
            not in {
                PublicationDisposition.AUTHORIZED,
                PublicationDisposition.COMPLETED,
                PublicationDisposition.DUPLICATE,
            }
            or publication.run_id != request.scm_run_id
            or publication.execution_identity_hash != identity.execution_identity_hash
            or publication.head_sha != identity.repository_revision.head_sha
            or publication.current_head_sha != publication.head_sha
        ):
            raise GithubAnnotationError()
        changed = {(item.path, item.line): item.content_sha256 for item in request.changed_lines}
        annotations: list[GithubAnnotationProjection] = []
        suppressions: list[GithubAnnotationSuppressionReceipt] = []
        for candidate in sorted(request.candidates, key=lambda item: item.finding.finding_id):
            reason = _suppression_reason(candidate, identity, changed)
            if reason is not None:
                suppressions.append(
                    GithubAnnotationSuppressionReceipt(candidate.finding.finding_id, reason)
                )
            elif len(annotations) >= MAX_GITHUB_ANNOTATIONS:
                suppressions.append(
                    GithubAnnotationSuppressionReceipt(
                        candidate.finding.finding_id,
                        GithubAnnotationSuppression.VOLUME_LIMIT,
                    )
                )
            else:
                annotations.append(_annotation(candidate.finding, identity))
        return GithubAnnotationReceipt(
            publication=publication,
            annotations=tuple(annotations),
            suppressions=tuple(suppressions),
        )


def _suppression_reason(
    candidate: GithubAnnotationCandidate,
    identity: RunExecutionIdentity,
    changed: dict[tuple[str, int], str],
) -> GithubAnnotationSuppression | None:
    finding = candidate.finding
    revision = finding.repository_revision
    expected = identity.repository_revision
    if (
        revision.tenant_id != expected.tenant_id
        or revision.scm_provider != expected.scm_provider
        or revision.repository_id != expected.repository_id
        or revision.head_sha != expected.head_sha
    ):
        return GithubAnnotationSuppression.IDENTITY_MISMATCH
    if not candidate.is_new_code:
        return GithubAnnotationSuppression.LEGACY
    if finding.finding_verdict is not FindingVerdict.CONFIRMED:
        return GithubAnnotationSuppression.UNCONFIRMED
    if len(finding.locations) != 1:
        return GithubAnnotationSuppression.AMBIGUOUS_LOCATION
    location = finding.locations[0]
    if not _is_safe_path(location.path):
        return GithubAnnotationSuppression.UNSAFE_PATH
    if location.start.line != location.end.line:
        return GithubAnnotationSuppression.IMPRECISE_LOCATION
    changed_hash = changed.get((location.path, location.start.line))
    if changed_hash != location.content_sha256:
        return GithubAnnotationSuppression.UNCHANGED_LINE
    return None


def _annotation(
    finding: FindingCase,
    identity: RunExecutionIdentity,
) -> GithubAnnotationProjection:
    location = finding.locations[0]
    return GithubAnnotationProjection(
        tenant_id=identity.repository_revision.tenant_id,
        repository_id=identity.repository_revision.repository_id,
        head_sha=identity.repository_revision.head_sha,
        execution_identity_hash=identity.execution_identity_hash,
        finding_id=finding.finding_id,
        cwe_id=finding.cwe_id,
        path=location.path,
        start_line=location.start.line,
        end_line=location.end.line,
        title=f"SecureCode confirmed {finding.cwe_id}",
        message="Confirmed new-code finding. Review SecureCode evidence before merge.",
    )


def _is_safe_path(path: str) -> bool:
    return (
        _SAFE_PATH.fullmatch(path) is not None
        and "//" not in path
        and all(part not in {".", ".."} for part in path.split("/"))
    )


__all__ = [
    "MAX_GITHUB_ANNOTATIONS",
    "GithubAnnotationCandidate",
    "GithubAnnotationError",
    "GithubAnnotationProjection",
    "GithubAnnotationPublisher",
    "GithubAnnotationReceipt",
    "GithubAnnotationRequest",
    "GithubAnnotationSuppression",
    "GithubAnnotationSuppressionReceipt",
    "GithubChangedLine",
    "GithubPublicationAuthorizer",
]
