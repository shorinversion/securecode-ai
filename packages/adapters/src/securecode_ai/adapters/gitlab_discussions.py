"""Bounded GitLab MR discussion projections for confirmed new-code findings."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from securecode_ai.contracts import FindingCase, FindingVerdict, RunExecutionIdentity
from securecode_ai.core.scm_run_state import PublicationDisposition, SCMRunPublicationReceipt

from .gitlab_ci import GitlabCIAdapter, GitlabCIError

MAX_GITLAB_DISCUSSIONS: Final = 50
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_SAFE_PATH: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}\Z")


class GitlabDiscussionSuppression(StrEnum):
    STALE_RUN = "STALE_RUN"
    LEGACY = "LEGACY"
    UNCONFIRMED = "UNCONFIRMED"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    AMBIGUOUS_LOCATION = "AMBIGUOUS_LOCATION"
    IMPRECISE_LOCATION = "IMPRECISE_LOCATION"
    UNCHANGED_LINE = "UNCHANGED_LINE"
    UNSAFE_PATH = "UNSAFE_PATH"
    INVALID_DIFF_POSITION = "INVALID_DIFF_POSITION"
    VOLUME_LIMIT = "VOLUME_LIMIT"


class GitlabDiscussionError(ValueError):
    def __init__(self) -> None:
        super().__init__("GitLab discussion projection was rejected")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GitlabChangedLine:
    path: str
    line: int
    content_sha256: str
    base_sha: str
    start_sha: str
    head_sha: str
    old_path: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.path) is not str
            or not _safe_path(self.path)
            or type(self.line) is not int
            or self.line < 1
            or type(self.content_sha256) is not str
            or _SHA256.fullmatch(self.content_sha256) is None
            or any(
                type(value) is not str or _COMMIT_SHA.fullmatch(value) is None
                for value in (self.base_sha, self.start_sha, self.head_sha)
            )
            or self.base_sha == self.head_sha
            or (self.old_path is not None and not _safe_path(self.old_path))
        ):
            raise GitlabDiscussionError()


@dataclass(frozen=True, slots=True)
class GitlabDiscussionCandidate:
    finding: FindingCase
    is_new_code: bool

    def __post_init__(self) -> None:
        if type(self.finding) is not FindingCase or type(self.is_new_code) is not bool:
            raise GitlabDiscussionError()


@dataclass(frozen=True, slots=True)
class GitlabDiscussionRequest:
    scm_run_id: str
    execution_identity: RunExecutionIdentity
    candidates: tuple[GitlabDiscussionCandidate, ...]
    changed_lines: tuple[GitlabChangedLine, ...]

    def __post_init__(self) -> None:
        if (
            type(self.scm_run_id) is not str
            or _ID.fullmatch(self.scm_run_id) is None
            or type(self.execution_identity) is not RunExecutionIdentity
            or type(self.candidates) is not tuple
            or type(self.changed_lines) is not tuple
            or any(type(item) is not GitlabDiscussionCandidate for item in self.candidates)
            or any(type(item) is not GitlabChangedLine for item in self.changed_lines)
            or len({item.finding.finding_id for item in self.candidates}) != len(self.candidates)
            or len({(item.path, item.line) for item in self.changed_lines})
            != len(self.changed_lines)
        ):
            raise GitlabDiscussionError()


@dataclass(frozen=True, slots=True)
class GitlabDiscussionProjection:
    finding_id: str
    cwe_id: str
    new_path: str
    new_line: int
    base_sha: str
    start_sha: str
    head_sha: str
    body: str
    merge_authority: bool = False
    old_path: str | None = None


@dataclass(frozen=True, slots=True)
class GitlabDiscussionSuppressionReceipt:
    finding_id: str
    reason: GitlabDiscussionSuppression


@dataclass(frozen=True, slots=True)
class GitlabDiscussionReceipt:
    publication: SCMRunPublicationReceipt
    discussions: tuple[GitlabDiscussionProjection, ...]
    suppressions: tuple[GitlabDiscussionSuppressionReceipt, ...]


class GitlabDiscussionPublisher:
    __slots__ = ("_adapter",)

    def __init__(self, adapter: GitlabCIAdapter) -> None:
        if type(adapter) is not GitlabCIAdapter:
            raise GitlabDiscussionError()
        self._adapter = adapter

    def project(self, request: GitlabDiscussionRequest) -> GitlabDiscussionReceipt:
        if type(request) is not GitlabDiscussionRequest:
            raise GitlabDiscussionError()
        try:
            publication = self._adapter.authorize_publication(request.scm_run_id)
        except GitlabCIError as error:
            raise GitlabDiscussionError() from error
        if publication.disposition is PublicationDisposition.SUPERSEDED:
            return GitlabDiscussionReceipt(
                publication=publication,
                discussions=(),
                suppressions=tuple(
                    GitlabDiscussionSuppressionReceipt(
                        candidate.finding.finding_id,
                        GitlabDiscussionSuppression.STALE_RUN,
                    )
                    for candidate in request.candidates
                ),
            )
        identity = request.execution_identity
        if (
            publication.disposition is not PublicationDisposition.AUTHORIZED
            or publication.execution_identity_hash != identity.execution_identity_hash
            or publication.head_sha != identity.repository_revision.head_sha
            or publication.current_head_sha != publication.head_sha
        ):
            raise GitlabDiscussionError()
        changed = {(item.path, item.line): item for item in request.changed_lines}
        discussions: list[GitlabDiscussionProjection] = []
        suppressions: list[GitlabDiscussionSuppressionReceipt] = []
        for candidate in sorted(request.candidates, key=lambda item: item.finding.finding_id):
            reason, changed_line = _suppression_reason(candidate, identity, changed)
            if reason is not None:
                suppressions.append(
                    GitlabDiscussionSuppressionReceipt(candidate.finding.finding_id, reason)
                )
            elif len(discussions) >= MAX_GITLAB_DISCUSSIONS:
                suppressions.append(
                    GitlabDiscussionSuppressionReceipt(
                        candidate.finding.finding_id,
                        GitlabDiscussionSuppression.VOLUME_LIMIT,
                    )
                )
            elif changed_line is None:
                raise GitlabDiscussionError()
            else:
                discussions.append(_discussion(candidate.finding, changed_line))
        return GitlabDiscussionReceipt(
            publication=publication,
            discussions=tuple(discussions),
            suppressions=tuple(suppressions),
        )


def _suppression_reason(
    candidate: GitlabDiscussionCandidate,
    identity: RunExecutionIdentity,
    changed: dict[tuple[str, int], GitlabChangedLine],
) -> tuple[GitlabDiscussionSuppression | None, GitlabChangedLine | None]:
    finding = candidate.finding
    actual = finding.repository_revision
    expected = identity.repository_revision
    if (
        actual.tenant_id != expected.tenant_id
        or actual.scm_provider != expected.scm_provider
        or actual.repository_id != expected.repository_id
        or actual.head_sha != expected.head_sha
    ):
        return GitlabDiscussionSuppression.IDENTITY_MISMATCH, None
    if not candidate.is_new_code:
        return GitlabDiscussionSuppression.LEGACY, None
    if finding.finding_verdict is not FindingVerdict.CONFIRMED:
        return GitlabDiscussionSuppression.UNCONFIRMED, None
    if len(finding.locations) != 1:
        return GitlabDiscussionSuppression.AMBIGUOUS_LOCATION, None
    location = finding.locations[0]
    if not _safe_path(location.path):
        return GitlabDiscussionSuppression.UNSAFE_PATH, None
    if location.start.line != location.end.line:
        return GitlabDiscussionSuppression.IMPRECISE_LOCATION, None
    changed_line = changed.get((location.path, location.start.line))
    if changed_line is None or changed_line.content_sha256 != location.content_sha256:
        return GitlabDiscussionSuppression.UNCHANGED_LINE, None
    if (
        changed_line.head_sha != expected.head_sha
        or expected.base_sha is None
        or changed_line.base_sha != expected.base_sha
    ):
        return GitlabDiscussionSuppression.INVALID_DIFF_POSITION, None
    return None, changed_line


def _discussion(
    finding: FindingCase,
    changed_line: GitlabChangedLine,
) -> GitlabDiscussionProjection:
    location = finding.locations[0]
    return GitlabDiscussionProjection(
        finding_id=finding.finding_id,
        cwe_id=finding.cwe_id,
        new_path=location.path,
        new_line=location.start.line,
        base_sha=changed_line.base_sha,
        start_sha=changed_line.start_sha,
        head_sha=changed_line.head_sha,
        body=(
            f"SecureCode confirmed {finding.cwe_id} in new code. "
            "Review the retained evidence before merge."
        ),
        old_path=changed_line.old_path or changed_line.path,
    )


def _safe_path(path: str) -> bool:
    return (
        _SAFE_PATH.fullmatch(path) is not None
        and "//" not in path
        and all(part not in {".", ".."} for part in path.split("/"))
    )


__all__ = [
    "MAX_GITLAB_DISCUSSIONS",
    "GitlabChangedLine",
    "GitlabDiscussionCandidate",
    "GitlabDiscussionError",
    "GitlabDiscussionProjection",
    "GitlabDiscussionPublisher",
    "GitlabDiscussionReceipt",
    "GitlabDiscussionRequest",
    "GitlabDiscussionSuppression",
    "GitlabDiscussionSuppressionReceipt",
]
