"""Idempotent GitHub pull-request summary and inline finding comments."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from securecode_ai.core.scm_run_state import (
    PublicationDisposition,
    SCMRunPublicationReceipt,
)

from .github_annotations import (
    GithubAnnotationProjection,
    GithubAnnotationReceipt,
    GithubAnnotationSuppression,
    GithubAnnotationSuppressionReceipt,
)
from .github_api import GitHubApi, GitHubError

MAX_GITHUB_INLINE_COMMENTS = 50
_MAX_RECONCILIATION_PAGES = 11
_COMMENTS_PER_PAGE = 100
_MAX_RECONCILIATION_COMMENTS = 1000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_REMOTE_ID = re.compile(r"[1-9][0-9]{0,19}\Z")


class GithubCommentSuppression(StrEnum):
    STALE_SUPPRESSED = "STALE_SUPPRESSED"
    VOLUME_LIMIT = "VOLUME_LIMIT"
    EXISTING = "EXISTING"
    NOT_ELIGIBLE = "NOT_ELIGIBLE"


class GithubCommentError(ValueError):
    def __init__(self, code: str = "COMMENT_INVALID") -> None:
        self.code = code
        super().__init__("GitHub comment publication was rejected")
        self.__cause__ = None
        self.__context__ = None


class PullRequestHeadResolver(Protocol):
    def __call__(self, installation_id: str, repository_id: str, change_id: str) -> str: ...


@dataclass(frozen=True, slots=True)
class GithubCommentReceipt:
    status: str
    summary_id: str | None
    inline_written: tuple[str, ...]
    suppressions: tuple[tuple[str, GithubCommentSuppression], ...]


class GithubCommentPublisher:
    __slots__ = ("_api", "_head")

    def __init__(self, api: GitHubApi, *, pull_request_head: PullRequestHeadResolver) -> None:
        if not callable(pull_request_head):
            raise GithubCommentError()
        self._api = api
        self._head = pull_request_head

    def publish(
        self,
        *,
        installation_id: str,
        repository_id: str,
        change_id: str,
        expected_head: str,
        external_id: str,
        summary: str,
        delivery_key: str,
        annotation_receipt: GithubAnnotationReceipt | None = None,
    ) -> GithubCommentReceipt:
        if (
            _ID.fullmatch(installation_id) is None
            or _ID.fullmatch(repository_id) is None
            or _REMOTE_ID.fullmatch(change_id) is None
            or _SHA.fullmatch(expected_head) is None
            or _ID.fullmatch(delivery_key) is None
            or _ID.fullmatch(external_id) is None
            or type(summary) is not str
            or not summary
            or len(summary) > 60_000
            or (
                annotation_receipt is not None
                and type(annotation_receipt) is not GithubAnnotationReceipt
            )
        ):
            raise GithubCommentError()
        inline, annotation_suppressions = _verified_annotations(
            annotation_receipt,
            expected_head=expected_head,
            repository_id=repository_id,
        )
        if (
            annotation_receipt is not None
            and annotation_receipt.publication.disposition is PublicationDisposition.SUPERSEDED
        ):
            return GithubCommentReceipt(
                "STALE_SUPPRESSED",
                None,
                (),
                annotation_suppressions,
            )
        if self._head(installation_id, repository_id, change_id) != expected_head:
            stale = tuple(
                (item.finding_id, GithubCommentSuppression.STALE_SUPPRESSED)
                for item in inline
            )
            return GithubCommentReceipt(
                "STALE_SUPPRESSED",
                None,
                (),
                (*annotation_suppressions, *stale),
            )
        repository = self._api.repository_path_for_id(installation_id, repository_id)
        summary_id = self._upsert_summary(
            installation_id,
            repository_id,
            repository,
            change_id,
            expected_head,
            external_id,
            summary,
            delivery_key,
        )
        if summary_id is None:
            stale = tuple(
                (item.finding_id, GithubCommentSuppression.STALE_SUPPRESSED)
                for item in inline
            )
            return GithubCommentReceipt(
                "STALE_SUPPRESSED",
                None,
                (),
                (*annotation_suppressions, *stale),
            )
        existing = self._existing_inline(installation_id, repository, change_id)
        written: list[str] = []
        suppressions: list[tuple[str, GithubCommentSuppression]] = []
        ordered_inline = sorted(inline, key=lambda value: value.finding_id)
        for index, item in enumerate(ordered_inline):
            if item.finding_id in existing:
                suppressions.append((item.finding_id, GithubCommentSuppression.EXISTING))
            elif len(written) >= MAX_GITHUB_INLINE_COMMENTS:
                suppressions.append((item.finding_id, GithubCommentSuppression.VOLUME_LIMIT))
            elif self._head(installation_id, repository_id, change_id) != expected_head:
                for pending in ordered_inline[index:]:
                    if pending.finding_id in existing:
                        reason = GithubCommentSuppression.EXISTING
                    else:
                        reason = GithubCommentSuppression.STALE_SUPPRESSED
                    suppressions.append((pending.finding_id, reason))
                break
            else:
                body = (
                    item.title
                    + "\n\n"
                    + item.message
                    + "\n\n<!-- securecode-ai-inline:"
                    + item.finding_id
                    + " -->"
                )
                response = self._api.request(
                    "POST",
                    repository + "/pulls/" + change_id + "/comments",
                    installation_id=installation_id,
                    document={
                        "body": body,
                        "commit_id": expected_head,
                        "path": item.path,
                        "line": item.start_line,
                        "side": "RIGHT",
                    },
                    idempotency_key=_inline_idempotency_key(delivery_key, item.finding_id),
                )
                if response.status != 201 or _remote_identity(response.document) is None:
                    raise GitHubError("COMMENT_RECEIPT_INVALID")
                written.append(item.finding_id)
        return GithubCommentReceipt(
            "WRITTEN",
            summary_id,
            tuple(written),
            (*annotation_suppressions, *suppressions),
        )

    def _upsert_summary(
        self,
        installation_id: str,
        repository_id: str,
        repository: str,
        change_id: str,
        expected_head: str,
        external_id: str,
        summary: str,
        delivery_key: str,
    ) -> str | None:
        marker = "<!-- securecode-ai-summary:" + external_id + " -->"
        comments = self._list(
            installation_id, repository + "/issues/" + change_id + "/comments?per_page=100"
        )
        matches = [item for item in comments if marker in str(item.get("body", ""))]
        if len(matches) > 1:
            raise GitHubError("SUMMARY_RECONCILIATION_CONFLICT")
        body = summary + "\n\n" + marker
        if matches:
            remote_id = _remote_identity(matches[0])
            if remote_id is None:
                raise GitHubError("SUMMARY_RECONCILIATION_INVALID")
            if self._head(installation_id, repository_id, change_id) != expected_head:
                return None
            response = self._api.request(
                "PATCH",
                repository + "/issues/comments/" + remote_id,
                installation_id=installation_id,
                document={"body": body},
                idempotency_key=delivery_key,
            )
            if response.status != 200 or _remote_identity(response.document) != remote_id:
                raise GitHubError("COMMENT_RECEIPT_INVALID")
            return remote_id
        if self._head(installation_id, repository_id, change_id) != expected_head:
            return None
        response = self._api.request(
            "POST",
            repository + "/issues/" + change_id + "/comments",
            installation_id=installation_id,
            document={"body": body},
            idempotency_key=delivery_key,
        )
        remote_id = _remote_identity(response.document)
        if response.status != 201 or remote_id is None:
            raise GitHubError("COMMENT_RECEIPT_INVALID")
        return remote_id

    def _existing_inline(self, installation_id: str, repository: str, change_id: str) -> set[str]:
        values = self._list(
            installation_id, repository + "/pulls/" + change_id + "/comments?per_page=100"
        )
        result: set[str] = set()
        for item in values:
            body = item.get("body")
            if type(body) is str:
                result.update(
                    re.findall(
                        r"<!-- securecode-ai-inline:([A-Za-z0-9][A-Za-z0-9._:-]{0,127}) -->", body
                    )
                )
        return result

    def _list(self, installation_id: str, path: str) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for page in range(1, _MAX_RECONCILIATION_PAGES + 1):
            separator = "&" if "?" in path else "?"
            paged_path = path + separator + f"page={page}"
            response = self._api.request("GET", paged_path, installation_id=installation_id)
            document = response.document
            values = (
                document.get("comments")
                if type(document) is dict and "comments" in document
                else document
            )
            if (
                response.status != 200
                or type(values) is not list
                or len(values) > _COMMENTS_PER_PAGE
                or any(type(item) is not dict for item in values)
                or len(result) + len(values) > _MAX_RECONCILIATION_COMMENTS
            ):
                raise GitHubError("COMMENT_RECONCILIATION_INVALID")
            result.extend(values)
            if len(values) < _COMMENTS_PER_PAGE:
                return result
        raise GitHubError("COMMENT_RECONCILIATION_LIMIT")


def _inline_idempotency_key(delivery_key: str, finding_id: str) -> str:
    material = (delivery_key + "\x00" + finding_id).encode("ascii")
    return "inline-" + hashlib.sha256(material).hexdigest()


def _remote_identity(document: object) -> str | None:
    if type(document) is not dict:
        return None
    value = document.get("id")
    remote_id = str(value) if type(value) is int and value > 0 else ""
    return remote_id if _REMOTE_ID.fullmatch(remote_id) else None


def _verified_annotations(
    receipt: GithubAnnotationReceipt | None,
    *,
    expected_head: str,
    repository_id: str,
) -> tuple[
    tuple[GithubAnnotationProjection, ...],
    tuple[tuple[str, GithubCommentSuppression], ...],
]:
    if receipt is None:
        return (), ()
    publication = receipt.publication
    if (
        type(publication) is not SCMRunPublicationReceipt
        or publication.disposition
        not in {PublicationDisposition.AUTHORIZED, PublicationDisposition.SUPERSEDED}
        or publication.head_sha != expected_head
        or type(receipt.annotations) is not tuple
        or type(receipt.suppressions) is not tuple
        or len(receipt.annotations) > MAX_GITHUB_INLINE_COMMENTS
        or len(receipt.suppressions) > 4096
        or any(type(item) is not GithubAnnotationSuppressionReceipt for item in receipt.suppressions)
    ):
        raise GithubCommentError("ANNOTATION_AUTHORIZATION_INVALID")
    mapped_suppressions: list[tuple[str, GithubCommentSuppression]] = []
    for item in receipt.suppressions:
        if (
            type(item.finding_id) is not str
            or _ID.fullmatch(item.finding_id) is None
            or type(item.reason) is not GithubAnnotationSuppression
        ):
            raise GithubCommentError("ANNOTATION_AUTHORIZATION_INVALID")
        reason = (
            GithubCommentSuppression.STALE_SUPPRESSED
            if item.reason is GithubAnnotationSuppression.STALE_RUN
            else GithubCommentSuppression.VOLUME_LIMIT
            if item.reason is GithubAnnotationSuppression.VOLUME_LIMIT
            else GithubCommentSuppression.NOT_ELIGIBLE
        )
        mapped_suppressions.append((item.finding_id, reason))
    if publication.disposition is PublicationDisposition.SUPERSEDED:
        if receipt.annotations:
            raise GithubCommentError("ANNOTATION_AUTHORIZATION_INVALID")
        return (), tuple(mapped_suppressions)
    if publication.current_head_sha != expected_head:
        raise GithubCommentError("ANNOTATION_AUTHORIZATION_INVALID")
    values = receipt.annotations
    if (
        any(type(item) is not GithubAnnotationProjection for item in values)
        or len({item.finding_id for item in values}) != len(values)
    ):
        raise GithubCommentError("ANNOTATION_AUTHORIZATION_INVALID")
    for item in values:
        if (
            _ID.fullmatch(item.finding_id) is None
            or item.repository_id != repository_id
            or item.head_sha != expected_head
            or item.execution_identity_hash != publication.execution_identity_hash
            or type(item.tenant_id) is not str
            or not item.tenant_id
            or not _safe_path(item.path)
            or type(item.start_line) is not int
            or item.start_line < 1
            or type(item.end_line) is not int
            or item.end_line != item.start_line
            or type(item.title) is not str
            or not item.title
            or len(item.title) > 256
            or type(item.message) is not str
            or not item.message
            or len(item.message) > 4096
            or item.merge_authority is not False
        ):
            raise GithubCommentError("ANNOTATION_AUTHORIZATION_INVALID")
    return values, tuple(mapped_suppressions)


def _safe_path(path: str) -> bool:
    return (
        type(path) is str
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}", path) is not None
        and "//" not in path
        and all(part not in {".", ".."} for part in path.split("/"))
    )


__all__ = [
    "MAX_GITHUB_INLINE_COMMENTS",
    "GithubCommentError",
    "GithubCommentPublisher",
    "GithubCommentReceipt",
    "GithubCommentSuppression",
    "PullRequestHeadResolver",
]
