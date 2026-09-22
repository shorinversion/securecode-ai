"""Idempotent GitHub pull-request summary and inline finding comments."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .github_api import GitHubApi, GitHubError

MAX_GITHUB_INLINE_COMMENTS = 50
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}\Z")
_REMOTE_ID = re.compile(r"[1-9][0-9]{0,19}\Z")


class GithubCommentSuppression(StrEnum):
    STALE_SUPPRESSED = "STALE_SUPPRESSED"
    VOLUME_LIMIT = "VOLUME_LIMIT"
    EXISTING = "EXISTING"


class GithubCommentError(ValueError):
    def __init__(self, code: str = "COMMENT_INVALID") -> None:
        self.code = code
        super().__init__("GitHub comment publication was rejected")
        self.__cause__ = None
        self.__context__ = None


class PullRequestHeadResolver(Protocol):
    def __call__(self, installation_id: str, repository_id: str, change_id: str) -> str: ...


@dataclass(frozen=True, slots=True)
class GithubInlineProjection:
    finding_id: str
    path: str
    line: int
    body: str

    def __post_init__(self) -> None:
        if (
            _ID.fullmatch(self.finding_id) is None
            or not _safe_path(self.path)
            or type(self.line) is not int
            or self.line < 1
            or type(self.body) is not str
            or not self.body
            or len(self.body) > 4096
        ):
            raise GithubCommentError()


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
        inline: tuple[GithubInlineProjection, ...] = (),
    ) -> GithubCommentReceipt:
        if (
            _SHA.fullmatch(expected_head) is None
            or _ID.fullmatch(external_id) is None
            or type(summary) is not str
            or not summary
            or len(summary) > 60_000
            or type(inline) is not tuple
            or any(type(item) is not GithubInlineProjection for item in inline)
            or len({item.finding_id for item in inline}) != len(inline)
        ):
            raise GithubCommentError()
        if self._head(installation_id, repository_id, change_id) != expected_head:
            return GithubCommentReceipt("STALE_SUPPRESSED", None, (), ())
        repository = "/repositories/" + repository_id
        summary_id = self._upsert_summary(
            installation_id, repository, change_id, external_id, summary, delivery_key
        )
        existing = self._existing_inline(installation_id, repository, change_id)
        written: list[str] = []
        suppressions: list[tuple[str, GithubCommentSuppression]] = []
        for item in sorted(inline, key=lambda value: value.finding_id):
            if item.finding_id in existing:
                suppressions.append((item.finding_id, GithubCommentSuppression.EXISTING))
            elif len(written) >= MAX_GITHUB_INLINE_COMMENTS:
                suppressions.append((item.finding_id, GithubCommentSuppression.VOLUME_LIMIT))
            else:
                body = item.body + "\n\n<!-- securecode-ai-inline:" + item.finding_id + " -->"
                response = self._api.request(
                    "POST",
                    repository + "/pulls/" + change_id + "/comments",
                    installation_id=installation_id,
                    document={
                        "body": body,
                        "commit_id": expected_head,
                        "path": item.path,
                        "line": item.line,
                        "side": "RIGHT",
                    },
                    idempotency_key=delivery_key + ":" + item.finding_id,
                )
                if response.status != 201 or _remote_identity(response.document) is None:
                    raise GitHubError("COMMENT_RECEIPT_INVALID")
                written.append(item.finding_id)
        return GithubCommentReceipt("WRITTEN", summary_id, tuple(written), tuple(suppressions))

    def _upsert_summary(
        self,
        installation_id: str,
        repository: str,
        change_id: str,
        external_id: str,
        summary: str,
        delivery_key: str,
    ) -> str:
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
            response = self._api.request(
                "PUT",
                repository + "/issues/comments/" + remote_id,
                installation_id=installation_id,
                document={"body": body},
                idempotency_key=delivery_key,
            )
            if response.status != 200 or _remote_identity(response.document) != remote_id:
                raise GitHubError("COMMENT_RECEIPT_INVALID")
            return remote_id
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
        response = self._api.request("GET", path, installation_id=installation_id)
        document = response.document
        values = (
            document.get("comments")
            if type(document) is dict and "comments" in document
            else document
        )
        if (
            response.status != 200
            or type(values) is not list
            or len(values) > 100
            or any(type(item) is not dict for item in values)
        ):
            raise GitHubError("COMMENT_RECONCILIATION_INVALID")
        return values


def _remote_identity(document: dict[str, object] | None) -> str | None:
    if type(document) is not dict:
        return None
    value = document.get("id")
    remote_id = str(value) if type(value) is int and value > 0 else ""
    return remote_id if _REMOTE_ID.fullmatch(remote_id) else None


def _safe_path(path: str) -> bool:
    return (
        _PATH.fullmatch(path) is not None
        and "//" not in path
        and all(part not in {".", ".."} for part in path.split("/"))
    )


__all__ = [
    "MAX_GITHUB_INLINE_COMMENTS",
    "GithubCommentError",
    "GithubCommentPublisher",
    "GithubCommentReceipt",
    "GithubCommentSuppression",
    "GithubInlineProjection",
    "PullRequestHeadResolver",
]
