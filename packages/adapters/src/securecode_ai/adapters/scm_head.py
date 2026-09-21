"""Authenticated exact-head resolvers for SCM admission and publication."""

from __future__ import annotations

import re

from .github_api import GitHubApi, GitHubError
from .gitlab_api import GitlabAPIError, GitlabRestAPI

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")


class SCMHeadUnavailable(RuntimeError):
    """Redacted failure to read the current SCM revision."""


class GithubPullRequestHeadResolver:
    def __init__(self, api: GitHubApi) -> None:
        if type(api) is not GitHubApi:
            raise ValueError("GitHub head resolver configuration is invalid")
        self._api = api

    def __call__(self, installation_id: str, repository_id: str, change_id: str) -> str:
        if any(
            _ID.fullmatch(value) is None for value in (installation_id, repository_id, change_id)
        ):
            raise SCMHeadUnavailable("GitHub head is unavailable")
        try:
            response = self._api.request(
                "GET",
                f"/repositories/{repository_id}/pulls/{change_id}",
                installation_id=installation_id,
            )
            document = response.document
            if document is None:
                raise ValueError
            head = document.get("head")
            if not isinstance(head, dict):
                raise ValueError
            sha = head.get("sha")
            if not isinstance(sha, str) or _SHA.fullmatch(sha) is None:
                raise ValueError
            return sha
        except (GitHubError, TypeError, ValueError):
            raise SCMHeadUnavailable("GitHub head is unavailable") from None


class GitlabMergeRequestHeadResolver:
    def __init__(self, api: GitlabRestAPI) -> None:
        if type(api) is not GitlabRestAPI:
            raise ValueError("GitLab head resolver configuration is invalid")
        self._api = api

    def __call__(self, project_id: str, merge_request_iid: str) -> str:
        if any(_ID.fullmatch(value) is None for value in (project_id, merge_request_iid)):
            raise SCMHeadUnavailable("GitLab head is unavailable")
        try:
            sha = self._api.merge_request_head(
                project_id=project_id,
                merge_request_iid=merge_request_iid,
            )
        except GitlabAPIError:
            raise SCMHeadUnavailable("GitLab head is unavailable") from None
        if _SHA.fullmatch(sha) is None:
            raise SCMHeadUnavailable("GitLab head is unavailable")
        return sha


__all__ = [
    "GithubPullRequestHeadResolver",
    "GitlabMergeRequestHeadResolver",
    "SCMHeadUnavailable",
]
