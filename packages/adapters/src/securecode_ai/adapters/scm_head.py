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


class GithubCommitLineageResolver:
    """Read one complete, exact, first-parent history from GitHub compare."""

    def __init__(self, api: GitHubApi) -> None:
        if type(api) is not GitHubApi:
            raise ValueError("GitHub lineage resolver configuration is invalid")
        self._api = api

    def __call__(
        self, installation_id: str, repository_id: str, base_sha: str, head_sha: str
    ) -> tuple[str, ...]:
        if any(_ID.fullmatch(value) is None for value in (installation_id, repository_id)) or any(
            _SHA.fullmatch(value) is None for value in (base_sha, head_sha)
        ):
            raise SCMHeadUnavailable("GitHub commit lineage is unavailable")
        try:
            repository = self._api.request(
                "GET", f"/repositories/{repository_id}", installation_id=installation_id
            ).document
            if repository is None:
                raise ValueError
            full_name = repository.get("full_name")
            if (
                type(full_name) is not str
                or re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", full_name) is None
            ):
                raise ValueError
            owner, name = full_name.split("/", 1)
            comparison = self._api.request(
                "GET",
                f"/repos/{owner}/{name}/compare/{base_sha}...{head_sha}",
                installation_id=installation_id,
            ).document
            if comparison is None:
                raise ValueError
            status = comparison.get("status")
            ahead = comparison.get("ahead_by")
            behind = comparison.get("behind_by")
            total = comparison.get("total_commits")
            commits = comparison.get("commits")
            base_commit = comparison.get("base_commit")
            if (
                type(commits) is not list
                or len(commits) > 250
                or type(ahead) is not int
                or type(behind) is not int
                or type(total) is not int
                or ahead != total
                or behind != 0
                or total != len(commits)
                or type(base_commit) is not dict
                or base_commit.get("sha") != base_sha
            ):
                raise ValueError
            if base_sha == head_sha:
                if status != "identical" or commits:
                    raise ValueError
                return (base_sha,)
            if status != "ahead" or not commits:
                raise ValueError
            lineage = [base_sha]
            for item in commits:
                if type(item) is not dict:
                    raise ValueError
                commit_sha = item.get("sha")
                commit = item.get("commit")
                parents = commit.get("parents") if type(commit) is dict else None
                if (
                    type(commit_sha) is not str
                    or _SHA.fullmatch(commit_sha) is None
                    or type(parents) is not list
                    or not parents
                    or type(parents[0]) is not dict
                    or parents[0].get("sha") != lineage[-1]
                    or commit_sha in lineage
                ):
                    raise ValueError
                lineage.append(commit_sha)
            if lineage[-1] != head_sha:
                raise ValueError
            return tuple(lineage)
        except (GitHubError, TypeError, ValueError):
            raise SCMHeadUnavailable("GitHub commit lineage is unavailable") from None


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


class GitlabCommitLineageResolver:
    """Read a bounded, exact first-parent history from GitLab compare."""

    def __init__(self, api: GitlabRestAPI) -> None:
        if type(api) is not GitlabRestAPI:
            raise ValueError("GitLab lineage resolver configuration is invalid")
        self._api = api

    def __call__(self, project_id: str, base_sha: str, head_sha: str) -> tuple[str, ...]:
        if _ID.fullmatch(project_id) is None or any(
            _SHA.fullmatch(value) is None for value in (base_sha, head_sha)
        ):
            raise SCMHeadUnavailable("GitLab commit lineage is unavailable")
        try:
            return self._api.compare_commit_lineage(
                project_id=project_id,
                base_sha=base_sha,
                head_sha=head_sha,
            )
        except GitlabAPIError:
            raise SCMHeadUnavailable("GitLab commit lineage is unavailable") from None


__all__ = [
    "GithubCommitLineageResolver",
    "GithubPullRequestHeadResolver",
    "GitlabCommitLineageResolver",
    "GitlabMergeRequestHeadResolver",
    "SCMHeadUnavailable",
]
