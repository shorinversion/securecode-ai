"""Exact provider lineage resolution used by connected SCM policy."""

from __future__ import annotations

import json

import pytest
from securecode_ai.adapters.github_api import GitHubApi, GitHubResponse
from securecode_ai.adapters.gitlab_api import GitlabHTTPResponse, GitlabRestAPI
from securecode_ai.adapters.scm_head import (
    GithubCommitLineageResolver,
    GitlabCommitLineageResolver,
    SCMHeadUnavailable,
)

BASE = "a" * 40
MIDDLE = "b" * 40
HEAD = "c" * 40


class _Tokens:
    def token(self, installation_id: str) -> str:
        return "token-for-" + installation_id


def _api(
    documents: list[dict[str, object]], monkeypatch: pytest.MonkeyPatch
) -> tuple[GitHubApi, list[tuple[str, str, str]]]:
    api = GitHubApi("https://api.github.com", _Tokens())
    calls: list[tuple[str, str, str]] = []

    def request(
        method: str,
        path: str,
        *,
        installation_id: str,
        document: dict[str, object] | None = None,
        idempotency_key: str | None = None,
    ) -> GitHubResponse:
        calls.append((method, path, installation_id))
        return GitHubResponse(200, documents.pop(0), {})

    monkeypatch.setattr(api, "request", request)
    return api, calls


def _comparison(*, status: str = "ahead", behind: int = 0) -> dict[str, object]:
    return {
        "ahead_by": 2,
        "base_commit": {"sha": BASE},
        "behind_by": behind,
        "commits": [
            {"sha": MIDDLE, "commit": {"parents": [{"sha": BASE}]}},
            {"sha": HEAD, "commit": {"parents": [{"sha": MIDDLE}]}},
        ],
        "status": status,
        "total_commits": 2,
    }


def test_github_commit_lineage_uses_authenticated_compare_and_checks_parent_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, calls = _api([{"full_name": "securecode/service"}, _comparison()], monkeypatch)
    resolver = GithubCommitLineageResolver(api)

    lineage = resolver("installation-1", "42", BASE, HEAD)

    assert lineage == (BASE, MIDDLE, HEAD)
    assert calls == [
        ("GET", "/repositories/42", "installation-1"),
        ("GET", f"/repos/securecode/service/compare/{BASE}...{HEAD}", "installation-1"),
    ]


@pytest.mark.parametrize(
    "comparison",
    (
        _comparison(status="diverged"),
        _comparison(behind=1),
        {
            **_comparison(),
            "commits": [
                {"sha": MIDDLE, "commit": {"parents": [{"sha": "d" * 40}]}},
                {"sha": HEAD, "commit": {"parents": [{"sha": MIDDLE}]}},
            ],
        },
        {**_comparison(), "total_commits": 3},
    ),
)
def test_github_commit_lineage_rejects_divergence_and_incomplete_history(
    monkeypatch: pytest.MonkeyPatch,
    comparison: dict[str, object],
) -> None:
    api, _ = _api([{"full_name": "securecode/service"}, comparison], monkeypatch)
    resolver = GithubCommitLineageResolver(api)

    with pytest.raises(SCMHeadUnavailable):
        resolver("installation-1", "42", BASE, HEAD)


def test_github_commit_lineage_rejects_untrusted_repository_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, _ = _api([{"full_name": "../attacker/repo"}], monkeypatch)
    resolver = GithubCommitLineageResolver(api)

    with pytest.raises(SCMHeadUnavailable):
        resolver("installation-1", "42", BASE, HEAD)


def test_gitlab_commit_lineage_resolver_redacts_provider_failures() -> None:
    response = {
        "compare_timeout": False,
        "commits": [
            {"id": MIDDLE, "parent_ids": [BASE]},
            {"id": HEAD, "parent_ids": [MIDDLE]},
        ],
        "commit": {"id": HEAD},
    }
    api = GitlabRestAPI(
        base_url="https://gitlab.example/api/v4",
        private_token="private-token",
        requester=lambda request: GitlabHTTPResponse(
            200, request.url, json.dumps(response).encode("utf-8")
        ),
    )

    resolver = GitlabCommitLineageResolver(api)

    assert resolver("project-1", BASE, HEAD) == (BASE, MIDDLE, HEAD)


def test_gitlab_commit_lineage_resolver_returns_only_safe_failure() -> None:
    api = GitlabRestAPI(
        base_url="https://gitlab.example/api/v4",
        private_token="private-token",
        requester=lambda request: GitlabHTTPResponse(503, request.url, b"private details"),
    )

    resolver = GitlabCommitLineageResolver(api)

    with pytest.raises(SCMHeadUnavailable, match="GitLab commit lineage is unavailable"):
        resolver("project-1", BASE, HEAD)
