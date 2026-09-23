"""Tenant-bound dispatch to provider-authenticated commit lineage endpoints."""

from __future__ import annotations

from typing import cast

import pytest
from securecode_ai.adapters.scm_head import (
    GithubCommitLineageResolver,
    GitlabCommitLineageResolver,
    SCMHeadUnavailable,
)
from securecode_ai.server.scm_runtime import SCMRunCommitLineageResolver
from securecode_ai.server.scm_state import SCMProviderTarget, SqliteSCMRunState

BASE = "a" * 40
HEAD = "b" * 40
IDENTITY = "c" * 64


class _State:
    def __init__(self, provider: str) -> None:
        self.target = SCMProviderTarget(
            provider=provider,
            installation_id="installation-1",
            repository_id="repository-1",
            change_id="change-1",
            execution_identity_hash=IDENTITY,
        )

    def provider_target(self, run_id: str) -> SCMProviderTarget:
        assert run_id == "run-1"
        return self.target


class _GithubLineage:
    def __call__(
        self, installation_id: str, repository_id: str, base_sha: str, head_sha: str
    ) -> tuple[str, ...]:
        assert (installation_id, repository_id, base_sha, head_sha) == (
            "installation-1",
            "repository-1",
            BASE,
            HEAD,
        )
        return (BASE, HEAD)


class _GitlabLineage:
    def __call__(self, project_id: str, base_sha: str, head_sha: str) -> tuple[str, ...]:
        assert (project_id, base_sha, head_sha) == ("repository-1", BASE, HEAD)
        return (BASE, HEAD)


@pytest.mark.parametrize("provider", ("github", "gitlab"))
def test_lineage_dispatch_uses_only_the_provider_bound_to_run(provider: str) -> None:
    resolver = SCMRunCommitLineageResolver(
        run_state=cast(SqliteSCMRunState, _State(provider)),
        github=cast(GithubCommitLineageResolver, _GithubLineage()),
        gitlab=cast(GitlabCommitLineageResolver, _GitlabLineage()),
    )

    assert resolver(
        run_id="run-1",
        execution_identity_hash=IDENTITY,
        base_sha=BASE,
        head_sha=HEAD,
    ) == (BASE, HEAD)


def test_lineage_dispatch_rejects_identity_mismatch_and_unknown_provider() -> None:
    resolver = SCMRunCommitLineageResolver(
        run_state=cast(SqliteSCMRunState, _State("github")),
        github=cast(GithubCommitLineageResolver, _GithubLineage()),
        gitlab=None,
    )

    with pytest.raises(SCMHeadUnavailable):
        resolver(
            run_id="run-1",
            execution_identity_hash="d" * 64,
            base_sha=BASE,
            head_sha=HEAD,
        )
    with pytest.raises(SCMHeadUnavailable):
        SCMRunCommitLineageResolver(
            run_state=cast(SqliteSCMRunState, _State("other")),
            github=None,
            gitlab=None,
        )(
            run_id="run-1",
            execution_identity_hash=IDENTITY,
            base_sha=BASE,
            head_sha=HEAD,
        )
