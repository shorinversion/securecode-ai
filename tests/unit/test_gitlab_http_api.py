"""P7.5 named HTTP client surface retains the hardened REST implementation."""

from __future__ import annotations

import pytest
from securecode_ai.adapters.gitlab_api import GitlabRestAPI
from securecode_ai.adapters.gitlab_http_api import GitlabAPIError, GitlabHttpAPI


def test_named_client_is_the_existing_hardened_rest_implementation() -> None:
    assert GitlabHttpAPI is GitlabRestAPI


def test_named_client_satisfies_publication_protocol() -> None:
    assert isinstance(GitlabHttpAPI, type)
    assert all(
        callable(getattr(GitlabHttpAPI, name))
        for name in (
            "upsert_merge_request_note",
            "create_merge_request_discussion",
            "set_external_status",
        )
    )


@pytest.mark.parametrize(
    "base_url",
    [
        "http://gitlab.example/api/v4",
        "https://user@gitlab.example",
        "https://gitlab.example/api/v4?x=1",
    ],
)
def test_named_client_preserves_strict_transport_configuration(base_url: str) -> None:
    with pytest.raises(GitlabAPIError):
        GitlabHttpAPI(base_url=base_url, private_token="token")
