from __future__ import annotations

from typing import Any

import pytest
from securecode_ai.adapters.github_api import GitHubResponse
from securecode_ai.adapters.github_comments import (
    GithubCommentPublisher,
    GithubCommentSuppression,
    GithubInlineProjection,
    MAX_GITHUB_INLINE_COMMENTS,
)


HEAD = "a" * 40


class FakeApi:
    def __init__(self, responses: list[GitHubResponse]) -> None:
        self.responses = responses
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, path: str, **kwargs: object) -> GitHubResponse:
        self.calls.append({"method": method, "path": path, **kwargs})
        return self.responses.pop(0)


def response(status: int, document: dict[str, object] | None) -> GitHubResponse:
    return GitHubResponse(status, document, {})


def publisher(api: FakeApi, head: str = HEAD) -> GithubCommentPublisher:
    return GithubCommentPublisher(api, pull_request_head=lambda *_: head)  # type: ignore[arg-type]


def invoke(api: FakeApi, **kwargs: object) -> object:
    return publisher(api).publish(
        installation_id="i",
        repository_id="42",
        change_id="7",
        expected_head=HEAD,
        external_id="run-1",
        summary="summary",
        delivery_key="delivery",
        **kwargs,
    )


def test_creates_summary() -> None:
    api = FakeApi([response(200, []), response(201, {"id": 1}), response(200, [])])
    receipt = invoke(api)
    assert receipt.summary_id == "1" and api.calls[1]["method"] == "POST"


def test_updates_existing_summary() -> None:
    api = FakeApi(
        [
            response(200, [{"id": 2, "body": "<!-- securecode-ai-summary:run-1 -->"}]),
            response(200, {"id": 2}),
            response(200, []),
        ]
    )
    receipt = invoke(api)
    assert receipt.summary_id == "2" and api.calls[1]["method"] == "PUT"


def test_stale_head_makes_no_api_requests() -> None:
    api = FakeApi([])
    receipt = publisher(api, "b" * 40).publish(
        installation_id="i",
        repository_id="42",
        change_id="7",
        expected_head=HEAD,
        external_id="run-1",
        summary="summary",
        delivery_key="delivery",
    )
    assert receipt.status == "STALE_SUPPRESSED" and not api.calls


def test_posts_verified_inline() -> None:
    api = FakeApi(
        [response(200, []), response(201, {"id": 1}), response(200, []), response(201, {"id": 3})]
    )
    receipt = invoke(api, inline=(GithubInlineProjection("f-1", "a.py", 4, "confirmed"),))
    assert receipt.inline_written == ("f-1",) and api.calls[-1]["document"]["side"] == "RIGHT"


def test_existing_inline_is_suppressed() -> None:
    api = FakeApi(
        [
            response(200, []),
            response(201, {"id": 1}),
            response(200, [{"id": 3, "body": "<!-- securecode-ai-inline:f-1 -->"}]),
        ]
    )
    receipt = invoke(api, inline=(GithubInlineProjection("f-1", "a.py", 4, "confirmed"),))
    assert receipt.suppressions == (("f-1", GithubCommentSuppression.EXISTING),)


def test_volume_limit_is_visible() -> None:
    inline = tuple(
        GithubInlineProjection(f"f-{item}", "a.py", item + 1, "confirmed")
        for item in range(MAX_GITHUB_INLINE_COMMENTS + 1)
    )
    api = FakeApi(
        [response(200, []), response(201, {"id": 1}), response(200, [])]
        + [response(201, {"id": item + 10}) for item in range(MAX_GITHUB_INLINE_COMMENTS)]
    )
    receipt = invoke(api, inline=inline)
    assert len(receipt.inline_written) == MAX_GITHUB_INLINE_COMMENTS
    assert receipt.suppressions[-1][1] is GithubCommentSuppression.VOLUME_LIMIT


@pytest.mark.parametrize(
    "path", ["", "../a.py", "a//b.py", ".hidden", "a.py/../b", "a\\b", "a b", "/a.py"]
)
def test_rejects_unsafe_inline_paths(path: str) -> None:
    with pytest.raises(ValueError):
        GithubInlineProjection("f", path, 1, "body")


@pytest.mark.parametrize("line", [0, -1, True, "1"])
def test_rejects_invalid_inline_lines(line: object) -> None:
    with pytest.raises(ValueError):
        GithubInlineProjection("f", "a.py", line, "body")  # type: ignore[arg-type]


@pytest.mark.parametrize("document", [None, {}, {"id": "1"}, {"id": 0}])
def test_rejects_invalid_summary_receipts(document: dict[str, object] | None) -> None:
    api = FakeApi([response(200, []), response(201, document)])
    with pytest.raises(Exception):
        invoke(api)


@pytest.mark.parametrize(
    "comments",
    [
        [
            {"id": 1, "body": "<!-- securecode-ai-summary:run-1 -->"},
            {"id": 2, "body": "<!-- securecode-ai-summary:run-1 -->"},
        ],
        ["bad"],
    ],
)
def test_rejects_ambiguous_or_malformed_summary_listing(comments: list[object]) -> None:
    api = FakeApi([response(200, comments)])  # type: ignore[arg-type]
    with pytest.raises(Exception):
        invoke(api)
