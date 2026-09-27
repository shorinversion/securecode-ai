from __future__ import annotations

from typing import cast

import pytest
from securecode_ai.adapters.github_annotations import (
    GithubAnnotationProjection,
    GithubAnnotationReceipt,
)
from securecode_ai.adapters.github_api import GitHubApi, GitHubError, GitHubResponse
from securecode_ai.adapters.github_comments import (
    MAX_GITHUB_INLINE_COMMENTS,
    GithubCommentError,
    GithubCommentPublisher,
    GithubCommentReceipt,
    GithubCommentSuppression,
)
from securecode_ai.core.scm_run_state import (
    PublicationDisposition,
    SCMRunLifecycle,
    SCMRunPublicationReceipt,
)

HEAD = "a" * 40
IDENTITY_HASH = "b" * 64
REPOSITORY_PATH = "/repos/example/project"


class FakeApi:
    def __init__(self, responses: list[GitHubResponse]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, object] | None]] = []

    def repository_path_for_id(self, installation_id: str, repository_id: str) -> str:
        assert installation_id == "installation-1"
        assert repository_id == "42"
        return REPOSITORY_PATH

    def request(
        self,
        method: str,
        path: str,
        *,
        installation_id: str,
        document: dict[str, object] | None = None,
        idempotency_key: str | None = None,
    ) -> GitHubResponse:
        assert installation_id == "installation-1"
        if idempotency_key is not None:
            assert idempotency_key
        self.calls.append((method, path, document))
        return self.responses.pop(0)


class HeadSequence:
    def __init__(self, values: list[str]) -> None:
        self.values = values

    def __call__(self, installation_id: str, repository_id: str, change_id: str) -> str:
        assert (installation_id, repository_id, change_id) == ("installation-1", "42", "7")
        return self.values.pop(0)


def response(status: int, document: dict[str, object] | list[object] | None) -> GitHubResponse:
    return GitHubResponse(status, document, {})


def projection(
    finding_id: str = "finding-1", *, repository_id: str = "42"
) -> GithubAnnotationProjection:
    return GithubAnnotationProjection(
        tenant_id="tenant-1",
        repository_id=repository_id,
        head_sha=HEAD,
        execution_identity_hash=IDENTITY_HASH,
        finding_id=finding_id,
        cwe_id="CWE-89",
        path="src/app.py",
        start_line=4,
        end_line=4,
        title="SQL injection",
        message="Use a parameterized query.",
    )


def annotation_receipt(*items: GithubAnnotationProjection) -> GithubAnnotationReceipt:
    publication = SCMRunPublicationReceipt(
        disposition=PublicationDisposition.AUTHORIZED,
        run_id="run-1",
        execution_identity_hash=IDENTITY_HASH,
        head_sha=HEAD,
        current_head_sha=HEAD,
        lifecycle=SCMRunLifecycle.ADMITTED,
        outcome=None,
        state_version=1,
    )
    return GithubAnnotationReceipt(publication, tuple(items), ())


def publisher(api: FakeApi, head: str = HEAD) -> GithubCommentPublisher:
    return GithubCommentPublisher(cast(GitHubApi, api), pull_request_head=lambda *_: head)


def invoke(
    api: FakeApi,
    *,
    head: str = HEAD,
    receipt: GithubAnnotationReceipt | None = None,
) -> GithubCommentReceipt:
    return publisher(api, head).publish(
        installation_id="installation-1",
        repository_id="42",
        change_id="7",
        expected_head=HEAD,
        external_id="run-1",
        summary="Audit completed",
        delivery_key="delivery-1",
        annotation_receipt=receipt,
    )


def test_creates_idempotent_summary_comment() -> None:
    body = "Audit completed\n\n<!-- securecode-ai-summary:run-1 -->"
    api = FakeApi(
        [
            response(200, []),
            response(201, {"id": 1, "body": body}),
            response(200, []),
        ]
    )

    receipt = invoke(api)

    assert receipt.status == "WRITTEN"
    assert receipt.summary_id == "1"
    assert api.calls[1][0] == "POST"
    assert api.calls[1][2] == {"body": body}


def test_updates_existing_summary_by_marker() -> None:
    previous = "Old summary\n\n<!-- securecode-ai-summary:run-1 -->"
    updated = "Audit completed\n\n<!-- securecode-ai-summary:run-1 -->"
    api = FakeApi(
        [
            response(200, [{"id": 2, "body": previous}]),
            response(200, {"id": 2, "body": updated}),
            response(200, []),
        ]
    )

    receipt = invoke(api)

    assert receipt.summary_id == "2"
    assert api.calls[1][0] == "PATCH"
    assert api.calls[1][2] == {"body": updated}


def test_stale_head_suppresses_without_writes() -> None:
    api = FakeApi([])

    receipt = invoke(api, head="c" * 40)

    assert receipt.status == "STALE_SUPPRESSED"
    assert api.calls == []


def test_posts_only_authorized_annotation_projection() -> None:
    summary_body = "Audit completed\n\n<!-- securecode-ai-summary:run-1 -->"
    inline_body = (
        "SQL injection\n\nUse a parameterized query.\n\n<!-- securecode-ai-inline:finding-1 -->"
    )
    api = FakeApi(
        [
            response(200, []),
            response(201, {"id": 1, "body": summary_body}),
            response(200, []),
            response(
                201,
                {
                    "id": 3,
                    "body": inline_body,
                    "commit_id": HEAD,
                    "path": "src/app.py",
                    "line": 4,
                    "side": "RIGHT",
                },
            ),
        ]
    )

    receipt = invoke(api, receipt=annotation_receipt(projection()))

    assert receipt.inline_written == ("finding-1",)
    assert api.calls[-1][2] == {
        "body": inline_body,
        "commit_id": HEAD,
        "path": "src/app.py",
        "line": 4,
        "side": "RIGHT",
    }


def test_existing_inline_comment_is_deduplicated() -> None:
    body = "Audit completed\n\n<!-- securecode-ai-summary:run-1 -->"
    api = FakeApi(
        [
            response(200, []),
            response(201, {"id": 1, "body": body}),
            response(
                200,
                [
                    {
                        "body": "SQL injection\n\n<!-- securecode-ai-inline:finding-1 -->",
                        "commit_id": HEAD,
                        "path": "src/app.py",
                        "line": 4,
                        "side": "RIGHT",
                    }
                ],
            ),
        ]
    )

    receipt = invoke(api, receipt=annotation_receipt(projection()))

    assert receipt.inline_written == ()
    assert receipt.suppressions == (("finding-1", GithubCommentSuppression.EXISTING),)
    assert len(api.calls) == 3


def test_head_change_after_summary_compensates_and_blocks_inline_write() -> None:
    summary_body = "Audit completed\n\n<!-- securecode-ai-summary:run-1 -->"
    api = FakeApi(
        [
            response(200, []),
            response(201, {"id": 1, "body": summary_body}),
            response(200, {"id": 1, "body": summary_body}),
            response(204, None),
        ]
    )
    guarded = GithubCommentPublisher(
        cast(GitHubApi, api),
        pull_request_head=HeadSequence([HEAD, HEAD, "c" * 40]),
    )

    receipt = guarded.publish(
        installation_id="installation-1",
        repository_id="42",
        change_id="7",
        expected_head=HEAD,
        external_id="run-1",
        summary="Audit completed",
        delivery_key="delivery-1",
        annotation_receipt=annotation_receipt(projection()),
    )

    assert receipt.status == "STALE_SUPPRESSED"
    assert receipt.inline_written == ()
    assert api.calls[-1][0] == "DELETE"
    assert not any(call[0] == "POST" and "/pulls/" in call[1] for call in api.calls)


def test_oversized_or_duplicate_annotation_receipt_is_rejected_before_io() -> None:
    api = FakeApi([])
    oversized = annotation_receipt(
        *(projection(f"finding-{index}") for index in range(MAX_GITHUB_INLINE_COMMENTS + 1))
    )

    with pytest.raises(GithubCommentError):
        invoke(api, receipt=oversized)

    assert api.calls == []


def test_annotation_for_another_repository_is_rejected_before_io() -> None:
    api = FakeApi([])

    with pytest.raises(GithubCommentError):
        invoke(api, receipt=annotation_receipt(projection(repository_id="84")))

    assert api.calls == []


@pytest.mark.parametrize(
    "document",
    [
        [
            {"id": 1, "body": "x\n\n<!-- securecode-ai-summary:run-1 -->"},
            {"id": 2, "body": "x\n\n<!-- securecode-ai-summary:run-1 -->"},
        ],
        ["malformed"],
    ],
)
def test_ambiguous_or_malformed_summary_listing_is_rejected(document: list[object]) -> None:
    api = FakeApi([response(200, document)])

    with pytest.raises(GitHubError):
        invoke(api)


@pytest.mark.parametrize("status_document", [(201, None), (201, {"id": 0}), (500, {"id": 1})])
def test_invalid_summary_write_receipt_is_rejected(
    status_document: tuple[int, dict[str, object] | None],
) -> None:
    status, document = status_document
    api = FakeApi([response(200, []), response(status, document)])

    with pytest.raises(GitHubError):
        invoke(api)
