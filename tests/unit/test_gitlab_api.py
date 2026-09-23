"""P7.5 bounded authenticated GitLab REST transport contracts."""

from __future__ import annotations

import json
from typing import Any

import pytest
from securecode_ai.adapters.gitlab_api import (
    GitlabAPIError,
    GitlabAPIErrorCode,
    GitlabHTTPResponse,
    GitlabRestAPI,
)
from securecode_ai.adapters.gitlab_ci import (
    GitlabExternalStatus,
    GitlabExternalStatusProjection,
)
from securecode_ai.adapters.gitlab_discussions import GitlabDiscussionProjection

BASE_URL = "https://gitlab.example/api/v4"
TOKEN = "private-token-canary"
HEAD = "a" * 40
BASE = "b" * 40
START = "c" * 40
HASH = "d" * 64


class _Requester:
    def __init__(self, responses: list[GitlabHTTPResponse]) -> None:
        self.responses = responses
        self.calls: list[Any] = []

    def __call__(self, request: Any) -> GitlabHTTPResponse:
        self.calls.append(request)
        if not self.responses:
            raise RuntimeError("unexpected extra request")
        return self.responses.pop(0)


def _response(status: int, payload: object, *, url: str = BASE_URL) -> GitlabHTTPResponse:
    return GitlabHTTPResponse(status, url, json.dumps(payload).encode("utf-8"))


def _api(responses: list[GitlabHTTPResponse]) -> tuple[GitlabRestAPI, _Requester]:
    requester = _Requester(responses)
    return GitlabRestAPI(base_url=BASE_URL, private_token=TOKEN, requester=requester), requester


def _summary(key: str = "note-key") -> str:
    return f"<!-- securecode-ai-gitlab-summary:{key} -->\n## SecureCode AI: PASS\n"


def _discussion() -> GitlabDiscussionProjection:
    return GitlabDiscussionProjection(
        finding_id="finding-1",
        cwe_id="CWE-89",
        new_path="src/app.py",
        new_line=9,
        base_sha=BASE,
        start_sha=START,
        head_sha=HEAD,
        body="Confirmed new-code finding. Review before merge.",
    )


def _external_status() -> GitlabExternalStatusProjection:
    return GitlabExternalStatusProjection(
        idempotency_key="status-key",
        execution_identity_hash=HASH,
        head_sha=HEAD,
        status=GitlabExternalStatus.PASSED,
        publish=True,
        merge_authority=False,
        safe_summary="SecureCode AI passed",
    )


def test_summary_upsert_uses_exact_marker_and_private_token_only_in_request() -> None:
    api, requester = _api([_response(200, []), _response(201, {"id": 17})])

    result = api.upsert_merge_request_note(
        project_id="project-1",
        merge_request_iid="42",
        idempotency_key="note-key",
        body=_summary(),
    )

    assert result == "17"
    assert [call.method for call in requester.calls] == ["GET", "POST"]
    assert requester.calls[1].url.endswith("/projects/project-1/merge_requests/42/notes")
    assert json.loads(requester.calls[1].body or b"{}") == {"body": _summary()}
    assert dict(requester.calls[1].headers)["PRIVATE-TOKEN"] == TOKEN
    assert dict(requester.calls[1].headers)["Idempotency-Key"] == "note-key"


def test_summary_updates_only_one_existing_exact_marker_note() -> None:
    key = "note-key"
    marker = f"<!-- securecode-ai-gitlab-summary:{key} -->"
    api, requester = _api(
        [
            _response(200, [{"id": 18, "body": marker + "\nold"}]),
            _response(200, {"id": 18}),
        ]
    )

    assert (
        api.upsert_merge_request_note(
            project_id="project-1",
            merge_request_iid="42",
            idempotency_key=key,
            body=_summary(key),
        )
        == "18"
    )
    assert [call.method for call in requester.calls] == ["GET", "PUT"]
    assert requester.calls[1].url.endswith("/notes/18")


def test_discussion_and_optional_external_status_use_bounded_exact_payloads() -> None:
    discussion = _discussion()
    marker = "<!-- securecode-ai-gitlab-discussion:discussion-key -->"
    discussion_body = marker + "\n" + discussion.body
    discussion_position = {
        "base_sha": BASE,
        "head_sha": HEAD,
        "new_line": 9,
        "new_path": "src/app.py",
        "old_path": "src/app.py",
        "position_type": "text",
        "start_sha": START,
    }
    external_status = _external_status()
    discussion_id_value = "e" * 40
    api, requester = _api(
        [
            _response(200, []),
            _response(
                201,
                {
                    "id": discussion_id_value,
                    "notes": [{"body": discussion_body, "position": discussion_position}],
                },
            ),
            _response(200, []),
            _response(
                201,
                {
                    "id": 32,
                    "sha": HEAD,
                    "name": "securecode-ai:status-key",
                    "status": "success",
                    "description": external_status.safe_summary,
                },
            ),
        ]
    )

    discussion_id = api.create_merge_request_discussion(
        project_id="project-1",
        merge_request_iid="42",
        idempotency_key="discussion-key",
        projection=discussion,
    )
    status_id = api.set_external_status(
        project_id="project-1",
        merge_request_iid="42",
        idempotency_key="status-key",
        projection=external_status,
    )

    assert (discussion_id, status_id) == (discussion_id_value, "32")
    assert [call.method for call in requester.calls] == ["GET", "POST", "GET", "POST"]
    discussion_payload = json.loads(requester.calls[1].body or b"{}")
    assert discussion_payload == {"body": discussion_body, "position": discussion_position}
    assert requester.calls[3].url.endswith(f"/statuses/{HEAD}")
    assert json.loads(requester.calls[3].body or b"{}") == {
        "description": external_status.safe_summary,
        "name": "securecode-ai:status-key",
        "state": "success",
    }


def test_compare_commit_lineage_requires_exact_first_parent_chain() -> None:
    api, requester = _api(
        [
            _response(
                200,
                {
                    "compare_timeout": False,
                    "commits": [
                        {"id": START, "parent_ids": [BASE]},
                        {"id": HEAD, "parent_ids": [START, "e" * 40]},
                    ],
                    "commit": {"id": HEAD},
                },
            )
        ]
    )

    assert api.compare_commit_lineage(project_id="project-1", base_sha=BASE, head_sha=HEAD) == (
        BASE,
        START,
        HEAD,
    )
    request = requester.calls[0]
    assert request.method == "GET"
    assert f"from={BASE}&to={HEAD}&straight=true" in request.url
    assert dict(request.headers)["PRIVATE-TOKEN"] == TOKEN


@pytest.mark.parametrize(
    "document",
    (
        {
            "compare_timeout": True,
            "commits": [{"id": HEAD, "parent_ids": [BASE]}],
            "commit": {"id": HEAD},
        },
        {
            "compare_timeout": False,
            "commits": [{"id": HEAD, "parent_ids": [START]}],
            "commit": {"id": HEAD},
        },
        {
            "compare_timeout": False,
            "commits": [{"id": START, "parent_ids": [BASE]}],
            "commit": {"id": HEAD},
        },
    ),
)
def test_compare_commit_lineage_rejects_incomplete_or_unconnected_history(
    document: object,
) -> None:
    api, _ = _api([_response(200, document)])

    with pytest.raises(GitlabAPIError) as error:
        api.compare_commit_lineage(project_id="project-1", base_sha=BASE, head_sha=HEAD)

    assert error.value.code is GitlabAPIErrorCode.RESPONSE_INVALID


def test_retry_and_redirect_failures_are_redacted_without_automatic_duplicate_post() -> None:
    api, requester = _api([_response(429, {"message": "retry"})])

    with pytest.raises(GitlabAPIError) as retry:
        api.create_merge_request_discussion(
            project_id="project-1",
            merge_request_iid="42",
            idempotency_key="discussion-key",
            projection=_discussion(),
        )

    assert retry.value.code is GitlabAPIErrorCode.RETRYABLE
    assert len(requester.calls) == 1

    redirect_api, _ = _api([_response(302, {}, url="https://evil.example/api/v4")])
    with pytest.raises(GitlabAPIError) as redirected:
        redirect_api.upsert_merge_request_note(
            project_id="project-1",
            merge_request_iid="42",
            idempotency_key="note-key",
            body=_summary(),
        )

    assert redirected.value.code is GitlabAPIErrorCode.REDIRECT_BLOCKED
    assert TOKEN not in str(redirected.value)


def test_invalid_base_url_and_response_identifier_fail_closed() -> None:
    with pytest.raises(GitlabAPIError) as insecure:
        GitlabRestAPI(base_url="http://gitlab.example/api/v4", private_token=TOKEN)

    assert insecure.value.code is GitlabAPIErrorCode.INVALID_CONFIGURATION

    api, _ = _api([_response(200, []), _response(201, {"id": "17"})])
    with pytest.raises(GitlabAPIError) as invalid:
        api.upsert_merge_request_note(
            project_id="project-1",
            merge_request_iid="42",
            idempotency_key="note-key",
            body=_summary(),
        )

    assert invalid.value.code is GitlabAPIErrorCode.RESPONSE_INVALID
