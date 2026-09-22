"""P5.4/P5.5 exact-head, crash-reconciling GitHub check writer behavior."""

from __future__ import annotations

from typing import Any

import pytest
from securecode_ai.adapters.github_api import GitHubError, GitHubResponse, repository_path
from securecode_ai.adapters.github_writer import GitHubWriter

INSTALLATION = "installation-1"
OWNER = "example-owner"
REPO = "example-repo"
HEAD = "a" * 40
OTHER_HEAD = "b" * 40
EXTERNAL_ID = "run-2026-09-22-001"
DELIVERY_KEY = "delivery-2026-09-22-001"
CHECK_NAME = "SecureCode AI"


class _FakeApi:
    """Record requests and replay canned responses without any network."""

    def __init__(self, responses: list[GitHubResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        installation_id: str,
        document: dict[str, object] | None = None,
        idempotency_key: str | None = None,
    ) -> GitHubResponse:
        self.calls.append(
            {
                "method": method,
                "path": path,
                "installation_id": installation_id,
                "document": document,
                "idempotency_key": idempotency_key,
            }
        )
        if not self._responses:
            raise AssertionError("unexpected additional request")
        return self._responses.pop(0)


def _head_response(status: int = 200, sha: str = HEAD) -> GitHubResponse:
    return GitHubResponse(
        status=status,
        document={"object": {"sha": sha}},
        headers={},
    )


def _listing_response(entries: list[dict[str, object]]) -> GitHubResponse:
    return GitHubResponse(
        status=200,
        document={"total_count": len(entries), "check_runs": entries},
        headers={},
    )


def _check_document(
    *,
    check_id: object = 777,
    name: str = CHECK_NAME,
    head_sha: str = HEAD,
    external_id: str = EXTERNAL_ID,
    status: str = "completed",
    conclusion: str = "neutral",
) -> dict[str, object]:
    return {
        "id": check_id,
        "name": name,
        "head_sha": head_sha,
        "external_id": external_id,
        "status": status,
        "conclusion": conclusion,
    }


def _projection() -> dict[str, object]:
    return {"conclusion": "neutral", "output": {"title": "SecureCode AI summary"}}


def test_head_returns_exact_commit_sha() -> None:
    api = _FakeApi([_head_response(sha=HEAD)])
    writer = GitHubWriter(api)  # type: ignore[arg-type]
    assert writer.head(INSTALLATION, OWNER, REPO) == HEAD
    assert api.calls[0]["path"] == repository_path(OWNER, REPO) + "/git/ref/heads/main"


@pytest.mark.parametrize(
    ("status", "document"),
    [
        (404, None),
        (200, None),
        (200, {}),
        (200, {"object": "main"}),
        (200, {"object": {"sha": "not-a-sha"}}),
        (200, {"object": {"sha": "A" * 40}}),
        (200, {"object": {"sha": "a" * 39}}),
    ],
)
def test_head_rejects_invalid_references(status: int, document: Any) -> None:
    api = _FakeApi([GitHubResponse(status=status, document=document, headers={})])
    writer = GitHubWriter(api)  # type: ignore[arg-type]
    with pytest.raises(GitHubError) as error:
        writer.head(INSTALLATION, OWNER, REPO)
    assert error.value.code == "HEAD_INVALID"


def test_write_check_suppresses_stale_head_without_writing() -> None:
    api = _FakeApi([_head_response(sha=OTHER_HEAD)])
    writer = GitHubWriter(api)  # type: ignore[arg-type]
    receipt = writer.write_check(
        installation_id=INSTALLATION,
        owner=OWNER,
        repo=REPO,
        expected_head=HEAD,
        external_id=EXTERNAL_ID,
        projection=_projection(),
        delivery_key=DELIVERY_KEY,
    )
    assert receipt.external_id == EXTERNAL_ID
    assert receipt.status == "STALE_SUPPRESSED"
    assert receipt.remote_check_id is None
    assert len(api.calls) == 1


def test_write_check_creates_check_run_when_head_matches() -> None:
    api = _FakeApi(
        [
            _head_response(sha=HEAD),
            _listing_response([]),
            GitHubResponse(status=201, document=_check_document(), headers={}),
        ]
    )
    writer = GitHubWriter(api)  # type: ignore[arg-type]
    receipt = writer.write_check(
        installation_id=INSTALLATION,
        owner=OWNER,
        repo=REPO,
        expected_head=HEAD,
        external_id=EXTERNAL_ID,
        projection=_projection(),
        delivery_key=DELIVERY_KEY,
    )
    assert receipt.status == "WRITTEN"
    assert receipt.remote_check_id == "777"
    create = api.calls[2]
    assert create["method"] == "POST"
    assert create["path"] == repository_path(OWNER, REPO) + "/check-runs"
    assert create["idempotency_key"] == DELIVERY_KEY
    body = create["document"]
    assert body is not None
    assert body["name"] == CHECK_NAME
    assert body["head_sha"] == HEAD
    assert body["external_id"] == EXTERNAL_ID
    assert body["status"] == "completed"
    assert body["conclusion"] == "neutral"


def test_write_check_updates_existing_check_without_head_sha() -> None:
    existing = _check_document(check_id=555)
    api = _FakeApi(
        [
            _head_response(sha=HEAD),
            _listing_response([existing]),
            GitHubResponse(status=200, document=existing, headers={}),
        ]
    )
    writer = GitHubWriter(api)  # type: ignore[arg-type]
    receipt = writer.write_check(
        installation_id=INSTALLATION,
        owner=OWNER,
        repo=REPO,
        expected_head=HEAD,
        external_id=EXTERNAL_ID,
        projection=_projection(),
        delivery_key=DELIVERY_KEY,
    )
    assert receipt.status == "WRITTEN"
    assert receipt.remote_check_id == "555"
    update = api.calls[2]
    assert update["method"] == "PATCH"
    assert update["path"] == repository_path(OWNER, REPO) + "/check-runs/555"
    assert update["document"] is not None
    assert "head_sha" not in update["document"]


@pytest.mark.parametrize(
    "entries",
    [
        [
            _check_document(check_id=1),
            _check_document(check_id=2),
        ],
    ],
)
def test_reconciliation_rejects_conflicting_matches(entries: list[dict[str, object]]) -> None:
    api = _FakeApi([_head_response(sha=HEAD), _listing_response(entries)])
    writer = GitHubWriter(api)  # type: ignore[arg-type]
    with pytest.raises(GitHubError) as error:
        writer.write_check(
            installation_id=INSTALLATION,
            owner=OWNER,
            repo=REPO,
            expected_head=HEAD,
            external_id=EXTERNAL_ID,
            projection=_projection(),
            delivery_key=DELIVERY_KEY,
        )
    assert error.value.code == "CHECK_RECONCILIATION_CONFLICT"


@pytest.mark.parametrize(
    "response",
    [
        GitHubResponse(status=500, document=None, headers={}),
        GitHubResponse(status=200, document={"total_count": "1", "check_runs": []}, headers={}),
        GitHubResponse(status=200, document={"total_count": 1, "check_runs": []}, headers={}),
        GitHubResponse(
            status=200,
            document={"total_count": 1, "check_runs": ["not-an-object"]},
            headers={},
        ),
    ],
)
def test_reconciliation_rejects_invalid_listings(response: GitHubResponse) -> None:
    api = _FakeApi([_head_response(sha=HEAD), response])
    writer = GitHubWriter(api)  # type: ignore[arg-type]
    with pytest.raises(GitHubError) as error:
        writer.write_check(
            installation_id=INSTALLATION,
            owner=OWNER,
            repo=REPO,
            expected_head=HEAD,
            external_id=EXTERNAL_ID,
            projection=_projection(),
            delivery_key=DELIVERY_KEY,
        )
    assert error.value.code == "CHECK_RECONCILIATION_INVALID"


@pytest.mark.parametrize("external_id", ["", "x" * 129])
def test_write_rejects_invalid_external_id(external_id: str) -> None:
    api = _FakeApi([_head_response(sha=HEAD)])
    writer = GitHubWriter(api)  # type: ignore[arg-type]
    with pytest.raises(GitHubError) as error:
        writer.write_check(
            installation_id=INSTALLATION,
            owner=OWNER,
            repo=REPO,
            expected_head=HEAD,
            external_id=external_id,
            projection=_projection(),
            delivery_key=DELIVERY_KEY,
        )
    assert error.value.code == "EXTERNAL_ID_INVALID"


@pytest.mark.parametrize("bad_head", ["short", "A" * 40, "g" * 40])
def test_write_rejects_invalid_expected_head_through_pr_path(bad_head: str) -> None:
    api = _FakeApi([])
    writer = GitHubWriter(
        api,  # type: ignore[arg-type]
        pull_request_head=lambda _installation, _repository, _change: bad_head,
    )
    with pytest.raises(GitHubError) as error:
        writer.write_pull_request_check(
            installation_id=INSTALLATION,
            repository_id="501",
            change_id="1",
            expected_head=bad_head,
            external_id=EXTERNAL_ID,
            projection=_projection(),
            delivery_key=DELIVERY_KEY,
        )
    assert error.value.code == "EXTERNAL_ID_INVALID"
    assert api.calls == []


def test_pull_request_check_requires_head_resolver() -> None:
    api = _FakeApi([])
    writer = GitHubWriter(api)  # type: ignore[arg-type]
    with pytest.raises(GitHubError) as error:
        writer.write_pull_request_check(
            installation_id=INSTALLATION,
            repository_id="501",
            change_id="1",
            expected_head=HEAD,
            external_id=EXTERNAL_ID,
            projection=_projection(),
            delivery_key=DELIVERY_KEY,
        )
    assert error.value.code == "HEAD_RESOLVER_UNAVAILABLE"


def test_pull_request_check_suppresses_stale_resolved_head() -> None:
    api = _FakeApi([])
    writer = GitHubWriter(
        api,  # type: ignore[arg-type]
        pull_request_head=lambda _installation, _repository, _change: OTHER_HEAD,
    )
    receipt = writer.write_pull_request_check(
        installation_id=INSTALLATION,
        repository_id="501",
        change_id="1",
        expected_head=HEAD,
        external_id=EXTERNAL_ID,
        projection=_projection(),
        delivery_key=DELIVERY_KEY,
    )
    assert receipt.status == "STALE_SUPPRESSED"
    assert api.calls == []


def test_pull_request_check_writes_after_authoritative_head_match() -> None:
    api = _FakeApi(
        [
            _listing_response([]),
            GitHubResponse(status=201, document=_check_document(), headers={}),
        ]
    )
    writer = GitHubWriter(
        api,  # type: ignore[arg-type]
        pull_request_head=lambda _installation, _repository, _change: HEAD,
    )
    receipt = writer.write_pull_request_check(
        installation_id=INSTALLATION,
        repository_id="501",
        change_id="1",
        expected_head=HEAD,
        external_id=EXTERNAL_ID,
        projection=_projection(),
        delivery_key=DELIVERY_KEY,
    )
    assert receipt.status == "WRITTEN"
    listing = api.calls[0]
    assert listing["path"] == (
        "/repositories/501/commits/"
        + HEAD
        + "/check-runs"
        + "?check_name=SecureCode%20AI&filter=all&per_page=100"
    )
    assert api.calls[1]["path"] == "/repositories/501/check-runs"


@pytest.mark.parametrize(
    "document",
    [
        None,
        {},
        _check_document(name="Other check"),
        _check_document(head_sha=OTHER_HEAD),
        _check_document(external_id="other-run"),
        _check_document(status="in_progress"),
        _check_document(conclusion="failure"),
        _check_document(check_id=0),
        _check_document(check_id="777"),
    ],
)
def test_create_receipt_rejects_mismatched_check(document: Any) -> None:
    api = _FakeApi(
        [
            _head_response(sha=HEAD),
            _listing_response([]),
            GitHubResponse(status=201, document=document, headers={}),
        ]
    )
    writer = GitHubWriter(api)  # type: ignore[arg-type]
    with pytest.raises(GitHubError) as error:
        writer.write_check(
            installation_id=INSTALLATION,
            owner=OWNER,
            repo=REPO,
            expected_head=HEAD,
            external_id=EXTERNAL_ID,
            projection=_projection(),
            delivery_key=DELIVERY_KEY,
        )
    assert error.value.code == "CHECK_RECEIPT_INVALID"
