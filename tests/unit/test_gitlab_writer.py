"""P7.5 retry-safe GitLab publication writer: idempotency, staleness, conflicts."""

from __future__ import annotations

import pytest
from securecode_ai.adapters.gitlab_ci import GitlabExternalStatus, GitlabExternalStatusProjection
from securecode_ai.adapters.gitlab_discussions import GitlabDiscussionProjection
from securecode_ai.adapters.gitlab_summary import GitlabSummaryProjection
from securecode_ai.adapters.gitlab_writer import (
    GitlabPublicationWriter,
    GitlabWriteError,
    GitlabWriteErrorCode,
    GitlabWriteStatus,
    GitlabWriteTarget,
)
from securecode_ai.contracts import AuditRunOutcome

PROJECT = "42"
IID = "7"
HEAD = "a" * 40
OTHER_HEAD = "b" * 40
BASE = "c" * 40
START = "d" * 40
IDENTITY = "e" * 64
RENDERED_SHA = "f" * 64


class _FakeApi:
    """Credential-free transport double that records calls and replays outcomes."""

    def __init__(self, *, fail: bool = False, external_id: object = "note-77") -> None:
        self.calls: list[tuple[str, str, str, str]] = []
        self._fail = fail
        self._external_id = external_id

    def upsert_merge_request_note(
        self,
        *,
        project_id: str,
        merge_request_iid: str,
        idempotency_key: str,
        body: str,
    ) -> str:
        self.calls.append(("SUMMARY", idempotency_key, project_id, merge_request_iid))
        if self._fail:
            raise RuntimeError("remote unavailable")
        return str(self._external_id)

    def create_merge_request_discussion(
        self,
        *,
        project_id: str,
        merge_request_iid: str,
        idempotency_key: str,
        projection: GitlabDiscussionProjection,
    ) -> str:
        self.calls.append(("DISCUSSION", idempotency_key, project_id, merge_request_iid))
        if self._fail:
            raise RuntimeError("remote unavailable")
        return str(self._external_id)

    def set_external_status(
        self,
        *,
        project_id: str,
        merge_request_iid: str,
        idempotency_key: str,
        projection: GitlabExternalStatusProjection,
    ) -> str:
        self.calls.append(("EXTERNAL_STATUS", idempotency_key, project_id, merge_request_iid))
        if self._fail:
            raise RuntimeError("remote unavailable")
        return str(self._external_id)


class _Head:
    def __init__(self, *values: str) -> None:
        self._values = list(values)

    def __call__(self, _project_id: str, _merge_request_iid: str) -> str:
        if not self._values:
            raise AssertionError("unexpected additional head read")
        return self._values.pop(0)


def _target(expected_head: str = HEAD) -> GitlabWriteTarget:
    return GitlabWriteTarget(
        project_id=PROJECT,
        merge_request_iid=IID,
        expected_head_sha=expected_head,
    )


def _summary() -> GitlabSummaryProjection:
    return GitlabSummaryProjection(
        note_idempotency_key="summary-key-1",
        execution_identity_hash=IDENTITY,
        head_sha=HEAD,
        outcome=AuditRunOutcome.PASS,
        rendered_markdown="## SecureCode AI summary",
        rendered_sha256=RENDERED_SHA,
    )


def _discussion() -> GitlabDiscussionProjection:
    return GitlabDiscussionProjection(
        finding_id="finding-1",
        cwe_id="CWE-89",
        new_path="app.py",
        new_line=3,
        base_sha=BASE,
        start_sha=START,
        head_sha=HEAD,
        body="Parameterize this query before merging.",
    )


def _external_status() -> GitlabExternalStatusProjection:
    return GitlabExternalStatusProjection(
        idempotency_key="status-key-1",
        execution_identity_hash=IDENTITY,
        head_sha=HEAD,
        status=GitlabExternalStatus.PASSED,
        publish=True,
        merge_authority=False,
        safe_summary="Advisory scan completed",
    )


def test_writer_rejects_unusable_api_or_resolver() -> None:
    with pytest.raises(GitlabWriteError) as error:
        GitlabPublicationWriter(api=object(), head_resolver=_Head(HEAD))
    assert error.value.code is GitlabWriteErrorCode.INVALID_REQUEST
    with pytest.raises(GitlabWriteError) as error:
        GitlabPublicationWriter(api=_FakeApi(), head_resolver="not-callable")
    assert error.value.code is GitlabWriteErrorCode.INVALID_REQUEST


@pytest.mark.parametrize(
    ("project_id", "merge_request_iid", "expected_head_sha"),
    [
        ("", IID, HEAD),
        ("-bad", IID, HEAD),
        (PROJECT, "", HEAD),
        (PROJECT, IID, "short"),
        (PROJECT, IID, "A" * 40),
    ],
)
def test_target_rejects_invalid_identity(
    project_id: str, merge_request_iid: str, expected_head_sha: str
) -> None:
    with pytest.raises(GitlabWriteError) as error:
        GitlabWriteTarget(
            project_id=project_id,
            merge_request_iid=merge_request_iid,
            expected_head_sha=expected_head_sha,
        )
    assert error.value.code is GitlabWriteErrorCode.INVALID_REQUEST


def test_summary_publishes_once_and_replays_idempotently() -> None:
    api = _FakeApi()
    writer = GitlabPublicationWriter(api=api, head_resolver=_Head(HEAD, HEAD, HEAD))
    first = writer.publish_summary(_target(), _summary())
    assert first.status is GitlabWriteStatus.SUCCEEDED
    assert first.external_id == "note-77"
    assert first.observed_head_sha == HEAD
    second = writer.publish_summary(_target(), _summary())
    assert second.status is GitlabWriteStatus.IDEMPOTENT
    assert second.external_id == "note-77"
    assert len(api.calls) == 1
    assert api.calls[0] == ("SUMMARY", "summary-key-1", PROJECT, IID)


def test_summary_suppresses_stale_head_before_and_after_write() -> None:
    api = _FakeApi()
    writer = GitlabPublicationWriter(api=api, head_resolver=_Head(OTHER_HEAD))
    stale = writer.publish_summary(_target(), _summary())
    assert stale.status is GitlabWriteStatus.STALE
    assert stale.reason_code == "HEAD_CHANGED"
    assert stale.observed_head_sha == OTHER_HEAD
    assert api.calls == []

    post_api = _FakeApi()
    post_writer = GitlabPublicationWriter(api=post_api, head_resolver=_Head(HEAD, OTHER_HEAD))
    post_stale = post_writer.publish_summary(_target(), _summary())
    assert post_stale.status is GitlabWriteStatus.STALE
    assert len(post_api.calls) == 1


def test_summary_same_key_with_different_payload_conflicts() -> None:
    api = _FakeApi()
    writer = GitlabPublicationWriter(api=api, head_resolver=_Head(HEAD, HEAD, HEAD, HEAD))
    writer.publish_summary(_target(), _summary())
    conflicting = GitlabSummaryProjection(
        note_idempotency_key="summary-key-1",
        execution_identity_hash=IDENTITY,
        head_sha=HEAD,
        outcome=AuditRunOutcome.FAIL,
        rendered_markdown="## Different summary",
        rendered_sha256="0" * 64,
    )
    with pytest.raises(GitlabWriteError) as error:
        writer.publish_summary(_target(), conflicting)
    assert error.value.code is GitlabWriteErrorCode.CONFLICT


def test_summary_rejects_head_mismatch_and_merge_authority() -> None:
    api = _FakeApi()
    writer = GitlabPublicationWriter(api=api, head_resolver=_Head())
    authority = GitlabSummaryProjection(
        note_idempotency_key="summary-key-2",
        execution_identity_hash=IDENTITY,
        head_sha=HEAD,
        outcome=AuditRunOutcome.PASS,
        rendered_markdown="## Summary",
        rendered_sha256=RENDERED_SHA,
        merge_authority=True,
    )
    with pytest.raises(GitlabWriteError) as error:
        writer.publish_summary(_target(), authority)
    assert error.value.code is GitlabWriteErrorCode.INVALID_REQUEST

    mismatched = GitlabSummaryProjection(
        note_idempotency_key="summary-key-3",
        execution_identity_hash=IDENTITY,
        head_sha=OTHER_HEAD,
        outcome=AuditRunOutcome.PASS,
        rendered_markdown="## Summary",
        rendered_sha256=RENDERED_SHA,
    )
    with pytest.raises(GitlabWriteError) as error:
        writer.publish_summary(_target(), mismatched)
    assert error.value.code is GitlabWriteErrorCode.INVALID_REQUEST
    assert api.calls == []


def test_remote_failure_returns_failed_receipt_without_raising() -> None:
    api = _FakeApi(fail=True)
    writer = GitlabPublicationWriter(api=api, head_resolver=_Head(HEAD, HEAD))
    receipt = writer.publish_summary(_target(), _summary())
    assert receipt.status is GitlabWriteStatus.FAILED
    assert receipt.reason_code == "REMOTE_WRITE_FAILED"


@pytest.mark.parametrize("external_id", ["", "-leading", "x" * 257])
def test_invalid_remote_external_id_becomes_failed_receipt(external_id: object) -> None:
    api = _FakeApi(external_id=external_id)
    writer = GitlabPublicationWriter(api=api, head_resolver=_Head(HEAD, HEAD))
    receipt = writer.publish_summary(_target(), _summary())
    assert receipt.status is GitlabWriteStatus.FAILED
    assert receipt.reason_code == "REMOTE_WRITE_FAILED"


def test_unavailable_head_becomes_head_unavailable_error() -> None:
    api = _FakeApi()

    def broken(_project_id: str, _merge_request_iid: str) -> str:
        raise OSError("resolver offline")

    writer = GitlabPublicationWriter(api=api, head_resolver=broken)
    with pytest.raises(GitlabWriteError) as error:
        writer.publish_summary(_target(), _summary())
    assert error.value.code is GitlabWriteErrorCode.HEAD_UNAVAILABLE
    assert api.calls == []


def test_discussion_publishes_with_deterministic_idempotency_key() -> None:
    api = _FakeApi()
    writer = GitlabPublicationWriter(api=api, head_resolver=_Head(HEAD, HEAD, HEAD, HEAD))
    first = writer.publish_discussion(_target(), _discussion())
    assert first.status is GitlabWriteStatus.SUCCEEDED
    replay_api = _FakeApi()
    replay_writer = GitlabPublicationWriter(api=replay_api, head_resolver=_Head(HEAD, HEAD))
    replay = replay_writer.publish_discussion(_target(), _discussion())
    assert replay.idempotency_key == first.idempotency_key
    assert replay.status is GitlabWriteStatus.SUCCEEDED
    assert first.idempotency_key.startswith("discussion-")
    assert api.calls[0][:2] == ("DISCUSSION", first.idempotency_key)


def test_external_status_requires_publish_and_matching_head() -> None:
    api = _FakeApi()
    writer = GitlabPublicationWriter(api=api, head_resolver=_Head(HEAD, HEAD))
    receipt = writer.publish_external_status(_target(), _external_status())
    assert receipt.status is GitlabWriteStatus.SUCCEEDED
    assert api.calls[0][:2] == ("EXTERNAL_STATUS", "status-key-1")

    disabled = GitlabExternalStatusProjection(
        idempotency_key="status-key-2",
        execution_identity_hash=IDENTITY,
        head_sha=HEAD,
        status=GitlabExternalStatus.PASSED,
        publish=False,
        merge_authority=False,
        safe_summary="Hidden",
    )
    with pytest.raises(GitlabWriteError) as error:
        writer.publish_external_status(_target(), disabled)
    assert error.value.code is GitlabWriteErrorCode.INVALID_REQUEST


def test_stale_replay_returns_stale_without_remote_write() -> None:
    api = _FakeApi()
    writer = GitlabPublicationWriter(api=api, head_resolver=_Head(OTHER_HEAD, HEAD))
    stale = writer.publish_summary(_target(), _summary())
    assert stale.status is GitlabWriteStatus.STALE
    replay = writer.publish_summary(_target(), _summary())
    assert replay.status is GitlabWriteStatus.STALE
    assert api.calls == []
