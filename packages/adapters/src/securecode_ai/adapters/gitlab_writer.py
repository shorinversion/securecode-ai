"""Retry-safe GitLab publication writer over an injected authenticated API port."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final, Protocol, cast

from .gitlab_ci import GitlabExternalStatusProjection
from .gitlab_discussions import GitlabDiscussionProjection
from .gitlab_summary import GitlabSummaryProjection

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_EXTERNAL_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/gitlab-writer/v1\x00"


class GitlabWriteStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    IDEMPOTENT = "IDEMPOTENT"
    STALE = "STALE"
    FAILED = "FAILED"


class GitlabWriteKind(StrEnum):
    SUMMARY = "SUMMARY"
    DISCUSSION = "DISCUSSION"
    EXTERNAL_STATUS = "EXTERNAL_STATUS"


class GitlabWriteErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    CONFLICT = "CONFLICT"
    HEAD_UNAVAILABLE = "HEAD_UNAVAILABLE"


class GitlabWriteError(ValueError):
    __slots__ = ("code", "safe_message")

    def __init__(self, code: GitlabWriteErrorCode) -> None:
        if type(code) is not GitlabWriteErrorCode:
            raise TypeError("GitLab write error code is invalid")
        self.code = code
        self.safe_message = "GitLab publication request was rejected"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class GitlabAuthenticatedAPI(Protocol):
    """Credential-owning transport. Implementations must not expose tokens."""

    def upsert_merge_request_note(
        self,
        *,
        project_id: str,
        merge_request_iid: str,
        idempotency_key: str,
        body: str,
    ) -> str: ...

    def create_merge_request_discussion(
        self,
        *,
        project_id: str,
        merge_request_iid: str,
        idempotency_key: str,
        projection: GitlabDiscussionProjection,
    ) -> str: ...

    def set_external_status(
        self,
        *,
        project_id: str,
        merge_request_iid: str,
        idempotency_key: str,
        projection: GitlabExternalStatusProjection,
    ) -> str: ...


@dataclass(frozen=True, slots=True)
class GitlabWriteTarget:
    project_id: str
    merge_request_iid: str
    expected_head_sha: str

    def __post_init__(self) -> None:
        if (
            type(self.project_id) is not str
            or _ID.fullmatch(self.project_id) is None
            or type(self.merge_request_iid) is not str
            or _ID.fullmatch(self.merge_request_iid) is None
            or type(self.expected_head_sha) is not str
            or _COMMIT_SHA.fullmatch(self.expected_head_sha) is None
        ):
            raise GitlabWriteError(GitlabWriteErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class GitlabWriteReceipt:
    kind: GitlabWriteKind
    idempotency_key: str
    payload_sha256: str
    expected_head_sha: str
    observed_head_sha: str | None
    status: GitlabWriteStatus
    external_id: str | None = None
    reason_code: str | None = None


TrustedHeadResolver = Callable[[str, str], str]


class GitlabPublicationWriter:
    """Perform GitLab writes with a last-moment current-head comparison."""

    __slots__ = ("_api", "_head_resolver", "_lock", "_receipts")

    def __init__(self, *, api: object, head_resolver: object) -> None:
        if not _is_api(api) or not callable(head_resolver):
            raise GitlabWriteError(GitlabWriteErrorCode.INVALID_REQUEST)
        self._api = cast(GitlabAuthenticatedAPI, api)
        self._head_resolver = cast(TrustedHeadResolver, head_resolver)
        self._lock = RLock()
        self._receipts: dict[str, GitlabWriteReceipt] = {}

    def publish_summary(
        self,
        target: GitlabWriteTarget,
        projection: GitlabSummaryProjection,
    ) -> GitlabWriteReceipt:
        if type(target) is not GitlabWriteTarget or type(projection) is not GitlabSummaryProjection:
            raise GitlabWriteError(GitlabWriteErrorCode.INVALID_REQUEST)
        if projection.head_sha != target.expected_head_sha or projection.merge_authority:
            raise GitlabWriteError(GitlabWriteErrorCode.INVALID_REQUEST)
        payload_hash = _hash(
            {
                "body_sha256": projection.rendered_sha256,
                "execution_identity_hash": projection.execution_identity_hash,
                "head_sha": projection.head_sha,
                "kind": GitlabWriteKind.SUMMARY.value,
            }
        )
        return self._write(
            kind=GitlabWriteKind.SUMMARY,
            key=projection.note_idempotency_key,
            payload_hash=payload_hash,
            target=target,
            operation=lambda: self._api.upsert_merge_request_note(
                project_id=target.project_id,
                merge_request_iid=target.merge_request_iid,
                idempotency_key=projection.note_idempotency_key,
                body=projection.rendered_markdown,
            ),
        )

    def publish_discussion(
        self,
        target: GitlabWriteTarget,
        projection: GitlabDiscussionProjection,
    ) -> GitlabWriteReceipt:
        if (
            type(target) is not GitlabWriteTarget
            or type(projection) is not GitlabDiscussionProjection
        ):
            raise GitlabWriteError(GitlabWriteErrorCode.INVALID_REQUEST)
        if projection.head_sha != target.expected_head_sha or projection.merge_authority:
            raise GitlabWriteError(GitlabWriteErrorCode.INVALID_REQUEST)
        key = _discussion_key(projection)
        payload_hash = _hash(
            {
                "base_sha": projection.base_sha,
                "body": projection.body,
                "finding_id": projection.finding_id,
                "head_sha": projection.head_sha,
                "kind": GitlabWriteKind.DISCUSSION.value,
                "line": projection.new_line,
                "old_path": projection.old_path or projection.new_path,
                "path": projection.new_path,
                "start_sha": projection.start_sha,
            }
        )
        return self._write(
            kind=GitlabWriteKind.DISCUSSION,
            key=key,
            payload_hash=payload_hash,
            target=target,
            operation=lambda: self._api.create_merge_request_discussion(
                project_id=target.project_id,
                merge_request_iid=target.merge_request_iid,
                idempotency_key=key,
                projection=projection,
            ),
        )

    def publish_external_status(
        self,
        target: GitlabWriteTarget,
        projection: GitlabExternalStatusProjection,
    ) -> GitlabWriteReceipt:
        if (
            type(target) is not GitlabWriteTarget
            or type(projection) is not GitlabExternalStatusProjection
            or not projection.publish
            or projection.head_sha != target.expected_head_sha
        ):
            raise GitlabWriteError(GitlabWriteErrorCode.INVALID_REQUEST)
        payload_hash = _hash(
            {
                "execution_identity_hash": projection.execution_identity_hash,
                "head_sha": projection.head_sha,
                "kind": GitlabWriteKind.EXTERNAL_STATUS.value,
                "merge_authority": projection.merge_authority,
                "status": projection.status.value,
            }
        )
        return self._write(
            kind=GitlabWriteKind.EXTERNAL_STATUS,
            key=projection.idempotency_key,
            payload_hash=payload_hash,
            target=target,
            operation=lambda: self._api.set_external_status(
                project_id=target.project_id,
                merge_request_iid=target.merge_request_iid,
                idempotency_key=projection.idempotency_key,
                projection=projection,
            ),
        )

    def _write(
        self,
        *,
        kind: GitlabWriteKind,
        key: str,
        payload_hash: str,
        target: GitlabWriteTarget,
        operation: Callable[[], str],
    ) -> GitlabWriteReceipt:
        with self._lock:
            observed_head = self._current_head(target)
            existing = self._receipts.get(key)
            if existing is not None:
                if (
                    existing.payload_sha256 != payload_hash
                    or existing.kind is not kind
                    or existing.expected_head_sha != target.expected_head_sha
                ):
                    raise GitlabWriteError(GitlabWriteErrorCode.CONFLICT)
                if (
                    existing.status is GitlabWriteStatus.STALE
                    or observed_head != target.expected_head_sha
                ):
                    return self._stale_receipt(kind, key, payload_hash, target, observed_head)
                if existing.status is not GitlabWriteStatus.SUCCEEDED:
                    raise GitlabWriteError(GitlabWriteErrorCode.CONFLICT)
                return GitlabWriteReceipt(
                    kind=existing.kind,
                    idempotency_key=existing.idempotency_key,
                    payload_sha256=existing.payload_sha256,
                    expected_head_sha=existing.expected_head_sha,
                    observed_head_sha=existing.observed_head_sha,
                    status=GitlabWriteStatus.IDEMPOTENT,
                    external_id=existing.external_id,
                    reason_code=existing.reason_code,
                )
            if observed_head != target.expected_head_sha:
                return self._stale_receipt(kind, key, payload_hash, target, observed_head)
            try:
                external_id = operation()
                if type(external_id) is not str or _EXTERNAL_ID.fullmatch(external_id) is None:
                    raise ValueError
            except (KeyboardInterrupt, SystemExit, GeneratorExit):
                raise
            except Exception:
                return GitlabWriteReceipt(
                    kind=kind,
                    idempotency_key=key,
                    payload_sha256=payload_hash,
                    expected_head_sha=target.expected_head_sha,
                    observed_head_sha=observed_head,
                    status=GitlabWriteStatus.FAILED,
                    reason_code="REMOTE_WRITE_FAILED",
                )
            observed_head = self._current_head(target)
            if observed_head != target.expected_head_sha:
                return self._stale_receipt(kind, key, payload_hash, target, observed_head)
            receipt = GitlabWriteReceipt(
                kind=kind,
                idempotency_key=key,
                payload_sha256=payload_hash,
                expected_head_sha=target.expected_head_sha,
                observed_head_sha=observed_head,
                status=GitlabWriteStatus.SUCCEEDED,
                external_id=external_id,
            )
            self._receipts[key] = receipt
            return receipt

    def _stale_receipt(
        self,
        kind: GitlabWriteKind,
        key: str,
        payload_hash: str,
        target: GitlabWriteTarget,
        observed_head: str,
    ) -> GitlabWriteReceipt:
        receipt = GitlabWriteReceipt(
            kind=kind,
            idempotency_key=key,
            payload_sha256=payload_hash,
            expected_head_sha=target.expected_head_sha,
            observed_head_sha=observed_head,
            status=GitlabWriteStatus.STALE,
            reason_code="HEAD_CHANGED",
        )
        self._receipts[key] = receipt
        return receipt

    def _current_head(self, target: GitlabWriteTarget) -> str:
        try:
            head_sha = self._head_resolver(target.project_id, target.merge_request_iid)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception as error:
            raise GitlabWriteError(GitlabWriteErrorCode.HEAD_UNAVAILABLE) from error
        if type(head_sha) is not str or _COMMIT_SHA.fullmatch(head_sha) is None:
            raise GitlabWriteError(GitlabWriteErrorCode.HEAD_UNAVAILABLE)
        return head_sha


def _discussion_key(projection: GitlabDiscussionProjection) -> str:
    return (
        "discussion-"
        + _hash(
            {
                "finding_id": projection.finding_id,
                "head_sha": projection.head_sha,
                "line": projection.new_line,
                "path": projection.new_path,
            }
        )[:40]
    )


def _hash(material: dict[str, object]) -> str:
    payload = json.dumps(
        material,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(_HASH_DOMAIN + payload).hexdigest()


def _is_api(value: object) -> bool:
    return all(
        callable(getattr(value, name, None))
        for name in (
            "upsert_merge_request_note",
            "create_merge_request_discussion",
            "set_external_status",
        )
    )


__all__ = [
    "GitlabAuthenticatedAPI",
    "GitlabPublicationWriter",
    "GitlabWriteError",
    "GitlabWriteErrorCode",
    "GitlabWriteKind",
    "GitlabWriteReceipt",
    "GitlabWriteStatus",
    "GitlabWriteTarget",
]
