"""Exact-head, crash-reconciling GitHub check writer."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import quote

from .github_api import GitHubApi, GitHubError, GitHubResponse, repository_path

_CHECK_NAME = "SecureCode AI"
_COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_REMOTE_ID = re.compile(r"[1-9][0-9]{0,19}\Z")


class PullRequestHeadResolver(Protocol):
    def __call__(
        self,
        installation_id: str,
        repository_id: str,
        change_id: str,
    ) -> str: ...


@dataclass(frozen=True, slots=True)
class GitHubWriteReceipt:
    external_id: str
    status: str
    remote_check_id: str | None = None


class GitHubWriter:
    """Write or reconcile one deterministic check at an exact trusted HEAD."""

    def __init__(
        self,
        api: GitHubApi,
        *,
        pull_request_head: PullRequestHeadResolver | None = None,
    ) -> None:
        self._api = api
        self._pull_request_head = pull_request_head

    def head(self, installation_id: str, owner: str, repo: str) -> str:
        response = self._api.request(
            "GET",
            repository_path(owner, repo) + "/git/ref/heads/main",
            installation_id=installation_id,
        )
        value = response.document or {}
        reference = value.get("object")
        if response.status != 200 or not isinstance(reference, dict):
            raise GitHubError("HEAD_INVALID")
        sha = reference.get("sha")
        if not isinstance(sha, str) or _COMMIT_SHA.fullmatch(sha) is None:
            raise GitHubError("HEAD_INVALID")
        return sha

    def write_check(
        self,
        *,
        installation_id: str,
        owner: str,
        repo: str,
        expected_head: str,
        external_id: str,
        projection: dict[str, object],
        delivery_key: str,
    ) -> GitHubWriteReceipt:
        if self.head(installation_id, owner, repo) != expected_head:
            return GitHubWriteReceipt(external_id, "STALE_SUPPRESSED")
        return self._write_reconciled(
            installation_id=installation_id,
            repository=repository_path(owner, repo),
            expected_head=expected_head,
            external_id=external_id,
            projection=projection,
            delivery_key=delivery_key,
        )

    def write_pull_request_check(
        self,
        *,
        installation_id: str,
        repository_id: str,
        change_id: str,
        expected_head: str,
        external_id: str,
        projection: dict[str, object],
        delivery_key: str,
    ) -> GitHubWriteReceipt:
        """Publish after an authoritative PR HEAD read and remote reconciliation."""

        resolver = self._pull_request_head
        if resolver is None:
            raise GitHubError("HEAD_RESOLVER_UNAVAILABLE")
        observed_head = resolver(installation_id, repository_id, change_id)
        if observed_head != expected_head:
            return GitHubWriteReceipt(external_id, "STALE_SUPPRESSED")
        return self._write_reconciled(
            installation_id=installation_id,
            repository=f"/repositories/{repository_id}",
            expected_head=expected_head,
            external_id=external_id,
            projection=projection,
            delivery_key=delivery_key,
        )

    def _write_reconciled(
        self,
        *,
        installation_id: str,
        repository: str,
        expected_head: str,
        external_id: str,
        projection: dict[str, object],
        delivery_key: str,
    ) -> GitHubWriteReceipt:
        if (
            _COMMIT_SHA.fullmatch(expected_head) is None
            or not external_id
            or len(external_id) > 128
        ):
            raise GitHubError("EXTERNAL_ID_INVALID")
        body = {
            "name": _CHECK_NAME,
            "head_sha": expected_head,
            "external_id": external_id,
            "status": "completed",
            "conclusion": projection.get("conclusion", "neutral"),
            "output": projection.get("output", {}),
        }
        existing = self._find_existing(
            installation_id=installation_id,
            repository=repository,
            expected_head=expected_head,
            external_id=external_id,
        )
        if existing is None:
            response = self._api.request(
                "POST",
                repository + "/check-runs",
                installation_id=installation_id,
                document=body,
                idempotency_key=delivery_key,
            )
            remote_id = _validated_check(response, 201, body)
        else:
            remote_id = existing
            update = dict(body)
            del update["head_sha"]
            response = self._api.request(
                "PATCH",
                repository + f"/check-runs/{remote_id}",
                installation_id=installation_id,
                document=update,
                idempotency_key=delivery_key,
            )
            remote_id = _validated_check(response, 200, body, expected_id=remote_id)
        return GitHubWriteReceipt(external_id, "WRITTEN", remote_id)

    def _find_existing(
        self,
        *,
        installation_id: str,
        repository: str,
        expected_head: str,
        external_id: str,
    ) -> str | None:
        query = "check_name=" + quote(_CHECK_NAME, safe="") + "&filter=all&per_page=100"
        response = self._api.request(
            "GET",
            repository + f"/commits/{expected_head}/check-runs?{query}",
            installation_id=installation_id,
        )
        document = response.document
        if response.status != 200 or type(document) is not dict:
            raise GitHubError("CHECK_RECONCILIATION_INVALID")
        total = document.get("total_count")
        values = document.get("check_runs")
        if (
            type(total) is not int
            or not 0 <= total <= 100
            or type(values) is not list
            or len(values) != total
        ):
            raise GitHubError("CHECK_RECONCILIATION_INVALID")
        matches: list[str] = []
        for value in values:
            if type(value) is not dict:
                raise GitHubError("CHECK_RECONCILIATION_INVALID")
            if value.get("external_id") != external_id:
                continue
            matches.append(_check_identity(value, expected_head, external_id))
        if len(matches) > 1:
            raise GitHubError("CHECK_RECONCILIATION_CONFLICT")
        return matches[0] if matches else None


def _validated_check(
    response: GitHubResponse,
    expected_status: int,
    expected: dict[str, object],
    *,
    expected_id: str | None = None,
) -> str:
    document = response.document
    if response.status != expected_status or type(document) is not dict:
        raise GitHubError("CHECK_RECEIPT_INVALID")
    identity = _check_identity(
        document,
        str(expected["head_sha"]),
        str(expected["external_id"]),
    )
    if (
        (expected_id is not None and identity != expected_id)
        or document.get("status") != "completed"
        or document.get("conclusion") != expected["conclusion"]
    ):
        raise GitHubError("CHECK_RECEIPT_INVALID")
    return identity


def _check_identity(document: dict[str, object], head_sha: str, external_id: str) -> str:
    raw_id = document.get("id")
    remote_id = str(raw_id) if type(raw_id) is int and raw_id > 0 else ""
    if (
        _REMOTE_ID.fullmatch(remote_id) is None
        or document.get("name") != _CHECK_NAME
        or document.get("head_sha") != head_sha
        or document.get("external_id") != external_id
    ):
        raise GitHubError("CHECK_RECEIPT_INVALID")
    return remote_id


__all__ = ["GitHubWriteReceipt", "GitHubWriter", "PullRequestHeadResolver"]
