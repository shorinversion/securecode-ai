"""Explicit, provider-injected immutable release publication boundary."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .release_candidate import ReleaseCandidate

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_NONCE = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")


class ReleasePublisherError(ValueError):
    """Safe release publication failure without artifact content or credentials."""

    def __init__(self) -> None:
        super().__init__("Release publication was rejected")
        self.__cause__ = None
        self.__context__ = None


class ReleasePublishDisposition(StrEnum):
    DRY_RUN = "DRY_RUN"
    PUBLISHED = "PUBLISHED"
    IDEMPOTENT = "IDEMPOTENT"
    CONFLICT = "CONFLICT"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class ReleaseDryRunPlan:
    candidate: ReleaseCandidate
    tag: str
    candidate_sha256: str
    artifact_checksums: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.candidate) is not ReleaseCandidate
            or self.tag != self.candidate.version
            or self.candidate_sha256 != self.candidate.candidate_sha256
            or self.artifact_checksums
            != tuple(item.checksum_sha256 for item in self.candidate.artifacts)
        ):
            raise ReleasePublisherError()


@dataclass(frozen=True, slots=True)
class PublishAuthorization:
    authorization_id: str
    action: str
    approver_id: str
    candidate_sha256: str
    expires_at: int
    key_id: str
    nonce: str
    store_identity_sha256: str
    signature_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.authorization_id) is not str
            or _ID.fullmatch(self.authorization_id) is None
            or self.action != "PUBLISH"
            or type(self.approver_id) is not str
            or _ID.fullmatch(self.approver_id) is None
            or type(self.candidate_sha256) is not str
            or _HASH.fullmatch(self.candidate_sha256) is None
            or type(self.expires_at) is not int
            or self.expires_at < 1
            or type(self.key_id) is not str
            or _ID.fullmatch(self.key_id) is None
            or type(self.nonce) is not str
            or _NONCE.fullmatch(self.nonce) is None
            or type(self.signature_sha256) is not str
            or _HASH.fullmatch(self.signature_sha256) is None
            or type(self.store_identity_sha256) is not str
            or _HASH.fullmatch(self.store_identity_sha256) is None
        ):
            raise ReleasePublisherError()


@dataclass(frozen=True, slots=True)
class AuthorizedPublishRequest:
    plan: ReleaseDryRunPlan
    authorization: PublishAuthorization

    def __post_init__(self) -> None:
        if (
            type(self.plan) is not ReleaseDryRunPlan
            or type(self.authorization) is not PublishAuthorization
            or self.authorization.candidate_sha256 != self.plan.candidate_sha256
        ):
            raise ReleasePublisherError()


class ReleaseAuthorizationVerifier(Protocol):
    def verify(self, authorization: PublishAuthorization, *, now: int | None) -> bool: ...


@dataclass(frozen=True, slots=True)
class RemoteRelease:
    tag: str
    immutable_id: str
    candidate_sha256: str
    artifact_checksums: tuple[str, ...]
    complete: bool

    def __post_init__(self) -> None:
        if (
            any(type(value) is not str or not value for value in (self.tag, self.immutable_id))
            or type(self.candidate_sha256) is not str
            or _HASH.fullmatch(self.candidate_sha256) is None
            or type(self.artifact_checksums) is not tuple
            or any(
                type(item) is not str or _HASH.fullmatch(item) is None
                for item in self.artifact_checksums
            )
            or type(self.complete) is not bool
        ):
            raise ReleasePublisherError()


class ReleaseProvider(Protocol):
    def get_tag(
        self, tag: str, authorization: PublishAuthorization | None = None
    ) -> RemoteRelease | None: ...
    def create_release(self, request: AuthorizedPublishRequest) -> RemoteRelease: ...


@dataclass(frozen=True, slots=True)
class ReleasePublishReceipt:
    disposition: ReleasePublishDisposition
    tag: str
    candidate_sha256: str
    remote_immutable_id: str | None
    remote_candidate_sha256: str | None
    artifact_checksums: tuple[str, ...]
    source_disclosed: bool = False


class ReleasePublisher:
    """Core publication coordinator; all transport effects belong to provider."""

    __slots__ = ("_provider",)

    def __init__(self, provider: ReleaseProvider) -> None:
        if not all(
            callable(getattr(provider, name, None)) for name in ("get_tag", "create_release")
        ):
            raise ReleasePublisherError()
        self._provider = provider

    def dry_run(self, candidate: ReleaseCandidate) -> ReleaseDryRunPlan:
        if type(candidate) is not ReleaseCandidate:
            raise ReleasePublisherError()
        return ReleaseDryRunPlan(
            candidate,
            candidate.version,
            candidate.candidate_sha256,
            tuple(item.checksum_sha256 for item in candidate.artifacts),
        )

    def publish(self, request: AuthorizedPublishRequest) -> ReleasePublishReceipt:
        if type(request) is not AuthorizedPublishRequest:
            raise ReleasePublisherError()
        plan = request.plan
        if type(plan.candidate) is not ReleaseCandidate:
            raise ReleasePublisherError()
        try:
            existing = self._provider.get_tag(plan.tag, request.authorization)
        except Exception:
            return _error(plan)
        if existing is not None:
            if _matches(existing, plan):
                return _receipt(ReleasePublishDisposition.IDEMPOTENT, plan, existing)
            return _receipt(ReleasePublishDisposition.CONFLICT, plan, existing)
        try:
            remote = self._provider.create_release(request)
        except Exception:
            return _error(plan)
        if not _matches(remote, plan):
            return _receipt(ReleasePublishDisposition.ERROR, plan, remote)
        return _receipt(ReleasePublishDisposition.PUBLISHED, plan, remote)


def _matches(remote: RemoteRelease, plan: ReleaseDryRunPlan) -> bool:
    return (
        type(remote) is RemoteRelease
        and remote.complete
        and remote.tag == plan.tag
        and remote.candidate_sha256 == plan.candidate_sha256
        and remote.artifact_checksums == plan.artifact_checksums
    )


def _receipt(
    disposition: ReleasePublishDisposition, plan: ReleaseDryRunPlan, remote: RemoteRelease
) -> ReleasePublishReceipt:
    return ReleasePublishReceipt(
        disposition,
        plan.tag,
        plan.candidate_sha256,
        remote.immutable_id,
        remote.candidate_sha256,
        remote.artifact_checksums,
    )


def _error(plan: ReleaseDryRunPlan) -> ReleasePublishReceipt:
    return ReleasePublishReceipt(
        ReleasePublishDisposition.ERROR,
        plan.tag,
        plan.candidate_sha256,
        None,
        None,
        plan.artifact_checksums,
    )


__all__ = [
    "AuthorizedPublishRequest",
    "PublishAuthorization",
    "ReleaseAuthorizationVerifier",
    "ReleaseDryRunPlan",
    "ReleaseProvider",
    "ReleasePublishDisposition",
    "ReleasePublishReceipt",
    "ReleasePublisher",
    "ReleasePublisherError",
    "RemoteRelease",
]
