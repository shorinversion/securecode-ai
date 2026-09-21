"""Fail-closed launch projections for fork and untrusted SCM contributions.

This module classifies only authenticated SCM metadata and produces transport-free
worker launch metadata.  It never starts a process, reads a checkout, accesses
credentials, or calls an SCM, provider, backend, deployment, or container API.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final

from securecode_ai.contracts import RunExecutionIdentity
from securecode_ai.core.scm_run_state import PublicationDisposition, SCMRunPublicationReceipt

from .github_app import GithubAppAdapter, GithubAppError

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/untrusted-contribution/v1\x00"
_ENVIRONMENT_NAMES: Final = (
    "SECURECODE_BASE_SHA",
    "SECURECODE_EGRESS_PROFILE_SHA256",
    "SECURECODE_EXECUTION_IDENTITY_HASH",
    "SECURECODE_HEAD_SHA",
    "SECURECODE_TRUST_CLASS",
)


class UntrustedContributionErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    AUTHORIZATION_REJECTED = "AUTHORIZATION_REJECTED"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"


class UntrustedContributionError(ValueError):
    """Safe policy-boundary error that excludes source, credentials, and secrets."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: UntrustedContributionErrorCode) -> None:
        if type(code) is not UntrustedContributionErrorCode:
            raise TypeError("untrusted contribution error code is invalid")
        self.code = code
        self.safe_message = "SCM contribution launch was rejected"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class ContributionTrust(StrEnum):
    TRUSTED_SAME_REPOSITORY = "TRUSTED_SAME_REPOSITORY"
    UNTRUSTED_FORK = "UNTRUSTED_FORK"
    UNTRUSTED_SAME_REPOSITORY = "UNTRUSTED_SAME_REPOSITORY"
    UNKNOWN = "UNKNOWN"


class WorkerEgressPolicy(StrEnum):
    AIR_GAPPED = "AIR_GAPPED"


class WorkerMountKind(StrEnum):
    CHECKOUT = "CHECKOUT"
    SCRATCH = "SCRATCH"


class WorkerLaunchDisposition(StrEnum):
    CREATED = "CREATED"
    IDEMPOTENT = "IDEMPOTENT"
    CONFLICT = "CONFLICT"
    DENIED = "DENIED"
    SUPERSEDED = "SUPERSEDED"


class WorkerLaunchDenial(StrEnum):
    UNKNOWN_TRUST = "UNKNOWN_TRUST"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    CREDENTIAL_INVENTORY_FAILED = "CREDENTIAL_INVENTORY_FAILED"
    SCM_PUBLICATION_FORBIDDEN = "SCM_PUBLICATION_FORBIDDEN"


@dataclass(frozen=True, slots=True)
class TrustedSCMContributionMetadata:
    """Authenticated PR metadata, never repository-controlled configuration."""

    tenant_id: str
    base_repository_id: str
    head_repository_id: str
    base_sha: str
    head_sha: str
    is_fork: bool
    contributor_metadata_known: bool
    contributor_trusted: bool

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (
                    self.tenant_id,
                    self.base_repository_id,
                    self.head_repository_id,
                )
            )
            or type(self.base_sha) is not str
            or _COMMIT_SHA.fullmatch(self.base_sha) is None
            or type(self.head_sha) is not str
            or _COMMIT_SHA.fullmatch(self.head_sha) is None
            or any(
                type(value) is not bool
                for value in (
                    self.is_fork,
                    self.contributor_metadata_known,
                    self.contributor_trusted,
                )
            )
        ):
            raise UntrustedContributionError(UntrustedContributionErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class CredentialInventoryAttestation:
    """Zero-disclosure inventory result from the trusted worker host."""

    inventory_sha256: str
    scm_write_credentials_present: bool
    backend_credentials_present: bool
    provider_credentials_present: bool
    deployment_credentials_present: bool
    secret_canary_present: bool
    unknown_credential_present: bool

    def __post_init__(self) -> None:
        if (
            type(self.inventory_sha256) is not str
            or _SHA256.fullmatch(self.inventory_sha256) is None
            or any(
                type(value) is not bool
                for value in (
                    self.scm_write_credentials_present,
                    self.backend_credentials_present,
                    self.provider_credentials_present,
                    self.deployment_credentials_present,
                    self.secret_canary_present,
                    self.unknown_credential_present,
                )
            )
        ):
            raise UntrustedContributionError(UntrustedContributionErrorCode.INVALID_REQUEST)

    @property
    def is_credential_free(self) -> bool:
        return not any(
            (
                self.scm_write_credentials_present,
                self.backend_credentials_present,
                self.provider_credentials_present,
                self.deployment_credentials_present,
                self.secret_canary_present,
                self.unknown_credential_present,
            )
        )


@dataclass(frozen=True, slots=True)
class WorkerEnvironmentEntry:
    """One generated, allowlisted, non-secret worker environment entry."""

    name: str
    value: str

    def __post_init__(self) -> None:
        if (
            self.name not in _ENVIRONMENT_NAMES
            or type(self.value) is not str
            or not self.value
            or len(self.value) > 128
            or not self.value.isascii()
            or any(ord(character) < 32 or ord(character) > 126 for character in self.value)
        ):
            raise UntrustedContributionError(UntrustedContributionErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class WorkerMount:
    """One fixed worker mount. Callers cannot select host or arbitrary paths."""

    kind: WorkerMountKind
    target: str
    read_only: bool

    def __post_init__(self) -> None:
        expected = {
            WorkerMountKind.CHECKOUT: ("/workspace/repository", True),
            WorkerMountKind.SCRATCH: ("/workspace/scratch", False),
        }
        if (
            type(self.kind) is not WorkerMountKind
            or type(self.target) is not str
            or type(self.read_only) is not bool
            or expected.get(self.kind) != (self.target, self.read_only)
        ):
            raise UntrustedContributionError(UntrustedContributionErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class WorkerLaunchProjection:
    """Credential-free fixed envelope suitable for an external worker launcher."""

    launch_idempotency_key: str
    execution_identity_hash: str
    base_sha: str
    head_sha: str
    trust: ContributionTrust
    egress_policy: WorkerEgressPolicy
    environment: tuple[WorkerEnvironmentEntry, ...]
    mounts: tuple[WorkerMount, ...]
    read_only_checkout: bool
    isolated_scratch: bool
    credentials_available: bool
    scm_write_authority: bool
    backend_authority: bool
    provider_authority: bool
    deployment_authority: bool
    docker_socket_mounted: bool
    host_network: bool
    parent_namespaces_shared: bool
    arbitrary_mounts: bool


@dataclass(frozen=True, slots=True)
class SCMContributionLaunchRequest:
    """Policy input tied to an admitted exact-SHA SCM run."""

    scm_run_id: str
    execution_identity: RunExecutionIdentity
    scm_metadata: TrustedSCMContributionMetadata
    credential_inventory: CredentialInventoryAttestation
    requests_scm_publication: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.scm_run_id) is not str
            or _ID.fullmatch(self.scm_run_id) is None
            or type(self.execution_identity) is not RunExecutionIdentity
            or type(self.scm_metadata) is not TrustedSCMContributionMetadata
            or type(self.credential_inventory) is not CredentialInventoryAttestation
            or type(self.requests_scm_publication) is not bool
        ):
            raise UntrustedContributionError(UntrustedContributionErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class SCMContributionLaunchReceipt:
    """Source-free launch decision. It does not execute or publish anything."""

    disposition: WorkerLaunchDisposition
    trust: ContributionTrust
    denial: WorkerLaunchDenial | None
    projection: WorkerLaunchProjection | None
    publication: SCMRunPublicationReceipt
    source_disclosed: bool = False
    credentials_disclosed: bool = False
    scm_publication_permitted: bool = False


class SCMContributionLaunchPublisher:
    """Build deterministic least-privilege launch projections after fresh HEAD checks."""

    __slots__ = ("_adapter", "_launches", "_lock")

    def __init__(self, adapter: GithubAppAdapter) -> None:
        if type(adapter) is not GithubAppAdapter:
            raise UntrustedContributionError(UntrustedContributionErrorCode.INVALID_REQUEST)
        self._adapter = adapter
        self._lock = RLock()
        self._launches: dict[str, WorkerLaunchProjection] = {}

    def project(self, request: SCMContributionLaunchRequest) -> SCMContributionLaunchReceipt:
        """Return a launch projection only if trusted metadata and inventory are safe."""

        if type(request) is not SCMContributionLaunchRequest:
            raise UntrustedContributionError(UntrustedContributionErrorCode.INVALID_REQUEST)
        publication = self._authorize(request.scm_run_id)
        trust = _classify(request.scm_metadata)
        if publication.disposition is PublicationDisposition.SUPERSEDED:
            return SCMContributionLaunchReceipt(
                WorkerLaunchDisposition.SUPERSEDED,
                trust,
                None,
                None,
                publication,
            )
        if not _identity_matches(request.execution_identity, request.scm_metadata, publication):
            return SCMContributionLaunchReceipt(
                WorkerLaunchDisposition.DENIED,
                trust,
                WorkerLaunchDenial.IDENTITY_MISMATCH,
                None,
                publication,
            )
        if trust is ContributionTrust.UNKNOWN:
            return SCMContributionLaunchReceipt(
                WorkerLaunchDisposition.DENIED,
                trust,
                WorkerLaunchDenial.UNKNOWN_TRUST,
                None,
                publication,
            )
        if request.requests_scm_publication:
            return SCMContributionLaunchReceipt(
                WorkerLaunchDisposition.DENIED,
                trust,
                WorkerLaunchDenial.SCM_PUBLICATION_FORBIDDEN,
                None,
                publication,
            )
        if not request.credential_inventory.is_credential_free:
            return SCMContributionLaunchReceipt(
                WorkerLaunchDisposition.DENIED,
                trust,
                WorkerLaunchDenial.CREDENTIAL_INVENTORY_FAILED,
                None,
                publication,
            )
        projection = _projection(request, trust)
        with self._lock:
            previous = self._launches.get(projection.launch_idempotency_key)
            if previous is None:
                self._launches[projection.launch_idempotency_key] = projection
                disposition = WorkerLaunchDisposition.CREATED
            elif previous == projection:
                disposition = WorkerLaunchDisposition.IDEMPOTENT
            else:
                return SCMContributionLaunchReceipt(
                    WorkerLaunchDisposition.CONFLICT,
                    trust,
                    None,
                    None,
                    publication,
                )
        return SCMContributionLaunchReceipt(
            disposition,
            trust,
            None,
            projection,
            publication,
        )

    def _authorize(self, scm_run_id: str) -> SCMRunPublicationReceipt:
        try:
            publication = self._adapter.authorize_publication(scm_run_id)
        except GithubAppError as error:
            raise UntrustedContributionError(
                UntrustedContributionErrorCode.AUTHORIZATION_REJECTED
            ) from error
        if publication.disposition not in {
            PublicationDisposition.AUTHORIZED,
            PublicationDisposition.SUPERSEDED,
        }:
            raise UntrustedContributionError(UntrustedContributionErrorCode.AUTHORIZATION_REJECTED)
        return publication


def _classify(metadata: TrustedSCMContributionMetadata) -> ContributionTrust:
    if not metadata.contributor_metadata_known:
        return ContributionTrust.UNKNOWN
    same_repository = metadata.head_repository_id == metadata.base_repository_id
    if metadata.is_fork and not same_repository:
        return ContributionTrust.UNTRUSTED_FORK
    if not metadata.is_fork and same_repository and metadata.contributor_trusted:
        return ContributionTrust.TRUSTED_SAME_REPOSITORY
    if not metadata.is_fork and same_repository:
        return ContributionTrust.UNTRUSTED_SAME_REPOSITORY
    return ContributionTrust.UNKNOWN


def _identity_matches(
    identity: RunExecutionIdentity,
    metadata: TrustedSCMContributionMetadata,
    publication: SCMRunPublicationReceipt,
) -> bool:
    revision = identity.repository_revision
    return (
        revision.base_sha is not None
        and publication.disposition is PublicationDisposition.AUTHORIZED
        and publication.execution_identity_hash == identity.execution_identity_hash
        and publication.head_sha == revision.head_sha
        and publication.current_head_sha == revision.head_sha
        and metadata.tenant_id == revision.tenant_id
        and metadata.base_repository_id == revision.repository_id
        and metadata.base_sha == revision.base_sha
        and metadata.head_sha == revision.head_sha
    )


def _projection(
    request: SCMContributionLaunchRequest,
    trust: ContributionTrust,
) -> WorkerLaunchProjection:
    identity = request.execution_identity
    revision = identity.repository_revision
    if revision.base_sha is None:
        raise UntrustedContributionError(UntrustedContributionErrorCode.IDENTITY_MISMATCH)
    environment = (
        WorkerEnvironmentEntry("SECURECODE_BASE_SHA", revision.base_sha),
        WorkerEnvironmentEntry(
            "SECURECODE_EGRESS_PROFILE_SHA256",
            identity.egress_profile.content_sha256,
        ),
        WorkerEnvironmentEntry(
            "SECURECODE_EXECUTION_IDENTITY_HASH",
            identity.execution_identity_hash,
        ),
        WorkerEnvironmentEntry("SECURECODE_HEAD_SHA", revision.head_sha),
        WorkerEnvironmentEntry("SECURECODE_TRUST_CLASS", trust.value),
    )
    mounts = (
        WorkerMount(WorkerMountKind.CHECKOUT, "/workspace/repository", True),
        WorkerMount(WorkerMountKind.SCRATCH, "/workspace/scratch", False),
    )
    return WorkerLaunchProjection(
        launch_idempotency_key=_idempotency_key(request.scm_run_id, identity),
        execution_identity_hash=identity.execution_identity_hash,
        base_sha=revision.base_sha,
        head_sha=revision.head_sha,
        trust=trust,
        egress_policy=WorkerEgressPolicy.AIR_GAPPED,
        environment=environment,
        mounts=mounts,
        read_only_checkout=True,
        isolated_scratch=True,
        credentials_available=False,
        scm_write_authority=False,
        backend_authority=False,
        provider_authority=False,
        deployment_authority=False,
        docker_socket_mounted=False,
        host_network=False,
        parent_namespaces_shared=False,
        arbitrary_mounts=False,
    )


def _idempotency_key(scm_run_id: str, identity: RunExecutionIdentity) -> str:
    material = json.dumps(
        {
            "execution_identity_hash": identity.execution_identity_hash,
            "scm_run_id": scm_run_id,
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "launch-" + hashlib.sha256(_HASH_DOMAIN + material).hexdigest()[:40]


__all__ = [
    "ContributionTrust",
    "CredentialInventoryAttestation",
    "SCMContributionLaunchPublisher",
    "SCMContributionLaunchReceipt",
    "SCMContributionLaunchRequest",
    "TrustedSCMContributionMetadata",
    "UntrustedContributionError",
    "UntrustedContributionErrorCode",
    "WorkerEgressPolicy",
    "WorkerEnvironmentEntry",
    "WorkerLaunchDenial",
    "WorkerLaunchDisposition",
    "WorkerLaunchProjection",
    "WorkerMount",
    "WorkerMountKind",
]
