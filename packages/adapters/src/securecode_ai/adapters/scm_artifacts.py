"""SCM-safe metadata artifact and optional SARIF publication projections.

The module is deliberately transport-free.  It emits deterministic upload work
items and records bounded, metadata-only outcomes supplied by an SCM transport.
Neither reports nor SARIF payloads can grant merge authority or alter an audit
outcome.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final
from urllib.parse import urlsplit

from securecode_ai.contracts import ArtifactRef, DataClass, RunExecutionIdentity
from securecode_ai.core.scm_run_state import PublicationDisposition, SCMRunPublicationReceipt

from .github_app import GithubAppAdapter, GithubAppError

MAX_SCM_ARTIFACTS: Final = 20
MAX_SCM_ARTIFACT_BYTES: Final = 10_485_760
MAX_UPLOAD_ATTEMPTS: Final = 3
DEFAULT_ALLOWED_HTTPS_ARTIFACT_HOSTS: Final = frozenset({"artifacts.securecode.ai"})
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_NAME: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
_SAFE_REFERENCE_PATH: Final = re.compile(r"/[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\Z")
_HOST: Final = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/scm-artifact/v1\x00"
_ALLOWED_DATA_CLASSES: Final = frozenset(
    {DataClass.PUBLIC, DataClass.INTERNAL_METADATA, DataClass.CONFIDENTIAL_SECURITY}
)
_REPORT_MEDIA_TYPES: Final = frozenset({"application/json", "text/markdown", "text/plain"})
_SARIF_MEDIA_TYPE: Final = "application/sarif+json"


class SCMArtifactErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    AUTHORIZATION_REJECTED = "AUTHORIZATION_REJECTED"
    UNSAFE_REFERENCE = "UNSAFE_REFERENCE"
    UPLOAD_UNKNOWN = "UPLOAD_UNKNOWN"


class SCMArtifactError(ValueError):
    """Bounded artifact boundary error that excludes content and credentials."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: SCMArtifactErrorCode) -> None:
        if type(code) is not SCMArtifactErrorCode:
            raise TypeError("SCM artifact error code is invalid")
        self.code = code
        self.safe_message = "SCM artifact publication was rejected"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class SCMArtifactKind(StrEnum):
    REPORT = "REPORT"
    SARIF = "SARIF"


class SCMArtifactDisposition(StrEnum):
    CREATED = "CREATED"
    IDEMPOTENT = "IDEMPOTENT"
    UPLOADED = "UPLOADED"
    RETRY_READY = "RETRY_READY"
    FAILED = "FAILED"
    SUPERSEDED = "SUPERSEDED"


class SCMArtifactSuppression(StrEnum):
    STALE_RUN = "STALE_RUN"
    SARIF_CAPABILITY_ABSENT = "SARIF_CAPABILITY_ABSENT"


@dataclass(frozen=True, slots=True)
class SCMArtifactCapabilities:
    """Explicit non-authoritative capabilities granted to this publication port."""

    sarif_upload_enabled: bool = False

    def __post_init__(self) -> None:
        if type(self.sarif_upload_enabled) is not bool:
            raise SCMArtifactError(SCMArtifactErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class SCMArtifactInput:
    """One metadata-only artifact bound to an immutable content-addressed object."""

    artifact: ArtifactRef
    safe_name: str
    media_type: str
    metadata_reference: str

    def __post_init__(self) -> None:
        if (
            type(self.artifact) is not ArtifactRef
            or type(self.safe_name) is not str
            or not _safe_name(self.safe_name)
            or type(self.media_type) is not str
            or self.media_type not in _REPORT_MEDIA_TYPES | {_SARIF_MEDIA_TYPE}
            or type(self.metadata_reference) is not str
            or not _reference_shape_is_safe(self.metadata_reference, self.artifact.content_id)
            or self.artifact.size_bytes > MAX_SCM_ARTIFACT_BYTES
            or self.artifact.data_class not in _ALLOWED_DATA_CLASSES
        ):
            raise SCMArtifactError(SCMArtifactErrorCode.INVALID_REQUEST)

    @property
    def kind(self) -> SCMArtifactKind:
        return (
            SCMArtifactKind.SARIF
            if self.media_type == _SARIF_MEDIA_TYPE
            else SCMArtifactKind.REPORT
        )


@dataclass(frozen=True, slots=True)
class SCMArtifactRequest:
    """Exact-run artifact projection request with an explicit SARIF capability."""

    scm_run_id: str
    execution_identity: RunExecutionIdentity
    artifacts: tuple[SCMArtifactInput, ...]
    capabilities: SCMArtifactCapabilities

    def __post_init__(self) -> None:
        if (
            type(self.scm_run_id) is not str
            or _ID.fullmatch(self.scm_run_id) is None
            or type(self.execution_identity) is not RunExecutionIdentity
            or type(self.artifacts) is not tuple
            or not self.artifacts
            or len(self.artifacts) > MAX_SCM_ARTIFACTS
            or any(type(item) is not SCMArtifactInput for item in self.artifacts)
            or len({item.safe_name for item in self.artifacts}) != len(self.artifacts)
            or type(self.capabilities) is not SCMArtifactCapabilities
        ):
            raise SCMArtifactError(SCMArtifactErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class SCMArtifactProjection:
    """Deterministic upload work item containing only artifact metadata."""

    upload_idempotency_key: str
    safe_name: str
    kind: SCMArtifactKind
    content_sha256: str
    size_bytes: int
    media_type: str
    metadata_reference: str
    execution_identity_hash: str
    head_sha: str
    merge_authority: bool = False
    comments_merge_authority: bool = False
    sarif_merge_authority: bool = False


@dataclass(frozen=True, slots=True)
class SCMArtifactUploadReceipt:
    """Metadata-only state of one transport upload attempt."""

    disposition: SCMArtifactDisposition
    upload_idempotency_key: str
    attempt_count: int
    retry_allowed: bool
    audit_outcome_changed: bool
    merge_authority: bool
    publication: SCMRunPublicationReceipt


@dataclass(frozen=True, slots=True)
class SCMArtifactSuppressionReceipt:
    safe_name: str
    reason: SCMArtifactSuppression


@dataclass(frozen=True, slots=True)
class SCMArtifactBatchReceipt:
    """Projection receipt with no payload bytes and no audit outcome mutation."""

    publication: SCMRunPublicationReceipt
    uploads: tuple[SCMArtifactUploadReceipt, ...]
    suppressions: tuple[SCMArtifactSuppressionReceipt, ...]
    audit_outcome_changed: bool = False
    merge_authority: bool = False


@dataclass(slots=True)
class _StoredUpload:
    scm_run_id: str
    execution_identity: RunExecutionIdentity
    projection: SCMArtifactProjection
    attempts: int = 0
    disposition: SCMArtifactDisposition = SCMArtifactDisposition.CREATED


class SCMArtifactPublisher:
    """Create idempotent work items and record bounded transport outcomes."""

    __slots__ = ("_adapter", "_allowed_https_hosts", "_lock", "_uploads")

    def __init__(
        self,
        adapter: GithubAppAdapter,
        *,
        allowed_https_hosts: frozenset[str] = DEFAULT_ALLOWED_HTTPS_ARTIFACT_HOSTS,
    ) -> None:
        if type(adapter) is not GithubAppAdapter or not _valid_hosts(allowed_https_hosts):
            raise SCMArtifactError(SCMArtifactErrorCode.INVALID_REQUEST)
        self._adapter = adapter
        self._allowed_https_hosts = allowed_https_hosts
        self._lock = RLock()
        self._uploads: dict[str, _StoredUpload] = {}

    def project(self, request: SCMArtifactRequest) -> SCMArtifactBatchReceipt:
        """Authorize exact HEAD and create metadata-only upload work items."""

        if type(request) is not SCMArtifactRequest:
            raise SCMArtifactError(SCMArtifactErrorCode.INVALID_REQUEST)
        publication = self._authorize(request.scm_run_id)
        if publication.disposition is PublicationDisposition.SUPERSEDED:
            return SCMArtifactBatchReceipt(
                publication=publication,
                uploads=(),
                suppressions=tuple(
                    SCMArtifactSuppressionReceipt(item.safe_name, SCMArtifactSuppression.STALE_RUN)
                    for item in request.artifacts
                ),
            )
        self._verify_publication(publication, request.execution_identity)
        uploads: list[SCMArtifactUploadReceipt] = []
        suppressions: list[SCMArtifactSuppressionReceipt] = []
        for item in sorted(request.artifacts, key=lambda candidate: candidate.safe_name):
            if item.artifact.tenant_id != request.execution_identity.repository_revision.tenant_id:
                raise SCMArtifactError(SCMArtifactErrorCode.IDENTITY_MISMATCH)
            if not _reference_allowed(
                item.metadata_reference,
                item.artifact.content_id,
                self._allowed_https_hosts,
            ):
                raise SCMArtifactError(SCMArtifactErrorCode.UNSAFE_REFERENCE)
            if item.kind is SCMArtifactKind.SARIF and not request.capabilities.sarif_upload_enabled:
                suppressions.append(
                    SCMArtifactSuppressionReceipt(
                        item.safe_name,
                        SCMArtifactSuppression.SARIF_CAPABILITY_ABSENT,
                    )
                )
                continue
            projection = _projection(request, item)
            uploads.append(self._store_projection(request, projection, publication))
        return SCMArtifactBatchReceipt(
            publication=publication,
            uploads=tuple(uploads),
            suppressions=tuple(suppressions),
        )

    def record_upload_result(
        self,
        upload_idempotency_key: str,
        *,
        succeeded: bool,
    ) -> SCMArtifactUploadReceipt:
        """Record a transport result after another fresh exact-HEAD authorization."""

        if (
            type(upload_idempotency_key) is not str
            or _ID.fullmatch(upload_idempotency_key) is None
            or type(succeeded) is not bool
        ):
            raise SCMArtifactError(SCMArtifactErrorCode.INVALID_REQUEST)
        with self._lock:
            stored = self._uploads.get(upload_idempotency_key)
            if stored is None:
                raise SCMArtifactError(SCMArtifactErrorCode.UPLOAD_UNKNOWN)
            run_id = stored.scm_run_id
            identity = stored.execution_identity
        publication = self._authorize(run_id)
        if publication.disposition is PublicationDisposition.SUPERSEDED:
            return SCMArtifactUploadReceipt(
                disposition=SCMArtifactDisposition.SUPERSEDED,
                upload_idempotency_key=upload_idempotency_key,
                attempt_count=stored.attempts,
                retry_allowed=False,
                audit_outcome_changed=False,
                merge_authority=False,
                publication=publication,
            )
        self._verify_publication(publication, identity)
        with self._lock:
            stored = self._uploads[upload_idempotency_key]
            if stored.disposition is SCMArtifactDisposition.UPLOADED:
                return _upload_receipt(stored, SCMArtifactDisposition.IDEMPOTENT, publication)
            if stored.disposition is SCMArtifactDisposition.FAILED:
                return _upload_receipt(stored, SCMArtifactDisposition.FAILED, publication)
            stored.attempts += 1
            if succeeded:
                stored.disposition = SCMArtifactDisposition.UPLOADED
                return _upload_receipt(stored, SCMArtifactDisposition.UPLOADED, publication)
            if stored.attempts >= MAX_UPLOAD_ATTEMPTS:
                stored.disposition = SCMArtifactDisposition.FAILED
                return _upload_receipt(stored, SCMArtifactDisposition.FAILED, publication)
            stored.disposition = SCMArtifactDisposition.RETRY_READY
            return _upload_receipt(stored, SCMArtifactDisposition.RETRY_READY, publication)

    def _store_projection(
        self,
        request: SCMArtifactRequest,
        projection: SCMArtifactProjection,
        publication: SCMRunPublicationReceipt,
    ) -> SCMArtifactUploadReceipt:
        with self._lock:
            stored = self._uploads.get(projection.upload_idempotency_key)
            if stored is None:
                stored = _StoredUpload(
                    scm_run_id=request.scm_run_id,
                    execution_identity=request.execution_identity,
                    projection=projection,
                )
                self._uploads[projection.upload_idempotency_key] = stored
                return _upload_receipt(stored, SCMArtifactDisposition.CREATED, publication)
            if (
                stored.scm_run_id != request.scm_run_id
                or stored.execution_identity != request.execution_identity
                or stored.projection != projection
            ):
                raise SCMArtifactError(SCMArtifactErrorCode.IDENTITY_MISMATCH)
            return _upload_receipt(stored, SCMArtifactDisposition.IDEMPOTENT, publication)

    def _authorize(self, scm_run_id: str) -> SCMRunPublicationReceipt:
        try:
            publication = self._adapter.authorize_publication(scm_run_id)
        except GithubAppError as error:
            raise SCMArtifactError(SCMArtifactErrorCode.AUTHORIZATION_REJECTED) from error
        if publication.disposition not in {
            PublicationDisposition.AUTHORIZED,
            PublicationDisposition.SUPERSEDED,
        }:
            raise SCMArtifactError(SCMArtifactErrorCode.AUTHORIZATION_REJECTED)
        return publication

    @staticmethod
    def _verify_publication(
        publication: SCMRunPublicationReceipt,
        identity: RunExecutionIdentity,
    ) -> None:
        revision = identity.repository_revision
        if (
            publication.disposition is not PublicationDisposition.AUTHORIZED
            or publication.execution_identity_hash != identity.execution_identity_hash
            or publication.head_sha != revision.head_sha
            or publication.current_head_sha != revision.head_sha
        ):
            raise SCMArtifactError(SCMArtifactErrorCode.IDENTITY_MISMATCH)


def _projection(request: SCMArtifactRequest, item: SCMArtifactInput) -> SCMArtifactProjection:
    identity = request.execution_identity
    return SCMArtifactProjection(
        upload_idempotency_key=_idempotency_key(request.scm_run_id, identity, item),
        safe_name=item.safe_name,
        kind=item.kind,
        content_sha256=item.artifact.content_sha256,
        size_bytes=item.artifact.size_bytes,
        media_type=item.media_type,
        metadata_reference=item.metadata_reference,
        execution_identity_hash=identity.execution_identity_hash,
        head_sha=identity.repository_revision.head_sha,
    )


def _idempotency_key(
    scm_run_id: str,
    identity: RunExecutionIdentity,
    item: SCMArtifactInput,
) -> str:
    material = json.dumps(
        {
            "content_sha256": item.artifact.content_sha256,
            "execution_identity_hash": identity.execution_identity_hash,
            "media_type": item.media_type,
            "safe_name": item.safe_name,
            "scm_run_id": scm_run_id,
            "size_bytes": item.artifact.size_bytes,
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "artifact-" + hashlib.sha256(_HASH_DOMAIN + material).hexdigest()[:40]


def _upload_receipt(
    stored: _StoredUpload,
    disposition: SCMArtifactDisposition,
    publication: SCMRunPublicationReceipt,
) -> SCMArtifactUploadReceipt:
    retry_allowed = disposition is SCMArtifactDisposition.RETRY_READY
    return SCMArtifactUploadReceipt(
        disposition=disposition,
        upload_idempotency_key=stored.projection.upload_idempotency_key,
        attempt_count=stored.attempts,
        retry_allowed=retry_allowed,
        audit_outcome_changed=False,
        merge_authority=False,
        publication=publication,
    )


def _safe_name(value: str) -> bool:
    return (
        _SAFE_NAME.fullmatch(value) is not None
        and "//" not in value
        and all(part not in {".", ".."} for part in value.split("/"))
    )


def _reference_shape_is_safe(reference: str, content_id: str) -> bool:
    if reference == f"scm://artifact/{content_id}":
        return True
    parsed = urlsplit(reference)
    return (
        parsed.scheme == "https"
        and parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None
        and parsed.port is None
        and not parsed.query
        and not parsed.fragment
        and _SAFE_REFERENCE_PATH.fullmatch(parsed.path) is not None
    )


def _reference_allowed(
    reference: str, content_id: str, allowed_https_hosts: frozenset[str]
) -> bool:
    if reference == f"scm://artifact/{content_id}":
        return True
    parsed = urlsplit(reference)
    return (
        _reference_shape_is_safe(reference, content_id)
        and parsed.hostname is not None
        and parsed.hostname.lower() in allowed_https_hosts
    )


def _valid_hosts(value: object) -> bool:
    return (
        type(value) is frozenset
        and bool(value)
        and all(
            type(host) is str and host == host.lower() and _HOST.fullmatch(host) is not None
            for host in value
        )
    )


__all__ = [
    "DEFAULT_ALLOWED_HTTPS_ARTIFACT_HOSTS",
    "MAX_SCM_ARTIFACTS",
    "MAX_SCM_ARTIFACT_BYTES",
    "MAX_UPLOAD_ATTEMPTS",
    "SCMArtifactBatchReceipt",
    "SCMArtifactCapabilities",
    "SCMArtifactDisposition",
    "SCMArtifactError",
    "SCMArtifactErrorCode",
    "SCMArtifactInput",
    "SCMArtifactKind",
    "SCMArtifactProjection",
    "SCMArtifactPublisher",
    "SCMArtifactRequest",
    "SCMArtifactSuppression",
    "SCMArtifactSuppressionReceipt",
    "SCMArtifactUploadReceipt",
]
