"""P6.4/P5.9 artifact intake: authorize, upload and register one run artifact.

The worker produces content (an evidence graph or an audit report) and must make
it citable by a terminal finding.  Three durable subsystems have to happen in
order for that to be true — a signed upload authorization bound to the live
lease, the exact bytes committed into the content-addressed store, and the
registered ``run_artifacts`` row the completion path validates against.  This
module is that sequence in one call, so no caller has to re-derive it.

It composes existing pieces and adds no new storage: authorization truth stays in
``SqliteArtifactAuthorizationStore``, bytes in the upload service, registration in
``SqliteWorkerQueue.advance``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION, ArtifactRef, DataClass

from .artifact_upload import (
    ArtifactPutRequest,
    ArtifactUploadService,
    AuthorizedLocalArtifactUploadService,
)
from .worker_artifact_authorization import (
    ArtifactUploadAuthorization,
    SqliteArtifactAuthorizationStore,
)
from .worker_queue import SqliteWorkerQueue

EVIDENCE_GRAPH_PURPOSE: Final = "evidence-graph"
AUDIT_REPORT_PURPOSE: Final = "audit-report"


class ArtifactIntakeError(RuntimeError):
    """Bounded failure for one rejected artifact intake."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("artifact intake was rejected")


@dataclass(frozen=True, slots=True)
class ArtifactIntakeReceipt:
    """Source-free result of one authorized, uploaded and registered artifact."""

    authorization_id: str
    content_id: str
    content_sha256: str
    size_bytes: int
    object_key: str
    purpose: str
    session_id: str
    lease_version: int

    def document(self) -> dict[str, object]:
        return {
            "authorization_id": self.authorization_id,
            "content_id": self.content_id,
            "content_sha256": self.content_sha256,
            "size_bytes": self.size_bytes,
            "object_key": self.object_key,
            "purpose": self.purpose,
            "session_id": self.session_id,
            "lease_version": self.lease_version,
        }


@dataclass(frozen=True, slots=True)
class ArtifactIntakeRequest:
    """Trusted, already-leased context for one artifact commit."""

    tenant_id: str
    worker_id: str
    repository_id: str
    run_id: str
    session_id: str
    execution_identity_hash: str
    expected_version: int
    content_id: str
    content: bytes
    purpose: str
    idempotency_key: str
    request_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.content) is not bytes
            or not self.content
            or self.purpose not in {EVIDENCE_GRAPH_PURPOSE, AUDIT_REPORT_PURPOSE}
            or type(self.expected_version) is not int
            or self.expected_version < 1
        ):
            raise ArtifactIntakeError("INVALID_REQUEST")

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


class ArtifactIntake:
    """Commit one artifact and register it against the leased run."""

    __slots__ = ("_authorizations", "_queue", "_uploads")

    def __init__(
        self,
        *,
        queue: SqliteWorkerQueue,
        authorizations: SqliteArtifactAuthorizationStore,
        uploads: AuthorizedLocalArtifactUploadService,
    ) -> None:
        if (
            not isinstance(queue, SqliteWorkerQueue)
            or not isinstance(authorizations, SqliteArtifactAuthorizationStore)
            or not isinstance(uploads, AuthorizedLocalArtifactUploadService)
        ):
            raise ArtifactIntakeError("INVALID_CONFIGURATION")
        self._queue = queue
        self._authorizations = authorizations
        self._uploads = uploads

    async def commit(self, request: ArtifactIntakeRequest) -> ArtifactIntakeReceipt:
        """Authorize, upload and register; any rejected step aborts the intake."""

        if type(request) is not ArtifactIntakeRequest:
            raise ArtifactIntakeError("INVALID_REQUEST")
        digest = request.content_sha256
        try:
            authorization = self._authorizations.issue(
                tenant_id=request.tenant_id,
                worker_id=request.worker_id,
                repository_id=request.repository_id,
                run_id=request.run_id,
                execution_identity_hash=request.execution_identity_hash,
                artifact_ref=ArtifactRef(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    tenant_id=request.tenant_id,
                    content_id=request.content_id,
                    content_sha256=digest,
                    size_bytes=len(request.content),
                    data_class=DataClass.INTERNAL_METADATA,
                ),
                purpose=request.purpose,
                method="PUT",
                idempotency_key=request.idempotency_key,
                request_sha256=request.request_sha256,
            )
        except Exception:
            raise ArtifactIntakeError("AUTHORIZATION_REJECTED") from None
        receipt = await self._upload(request, authorization)
        return self._register(request, authorization, receipt, digest)

    async def _upload(
        self,
        request: ArtifactIntakeRequest,
        authorization: ArtifactUploadAuthorization,
    ) -> object:
        uploads: ArtifactUploadService = self._uploads
        try:
            return await uploads.put(
                ArtifactPutRequest(
                    authorization_id=authorization.authorization_id,
                    tenant_id=authorization.tenant_id,
                    worker_id=authorization.worker_id,
                    run_id=authorization.run_id,
                    execution_identity_hash=authorization.execution_identity_hash,
                    content_sha256=authorization.content_sha256,
                    size_bytes=authorization.size_bytes,
                    purpose=authorization.purpose,
                    receipt_signature=authorization.receipt_signature,
                    content=request.content,
                )
            )
        except Exception:
            raise ArtifactIntakeError("UPLOAD_REJECTED") from None

    def _register(
        self,
        request: ArtifactIntakeRequest,
        authorization: ArtifactUploadAuthorization,
        receipt: object,
        digest: str,
    ) -> ArtifactIntakeReceipt:
        """Register the committed artifact so a terminal finding may cite it."""

        object_key = str(getattr(receipt, "object_key", ""))
        if not object_key:
            raise ArtifactIntakeError("UPLOAD_REJECTED")
        try:
            lease = self._queue.advance(
                tenant_id=request.tenant_id,
                session_id=request.session_id,
                worker_id=request.worker_id,
                execution_identity_hash=request.execution_identity_hash,
                run_id=request.run_id,
                expected_version=request.expected_version,
                artifact={
                    "authorization_id": authorization.authorization_id,
                    "content_id": request.content_id,
                    "content_sha256": digest,
                    "purpose": request.purpose,
                    "size_bytes": len(request.content),
                },
            )
        except Exception:
            raise ArtifactIntakeError("REGISTRATION_REJECTED") from None
        return ArtifactIntakeReceipt(
            authorization_id=authorization.authorization_id,
            content_id=request.content_id,
            content_sha256=digest,
            size_bytes=len(request.content),
            object_key=object_key,
            purpose=request.purpose,
            session_id=request.session_id,
            lease_version=lease.version,
        )


__all__ = [
    "AUDIT_REPORT_PURPOSE",
    "EVIDENCE_GRAPH_PURPOSE",
    "ArtifactIntake",
    "ArtifactIntakeError",
    "ArtifactIntakeReceipt",
    "ArtifactIntakeRequest",
]
