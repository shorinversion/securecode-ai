"""P6.4/P5.9 artifact upload: signed authorization, exact bytes, atomic storage."""

from __future__ import annotations

import asyncio
import hashlib
import json
import pathlib
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ArtifactRef,
    ComponentPin,
    DataClass,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.contracts.domain import ACCEPTED_STAGE_CATALOGUE_PIN
from securecode_ai.server.artifact_upload import (
    ArtifactPutRequest,
    ArtifactUploadReceipt,
    ArtifactUploadRejected,
    AuthorizedLocalArtifactUploadService,
)
from securecode_ai.server.persistence import DevelopmentRepository
from securecode_ai.server.worker_artifact_authorization import (
    ArtifactAuthorizationDenied,
    ArtifactUploadAuthorization,
    HmacSha256ArtifactReceiptSigner,
    SqliteArtifactAuthorizationStore,
    StaticArtifactUploadUrlFactory,
)
from securecode_ai.server.worker_queue import SqliteWorkerQueue
from securecode_ai.server.worker_queue_models import WorkerQueueLease

TENANT = "tenant-1"
OTHER_TENANT = "tenant-2"
REPOSITORY = "repo-1"
RUN_ID = "run-1"
WORKER_ID = "worker-1"
HEAD = "a" * 40
BASE = "b" * 40
HASH_A = "a" * 64
SECRET = b"artifact-receipt-secret-32-bytes-min"
PURPOSE = "evidence-graph"
NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
CONTENT = b'{"graph":"evidence"}\n'


def _pin(name: str, digest: str) -> ComponentPin:
    if name == "catalogue":
        component_id, version, accepted = ACCEPTED_STAGE_CATALOGUE_PIN
        return ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id=component_id,
            component_version=version,
            content_sha256=accepted,
        )
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=name,
        component_version="1.0.0",
        content_sha256=digest,
    )


def _identity() -> RunExecutionIdentity:
    return RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=TENANT,
            scm_provider="gitlab",
            repository_id=REPOSITORY,
            head_sha=HEAD,
            base_sha=BASE,
        ),
        stage_catalogue=_pin("catalogue", HASH_A),
        workflow=_pin("workflow", HASH_A),
        policy=_pin("policy", "c" * 64),
        configuration=_pin("configuration", "d" * 64),
        provider_profile=_pin("provider", "e" * 64),
        capability_profile=_pin("capability", "f" * 64),
        egress_profile=_pin("egress", "1" * 64),
    )


class World:
    """A leased RUNNING run plus the signed upload path for one artifact."""

    def __init__(self, tmp_path: Path, *, max_bytes: int = 1_048_576) -> None:
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.repository = DevelopmentRepository(self.connection)
        self.identity = _identity()
        self.clock = {"now": NOW}
        self.queue = SqliteWorkerQueue(
            self.connection, lease_seconds=3600, now=lambda: self.clock["now"]
        )
        self.signers = HmacSha256ArtifactReceiptSigner(SECRET, key_id="key-1")
        self.authorizations = SqliteArtifactAuthorizationStore(
            self.connection,
            signer=self.signers,
            upload_urls=StaticArtifactUploadUrlFactory("https://uploads.example.invalid"),
            ttl_seconds=600,
            now=lambda: self.clock["now"],
        )
        self.service = AuthorizedLocalArtifactUploadService(
            tmp_path / "objects",
            authorizations=self.authorizations,
            max_bytes=max_bytes,
            now=lambda: self.clock["now"],
        )
        self.content = CONTENT
        self.content_sha256 = hashlib.sha256(self.content).hexdigest()
        self.lease: WorkerQueueLease | None = None

    def start_run(self) -> None:
        self.repository.create_run(
            tenant_id=TENANT,
            run_id=RUN_ID,
            repository_id=REPOSITORY,
            execution_identity_hash=self.identity.execution_identity_hash,
            base_sha=BASE,
            head_sha=HEAD,
            metadata={"scm_provider": "gitlab"},
            idempotency_key="intake-0001",
            request_sha256=HASH_A,
        )
        self.queue.enqueue(tenant_id=TENANT, run_id=RUN_ID, execution_identity=self.identity)
        lease = self.queue.claim(
            tenant_id=TENANT,
            worker_id=WORKER_ID,
            idempotency_key="claim-0001",
            allowed_repository_ids=frozenset({REPOSITORY}),
        )
        assert lease is not None
        self.lease = lease

    def authorize(
        self,
        *,
        content_sha256: str | None = None,
        size_bytes: int | None = None,
        purpose: str = PURPOSE,
        tenant_id: str = TENANT,
        worker_id: str = WORKER_ID,
        idempotency_key: str = "upload-0001",
    ) -> ArtifactUploadAuthorization:
        return self.authorizations.issue(
            tenant_id=tenant_id,
            worker_id=worker_id,
            session_id=self.lease.session_id if self.lease is not None else "session-unleased",
            repository_id=REPOSITORY,
            run_id=RUN_ID,
            execution_identity_hash=self.identity.execution_identity_hash,
            artifact_ref=ArtifactRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                tenant_id=tenant_id,
                content_id="graph-1",
                content_sha256=content_sha256 or self.content_sha256,
                size_bytes=size_bytes if size_bytes is not None else len(self.content),
                data_class=DataClass.INTERNAL_METADATA,
            ),
            purpose=purpose,
            method="PUT",
            idempotency_key=idempotency_key,
            request_sha256=HASH_A,
        )

    def request(
        self, authorization: ArtifactUploadAuthorization, **overrides: object
    ) -> ArtifactPutRequest:
        values: dict[str, object] = {
            "authorization_id": authorization.authorization_id,
            "tenant_id": authorization.tenant_id,
            "worker_id": authorization.worker_id,
            "run_id": authorization.run_id,
            "execution_identity_hash": authorization.execution_identity_hash,
            "content_sha256": authorization.content_sha256,
            "size_bytes": authorization.size_bytes,
            "purpose": authorization.purpose,
            "receipt_signature": authorization.receipt_signature,
            "content": self.content,
        }
        values.update(overrides)
        return ArtifactPutRequest(**values)  # type: ignore[arg-type]

    def upload(self, request: ArtifactPutRequest) -> ArtifactUploadReceipt:
        return asyncio.run(self.service.put(request))


def _world(tmp_path: Path, **kwargs: object) -> World:
    world = World(tmp_path, **kwargs)  # type: ignore[arg-type]
    world.start_run()
    return world


# --- authorization preconditions ---------------------------------------------


def test_authorization_requires_a_leased_running_run(tmp_path: Path) -> None:
    world = World(tmp_path)
    world.repository.create_run(
        tenant_id=TENANT,
        run_id=RUN_ID,
        repository_id=REPOSITORY,
        execution_identity_hash=world.identity.execution_identity_hash,
        base_sha=BASE,
        head_sha=HEAD,
        metadata={},
        idempotency_key="intake-0001",
        request_sha256=HASH_A,
    )
    with pytest.raises(ArtifactAuthorizationDenied):
        world.authorize()


def test_authorization_rejects_unknown_purpose(tmp_path: Path) -> None:
    world = _world(tmp_path)
    with pytest.raises(ArtifactAuthorizationDenied):
        world.authorize(purpose="not-a-purpose")


@pytest.mark.parametrize(
    "purpose",
    ["audit-report", "audit-run", "evidence-graph", "sarif-report"],
)
def test_authorization_accepts_every_worker_published_purpose(tmp_path: Path, purpose: str) -> None:
    world = _world(tmp_path)

    authorization = world.authorize(purpose=purpose, idempotency_key=f"upload-{purpose}")

    assert authorization.purpose == purpose


def test_sarif_authorization_is_idempotent_for_retries(tmp_path: Path) -> None:
    world = _world(tmp_path)

    first = world.authorize(purpose="sarif-report", idempotency_key="sarif-retry")
    replay = world.authorize(purpose="sarif-report", idempotency_key="sarif-retry")

    assert replay.authorization_id == first.authorization_id
    assert replay.receipt_signature == first.receipt_signature


def test_authorization_is_idempotent_for_one_key(tmp_path: Path) -> None:
    world = _world(tmp_path)
    first = world.authorize()
    second = world.authorize()
    assert first.authorization_id == second.authorization_id
    assert first.receipt_signature == second.receipt_signature


def test_expired_authorization_is_not_returned_for_idempotent_replay(tmp_path: Path) -> None:
    world = _world(tmp_path)
    first = world.authorize()

    world.clock["now"] = first.expires_at

    with pytest.raises(ArtifactAuthorizationDenied):
        world.authorize()


def test_authorization_rejects_foreign_tenant_reference(tmp_path: Path) -> None:
    world = _world(tmp_path)
    with pytest.raises(ArtifactAuthorizationDenied):
        world.authorize(tenant_id=OTHER_TENANT)


# --- upload happy path -------------------------------------------------------


def test_upload_stores_exact_bytes_and_returns_source_free_receipt(tmp_path: Path) -> None:
    world = _world(tmp_path)
    authorization = world.authorize()
    receipt = world.upload(world.request(authorization))

    assert receipt.tenant_id == TENANT
    assert receipt.run_id == RUN_ID
    assert receipt.content_sha256 == world.content_sha256
    assert receipt.size_bytes == len(world.content)
    assert receipt.purpose == PURPOSE
    assert receipt.authorization_id == authorization.authorization_id
    assert receipt.signer_key_id == "key-1"
    assert receipt.object_key
    assert receipt.data_class == DataClass.INTERNAL_METADATA.value

    document = receipt.document()
    assert document["content_id"] == "graph-1"
    assert isinstance(document["stored_at"], str)

    # Content is committed atomically under the content-addressed object key.
    object_root = tmp_path / "objects" / pathlib.Path(receipt.object_key)
    payload = object_root / "payload"
    assert payload.is_file()
    assert payload.read_bytes() == world.content
    assert hashlib.sha256(payload.read_bytes()).hexdigest() == world.content_sha256
    metadata = json.loads((object_root / "receipt.json").read_text(encoding="utf-8"))
    assert metadata["content_id"] == "graph-1"
    assert metadata["content_sha256"] == world.content_sha256


def test_repeated_upload_is_idempotent(tmp_path: Path) -> None:
    world = _world(tmp_path)
    authorization = world.authorize()
    first = world.upload(world.request(authorization))
    second = world.upload(world.request(authorization))
    assert second.content_id == first.content_id
    assert second.object_key == first.object_key


# --- upload rejections -------------------------------------------------------


def test_upload_rejects_content_that_does_not_match_the_digest(tmp_path: Path) -> None:
    world = _world(tmp_path)
    authorization = world.authorize()
    with pytest.raises(ArtifactUploadRejected):
        world.upload(world.request(authorization, content=b"tampered"))


def test_upload_rejects_size_mismatch(tmp_path: Path) -> None:
    world = _world(tmp_path)
    authorization = world.authorize()
    with pytest.raises(ArtifactUploadRejected):
        world.upload(world.request(authorization, size_bytes=len(world.content) + 1))


def test_upload_rejects_oversized_content(tmp_path: Path) -> None:
    world = _world(tmp_path, max_bytes=len(CONTENT) - 1)
    large = b"x" * 4096
    authorization = world.authorize(
        content_sha256=hashlib.sha256(large).hexdigest(), size_bytes=len(large)
    )
    with pytest.raises(ArtifactUploadRejected):
        world.upload(world.request(authorization, content=large))


def test_upload_rejects_unknown_authorization(tmp_path: Path) -> None:
    world = _world(tmp_path)
    authorization = world.authorize()
    with pytest.raises(ArtifactUploadRejected):
        world.upload(world.request(authorization, authorization_id="upload-unknown"))


def test_upload_rejects_foreign_worker(tmp_path: Path) -> None:
    world = _world(tmp_path)
    authorization = world.authorize()
    with pytest.raises(ArtifactUploadRejected):
        world.upload(world.request(authorization, worker_id="worker-2"))


def test_upload_rejects_forged_receipt_signature(tmp_path: Path) -> None:
    world = _world(tmp_path)
    authorization = world.authorize()
    with pytest.raises(ArtifactUploadRejected):
        world.upload(world.request(authorization, receipt_signature="f" * 64))


def test_upload_rejects_expired_authorization(tmp_path: Path) -> None:
    world = _world(tmp_path)
    authorization = world.authorize()
    world.clock["now"] = NOW + timedelta(hours=1)
    with pytest.raises(ArtifactUploadRejected):
        world.upload(world.request(authorization))


def test_upload_rejects_foreign_tenant(tmp_path: Path) -> None:
    world = _world(tmp_path)
    authorization = world.authorize()
    with pytest.raises(ArtifactUploadRejected):
        world.upload(world.request(authorization, tenant_id=OTHER_TENANT))


def test_upload_rejects_non_request_object(tmp_path: Path) -> None:
    world = _world(tmp_path)
    with pytest.raises(ArtifactUploadRejected):
        asyncio.run(world.service.put(object()))  # type: ignore[arg-type]


def test_request_rejects_invalid_shape() -> None:
    with pytest.raises(ValueError):
        ArtifactPutRequest(
            authorization_id="upload-1",
            tenant_id="tenant-1",
            worker_id="worker-1",
            repository_id="repository-1",
            run_id="run-1",
            execution_identity_hash="short",
            content_sha256="a" * 64,
            size_bytes=1,
            purpose=PURPOSE,
            receipt_signature="sig",
            content=b"x",
        )


def test_service_rejects_invalid_settings(tmp_path: Path) -> None:
    world = _world(tmp_path)
    with pytest.raises(ValueError):
        AuthorizedLocalArtifactUploadService(
            "not-a-path",  # type: ignore[arg-type]
            authorizations=world.authorizations,
        )
    with pytest.raises(ValueError):
        AuthorizedLocalArtifactUploadService(
            tmp_path / "other",
            authorizations=world.authorizations,
            max_bytes=0,
        )


def test_authorization_row_is_scoped_to_the_recording_tenant(tmp_path: Path) -> None:
    """A second tenant cannot require the first tenant's authorization row."""

    world = _world(tmp_path)
    authorization = world.authorize()
    other = SqliteArtifactAuthorizationStore(
        world.connection,
        signer=world.signers,
        upload_urls=StaticArtifactUploadUrlFactory("https://uploads.example.invalid"),
        ttl_seconds=600,
        now=lambda: world.clock["now"],
    )
    with pytest.raises(ArtifactAuthorizationDenied):
        other.require(
            tenant_id=OTHER_TENANT,
            authorization_id=authorization.authorization_id,
            repository_id=REPOSITORY,
            run_id=RUN_ID,
            execution_identity_hash=world.identity.execution_identity_hash,
            content_sha256=world.content_sha256,
            size_bytes=len(world.content),
            purpose=PURPOSE,
            request_sha256=HASH_A,
        )
