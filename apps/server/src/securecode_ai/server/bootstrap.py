"""Safe local composition for the executable control-plane service."""

from __future__ import annotations

import os
import re
import secrets
import time
from pathlib import Path
from typing import Final

from .application import ServerApp, create_app
from .approvals import ApprovalLedger
from .artifact_upload import AuthorizedLocalArtifactUploadService
from .artifact_upload_handler import ArtifactUploadHandler
from .artifact_upload_verifier import LocalArtifactUploadVerifier
from .assurance_repository import AssuranceRepository
from .assurance_service import AssuranceService
from .assurance_verifiers import load_assurance_verifier_registry
from .audit_log import AuditLog
from .auth_configuration import build_oidc_verifier
from .auth_runtime import CompositeIdentityVerifier
from .baseline_store import DurableBaselineStore
from .bootstrap_identity import (
    BootstrapIdentity,
    HashedTokenIdentityVerifier,
    load_bootstrap_identities,
)
from .composite_readiness import CompositeReadiness
from .composite_service import CompositeService
from .data_lifecycle import LifecycleLedger
from .feedback_repository import FeedbackRepository
from .feedback_service import FeedbackService
from .idempotency import SqliteRequestReplayStore
from .openapi import CAPABILITIES
from .operations_audit import AuditTelemetryControlPlane
from .operations_handler_evidence import (
    AssuranceOperationsHandler,
    FeedbackOperationsHandler,
)
from .operations_handler_governance import (
    ApprovalOperationsHandler,
    LifecycleOperationsHandler,
    LifecycleScopeRepository,
)
from .operations_runtime import build_operational_handlers
from .operations_telemetry import OperationsTelemetry
from .persistence import DevelopmentRepository
from .ports import (
    ControlPlaneService,
    IdentityVerifier,
    VerifiedIdentity,
)
from .reloading_identity import ReloadingIdentityVerifier
from .resource_configuration import (
    TenantProvisioningResourceService,
    load_resource_configuration,
)
from .resource_repository import ResourceRepository
from .resource_service import ResourceService
from .run_admission import (
    RunAdmissionHandler,
    RunAdmissionRoutingService,
    RunAdmissionService,
)
from .run_admission_models import DefaultResourceRequestPolicy
from .run_admission_store import SqliteRunAdmissionStore
from .runtime import RuntimeSettings
from .scm_admission import (
    ExactWebhookRunAuthorization,
    IdentityBindingWebhookAdapter,
    SCMAdmissionHandler,
    SqliteWorkerSupersession,
)
from .scm_completion import (
    SCMCompletionPublicationHandler,
    SCMCompletionPublicationService,
)
from .scm_publication_store import SqliteSCMPublicationStore
from .scm_resolution import SCMRunResolutionHandler
from .scm_runtime import build_scm_handlers
from .secure_files import read_secret_bytes
from .service import DurableControlPlaneService
from .sqlite_database import (
    SqliteSchemaReadiness,
    open_private_sqlite,
    prepare_private_data_directory,
)
from .storage_executor import LocalArtifactStorageExecutor
from .worker_artifact_authorization import (
    HmacSha256ArtifactReceiptSigner,
    SignedArtifactAuthorizationHandler,
    SqliteArtifactAuthorizationStore,
    StaticArtifactUploadUrlFactory,
)
from .worker_queue import SqliteWorkerQueue
from .worker_queue_handler import WorkerQueueHandler
from .worker_resource_accounting import (
    WorkerResourceAccountingHandler,
    WorkerResourceAccountingService,
)
from .worker_resource_store import SqliteWorkerReservationBindingStore

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class RoleAuthorization:
    """Closed action matrix; repository scope is enforced by services/stores."""

    __slots__ = ()

    _ROLE_ACTIONS: Final = {
        "admin": frozenset({"*"}),
        "viewer": frozenset(
            {
                "runs.read",
                "runs.events.read",
                "runs.findings.read",
                "runs.artifacts.read",
                "findings.read",
                "policies.read",
                "approvals.read",
                "lifecycle.deletions.read",
                "feedback.metrics.read",
                "assurance.read",
            }
        ),
        "auditor": frozenset(
            {
                "runs.create",
                "runs.cancel",
                "runs.read",
                "runs.events.read",
                "runs.findings.read",
                "runs.artifacts.read",
                "runs.audit.read",
                "findings.read",
                "policies.read",
                "artifacts.authorize",
                "approvals.create",
                "approvals.read",
                "lifecycle.deletions.create",
                "lifecycle.deletions.read",
                "feedback.submit",
                "feedback.metrics.read",
                "assurance.append",
                "assurance.read",
            }
        ),
        "approver": frozenset(
            {
                "runs.read",
                "runs.events.read",
                "runs.findings.read",
                "runs.artifacts.read",
                "findings.read",
                "findings.decide",
                "policies.read",
                "approvals.read",
                "approvals.decide",
                "lifecycle.deletions.read",
                "lifecycle.deletions.approve",
                "lifecycle.deletions.legal_hold",
            }
        ),
        "worker": frozenset(
            {
                "artifacts.authorize",
                "scm.runs.resolve",
                "worker_sessions.create",
                "worker_sessions.heartbeat",
                "worker_sessions.events.append",
                "worker_sessions.artifacts.commit",
                "worker_sessions.complete",
            }
        ),
        "scm": frozenset({"webhooks.github", "webhooks.gitlab"}),
        "artifact_uploader": frozenset({"artifacts.upload"}),
    }

    def allows(
        self,
        identity: VerifiedIdentity,
        *,
        action: str,
        repository_id: str | None,
    ) -> bool:
        if type(identity) is not VerifiedIdentity or type(action) is not str:
            return False
        allowed: set[str] = set()
        for role in identity.roles:
            allowed.update(self._ROLE_ACTIONS.get(role, ()))
        if identity.workload and identity.roles.isdisjoint({"worker", "scm", "artifact_uploader"}):
            return False
        if "*" in allowed:
            return True
        if repository_id is not None and repository_id not in identity.repository_ids:
            return False
        return action in allowed


def build_local_app(
    settings: RuntimeSettings,
    environment: dict[str, str] | None = None,
) -> ServerApp:
    values = os.environ if environment is None else environment
    data_dir = prepare_private_data_directory(Path(settings.data_dir))
    database_path = data_dir / "control-plane.sqlite3"
    connection = open_private_sqlite(database_path)
    repository = DevelopmentRepository(connection)
    oidc = build_oidc_verifier(values)
    identities = load_bootstrap_identities(values, required=oidc is None)
    identity_readiness: list[ReloadingIdentityVerifier] = []
    oidc_identity = (
        None if oidc is None else ReloadingIdentityVerifier(lambda: build_oidc_verifier(values))
    )
    if oidc_identity is not None:
        identity_readiness.append(oidc_identity)
    if identities:
        bootstrap_identity = ReloadingIdentityVerifier(
            lambda: HashedTokenIdentityVerifier(load_bootstrap_identities(values, required=True))
        )
        identity_readiness.append(bootstrap_identity)
        identity_verifier: IdentityVerifier = (
            bootstrap_identity
            if oidc_identity is None
            else CompositeIdentityVerifier(oidc_identity, bootstrap_identity)
        )
    elif oidc_identity is not None:
        identity_verifier = oidc_identity
    else:
        raise ValueError("identity verification is not configured")
    scm_tenant = values.get("SECURECODE_SCM_TENANT_ID")
    if scm_tenant is None:
        scm_tenant = identities[0].identity.tenant_id if identities else "local"
    if _ID.fullmatch(scm_tenant) is None:
        raise ValueError("SCM tenant is invalid")
    scm = build_scm_handlers(values, tenant_id=scm_tenant, connection=connection)
    webhook_identity = VerifiedIdentity(
        subject_id="scm-webhook",
        tenant_id=scm_tenant,
        roles=frozenset({"scm"}),
        workload=True,
    )
    worker_queue = SqliteWorkerQueue(connection)
    resource_configuration = load_resource_configuration(values, tenant_id=scm_tenant)
    durable_resources = ResourceService(ResourceRepository(connection))
    durable_resources.configure(resource_configuration.limits)
    resource_service = TenantProvisioningResourceService(
        durable_resources,
        resource_configuration.limits,
    )
    authorization = RoleAuthorization()
    admission_store = SqliteRunAdmissionStore(connection)
    resource_policy = DefaultResourceRequestPolicy(resource_configuration.run_defaults)
    admission_service = RunAdmissionService(
        store=admission_store,
        resources=resource_service,
        queue=worker_queue,
        authorization=authorization,
        clock=lambda: time.time_ns() // 1_000_000,
        default_resource_policy=resource_policy,
    )
    admission = RunAdmissionHandler(admission_service)
    webhook_admission = RunAdmissionService(
        store=admission_store,
        resources=resource_service,
        queue=worker_queue,
        authorization=ExactWebhookRunAuthorization(webhook_identity),
        clock=lambda: time.time_ns() // 1_000_000,
        default_resource_policy=resource_policy,
    )
    upload_base_url = values.get("SECURECODE_ARTIFACT_UPLOAD_URL")
    if upload_base_url is None:
        if settings.host == "0.0.0.0":
            raise ValueError("external artifact upload URL is not configured")
        scheme = "https" if settings.tls_cert_file is not None else "http"
        upload_base_url = f"{scheme}://127.0.0.1:{settings.port}/api/v1/artifact-uploads"
    artifact_authorizations = SqliteArtifactAuthorizationStore(
        connection,
        signer=HmacSha256ArtifactReceiptSigner(
            _artifact_receipt_secret(values, data_dir),
            key_id=values.get("SECURECODE_ARTIFACT_RECEIPT_KEY_ID", "local-v1"),
        ),
        upload_urls=StaticArtifactUploadUrlFactory(upload_base_url),
    )
    artifact_uploads = AuthorizedLocalArtifactUploadService(
        data_dir / "artifacts",
        authorizations=artifact_authorizations,
    )
    artifact_storage = LocalArtifactStorageExecutor(
        connection,
        data_dir / "artifacts",
    )
    supersession = SqliteWorkerSupersession(runs=repository, queue=worker_queue)
    scm_publications = SqliteSCMPublicationStore(connection)
    github_handler = (
        SCMAdmissionHandler(
            adapter=IdentityBindingWebhookAdapter(adapter=scm.github, pins=scm.pins),
            runs=webhook_admission,
            supersession=supersession,
            publications=scm_publications,
        )
        if scm.github is not None and scm.pins is not None
        else None
    )
    gitlab_handler = (
        SCMAdmissionHandler(
            adapter=IdentityBindingWebhookAdapter(adapter=scm.gitlab, pins=scm.pins),
            runs=webhook_admission,
            supersession=supersession,
            publications=scm_publications,
        )
        if scm.gitlab is not None and scm.pins is not None
        else None
    )
    worker_handler: ControlPlaneService = WorkerResourceAccountingHandler(
        accounting=WorkerResourceAccountingService(
            bindings=SqliteWorkerReservationBindingStore(connection),
            resources=durable_resources,
            clock=lambda: time.time_ns() // 1_000_000,
        ),
        fallback=WorkerQueueHandler(
            queue=worker_queue,
            artifact_authorizations=artifact_authorizations,
            uploaded_artifacts=LocalArtifactUploadVerifier(data_dir / "artifacts"),
            baseline_store=DurableBaselineStore(connection),
            lineage_resolver=scm.lineage_resolver,
        ),
    )
    if scm.run_state is not None:
        worker_handler = SCMCompletionPublicationHandler(
            publisher=SCMCompletionPublicationService(
                publications=scm_publications,
                run_state=scm.run_state,
                github_head=scm.github_head,
                github_writer=scm.github_writer,
                gitlab_head=scm.gitlab_head,
                gitlab_writer=scm.gitlab_writer,
            ),
            fallback=worker_handler,
        )
    approvals = ApprovalOperationsHandler(ApprovalLedger(connection))
    lifecycle = LifecycleOperationsHandler(
        LifecycleLedger(connection, storage=artifact_storage),
        LifecycleScopeRepository(connection),
        execute_available=True,
    )
    feedback = FeedbackOperationsHandler(FeedbackService(FeedbackRepository(connection)))
    assurance = AssuranceOperationsHandler(
        AssuranceService(AssuranceRepository(connection)),
        load_assurance_verifier_registry(values),
    )
    operations = build_operational_handlers(values, connection)
    service: ControlPlaneService = CompositeService(
        core=RunAdmissionRoutingService(
            admission=admission,
            fallback=DurableControlPlaneService(repository),
        ),
        worker=worker_handler,
        github=github_handler,
        gitlab=gitlab_handler,
        optional={
            "artifacts.authorize": SignedArtifactAuthorizationHandler(artifact_authorizations),
            "artifacts.upload": ArtifactUploadHandler(artifact_uploads),
            "approvals.create": approvals,
            "approvals.read": approvals,
            "approvals.decide": approvals,
            "lifecycle.deletions.create": lifecycle,
            "lifecycle.deletions.read": lifecycle,
            "lifecycle.deletions.approve": lifecycle,
            "lifecycle.deletions.legal_hold": lifecycle,
            "lifecycle.deletions.execute": lifecycle,
            "feedback.submit": feedback,
            "feedback.metrics.read": feedback,
            "assurance.append": assurance,
            "assurance.read": assurance,
            "secrets.grant": operations.secrets,
            "secrets.read": operations.secrets,
            "secrets.rotate": operations.secrets,
            "secrets.revoke": operations.secrets,
            "backups.create": operations.backups,
            "backups.read": operations.backups,
            "backups.execute": operations.backups,
            "backups.restore": operations.backups,
        },
    )
    service = SCMRunResolutionHandler(store=scm_publications, fallback=service)
    service = AuditTelemetryControlPlane(
        fallback=service,
        audit_log=AuditLog(connection),
        telemetry=OperationsTelemetry(),
        runs=repository,
    )
    disabled_capabilities = {
        name
        for name, available in (
            ("backup-restore", operations.backups_available),
            ("secret-leases", operations.secrets_available),
        )
        if not available
    }
    return create_app(
        identities=identity_verifier,
        authorization=authorization,
        service=service,
        readiness=CompositeReadiness(
            SqliteSchemaReadiness(connection),
            *identity_readiness,
        ),
        replay_store=SqliteRequestReplayStore(connection),
        webhook_identity=webhook_identity,
        artifact_upload_identity=VerifiedIdentity(
            subject_id="artifact-upload",
            tenant_id="artifact-transport",
            roles=frozenset({"artifact_uploader"}),
            workload=True,
        ),
        capabilities=tuple(
            capability for capability in CAPABILITIES if capability not in disabled_capabilities
        ),
    )


def _artifact_receipt_secret(values: object, data_dir: Path) -> bytes:
    if not hasattr(values, "get"):
        raise ValueError("artifact receipt signer is not configured")
    get = values.get
    secret_path = get("SECURECODE_ARTIFACT_RECEIPT_SECRET_FILE")
    if secret_path is not None:
        if type(secret_path) is not str:
            raise ValueError("artifact receipt signer is not configured")
        return read_secret_bytes(Path(secret_path), minimum=32, maximum=4096)
    secret = get("SECURECODE_ARTIFACT_RECEIPT_SECRET")
    if secret is None:
        return _local_artifact_receipt_secret(data_dir)
    if type(secret) is not str:
        raise ValueError("artifact receipt signer is not configured")
    try:
        encoded = secret.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise ValueError("artifact receipt signer is not configured") from None
    if not 32 <= len(encoded) <= 4096 or b"\x00" in encoded:
        raise ValueError("artifact receipt signer is not configured")
    return encoded


def _local_artifact_receipt_secret(data_dir: Path) -> bytes:
    path = data_dir / "artifact-receipt.key"
    if path.exists():
        return read_secret_bytes(path, minimum=32, maximum=32)
    value = secrets.token_bytes(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        return read_secret_bytes(path, minimum=32, maximum=32)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return read_secret_bytes(path, minimum=32, maximum=32)


__all__ = [
    "BootstrapIdentity",
    "HashedTokenIdentityVerifier",
    "RoleAuthorization",
    "build_local_app",
]
