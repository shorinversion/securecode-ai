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
from .auth_configuration import build_oidc_login_service, build_oidc_verifier
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
from .finding_evidence import FindingEvidenceReader
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
from .scm_annotations import GithubAnnotationReceiptResolver
from .scm_policy_registry import load_scm_policy_registry
from .scm_publication_store import SqliteSCMPublicationStore
from .scm_resolution import SCMRunResolutionHandler
from .scm_runtime import build_scm_handlers
from .secure_files import read_secret_bytes
from .service import DurableControlPlaneService
from .sessions import SessionIdentityVerifier, SessionStore
from .sqlite_database import (
    SqliteSchemaReadiness,
    open_private_sqlite,
    prepare_private_data_directory,
)
from .sqlite_request_quota import SqliteQuotaLedger
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
from .worker_scm_policy import load_run_scm_policy_decision

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class RoleAuthorization:
    """Closed action matrix; repository scope is enforced by services/stores."""

    __slots__ = ()

    _ROLE_ACTIONS: Final = {
        "admin": frozenset({"*"}),
        "viewer": frozenset(
            {
                "runs.read",
                "runs.list",
                "runs.events.read",
                "runs.findings.read",
                "runs.artifacts.read",
                "findings.read",
                "findings.evidence.read",
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
                "runs.list",
                "runs.events.read",
                "runs.findings.read",
                "runs.artifacts.read",
                "runs.audit.read",
                "findings.read",
                "findings.evidence.read",
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
                "runs.list",
                "runs.events.read",
                "runs.findings.read",
                "runs.artifacts.read",
                "findings.read",
                "findings.evidence.read",
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
        if (
            type(identity) is not VerifiedIdentity
            or type(action) is not str
            or not action
            or type(identity.roles) is not frozenset
            or not identity.roles
            or not all(type(role) is str and role in self._ROLE_ACTIONS for role in identity.roles)
            or type(identity.repository_ids) is not frozenset
            or not all(type(value) is str and value for value in identity.repository_ids)
            or (repository_id is not None and (type(repository_id) is not str or not repository_id))
        ):
            return False
        if identity.workload and not identity.roles.issubset(
            {"worker", "scm", "artifact_uploader"}
        ):
            return False
        allowed: set[str] = set()
        for role in identity.roles:
            allowed.update(self._ROLE_ACTIONS.get(role, ()))
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
    session_store = SessionStore(connection=connection)
    oidc_login = build_oidc_login_service(
        values,
        oidc,
        session_store,
        verifier_loader=lambda: build_oidc_verifier(values),
        connection=connection,
    )
    identity_readiness: list[ReloadingIdentityVerifier] = []
    oidc_identity = (
        None if oidc is None else ReloadingIdentityVerifier(lambda: build_oidc_verifier(values))
    )
    if oidc_identity is not None:
        identity_readiness.append(oidc_identity)
    identity_verifiers: list[IdentityVerifier] = []
    if oidc_identity is not None:
        identity_verifiers.append(oidc_identity)
    if identities:
        bootstrap_identity = ReloadingIdentityVerifier(
            lambda: HashedTokenIdentityVerifier(load_bootstrap_identities(values, required=True))
        )
        identity_readiness.append(bootstrap_identity)
        identity_verifiers.append(bootstrap_identity)
    if oidc_login is not None:
        identity_verifiers.append(SessionIdentityVerifier(session_store))
    if not identity_verifiers:
        raise ValueError("identity verification is not configured")
    identity_verifier: IdentityVerifier = (
        identity_verifiers[0]
        if len(identity_verifiers) == 1
        else CompositeIdentityVerifier(*identity_verifiers)
    )
    scm_tenant = values.get("SECURECODE_SCM_TENANT_ID")
    if scm_tenant is None:
        scm_tenant = identities[0].identity.tenant_id if identities else "local"
    if _ID.fullmatch(scm_tenant) is None:
        raise ValueError("SCM tenant is invalid")
    scm = build_scm_handlers(values, tenant_id=scm_tenant, connection=connection)
    policy_registry_path = values.get("SECURECODE_SCM_POLICY_REGISTRY_FILE")
    policy_registry = (
        None
        if policy_registry_path is None
        else load_scm_policy_registry(Path(policy_registry_path))
    )
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
            changed_lines_resolver=scm.changed_lines_resolver,
            policy_resolver=policy_registry,
        ),
    )
    if scm.run_state is not None:
        github_annotation_receipt = (
            GithubAnnotationReceiptResolver(
                connection=connection,
                artifact_root=data_dir / "artifacts",
                baseline_store=DurableBaselineStore(connection),
                lineage_resolver=scm.lineage_resolver,
                changed_lines_resolver=scm.changed_lines_resolver,
                authorizer=scm.github,
            )
            if (
                scm.github is not None
                and scm.github_comments is not None
                and scm.lineage_resolver is not None
                and scm.changed_lines_resolver is not None
            )
            else None
        )
        worker_handler = SCMCompletionPublicationHandler(
            publisher=SCMCompletionPublicationService(
                publications=scm_publications,
                run_state=scm.run_state,
                github_head=scm.github_head,
                github_writer=scm.github_writer,
                github_comment_writer=scm.github_comments,
                github_annotation_receipt=github_annotation_receipt,
                gitlab_head=scm.gitlab_head,
                gitlab_writer=scm.gitlab_writer,
                policy_decisions=lambda tenant_id, run_id, identity_hash: (
                    load_run_scm_policy_decision(
                        connection,
                        tenant_id=tenant_id,
                        run_id=run_id,
                        execution_identity_hash=identity_hash,
                    )
                ),
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
            fallback=DurableControlPlaneService(
                repository,
                finding_evidence=FindingEvidenceReader(
                    repository=repository,
                    artifact_root=data_dir / "artifacts",
                ),
            ),
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
    scm_webhooks_available = scm.github is not None or scm.gitlab is not None
    available_capabilities = tuple(
        capability
        for capability in CAPABILITIES
        if capability != "scm-webhooks" or scm_webhooks_available
    )
    if oidc_login is not None:
        available_capabilities += ("oidc-login",)
    return create_app(
        identities=identity_verifier,
        oidc_login=oidc_login,
        sessions=session_store if oidc_login is not None else None,
        authorization=authorization,
        service=service,
        readiness=CompositeReadiness(
            SqliteSchemaReadiness(connection),
            *identity_readiness,
        ),
        replay_store=SqliteRequestReplayStore(connection),
        webhook_identity=webhook_identity,
        quota=SqliteQuotaLedger(
            connection,
            window_seconds=_quota_integer(
                values,
                "SECURECODE_API_QUOTA_WINDOW_SECONDS",
                default=60,
                minimum=1,
                maximum=86_400,
            ),
            max_requests=_quota_integer(
                values,
                "SECURECODE_API_MAX_REQUESTS_PER_WINDOW",
                default=5_000,
                minimum=1,
                maximum=1_000_000,
            ),
        ),
        artifact_upload_identity=VerifiedIdentity(
            subject_id="artifact-upload",
            tenant_id="artifact-transport",
            roles=frozenset({"artifact_uploader"}),
            workload=True,
        ),
        capabilities=tuple(
            sorted(
                capability
                for capability in available_capabilities
                if capability not in disabled_capabilities
            )
        ),
    )


def _quota_integer(
    values: object,
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    if not hasattr(values, "get"):
        raise ValueError("request quota configuration is invalid")
    value = values.get(name, str(default))
    if type(value) is not str or not value.isascii() or not value.isdecimal():
        raise ValueError("request quota configuration is invalid")
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise ValueError("request quota configuration is invalid")
    return parsed


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
