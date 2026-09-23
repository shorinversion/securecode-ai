"""Durable bridge from authenticated SCM webhooks to worker run admission.

The existing webhook adapters deliberately return source-free receipts and keep
the full execution identity private. ``IdentityBindingWebhookAdapter`` is the
narrow integration shim: it calls the adapter first so raw-body authentication
and authoritative HEAD checks remain unchanged, then reconstructs the identity
from the same host-owned pins and proves it by the receipt identity hash.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Protocol

from securecode_ai.contracts import RunExecutionIdentity
from securecode_ai.core.scm_run_state import SCMRunLifecycle

from .persistence import DevelopmentRepository, NotFoundError
from .ports import ServiceRequest, ServiceResponse, ServiceUnavailableError, VerifiedIdentity
from .run_admission import RunAdmissionService
from .run_admission_models import AdmissionError, AdmissionErrorCode, safe_message
from .scm_publication_store import SCMPublicationTarget, SqliteSCMPublicationStore
from .scm_webhooks import (
    SCMWebhookError,
    SCMWebhookErrorCode,
    WebhookAdmissionReceipt,
    WebhookExecutionPins,
)
from .worker_queue import SqliteWorkerQueue, WorkerQueueConflict

_COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ACTIVE_RUN_STATES = frozenset({"ADMISSION_PENDING", "REQUESTED", "RUNNING", "CANCEL_REQUESTED"})
_SETTLED_RUN_STATES = frozenset(
    {
        "ADMISSION_BLOCKED",
        "ADMISSION_FAILED",
        "CANCELLED",
        "FAILED",
        "INDETERMINATE",
        "SUCCEEDED",
        "SUPERSEDED",
        "SUPERSEDE_REQUESTED",
    }
)


class WebhookReceiptPort(Protocol):
    """Current GitHub/GitLab adapter receipt surface."""

    def receive(
        self,
        body: bytes,
        *,
        headers: Mapping[str, str],
        delivery_key: str | None,
    ) -> WebhookAdmissionReceipt: ...


class AuthenticatedWebhookPort(Protocol):
    """Proposed narrow SCM integration surface exposing the proven identity."""

    def receive_authenticated(
        self,
        body: bytes,
        *,
        headers: Mapping[str, str],
        delivery_key: str | None,
    ) -> tuple[WebhookAdmissionReceipt, RunExecutionIdentity]: ...


class SupersessionPort(Protocol):
    def request(
        self,
        *,
        tenant_id: str,
        run_id: str,
        superseding_head_sha: str,
    ) -> None: ...


class IdentityBindingWebhookAdapter:
    """Expose an exact identity without weakening the existing raw adapter."""

    __slots__ = ("_adapter", "_pins")

    def __init__(
        self,
        *,
        adapter: WebhookReceiptPort,
        pins: WebhookExecutionPins,
    ) -> None:
        if adapter is None or type(pins) is not WebhookExecutionPins:
            raise TypeError("SCM webhook identity dependencies are invalid")
        self._adapter = adapter
        self._pins = pins

    def receive_authenticated(
        self,
        body: bytes,
        *,
        headers: Mapping[str, str],
        delivery_key: str | None,
    ) -> tuple[WebhookAdmissionReceipt, RunExecutionIdentity]:
        # Authentication, bounded parsing, and fresh HEAD resolution happen here
        # before this bridge examines the already-authenticated payload.
        receipt = self._adapter.receive(
            body,
            headers=headers,
            delivery_key=delivery_key,
        )
        if receipt.provider == "github":
            base_sha = receipt.base_sha
        elif receipt.provider == "gitlab" and receipt.base_sha is None:
            base_sha = None
        else:
            raise SCMWebhookError(SCMWebhookErrorCode.INVALID_CONFIGURATION)
        identity = self._pins.build_identity(
            scm_provider=receipt.provider,
            repository_id=receipt.repository_id,
            head_sha=receipt.head_sha,
            base_sha=base_sha,
        )
        revision = identity.repository_revision
        if (
            revision.repository_id != receipt.repository_id
            or revision.head_sha != receipt.head_sha
            or identity.execution_identity_hash != receipt.admission.execution_identity_hash
        ):
            raise SCMWebhookError(SCMWebhookErrorCode.IDENTITY_MISMATCH)
        return receipt, identity


class ExactWebhookRunAuthorization:
    """Authorize only the exact self-authenticated webhook principal."""

    __slots__ = ("_principal",)

    def __init__(self, principal: VerifiedIdentity) -> None:
        if not isinstance(principal, VerifiedIdentity) or not principal.workload:
            raise TypeError("webhook principal is invalid")
        self._principal = principal

    def allows(
        self,
        identity: VerifiedIdentity,
        *,
        action: str,
        repository_id: str | None,
    ) -> bool:
        return (
            identity == self._principal
            and action == "runs.create"
            and repository_id is not None
            and (not identity.repository_ids or repository_id in identity.repository_ids)
        )


class SqliteWorkerSupersession:
    """Request durable worker supersession with replay-safe state adoption."""

    __slots__ = ("_queue", "_runs")

    def __init__(
        self,
        *,
        runs: DevelopmentRepository,
        queue: SqliteWorkerQueue,
    ) -> None:
        if not isinstance(runs, DevelopmentRepository) or not isinstance(queue, SqliteWorkerQueue):
            raise TypeError("SCM supersession dependencies are invalid")
        self._runs = runs
        self._queue = queue

    def request(
        self,
        *,
        tenant_id: str,
        run_id: str,
        superseding_head_sha: str,
    ) -> None:
        if _COMMIT_SHA.fullmatch(superseding_head_sha) is None:
            raise WorkerQueueConflict()
        for attempt in range(2):
            try:
                run = self._runs.get_run(tenant_id, run_id)
            except NotFoundError:
                return
            state = run.get("state")
            if state in _SETTLED_RUN_STATES:
                return
            if state not in _ACTIVE_RUN_STATES:
                raise WorkerQueueConflict()
            if run.get("head_sha") == superseding_head_sha:
                raise WorkerQueueConflict()
            version = run.get("version")
            if type(version) is not int:
                raise WorkerQueueConflict()
            try:
                self._queue.request_command(
                    tenant_id=tenant_id,
                    run_id=run_id,
                    command="SUPERSEDE",
                    expected_run_version=version,
                )
                return
            except WorkerQueueConflict:
                if attempt:
                    raise


class SCMAdmissionHandler:
    """Authenticate a webhook, supersede stale work, and admit its exact run."""

    __slots__ = ("_adapter", "_publications", "_runs", "_supersession")

    def __init__(
        self,
        *,
        adapter: AuthenticatedWebhookPort,
        runs: RunAdmissionService,
        supersession: SupersessionPort,
        publications: SqliteSCMPublicationStore | None = None,
    ) -> None:
        if adapter is None or not isinstance(runs, RunAdmissionService) or supersession is None:
            raise TypeError("SCM admission dependencies are invalid")
        self._adapter = adapter
        self._runs = runs
        self._supersession = supersession
        self._publications = publications

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.document is not None or request.action not in {
            "webhooks.github",
            "webhooks.gitlab",
        }:
            raise ServiceUnavailableError()
        try:
            receipt, identity = self._adapter.receive_authenticated(
                request.raw_body,
                headers=request.headers,
                delivery_key=request.idempotency_key,
            )
            _require_request_binding(request, receipt, identity)
            if receipt.admission.lifecycle is SCMRunLifecycle.SUPERSEDED:
                return ServiceResponse(202, receipt.as_document())

            revision = identity.repository_revision
            for superseded_run_id in receipt.admission.superseded_run_ids:
                self._supersession.request(
                    tenant_id=revision.tenant_id,
                    run_id=superseded_run_id,
                    superseding_head_sha=revision.head_sha,
                )

            run_response = self._runs.create(_run_request(request, receipt, identity))
            if run_response.status != 201:
                raise AdmissionError(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503)
            self._bind_publication(receipt, identity)
            document = receipt.as_document()
            document["run"] = dict(run_response.document)
            return ServiceResponse(202, document)
        except SCMWebhookError as error:
            return _webhook_error(error)
        except AdmissionError as error:
            return ServiceResponse(
                error.status,
                {
                    "error": {
                        "code": error.code.value,
                        "message": safe_message(error.code),
                    }
                },
            )
        except Exception:
            return ServiceResponse(
                503,
                {
                    "error": {
                        "code": AdmissionErrorCode.SERVICE_UNAVAILABLE.value,
                        "message": safe_message(AdmissionErrorCode.SERVICE_UNAVAILABLE),
                    }
                },
            )

    def _bind_publication(
        self,
        receipt: WebhookAdmissionReceipt,
        identity: RunExecutionIdentity,
    ) -> None:
        store = self._publications
        if store is None:
            return
        if receipt.change_id is None:
            raise SCMWebhookError(SCMWebhookErrorCode.PAYLOAD_INVALID)
        revision = identity.repository_revision
        store.bind(
            SCMPublicationTarget(
                tenant_id=revision.tenant_id,
                run_id=receipt.admission.run_id,
                provider=receipt.provider,
                installation_id=receipt.installation_id,
                repository_id=receipt.repository_id,
                change_id=receipt.change_id,
                head_sha=receipt.head_sha,
                execution_identity_hash=identity.execution_identity_hash,
            )
        )


def _run_request(
    request: ServiceRequest,
    receipt: WebhookAdmissionReceipt,
    identity: RunExecutionIdentity,
) -> ServiceRequest:
    document: dict[str, object] = {
        "execution_identity": identity.model_dump(mode="json"),
        "execution_identity_hash": identity.execution_identity_hash,
        "run_id": receipt.admission.run_id,
        "contribution_trust": receipt.contribution_trust.value,
    }
    raw_body = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return ServiceRequest(
        method="POST",
        route="/api/v1/runs",
        action="runs.create",
        identity=request.identity,
        # The run ID is deterministic across delivery retries and semantic
        # duplicate deliveries, so the durable admission saga adopts one run.
        idempotency_key=receipt.admission.run_id,
        precondition=None,
        path_params={},
        query={},
        document=document,
        raw_body=raw_body,
        headers={},
        server_context={"contribution_trust": receipt.contribution_trust.value},
    )


def _require_request_binding(
    request: ServiceRequest,
    receipt: WebhookAdmissionReceipt,
    identity: RunExecutionIdentity,
) -> None:
    expected_action = f"webhooks.{receipt.provider}"
    revision = identity.repository_revision
    if (
        request.action != expected_action
        or request.identity.tenant_id != revision.tenant_id
        or receipt.admission.run_id == ""
        or receipt.admission.execution_identity_hash != identity.execution_identity_hash
    ):
        raise SCMWebhookError(SCMWebhookErrorCode.IDENTITY_MISMATCH)


def _webhook_error(error: SCMWebhookError) -> ServiceResponse:
    status = 401 if error.code is SCMWebhookErrorCode.AUTHENTICATION_FAILED else 409
    if error.code in {
        SCMWebhookErrorCode.INVALID_HEADERS,
        SCMWebhookErrorCode.PAYLOAD_INVALID,
        SCMWebhookErrorCode.IDENTITY_MISMATCH,
    }:
        status = 400
    elif error.code in {
        SCMWebhookErrorCode.HEAD_UNAVAILABLE,
        SCMWebhookErrorCode.INVALID_CONFIGURATION,
    }:
        status = 503
    return ServiceResponse(
        status,
        {"error": {"code": error.code.value, "message": error.safe_message}},
    )


__all__ = [
    "AuthenticatedWebhookPort",
    "ExactWebhookRunAuthorization",
    "IdentityBindingWebhookAdapter",
    "SCMAdmissionHandler",
    "SqliteWorkerSupersession",
    "SupersessionPort",
    "WebhookReceiptPort",
]
