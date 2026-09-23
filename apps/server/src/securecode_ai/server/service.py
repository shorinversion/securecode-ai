"""P6.2 durable handlers installed behind the P6.1 control-plane service port."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

from securecode_ai.contracts import RunExecutionIdentity

from .finding_evidence import FindingEvidenceReader
from .persistence import (
    ConflictError,
    DevelopmentRepository,
    NotFoundError,
    PreconditionError,
    RepositoryError,
)
from .ports import ServiceRequest, ServiceResponse, ServiceUnavailableError


class DurableControlPlaneService:
    def __init__(
        self,
        repository: DevelopmentRepository,
        *,
        finding_evidence: FindingEvidenceReader | None = None,
    ) -> None:
        self._repository = repository
        self._finding_evidence = finding_evidence

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        try:
            return self._dispatch(request)
        except NotFoundError:
            return ServiceResponse(
                404, {"error": {"code": "NOT_FOUND", "message": "resource was not found"}}
            )
        except PreconditionError:
            return ServiceResponse(
                412,
                {
                    "error": {
                        "code": "PRECONDITION_FAILED",
                        "message": "resource precondition failed",
                    }
                },
            )
        except ConflictError:
            return ServiceResponse(
                409,
                {"error": {"code": "CONFLICT", "message": "request conflicts with current state"}},
            )
        except RepositoryError:
            return ServiceResponse(
                503,
                {
                    "error": {
                        "code": "SERVICE_UNAVAILABLE",
                        "message": "requested service is unavailable",
                    }
                },
            )

    def _dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.action == "runs.create":
            return self._create_run(request)
        if request.action == "runs.read":
            run = self._repository.get_run(
                request.identity.tenant_id,
                request.path_params["run_id"],
            )
            if not _repository_allowed(request, run.get("repository_id")):
                return _forbidden()
            return ServiceResponse(200, run)
        if request.action == "runs.cancel":
            return self._cancel_run(request)
        if request.action == "runs.events.read":
            if not self._run_allowed(request, request.path_params["run_id"]):
                return _forbidden()
            return ServiceResponse(
                200,
                self._repository.list_events(
                    request.identity.tenant_id,
                    request.path_params["run_id"],
                    _one(request.query, "cursor"),
                    _limit(request.query),
                ),
            )
        if request.action == "runs.findings.read":
            if not self._run_allowed(request, request.path_params["run_id"]):
                return _forbidden()
            return ServiceResponse(
                200,
                self._repository.list_findings(
                    request.identity.tenant_id,
                    request.path_params["run_id"],
                    _one(request.query, "cursor"),
                    _limit(request.query),
                ),
            )
        if request.action == "runs.artifacts.read":
            run_id = request.path_params["run_id"]
            if not self._run_allowed(request, run_id):
                return _forbidden()
            return ServiceResponse(
                200,
                self._repository.list_artifacts(request.identity.tenant_id, run_id),
            )
        if request.action == "findings.read":
            finding = self._repository.get_finding(
                request.identity.tenant_id,
                request.path_params["finding_id"],
            )
            if not self._run_allowed(request, str(finding["run_id"])):
                return _forbidden()
            return ServiceResponse(200, finding)
        if request.action == "findings.evidence.read":
            finding_id = request.path_params["finding_id"]
            finding = self._repository.get_finding(request.identity.tenant_id, finding_id)
            if not self._run_allowed(request, str(finding["run_id"])):
                return _forbidden()
            if self._finding_evidence is None:
                raise ServiceUnavailableError()
            return ServiceResponse(
                200,
                self._finding_evidence.read(
                    tenant_id=request.identity.tenant_id,
                    finding_id=finding_id,
                ),
            )
        if request.action == "findings.decide":
            return self._decide_finding(request)
        if request.action == "policies.read":
            return ServiceResponse(200, self._repository.list_policies(request.identity.tenant_id))
        raise ServiceUnavailableError()

    def _run_allowed(self, request: ServiceRequest, run_id: str) -> bool:
        run = self._repository.get_run(request.identity.tenant_id, run_id)
        return _repository_allowed(request, run.get("repository_id"))

    def _create_run(self, request: ServiceRequest) -> ServiceResponse:
        document = _document(request)
        identity = document.get("execution_identity")
        if not isinstance(identity, dict):
            raise ConflictError()
        try:
            validated = RunExecutionIdentity.model_validate(identity)
        except (TypeError, ValueError):
            raise ConflictError() from None
        revision = validated.repository_revision
        tenant = revision.tenant_id
        repository = revision.repository_id
        base = revision.base_sha
        head = revision.head_sha
        run_id = document.get("run_id")
        if not isinstance(run_id, str) or not run_id or tenant != request.identity.tenant_id:
            raise ConflictError()
        if not _repository_allowed(request, repository):
            return _forbidden()
        identity_hash = document.get("execution_identity_hash")
        expected_hash = validated.execution_identity_hash
        if identity_hash != expected_hash:
            raise ConflictError()
        response = self._repository.create_run(
            tenant_id=tenant,
            run_id=run_id,
            repository_id=repository,
            execution_identity_hash=expected_hash,
            base_sha=base,
            head_sha=head,
            metadata=_safe_run_metadata(document),
            idempotency_key=_idempotency_key(request),
            request_sha256=_request_hash(request),
        )
        return ServiceResponse(response.status, response.document)

    def _cancel_run(self, request: ServiceRequest) -> ServiceResponse:
        if not self._run_allowed(request, request.path_params["run_id"]):
            return _forbidden()
        response = self._repository.cancel_run(
            tenant_id=request.identity.tenant_id,
            run_id=request.path_params["run_id"],
            precondition=_precondition(request),
            idempotency_key=_idempotency_key(request),
            request_sha256=_request_hash(request),
        )
        return ServiceResponse(response.status, response.document)

    def _decide_finding(self, request: ServiceRequest) -> ServiceResponse:
        document = _document(request)
        run_id = document.get("run_id")
        revision = document.get("revision_sha")
        decision_type = document.get("decision_type")
        reason = document.get("reason")
        if (
            not isinstance(run_id, str)
            or not run_id
            or not isinstance(revision, str)
            or not isinstance(decision_type, str)
            or not isinstance(reason, str)
            or not 1 <= len(reason) <= 1024
        ):
            raise ConflictError()
        response = self._repository.decide_finding(
            tenant_id=request.identity.tenant_id,
            run_id=run_id,
            finding_id=request.path_params["finding_id"],
            revision_sha=revision,
            decision_type=decision_type,
            metadata={"reason_code": document.get("reason_code"), "expiry": document.get("expiry")},
            idempotency_key=_idempotency_key(request),
            request_sha256=_request_hash(request),
            authorized_repository_ids=(
                None if "admin" in request.identity.roles else request.identity.repository_ids
            ),
        )
        return ServiceResponse(response.status, response.document)


def _document(request: ServiceRequest) -> Mapping[str, object]:
    if request.document is None:
        raise ConflictError()
    return request.document


def _idempotency_key(request: ServiceRequest) -> str:
    if request.idempotency_key is None:
        raise ConflictError()
    return request.idempotency_key


def _precondition(request: ServiceRequest) -> int:
    if request.precondition is None:
        raise PreconditionError()
    value = request.precondition.strip('"')
    if not value.isdigit():
        raise PreconditionError()
    version = int(value)
    if version <= 0:
        raise PreconditionError()
    return version


def _request_hash(request: ServiceRequest) -> str:
    return hashlib.sha256(
        request.method.encode("ascii")
        + b"\x00"
        + request.route.encode("utf-8")
        + b"\x00"
        + request.raw_body
    ).hexdigest()


def _safe_run_metadata(document: Mapping[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in document.items()
        if key in {"request_id", "policy_id", "workflow_id"}
    }


def _one(query: Mapping[str, tuple[str, ...]], name: str) -> str | None:
    values = query.get(name, ())
    return values[0] if len(values) == 1 else None


def _limit(query: Mapping[str, tuple[str, ...]]) -> int:
    value = _one(query, "limit")
    return int(value) if value is not None and value.isdigit() and 1 <= int(value) <= 100 else 50


def _repository_allowed(request: ServiceRequest, repository_id: object) -> bool:
    return "admin" in request.identity.roles or (
        isinstance(repository_id, str) and repository_id in request.identity.repository_ids
    )


def _forbidden() -> ServiceResponse:
    return ServiceResponse(
        403,
        {"error": {"code": "FORBIDDEN", "message": "request is not authorized"}},
    )
