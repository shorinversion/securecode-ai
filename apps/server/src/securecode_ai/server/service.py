"""P6.2 durable handlers installed behind the P6.1 control-plane service port."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import TypeGuard

from securecode_ai.contracts import RunExecutionIdentity

from .artifact_read import LocalCommittedArtifactReader
from .finding_evidence import FindingEvidenceReader
from .persistence import (
    ConflictError,
    DevelopmentRepository,
    NotFoundError,
    PreconditionError,
    RepositoryError,
)
from .policy_store import PolicyStore
from .ports import ServiceRequest, ServiceResponse, ServiceUnavailableError
from .profiles import ProfileConflict, RolloutMode, ScanProfile
from .sqlite_database import open_private_sqlite


class DurableControlPlaneService:
    def __init__(
        self,
        repository: DevelopmentRepository,
        *,
        finding_evidence: FindingEvidenceReader | None = None,
        artifact_reader: LocalCommittedArtifactReader | None = None,
        policy_store: PolicyStore | None = None,
    ) -> None:
        self._repository = repository
        if policy_store is not None and type(policy_store) is not PolicyStore:
            raise ProfileConflict("policy store is invalid")
        if policy_store is None:
            policy_connection = _policy_store_connection(repository)
            try:
                policy_store = PolicyStore(policy_connection)
            except Exception:
                if policy_connection is not repository._connection:
                    policy_connection.close()
                raise
        self._policy_store = policy_store
        self._finding_evidence = finding_evidence
        self._artifact_reader = artifact_reader

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
        except (RepositoryError, ProfileConflict):
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
        if request.action == "runs.list":
            repository_id = request.path_params["repository_id"]
            if not _repository_allowed(request, repository_id):
                return _forbidden()
            return ServiceResponse(
                200,
                self._repository.list_runs(
                    request.identity.tenant_id,
                    repository_id,
                    _one(request.query, "cursor"),
                    _limit(request.query),
                ),
            )
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
            content_sha256 = _one(request.query, "content_sha256")
            if content_sha256 is not None:
                if self._artifact_reader is None:
                    raise ServiceUnavailableError()
                return ServiceResponse(
                    200,
                    self._artifact_reader.read_for_principal(
                        principal=request.identity,
                        run_id=run_id,
                        content_sha256=content_sha256,
                    ),
                )
            if self._artifact_reader is not None:
                self._artifact_reader.require_tenant_access(request.identity.tenant_id)
            return ServiceResponse(
                200,
                self._repository.list_artifacts(
                    request.identity.tenant_id,
                    run_id,
                    _one(request.query, "cursor"),
                    _limit(request.query),
                ),
            )
        if request.action == "runs.artifacts.content":
            run_id = request.path_params["run_id"]
            if not self._run_allowed(request, run_id):
                return _forbidden()
            if self._artifact_reader is None:
                raise ServiceUnavailableError()
            content = self._artifact_reader.read_binary_for_principal(
                principal=request.identity,
                run_id=run_id,
                content_sha256=request.path_params["content_sha256"],
            )
            return ServiceResponse(
                200,
                {},
                {
                    "cache-control": "no-store",
                    "content-sha256": content.content_sha256,
                    "content-type": "application/octet-stream",
                },
                content.content,
            )
        if request.action == "runs.repair_patches.content":
            run_id = request.path_params["run_id"]
            if not self._run_allowed(request, run_id):
                return _forbidden()
            if self._artifact_reader is None:
                raise ServiceUnavailableError()
            patch_sha256 = _one(request.query, "patch_sha256")
            if patch_sha256 is None:
                raise ConflictError()
            content = self._artifact_reader.read_repair_patch_for_principal(
                principal=request.identity,
                run_id=run_id,
                finding_id=request.path_params["finding_id"],
                patch_sha256=patch_sha256,
            )
            return ServiceResponse(
                200,
                {},
                {
                    "cache-control": "no-store",
                    "content-sha256": content.content_sha256,
                    "content-type": "application/octet-stream",
                    "x-securecode-repair-finding": request.path_params["finding_id"],
                    "x-securecode-repair-patch-sha256": patch_sha256,
                },
                content.content,
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
            return ServiceResponse(
                200,
                self._list_policies(
                    request.identity.tenant_id,
                    cursor=_one(request.query, "cursor"),
                    limit=_limit(request.query),
                ),
            )
        if request.action == "policies.create":
            return self._create_policy(request)
        if request.action == "policies.activate":
            return self._activate_policy(request)
        if request.action == "policies.assign":
            return self._assign_policy(request)
        if request.action == "policies.default":
            return self._set_policy_default(request)
        raise ServiceUnavailableError()

    def _create_policy(self, request: ServiceRequest) -> ServiceResponse:
        if not _admin_policy_request(request):
            return _forbidden()
        document = _exact_policy_document(
            request,
            required={"profile_id", "version", "rollout", "calibrated", "content"},
        )
        if document is None:
            return _invalid_policy_request()
        profile_id = document["profile_id"]
        version = document["version"]
        rollout = document["rollout"]
        calibrated = document["calibrated"]
        content = document["content"]
        if (
            not _policy_identifier(profile_id)
            or not _policy_version(version)
            or type(rollout) is not str
            or type(calibrated) is not bool
            or not isinstance(content, Mapping)
        ):
            return _invalid_policy_request()
        try:
            mode = RolloutMode(rollout)
            profile = ScanProfile.build(
                tenant_id=request.identity.tenant_id,
                profile_id=profile_id,
                version=version,
                rollout=mode,
                calibrated=calibrated,
                content=content,
            )
        except (TypeError, ValueError):
            return _invalid_policy_request()
        try:
            stored = self._policy_store.create(
                profile,
                idempotency_key=_idempotency_key(request),
            )
        except ProfileConflict:
            return _policy_conflict()
        return ServiceResponse(201, _policy_document(stored))

    def _activate_policy(self, request: ServiceRequest) -> ServiceResponse:
        if not _admin_policy_request(request):
            return _forbidden()
        document = _exact_policy_document(request, required={"expected_active"})
        if document is None:
            return _invalid_policy_request()
        expected_active = document["expected_active"]
        if expected_active is not None and not _policy_version(expected_active):
            return _invalid_policy_request()
        try:
            profile = self._policy_store.activate(
                tenant_id=request.identity.tenant_id,
                profile_id=request.path_params["profile_id"],
                version=_path_policy_version(request),
                expected_active=expected_active,
                idempotency_key=_idempotency_key(request),
            )
        except (ProfileConflict, TypeError, ValueError):
            return _policy_conflict()
        return ServiceResponse(200, _policy_document(profile))

    def _assign_policy(self, request: ServiceRequest) -> ServiceResponse:
        if not _admin_policy_request(request):
            return _forbidden()
        document = _exact_policy_document(
            request,
            required={"repository_id", "expected_assignment_version"},
        )
        if document is None:
            return _invalid_policy_request()
        repository_id = document["repository_id"]
        expected = document["expected_assignment_version"]
        if (
            not _policy_identifier(repository_id)
            or (expected is not None and not _policy_version(expected))
            or not _repository_allowed(request, repository_id)
        ):
            return _invalid_policy_request()
        profile_id = request.path_params["profile_id"]
        version = _path_policy_version(request)
        try:
            self._policy_store.assign_repository(
                tenant_id=request.identity.tenant_id,
                repository_id=repository_id,
                profile_id=profile_id,
                version=version,
                expected_assignment_version=expected,
                idempotency_key=_idempotency_key(request),
            )
        except (ProfileConflict, TypeError, ValueError):
            return _policy_conflict()
        return ServiceResponse(
            200,
            {
                "repository_id": repository_id,
                "policy_id": profile_id,
                "policy_version": f"{version}.0.0",
            },
        )

    def _set_policy_default(self, request: ServiceRequest) -> ServiceResponse:
        if not _admin_policy_request(request):
            return _forbidden()
        document = _exact_policy_document(
            request,
            required={"expected_assignment_version"},
        )
        if document is None:
            return _invalid_policy_request()
        expected = document["expected_assignment_version"]
        if expected is not None and not _policy_version(expected):
            return _invalid_policy_request()
        profile_id = request.path_params["profile_id"]
        version = _path_policy_version(request)
        try:
            self._policy_store.set_tenant_default(
                tenant_id=request.identity.tenant_id,
                profile_id=profile_id,
                version=version,
                expected_assignment_version=expected,
                idempotency_key=_idempotency_key(request),
            )
        except (ProfileConflict, TypeError, ValueError):
            return _policy_conflict()
        return ServiceResponse(
            200,
            {
                "tenant_id": request.identity.tenant_id,
                "policy_id": profile_id,
                "policy_version": f"{version}.0.0",
            },
        )

    def _list_policies(
        self,
        tenant_id: str,
        *,
        cursor: str | None,
        limit: int,
    ) -> dict[str, object]:
        page = self._policy_store.list(tenant_id=tenant_id, cursor=cursor, limit=limit)
        page_items = page["items"]
        if not isinstance(page_items, list):
            raise ConflictError()
        items = [
            {
                "policy_id": item["profile_id"],
                "policy_version": f"{item['version']}.0.0",
                "content_sha256": item["content_sha256"],
            }
            for item in page_items
        ]
        return {"items": items, "next_cursor": page["next_cursor"]}

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


def _policy_store_connection(repository: DevelopmentRepository) -> sqlite3.Connection:
    try:
        row = repository._connection.execute("PRAGMA database_list").fetchone()
    except sqlite3.Error as error:
        raise RepositoryError() from error
    if row is None or len(row) != 3 or row[1] != "main" or type(row[2]) is not str:
        raise RepositoryError()
    if not row[2]:
        return repository._connection
    return open_private_sqlite(Path(row[2]), create=False)


def _idempotency_key(request: ServiceRequest) -> str:
    if request.idempotency_key is None:
        raise ConflictError()
    return request.idempotency_key


def _precondition(request: ServiceRequest) -> int:
    raw = request.precondition
    if type(raw) is not str or not raw:
        raise PreconditionError()
    value = raw
    if value.startswith('"') or value.endswith('"'):
        if len(value) < 3 or not (value.startswith('"') and value.endswith('"')):
            raise PreconditionError()
        value = value[1:-1]
    if not value.isascii() or not value.isdecimal() or len(value) > 10:
        raise PreconditionError()
    version = int(value)
    if not 1 <= version <= 2_147_483_647:
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
    if len(values) > 1:
        raise ConflictError()
    return values[0] if values else None


def _limit(query: Mapping[str, tuple[str, ...]]) -> int:
    value = _one(query, "limit")
    if value is None:
        return 50
    if not value.isascii() or not value.isdecimal():
        raise ConflictError()
    normalized = value.lstrip("0") or "0"
    if len(normalized) > 3:
        raise ConflictError()
    limit = int(normalized)
    if not 1 <= limit <= 100:
        raise ConflictError()
    return limit


def _repository_allowed(request: ServiceRequest, repository_id: object) -> bool:
    return "admin" in request.identity.roles or (
        isinstance(repository_id, str) and repository_id in request.identity.repository_ids
    )


def _admin_policy_request(request: ServiceRequest) -> bool:
    return "admin" in request.identity.roles and not request.identity.workload


def _exact_policy_document(
    request: ServiceRequest,
    *,
    required: set[str],
) -> dict[str, object] | None:
    document = request.document
    if document is None or set(document) != required:
        return None
    return dict(document)


def _policy_identifier(value: object) -> TypeGuard[str]:
    return (
        type(value) is str
        and value.isascii()
        and 1 <= len(value) <= 128
        and value[0].isalnum()
        and all(character.isalnum() or character in "._:-" for character in value)
    )


def _policy_version(value: object) -> TypeGuard[int]:
    return type(value) is int and 1 <= value <= 2_147_483_647


def _path_policy_version(request: ServiceRequest) -> int:
    value = request.path_params.get("version")
    if type(value) is not str or not value.isascii() or not value.isdecimal() or len(value) > 10:
        raise ConflictError()
    version = int(value)
    if not _policy_version(version):
        raise ConflictError()
    return version


def _policy_document(profile: ScanProfile) -> dict[str, object]:
    return {
        "policy_id": profile.profile_id,
        "policy_version": f"{profile.version}.0.0",
        "content_sha256": profile.content_sha256,
        "rollout": profile.rollout.value,
        "calibrated": profile.calibrated,
    }


def _invalid_policy_request() -> ServiceResponse:
    return ServiceResponse(
        400,
        {"error": {"code": "INVALID_REQUEST", "message": "request is invalid"}},
    )


def _policy_conflict() -> ServiceResponse:
    return ServiceResponse(
        409,
        {"error": {"code": "CONFLICT", "message": "policy state conflicts"}},
    )


def _forbidden() -> ServiceResponse:
    return ServiceResponse(
        403,
        {"error": {"code": "FORBIDDEN", "message": "request is not authorized"}},
    )
