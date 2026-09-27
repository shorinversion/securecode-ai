"""Tenant-scoped HTTP operations for immutable scan policy profiles."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .policy_store import PolicyStore
from .ports import ServiceRequest, ServiceResponse
from .profiles import ProfileConflict, RolloutMode, ScanProfile


class PolicyOperationsHandler:
    """Expose policy profile aliases through the composed control-plane service."""

    __slots__ = ("_store",)

    def __init__(self, store: PolicyStore) -> None:
        if type(store) is not PolicyStore:
            raise TypeError("policy store is invalid")
        self._store = store

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        try:
            if request.action == "policies.read":
                if not _authenticated(request):
                    return _error(403, "FORBIDDEN")
                return ServiceResponse(
                    200,
                    self._store.list(
                        tenant_id=request.identity.tenant_id,
                        cursor=_query_one(request.query, "cursor"),
                        limit=_query_limit(request.query),
                    ),
                )
            if request.action == "policies.create":
                return self._create(request)
            if request.action == "policies.assign_repository":
                return self._assign_repository(request)
            if request.action == "policies.set_tenant_default":
                return self._set_tenant_default(request)
        except ProfileConflict:
            return _error(409, "POLICY_CONFLICT")
        except (TypeError, ValueError):
            return _error(400, "INVALID_POLICY_REQUEST")
        return _error(404, "NOT_FOUND")

    def _create(self, request: ServiceRequest) -> ServiceResponse:
        if not _admin_mutation(request):
            return _error(403, "FORBIDDEN")
        document = _document(request)
        if set(document) != {"profile_id", "version", "rollout", "calibrated", "content"}:
            return _error(400, "INVALID_POLICY_REQUEST")
        rollout_value = document["rollout"]
        content = document["content"]
        if type(rollout_value) is not str or not isinstance(content, Mapping):
            return _error(400, "INVALID_POLICY_REQUEST")
        try:
            rollout = RolloutMode(rollout_value)
        except ValueError:
            return _error(400, "INVALID_POLICY_REQUEST")
        if request.idempotency_key is None:
            return _error(400, "IDEMPOTENCY_KEY_REQUIRED")
        profile = ScanProfile.build(
            tenant_id=request.identity.tenant_id,
            profile_id=_required_text(document, "profile_id"),
            version=_required_int(document, "version"),
            rollout=rollout,
            calibrated=_required_bool(document, "calibrated"),
            content=content,
        )
        stored = self._store.create(profile, idempotency_key=request.idempotency_key)
        return ServiceResponse(201, _profile_document(stored))

    def _assign_repository(self, request: ServiceRequest) -> ServiceResponse:
        if not _admin_mutation(request):
            return _error(403, "FORBIDDEN")
        document = _document(request)
        if set(document) != {
            "repository_id",
            "profile_id",
            "version",
            "expected_assignment_version",
        }:
            return _error(400, "INVALID_POLICY_REQUEST")
        if request.idempotency_key is None:
            return _error(400, "IDEMPOTENCY_KEY_REQUIRED")
        repository_id = _required_text(document, "repository_id")
        self._store.assign_repository(
            tenant_id=request.identity.tenant_id,
            repository_id=repository_id,
            profile_id=_required_text(document, "profile_id"),
            version=_required_int(document, "version"),
            expected_assignment_version=_optional_version(
                document["expected_assignment_version"]
            ),
            idempotency_key=request.idempotency_key,
        )
        profile = self._store.resolve_profile(
            tenant_id=request.identity.tenant_id,
            repository_id=repository_id,
        )
        return ServiceResponse(
            200,
            {"repository_id": repository_id, "profile": _profile_document(profile)},
        )

    def _set_tenant_default(self, request: ServiceRequest) -> ServiceResponse:
        if not _admin_mutation(request):
            return _error(403, "FORBIDDEN")
        document = _document(request)
        if set(document) != {"profile_id", "version", "expected_assignment_version"}:
            return _error(400, "INVALID_POLICY_REQUEST")
        if request.idempotency_key is None:
            return _error(400, "IDEMPOTENCY_KEY_REQUIRED")
        profile_id = _required_text(document, "profile_id")
        version = _required_int(document, "version")
        self._store.set_tenant_default(
            tenant_id=request.identity.tenant_id,
            profile_id=profile_id,
            version=version,
            expected_assignment_version=_optional_version(
                document["expected_assignment_version"]
            ),
            idempotency_key=request.idempotency_key,
        )
        profile = self._store.get_profile(
            tenant_id=request.identity.tenant_id,
            profile_id=profile_id,
            version=version,
        )
        return ServiceResponse(200, {"profile": _profile_document(profile)})


def _authenticated(request: ServiceRequest) -> bool:
    return bool(request.identity.tenant_id)


def _admin_mutation(request: ServiceRequest) -> bool:
    return "admin" in request.identity.roles and not request.identity.workload


def _document(request: ServiceRequest) -> Mapping[str, object]:
    if request.document is None:
        raise ValueError("request document is missing")
    return request.document


def _required_text(document: Mapping[str, object], key: str) -> str:
    value = document.get(key)
    if type(value) is not str or not value:
        raise ValueError("policy request text is invalid")
    return value


def _required_int(document: Mapping[str, object], key: str) -> int:
    value = document.get(key)
    if type(value) is not int or value < 1:
        raise ValueError("policy request integer is invalid")
    return value


def _required_bool(document: Mapping[str, object], key: str) -> bool:
    value = document.get(key)
    if type(value) is not bool:
        raise ValueError("policy request boolean is invalid")
    return value


def _optional_version(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 1:
        raise ValueError("policy assignment version is invalid")
    return value


def _query_one(query: Mapping[str, tuple[str, ...]], key: str) -> str | None:
    values = query.get(key)
    if values is None:
        return None
    if len(values) != 1:
        raise ValueError("policy query is invalid")
    return values[0]


def _query_limit(query: Mapping[str, tuple[str, ...]]) -> int:
    value = _query_one(query, "limit")
    if value is None:
        return 50
    if not value.isascii() or not value.isdecimal() or len(value) > 3:
        raise ValueError("policy query is invalid")
    limit = int(value)
    if not 1 <= limit <= 100:
        raise ValueError("policy query is invalid")
    return limit


def _profile_document(profile: ScanProfile) -> dict[str, object]:
    return {
        "profile_id": profile.profile_id,
        "version": profile.version,
        "content_sha256": profile.content_sha256,
        "rollout": profile.rollout.value,
        "calibrated": profile.calibrated,
        "content": _plain_json(profile.content),
    }


def _plain_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_plain_json(item) for item in value]
    return value


def _error(status: int, code: str) -> ServiceResponse:
    return ServiceResponse(
        status,
        {"error": {"code": code, "message": "policy request was rejected"}},
    )


__all__ = ["PolicyOperationsHandler"]
