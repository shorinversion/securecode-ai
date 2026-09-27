"""Closed HTTP route table and bounded ASGI boundary parsing."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Final

from .json_boundary import JsonBoundaryError, load_json_object
from .openapi import SUPPORTED_MAJOR

_MAX_BODY_BYTES: Final = 16_777_216
_MAX_QUERY_BYTES: Final = 8_192
_MAX_QUERY_FIELDS: Final = 64
_IDEMPOTENCY: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")
_PATH_PARAMETER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_VERSION_HEADER: Final = "x-securecode-api-version"
_MUTATING: Final = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True, slots=True)
class _Route:
    method: str
    pattern: str
    action: str
    workload_only: bool = False
    needs_precondition: bool = False
    raw_body: bool = False
    self_authenticated: bool = False


_ROUTES: Final = (
    _Route("POST", "/api/v1/runs", "runs.create"),
    _Route("GET", "/api/v1/repositories/{repository_id}/runs", "runs.list"),
    _Route("POST", "/api/v1/scm/runs:resolve", "scm.runs.resolve", workload_only=True),
    _Route("GET", "/api/v1/runs/{run_id}", "runs.read"),
    _Route("POST", "/api/v1/runs/{run_id}:cancel", "runs.cancel", needs_precondition=True),
    _Route("GET", "/api/v1/runs/{run_id}/events", "runs.events.read"),
    _Route("GET", "/api/v1/runs/{run_id}/findings", "runs.findings.read"),
    _Route("GET", "/api/v1/runs/{run_id}/artifacts", "runs.artifacts.read"),
    _Route(
        "GET",
        "/api/v1/runs/{run_id}/artifacts/{content_sha256}/content",
        "runs.artifacts.content",
    ),
    _Route(
        "GET",
        "/api/v1/runs/{run_id}/repair-patches/{finding_id}/content",
        "runs.repair_patches.content",
    ),
    _Route("GET", "/api/v1/runs/{run_id}/audit", "runs.audit.read"),
    _Route(
        "GET",
        "/api/v1/audit/resources/{resource_type}/{resource_id}",
        "runs.audit.read",
    ),
    _Route(
        "GET",
        "/api/v1/audit/resources/{resource_type}",
        "runs.audit.read",
    ),
    _Route("GET", "/api/v1/operations/metrics", "operations.metrics.read"),
    _Route("GET", "/api/v1/findings/{finding_id}", "findings.read"),
    _Route("GET", "/api/v1/findings/{finding_id}/evidence", "findings.evidence.read"),
    _Route(
        "POST",
        "/api/v1/findings/{finding_id}/decisions",
        "findings.decide",
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/artifacts:authorize",
        "artifacts.authorize",
        workload_only=True,
    ),
    _Route(
        "PUT",
        "/api/v1/artifact-uploads/{tenant_id}/{content_sha256}/{authorization_id}",
        "artifacts.upload",
        raw_body=True,
        self_authenticated=True,
    ),
    _Route("GET", "/api/v1/policies", "policies.read"),
    _Route("POST", "/api/v1/policies", "policies.create"),
    _Route(
        "POST",
        "/api/v1/policies/{profile_id}/versions/{version}:activate",
        "policies.activate",
    ),
    _Route(
        "POST",
        "/api/v1/policies/{profile_id}/versions/{version}/assignment",
        "policies.assign",
    ),
    _Route(
        "POST",
        "/api/v1/policies/{profile_id}/versions/{version}/default",
        "policies.default",
    ),
    _Route(
        "POST",
        "/api/v1/policies/repository-assignments",
        "policies.assign_repository",
    ),
    _Route("POST", "/api/v1/policies/tenant-default", "policies.set_tenant_default"),
    _Route("POST", "/api/v1/approvals", "approvals.create"),
    _Route("GET", "/api/v1/approvals/{approval_id}", "approvals.read"),
    _Route(
        "POST",
        "/api/v1/approvals/{approval_id}:decide",
        "approvals.decide",
        needs_precondition=True,
    ),
    _Route("POST", "/api/v1/findings/{finding_id}/waivers", "waivers.create"),
    _Route("GET", "/api/v1/waivers/{waiver_id}", "waivers.read"),
    _Route(
        "POST",
        "/api/v1/waivers/{waiver_id}:revoke",
        "waivers.revoke",
        needs_precondition=True,
    ),
    _Route("POST", "/api/v1/secret-grants", "secrets.grant"),
    _Route("GET", "/api/v1/secret-grants/{grant_id}", "secrets.read"),
    _Route(
        "POST",
        "/api/v1/secret-grants/{grant_id}:rotate",
        "secrets.rotate",
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/secret-grants/{grant_id}:revoke",
        "secrets.revoke",
        needs_precondition=True,
    ),
    _Route("POST", "/api/v1/backups", "backups.create"),
    _Route("GET", "/api/v1/backups/{backup_id}", "backups.read"),
    _Route(
        "POST",
        "/api/v1/backups/{backup_id}:execute",
        "backups.execute",
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/backups/{backup_id}:restore",
        "backups.restore",
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/backups/{backup_id}:restore:resolve",
        "backups.restore.resolve",
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/lifecycle/deletions",
        "lifecycle.deletions.create",
    ),
    _Route(
        "GET",
        "/api/v1/lifecycle/deletions/{deletion_id}",
        "lifecycle.deletions.read",
    ),
    _Route(
        "POST",
        "/api/v1/lifecycle/deletions/{deletion_id}:approve",
        "lifecycle.deletions.approve",
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/lifecycle/deletions/{deletion_id}:legal-hold",
        "lifecycle.deletions.legal_hold",
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/lifecycle/deletions/{deletion_id}:execute",
        "lifecycle.deletions.execute",
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/feedback",
        "feedback.submit",
        needs_precondition=True,
    ),
    _Route("GET", "/api/v1/feedback/metrics", "feedback.metrics.read"),
    _Route(
        "POST",
        "/api/v1/assurance",
        "assurance.append",
        needs_precondition=True,
    ),
    _Route("GET", "/api/v1/assurance", "assurance.read"),
    _Route(
        "POST",
        "/api/v1/integrations/github/webhook",
        "webhooks.github",
        raw_body=True,
        self_authenticated=True,
    ),
    _Route(
        "POST",
        "/api/v1/integrations/gitlab/webhook",
        "webhooks.gitlab",
        raw_body=True,
        self_authenticated=True,
    ),
    _Route("POST", "/api/v1/worker-sessions", "worker_sessions.create", workload_only=True),
    _Route(
        "POST",
        "/api/v1/worker-sessions/{session_id}/osv:query",
        "worker_sessions.osv.query",
        workload_only=True,
    ),
    _Route(
        "POST",
        "/api/v1/worker-sessions/{session_id}:heartbeat",
        "worker_sessions.heartbeat",
        workload_only=True,
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/worker-sessions/{session_id}/events:append",
        "worker_sessions.events.append",
        workload_only=True,
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/worker-sessions/{session_id}/artifacts:commit",
        "worker_sessions.artifacts.commit",
        workload_only=True,
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/worker-sessions/{session_id}:complete",
        "worker_sessions.complete",
        workload_only=True,
        needs_precondition=True,
    ),
)


def _headers(value: object) -> dict[str, str]:
    if not isinstance(value, (list, tuple)):
        return {}
    output: dict[str, str] = {}
    for item in value:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not all(isinstance(part, bytes) for part in item)
        ):
            return {}
        try:
            name, item_value = item[0].decode("ascii").lower(), item[1].decode("latin-1")
        except UnicodeDecodeError:
            return {}
        if name in output:
            return {}
        output[name] = item_value
    return output


def _login_transport_allowed(scope: Mapping[str, object]) -> bool:
    if scope.get("scheme") == "https":
        return True
    if scope.get("scheme") != "http":
        return False
    client = scope.get("client")
    if not isinstance(client, (tuple, list)) or not client or type(client[0]) is not str:
        return False
    try:
        return ipaddress.ip_address(client[0]).is_loopback
    except ValueError:
        return False


async def _read_body(
    receive: Callable[[], Awaitable[Mapping[str, object]]], limit: int
) -> bytes | None:
    chunks: list[bytes] = []
    size = 0
    while True:
        event = await receive()
        if event.get("type") != "http.request":
            return None
        chunk = event.get("body", b"")
        if not isinstance(chunk, bytes):
            return None
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
        if not event.get("more_body", False):
            return b"".join(chunks)


def _json_object(body: bytes) -> dict[str, object] | None:
    try:
        return load_json_object(body)
    except JsonBoundaryError:
        return None


def _match_route(method: str, path: str) -> tuple[_Route | None, dict[str, str]]:
    if path != "/" + path.strip("/") or "//" in path:
        return None, {}
    parts = path.strip("/").split("/")
    for route in _ROUTES:
        template = route.pattern.strip("/").split("/")
        if route.method != method or len(template) != len(parts):
            continue
        parameters: dict[str, str] = {}
        for expected, actual in zip(template, parts, strict=True):
            parameter = _match_path_segment(expected, actual)
            if parameter is not None:
                name, value = parameter
                parameters[name] = value
            elif expected != actual:
                break
        else:
            return route, parameters
    return None, {}


def _match_path_segment(expected: str, actual: str) -> tuple[str, str] | None:
    opening = expected.find("{")
    closing = expected.find("}", opening + 1)
    if opening < 0 or closing < 0:
        return None
    name = expected[opening + 1 : closing]
    prefix = expected[:opening]
    suffix = expected[closing + 1 :]
    if not name or not actual.startswith(prefix) or not actual.endswith(suffix):
        return None
    end = len(actual) - len(suffix) if suffix else len(actual)
    value = actual[len(prefix) : end]
    if _PATH_PARAMETER.fullmatch(value) is None:
        return None
    return name, value


def _idempotency_key(
    route: _Route,
    method: str,
    headers: Mapping[str, str],
) -> str | None:
    if method not in _MUTATING:
        return None
    if route.action == "webhooks.github":
        return headers.get("x-github-delivery")
    if route.action == "webhooks.gitlab":
        return headers.get("x-gitlab-event-uuid")
    if route.action == "artifacts.upload":
        return headers.get("x-securecode-authorization-id")
    return headers.get("idempotency-key")


def _supports_version(headers: Mapping[str, str]) -> bool:
    value = headers.get(_VERSION_HEADER)
    if value is None:
        return True
    major = value.split(".", 1)[0]
    return major == str(SUPPORTED_MAJOR)


def _valid_precondition(value: str | None) -> bool:
    return value is not None and 1 <= len(value) <= 256 and "\r" not in value and "\n" not in value


def _query(value: object) -> str | None:
    if type(value) is not bytes or len(value) > _MAX_QUERY_BYTES:
        return None
    try:
        decoded = value.decode("ascii")
    except UnicodeDecodeError:
        return None
    return decoded


def _safe_message(code: str) -> str:
    return {
        "INVALID_REQUEST": "request is invalid",
        "INVALID_JSON": "request JSON is invalid",
        "BODY_TOO_LARGE": "request body exceeds the allowed limit",
        "UNSUPPORTED_VERSION": "API version is unsupported",
        "UNAUTHENTICATED": "authentication is required",
        "FORBIDDEN": "request is not authorized",
        "NOT_FOUND": "resource was not found",
        "IDEMPOTENCY_KEY_REQUIRED": "a valid idempotency key is required",
        "IDEMPOTENCY_CONFLICT": "idempotency key conflicts with a prior request",
        "PRECONDITION_REQUIRED": "a current resource precondition is required",
        "SERVICE_UNAVAILABLE": "requested service is unavailable",
        "OPERATION_FAILED": "operation could not be completed",
    }.get(code, "request could not be completed")
