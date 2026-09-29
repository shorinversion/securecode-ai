from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TextIO

from securecode_ai.contracts import CliExitCode

from .connected_approvals import parse_approval_arguments
from .connected_payload import parse_payload
from .connected_transport import (
    ConnectedApi,
    ConnectedCliError,
    ConnectedCliErrorCode,
    HttpConnectedApi,
    _idempotency_key,
    _identifier,
    _safe_base_url,
)


@dataclass(frozen=True, slots=True)
class PolicyAdminSettings:
    base_url: str
    token: str
    tenant_id: str


def _settings(environment: Mapping[str, str]) -> PolicyAdminSettings:
    def required(name: str) -> str:
        value = environment.get(name)
        if type(value) is not str or not value:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        return value

    base_url = _safe_base_url(required("SECURECODE_CONTROL_PLANE_URL"))
    token = required("SECURECODE_CONTROL_PLANE_TOKEN")
    tenant_id = required("SECURECODE_TENANT_ID")
    if not _identifier(tenant_id) or len(token) > 8192:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return PolicyAdminSettings(base_url=base_url, token=token, tenant_id=tenant_id)


def _key(
    environment: Mapping[str, str],
    *,
    operation: str,
    payload: Mapping[str, object],
) -> str:
    value = environment.get("SECURECODE_IDEMPOTENCY_KEY")
    if not value:
        try:
            material = json.dumps(
                {
                    "operation": operation,
                    "payload": payload,
                    "tenant_id": environment.get("SECURECODE_TENANT_ID"),
                },
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        except (TypeError, ValueError):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION) from None
        value = "cli-" + hashlib.sha256(material).hexdigest()[:48]
    if not _idempotency_key(value):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return value


def _version(value: str) -> int:
    if not value.isascii() or not value.isdecimal() or len(value) > 10:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    result = int(value)
    if not 1 <= result <= 2_147_483_647:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return result


def _page_limit(value: str) -> int:
    if not value.isascii() or not value.isdecimal() or len(value) > 3:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    result = int(value)
    if not 1 <= result <= 100:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return result


def _policy_cursor(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 1024
        and value.isascii()
        and all(character.isalnum() or character in "_-" for character in value)
    )


def _policy_version(value: object) -> bool:
    if type(value) is not str or not value.endswith(".0.0"):
        return False
    major = value[:-4]
    return (
        major.isascii()
        and major.isdecimal()
        and len(major) <= 10
        and 1 <= int(major) <= 2_147_483_647
        and value == f"{int(major)}.0.0"
    )


def _expected_version(value: str) -> int | None:
    if value == "none":
        return None
    return _version(value)


def _required_fields(tokens: tuple[str, ...], names: set[str]) -> dict[str, str]:
    fields = parse_approval_arguments(tokens)
    if set(fields) != names:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return fields


def _client(settings: PolicyAdminSettings, api: ConnectedApi | None) -> ConnectedApi:
    return api if api is not None else HttpConnectedApi(settings.base_url)


def _policy_response(
    document: object,
    *,
    expected_profile_id: str,
    expected_version: int,
) -> dict[str, object]:
    if not isinstance(document, dict):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    required = {"policy_id", "policy_version", "content_sha256", "rollout", "calibrated"}
    if set(document) != required:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if (
        not _identifier(document["policy_id"])
        or not isinstance(document["policy_version"], str)
        or not document["policy_version"].endswith(".0.0")
        or not isinstance(document["content_sha256"], str)
        or len(document["content_sha256"]) != 64
        or any(item not in "0123456789abcdef" for item in document["content_sha256"])
        or document["rollout"] not in {"advisory", "new_code", "strict"}
        or type(document["calibrated"]) is not bool
        or document["policy_id"] != expected_profile_id
        or document["policy_version"] != f"{expected_version}.0.0"
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return dict(document)


def _assignment_response(
    document: object,
    *,
    expected_profile_id: str,
    expected_version: int,
    repository_id: str | None,
    tenant_id: str | None = None,
) -> dict[str, object]:
    if not isinstance(document, dict):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    required = {"policy_id", "policy_version"}
    if repository_id is not None:
        required.add("repository_id")
    else:
        required.add("tenant_id")
    if set(document) != required:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if (
        not _identifier(document["policy_id"])
        or not isinstance(document["policy_version"], str)
        or document["policy_version"] != f"{expected_version}.0.0"
        or document["policy_id"] != expected_profile_id
        or (repository_id is not None and document.get("repository_id") != repository_id)
        or (tenant_id is not None and document.get("tenant_id") != tenant_id)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return dict(document)


def _policy_page(document: object, *, limit: int) -> dict[str, object]:
    if not isinstance(document, dict) or set(document) != {"items", "next_cursor"}:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    items = document["items"]
    cursor = document["next_cursor"]
    if (
        not isinstance(items, list)
        or len(items) > limit
        or (cursor is not None and not _policy_cursor(cursor))
        or (cursor is not None and len(items) != limit)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    for item in items:
        if not isinstance(item, dict) or set(item) != {
            "policy_id",
            "policy_version",
            "content_sha256",
        }:
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
        if (
            not _identifier(item["policy_id"])
            or not _policy_version(item["policy_version"])
            or not isinstance(item["content_sha256"], str)
            or len(item["content_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in item["content_sha256"])
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return dict(document)


def create_policy(
    settings: PolicyAdminSettings,
    *,
    profile_id: str,
    version: int,
    rollout: str,
    calibrated: bool,
    content: dict[str, object],
    idempotency_key: str,
    api: ConnectedApi | None = None,
) -> dict[str, object]:
    if (
        not _identifier(profile_id)
        or not 1 <= version <= 2_147_483_647
        or rollout not in {"advisory", "new_code", "strict"}
        or type(calibrated) is not bool
        or not isinstance(content, dict)
        or not _idempotency_key(idempotency_key)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    document = _client(settings, api).mutate(
        "/api/v1/policies",
        document={
            "profile_id": profile_id,
            "version": version,
            "rollout": rollout,
            "calibrated": calibrated,
            "content": content,
        },
        token=settings.token,
        idempotency_key=idempotency_key,
    )
    return _policy_response(
        document,
        expected_profile_id=profile_id,
        expected_version=version,
    )


def activate_policy(
    settings: PolicyAdminSettings,
    *,
    profile_id: str,
    version: int,
    expected_active: int | None,
    idempotency_key: str,
    api: ConnectedApi | None = None,
) -> dict[str, object]:
    if not _identifier(profile_id) or not 1 <= version <= 2_147_483_647:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if expected_active is not None and not 1 <= expected_active <= 2_147_483_647:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if not _idempotency_key(idempotency_key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    document = _client(settings, api).mutate(
        f"/api/v1/policies/{profile_id}/versions/{version}:activate",
        document={"expected_active": expected_active},
        token=settings.token,
        idempotency_key=idempotency_key,
    )
    return _policy_response(
        document,
        expected_profile_id=profile_id,
        expected_version=version,
    )


def assign_policy(
    settings: PolicyAdminSettings,
    *,
    profile_id: str,
    version: int,
    repository_id: str,
    expected_assignment_version: int | None,
    idempotency_key: str,
    api: ConnectedApi | None = None,
) -> dict[str, object]:
    if (
        not _identifier(profile_id)
        or not _identifier(repository_id)
        or not 1 <= version <= 2_147_483_647
        or (
            expected_assignment_version is not None
            and not 1 <= expected_assignment_version <= 2_147_483_647
        )
        or not _idempotency_key(idempotency_key)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    document = _client(settings, api).mutate(
        f"/api/v1/policies/{profile_id}/versions/{version}/assignment",
        document={
            "repository_id": repository_id,
            "expected_assignment_version": expected_assignment_version,
        },
        token=settings.token,
        idempotency_key=idempotency_key,
    )
    return _assignment_response(
        document,
        expected_profile_id=profile_id,
        expected_version=version,
        repository_id=repository_id,
    )


def set_policy_default(
    settings: PolicyAdminSettings,
    *,
    profile_id: str,
    version: int,
    expected_assignment_version: int | None,
    idempotency_key: str,
    api: ConnectedApi | None = None,
) -> dict[str, object]:
    if (
        not _identifier(profile_id)
        or not 1 <= version <= 2_147_483_647
        or (
            expected_assignment_version is not None
            and not 1 <= expected_assignment_version <= 2_147_483_647
        )
        or not _idempotency_key(idempotency_key)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    document = _client(settings, api).mutate(
        f"/api/v1/policies/{profile_id}/versions/{version}/default",
        document={"expected_assignment_version": expected_assignment_version},
        token=settings.token,
        idempotency_key=idempotency_key,
    )
    return _assignment_response(
        document,
        expected_profile_id=profile_id,
        expected_version=version,
        repository_id=None,
        tenant_id=settings.tenant_id,
    )


def _content(value: str) -> dict[str, object]:
    try:
        return parse_payload(value)
    except ConnectedCliError:
        raise


def run_connected_policy_admin(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    try:
        settings = _settings(environment)
        action = tokens[1] if len(tokens) > 1 else "list"
        if action == "list":
            fields = parse_approval_arguments(tokens[2:])
            if not set(fields).issubset({"cursor", "limit"}):
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            cursor = fields.get("cursor")
            if cursor is not None and not _policy_cursor(cursor):
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            limit = _page_limit(fields.get("limit", "50"))
            query = {"limit": str(limit)}
            if cursor is not None:
                query["cursor"] = cursor
            document = _client(settings, None).read(
                "/api/v1/policies", token=settings.token, query=query
            )
            result = _policy_page(document, limit=limit)
        elif action == "create":
            fields = _required_fields(
                tokens[2:], {"profile-id", "version", "rollout", "calibrated", "content"}
            )
            if fields["calibrated"] not in {"true", "false"}:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            profile_id = fields["profile-id"]
            version = _version(fields["version"])
            rollout = fields["rollout"]
            calibrated = fields["calibrated"] == "true"
            content = _content(fields["content"])
            request: dict[str, object] = {
                "profile_id": profile_id,
                "version": version,
                "rollout": rollout,
                "calibrated": calibrated,
                "content": content,
            }
            result = create_policy(
                settings,
                profile_id=profile_id,
                version=version,
                rollout=rollout,
                calibrated=calibrated,
                content=content,
                idempotency_key=_key(environment, operation="policy-create", payload=request),
            )
        elif action == "activate":
            fields = _required_fields(tokens[2:], {"profile-id", "version", "expected-active"})
            profile_id = fields["profile-id"]
            version = _version(fields["version"])
            expected_active = _expected_version(fields["expected-active"])
            request = {
                "profile_id": profile_id,
                "version": version,
                "expected_active": expected_active,
            }
            result = activate_policy(
                settings,
                profile_id=profile_id,
                version=version,
                expected_active=expected_active,
                idempotency_key=_key(environment, operation="policy-activate", payload=request),
            )
        elif action == "assign":
            fields = _required_fields(
                tokens[2:],
                {"profile-id", "version", "repository", "expected-assignment-version"},
            )
            profile_id = fields["profile-id"]
            version = _version(fields["version"])
            repository_id = fields["repository"]
            expected_assignment_version = _expected_version(fields["expected-assignment-version"])
            request = {
                "profile_id": profile_id,
                "version": version,
                "repository_id": repository_id,
                "expected_assignment_version": expected_assignment_version,
            }
            result = assign_policy(
                settings,
                profile_id=profile_id,
                version=version,
                repository_id=repository_id,
                expected_assignment_version=expected_assignment_version,
                idempotency_key=_key(environment, operation="policy-assign", payload=request),
            )
        elif action == "default":
            fields = _required_fields(
                tokens[2:], {"profile-id", "version", "expected-assignment-version"}
            )
            profile_id = fields["profile-id"]
            version = _version(fields["version"])
            expected_assignment_version = _expected_version(fields["expected-assignment-version"])
            request = {
                "profile_id": profile_id,
                "version": version,
                "expected_assignment_version": expected_assignment_version,
            }
            result = set_policy_default(
                settings,
                profile_id=profile_id,
                version=version,
                expected_assignment_version=expected_assignment_version,
                idempotency_key=_key(environment, operation="policy-default", payload=request),
            )
        else:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    except ConnectedCliError as error:
        stderr.write("connected policy operation was rejected (" + error.code.value + ")\n")
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    except Exception:
        stderr.write("connected policy operation failed\n")
        return int(CliExitCode.OPERATIONAL_ERROR)
    stdout.write(
        json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    )
    return int(CliExitCode.COMPLETED)


__all__ = [
    "PolicyAdminSettings",
    "activate_policy",
    "assign_policy",
    "create_policy",
    "run_connected_policy_admin",
    "set_policy_default",
]
