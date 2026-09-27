"""Strict request helpers shared by operational control-plane handlers."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime, timedelta

from .ports import ServiceRequest, ServiceResponse, VerifiedIdentity

_PATH_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def document(
    request: ServiceRequest,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> Mapping[str, object] | None:
    value = request.document
    if (
        not isinstance(value, Mapping)
        or set(value) - required - optional
        or not required.issubset(value)
    ):
        return None
    return value


def string(
    value: Mapping[str, object],
    name: str,
    *,
    maximum: int = 256,
) -> str | None:
    if not isinstance(value, Mapping):
        return None
    item = value.get(name)
    if (
        type(item) is not str
        or not 1 <= len(item) <= maximum
        or item != item.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in item)
    ):
        return None
    return item


def optional_string(
    value: Mapping[str, object],
    name: str,
    *,
    maximum: int = 256,
) -> str | None:
    if value.get(name) is None:
        return None
    return string(value, name, maximum=maximum)


def path_identifier(value: Mapping[str, object], name: str) -> str | None:
    item = string(value, name, maximum=128)
    if item is None or _PATH_IDENTIFIER.fullmatch(item) is None:
        return None
    return item


def boolean(value: Mapping[str, object], name: str) -> bool | None:
    if not isinstance(value, Mapping):
        return None
    item = value.get(name)
    return item if type(item) is bool else None


def integer(value: Mapping[str, object], name: str) -> int | None:
    if not isinstance(value, Mapping):
        return None
    item = value.get(name)
    return item if type(item) is int else None


def utc_datetime(value: Mapping[str, object], name: str) -> datetime | None:
    item = string(value, name, maximum=64)
    if item is None:
        return None
    try:
        parsed = datetime.fromisoformat(item.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.utcoffset() != timedelta(0):
        return None
    return parsed


def expected_version(request: ServiceRequest) -> int | None:
    value = request.precondition
    if type(value) is not str:
        return None
    if value.startswith('W/"') and value.endswith('"'):
        value = value[3:-1]
    elif value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    if not value.isascii() or not value.isdecimal():
        return None
    parsed = int(value)
    return parsed if 0 <= parsed <= 2_147_483_647 else None


def query_value(request: ServiceRequest, name: str) -> str | None:
    if not isinstance(request.query, Mapping):
        return None
    raw = request.query.get(name)
    if type(raw) is not tuple or len(raw) != 1:
        return None
    value = raw[0]
    if type(value) is not str or not value or value != value.strip():
        return None
    return value


def path_value(request: ServiceRequest, name: str) -> str | None:
    if not isinstance(request.path_params, Mapping):
        return None
    value = request.path_params.get(name)
    return value if type(value) is str and value else None


def repository_allowed(identity: VerifiedIdentity, repository_id: str) -> bool:
    return "admin" in identity.roles or repository_id in identity.repository_ids


def matches_tenant(value: Mapping[str, object], identity: VerifiedIdentity) -> bool:
    return "tenant_id" not in value or value.get("tenant_id") == identity.tenant_id


def response(
    status: int,
    body: Mapping[str, object],
    *,
    version: int | None = None,
) -> ServiceResponse:
    headers = None if version is None else {"etag": f'"{version}"'}
    return ServiceResponse(status, body, headers)


def error(status: int, code: str, message: str) -> ServiceResponse:
    return ServiceResponse(status, {"error": {"code": code, "message": message}})


INVALID_REQUEST = error(400, "INVALID_REQUEST", "request is invalid")
FORBIDDEN = error(403, "FORBIDDEN", "request is not authorized")
NOT_FOUND = error(404, "NOT_FOUND", "resource was not found")
CONFLICT = error(409, "CONFLICT", "operation conflicts with current state")
PRECONDITION_FAILED = error(
    412,
    "PRECONDITION_FAILED",
    "resource precondition failed",
)


__all__ = [
    "CONFLICT",
    "FORBIDDEN",
    "INVALID_REQUEST",
    "NOT_FOUND",
    "PRECONDITION_FAILED",
    "boolean",
    "document",
    "error",
    "expected_version",
    "integer",
    "matches_tenant",
    "optional_string",
    "path_identifier",
    "path_value",
    "query_value",
    "repository_allowed",
    "response",
    "string",
    "utc_datetime",
]
