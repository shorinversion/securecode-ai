"""Typed server-boundary ports. Implementations own persistence and credentials."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True, slots=True)
class VerifiedIdentity:
    """Verified subject context. Tenant scope never comes from request JSON."""

    subject_id: str
    tenant_id: str
    roles: frozenset[str]
    workload: bool = False
    repository_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.subject_id, str)
            or not self.subject_id
            or not isinstance(self.tenant_id, str)
            or not self.tenant_id
            or not isinstance(self.roles, frozenset)
            or not all(isinstance(role, str) and role for role in self.roles)
            or type(self.workload) is not bool
            or not isinstance(self.repository_ids, frozenset)
            or not all(
                isinstance(repository_id, str) and repository_id
                for repository_id in self.repository_ids
            )
        ):
            raise ValueError("verified identity is invalid")


class IdentityVerifier(Protocol):
    def verify_bearer(self, token: str) -> VerifiedIdentity | None: ...


class AuthorizationPort(Protocol):
    def allows(
        self,
        identity: VerifiedIdentity,
        *,
        action: str,
        repository_id: str | None,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class ServiceRequest:
    """Already-admitted metadata passed to a durable P6.2+ service implementation."""

    method: str
    route: str
    action: str
    identity: VerifiedIdentity
    idempotency_key: str | None
    precondition: str | None
    path_params: Mapping[str, str]
    query: Mapping[str, tuple[str, ...]]
    document: Mapping[str, object] | None
    raw_body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)
    server_context: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ServiceResponse:
    status: int
    document: Mapping[str, object]
    headers: Mapping[str, str] | None = None
    raw_body: bytes | None = None


class ServiceUnavailableError(Exception):
    """Explicitly signals an admitted route without an installed resource handler."""


class ControlPlaneService(Protocol):
    async def dispatch(self, request: ServiceRequest) -> ServiceResponse: ...


class ReadinessPort(Protocol):
    def ready(self) -> bool: ...


class DenyIdentityVerifier:
    def verify_bearer(self, token: str) -> VerifiedIdentity | None:
        return None


class DenyAuthorization:
    def allows(
        self,
        identity: VerifiedIdentity,
        *,
        action: str,
        repository_id: str | None,
    ) -> bool:
        return False


class UnavailableControlPlaneService:
    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        raise ServiceUnavailableError()


class StaticReadiness:
    def __init__(self, is_ready: bool = False) -> None:
        self._is_ready = is_ready

    def ready(self) -> bool:
        return self._is_ready
