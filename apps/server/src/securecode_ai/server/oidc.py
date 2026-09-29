"""Provider-neutral, fail-closed OIDC admission over an injected signature verifier."""

from __future__ import annotations

import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol, TypeGuard

from .identity import Principal, Role

_MAX_TOKEN_LENGTH = 16_384
_MAX_CLAIM_LENGTH = 2_048
_MAX_NONCE_LENGTH = 1_024
_MAX_GROUP_LENGTH = 128
_MAX_GROUPS = 32
_MAX_ROLE_GROUPS = 128
_MAX_GRANTS = 128
_MAX_TOKEN_LIFETIME_SECONDS = 86_400


class TenantState(StrEnum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    DELETED = "DELETED"


class OidcDenied(Exception):
    pass


class SignedTokenVerifier(Protocol):
    def verify(self, token: str) -> dict[str, object] | None: ...


@dataclass(frozen=True, slots=True)
class OidcPolicy:
    issuer: str
    audience: str
    allowed_azp: frozenset[str]
    role_groups: dict[str, Role]
    subject_map: Mapping[str, str] = field(default_factory=dict)
    tenant_claim: str = "tenant_id"
    tenant_map: Mapping[str, str] = field(default_factory=dict)
    roles_claim: str = "groups"
    subject_claim: str = "sub"


@dataclass(frozen=True, slots=True)
class SubjectBinding:
    issuer: str
    subject: str
    tenant_id: str
    state: TenantState
    grants: frozenset[str]


@dataclass(frozen=True, slots=True)
class OidcReceipt:
    subject_id: str
    tenant_id: str
    roles: tuple[str, ...]
    expires_at: int

    def __post_init__(self) -> None:
        if (
            not _bounded_text(self.subject_id, _MAX_CLAIM_LENGTH)
            or not _bounded_text(self.tenant_id, _MAX_CLAIM_LENGTH)
            or type(self.roles) is not tuple
            or not 1 <= len(self.roles) <= len(Role)
            or not all(_bounded_text(role, _MAX_GROUP_LENGTH) for role in self.roles)
            or not set(self.roles).issubset({role.value for role in Role})
            or self.roles != tuple(sorted(set(self.roles)))
            or type(self.expires_at) is not int
            or self.expires_at < 0
        ):
            raise OidcDenied()


class OidcAdmission:
    def __init__(
        self,
        verifier: SignedTokenVerifier,
        policy: OidcPolicy,
        bindings: tuple[SubjectBinding, ...],
        *,
        now: Callable[[], int] = lambda: int(datetime.now(UTC).timestamp()),
    ) -> None:
        _validate_policy(policy)
        _validate_verifier(verifier)
        if not callable(now):
            raise OidcDenied()

        self._verifier = verifier
        self._policy = OidcPolicy(
            issuer=policy.issuer,
            audience=policy.audience,
            allowed_azp=frozenset(policy.allowed_azp),
            role_groups=dict(policy.role_groups),
            subject_map=dict(policy.subject_map),
            tenant_claim=policy.tenant_claim,
            tenant_map=dict(policy.tenant_map),
            roles_claim=policy.roles_claim,
            subject_claim=policy.subject_claim,
        )
        self._bindings = _validated_bindings(bindings, policy.issuer)
        self._now = now

    def active_subject(
        self,
        *,
        subject_id: str,
        tenant_id: str,
        roles: frozenset[Role],
        repository_grants: frozenset[str],
    ) -> bool:
        """Re-check a persisted session against current issuer-owned bindings."""

        if (
            not _bounded_text(subject_id, _MAX_CLAIM_LENGTH)
            or not _bounded_text(tenant_id, _MAX_CLAIM_LENGTH)
            or type(roles) is not frozenset
            or not roles
            or not all(type(role) is Role and role is not Role.WORKER for role in roles)
            or len(roles) > len(Role)
            or type(repository_grants) is not frozenset
            or len(repository_grants) > _MAX_GRANTS
            or any(not _bounded_text(grant, _MAX_CLAIM_LENGTH) for grant in repository_grants)
        ):
            return False
        configured_roles = frozenset(self._policy.role_groups.values())
        return any(
            binding.state is TenantState.ACTIVE
            and binding.tenant_id == tenant_id
            and roles.issubset(configured_roles)
            and binding.grants == repository_grants
            and _mapped_subject(binding.subject, self._policy.subject_map) == subject_id
            for binding in self._bindings.values()
        )

    def admit(self, token: str, *, nonce: str) -> tuple[Principal, OidcReceipt]:
        if (
            type(token) is not str
            or not token
            or len(token) > _MAX_TOKEN_LENGTH
            or token.count(".") != 2
            or not _bounded_text(nonce, _MAX_NONCE_LENGTH)
        ):
            raise OidcDenied()

        try:
            claims = self._verifier.verify(token)
        except Exception:
            raise OidcDenied() from None

        algorithm = claims.get("alg") if type(claims) is dict else None
        if (
            type(claims) is not dict
            or not _bounded_text(algorithm, _MAX_CLAIM_LENGTH)
            or algorithm.casefold() == "none"
        ):
            raise OidcDenied()

        issuer = claims.get("iss")
        subject = claims.get(self._policy.subject_claim)
        audience = claims.get("aud")
        azp = claims.get("azp")
        expiry = claims.get("exp")
        issued = claims.get("iat")
        claim_nonce = claims.get("nonce")
        try:
            current_time = self._now()
        except Exception:
            raise OidcDenied() from None
        if (
            not _bounded_text(issuer, _MAX_CLAIM_LENGTH)
            or not _bounded_text(subject, _MAX_CLAIM_LENGTH)
            or not _audience_matches(audience, self._policy.audience)
            or not _bounded_text(azp, _MAX_CLAIM_LENGTH)
            or not _bounded_text(claim_nonce, _MAX_NONCE_LENGTH)
            or issuer != self._policy.issuer
            or azp not in self._policy.allowed_azp
            or not secrets.compare_digest(claim_nonce, nonce)
            or type(expiry) is not int
            or type(issued) is not int
            or type(current_time) is not int
            or current_time < 0
            or issued < 0
            or expiry < 0
            or issued >= expiry
            or expiry - issued > _MAX_TOKEN_LIFETIME_SECONDS
            or issued > current_time + 60
            or expiry <= current_time
        ):
            raise OidcDenied()

        binding = self._bindings.get((issuer, subject))
        if binding is None or binding.state is not TenantState.ACTIVE:
            raise OidcDenied()

        if self._policy.tenant_map:
            tenant_source = claims.get(self._policy.tenant_claim)
            if not _bounded_text(tenant_source, _MAX_CLAIM_LENGTH):
                raise OidcDenied()
            mapped_tenant = _mapped_tenant(tenant_source, self._policy.tenant_map)
            if mapped_tenant != binding.tenant_id:
                raise OidcDenied()

        groups = claims.get(self._policy.roles_claim, ())
        if (
            type(groups) is not list
            or len(groups) > _MAX_GROUPS
            or not all(_bounded_text(item, _MAX_GROUP_LENGTH) for item in groups)
            or len(groups) != len(set(groups))
        ):
            raise OidcDenied()

        roles = frozenset(
            self._policy.role_groups[item] for item in groups if item in self._policy.role_groups
        )
        if not roles:
            raise OidcDenied()

        principal_subject = _mapped_subject(subject, self._policy.subject_map)

        principal = Principal(
            principal_subject,
            binding.tenant_id,
            roles,
            binding.grants,
        )
        receipt = OidcReceipt(
            principal_subject,
            binding.tenant_id,
            tuple(sorted(role.value for role in roles)),
            expiry,
        )
        return principal, receipt


def _validate_verifier(verifier: SignedTokenVerifier) -> None:
    try:
        verify = verifier.verify
    except Exception:
        raise OidcDenied() from None
    if not callable(verify):
        raise OidcDenied()


def _validate_policy(policy: OidcPolicy) -> None:
    if (
        type(policy) is not OidcPolicy
        or not _bounded_text(policy.issuer, _MAX_CLAIM_LENGTH)
        or not _bounded_text(policy.audience, _MAX_CLAIM_LENGTH)
        or type(policy.allowed_azp) is not frozenset
        or not policy.allowed_azp
        or len(policy.allowed_azp) > 16
        or any(not _bounded_text(value, _MAX_CLAIM_LENGTH) for value in policy.allowed_azp)
        or type(policy.role_groups) is not dict
        or not policy.role_groups
        or len(policy.role_groups) > _MAX_ROLE_GROUPS
        or not _bounded_text(policy.tenant_claim, _MAX_CLAIM_LENGTH)
        or not _bounded_text(policy.subject_claim, _MAX_CLAIM_LENGTH)
        or not _bounded_text(policy.roles_claim, _MAX_CLAIM_LENGTH)
        or policy.roles_claim
        in {
            "iss",
            "sub",
            "aud",
            "azp",
            "exp",
            "iat",
            "nonce",
            policy.tenant_claim,
            policy.subject_claim,
        }
        or any(
            not _bounded_text(group, _MAX_GROUP_LENGTH)
            or type(role) is not Role
            or role is Role.WORKER
            for group, role in policy.role_groups.items()
        )
        or not _valid_subject_map(policy.subject_map)
        or policy.tenant_claim
        in {"iss", "sub", "aud", "azp", "exp", "iat", "nonce", policy.subject_claim}
        or not _valid_tenant_map(policy.tenant_map)
        or policy.subject_claim in {"iss", "aud", "azp", "exp", "iat", "nonce", policy.tenant_claim}
    ):
        raise OidcDenied()


def _validated_bindings(
    bindings: tuple[SubjectBinding, ...],
    issuer: str,
) -> dict[tuple[str, str], SubjectBinding]:
    if type(bindings) is not tuple or len(bindings) > 10_000:
        raise OidcDenied()

    validated: dict[tuple[str, str], SubjectBinding] = {}
    for binding in bindings:
        if (
            type(binding) is not SubjectBinding
            or binding.issuer != issuer
            or not _bounded_text(binding.subject, _MAX_CLAIM_LENGTH)
            or not _bounded_text(binding.tenant_id, _MAX_CLAIM_LENGTH)
            or type(binding.state) is not TenantState
            or type(binding.grants) is not frozenset
            or len(binding.grants) > _MAX_GRANTS
            or any(not _bounded_text(grant, _MAX_CLAIM_LENGTH) for grant in binding.grants)
        ):
            raise OidcDenied()

        key = (binding.issuer, binding.subject)
        if key in validated:
            raise OidcDenied()
        validated[key] = binding
    return validated


def _bounded_text(value: object, maximum: int) -> TypeGuard[str]:
    if (
        type(value) is not str
        or not 0 < len(value) <= maximum
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        return False
    try:
        return len(value.encode("utf-8")) <= maximum * 4
    except UnicodeEncodeError:
        return False


def _audience_matches(value: object, expected: str) -> bool:
    if type(value) is str:
        return value == expected
    if type(value) is not list or not 1 <= len(value) <= 16:
        return False
    if not all(_bounded_text(item, _MAX_CLAIM_LENGTH) for item in value):
        return False
    if len(value) != len(set(value)):
        return False
    return expected in value


def _valid_subject_map(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    try:
        items = tuple(value.items())
    except Exception:
        return False
    return (
        len(items) <= 10_000
        and all(
            _bounded_text(subject, _MAX_CLAIM_LENGTH)
            and _bounded_text(principal, _MAX_CLAIM_LENGTH)
            for subject, principal in items
        )
        and len({principal for _, principal in items}) == len(items)
    )


def _valid_tenant_map(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    try:
        items = tuple(value.items())
    except Exception:
        return False
    return len(items) <= 10_000 and all(
        _bounded_text(source, _MAX_CLAIM_LENGTH) and _bounded_text(tenant, _MAX_CLAIM_LENGTH)
        for source, tenant in items
    )


def _mapped_subject(subject: str, mapping: Mapping[str, str]) -> str:
    """Use a server-owned canonical identifier when a mapping was configured."""

    if not mapping:
        return subject
    try:
        principal = mapping[subject]
    except (KeyError, TypeError):
        raise OidcDenied() from None
    if not _bounded_text(principal, _MAX_CLAIM_LENGTH):
        raise OidcDenied()
    return principal


def _mapped_tenant(source: str, mapping: Mapping[str, str]) -> str:
    """Resolve a signed external tenant claim to a server-owned identifier."""

    try:
        tenant = mapping[source]
    except (KeyError, TypeError):
        raise OidcDenied() from None
    if not _bounded_text(tenant, _MAX_CLAIM_LENGTH):
        raise OidcDenied()
    return tenant
