"""Provider-neutral, fail-closed OIDC admission over an injected signature verifier."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol, TypeGuard

from .identity import Principal, Role

_MAX_TOKEN_LENGTH = 16_384
_MAX_CLAIM_LENGTH = 2_048
_MAX_NONCE_LENGTH = 1_024
_MAX_GROUP_LENGTH = 128
_MAX_GROUPS = 32


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
        )
        self._bindings = _validated_bindings(bindings, policy.issuer)
        self._now = now

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
        subject = claims.get("sub")
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
            or claim_nonce != nonce
            or type(expiry) is not int
            or type(issued) is not int
            or type(current_time) is not int
            or current_time < 0
            or issued < 0
            or expiry < 0
            or issued >= expiry
            or issued > current_time + 60
            or expiry <= current_time
        ):
            raise OidcDenied()

        binding = self._bindings.get((issuer, subject))
        if binding is None or binding.state is not TenantState.ACTIVE:
            raise OidcDenied()

        groups = claims.get("groups", ())
        if (
            type(groups) is not list
            or len(groups) > _MAX_GROUPS
            or not all(_bounded_text(item, _MAX_GROUP_LENGTH) for item in groups)
        ):
            raise OidcDenied()

        roles = frozenset(
            self._policy.role_groups[item] for item in groups if item in self._policy.role_groups
        )
        if not roles:
            raise OidcDenied()

        principal = Principal(
            subject,
            binding.tenant_id,
            roles,
            binding.grants,
        )
        receipt = OidcReceipt(
            subject,
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
        or any(not _bounded_text(value, _MAX_CLAIM_LENGTH) for value in policy.allowed_azp)
        or type(policy.role_groups) is not dict
        or any(
            not _bounded_text(group, _MAX_GROUP_LENGTH) or type(role) is not Role
            for group, role in policy.role_groups.items()
        )
    ):
        raise OidcDenied()


def _validated_bindings(
    bindings: tuple[SubjectBinding, ...],
    issuer: str,
) -> dict[tuple[str, str], SubjectBinding]:
    if type(bindings) is not tuple:
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
            or any(not _bounded_text(grant, _MAX_CLAIM_LENGTH) for grant in binding.grants)
        ):
            raise OidcDenied()

        key = (binding.issuer, binding.subject)
        if key in validated:
            raise OidcDenied()
        validated[key] = binding
    return validated


def _bounded_text(value: object, maximum: int) -> TypeGuard[str]:
    return type(value) is str and 0 < len(value) <= maximum


def _audience_matches(value: object, expected: str) -> bool:
    if type(value) is str:
        return value == expected
    if type(value) is not list or not 1 <= len(value) <= 16:
        return False
    if not all(_bounded_text(item, _MAX_CLAIM_LENGTH) for item in value):
        return False
    return expected in value
