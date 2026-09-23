"""Production bearer authentication with injected, offline JWT verification."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final, Protocol, TypeGuard, cast

from .auth_crypto import RsaPublicKey, RsaSha256SignatureVerifier
from .ports import IdentityVerifier, VerifiedIdentity

_BASE64URL: Final = re.compile(r"[A-Za-z0-9_-]+\Z")
_ALGORITHM: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{1,31}\Z")
_SAFE_ROLES: Final = frozenset({"viewer", "auditor", "approver", "admin", "worker", "scm"})
_WORKLOAD_ROLES: Final = frozenset({"worker", "scm"})
_REMOTE_KEY_HEADERS: Final = frozenset({"jku", "jwk", "x5u", "x5c"})


class AuthenticationDenied(Exception):
    """Redacted authentication failure safe to cross an application boundary."""

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__("authentication failed")


class JwtKeyResolver(Protocol):
    """Resolve already provisioned key material without performing network I/O."""

    def resolve_key(self, *, issuer: str, algorithm: str, key_id: str) -> object | None: ...


class JwtSignatureVerifier(Protocol):
    """Algorithm-specific signature verification injected into the JWT boundary."""

    def verify_signature(
        self,
        *,
        algorithm: str,
        key: object,
        signing_input: bytes,
        signature: bytes,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class JwtVerificationPolicy:
    """Pinned trust and time policy for one issuer profile."""

    issuer: str
    audience: str
    algorithm: str
    key_id: str
    clock_skew_seconds: int = 30
    max_token_bytes: int = 8192
    max_token_lifetime_seconds: int | None = None
    authorized_party: str | None = None
    accepted_types: frozenset[str] = field(default_factory=lambda: frozenset({"JWT", "at+jwt"}))

    def __post_init__(self) -> None:
        if (
            not _configured_string(self.issuer, 2048)
            or not _configured_string(self.audience, 512)
            or not _configured_string(self.key_id, 256)
            or type(self.algorithm) is not str
            or _ALGORITHM.fullmatch(self.algorithm) is None
            or self.algorithm.casefold() == "none"
            or type(self.clock_skew_seconds) is not int
            or not 0 <= self.clock_skew_seconds <= 300
            or type(self.max_token_bytes) is not int
            or not 128 <= self.max_token_bytes <= 65_536
            or (
                self.max_token_lifetime_seconds is not None
                and (
                    type(self.max_token_lifetime_seconds) is not int
                    or not 1 <= self.max_token_lifetime_seconds <= 86_400
                )
            )
            or (
                self.authorized_party is not None
                and not _configured_string(self.authorized_party, 512)
            )
            or not isinstance(self.accepted_types, frozenset)
            or not self.accepted_types
            or not all(_configured_string(value, 64) for value in self.accepted_types)
        ):
            raise ValueError("JWT verification policy is invalid")


@dataclass(frozen=True, slots=True)
class IdentityClaimMapping:
    """Closed mapping from provider claims to server identity fields."""

    role_map: Mapping[str, str]
    tenant_claim: str = "tenant_id"
    subject_claim: str = "sub"
    roles_claim: str = "roles"
    workload_claim: str = "workload"
    repository_ids_claim: str = "repository_ids"
    tenant_map: Mapping[str, str] | None = None
    subject_map: Mapping[str, str] | None = None
    repository_id_map: Mapping[str, str] | None = None
    allowed_roles: frozenset[str] = field(default_factory=lambda: _SAFE_ROLES)
    workload_roles: frozenset[str] = field(default_factory=lambda: _WORKLOAD_ROLES)
    max_roles: int = 16
    max_repository_ids: int = 128

    def __post_init__(self) -> None:
        claim_names = (
            self.tenant_claim,
            self.subject_claim,
            self.roles_claim,
            self.workload_claim,
            self.repository_ids_claim,
        )
        if (
            len(set(claim_names)) != len(claim_names)
            or not all(_configured_string(name, 256) for name in claim_names)
            or not _valid_string_map(self.role_map)
            or not _valid_optional_string_map(self.tenant_map)
            or not _valid_optional_string_map(self.subject_map)
            or not _valid_optional_string_map(self.repository_id_map)
            or not isinstance(self.allowed_roles, frozenset)
            or not self.allowed_roles
            or not self.allowed_roles.issubset(_SAFE_ROLES)
            or not isinstance(self.workload_roles, frozenset)
            or not self.workload_roles
            or not self.workload_roles.issubset(self.allowed_roles)
            or not self.workload_roles.issubset(_WORKLOAD_ROLES)
            or not set(self.role_map.values()).issubset(self.allowed_roles)
            or type(self.max_roles) is not int
            or not 1 <= self.max_roles <= 64
            or type(self.max_repository_ids) is not int
            or not 0 <= self.max_repository_ids <= 1024
        ):
            raise ValueError("identity claim mapping is invalid")
        object.__setattr__(self, "role_map", MappingProxyType(dict(self.role_map)))
        if self.tenant_map is not None:
            object.__setattr__(self, "tenant_map", MappingProxyType(dict(self.tenant_map)))
        if self.subject_map is not None:
            object.__setattr__(self, "subject_map", MappingProxyType(dict(self.subject_map)))
        if self.repository_id_map is not None:
            object.__setattr__(
                self,
                "repository_id_map",
                MappingProxyType(dict(self.repository_id_map)),
            )


class PinnedKeyResolver:
    """Single-key offline resolver useful for a pinned local issuer profile."""

    __slots__ = ("_algorithm", "_issuer", "_key", "_key_id")

    def __init__(self, *, issuer: str, algorithm: str, key_id: str, key: object) -> None:
        if (
            not _configured_string(issuer, 2048)
            or type(algorithm) is not str
            or _ALGORITHM.fullmatch(algorithm) is None
            or algorithm.casefold() == "none"
            or not _configured_string(key_id, 256)
            or key is None
        ):
            raise ValueError("pinned key configuration is invalid")
        self._issuer = issuer
        self._algorithm = algorithm
        self._key_id = key_id
        self._key = key

    def resolve_key(self, *, issuer: str, algorithm: str, key_id: str) -> object | None:
        if not (
            hmac.compare_digest(issuer, self._issuer)
            and hmac.compare_digest(algorithm, self._algorithm)
            and hmac.compare_digest(key_id, self._key_id)
        ):
            return None
        return self._key

    def __repr__(self) -> str:
        return "PinnedKeyResolver(<redacted>)"


class HmacSha256SignatureVerifier:
    """Local symmetric HS256 profile using only Python standard library crypto."""

    __slots__ = ()

    def verify_signature(
        self,
        *,
        algorithm: str,
        key: object,
        signing_input: bytes,
        signature: bytes,
    ) -> bool:
        if algorithm != "HS256" or not isinstance(key, bytes) or len(key) < 32:
            return False
        expected = hmac.new(key, signing_input, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)


class BearerJwtIdentityVerifier:
    """Fail-closed JWT bearer verifier implementing the IdentityVerifier port."""

    __slots__ = (
        "_allowed_roles",
        "_clock",
        "_key_resolver",
        "_mapping",
        "_policy",
        "_repository_id_map",
        "_role_map",
        "_signature_verifier",
        "_subject_map",
        "_tenant_map",
        "_workload_roles",
    )

    def __init__(
        self,
        *,
        policy: JwtVerificationPolicy,
        mapping: IdentityClaimMapping,
        key_resolver: JwtKeyResolver,
        signature_verifier: JwtSignatureVerifier,
        clock: Callable[[], int | float] | None = None,
    ) -> None:
        if (
            type(policy) is not JwtVerificationPolicy
            or type(mapping) is not IdentityClaimMapping
            or not callable(getattr(key_resolver, "resolve_key", None))
            or not callable(getattr(signature_verifier, "verify_signature", None))
            or (clock is not None and not callable(clock))
        ):
            raise ValueError("JWT verifier configuration is invalid")
        self._mapping = mapping
        self._role_map = dict(mapping.role_map)
        self._tenant_map = None if mapping.tenant_map is None else dict(mapping.tenant_map)
        self._subject_map = None if mapping.subject_map is None else dict(mapping.subject_map)
        self._repository_id_map = (
            None if mapping.repository_id_map is None else dict(mapping.repository_id_map)
        )
        self._allowed_roles = mapping.allowed_roles
        self._workload_roles = mapping.workload_roles
        self._key_resolver = key_resolver
        self._signature_verifier = signature_verifier
        self._clock = time.time if clock is None else clock
        self._policy = policy

    def verify_bearer(self, token: str) -> VerifiedIdentity | None:
        try:
            return self._verify_bearer(token)
        except Exception:
            return None

    def _verify_bearer(self, token: str) -> VerifiedIdentity:
        policy: JwtVerificationPolicy = self._policy
        if (
            type(token) is not str
            or not 16 <= len(token) <= policy.max_token_bytes
            or token.count(".") != 2
            or not token.isascii()
        ):
            raise AuthenticationDenied
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        header_bytes = _decode_segment(encoded_header, 4096)
        payload_bytes = _decode_segment(encoded_payload, policy.max_token_bytes)
        signature = _decode_segment(encoded_signature, 4096)
        header = _json_object(header_bytes)
        claims = _json_object(payload_bytes)
        self._validate_header(header, policy)

        issuer = claims.get("iss")
        if type(issuer) is not str or not hmac.compare_digest(issuer, policy.issuer):
            raise AuthenticationDenied
        try:
            key = self._key_resolver.resolve_key(
                issuer=policy.issuer,
                algorithm=policy.algorithm,
                key_id=policy.key_id,
            )
        except Exception:
            raise AuthenticationDenied from None
        if key is None:
            raise AuthenticationDenied
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        try:
            verified = self._signature_verifier.verify_signature(
                algorithm=policy.algorithm,
                key=key,
                signing_input=signing_input,
                signature=signature,
            )
        except Exception:
            raise AuthenticationDenied from None
        if verified is not True:
            raise AuthenticationDenied

        now = self._clock()
        if (
            type(now) not in (int, float)
            or isinstance(now, bool)
            or not 0 <= now <= 253_402_300_799
        ):
            raise AuthenticationDenied
        current_time = int(now)
        self._validate_registered_claims(claims, policy, current_time)
        return self._identity(claims)

    @staticmethod
    def _validate_header(header: dict[str, object], policy: JwtVerificationPolicy) -> None:
        algorithm = header.get("alg")
        key_id = header.get("kid")
        token_type = header.get("typ")
        if (
            type(algorithm) is not str
            or not hmac.compare_digest(algorithm, policy.algorithm)
            or type(key_id) is not str
            or not hmac.compare_digest(key_id, policy.key_id)
            or any(name in header for name in _REMOTE_KEY_HEADERS)
            or "crit" in header
            or "b64" in header
            or (
                token_type is not None
                and (type(token_type) is not str or token_type not in policy.accepted_types)
            )
        ):
            raise AuthenticationDenied

    @staticmethod
    def _validate_registered_claims(
        claims: dict[str, object],
        policy: JwtVerificationPolicy,
        now: int,
    ) -> None:
        audience = claims.get("aud")
        if type(audience) is str:
            audience_matches = hmac.compare_digest(audience, policy.audience)
        elif type(audience) is list and 1 <= len(audience) <= 16:
            audience_matches = _audience_matches(audience, policy.audience)
        else:
            audience_matches = False
        if not audience_matches:
            raise AuthenticationDenied
        authorized_party = claims.get("azp")
        if policy.authorized_party is not None:
            if type(authorized_party) is not str or not hmac.compare_digest(
                authorized_party, policy.authorized_party
            ):
                raise AuthenticationDenied
        elif authorized_party is not None and not _claim_string(authorized_party, 512):
            raise AuthenticationDenied

        expires_at = _numeric_date(claims.get("exp"))
        issued_at = _numeric_date(claims.get("iat"))
        not_before_value = claims.get("nbf")
        not_before = None if not_before_value is None else _numeric_date(not_before_value)
        skew = policy.clock_skew_seconds
        if (
            expires_at <= now - skew
            or issued_at > now + skew
            or issued_at >= expires_at
            or (not_before is not None and not_before > now + skew)
            or (not_before is not None and not_before >= expires_at)
            or (
                policy.max_token_lifetime_seconds is not None
                and expires_at - issued_at > policy.max_token_lifetime_seconds
            )
        ):
            raise AuthenticationDenied

    def _identity(self, claims: dict[str, object]) -> VerifiedIdentity:
        mapping = self._mapping
        tenant_source = claims.get(mapping.tenant_claim)
        subject_source = claims.get(mapping.subject_claim)
        if not _claim_string(tenant_source, 256) or not _claim_string(subject_source, 256):
            raise AuthenticationDenied
        tenant_id = _mapped_value(tenant_source, self._tenant_map)
        subject_id = _mapped_value(subject_source, self._subject_map)

        raw_roles = claims.get(mapping.roles_claim)
        if (
            type(raw_roles) is not list
            or not 1 <= len(raw_roles) <= mapping.max_roles
            or not all(_claim_string(role, 128) for role in raw_roles)
            or len(set(raw_roles)) != len(raw_roles)
        ):
            raise AuthenticationDenied
        try:
            roles = frozenset(self._role_map[role] for role in raw_roles)
        except KeyError:
            raise AuthenticationDenied from None
        if not roles or not roles.issubset(self._allowed_roles):
            raise AuthenticationDenied

        workload_value = claims.get(mapping.workload_claim, False)
        if type(workload_value) is not bool:
            raise AuthenticationDenied
        if workload_value:
            if roles.isdisjoint(self._workload_roles) or not roles.issubset(self._workload_roles):
                raise AuthenticationDenied
        elif not roles.isdisjoint(self._workload_roles):
            raise AuthenticationDenied

        raw_repository_ids = claims.get(mapping.repository_ids_claim, [])
        if (
            type(raw_repository_ids) is not list
            or len(raw_repository_ids) > mapping.max_repository_ids
            or not all(_claim_string(value, 256) for value in raw_repository_ids)
            or len(set(raw_repository_ids)) != len(raw_repository_ids)
        ):
            raise AuthenticationDenied
        repository_ids = frozenset(
            _mapped_value(value, self._repository_id_map) for value in raw_repository_ids
        )
        return VerifiedIdentity(
            subject_id=subject_id,
            tenant_id=tenant_id,
            roles=roles,
            workload=workload_value,
            repository_ids=repository_ids,
        )


class CompositeIdentityVerifier:
    """Compose production OIDC and hashed bootstrap verifiers without token retention."""

    __slots__ = ("_verifiers",)

    def __init__(self, *verifiers: IdentityVerifier) -> None:
        if not 1 <= len(verifiers) <= 8 or not all(
            callable(getattr(verifier, "verify_bearer", None)) for verifier in verifiers
        ):
            raise ValueError("identity verifier composition is invalid")
        self._verifiers = verifiers

    def verify_bearer(self, token: str) -> VerifiedIdentity | None:
        if type(token) is not str or not 1 <= len(token) <= 8192:
            return None
        matched: VerifiedIdentity | None = None
        for verifier in self._verifiers:
            try:
                identity = verifier.verify_bearer(token)
            except Exception:
                continue
            if identity is None:
                continue
            if type(identity) is not VerifiedIdentity or matched is not None:
                return None
            matched = identity
        return matched


def _configured_string(value: object, maximum: int) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= maximum
        and value == value.strip()
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


def _claim_string(value: object, maximum: int) -> TypeGuard[str]:
    return _configured_string(value, maximum)


def _valid_string_map(value: object) -> bool:
    return (
        isinstance(value, Mapping)
        and bool(value)
        and len(value) <= 1024
        and all(
            _configured_string(key, 256) and _configured_string(item, 256)
            for key, item in value.items()
        )
    )


def _valid_optional_string_map(value: object) -> bool:
    return value is None or _valid_string_map(value)


def _mapped_value(value: str, mapping: dict[str, str] | None) -> str:
    if mapping is None:
        return value
    try:
        return mapping[value]
    except KeyError:
        raise AuthenticationDenied from None


def _audience_matches(values: list[object], expected: str) -> bool:
    matched = False
    for value in values:
        if type(value) is not str or not _claim_string(value, 512):
            return False
        if hmac.compare_digest(value, expected):
            matched = True
    return matched


def _decode_segment(value: str, maximum: int) -> bytes:
    if (
        not value
        or len(value) > maximum * 2
        or _BASE64URL.fullmatch(value) is None
        or len(value) % 4 == 1
    ):
        raise AuthenticationDenied
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError):
        raise AuthenticationDenied from None
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if len(decoded) > maximum or not hmac.compare_digest(canonical, value):
        raise AuthenticationDenied
    return decoded


def _json_object(value: bytes) -> dict[str, object]:
    try:
        parsed: object = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, AuthenticationDenied, RecursionError):
        raise AuthenticationDenied from None
    if type(parsed) is not dict:
        raise AuthenticationDenied
    return cast(dict[str, object], parsed)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise AuthenticationDenied
        output[key] = value
    return output


def _reject_constant(value: str) -> object:
    raise AuthenticationDenied


def _numeric_date(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 253_402_300_799:
        raise AuthenticationDenied
    return value


OidcBearerIdentityVerifier = BearerJwtIdentityVerifier
JwtIdentityVerifier = BearerJwtIdentityVerifier

__all__ = [
    "AuthenticationDenied",
    "BearerJwtIdentityVerifier",
    "CompositeIdentityVerifier",
    "HmacSha256SignatureVerifier",
    "IdentityClaimMapping",
    "JwtIdentityVerifier",
    "JwtKeyResolver",
    "JwtSignatureVerifier",
    "JwtVerificationPolicy",
    "OidcBearerIdentityVerifier",
    "PinnedKeyResolver",
    "RsaPublicKey",
    "RsaSha256SignatureVerifier",
]
