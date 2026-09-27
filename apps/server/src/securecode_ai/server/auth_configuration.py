"""Build an offline OIDC verifier from protected server-owned files."""

from __future__ import annotations

import base64
import binascii
import hmac
import sqlite3
from collections.abc import Callable, Mapping
from pathlib import Path

from .auth_runtime import (
    BearerJwtIdentityVerifier,
    HmacSha256SignatureVerifier,
    IdentityClaimMapping,
    JwtSignatureVerifier,
    JwtVerificationPolicy,
    PinnedKeyResolver,
    RsaPublicKey,
    RsaSha256SignatureVerifier,
)
from .identity import Principal, Role
from .oidc import OidcAdmission, OidcDenied, OidcPolicy, OidcReceipt, SubjectBinding, TenantState
from .oidc_login import (
    OidcAuthorizationClient,
    OidcLoginError,
    OidcLoginService,
    OidcSourceRateLimitPort,
)
from .oidc_sessions import NonceReplayLedger, OpaqueSessionIssuer, SqliteOidcLoginState
from .secure_files import read_json_object, read_secret_bytes
from .sessions import SessionStore


def build_oidc_verifier(
    values: Mapping[str, str],
) -> BearerJwtIdentityVerifier | None:
    config_path = values.get("SECURECODE_OIDC_CONFIG_FILE")
    key_path = values.get("SECURECODE_OIDC_KEY_FILE")
    if config_path is None and key_path is None:
        return None
    if not config_path or not key_path:
        raise ValueError("OIDC configuration is incomplete")
    document = read_json_object(Path(config_path), 65_536)
    allowed = {
        "issuer",
        "audience",
        "algorithm",
        "key_id",
        "clock_skew_seconds",
        "max_token_lifetime_seconds",
        "authorized_party",
        "role_map",
        "tenant_map",
        "subject_map",
        "repository_id_map",
        "allowed_roles",
        "workload_roles",
        "tenant_claim",
        "subject_claim",
        "roles_claim",
        "workload_claim",
        "repository_ids_claim",
        "login_role_groups",
        "login_subject_bindings",
        "authorization_endpoint",
        "client_id",
        "redirect_uri",
        "login_scope",
        "login_attempt_limit",
        "login_attempt_window_seconds",
    }
    if set(document) - allowed:
        raise ValueError("OIDC configuration is invalid")
    issuer = _string(document, "issuer")
    audience = _string(document, "audience")
    algorithm = _string(document, "algorithm")
    key_id = _string(document, "key_id")
    policy = JwtVerificationPolicy(
        issuer=issuer,
        audience=audience,
        algorithm=algorithm,
        key_id=key_id,
        clock_skew_seconds=_integer(document, "clock_skew_seconds", 30),
        max_token_lifetime_seconds=_optional_integer(
            document,
            "max_token_lifetime_seconds",
        ),
        authorized_party=_optional_string(document, "authorized_party"),
    )
    tenant_map = _string_map(document, "tenant_map")
    subject_map = _string_map(document, "subject_map")
    # A canonical subject must have exactly one external source.  Otherwise a
    # reloaded session binding could match an unrelated issuer subject after a
    # configuration rotation, making revocation depend on map iteration order.
    if len(subject_map) != len(set(subject_map.values())):
        raise ValueError("OIDC subject mapping is ambiguous")
    mapping = IdentityClaimMapping(
        role_map=_string_map(document, "role_map"),
        tenant_claim=_string(document, "tenant_claim", "tenant_id"),
        subject_claim=_string(document, "subject_claim", "sub"),
        roles_claim=_string(document, "roles_claim", "roles"),
        workload_claim=_string(document, "workload_claim", "workload"),
        repository_ids_claim=_string(
            document,
            "repository_ids_claim",
            "repository_ids",
        ),
        # OIDC is an external trust boundary.  A signed issuer claim is not
        # enough to establish the server's tenant or subject namespace: both
        # must be explicitly admitted by the server-owned mapping.  Keeping
        # these mappings mandatory here also makes unknown subjects and
        # tenants fail closed before they can reach RoleAuthorization.
        tenant_map=tenant_map,
        subject_map=subject_map,
        repository_id_map=_optional_string_map(document, "repository_id_map"),
        allowed_roles=frozenset(_string_list(document, "allowed_roles", required=False)),
        workload_roles=frozenset(_string_list(document, "workload_roles", required=False)),
    )
    if not mapping.allowed_roles or not mapping.workload_roles:
        raise ValueError("OIDC role mapping is invalid")
    if algorithm == "HS256":
        key: object = read_secret_bytes(Path(key_path), minimum=32, maximum=4096)
        signature_verifier: JwtSignatureVerifier = HmacSha256SignatureVerifier()
    elif algorithm == "RS256":
        key = _rsa_key(Path(key_path), key_id)
        signature_verifier = RsaSha256SignatureVerifier()
    else:
        raise ValueError("OIDC algorithm is unsupported")
    return BearerJwtIdentityVerifier(
        policy=policy,
        mapping=mapping,
        key_resolver=PinnedKeyResolver(
            issuer=issuer,
            algorithm=algorithm,
            key_id=key_id,
            key=key,
        ),
        signature_verifier=signature_verifier,
    )


def build_oidc_login_service(
    values: Mapping[str, str],
    verifier: BearerJwtIdentityVerifier | None,
    sessions: SessionStore,
    *,
    verifier_loader: Callable[[], BearerJwtIdentityVerifier | None] | None = None,
    connection: sqlite3.Connection | None = None,
    source_rate_limiter: OidcSourceRateLimitPort | None = None,
) -> OidcLoginService | None:
    """Enable interactive login only with explicit group and subject bindings."""

    config_path = values.get("SECURECODE_OIDC_CONFIG_FILE")
    if verifier is None or config_path is None:
        return None
    loader = verifier_loader or (lambda: verifier)
    if _build_oidc_admission(values, verifier) is None:
        return None
    authorization_client = _build_oidc_authorization_client(values)
    if (
        authorization_client is None
        or verifier.policy.authorized_party != authorization_client.client_id
    ):
        raise ValueError("OIDC authorization client configuration is required")
    login_attempt_limit, login_attempt_window = _oidc_login_limits(config_path)

    def authorization_client_loader() -> OidcAuthorizationClient:
        current_verifier = loader()
        current_client = _build_oidc_authorization_client(values)
        if (
            current_verifier is None
            or current_client is None
            or current_verifier.policy.authorized_party != current_client.client_id
        ):
            raise ValueError("OIDC authorization client configuration is invalid")
        return current_client

    return OidcLoginService(
        admission=_ReloadingOidcAdmission(values, loader),
        ledger=NonceReplayLedger(connection=connection),
        issuer=OpaqueSessionIssuer(sessions),
        state_store=None if connection is None else SqliteOidcLoginState(connection),
        source_rate_limiter=source_rate_limiter,
        authorization_client_loader=authorization_client_loader,
        attempt_policy_loader=lambda: _oidc_login_limits(config_path),
        attempt_limit=login_attempt_limit,
        attempt_window_seconds=login_attempt_window,
    )


def active_oidc_session_principal(
    values: Mapping[str, str],
    principal: Principal,
) -> bool | None:
    """Fail closed when a stored session's tenant binding was suspended or removed."""

    if type(principal) is not Principal:
        return False
    try:
        verifier = build_oidc_verifier(values)
        if verifier is None:
            return None
        admission = _build_oidc_admission(values, verifier)
        return admission is not None and admission.active_subject(
            subject_id=principal.subject_id,
            tenant_id=principal.tenant_id,
            roles=principal.roles,
            repository_grants=principal.repository_grants,
        )
    except Exception:
        return None


def _build_oidc_admission(
    values: Mapping[str, str],
    verifier: BearerJwtIdentityVerifier,
) -> OidcAdmission | None:
    config_path = values.get("SECURECODE_OIDC_CONFIG_FILE")
    if config_path is None:
        return None
    document = read_json_object(Path(config_path), 65_536)
    groups_value = document.get("login_role_groups")
    bindings_value = document.get("login_subject_bindings")
    if groups_value is None and bindings_value is None:
        return None
    if (
        not isinstance(groups_value, dict)
        or not groups_value
        or len(groups_value) > 128
        or type(bindings_value) is not list
        or not 1 <= len(bindings_value) <= 10_000
    ):
        raise ValueError("OIDC login configuration is invalid")
    role_groups: dict[str, Role] = {}
    for group, role_name in groups_value.items():
        if type(group) is not str or type(role_name) is not str:
            raise ValueError("OIDC login configuration is invalid")
        try:
            role = Role(role_name)
        except ValueError:
            raise ValueError("OIDC login configuration is invalid") from None
        if (
            role is Role.WORKER
            or role.value not in verifier.allowed_roles
            or not 1 <= len(group) <= 128
        ):
            raise ValueError("OIDC login configuration is invalid")
        role_groups[group] = role
    subject_bindings: list[SubjectBinding] = []
    for binding in bindings_value:
        if type(binding) is not dict or set(binding) != {
            "subject",
            "tenant_id",
            "state",
            "grants",
        }:
            raise ValueError("OIDC login configuration is invalid")
        subject = binding.get("subject")
        tenant_id = binding.get("tenant_id")
        grants = binding.get("grants")
        state_value = binding.get("state")
        if (
            type(subject) is not str
            or not 1 <= len(subject) <= 256
            or type(tenant_id) is not str
            or not 1 <= len(tenant_id) <= 256
            or type(grants) is not list
            or len(grants) > 128
            or not all(type(grant) is str and 1 <= len(grant) <= 256 for grant in grants)
            or len(grants) != len(set(grants))
            or type(state_value) is not str
        ):
            raise ValueError("OIDC login configuration is invalid")
        try:
            state = TenantState(state_value)
        except ValueError:
            raise ValueError("OIDC login configuration is invalid") from None
        subject_bindings.append(
            SubjectBinding(
                issuer=verifier.policy.issuer,
                subject=subject,
                tenant_id=tenant_id,
                state=state,
                grants=frozenset(grants),
            )
        )
    configured_subjects = verifier.subject_map
    if any(binding.subject not in configured_subjects for binding in subject_bindings):
        raise ValueError("OIDC login subject binding is not mapped")
    configured_tenants = verifier.tenant_map
    configured_tenant_values = frozenset(configured_tenants.values())
    if any(binding.tenant_id not in configured_tenant_values for binding in subject_bindings):
        raise ValueError("OIDC login tenant binding is not mapped")
    authorized_party = verifier.policy.authorized_party
    if authorized_party is None:
        raise ValueError("OIDC login authorized party is missing")
    admission = OidcAdmission(
        _VerifiedJwtClaims(verifier),
        OidcPolicy(
            issuer=verifier.policy.issuer,
            audience=verifier.policy.audience,
            allowed_azp=frozenset({authorized_party}),
            role_groups=role_groups,
            subject_map=verifier.subject_map,
            tenant_claim=verifier.tenant_claim,
            tenant_map=verifier.tenant_map,
            roles_claim=verifier.roles_claim,
            subject_claim=verifier.subject_claim,
        ),
        tuple(subject_bindings),
    )
    return admission


def _build_oidc_authorization_client(
    values: Mapping[str, str],
) -> OidcAuthorizationClient | None:
    config_path = values.get("SECURECODE_OIDC_CONFIG_FILE")
    if config_path is None:
        return None
    document = read_json_object(Path(config_path), 65_536)
    endpoint = document.get("authorization_endpoint")
    client_id = document.get("client_id")
    redirect_uri = document.get("redirect_uri")
    scope = document.get("login_scope", "openid profile email")
    if (
        type(endpoint) is not str
        or not endpoint
        or type(client_id) is not str
        or not client_id
        or type(redirect_uri) is not str
        or not redirect_uri
        or type(scope) is not str
        or not scope
    ):
        raise ValueError("OIDC authorization client configuration is invalid")
    try:
        return OidcAuthorizationClient(
            authorization_endpoint=endpoint,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
        )
    except (OidcLoginError, TypeError, ValueError):
        raise ValueError("OIDC authorization client configuration is invalid") from None


def _oidc_login_limits(config_path: str) -> tuple[int, int]:
    document = read_json_object(Path(config_path), 65_536)
    attempt_limit = _integer(document, "login_attempt_limit", 60)
    attempt_window = _integer(document, "login_attempt_window_seconds", 60)
    if not 1 <= attempt_limit <= 100_000 or not 1 <= attempt_window <= 3600:
        raise ValueError("OIDC login limits are invalid")
    return attempt_limit, attempt_window


class _ReloadingOidcAdmission:
    __slots__ = ("_values", "_verifier_loader")

    def __init__(
        self,
        values: Mapping[str, str],
        verifier_loader: Callable[[], BearerJwtIdentityVerifier | None],
    ) -> None:
        self._values = values
        self._verifier_loader = verifier_loader

    def admit(self, token: str, *, nonce: str) -> tuple[Principal, OidcReceipt]:
        try:
            verifier = self._verifier_loader()
            if verifier is None:
                raise OidcDenied()
            admission = _build_oidc_admission(self._values, verifier)
            if admission is None:
                raise OidcDenied()
            return admission.admit(token, nonce=nonce)
        except Exception:
            raise OidcDenied() from None


class _VerifiedJwtClaims:
    __slots__ = ("_verifier",)

    def __init__(self, verifier: BearerJwtIdentityVerifier) -> None:
        self._verifier = verifier

    def verify(self, token: str) -> dict[str, object] | None:
        try:
            claims = self._verifier.verify_claims(token)
        except Exception:
            return None
        if claims is None:
            return None
        return claims


def _rsa_key(path: Path, key_id: str) -> RsaPublicKey:
    document = read_json_object(path, 16_384)
    if set(document) - {"kty", "kid", "alg", "use", "n", "e"}:
        raise ValueError("OIDC RSA key is invalid")
    if (
        document.get("kty") != "RSA"
        or document.get("alg") not in {None, "RS256"}
        or document.get("use") not in {None, "sig"}
        or type(document.get("kid")) is not str
        or not hmac.compare_digest(str(document["kid"]), key_id)
    ):
        raise ValueError("OIDC RSA key is invalid")
    modulus = _base64url_integer(document.get("n"))
    exponent = _base64url_integer(document.get("e"))
    return RsaPublicKey(modulus=modulus, exponent=exponent)


def _base64url_integer(value: object) -> int:
    if type(value) is not str or not value or len(value) > 2048 or len(value) % 4 == 1:
        raise ValueError("OIDC RSA key is invalid")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError):
        raise ValueError("OIDC RSA key is invalid") from None
    if not raw or raw[0] == 0 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError("OIDC RSA key is invalid")
    return int.from_bytes(raw, "big")


def _string(document: Mapping[str, object], name: str, default: str | None = None) -> str:
    value = document.get(name, default)
    if type(value) is not str or not value:
        raise ValueError("OIDC configuration is invalid")
    return value


def _optional_string(document: Mapping[str, object], name: str) -> str | None:
    value = document.get(name)
    if value is None:
        return None
    if type(value) is not str or not value:
        raise ValueError("OIDC configuration is invalid")
    return value


def _integer(document: Mapping[str, object], name: str, default: int) -> int:
    value = document.get(name, default)
    if type(value) is not int:
        raise ValueError("OIDC configuration is invalid")
    return value


def _optional_integer(document: Mapping[str, object], name: str) -> int | None:
    value = document.get(name)
    if value is not None and type(value) is not int:
        raise ValueError("OIDC configuration is invalid")
    return value


def _string_map(document: Mapping[str, object], name: str) -> dict[str, str]:
    value = document.get(name)
    if not isinstance(value, dict) or not value:
        raise ValueError("OIDC configuration is invalid")
    if not all(type(key) is str and type(item) is str for key, item in value.items()):
        raise ValueError("OIDC configuration is invalid")
    return dict(value)


def _optional_string_map(
    document: Mapping[str, object],
    name: str,
) -> dict[str, str] | None:
    if document.get(name) is None:
        return None
    return _string_map(document, name)


def _string_list(
    document: Mapping[str, object],
    name: str,
    *,
    required: bool,
) -> tuple[str, ...]:
    value = document.get(name)
    if value is None and not required:
        defaults = ("viewer", "auditor", "approver", "admin", "worker", "scm")
        return ("worker", "scm") if name == "workload_roles" else defaults
    if not isinstance(value, list) or not value or not all(type(item) is str for item in value):
        raise ValueError("OIDC configuration is invalid")
    return tuple(value)


__all__ = [
    "active_oidc_session_principal",
    "build_oidc_login_service",
    "build_oidc_verifier",
]
