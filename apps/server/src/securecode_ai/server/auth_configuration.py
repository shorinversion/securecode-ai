"""Build an offline OIDC verifier from protected server-owned files."""

from __future__ import annotations

import base64
import binascii
import hmac
from collections.abc import Mapping
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
from .secure_files import read_json_object, read_secret_bytes


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
        tenant_map=_optional_string_map(document, "tenant_map"),
        subject_map=_optional_string_map(document, "subject_map"),
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


__all__ = ["build_oidc_verifier"]
