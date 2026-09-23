from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import cast

import pytest
from securecode_ai.server.auth_runtime import (
    AuthenticationDenied,
    BearerJwtIdentityVerifier,
    HmacSha256SignatureVerifier,
    IdentityClaimMapping,
    JwtVerificationPolicy,
    PinnedKeyResolver,
)

_KEY = bytes(range(32))


def _verifier() -> BearerJwtIdentityVerifier:
    policy = JwtVerificationPolicy(
        issuer="https://idp.example.invalid",
        audience="securecode-api",
        algorithm="HS256",
        key_id="key-1",
        clock_skew_seconds=0,
        max_token_lifetime_seconds=120,
        authorized_party="securecode-client",
    )
    mapping = IdentityClaimMapping(
        role_map={
            "read-only": "viewer",
            "reviewer": "auditor",
            "approver": "approver",
            "tenant-admin": "admin",
            "background-worker": "worker",
            "scm-integration": "scm",
        },
        tenant_map={"org-acme": "tenant-acme"},
        subject_map={"person-7": "user-7"},
        repository_id_map={"project-22": "repo-22"},
    )
    resolver = PinnedKeyResolver(
        issuer=policy.issuer,
        algorithm=policy.algorithm,
        key_id=policy.key_id,
        key=_KEY,
    )
    return BearerJwtIdentityVerifier(
        policy=policy,
        mapping=mapping,
        key_resolver=resolver,
        signature_verifier=HmacSha256SignatureVerifier(),
        clock=lambda: 1_000,
    )


def _segment(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(encoded).decode().rstrip("=")


def _signed_document(overrides: dict[str, object] | None = None) -> str:
    header = {"alg": "HS256", "kid": "key-1", "typ": "JWT"}
    claims: dict[str, object] = {
        "iss": "https://idp.example.invalid",
        "aud": ["another-api", "securecode-api"],
        "azp": "securecode-client",
        "sub": "person-7",
        "tenant_id": "org-acme",
        "roles": ["reviewer"],
        "workload": False,
        "repository_ids": ["project-22"],
        "iat": 990,
        "exp": 1_050,
    }
    if overrides is not None:
        claims.update(overrides)
    signing_input = f"{_segment(header)}.{_segment(claims)}"
    signature = hmac.new(_KEY, signing_input.encode("ascii"), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{signing_input}.{encoded_signature}"


def test_valid_oidc_identity_maps_tenant_subject_roles_and_repositories() -> None:
    identity = _verifier().verify_bearer(_signed_document())

    assert identity is not None
    assert identity.tenant_id == "tenant-acme"
    assert identity.subject_id == "user-7"
    assert identity.roles == frozenset({"auditor"})
    assert identity.repository_ids == frozenset({"repo-22"})
    assert not identity.workload


@pytest.mark.parametrize(
    "claims",
    (
        {"roles": ["tenant-admin", "read-only"], "workload": True},
        {"roles": ["background-worker"], "workload": False},
        {"roles": ["read-only"], "workload": True},
        {"roles": ["unknown-group"]},
        {"tenant_id": "org-other"},
        {"repository_ids": ["project-22", "project-22"]},
        {"sub": "person-8"},
        {"azp": "different-client"},
        {"aud": ["another-api"]},
        {"exp": 999},
        {"iat": 1_051},
    ),
)
def test_oidc_rejects_privilege_or_scope_escalation(claims: dict[str, object]) -> None:
    assert _verifier().verify_bearer(_signed_document(claims)) is None


def test_oidc_rejects_untrusted_algorithm_even_with_valid_signature() -> None:
    verifier = _verifier()
    token = _signed_document()
    _header_part, claims_part, signature_part = token.split(".")
    forged_header = _segment({"alg": "none", "kid": "key-1", "typ": "JWT"})
    assert verifier.verify_bearer(f"{forged_header}.{claims_part}.{signature_part}") is None


def test_verifier_direct_validation_error_is_closed() -> None:
    verifier = _verifier()
    with pytest.raises(AuthenticationDenied):
        verifier._verify_bearer("not-a-compact-token")


def test_claim_mapping_snapshots_external_configuration() -> None:
    roles = {"reviewer": "auditor"}
    mapping = IdentityClaimMapping(role_map=roles)
    roles["reviewer"] = "admin"

    assert mapping.role_map["reviewer"] == "auditor"
    with pytest.raises(TypeError):
        cast(dict[str, str], mapping.role_map)["reviewer"] = "admin"
