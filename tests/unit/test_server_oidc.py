from __future__ import annotations

import pytest
from securecode_ai.server.identity import Role
from securecode_ai.server.oidc import (
    OidcAdmission,
    OidcDenied,
    OidcPolicy,
    SubjectBinding,
    TenantState,
)


class V:
    def verify(self, token: str) -> dict[str, object] | None:
        return {
            "alg": "RS256",
            "iss": "issuer",
            "sub": "user",
            "aud": "app",
            "azp": "client",
            "nonce": "n",
            "iat": 1,
            "exp": 9999999999,
            "groups": ["auditors"],
        }


def test_oidc_allowlisted_binding_only() -> None:
    admission = OidcAdmission(
        V(),
        OidcPolicy("issuer", "app", frozenset({"client"}), {"auditors": Role.AUDITOR}),
        (SubjectBinding("issuer", "user", "tenant", TenantState.ACTIVE, frozenset({"repo"})),),
        now=lambda: 2,
    )
    principal, receipt = admission.admit("a.b.c", nonce="n")
    assert principal.tenant_id == "tenant" and "a.b.c" not in repr(receipt)


def test_unsigned_is_denied() -> None:
    class U:
        def verify(self, token: str) -> dict[str, object] | None:
            return {"alg": "none"}

    with pytest.raises(OidcDenied):
        OidcAdmission(U(), OidcPolicy("i", "a", frozenset(), {}), (), now=lambda: 1).admit(
            "a.b.c",
            nonce="n",
        )
