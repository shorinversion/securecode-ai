import pytest
from securecode_ai.server.secret_provider import OpaqueSecretLease
from securecode_ai.server.secret_service import SecretDenied, SecretService


class P:
    def issue(self, reference: str, *, purpose: str, grant_id: str) -> OpaqueSecretLease:
        return OpaqueSecretLease("secret", 100)

    def rotate(
        self,
        reference: str,
        *,
        purpose: str,
        previous_grant_id: str,
        grant_id: str,
    ) -> OpaqueSecretLease:
        return OpaqueSecretLease("secret", 100)

    def revoke(self, grant_id: str) -> None:
        return None


def test_handle_never_in_receipt() -> None:
    grant, receipt = SecretService(P(), clock=lambda: 1).grant(
        tenant_id="t", workload_id="w", reference="r", purpose="provider_api", idempotency_key="k"
    )
    assert "secret" not in repr(grant) and "secret" not in repr(receipt)


class ExpiredProvider(P):
    def issue(self, reference: str, *, purpose: str, grant_id: str) -> OpaqueSecretLease:
        return OpaqueSecretLease("expired", 1)


def test_expired_provider_lease_is_revoked_and_not_persisted() -> None:
    provider = ExpiredProvider()

    with pytest.raises(SecretDenied, match="EXPIRED_PROVIDER_LEASE"):
        SecretService(provider, clock=lambda: 1).grant(
            tenant_id="t",
            workload_id="w",
            reference="r",
            purpose="provider_api",
            idempotency_key="k",
        )
