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

    def retrieve(self, grant_id: str) -> OpaqueSecretLease:
        raise AssertionError("retrieve is not exercised by these tests")

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


class ExpiredRotationProvider(P):
    def __init__(self) -> None:
        self.revoked: list[str] = []

    def rotate(
        self,
        reference: str,
        *,
        purpose: str,
        previous_grant_id: str,
        grant_id: str,
    ) -> OpaqueSecretLease:
        return OpaqueSecretLease("expired-replacement", 1)

    def revoke(self, grant_id: str) -> None:
        self.revoked.append(grant_id)


def test_expired_rotation_lease_preserves_the_previous_active_grant() -> None:
    provider = ExpiredRotationProvider()
    service = SecretService(provider, clock=lambda: 1)
    grant, _ = service.grant(
        tenant_id="t",
        workload_id="w",
        reference="r",
        purpose="provider_api",
        idempotency_key="initial",
    )
    assert grant is not None

    with pytest.raises(SecretDenied, match="EXPIRED_PROVIDER_LEASE"):
        service.rotate(
            tenant_id="t",
            workload_id="w",
            reference="r",
            purpose="provider_api",
            previous_grant_id=grant.grant_id,
            expected_version=1,
            idempotency_key="rotate",
        )

    assert service.receipt(tenant_id="t", grant_id=grant.grant_id).state == "ACTIVE"
    assert len(provider.revoked) == 1
