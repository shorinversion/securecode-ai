from securecode_ai.server.secret_provider import OpaqueSecretLease
from securecode_ai.server.secret_service import SecretService


class P:
    def issue(self, reference: str, *, purpose: str, grant_id: str) -> OpaqueSecretLease:
        return OpaqueSecretLease("secret", 1)

    def rotate(
        self,
        reference: str,
        *,
        purpose: str,
        previous_grant_id: str,
        grant_id: str,
    ) -> OpaqueSecretLease:
        return OpaqueSecretLease("secret", 1)

    def revoke(self, grant_id: str) -> None:
        return None


def test_handle_never_in_receipt() -> None:
    grant, receipt = SecretService(P()).grant(
        tenant_id="t", workload_id="w", reference="r", purpose="provider_api", idempotency_key="k"
    )
    assert "secret" not in repr(grant) and "secret" not in repr(receipt)
