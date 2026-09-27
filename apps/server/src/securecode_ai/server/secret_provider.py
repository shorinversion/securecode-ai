"""Secret-manager boundary used by the control plane."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True, repr=False)
class OpaqueSecretLease:
    """An ephemeral provider lease. Its handle must never enter durable state."""

    handle: str
    expires_at: int

    def __post_init__(self) -> None:
        if type(self.handle) is not str or not self.handle or len(self.handle) > 8192:
            raise ValueError("secret provider returned an invalid handle")
        if type(self.expires_at) is not int or self.expires_at < 1:
            raise ValueError("secret provider returned an invalid expiry")

    def __repr__(self) -> str:
        return "OpaqueSecretLease(<redacted>)"


class SecretProvider(Protocol):
    """External secret manager that issues, retrieves, and revokes opaque leases.

    ``rotate`` issues a replacement lease but leaves the previous grant live.
    The service revokes the previous grant only after its replacement is durable.
    ``revoke`` must be idempotent because service retries can follow a provider
    success whose database acknowledgement was interrupted.
    """

    def issue(
        self,
        reference: str,
        *,
        purpose: str,
        grant_id: str,
    ) -> OpaqueSecretLease: ...

    def rotate(
        self,
        reference: str,
        *,
        purpose: str,
        previous_grant_id: str,
        grant_id: str,
    ) -> OpaqueSecretLease: ...

    def retrieve(self, grant_id: str) -> OpaqueSecretLease: ...

    def revoke(self, grant_id: str) -> None: ...


__all__ = ["OpaqueSecretLease", "SecretProvider"]
