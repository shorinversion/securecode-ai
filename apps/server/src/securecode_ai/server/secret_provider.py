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
    """External secret manager that issues and revokes opaque leases."""

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

    def revoke(self, grant_id: str) -> None: ...


__all__ = ["OpaqueSecretLease", "SecretProvider"]
