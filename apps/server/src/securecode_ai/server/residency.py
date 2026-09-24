"""Tenant residency allowlists where cross-region transfer is denied by default."""

from __future__ import annotations

import re
from dataclasses import dataclass

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_REGION = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")


class ResidencyDenied(Exception):
    """Requested storage or transfer violates the tenant residency profile."""


@dataclass(frozen=True, slots=True)
class ResidencyProfile:
    tenant_id: str
    allowed_regions: frozenset[str]

    def __post_init__(self) -> None:
        if (
            type(self.tenant_id) is not str
            or _ID.fullmatch(self.tenant_id) is None
            or type(self.allowed_regions) is not frozenset
            or not self.allowed_regions
            or any(
                type(region) is not str or _REGION.fullmatch(region) is None
                for region in self.allowed_regions
            )
        ):
            raise ValueError("residency profile is invalid")

    def allows(self, region: str) -> bool:
        return type(region) is str and region in self.allowed_regions


def require_transfer(
    profile: ResidencyProfile,
    *,
    source_region: str,
    destination_region: str,
) -> None:
    if type(profile) is not ResidencyProfile:
        raise ResidencyDenied()
    # An allowlist identifies regions in which data may reside.  It is not
    # consent to move data between two allowed regions.  Cross-region moves
    # need a separate, audited policy decision and therefore remain denied by
    # this default enforcement path.
    if source_region != destination_region:
        raise ResidencyDenied()
    if not profile.allows(source_region) or not profile.allows(destination_region):
        raise ResidencyDenied()


__all__ = ["ResidencyDenied", "ResidencyProfile", "require_transfer"]
