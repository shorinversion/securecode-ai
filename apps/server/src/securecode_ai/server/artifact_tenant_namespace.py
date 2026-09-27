"""Stable filesystem components for contract-valid artifact tenant identifiers."""

from __future__ import annotations

import base64
import re
from typing import Final

_OPAQUE_TENANT: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ENCODED_PREFIX: Final = "tenant."


class ArtifactTenantNamespaceError(ValueError):
    """A tenant identifier cannot be represented in an artifact namespace."""


def artifact_tenant_path_component(tenant_id: str) -> str:
    """Return the stable local directory name for one valid ``OpaqueId`` tenant.

    Encode every tenant identifier into a lower-case, separator-free component.
    Base32 is used instead of a case-preserving alphabet because Windows
    artifact roots are commonly case-insensitive. The encoding is injective,
    so distinct contract-valid tenant IDs cannot share a local directory even
    when the store is moved between Windows and POSIX hosts.
    """

    if type(tenant_id) is not str or _OPAQUE_TENANT.fullmatch(tenant_id) is None:
        raise ArtifactTenantNamespaceError("tenant identifier is invalid")
    encoded = base64.b32encode(tenant_id.encode("ascii")).decode("ascii").lower()
    return _ENCODED_PREFIX + encoded.rstrip("=")


__all__ = ["ArtifactTenantNamespaceError", "artifact_tenant_path_component"]
