"""Repository scope extraction at the authenticated HTTP boundary."""

from __future__ import annotations

from collections.abc import Mapping


def repository_id(
    document: Mapping[str, object] | None,
    query: Mapping[str, tuple[str, ...]],
) -> str | None:
    if document is not None:
        direct = document.get("repository_id")
        if isinstance(direct, str) and direct:
            return direct
        identity = document.get("execution_identity")
        if isinstance(identity, dict):
            revision = identity.get("repository_revision")
            if isinstance(revision, dict):
                value = revision.get("repository_id")
                return value if isinstance(value, str) and value else None
    values = query.get("repository_id")
    if values is not None and len(values) == 1 and values[0]:
        return values[0]
    return None


__all__ = ["repository_id"]
