"""Tenant-bound principals and least-privilege authorization rules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


_MAX_ID_LENGTH = 256
_MAX_ACTION_LENGTH = 128


class Role(StrEnum):
    VIEWER = "viewer"
    AUDITOR = "auditor"
    APPROVER = "approver"
    ADMIN = "admin"
    WORKER = "worker"


_ALLOW = {
    Role.VIEWER: frozenset(
        {
            "runs.read",
            "runs.list",
            "runs.events.read",
            "runs.findings.read",
            "findings.read",
            "findings.evidence.read",
            "policies.read",
            "waivers.read",
        }
    ),
    Role.AUDITOR: frozenset(
        {
            "runs.create",
            "runs.cancel",
            "findings.decide",
            "artifacts.authorize",
            "waivers.read",
        }
    ),
    Role.APPROVER: frozenset(
        {
            "findings.decide",
            "policies.read",
            "waivers.create",
            "waivers.read",
            "waivers.revoke",
        }
    ),
    Role.ADMIN: frozenset({"*"}),
    Role.WORKER: frozenset(
        {
            "worker_sessions.create",
            "worker_sessions.osv.query",
            "worker_sessions.heartbeat",
            "worker_sessions.events.append",
            "worker_sessions.artifacts.commit",
            "worker_sessions.complete",
        }
    ),
}


@dataclass(frozen=True, slots=True)
class Principal:
    subject_id: str
    tenant_id: str
    roles: frozenset[Role]
    repository_grants: frozenset[str] = frozenset()

    def allows(self, *, action: str, repository_id: str | None) -> bool:
        # Principal instances can be reconstructed from external identity
        # state, so do not let an unknown role turn authorization into an
        # exception.  Malformed principals must fail closed.
        if (
            type(self.subject_id) is not str
            or not _safe_identifier(self.subject_id)
            or not _safe_identifier(self.tenant_id)
            or not _safe_identifier(action, _MAX_ACTION_LENGTH)
            or type(self.roles) is not frozenset
            or not self.roles
            or not all(type(role) is Role for role in self.roles)
            or type(self.repository_grants) is not frozenset
            or any(not _safe_identifier(grant) for grant in self.repository_grants)
            or (
                repository_id is not None
                and not _safe_identifier(repository_id)
            )
        ):
            return False
        if (
            repository_id is not None
            and repository_id not in self.repository_grants
            and Role.ADMIN not in self.roles
        ):
            return False
        return any("*" in _ALLOW[role] or action in _ALLOW[role] for role in self.roles)


def _safe_identifier(value: object, maximum: int = _MAX_ID_LENGTH) -> bool:
    """Keep externally reconstructed identity fields bounded and log-safe."""

    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        return False
    try:
        return len(value.encode("utf-8")) <= maximum * 4
    except UnicodeEncodeError:
        return False
