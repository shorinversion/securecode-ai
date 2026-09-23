"""Tenant-bound principals and least-privilege authorization rules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


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
            "runs.events.read",
            "runs.findings.read",
            "findings.read",
            "findings.evidence.read",
            "policies.read",
        }
    ),
    Role.AUDITOR: frozenset(
        {"runs.create", "runs.cancel", "findings.decide", "artifacts.authorize"}
    ),
    Role.APPROVER: frozenset({"findings.decide", "policies.read"}),
    Role.ADMIN: frozenset({"*"}),
    Role.WORKER: frozenset(
        {
            "worker_sessions.create",
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
        if not action or not self.roles:
            return False
        if (
            repository_id is not None
            and repository_id not in self.repository_grants
            and Role.ADMIN not in self.roles
        ):
            return False
        return any("*" in _ALLOW[role] or action in _ALLOW[role] for role in self.roles)
