"""Validated models and schema for durable data lifecycle controls."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Protocol

_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
DATA_CLASSES: Final = frozenset({"metadata", "artifact", "audit"})


class LifecycleConflict(RuntimeError):
    """A lifecycle request is invalid, stale, cross-tenant or contradictory."""


@dataclass(frozen=True, slots=True)
class RetentionProfile:
    tenant_id: str
    metadata_days: int
    artifact_days: int
    audit_days: int

    def __post_init__(self) -> None:
        require_identifier(self.tenant_id, "tenant_id")
        for value in (self.metadata_days, self.artifact_days, self.audit_days):
            if type(value) is not int or value < 0 or value > 36500:
                raise LifecycleConflict("retention period is invalid")


@dataclass(frozen=True, slots=True)
class DeletionRequest:
    deletion_id: str
    tenant_id: str
    content_sha256: str
    data_class: str
    identity_hash: str
    requested_by: str
    version: int
    approved_by: str | None = None
    executed: bool = False
    legal_hold: bool = False

    def __post_init__(self) -> None:
        require_identifier(self.deletion_id, "deletion_id")
        require_identifier(self.tenant_id, "tenant_id")
        require_identifier(self.requested_by, "requested_by")
        if self.approved_by is not None:
            require_identifier(self.approved_by, "approved_by")
        require_sha256(self.content_sha256, "content_sha256")
        require_sha256(self.identity_hash, "identity_hash")
        if self.data_class not in DATA_CLASSES:
            raise LifecycleConflict("data_class is invalid")
        if type(self.version) is not int or self.version < 1:
            raise LifecycleConflict("version is invalid")
        if type(self.executed) is not bool or type(self.legal_hold) is not bool:
            raise LifecycleConflict("lifecycle flags are invalid")


@dataclass(frozen=True, slots=True)
class DeletionReceipt:
    """Source-free proof of a durable deletion-control transition."""

    deletion_id: str
    tenant_id: str
    content_sha256: str
    identity_hash: str
    state: str
    version: int
    occurred_at: str
    actor_id_hash: str


class StorageExecutor(Protocol):
    """Idempotent storage boundary used to apply an approved tombstone."""

    def execute_tombstone(
        self,
        *,
        tenant_id: str,
        content_sha256: str,
        deletion_id: str,
        repository_id: str,
        identity_hash: str,
    ) -> None: ...


LIFECYCLE_SCHEMA: Final = (
    """CREATE TABLE IF NOT EXISTS lifecycle_deletions (
        deletion_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        content_sha256 TEXT NOT NULL,
        data_class TEXT NOT NULL,
        identity_hash TEXT NOT NULL,
        requested_by TEXT NOT NULL,
        version INTEGER NOT NULL,
        approved_by TEXT,
        executed INTEGER NOT NULL,
        legal_hold INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        approved_at TEXT,
        executed_at TEXT,
        hold_actor TEXT,
        hold_reason_sha256 TEXT,
        PRIMARY KEY (tenant_id, deletion_id),
        UNIQUE (tenant_id, content_sha256, identity_hash)
    )""",
    """CREATE INDEX IF NOT EXISTS lifecycle_deletions_tenant_idx
       ON lifecycle_deletions (tenant_id, executed, legal_hold)""",
    """CREATE TABLE IF NOT EXISTS lifecycle_idempotency (
        tenant_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        operation TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        deletion_id TEXT NOT NULL,
        resulting_version INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, idempotency_key),
        FOREIGN KEY (tenant_id, deletion_id)
            REFERENCES lifecycle_deletions (tenant_id, deletion_id)
    )""",
)


def require_identifier(value: str, field: str) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise LifecycleConflict(f"{field} is invalid")


def require_sha256(value: str, field: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise LifecycleConflict(f"{field} is invalid")


def require_version(value: int) -> None:
    if type(value) is not int or value < 1:
        raise LifecycleConflict("expected_version is invalid")


__all__ = [
    "DATA_CLASSES",
    "LIFECYCLE_SCHEMA",
    "DeletionReceipt",
    "DeletionRequest",
    "LifecycleConflict",
    "RetentionProfile",
    "StorageExecutor",
    "require_identifier",
    "require_sha256",
    "require_version",
]
