"""Source-free artifact metadata contracts for P6.4."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

_SHA = re.compile(r"[0-9a-f]{64}\Z")


class ArtifactConflict(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ArtifactMetadata:
    tenant_id: str
    repository_id: str
    run_id: str
    execution_identity_hash: str
    content_sha256: str
    size_bytes: int
    content_class: str
    purpose: str
    created_at: datetime
    expires_at: datetime | None = None
    retention_marked: bool = False

    def __post_init__(self) -> None:
        if (
            not all(
                isinstance(v, str) and v
                for v in (
                    self.tenant_id,
                    self.repository_id,
                    self.run_id,
                    self.content_class,
                    self.purpose,
                )
            )
            or _SHA.fullmatch(self.execution_identity_hash) is None
            or _SHA.fullmatch(self.content_sha256) is None
            or type(self.size_bytes) is not int
            or not 0 <= self.size_bytes <= 1_073_741_824
            or not isinstance(self.created_at, datetime)
            or (self.expires_at is not None and not isinstance(self.expires_at, datetime))
            or type(self.retention_marked) is not bool
        ):
            raise ValueError("artifact metadata is invalid")
        if any(
            len(value) > 256 or any(ord(character) < 0x20 for character in value)
            for value in (
                self.repository_id,
                self.run_id,
                self.content_class,
                self.purpose,
            )
        ):
            raise ValueError("artifact metadata is invalid")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() != timedelta(0):
            raise ValueError("artifact metadata timestamp is invalid")
        if self.expires_at is not None and (
            self.expires_at.tzinfo is None
            or self.expires_at.utcoffset() != timedelta(0)
            or self.expires_at <= self.created_at
        ):
            raise ValueError("artifact metadata expiration is invalid")


class ArtifactStore(Protocol):
    def put(
        self, metadata: ArtifactMetadata, chunks: object, idempotency_key: str
    ) -> ArtifactMetadata: ...
    def get(self, *, tenant_id: str, content_sha256: str) -> tuple[ArtifactMetadata, object]: ...
    def list(self, *, tenant_id: str, run_id: str) -> tuple[ArtifactMetadata, ...]: ...
