"""Source-free artifact metadata contracts for P6.4."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
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
        ):
            raise ValueError("artifact metadata is invalid")


class ArtifactStore(Protocol):
    def put(
        self, metadata: ArtifactMetadata, chunks: object, idempotency_key: str
    ) -> ArtifactMetadata: ...
    def get(self, *, tenant_id: str, content_sha256: str) -> tuple[ArtifactMetadata, object]: ...
    def list(self, *, tenant_id: str, run_id: str) -> tuple[ArtifactMetadata, ...]: ...
