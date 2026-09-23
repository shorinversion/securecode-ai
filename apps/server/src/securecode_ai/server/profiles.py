"""Immutable, content-addressed backend scan profiles and rollout validation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class ProfileConflict(Exception):
    pass


class RolloutMode(StrEnum):
    ADVISORY = "advisory"
    NEW_CODE = "new_code"
    STRICT = "strict"


@dataclass(frozen=True, slots=True)
class ScanProfile:
    tenant_id: str
    profile_id: str
    version: int
    content_sha256: str
    rollout: RolloutMode
    calibrated: bool
    content: dict[str, object]

    @classmethod
    def build(
        cls,
        *,
        tenant_id: str,
        profile_id: str,
        version: int,
        rollout: RolloutMode,
        calibrated: bool,
        content: dict[str, object],
    ) -> ScanProfile:
        canonical = json.dumps(
            content, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        )
        return cls(
            tenant_id,
            profile_id,
            version,
            hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            rollout,
            calibrated,
            content,
        )

    def __post_init__(self) -> None:
        try:
            canonical = json.dumps(
                self.content,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        except (TypeError, ValueError):
            raise ValueError("profile content is not canonical JSON") from None
        actual_digest = hashlib.sha256(canonical.encode("ascii")).hexdigest()
        if (
            not all(isinstance(value, str) and value for value in (self.tenant_id, self.profile_id))
            or type(self.version) is not int
            or self.version < 1
            or type(self.content_sha256) is not str
            or _SHA256.fullmatch(self.content_sha256) is None
            or self.content_sha256 != actual_digest
            or type(self.rollout) is not RolloutMode
            or type(self.calibrated) is not bool
            or type(self.content) is not dict
            or (self.rollout is not RolloutMode.ADVISORY and not self.calibrated)
        ):
            raise ValueError("profile is invalid")


@dataclass(frozen=True, slots=True)
class WaiverReference:
    waiver_id: str
    expires_at: str
    reason_ref: str
