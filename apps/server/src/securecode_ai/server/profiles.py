"""Immutable, content-addressed backend scan profiles and rollout validation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

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
    content: Mapping[str, object]

    @classmethod
    def build(
        cls,
        *,
        tenant_id: str,
        profile_id: str,
        version: int,
        rollout: RolloutMode,
        calibrated: bool,
        content: Mapping[str, object],
    ) -> ScanProfile:
        frozen_content = _freeze_json(content)
        if not isinstance(frozen_content, Mapping):
            raise ValueError("profile content is invalid")
        canonical = _canonical_content(frozen_content)
        return cls(
            tenant_id,
            profile_id,
            version,
            hashlib.sha256(canonical.encode("ascii")).hexdigest(),
            rollout,
            calibrated,
            frozen_content,
        )

    def __post_init__(self) -> None:
        frozen_content = _freeze_json(self.content)
        if not isinstance(frozen_content, Mapping):
            raise ValueError("profile content is invalid")
        try:
            canonical = _canonical_content(frozen_content)
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
            or (self.rollout is not RolloutMode.ADVISORY and not self.calibrated)
        ):
            raise ValueError("profile is invalid")
        object.__setattr__(self, "content", frozen_content)


def _canonical_content(value: object) -> str:
    return json.dumps(
        _plain_json(value),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _freeze_json(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(_freeze_json(item) for item in value)
    return value


def _plain_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_plain_json(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class WaiverReference:
    waiver_id: str
    expires_at: str
    reason_ref: str
