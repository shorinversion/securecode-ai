"""Canonical bounded metadata-only EvidencePackage assembly, never transport."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .evidence_egress import DataClass, EgressAuthorization, EgressDenied, EgressPolicy


class PackageConflict(Exception):
    pass


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    item_id: str
    data_class: DataClass
    content_sha256: str
    size_bytes: int
    media_type: str
    purpose: str

    def __post_init__(self) -> None:
        if (
            not all(
                isinstance(value, str) and value
                for value in (self.item_id, self.content_sha256, self.media_type, self.purpose)
            )
            or len(self.content_sha256) != 64
            or type(self.size_bytes) is not int
            or not 0 <= self.size_bytes <= 16_777_216
        ):
            raise ValueError("evidence item is invalid")


@dataclass(frozen=True, slots=True)
class EvidencePackage:
    authorization: EgressAuthorization
    items: tuple[EvidenceItem, ...]
    manifest_sha256: str

    @classmethod
    def prepare(
        cls,
        authorization: EgressAuthorization,
        policy: EgressPolicy,
        items: tuple[EvidenceItem, ...],
    ) -> EvidencePackage:
        if (
            not 0 < len(items) <= 128
            or len({item.item_id for item in items}) != len(items)
            or any(not policy.permits(item.data_class) for item in items)
        ):
            raise EgressDenied()
        ordered = tuple(sorted(items, key=lambda item: item.item_id))
        document = {
            "tenant_id": authorization.tenant_id,
            "repository_id": authorization.repository_id,
            "run_id": authorization.run_id,
            "execution_identity_hash": authorization.execution_identity_hash,
            "destination_id": authorization.destination_id,
            "profile_id": authorization.profile_id,
            "capability_id": authorization.capability_id,
            "items": [
                {
                    "item_id": item.item_id,
                    "data_class": item.data_class.value,
                    "content_sha256": item.content_sha256,
                    "size_bytes": item.size_bytes,
                    "media_type": item.media_type,
                    "purpose": item.purpose,
                }
                for item in ordered
            ],
        }
        digest = hashlib.sha256(
            json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
                "ascii"
            )
        ).hexdigest()
        return cls(authorization, ordered, digest)

    def receipt(self) -> dict[str, object]:
        return {
            "manifest_sha256": self.manifest_sha256,
            "destination_id": self.authorization.destination_id,
            "profile_id": self.authorization.profile_id,
            "capability_id": self.authorization.capability_id,
            "item_count": len(self.items),
            "item_hashes": tuple(item.content_sha256 for item in self.items),
        }


class EvidencePackageRegistry:
    def __init__(self) -> None:
        self._values: dict[str, EvidencePackage] = {}

    def prepare(
        self,
        *,
        idempotency_key: str,
        authorization: EgressAuthorization,
        policy: EgressPolicy,
        items: tuple[EvidenceItem, ...],
    ) -> EvidencePackage:
        package = EvidencePackage.prepare(authorization, policy, items)
        prior = self._values.get(idempotency_key)
        if prior is not None:
            if prior == package:
                return prior
            raise PackageConflict()
        self._values[idempotency_key] = package
        return package
