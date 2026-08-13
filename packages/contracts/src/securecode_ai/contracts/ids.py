"""Deterministic, opaque identifiers derived only from hashed semantic material."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum

from .base import ClosedModel, OpaqueId, Sha256


class StableIdKind(StrEnum):
    RUN = "run"
    EVENT = "evt"
    IDEMPOTENCY = "idem"
    CORRELATION = "corr"
    SIGNAL = "sig"
    CANDIDATE = "cand"
    EVIDENCE = "evd"
    FINDING = "find"
    PATCH = "patch"
    VALIDATION = "val"


class _StableIdMaterial(ClosedModel):
    derivation_version: str
    kind: StableIdKind
    tenant_id: OpaqueId
    scope_id: OpaqueId
    semantic_sha256: Sha256


def _stable_digest(material: dict[str, str]) -> str:
    payload = json.dumps(
        material,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def derive_stable_id(
    kind: StableIdKind,
    *,
    tenant_id: OpaqueId,
    scope_id: OpaqueId,
    semantic_sha256: Sha256,
) -> str:
    """Derive a stable opaque ID without accepting raw semantic content."""

    material = _StableIdMaterial(
        derivation_version="1",
        kind=kind,
        tenant_id=tenant_id,
        scope_id=scope_id,
        semantic_sha256=semantic_sha256,
    )
    digest = _stable_digest(material.model_dump(mode="json"))
    return f"{kind.value}:{digest}"


def derive_idempotency_key(
    *, tenant_id: OpaqueId, run_id: OpaqueId, operation_sha256: Sha256
) -> str:
    return derive_stable_id(
        StableIdKind.IDEMPOTENCY,
        tenant_id=tenant_id,
        scope_id=run_id,
        semantic_sha256=operation_sha256,
    )


def derive_event_id(*, tenant_id: OpaqueId, run_id: OpaqueId, idempotency_key: OpaqueId) -> str:
    semantic_hash = _stable_digest(
        {
            "derivation_version": "1",
            "idempotency_key": idempotency_key,
        }
    )
    return derive_stable_id(
        StableIdKind.EVENT,
        tenant_id=tenant_id,
        scope_id=run_id,
        semantic_sha256=semantic_hash,
    )


__all__ = [
    "StableIdKind",
    "derive_event_id",
    "derive_idempotency_key",
    "derive_stable_id",
]
