"""Skeptic evidence-package binding and ephemeral context assembly."""

from __future__ import annotations

import json

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ArtifactRef,
    DataClass,
    EgressContentRef,
    ModelRequest,
)
from securecode_ai.core.evidence_package import EvidencePackage
from securecode_ai.core.skeptic import AuditorSnapshot

from .model import HmacContentIdentifier, PreparedModelContext
from .product_skeptic_contracts import (
    _SKEPTIC_INSTRUCTIONS,
    SKEPTIC_WIRE_SCHEMA_JSON,
)

_DATA_CLASS_RANK = {
    DataClass.PUBLIC: 0,
    DataClass.INTERNAL_METADATA: 1,
    DataClass.CONFIDENTIAL_SECURITY: 2,
    DataClass.CONFIDENTIAL_SOURCE: 3,
    DataClass.RESTRICTED: 4,
}


def _package_matches_snapshot(
    package: EvidencePackage,
    snapshot: AuditorSnapshot,
    *,
    expected_tenant_id: str | None = None,
) -> bool:
    selected_ids = {item.evidence_id for item in package.selected}
    return (
        package.candidate_id == snapshot.candidate_id
        and package.candidate_version == snapshot.candidate_version
        and package.head_sha == snapshot.head_sha
        and (expected_tenant_id is None or package.tenant_id == expected_tenant_id)
        and bool(selected_ids)
        and selected_ids.issubset(snapshot.evidence_ids)
    )


def _skeptic_context(
    *,
    request: ModelRequest,
    snapshot: AuditorSnapshot,
    package: EvidencePackage,
    entries: tuple[tuple[str, ArtifactRef, bytes], ...],
    key: bytes,
) -> PreparedModelContext:
    if not entries or not _package_matches_snapshot(
        package, snapshot, expected_tenant_id=request.tenant_id
    ):
        raise ValueError("Skeptic context is invalid")
    unique: dict[str, tuple[ArtifactRef, bytes, list[str]]] = {}
    for evidence_id, artifact, content in entries:
        if artifact.tenant_id != request.tenant_id:
            raise ValueError("Skeptic context is invalid")
        previous = unique.get(artifact.content_id)
        if previous is None:
            unique[artifact.content_id] = (artifact, content, [evidence_id])
        elif previous[0] != artifact or previous[1] != content:
            raise ValueError("Skeptic context content identity collision")
        else:
            previous[2].append(evidence_id)
    selected_ids = tuple(item.evidence_id for item in package.selected)
    material = {
        "trusted_controls": {
            "role": "skeptic",
            "instructions": _SKEPTIC_INSTRUCTIONS,
            "output_schema": json.loads(SKEPTIC_WIRE_SCHEMA_JSON),
            "source_revision": {"tenant_id": request.tenant_id, "head_sha": request.head_sha},
            "selected_evidence_ids": list(selected_ids),
            "selection_truncated": package.truncated,
        },
        "untrusted_auditor_metadata": {
            "candidate_id": snapshot.candidate_id,
            "candidate_version": snapshot.candidate_version,
            "auditor_identity": snapshot.auditor_identity,
            "auditor_output_sha256": snapshot.auditor_output_sha256,
            "finding_verdict": snapshot.finding_verdict.value,
            "instruction_authority": "NONE",
        },
        "untrusted_evidence": [
            {
                "evidence_ids": aliases,
                "content_id": artifact.content_id,
                "data_class": artifact.data_class.value,
                "instruction_authority": "NONE",
                "content": content.decode("utf-8"),
            }
            for artifact, content, aliases in unique.values()
        ],
    }
    payload = json.dumps(
        material, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode()
    egress_data_class = max(
        (artifact.data_class for artifact, _, _ in unique.values()),
        key=_DATA_CLASS_RANK.__getitem__,
    )
    return PreparedModelContext(
        payload=payload,
        content=tuple(
            EgressContentRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                content_id=artifact.content_id,
                data_class=egress_data_class,
            )
            for artifact, _, _ in unique.values()
        ),
        applied_transforms=("bounded_repository_view",),
        request_id=request.request_id,
        tenant_id=request.tenant_id,
        content_identifier=HmacContentIdentifier(key),
    )
