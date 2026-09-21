"""Authorized product-model ports built on the existing provider harness."""

from __future__ import annotations

import hashlib
import json

from securecode_ai.contracts import (
    ModelRequest,
)
from securecode_ai.core.model_discovery import (
    ModelNativeCandidateDraft,
    ModelNativeDiscoveryPayload,
)
from securecode_ai.core.normalization import root_cause_location_fingerprint

from .product_model import (
    DiscoverySchemaRefusalCategory,
    ModelNativeDiscoveryWireCandidate,
    to_model_native_candidate_draft,
)
from .product_runtime_contracts import DiscoveryEvidence


class _NativeCycleExecution:
    """Closed native payload plus knowledge flags that contracts cannot encode."""

    payload: ModelNativeDiscoveryPayload
    elapsed_known: bool
    token_usage_known: bool
    schema_refusal_category: DiscoverySchemaRefusalCategory = (
        DiscoverySchemaRefusalCategory.NOT_OBSERVED
    )


def _draft(
    item: ModelNativeDiscoveryWireCandidate,
    catalogue: dict[str, DiscoveryEvidence],
    request: ModelRequest,
) -> ModelNativeCandidateDraft:
    root = catalogue[item.root_evidence_id]
    fingerprint = root_cause_location_fingerprint(
        tenant_id=request.tenant_id, rule_id=item.rule_id, location=root.location
    )
    material = json.dumps(
        [
            "product-candidate-v1",
            request.tenant_id,
            request.head_sha,
            item.rule_id,
            item.root_evidence_id,
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode()
    identity = hashlib.sha256(material).hexdigest()
    return to_model_native_candidate_draft(
        item,
        candidate_id=f"candidate:{identity}",
        candidate_version=1,
        source_id=f"source:{identity}",
        root_cause_fingerprint=fingerprint,
    )
