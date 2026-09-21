"""Role-specific model request construction for installed product scans."""

from __future__ import annotations

import json

from securecode_ai.contracts import ComponentPin, ModelPurpose, ModelRequest, ModelRole
from securecode_ai.core.evidence_package import EvidencePackage

from .local_product_runner_config import LocalProductUnavailableError


def build_role_request(
    base: ModelRequest,
    package: EvidencePackage,
    attempt: int,
    schema: object,
    role: ModelRole,
    purpose: ModelPurpose,
    prompt: ComponentPin,
) -> ModelRequest:
    if type(schema) is not ComponentPin:
        raise LocalProductUnavailableError()
    data = base.model_dump(mode="json")
    identifier = role.value + "-" + package.candidate_id + "-" + str(attempt)
    data.update(
        request_id=identifier,
        idempotency_key=identifier,
        attempt=attempt,
        role=role.value,
        mode=purpose.value,
        evidence=[item.model_dump(mode="json") for item in package.model_evidence],
        prompt=prompt.model_dump(mode="json"),
        output_schema=schema.model_dump(mode="json"),
    )
    return ModelRequest.model_validate_json(json.dumps(data))


__all__ = ["build_role_request"]
