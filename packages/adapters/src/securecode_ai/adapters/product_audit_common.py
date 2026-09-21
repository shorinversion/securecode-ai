"""Compose actual product-flow receipts into a conservative Core audit run.

The adapter deliberately does not fill gaps in the accepted stage catalogue.
It returns a typed obstacle when immutable upstream receipts cannot be represented
by the frozen public ``CoverageManifest`` contract.
"""

from __future__ import annotations

import hashlib
import json

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    CoverageStatus,
    CoverageUnit,
    ModelRequest,
)
from securecode_ai.core.investigation import (
    AuditorAttemptReceipt,
)


def _request_sha256(request: ModelRequest) -> str:
    return _sha256(request.model_dump(mode="json"))


def _terminal_output_sha256(attempt: AuditorAttemptReceipt) -> str:
    return _sha256(
        {
            "cited_evidence_ids": list(attempt.cited_evidence_ids),
            "finding_verdict": None
            if attempt.finding_verdict is None
            else attempt.finding_verdict.value,
            "rationale_sha256": attempt.rationale_sha256,
            "selection_sha256": attempt.selection_sha256,
            "verdict_id": attempt.verdict_id,
        }
    )


def _receipt_id(stage: str, candidate_id: str) -> str:
    return f"{stage}-{_sha256({'candidate_id': candidate_id})[:32]}"


def _sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
    ).hexdigest()


def _pin_key(value: ComponentPin) -> tuple[str, str]:
    return value.component_id, value.component_version


def _completed_unit(
    stage: str, *, input_hashes: tuple[str, ...], output_hashes: tuple[str, ...]
) -> CoverageUnit:
    return CoverageUnit(
        schema_version=CONTRACT_SCHEMA_VERSION,
        coverage_unit_id=f"product-{stage}",
        stage_id=stage,
        required=True,
        applicable=True,
        coverage_status=CoverageStatus.COMPLETED,
        producer_version="1.0.0",
        input_hashes=input_hashes,
        output_hashes=output_hashes,
    )


def _skipped_unit(stage: str, reason: str) -> CoverageUnit:
    return CoverageUnit(
        schema_version=CONTRACT_SCHEMA_VERSION,
        coverage_unit_id=f"product-{stage}",
        stage_id=stage,
        required=True,
        applicable=True,
        coverage_status=CoverageStatus.SKIPPED,
        reason_code=reason,
    )
