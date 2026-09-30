"""Strict private Skeptic wire validation."""

from __future__ import annotations

import json

import pytest
from securecode_ai.adapters.model import HmacContentIdentifier
from securecode_ai.adapters.product_model import AuditorPayloadValidator
from securecode_ai.adapters.product_skeptic import (
    SKEPTIC_WIRE_PIN,
    SKEPTIC_WIRE_SCHEMA_JSON,
    SkepticPayloadValidator,
)
from securecode_ai.contracts import (
    FindingVerdict,
    ModelCallStatus,
    ModelPurpose,
    ModelRequest,
    ModelRole,
)
from securecode_ai.core.skeptic import AuditorSnapshot, SkepticObjectionKind

from tests.unit.test_product_model import _auditor_request, _package


def _snapshot(*, evidence_ids: tuple[str, ...] = ("evidence-a",)) -> AuditorSnapshot:
    return AuditorSnapshot(
        candidate_id="candidate-a",
        candidate_version=1,
        head_sha="1" * 40,
        auditor_identity="auditor-a",
        auditor_output_sha256="a" * 64,
        model_call_status=ModelCallStatus.SUCCEEDED,
        finding_verdict=FindingVerdict.CONFIRMED,
        evidence_ids=evidence_ids,
    )


def _validator() -> SkepticPayloadValidator:
    return SkepticPayloadValidator(
        package=_package(),
        snapshot=_snapshot(),
        content_identifier=HmacContentIdentifier(b"s" * 32),
        expected_tenant_id="tenant-a",
    )


def _request(validator: SkepticPayloadValidator) -> ModelRequest:
    auditor = AuditorPayloadValidator(
        package=_package(), content_identifier=HmacContentIdentifier(b"a" * 32)
    )
    value = _auditor_request(auditor).model_dump(mode="json")
    value.update(
        role=ModelRole.SKEPTIC.value,
        mode=ModelPurpose.SKEPTIC_REVIEW.value,
        output_schema=validator.validator.model_dump(mode="json"),
    )
    return ModelRequest.model_validate_json(json.dumps(value, sort_keys=True))


def _payload() -> dict[str, object]:
    return {
        "finding_verdict": FindingVerdict.REJECTED_WITH_EVIDENCE.value,
        "objections": [
            {
                "kind": SkepticObjectionKind.CONTRADICTORY_EVIDENCE.value,
                "evidence_ids": ["evidence-a"],
            }
        ],
    }


def test_skeptic_wire_is_closed_and_maps_only_to_core_output() -> None:
    validator = _validator()
    request = _request(validator)

    result = validator.validate(_payload(), request=request)
    output = validator.parse(_payload(), request=request)

    assert result.accepted and result.validator == SKEPTIC_WIRE_PIN
    assert result.content_id is not None and result.content_id.startswith("kid:")
    assert output.finding_verdict is FindingVerdict.REJECTED_WITH_EVIDENCE
    assert output.objections[0].kind is SkepticObjectionKind.CONTRADICTORY_EVIDENCE
    assert "\\Z" not in SKEPTIC_WIRE_SCHEMA_JSON.decode()


def test_skeptic_objection_note_is_accepted_and_dropped() -> None:
    validator = _validator()
    payload = _payload()
    objections = payload["objections"]
    assert isinstance(objections, list)
    objections[0]["note"] = "The query is parameterized two lines above."

    output = validator.parse(payload, request=_request(validator))

    assert output.objections[0].kind is SkepticObjectionKind.CONTRADICTORY_EVIDENCE
    assert "parameterized" not in repr(output)


@pytest.mark.parametrize(
    "payload",
    [
        {"finding_verdict": "CONFIRMED", "objections": [], "prose": "raw"},
        {
            "finding_verdict": "CONFIRMED",
            "objections": [
                {"kind": "CONTRADICTORY_EVIDENCE", "evidence_ids": ["evidence-a"], "note": 7}
            ],
        },
        {
            "finding_verdict": "CONFIRMED",
            "objections": [
                {"kind": "CONTRADICTORY_EVIDENCE", "evidence_ids": ["evidence-a"]},
                {"kind": "CONTRADICTORY_EVIDENCE", "evidence_ids": ["evidence-a"]},
            ],
        },
        {
            "finding_verdict": "CONFIRMED",
            "objections": [
                {"kind": "CONTRADICTORY_EVIDENCE", "evidence_ids": ["foreign-evidence"]}
            ],
        },
    ],
)
def test_skeptic_wire_rejects_extra_duplicate_and_foreign_output(payload: object) -> None:
    validator = _validator()
    result = validator.validate(payload, request=_request(validator))

    assert not result.accepted
    assert result.error_code == "SCHEMA_INVALID"
    assert result.content_id is None


@pytest.mark.parametrize("field,value", [("role", ModelRole.AUDITOR), ("head_sha", "2" * 40)])
def test_skeptic_wire_requires_exact_role_purpose_context_and_pin(
    field: str, value: object
) -> None:
    validator = _validator()
    request = _request(validator).model_copy(update={field: value})

    result = validator.validate(_payload(), request=request)

    assert not result.accepted
    assert result.content_id is None


def test_skeptic_validator_rejects_selected_package_outside_snapshot_or_tenant() -> None:
    with pytest.raises(ValueError, match="trusted Skeptic context"):
        SkepticPayloadValidator(
            package=_package(),
            snapshot=_snapshot(evidence_ids=("other",)),
            content_identifier=HmacContentIdentifier(b"s" * 32),
            expected_tenant_id="tenant-a",
        )
    with pytest.raises(ValueError, match="trusted Skeptic context"):
        SkepticPayloadValidator(
            package=_package(),
            snapshot=_snapshot(),
            content_identifier=HmacContentIdentifier(b"s" * 32),
            expected_tenant_id="tenant-b",
        )
