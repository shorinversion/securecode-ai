"""Focused contracts for strict product structured-output leaves."""

from __future__ import annotations

import hashlib
import json

import pytest
from securecode_ai.adapters.model import HmacContentIdentifier
from securecode_ai.adapters.product_model import (
    AUDITOR_WIRE_PIN,
    AUDITOR_WIRE_SCHEMA_JSON,
    MODEL_NATIVE_DISCOVERY_WIRE_PIN,
    MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON,
    AuditorPayloadValidator,
    DiscoverySchemaRefusalCategory,
    ModelNativeDiscoveryPayloadValidator,
    to_model_native_candidate_draft,
)
from securecode_ai.contracts import DataClass, FindingVerdict, ModelPurpose, ModelRequest, ModelRole
from securecode_ai.core.auditor import AUDITOR_VERDICTS
from securecode_ai.core.evidence_package import EvidenceContextRef, EvidencePackage

from .test_model_contracts import valid_request_payload


@pytest.mark.parametrize(
    ("encoded", "pin"),
    (
        (MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON, MODEL_NATIVE_DISCOVERY_WIRE_PIN),
        (AUDITOR_WIRE_SCHEMA_JSON, AUDITOR_WIRE_PIN),
    ),
)
def test_context_wire_schema_bytes_match_validator_pin(encoded: bytes, pin: object) -> None:
    from securecode_ai.contracts import ComponentPin

    assert isinstance(pin, ComponentPin)
    assert type(encoded) is bytes
    assert hashlib.sha256(encoded).hexdigest() == pin.content_sha256
    decoded = json.loads(encoded)
    decoded["additionalProperties"] = True
    assert json.loads(encoded)["additionalProperties"] is False


def _discovery_validator() -> ModelNativeDiscoveryPayloadValidator:
    return ModelNativeDiscoveryPayloadValidator(
        content_identifier=HmacContentIdentifier(b"d" * 32),
        rule_ids=frozenset({"rule-sqli", "rule-ssrf"}),
        evidence_ids=frozenset({"evidence-a", "evidence-b", "evidence-c"}),
        expected_tenant_id="tenant-a",
        expected_head_sha="1" * 40,
    )


def _discovery_request() -> ModelRequest:
    payload = valid_request_payload()
    payload["output_schema"] = MODEL_NATIVE_DISCOVERY_WIRE_PIN.model_dump(mode="json")
    return ModelRequest.model_validate_json(json.dumps(payload, sort_keys=True))


def _package() -> EvidencePackage:
    reference = EvidenceContextRef(
        evidence_id="evidence-a",
        content_id="content-a",
        data_class=DataClass.CONFIDENTIAL_SECURITY,
        evidence_sha256="a" * 64,
        producer_id="scanner",
        producer_version="1.0.0",
        producer_sha256="b" * 64,
        context_bytes=4,
        estimated_tokens=1,
    )
    return EvidencePackage(
        candidate_id="candidate-a",
        candidate_version=1,
        tenant_id="tenant-a",
        head_sha="1" * 40,
        graph_id="graph-a",
        graph_sha256="c" * 64,
        selection_sha256="d" * 64,
        selected=(reference,),
        omitted_evidence_ids=(),
        total_context_bytes=4,
        total_input_tokens=1,
        truncated=False,
    )


def _auditor_validator() -> AuditorPayloadValidator:
    return AuditorPayloadValidator(
        package=_package(),
        content_identifier=HmacContentIdentifier(b"a" * 32),
    )


def _auditor_request(validator: AuditorPayloadValidator) -> ModelRequest:
    payload = valid_request_payload()
    payload["role"] = ModelRole.AUDITOR.value
    payload["mode"] = ModelPurpose.CANDIDATE_INVESTIGATION.value
    payload["output_schema"] = validator.validator.model_dump(mode="json")
    payload["evidence"] = [item.model_dump(mode="json") for item in _package().model_evidence]
    return ModelRequest.model_validate_json(json.dumps(payload, sort_keys=True))


def _discovery_payload() -> dict[str, object]:
    return {
        "candidates": [
            {
                "rule_id": "rule-sqli",
                "root_evidence_id": "evidence-a",
                "evidence_ids": ["evidence-a"],
            }
        ]
    }


def _auditor_payload() -> dict[str, object]:
    return {
        "finding_verdict": "CONFIRMED",
        "cited_evidence_ids": ["evidence-a"],
        "rationale": "The selected evidence supports the verdict.",
    }


def test_discovery_wire_uses_registered_selectors_and_host_derives_core_draft() -> None:
    validator = _discovery_validator()
    request = _discovery_request()
    payload = _discovery_payload()

    result = validator.validate(payload, request=request)

    assert result.accepted
    assert result.error_code is None
    assert result.content_id is not None and result.content_id.startswith("kid:")
    assert result.data_class is DataClass.CONFIDENTIAL_SECURITY
    assert result.validator == MODEL_NATIVE_DISCOVERY_WIRE_PIN
    candidate = validator.parse(payload)[0]
    draft = to_model_native_candidate_draft(
        candidate,
        candidate_id="host-candidate-1",
        candidate_version=1,
        source_id="host-source-1",
        root_cause_fingerprint="d" * 64,
    )
    assert draft.candidate_id == "host-candidate-1"
    assert draft.evidence_ids == ("evidence-a",)


def test_discovery_completed_zero_is_a_valid_closed_envelope() -> None:
    result = _discovery_validator().validate({"candidates": []}, request=_discovery_request())

    assert result.accepted


@pytest.mark.parametrize(
    "payload",
    [
        {"candidates": "not-a-list"},
        {"candidates": [], "next_node": "approve"},
        {
            "candidates": [
                {
                    "rule_id": "rule-sqli",
                    "root_evidence_id": "evidence-a",
                    "evidence_ids": ["evidence-a"],
                    "candidate_version": True,
                }
            ]
        },
    ],
)
def test_discovery_rejects_generic_validator_acceptance_gaps(payload: object) -> None:
    result = _discovery_validator().validate(payload, request=_discovery_request())

    assert not result.accepted
    assert result.error_code == "SCHEMA_INVALID"
    assert result.content_id is None


@pytest.mark.parametrize(
    "payload",
    [
        {
            "candidates": [
                {
                    "rule_id": "rule-sqli",
                    "root_evidence_id": "evidence-a",
                    "evidence_ids": ["evidence-a"],
                },
                {
                    "rule_id": "rule-sqli",
                    "root_evidence_id": "evidence-a",
                    "evidence_ids": ["evidence-a"],
                },
            ]
        },
        {
            "candidates": [
                {
                    "rule_id": "rule-sqli",
                    "root_evidence_id": "evidence-a",
                    "evidence_ids": ["invented-evidence"],
                }
            ]
        },
    ],
)
def test_discovery_rejects_duplicate_or_untrusted_context(payload: object) -> None:
    result = _discovery_validator().validate(payload, request=_discovery_request())

    assert not result.accepted
    assert result.error_code == "SCHEMA_INVALID"


@pytest.mark.parametrize(
    ("payload", "category"),
    (
        ({"other": []}, DiscoverySchemaRefusalCategory.TOP_LEVEL_SHAPE),
        ({"candidates": "not-a-list"}, DiscoverySchemaRefusalCategory.CANDIDATE_LIST_SHAPE),
        (
            {
                "candidates": [
                    {
                        "rule_id": "unregistered-rule",
                        "root_evidence_id": "evidence-a",
                        "evidence_ids": ["evidence-a"],
                    }
                ]
            },
            DiscoverySchemaRefusalCategory.UNKNOWN_RULE,
        ),
        (
            {
                "candidates": [
                    {
                        "rule_id": "rule-sqli",
                        "root_evidence_id": "unregistered-evidence",
                        "evidence_ids": ["unregistered-evidence"],
                    }
                ]
            },
            DiscoverySchemaRefusalCategory.UNKNOWN_EVIDENCE,
        ),
        (
            {
                "candidates": [
                    {
                        "rule_id": "rule-sqli",
                        "root_evidence_id": "evidence-a",
                        "evidence_ids": ["evidence-a"],
                    },
                    {
                        "rule_id": "rule-sqli",
                        "root_evidence_id": "evidence-a",
                        "evidence_ids": ["evidence-a"],
                    },
                ]
            },
            DiscoverySchemaRefusalCategory.DUPLICATE_HYPOTHESIS,
        ),
    ),
)
def test_discovery_schema_refusal_category_is_closed_and_keeps_existing_error(
    payload: object, category: DiscoverySchemaRefusalCategory
) -> None:
    validator = _discovery_validator()

    result = validator.validate(payload, request=_discovery_request())

    assert not result.accepted
    assert result.error_code == "SCHEMA_INVALID"
    assert validator.last_schema_refusal_category is category
    assert validator.validate(_discovery_payload(), request=_discovery_request()).accepted
    assert validator.last_schema_refusal_category is DiscoverySchemaRefusalCategory.NOT_OBSERVED


def test_discovery_schema_refusal_category_uses_fixed_precedence() -> None:
    validator = _discovery_validator()
    payload = {
        "candidates": [
            {
                "rule_id": "unregistered-rule",
                "root_evidence_id": "unregistered-evidence",
                "evidence_ids": ["unregistered-evidence"],
            }
        ]
    }

    result = validator.validate(payload, request=_discovery_request())

    assert not result.accepted and result.error_code == "SCHEMA_INVALID"
    assert validator.last_schema_refusal_category is DiscoverySchemaRefusalCategory.UNKNOWN_RULE


def test_discovery_allows_distinct_hypotheses_with_shared_support() -> None:
    payload = {
        "candidates": [
            {
                "rule_id": "rule-sqli",
                "root_evidence_id": "evidence-a",
                "evidence_ids": ["evidence-a"],
            },
            {
                "rule_id": "rule-sqli",
                "root_evidence_id": "evidence-b",
                "evidence_ids": ["evidence-b"],
            },
            {
                "rule_id": "rule-ssrf",
                "root_evidence_id": "evidence-a",
                "evidence_ids": ["evidence-a"],
            },
        ]
    }

    result = _discovery_validator().validate(payload, request=_discovery_request())

    assert result.accepted


def test_discovery_requires_implementation_pin_and_role() -> None:
    validator = _discovery_validator()
    wrong_pin = ModelRequest.model_validate_json(
        json.dumps(valid_request_payload(), sort_keys=True)
    )
    wrong_role = _discovery_request().model_copy(update={"role": ModelRole.AUDITOR})

    pin_result = validator.validate(_discovery_payload(), request=wrong_pin)
    role_result = validator.validate(_discovery_payload(), request=wrong_role)

    assert not pin_result.accepted
    assert pin_result.error_code == "OUTPUT_SCHEMA_PIN_MISMATCH"
    assert not role_result.accepted
    assert role_result.error_code == "REQUEST_ROLE_PURPOSE_MISMATCH"


def test_auditor_wire_hashes_ephemeral_rationale_before_core_parser() -> None:
    validator = _auditor_validator()
    request = _auditor_request(validator)

    result = validator.validate(_auditor_payload(), request=request)
    verdict = validator.parse(_auditor_payload(), request=request)

    assert result.accepted
    assert result.content_id is not None and result.content_id.startswith("kid:")
    assert result.data_class is DataClass.CONFIDENTIAL_SECURITY
    assert result.validator == AUDITOR_WIRE_PIN
    assert verdict.verdict_id.startswith("kid:")
    assert verdict.cited_evidence_ids == ("evidence-a",)
    assert len(verdict.rationale_sha256) == 64


@pytest.mark.parametrize(
    "payload",
    [
        {
            "finding_verdict": "CONFIRMED",
            "cited_evidence_ids": ["evidence-a"],
            "rationale": "x",
            "prose": "raw",
        },
        {
            "finding_verdict": "CONFIRMED",
            "cited_evidence_ids": ["invented-evidence"],
            "rationale": "x",
        },
        {
            "finding_verdict": "CONFIRMED",
            "cited_evidence_ids": ["evidence-a"],
            "rationale": "x" * 4097,
        },
    ],
)
def test_auditor_rejects_extra_untrusted_or_oversized_wire_content(payload: object) -> None:
    validator = _auditor_validator()
    result = validator.validate(payload, request=_auditor_request(validator))

    assert not result.accepted
    assert result.error_code == "SCHEMA_INVALID"
    assert result.content_id is None


def test_auditor_requires_exact_context_role_purpose_and_pin() -> None:
    validator = _auditor_validator()
    request = _auditor_request(validator)
    wrong_context = request.model_copy(update={"evidence": ()})
    wrong_role = request.model_copy(update={"role": ModelRole.DISCOVERY})
    wrong_pin = request.model_copy(update={"output_schema": MODEL_NATIVE_DISCOVERY_WIRE_PIN})
    wrong_head = request.model_copy(update={"head_sha": "2" * 40})

    for invalid_request in (wrong_context, wrong_role, wrong_pin, wrong_head):
        result = validator.validate(_auditor_payload(), request=invalid_request)
        assert not result.accepted
        assert result.content_id is None
        assert "rationale" not in (result.error_code or "")
        with pytest.raises(ValueError, match="auditor request is invalid"):
            validator.parse(_auditor_payload(), request=invalid_request)


def test_auditor_snapshots_and_deep_validates_its_evidence_context() -> None:
    package = _package()
    validator = AuditorPayloadValidator(
        package=package,
        content_identifier=HmacContentIdentifier(b"a" * 32),
    )
    object.__setattr__(package.selected[0], "evidence_id", "tampered-evidence")

    assert validator.validate(_auditor_payload(), request=_auditor_request(validator)).accepted

    invalid_package = _package()
    object.__setattr__(invalid_package.selected[0], "evidence_id", "")
    with pytest.raises(ValueError, match="trusted auditor context is invalid"):
        AuditorPayloadValidator(
            package=invalid_package,
            content_identifier=HmacContentIdentifier(b"b" * 32),
        )


@pytest.mark.parametrize(
    "finding_verdict", tuple(item for item in FindingVerdict if item in AUDITOR_VERDICTS)
)
def test_auditor_wire_preserves_all_accepted_core_verdicts(finding_verdict: FindingVerdict) -> None:
    validator = _auditor_validator()
    request = _auditor_request(validator)
    payload = _auditor_payload()
    payload["finding_verdict"] = finding_verdict.value
    assert validator.validate(payload, request=request).accepted
    assert validator.parse(payload, request=request).finding_verdict is finding_verdict


@pytest.mark.parametrize("finding_verdict", ["CONFLICTING", "NOT_EVALUATED"])
def test_auditor_wire_schema_excludes_run_level_verdicts(finding_verdict: str) -> None:
    validator = _auditor_validator()
    request = _auditor_request(validator)
    enum = json.loads(AUDITOR_WIRE_SCHEMA_JSON)["properties"]["finding_verdict"]["enum"]
    assert finding_verdict not in enum
    payload = _auditor_payload()
    payload["finding_verdict"] = finding_verdict
    assert not validator.validate(payload, request=request).accepted


@pytest.mark.parametrize(("tenant", "head"), [("tenant-b", "1" * 40), ("tenant-a", "2" * 40)])
@pytest.mark.parametrize("payload", [_discovery_payload(), {"candidates": []}])
def test_discovery_stale_context_cannot_mint_foreign_tenant_provenance(
    tenant: str, head: str, payload: object
) -> None:
    validator = ModelNativeDiscoveryPayloadValidator(
        content_identifier=HmacContentIdentifier(b"d" * 32),
        rule_ids=frozenset({"rule-sqli"}),
        evidence_ids=frozenset({"evidence-a"}),
        expected_tenant_id=tenant,
        expected_head_sha=head,
    )
    result = validator.validate(payload, request=_discovery_request())
    assert not result.accepted
    assert result.error_code == "REQUEST_CONTEXT_MISMATCH"
    assert result.content_id is None
    assert result.data_class is None


def test_discovery_adds_an_omitted_root_and_drops_repeated_evidence() -> None:
    payload = {
        "candidates": [
            {
                "rule_id": "rule-sqli",
                "root_evidence_id": "evidence-a",
                "evidence_ids": ["evidence-b", "evidence-b"],
            }
        ]
    }
    validator = _discovery_validator()

    assert validator.validate(payload, request=_discovery_request()).accepted
    parsed = validator.parse(payload)
    assert parsed[0].evidence_ids == ("evidence-a", "evidence-b")


def test_discovery_still_rejects_an_unregistered_root() -> None:
    payload = {
        "candidates": [
            {
                "rule_id": "rule-sqli",
                "root_evidence_id": "invented-evidence",
                "evidence_ids": ["evidence-a"],
            }
        ]
    }

    result = _discovery_validator().validate(payload, request=_discovery_request())

    assert not result.accepted
