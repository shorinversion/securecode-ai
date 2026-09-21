"""Strict product role validation through native provider normalization."""

from __future__ import annotations

import json

import pytest
from securecode_ai.adapters import ProviderAttempt, ProviderStreamState, normalize_provider_attempt
from securecode_ai.contracts import ApiDialect, ModelCallStatus

from tests.unit.test_product_model import _discovery_request, _discovery_validator
from tests.unit.test_provider_normalization import _binding


@pytest.mark.parametrize(
    ("payload", "refusal", "expected"),
    [
        ({"candidates": []}, None, ModelCallStatus.SUCCEEDED),
        ({"candidates": "invalid"}, None, ModelCallStatus.INVALID_SCHEMA),
        ({"candidates": [], "next_node": "approve"}, None, ModelCallStatus.INVALID_SCHEMA),
        ({"candidates": [{"candidate_version": True}]}, None, ModelCallStatus.INVALID_SCHEMA),
        ({"candidates": []}, "REFUSED", ModelCallStatus.REFUSED),
    ],
)
def test_product_wire_failure_never_becomes_completed_zero(
    payload: object, refusal: str | None, expected: ModelCallStatus
) -> None:
    request = _discovery_request().model_copy(update={"api_dialect": ApiDialect.FAKE})
    binding = _binding(request)
    body = {
        "request_code": "FAKE_RESPONSE",
        "finish_code": "COMPLETE",
        "refusal_code": refusal,
        "filter_code": None,
        "content_text": json.dumps(payload),
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }
    attempt = ProviderAttempt(
        dialect=ApiDialect.FAKE,
        http_status=200,
        response_bytes=json.dumps(body).encode(),
        transport_failure=None,
        stream_state=ProviderStreamState.COMPLETE,
        binding=binding,
        elapsed_ms=1,
    )
    execution = normalize_provider_attempt(
        request=request, attempt=attempt, expected_binding=binding, validator=_discovery_validator()
    )
    assert execution.result.model_call_status is expected
    if expected is ModelCallStatus.SUCCEEDED:
        assert execution.payload is not None
        assert execution.payload.reveal_for(request.request_id) == {"candidates": []}
        execution.payload.close()
    else:
        assert execution.payload is None
        assert execution.result.content_provenance is None
