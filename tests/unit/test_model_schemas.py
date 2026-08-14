"""Deterministic public JSON Schema tests for P1.8 model roots."""

from __future__ import annotations

import importlib.resources
import json

from securecode_ai.contracts import ModelCallResult, ModelRequest
from securecode_ai.contracts.schema_export import (
    DEFAULT_SCHEMA_DIRECTORY,
    compare_schema_documents,
    render_schema_documents,
    validate_public_document,
)

from .test_model_contracts import valid_request_payload, valid_success_result_payload


def test_model_roots_are_deterministic_checked_in_schemas() -> None:
    rendered = render_schema_documents()
    assert "model-request.schema.json" in rendered
    assert "model-call-result.schema.json" in rendered
    assert compare_schema_documents(DEFAULT_SCHEMA_DIRECTORY) == ()


def test_model_schema_artifacts_are_packaged() -> None:
    schema_root = importlib.resources.files("securecode_ai.contracts") / "schemas" / "v0.2.0"
    for name in ("model-request.schema.json", "model-call-result.schema.json"):
        document = json.loads((schema_root / name).read_text(encoding="utf-8"))
        assert document["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert document["additionalProperties"] is False
        if name == "model-call-result.schema.json":
            assert "model_call_status" in document["properties"]
            assert "status" not in document["properties"]


def test_model_public_semantic_validator_round_trips() -> None:
    request = validate_public_document(
        "model-request", json.dumps(valid_request_payload(), sort_keys=True)
    )
    result = validate_public_document(
        "model-call-result", json.dumps(valid_success_result_payload(), sort_keys=True)
    )
    assert isinstance(request, ModelRequest)
    assert isinstance(result, ModelCallResult)
