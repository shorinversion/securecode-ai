"""Deterministic JSON Schema and semantic-validator parity for CLI roots."""

from __future__ import annotations

import importlib.resources
import json

import pytest
from pydantic import ValidationError
from securecode_ai.cli import FoundationDoctor
from securecode_ai.contracts import (
    CliDoctorResult,
    CliErrorCode,
    CliErrorResult,
    cli_error_result,
)
from securecode_ai.contracts.schema_export import (
    DEFAULT_SCHEMA_DIRECTORY,
    compare_schema_documents,
    render_schema_documents,
    validate_public_document,
)

CLI_SCHEMA_FILES = {
    "cli-doctor-result.schema.json",
    "cli-error-result.schema.json",
}


def test_cli_roots_are_deterministic_checked_in_schemas() -> None:
    first = render_schema_documents()
    second = render_schema_documents()
    assert first == second
    assert CLI_SCHEMA_FILES.issubset(first)
    assert len(first) == 15
    assert compare_schema_documents(DEFAULT_SCHEMA_DIRECTORY) == ()


def test_cli_schema_artifacts_are_closed_and_packaged() -> None:
    root = importlib.resources.files("securecode_ai.contracts") / "schemas" / "v0.2.0"
    for name in CLI_SCHEMA_FILES:
        document = json.loads((root / name).read_text(encoding="utf-8"))
        assert document["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert document["additionalProperties"] is False
        assert "status" not in document["properties"]
        assert document["x-securecode-semantic-rules"] == [
            "SC-DOM-001",
            "SC-DOM-005",
            "SC-DOM-007",
            "SC-DOM-008",
            "SC-CLI-002",
            "SC-CLI-003",
        ]


def test_cli_public_semantic_validator_round_trips_both_roots() -> None:
    doctor = FoundationDoctor().run({})
    error = cli_error_result(
        CliErrorCode.INVALID_USAGE,
        correlation_id="correlation",
        command=None,
    )
    parsed_doctor = validate_public_document("cli-doctor-result", doctor.model_dump_json())
    parsed_error = validate_public_document("cli-error-result", error.model_dump_json())
    assert isinstance(parsed_doctor, CliDoctorResult)
    assert isinstance(parsed_error, CliErrorResult)


@pytest.mark.parametrize("root_name", ["cli-doctor-result", "cli-error-result"])
def test_cli_semantic_validator_rejects_unknown_fields(root_name: str) -> None:
    model = (
        FoundationDoctor().run({})
        if root_name == "cli-doctor-result"
        else cli_error_result(
            CliErrorCode.INVALID_USAGE,
            correlation_id="correlation",
            command=None,
        )
    )
    payload = model.model_dump(mode="json")
    payload["status"] = "PASS"
    with pytest.raises(ValidationError):
        validate_public_document(root_name, json.dumps(payload, sort_keys=True))
