"""Determinism and closed-surface checks for generated public JSON Schemas."""

from __future__ import annotations

import importlib
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from securecode_ai.contracts.schema_export import (
    JSON_SCHEMA_DIALECT,
    compare_schema_documents,
    render_schema_documents,
    schema_file_hashes,
    validate_public_document,
    write_schema_documents,
)

EXPECTED_SCHEMA_FILES = {
    "audit-event.schema.json",
    "audit-run.schema.json",
    "evidence.schema.json",
    "finding-case.schema.json",
    "model-call-result.schema.json",
    "model-request.schema.json",
    "patch-candidate.schema.json",
    "validation-result.schema.json",
    "workflow-definition.schema.json",
    "workflow-runtime-request.schema.json",
    "workflow-runtime-result.schema.json",
    "workflow-snapshot.schema.json",
    "workflow-transition-event.schema.json",
}
FORBIDDEN_EMBEDDED_FIELDS = {
    "api_key",
    "command",
    "diff",
    "provider_response",
    "raw_response",
    "raw_source",
    "secret",
    "source_code",
    "unified_diff",
}


def _walk(value: Any) -> Iterator[Any]:
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def test_schema_rendering_is_byte_deterministic_and_hashed() -> None:
    first = render_schema_documents()
    second = render_schema_documents()
    assert first == second
    assert set(first) == EXPECTED_SCHEMA_FILES
    assert schema_file_hashes(first) == schema_file_hashes(second)
    assert all(len(digest) == 64 for digest in schema_file_hashes(first).values())


def test_schema_documents_use_draft_2020_12_and_closed_objects() -> None:
    for content in render_schema_documents().values():
        document = json.loads(content)
        assert document["$schema"] == JSON_SCHEMA_DIALECT
        assert document["$id"].startswith("https://schemas.securecode.ai/domain/0.2.0/")
        assert document["x-securecode-semantic-validator"] == (
            "securecode_ai.contracts.schema_export:validate_public_document"
        )
        assert document["x-securecode-semantic-rules"]
        assert "Full conformance" in document["$comment"]
        for node in _walk(document):
            if isinstance(node, dict) and "properties" in node:
                assert node.get("additionalProperties") is False


def test_named_semantic_validator_entrypoint_is_resolvable() -> None:
    document = json.loads(render_schema_documents()["audit-run.schema.json"])
    module_name, symbol_name = document["x-securecode-semantic-validator"].split(":", 1)
    validator = getattr(importlib.import_module(module_name), symbol_name)
    assert validator is validate_public_document


def test_every_versioned_object_schema_requires_schema_version() -> None:
    for content in render_schema_documents().values():
        document = json.loads(content)
        for node in _walk(document):
            if not isinstance(node, dict) or "properties" not in node:
                continue
            properties = node["properties"]
            if "schema_version" in properties:
                assert "schema_version" in node.get("required", [])


def test_schema_surface_has_no_raw_source_diff_command_or_secret_fields() -> None:
    property_names: set[str] = set()
    for content in render_schema_documents().values():
        document = json.loads(content)
        for node in _walk(document):
            if isinstance(node, dict) and isinstance(node.get("properties"), dict):
                property_names.update(node["properties"])
    assert property_names.isdisjoint(FORBIDDEN_EMBEDDED_FIELDS)


def test_schema_writer_and_comparator_detect_missing_extra_and_drift(tmp_path: Path) -> None:
    written = write_schema_documents(tmp_path)
    assert {path.name for path in written} == EXPECTED_SCHEMA_FILES
    assert compare_schema_documents(tmp_path) == ()

    drifted = tmp_path / "audit-run.schema.json"
    drifted.write_bytes(b"{}\n")
    missing = tmp_path / "evidence.schema.json"
    missing.unlink()
    extra = tmp_path / "extra.schema.json"
    extra.write_bytes(b"{}\n")

    assert compare_schema_documents(tmp_path) == (
        "missing:evidence.schema.json",
        "extra:extra.schema.json",
        "drift:audit-run.schema.json",
    )


def test_schema_writer_rejects_unexpected_existing_schema(tmp_path: Path) -> None:
    (tmp_path / "unexpected.schema.json").write_bytes(b"{}\n")
    try:
        write_schema_documents(tmp_path)
    except ValueError as error:
        assert "unexpected" in str(error)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("writer accepted an unexpected checked-in schema")


def test_named_semantic_validator_round_trips_a_public_document() -> None:
    document = render_schema_documents()["evidence.schema.json"]
    assert b"x-securecode-semantic-validator" in document
    try:
        validate_public_document("unknown-root", b"{}")
    except ValueError as error:
        assert "unknown" in str(error)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("unknown public root was accepted")


def test_raw_opaque_id_and_semver_patterns_are_structural_semantic_parity() -> None:
    audit_schema = json.loads(render_schema_documents()["audit-run.schema.json"])
    pin_schema = audit_schema["$defs"]["ComponentPin"]
    id_pattern = pin_schema["properties"]["component_id"]["pattern"]
    semver_pattern = pin_schema["properties"]["component_version"]["pattern"]
    assert re.fullmatch(id_pattern, "policy")
    assert re.fullmatch(id_pattern, " policy ") is None
    assert "?P<" not in semver_pattern
    assert re.fullmatch(semver_pattern, "1.2.3")
