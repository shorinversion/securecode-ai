"""Workflow JSON Schema inventory, metadata, and semantic-validator parity."""

from __future__ import annotations

import importlib
import json
import re
from collections.abc import Iterator
from typing import Any

import pytest
from pydantic import ValidationError
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    RepositoryRevision,
    RunExecutionIdentity,
    WorkflowOperation,
    WorkflowStartRequest,
)
from securecode_ai.contracts.schema_export import (
    render_schema_documents,
    validate_public_document,
)
from securecode_ai.core import (
    DEFAULT_POLICY_PIN,
    DEFAULT_STAGE_CATALOGUE_PIN,
    DEFAULT_WORKFLOW_DEFINITION,
)

WORKFLOW_SCHEMA_FILES = {
    "workflow-definition.schema.json",
    "workflow-runtime-request.schema.json",
    "workflow-runtime-result.schema.json",
    "workflow-snapshot.schema.json",
    "workflow-transition-event.schema.json",
}
FORBIDDEN_PATTERN_TOKENS = ("(?P<", "(?P=", "\\A", "\\Z", "\\z")
FORBIDDEN_PROPERTIES = {
    "audit_outcome",
    "command",
    "diagnostic",
    "next_node",
    "patch",
    "prompt_text",
    "raw_prompt",
    "raw_error",
    "route",
    "source",
    "traceback",
    "url",
}


def _walk(value: Any) -> Iterator[Any]:
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _pin(name: str) -> ComponentPin:
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=name,
        component_version="1.0.0",
        content_sha256="a" * 64,
    )


def _request() -> WorkflowStartRequest:
    shared = _pin("component")
    identity = RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant",
            scm_provider="git",
            repository_id="repository",
            head_sha="a" * 40,
        ),
        stage_catalogue=DEFAULT_STAGE_CATALOGUE_PIN,
        workflow=DEFAULT_WORKFLOW_DEFINITION.component_pin,
        policy=DEFAULT_POLICY_PIN,
        configuration=shared,
        provider_profile=shared,
        capability_profile=shared,
        egress_profile=shared,
    )
    return WorkflowStartRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        operation=WorkflowOperation.START,
        request_id="request",
        run_id="run",
        tenant_id="tenant",
        execution_identity=identity,
        idempotency_key="key",
    )


def test_five_workflow_schema_roots_are_checked_in_and_deterministic() -> None:
    first = render_schema_documents()
    second = render_schema_documents()
    assert first == second
    assert WORKFLOW_SCHEMA_FILES.issubset(first)
    assert len(first) == 15


def test_workflow_schemas_name_resolvable_semantic_validator_and_rules() -> None:
    documents = render_schema_documents()
    for filename in WORKFLOW_SCHEMA_FILES:
        document = json.loads(documents[filename])
        assert document["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert document["$id"].endswith(filename)
        assert document["x-securecode-semantic-rules"]
        module_name, symbol_name = document["x-securecode-semantic-validator"].split(":", 1)
        assert (
            getattr(importlib.import_module(module_name), symbol_name) is validate_public_document
        )


def test_workflow_schema_patterns_use_the_ecmascript_portable_subset() -> None:
    for filename, payload in render_schema_documents().items():
        if filename not in WORKFLOW_SCHEMA_FILES:
            continue
        for node in _walk(json.loads(payload)):
            if not isinstance(node, dict) or not isinstance(node.get("pattern"), str):
                continue
            pattern = node["pattern"]
            assert not any(token in pattern for token in FORBIDDEN_PATTERN_TOKENS)
            re.compile(pattern)


def test_workflow_schema_surface_contains_no_route_or_sensitive_content_slots() -> None:
    properties: set[str] = set()
    for filename, payload in render_schema_documents().items():
        if filename not in WORKFLOW_SCHEMA_FILES:
            continue
        for node in _walk(json.loads(payload)):
            if isinstance(node, dict) and isinstance(node.get("properties"), dict):
                properties.update(node["properties"])
    assert properties.isdisjoint(FORBIDDEN_PROPERTIES)


def test_named_request_semantic_validator_round_trips_and_rejects_extra_route() -> None:
    request = _request()
    parsed = validate_public_document("workflow-runtime-request", request.model_dump_json())
    assert parsed.root == request  # type: ignore[attr-defined]
    values = request.model_dump(mode="json")
    with pytest.raises(ValidationError):
        validate_public_document(
            "workflow-runtime-request",
            json.dumps({**values, "route": "REPORTING"}),
        )


def test_definition_schema_semantic_validator_rejects_content_hash_drift() -> None:
    values = DEFAULT_WORKFLOW_DEFINITION.model_dump(mode="json")
    with pytest.raises(ValidationError):
        validate_public_document(
            "workflow-definition",
            json.dumps({**values, "content_sha256": "b" * 64}),
        )
