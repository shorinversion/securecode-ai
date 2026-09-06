"""P3.8 deterministic replay and metadata-only telemetry contract tests."""

from dataclasses import replace
from typing import Any

import pytest
from securecode_ai.contracts import ModelCallStatus
from securecode_ai.core.investigation_telemetry import (
    InvestigationTelemetry,
    InvestigationTrace,
    NodeKind,
    NodeTelemetry,
    TelemetryUsage,
    TelemetryValidationError,
    replay_trace,
)

H = "a" * 40


def record(**changes: Any) -> InvestigationTelemetry:
    value = InvestigationTelemetry(
        tenant_id="tenant-a",
        run_id="run-1",
        head_sha=H,
        execution_identity_hash="b" * 64,
        provider="fake",
        model="model-1",
        profile="metadata_external",
        prompt_schema_hash="c" * 64,
        output_schema_hash="d" * 64,
        tool_policy_hash="e" * 64,
        evidence_package_hash="f" * 64,
        package_hash="1" * 64,
        route_hash="2" * 64,
        idempotency_key="idem-1",
        attempt=1,
        status=ModelCallStatus.SUCCEEDED,
        usage=TelemetryUsage(calls=1, input_tokens=2),
        latency_ms=10,
        cost_microunits=0,
        node=NodeTelemetry("node-1", NodeKind.INVESTIGATION, 1, ModelCallStatus.SUCCEEDED, 10),
    )
    return replace(value, replay_digest="", **changes)


def test_fake_replay_is_deterministic_and_complete() -> None:
    first = replay_trace((record(),))
    second = replay_trace((record(),))
    assert first.replay_digest == second.replay_digest
    assert first.complete_for(("node-1",))
    assert first.records[0].canonical_bytes() == second.records[0].canonical_bytes()


@pytest.mark.parametrize(
    "field",
    [
        "head_sha",
        "prompt_schema_hash",
        "output_schema_hash",
        "tool_policy_hash",
        "evidence_package_hash",
        "package_hash",
        "route_hash",
        "status",
        "cost_microunits",
    ],
)
def test_replay_digest_changes_for_semantic_pin(field: str) -> None:
    changed = (
        ("3" * 40 if field == "head_sha" else "3" * 64)
        if field != "status" and field != "cost_microunits"
        else (ModelCallStatus.TIMEOUT if field == "status" else 1)
    )
    assert record().replay_digest != record(**{field: changed}).replay_digest


def test_non_success_is_explicit_and_canary_is_absent() -> None:
    failed = record(status=ModelCallStatus.PROVIDER_ERROR)
    payload = failed.canonical_bytes()
    assert not failed.is_success
    assert b"source-canary" not in payload
    assert b"prompt-canary" not in payload
    assert b"model-response-canary" not in payload


def test_negative_cost_and_duplicate_keys_fail_closed() -> None:
    with pytest.raises(TelemetryValidationError):
        record(cost_microunits=-1)
    with pytest.raises(TelemetryValidationError):
        InvestigationTrace((record(), record(idempotency_key="idem-1")))


def test_attempts_are_positive() -> None:
    with pytest.raises(TelemetryValidationError):
        record(attempt=0)
    with pytest.raises(TelemetryValidationError):
        record(
            node=NodeTelemetry("node-1", NodeKind.INVESTIGATION, 0, ModelCallStatus.SUCCEEDED, 10)
        )
