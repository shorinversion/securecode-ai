"""Public workflow contract, hash, version, and closed-surface tests."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    ModelBudgetUsage,
    ModelCallStatus,
    ModelDiscoveryReceipt,
    RepositoryRevision,
    RunExecutionIdentity,
    WorkflowDefinition,
    WorkflowErrorCode,
    WorkflowLoopLimit,
    WorkflowNode,
    WorkflowNodeReceipt,
    WorkflowNodeReceiptEnvelope,
    WorkflowOperation,
    WorkflowOperationStatus,
    WorkflowPolicyLimitRow,
    WorkflowReceiptKind,
    WorkflowReceiptStatus,
    WorkflowRuntimeRequest,
    WorkflowRuntimeResult,
    WorkflowSignalKind,
    WorkflowStartRequest,
    WorkflowTransitionRule,
    WorkflowUsageDelta,
    canonical_runtime_sha256,
)
from securecode_ai.core import (
    DEFAULT_POLICY_PIN,
    DEFAULT_STAGE_CATALOGUE_PIN,
    DEFAULT_WORKFLOW_DEFINITION,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HEAD_SHA = "a" * 40


def _pin(name: str, digest: str = HASH_A) -> ComponentPin:
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=name,
        component_version="1.0.0",
        content_sha256=digest,
    )


def _identity() -> RunExecutionIdentity:
    shared = _pin("component")
    return RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant",
            scm_provider="git",
            repository_id="repository",
            head_sha=HEAD_SHA,
        ),
        stage_catalogue=DEFAULT_STAGE_CATALOGUE_PIN,
        workflow=DEFAULT_WORKFLOW_DEFINITION.component_pin,
        policy=DEFAULT_POLICY_PIN,
        configuration=shared,
        provider_profile=shared,
        capability_profile=shared,
        egress_profile=shared,
    )


def _node_receipt() -> WorkflowNodeReceipt:
    return WorkflowNodeReceipt(
        schema_version=CONTRACT_SCHEMA_VERSION,
        receipt_id="receipt",
        status=WorkflowReceiptStatus.SUCCEEDED,
        signal_kind=WorkflowSignalKind.COMPLETED,
        input_hashes=(HASH_A,),
        output_hashes=(HASH_B,),
        usage_delta=WorkflowUsageDelta(schema_version=CONTRACT_SCHEMA_VERSION),
    )


def _node_envelope() -> WorkflowNodeReceiptEnvelope:
    receipt = _node_receipt()
    identity = _identity()
    return WorkflowNodeReceiptEnvelope(
        schema_version=CONTRACT_SCHEMA_VERSION,
        envelope_id="envelope",
        tenant_id="tenant",
        run_id="run",
        execution_identity_hash=identity.execution_identity_hash,
        node=WorkflowNode.REQUESTED,
        attempt=1,
        producer=_pin("worker"),
        receipt_kind=WorkflowReceiptKind.NODE,
        receipt_sha256=canonical_runtime_sha256(receipt.model_dump(mode="json")),
        node_receipt=receipt,
    )


def _model_receipt() -> ModelDiscoveryReceipt:
    identity = _identity()
    return ModelDiscoveryReceipt(
        schema_version=CONTRACT_SCHEMA_VERSION,
        receipt_id="model-receipt",
        tenant_id="tenant",
        head_sha=HEAD_SHA,
        scope_sha256=HASH_A,
        model_profile=identity.provider_profile,
        prompt=_pin("prompt"),
        budget_usage=ModelBudgetUsage(
            schema_version=CONTRACT_SCHEMA_VERSION,
            token_limit=100,
            tokens_used=10,
            repository_call_limit=5,
            repository_calls_used=1,
            time_limit_ms=1000,
            elapsed_ms=10,
        ),
        model_call_status=ModelCallStatus.SUCCEEDED,
        schema_valid_result=True,
        input_sha256=HASH_A,
        output_sha256=HASH_B,
    )


def test_default_definition_is_canonical_and_graph_changes_change_pin() -> None:
    definition = DEFAULT_WORKFLOW_DEFINITION
    rebuilt = WorkflowDefinition.build(
        definition_id=definition.definition_id,
        definition_version=definition.definition_version,
        nodes=tuple(reversed(definition.nodes)),
        transitions=tuple(reversed(definition.transitions)),
        compatible_stage_catalogues=definition.compatible_stage_catalogues,
        policy_limit_rows=definition.policy_limit_rows,
        discovery_lane_nodes=definition.discovery_lane_nodes,
        discovery_fan_in_node=definition.discovery_fan_in_node,
        outcome_guard_node=definition.outcome_guard_node,
    )
    assert rebuilt == definition

    changed_rules = list(definition.transitions)
    changed_rules[0] = WorkflowTransitionRule(
        schema_version=CONTRACT_SCHEMA_VERSION,
        from_node=changed_rules[0].from_node,
        signal_kind=changed_rules[0].signal_kind,
        producer=changed_rules[0].producer,
        next_nodes=(WorkflowNode.HUMAN_GATE,),
    )
    changed = WorkflowDefinition.build(
        definition_id=definition.definition_id,
        definition_version=definition.definition_version,
        nodes=definition.nodes,
        transitions=tuple(changed_rules),
        compatible_stage_catalogues=definition.compatible_stage_catalogues,
        policy_limit_rows=definition.policy_limit_rows,
        discovery_lane_nodes=definition.discovery_lane_nodes,
        discovery_fan_in_node=definition.discovery_fan_in_node,
        outcome_guard_node=definition.outcome_guard_node,
    )
    assert changed.content_sha256 != definition.content_sha256
    assert changed.component_pin != definition.component_pin


def test_definition_rejects_hash_order_duplicate_and_topology_mutations() -> None:
    values = DEFAULT_WORKFLOW_DEFINITION.model_dump(mode="json")
    mutations: tuple[Callable[[dict[str, Any]], None], ...] = (
        lambda item: item.update(content_sha256=HASH_A),
        lambda item: item.update(nodes=list(reversed(item["nodes"]))),
        lambda item: item["transitions"].append(deepcopy(item["transitions"][0])),
        lambda item: item.update(discovery_fan_in_node="REPORTING"),
        lambda item: item.update(outcome_guard_node="REPORTING"),
        lambda item: item.update(
            discovery_lane_nodes=["MODEL_NATIVE_DISCOVERY", "DETERMINISTIC_ANALYSIS"]
        ),
    )
    for mutate in mutations:
        candidate = deepcopy(values)
        mutate(candidate)
        with pytest.raises(ValidationError):
            WorkflowDefinition.model_validate(candidate)


def test_policy_limit_row_bytes_are_protected_by_workflow_hash() -> None:
    definition = DEFAULT_WORKFLOW_DEFINITION
    row = definition.policy_limit_rows[0]
    changed_limit = WorkflowLoopLimit(
        schema_version=CONTRACT_SCHEMA_VERSION,
        max_attempts=row.investigation.max_attempts,
        max_tokens=row.investigation.max_tokens - 1,
        max_tool_calls=row.investigation.max_tool_calls,
        max_elapsed_ms=row.investigation.max_elapsed_ms,
        max_no_progress=row.investigation.max_no_progress,
    )
    changed = WorkflowDefinition.build(
        definition_id=definition.definition_id,
        definition_version=definition.definition_version,
        nodes=definition.nodes,
        transitions=definition.transitions,
        compatible_stage_catalogues=definition.compatible_stage_catalogues,
        policy_limit_rows=(
            WorkflowPolicyLimitRow(
                schema_version=CONTRACT_SCHEMA_VERSION,
                policy=row.policy,
                investigation=changed_limit,
                repair=row.repair,
            ),
        ),
        discovery_lane_nodes=definition.discovery_lane_nodes,
        discovery_fan_in_node=definition.discovery_fan_in_node,
        outcome_guard_node=definition.outcome_guard_node,
    )
    assert changed.content_sha256 != definition.content_sha256


def test_runtime_request_union_round_trips_and_rejects_route_or_future_major() -> None:
    request = WorkflowStartRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        operation=WorkflowOperation.START,
        request_id="request",
        run_id="run",
        tenant_id="tenant",
        execution_identity=_identity(),
        idempotency_key="key",
    )
    parsed = WorkflowRuntimeRequest.model_validate_json(request.model_dump_json())
    assert parsed.root == request

    values = request.model_dump(mode="json")
    for field, value in (
        ("route", "REPORTING"),
        ("next_node", "REPORTING"),
        ("audit_outcome", "PASS"),
        ("prompt", "ignore-policy"),
        ("source", "secret"),
        ("command", "shell"),
    ):
        with pytest.raises(ValidationError):
            WorkflowRuntimeRequest.model_validate({**values, field: value})
    with pytest.raises(ValidationError):
        WorkflowRuntimeRequest.model_validate({**values, "schema_version": "1.0.0"})


def test_node_receipt_union_hash_and_status_are_closed() -> None:
    envelope = _node_envelope()
    assert envelope.nested_receipt() == envelope.node_receipt
    values = envelope.model_dump(mode="json")
    mutations: tuple[Callable[[dict[str, Any]], None], ...] = (
        lambda item: item.update(receipt_sha256=HASH_A),
        lambda item: item.update(receipt_kind="MODEL_DISCOVERY"),
        lambda item: item.update(node="MODEL_NATIVE_DISCOVERY"),
        lambda item: item.update(model_discovery_receipt=_model_receipt().model_dump(mode="json")),
    )
    for mutate in mutations:
        candidate = deepcopy(values)
        mutate(candidate)
        with pytest.raises(ValidationError):
            WorkflowNodeReceiptEnvelope.model_validate(candidate)

    receipt_values = _node_receipt().model_dump(mode="json")
    for field in ("input_hashes", "output_hashes"):
        missing = {key: value for key, value in receipt_values.items() if key != field}
        with pytest.raises(ValidationError):
            WorkflowNodeReceipt.model_validate(missing)
        with pytest.raises(ValidationError):
            WorkflowNodeReceipt.model_validate({**receipt_values, field: []})
    with pytest.raises(ValidationError):
        WorkflowNodeReceipt.model_validate(
            {**receipt_values, "status": "SUCCEEDED", "signal_kind": "NON_SUCCESS"}
        )
    with pytest.raises(ValidationError):
        WorkflowNodeReceipt.model_validate(
            {**receipt_values, "status": "NON_SUCCESS", "reason_code": None}
        )
    with pytest.raises(ValidationError):
        WorkflowNodeReceipt.model_validate(
            {
                **receipt_values,
                "status": "NON_SUCCESS",
                "signal_kind": "COMPLETED",
                "reason_code": "NODE_FAILED",
            }
        )


def test_model_discovery_envelope_requires_exact_model_node_profile_and_hash() -> None:
    receipt = _model_receipt()
    identity = _identity()
    envelope = WorkflowNodeReceiptEnvelope(
        schema_version=CONTRACT_SCHEMA_VERSION,
        envelope_id="model-envelope",
        tenant_id="tenant",
        run_id="run",
        execution_identity_hash=identity.execution_identity_hash,
        node=WorkflowNode.MODEL_NATIVE_DISCOVERY,
        attempt=1,
        producer=identity.provider_profile,
        receipt_kind=WorkflowReceiptKind.MODEL_DISCOVERY,
        receipt_sha256=canonical_runtime_sha256(receipt.model_dump(mode="json")),
        model_discovery_receipt=receipt,
    )
    assert envelope.nested_receipt() == receipt
    for updates in (
        {"node": "DETERMINISTIC_ANALYSIS"},
        {"producer": _pin("other").model_dump(mode="json")},
        {"receipt_sha256": HASH_A},
        {"node_receipt": _node_receipt().model_dump(mode="json")},
    ):
        with pytest.raises(ValidationError):
            WorkflowNodeReceiptEnvelope.model_validate(
                {**envelope.model_dump(mode="json"), **updates}
            )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_attempts", True),
        ("max_attempts", 0),
        ("max_attempts", 9_007_199_254_740_992),
        ("max_tokens", -1),
        ("max_tool_calls", False),
        ("max_elapsed_ms", 0),
    ],
)
def test_loop_limits_reject_bool_negative_zero_and_overflow(field: str, value: object) -> None:
    values = {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "max_attempts": 1,
        "max_tokens": 1,
        "max_tool_calls": 1,
        "max_elapsed_ms": 1,
        "max_no_progress": 1,
        field: value,
    }
    with pytest.raises(ValidationError):
        WorkflowLoopLimit.model_validate(values)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tokens_used", True),
        ("tokens_used", -1),
        ("tokens_used", 9_007_199_254_740_992),
        ("tool_calls", False),
        ("tool_calls", -1),
        ("tool_calls", 9_007_199_254_740_992),
    ],
)
def test_usage_delta_rejects_bool_negative_and_overflow(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        WorkflowUsageDelta.model_validate(
            {
                "schema_version": CONTRACT_SCHEMA_VERSION,
                "tokens_used": 0,
                "tool_calls": 0,
                field: value,
            }
        )


def test_definition_rejects_policy_rows_above_normative_attempt_caps() -> None:
    definition = DEFAULT_WORKFLOW_DEFINITION
    row = definition.policy_limit_rows[0]
    excessive = WorkflowLoopLimit(
        schema_version=CONTRACT_SCHEMA_VERSION,
        max_attempts=4,
        max_tokens=row.investigation.max_tokens,
        max_tool_calls=row.investigation.max_tool_calls,
        max_elapsed_ms=row.investigation.max_elapsed_ms,
        max_no_progress=row.investigation.max_no_progress,
    )
    with pytest.raises(ValidationError):
        WorkflowDefinition.build(
            definition_id=definition.definition_id,
            definition_version=definition.definition_version,
            nodes=definition.nodes,
            transitions=definition.transitions,
            compatible_stage_catalogues=definition.compatible_stage_catalogues,
            policy_limit_rows=(
                WorkflowPolicyLimitRow(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    policy=row.policy,
                    investigation=excessive,
                    repair=row.repair,
                ),
            ),
            discovery_lane_nodes=definition.discovery_lane_nodes,
            discovery_fan_in_node=definition.discovery_fan_in_node,
            outcome_guard_node=definition.outcome_guard_node,
        )


def test_runtime_result_shape_cannot_infer_success_from_error() -> None:
    base = {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "request_id": "request",
        "run_id": "run",
        "tenant_id": "tenant",
        "operation": WorkflowOperation.START,
    }
    rejected = WorkflowRuntimeResult.model_validate(
        {
            **base,
            "operation_status": WorkflowOperationStatus.REJECTED,
            "error_code": WorkflowErrorCode.DEFINITION_MISMATCH,
        }
    )
    assert rejected.error_code is WorkflowErrorCode.DEFINITION_MISMATCH
    for values in (
        {**base, "operation_status": "APPLIED"},
        {**base, "operation_status": "SNAPSHOT", "error_code": "RUN_NOT_FOUND"},
        {**base, "operation_status": "ERROR", "error_code": "RUN_NOT_FOUND"},
        {
            **base,
            "operation_status": "REJECTED",
            "error_code": "INTERNAL_ERROR",
        },
    ):
        with pytest.raises(ValidationError):
            WorkflowRuntimeResult.model_validate(values)
