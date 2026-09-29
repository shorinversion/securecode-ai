"""Golden LocalRuntime conformance, replay, race, and fail-closed tests."""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Protocol, cast

import pytest
from pydantic import ValidationError
from securecode_ai.adapters import LocalWorkflowRuntime
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    ModelBudgetUsage,
    ModelCallStatus,
    ModelDiscoveryReceipt,
    RepositoryRevision,
    RunExecutionIdentity,
    WorkflowCancelRequest,
    WorkflowControlState,
    WorkflowDefinition,
    WorkflowErrorCode,
    WorkflowExhaustionReason,
    WorkflowLoopKind,
    WorkflowLoopLimit,
    WorkflowNode,
    WorkflowNodeReceipt,
    WorkflowNodeReceiptEnvelope,
    WorkflowOperation,
    WorkflowOperationStatus,
    WorkflowPolicyLimitRow,
    WorkflowReceiptKind,
    WorkflowReceiptStatus,
    WorkflowResumeRequest,
    WorkflowRuntimeResult,
    WorkflowSignalKind,
    WorkflowSignalRequest,
    WorkflowSnapshot,
    WorkflowSnapshotRequest,
    WorkflowStartRequest,
    WorkflowSupersedeRequest,
    WorkflowUsageDelta,
    WorkflowWaitReason,
    canonical_runtime_sha256,
)
from securecode_ai.core import (
    DEFAULT_POLICY_PIN,
    DEFAULT_STAGE_CATALOGUE_PIN,
    DEFAULT_WORKFLOW_DEFINITION,
    DEFAULT_WORKFLOW_REGISTRY,
    WorkflowDecisionError,
    WorkflowDefinitionRegistry,
    WorkflowRuntime,
    replay_workflow_journal,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HEAD_SHA = "a" * 40
NEW_HEAD_SHA = "b" * 40


class RuntimeFactory(Protocol):
    def __call__(self) -> WorkflowRuntime: ...


RUNTIME_FACTORIES: tuple[RuntimeFactory, ...] = (LocalWorkflowRuntime,)


@dataclass(slots=True)
class ManualClock:
    value: int = 1_000

    def __call__(self) -> int:
        return self.value


class ToggleFailureRegistry(WorkflowDefinitionRegistry):
    def __init__(self, canary: str) -> None:
        super().__init__((DEFAULT_WORKFLOW_DEFINITION,))
        self.canary = canary
        self.fail = False

    def resolve(self, identity: RunExecutionIdentity) -> WorkflowDefinition:
        if self.fail:
            raise RuntimeError(self.canary)
        return super().resolve(identity)


def _pin(name: str, digest: str = HASH_A) -> ComponentPin:
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=name,
        component_version="1.0.0",
        content_sha256=digest,
    )


def _identity(
    *,
    tenant_id: str = "tenant",
    workflow: ComponentPin | None = None,
    catalogue: ComponentPin = DEFAULT_STAGE_CATALOGUE_PIN,
    policy: ComponentPin = DEFAULT_POLICY_PIN,
) -> RunExecutionIdentity:
    shared = _pin("component")
    return RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=tenant_id,
            scm_provider="git",
            repository_id="repository",
            head_sha=HEAD_SHA,
        ),
        stage_catalogue=catalogue,
        workflow=workflow or DEFAULT_WORKFLOW_DEFINITION.component_pin,
        policy=policy,
        configuration=shared,
        provider_profile=shared,
        capability_profile=shared,
        egress_profile=shared,
    )


def _start_request(
    identity: RunExecutionIdentity,
    *,
    run_id: str = "run",
    request_id: str = "start-request",
    key: str = "start-key",
) -> WorkflowStartRequest:
    return WorkflowStartRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        operation=WorkflowOperation.START,
        request_id=request_id,
        run_id=run_id,
        tenant_id=identity.repository_revision.tenant_id,
        execution_identity=identity,
        idempotency_key=key,
    )


def _start(
    runtime: WorkflowRuntime,
    identity: RunExecutionIdentity | None = None,
    *,
    run_id: str = "run",
) -> WorkflowRuntimeResult:
    result = runtime.start(_start_request(identity or _identity(), run_id=run_id))
    assert result.operation_status is WorkflowOperationStatus.APPLIED
    assert result.snapshot is not None
    assert result.transition_event is not None
    assert result.transition_event.input_hashes and result.transition_event.output_hashes
    return result


def _node_envelope(
    snapshot: WorkflowSnapshot,
    signal: WorkflowSignalKind,
    *,
    status: WorkflowReceiptStatus = WorkflowReceiptStatus.SUCCEEDED,
    output_hashes: tuple[str, ...] = (HASH_B,),
    tokens: int = 0,
    tools: int = 0,
    suffix: str = "x",
) -> WorkflowNodeReceiptEnvelope:
    node = snapshot.active_nodes[0]
    attempt = next(item.attempt for item in snapshot.node_attempts if item.node is node)
    receipt = WorkflowNodeReceipt(
        schema_version=CONTRACT_SCHEMA_VERSION,
        receipt_id=f"receipt-{suffix}",
        status=status,
        signal_kind=signal,
        input_hashes=(HASH_A,),
        output_hashes=output_hashes,
        usage_delta=WorkflowUsageDelta(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tokens_used=tokens,
            tool_calls=tools,
        ),
        reason_code=None if status is WorkflowReceiptStatus.SUCCEEDED else "NODE_FAILED",
    )
    return WorkflowNodeReceiptEnvelope(
        schema_version=CONTRACT_SCHEMA_VERSION,
        envelope_id=f"envelope-{suffix}",
        tenant_id=snapshot.tenant_id,
        run_id=snapshot.run_id,
        execution_identity_hash=snapshot.execution_identity.execution_identity_hash,
        node=node,
        attempt=attempt,
        producer=_pin("worker"),
        receipt_kind=WorkflowReceiptKind.NODE,
        receipt_sha256=canonical_runtime_sha256(receipt.model_dump(mode="json")),
        node_receipt=receipt,
    )


def _model_envelope(
    snapshot: WorkflowSnapshot,
    *,
    status: ModelCallStatus = ModelCallStatus.SUCCEEDED,
    candidates: tuple[str, ...] = (),
    suffix: str = "model",
) -> WorkflowNodeReceiptEnvelope:
    assert WorkflowNode.MODEL_NATIVE_DISCOVERY in snapshot.active_nodes
    attempt = next(
        item.attempt
        for item in snapshot.node_attempts
        if item.node is WorkflowNode.MODEL_NATIVE_DISCOVERY
    )
    succeeded = status is ModelCallStatus.SUCCEEDED
    receipt = ModelDiscoveryReceipt(
        schema_version=CONTRACT_SCHEMA_VERSION,
        receipt_id=f"receipt-{suffix}",
        tenant_id=snapshot.tenant_id,
        head_sha=snapshot.execution_identity.repository_revision.head_sha,
        scope_sha256=HASH_A,
        model_profile=snapshot.execution_identity.provider_profile,
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
        model_call_status=status,
        schema_valid_result=succeeded,
        input_sha256=HASH_A,
        output_sha256=HASH_B if succeeded else None,
        candidate_ids=candidates if succeeded else (),
    )
    return WorkflowNodeReceiptEnvelope(
        schema_version=CONTRACT_SCHEMA_VERSION,
        envelope_id=f"envelope-{suffix}",
        tenant_id=snapshot.tenant_id,
        run_id=snapshot.run_id,
        execution_identity_hash=snapshot.execution_identity.execution_identity_hash,
        node=WorkflowNode.MODEL_NATIVE_DISCOVERY,
        attempt=attempt,
        producer=snapshot.execution_identity.provider_profile,
        receipt_kind=WorkflowReceiptKind.MODEL_DISCOVERY,
        receipt_sha256=canonical_runtime_sha256(receipt.model_dump(mode="json")),
        model_discovery_receipt=receipt,
    )


def _signal_request(
    snapshot: WorkflowSnapshot,
    envelope: WorkflowNodeReceiptEnvelope,
    *,
    key: str,
    request_id: str | None = None,
) -> WorkflowSignalRequest:
    return WorkflowSignalRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        operation=WorkflowOperation.SIGNAL,
        request_id=request_id or f"request-{key}",
        run_id=snapshot.run_id,
        tenant_id=snapshot.tenant_id,
        execution_identity=snapshot.execution_identity,
        idempotency_key=key,
        expected_sequence=snapshot.journal_sequence,
        expected_journal_head_sha256=snapshot.journal_head_sha256,
        expected_state_sha256=snapshot.state_sha256,
        receipt=envelope,
    )


def _cancel_request(
    snapshot: WorkflowSnapshot,
    *,
    key: str = "cancel",
    request_id: str = "cancel-request",
) -> WorkflowCancelRequest:
    return WorkflowCancelRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        operation=WorkflowOperation.CANCEL,
        request_id=request_id,
        run_id=snapshot.run_id,
        tenant_id=snapshot.tenant_id,
        execution_identity=snapshot.execution_identity,
        idempotency_key=key,
        expected_sequence=snapshot.journal_sequence,
        expected_journal_head_sha256=snapshot.journal_head_sha256,
        expected_state_sha256=snapshot.state_sha256,
    )


def _supersede_request(
    snapshot: WorkflowSnapshot,
    *,
    key: str = "supersede",
    request_id: str = "supersede-request",
) -> WorkflowSupersedeRequest:
    return WorkflowSupersedeRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        operation=WorkflowOperation.SUPERSEDE,
        request_id=request_id,
        run_id=snapshot.run_id,
        tenant_id=snapshot.tenant_id,
        execution_identity=snapshot.execution_identity,
        idempotency_key=key,
        expected_sequence=snapshot.journal_sequence,
        expected_journal_head_sha256=snapshot.journal_head_sha256,
        expected_state_sha256=snapshot.state_sha256,
        superseding_head_sha=NEW_HEAD_SHA,
    )


def _read_snapshot(
    runtime: WorkflowRuntime,
    snapshot: WorkflowSnapshot,
    *,
    request_id: str,
) -> WorkflowRuntimeResult:
    return runtime.snapshot(
        WorkflowSnapshotRequest(
            schema_version=CONTRACT_SCHEMA_VERSION,
            operation=WorkflowOperation.SNAPSHOT,
            request_id=request_id,
            run_id=snapshot.run_id,
            tenant_id=snapshot.tenant_id,
            execution_identity=snapshot.execution_identity,
            expected_sequence=snapshot.journal_sequence,
            expected_journal_head_sha256=snapshot.journal_head_sha256,
            expected_state_sha256=snapshot.state_sha256,
        )
    )


def _signal(
    runtime: WorkflowRuntime,
    result: WorkflowRuntimeResult,
    signal: WorkflowSignalKind,
    *,
    key: str,
    status: WorkflowReceiptStatus = WorkflowReceiptStatus.SUCCEEDED,
    output_hashes: tuple[str, ...] = (HASH_B,),
    tokens: int = 0,
    tools: int = 0,
    receipt_suffix: str | None = None,
) -> WorkflowRuntimeResult:
    assert result.snapshot is not None
    envelope = _node_envelope(
        result.snapshot,
        signal,
        status=status,
        output_hashes=output_hashes,
        tokens=tokens,
        tools=tools,
        suffix=receipt_suffix or key,
    )
    next_result = runtime.signal(_signal_request(result.snapshot, envelope, key=key))
    assert next_result.operation_status is WorkflowOperationStatus.APPLIED
    assert next_result.snapshot is not None
    assert next_result.transition_event is not None
    assert next_result.transition_event.input_hashes and next_result.transition_event.output_hashes
    return next_result


def _to_discovery_fork(
    runtime: WorkflowRuntime,
    identity: RunExecutionIdentity | None = None,
) -> WorkflowRuntimeResult:
    result = _start(runtime, identity)
    for index in range(4):
        result = _signal(runtime, result, WorkflowSignalKind.COMPLETED, key=f"prefix-{index}")
    assert result.snapshot is not None
    assert result.snapshot.active_nodes == (
        WorkflowNode.DETERMINISTIC_ANALYSIS,
        WorkflowNode.MODEL_NATIVE_DISCOVERY,
    )
    return result


def _resolve_discovery(
    runtime: WorkflowRuntime,
    result: WorkflowRuntimeResult,
    *,
    candidates: bool,
    model_status: ModelCallStatus = ModelCallStatus.SUCCEEDED,
) -> WorkflowRuntimeResult:
    assert result.snapshot is not None
    deterministic = _node_envelope(
        result.snapshot.model_copy(update={"active_nodes": (WorkflowNode.DETERMINISTIC_ANALYSIS,)}),
        (
            WorkflowSignalKind.COMPLETED_WITH_CANDIDATES
            if candidates
            else WorkflowSignalKind.COMPLETED_ZERO
        ),
        suffix="deterministic",
    )
    result = runtime.signal(
        _signal_request(result.snapshot, deterministic, key="deterministic-lane")
    )
    assert result.snapshot is not None
    assert result.snapshot.active_nodes == (WorkflowNode.MODEL_NATIVE_DISCOVERY,)
    model = _model_envelope(
        result.snapshot,
        status=model_status,
        candidates=("candidate",)
        if candidates and model_status is ModelCallStatus.SUCCEEDED
        else (),
    )
    result = runtime.signal(_signal_request(result.snapshot, model, key="model-lane"))
    assert result.snapshot is not None
    assert result.snapshot.active_nodes == (WorkflowNode.NORMALIZATION,)
    return result


def _to_auditor(
    runtime: WorkflowRuntime,
    identity: RunExecutionIdentity | None = None,
) -> WorkflowRuntimeResult:
    result = _resolve_discovery(
        runtime,
        _to_discovery_fork(runtime, identity),
        candidates=True,
    )
    result = _signal(
        runtime,
        result,
        WorkflowSignalKind.COMPLETED_WITH_CANDIDATES,
        key="normalize-candidates",
    )
    result = _signal(runtime, result, WorkflowSignalKind.COMPLETED, key="evidence")
    assert result.snapshot is not None
    assert result.snapshot.active_nodes == (WorkflowNode.AUDITOR_INVESTIGATION,)
    return result


@pytest.mark.parametrize("factory", RUNTIME_FACTORIES)
def test_golden_zero_candidate_route_requires_both_lanes(factory: RuntimeFactory) -> None:
    runtime = factory()
    result = _to_discovery_fork(runtime)
    result = _resolve_discovery(runtime, result, candidates=False)
    assert result.snapshot is not None
    assert all(item.resolved and item.satisfied for item in result.snapshot.lane_resolutions)
    result = _signal(
        runtime,
        result,
        WorkflowSignalKind.COMPLETED_ZERO,
        key="normalize-zero",
    )
    assert result.snapshot is not None
    assert result.snapshot.active_nodes == (WorkflowNode.COVERAGE_GUARD,)
    assert result.snapshot.wait_reason is WorkflowWaitReason.WAITING_FOR_TRUSTED_OUTCOME_GUARD
    assert WorkflowNode.REPORTING not in result.snapshot.active_nodes


@pytest.mark.parametrize("factory", RUNTIME_FACTORIES)
@pytest.mark.parametrize(
    "model_status",
    tuple(status for status in ModelCallStatus if status is not ModelCallStatus.SUCCEEDED),
)
def test_deterministic_zero_never_skips_model_native_and_model_failure_is_unsatisfied(
    factory: RuntimeFactory,
    model_status: ModelCallStatus,
) -> None:
    runtime = factory()
    result = _to_discovery_fork(runtime)
    assert result.snapshot is not None
    deterministic = _node_envelope(
        result.snapshot.model_copy(update={"active_nodes": (WorkflowNode.DETERMINISTIC_ANALYSIS,)}),
        WorkflowSignalKind.COMPLETED_ZERO,
        suffix="det-zero",
    )
    result = runtime.signal(_signal_request(result.snapshot, deterministic, key="det-zero"))
    assert result.snapshot is not None
    assert result.snapshot.active_nodes == (WorkflowNode.MODEL_NATIVE_DISCOVERY,)
    model = _model_envelope(result.snapshot, status=model_status)
    result = runtime.signal(_signal_request(result.snapshot, model, key="model-refused"))
    assert result.snapshot is not None and result.transition_event is not None
    assert result.transition_event.output_hashes == (model.receipt_sha256,)
    model_lane = result.snapshot.lane_resolutions[1]
    assert model_lane.resolved and not model_lane.satisfied
    assert model_lane.model_call_status is model_status
    assert result.snapshot.active_nodes == (WorkflowNode.NORMALIZATION,)


@pytest.mark.parametrize("factory", RUNTIME_FACTORIES)
def test_confirmed_finding_without_repair_and_rejected_routes_reach_guard(
    factory: RuntimeFactory,
) -> None:
    for gate_signal in (
        WorkflowSignalKind.REJECTED_WITH_EVIDENCE,
        WorkflowSignalKind.CONFIRMED_NO_REPAIR,
    ):
        runtime = factory()
        result = _to_auditor(runtime)
        result = _signal(runtime, result, WorkflowSignalKind.COMPLETED, key="auditor")
        result = _signal(runtime, result, WorkflowSignalKind.COMPLETED, key="skeptic")
        result = _signal(runtime, result, gate_signal, key=f"gate-{gate_signal.value}")
        assert result.snapshot is not None
        assert result.snapshot.active_nodes == (WorkflowNode.COVERAGE_GUARD,)


@pytest.mark.parametrize("factory", RUNTIME_FACTORIES)
def test_repair_route_reaches_validation_human_and_guard(factory: RuntimeFactory) -> None:
    runtime = factory()
    result = _to_auditor(runtime)
    for signal, key in (
        (WorkflowSignalKind.COMPLETED, "auditor"),
        (WorkflowSignalKind.COMPLETED, "skeptic"),
        (WorkflowSignalKind.CONFIRMED_REPAIR_REQUESTED, "finding"),
        (WorkflowSignalKind.COMPLETED, "root-cause"),
        (WorkflowSignalKind.COMPLETED, "security-test"),
        (WorkflowSignalKind.COMPLETED, "architect"),
        (WorkflowSignalKind.VALIDATED, "validation"),
        (WorkflowSignalKind.HUMAN_APPROVED, "human"),
    ):
        result = _signal(runtime, result, signal, key=key)
    assert result.snapshot is not None
    assert result.snapshot.active_nodes == (WorkflowNode.COVERAGE_GUARD,)


@pytest.mark.parametrize("factory", RUNTIME_FACTORIES)
def test_investigation_retry_exhausts_at_inclusive_attempt_limit(
    factory: RuntimeFactory,
) -> None:
    runtime = factory()
    result = _to_auditor(runtime)
    result = _signal(
        runtime,
        result,
        WorkflowSignalKind.RETRYABLE_FAILURE,
        key="retry-1",
        status=WorkflowReceiptStatus.NON_SUCCESS,
        output_hashes=(HASH_C,),
    )
    assert result.snapshot is not None
    assert result.snapshot.active_nodes == (WorkflowNode.AUDITOR_INVESTIGATION,)
    result = _signal(
        runtime,
        result,
        WorkflowSignalKind.RETRYABLE_FAILURE,
        key="retry-2",
        status=WorkflowReceiptStatus.NON_SUCCESS,
        output_hashes=(HASH_C,),
    )
    assert result.snapshot is not None and result.transition_event is not None
    assert result.snapshot.active_nodes == (WorkflowNode.AUDITOR_INVESTIGATION,)
    result = _signal(
        runtime,
        result,
        WorkflowSignalKind.RETRYABLE_FAILURE,
        key="retry-3",
        status=WorkflowReceiptStatus.NON_SUCCESS,
        output_hashes=(HASH_C,),
    )
    assert result.snapshot is not None and result.transition_event is not None
    assert result.snapshot.active_nodes == (WorkflowNode.HUMAN_GATE,)
    assert result.transition_event.exhaustion_reason is WorkflowExhaustionReason.ATTEMPTS
    usage = result.snapshot.loop_usage[0]
    assert usage.attempts == 3 and usage.no_progress_count == 0


def _definition_with_limit(
    investigation: WorkflowLoopLimit | None = None,
    repair: WorkflowLoopLimit | None = None,
) -> WorkflowDefinition:
    base = DEFAULT_WORKFLOW_DEFINITION
    row = base.policy_limit_rows[0]
    return WorkflowDefinition.build(
        definition_id=base.definition_id,
        definition_version=base.definition_version,
        nodes=base.nodes,
        transitions=base.transitions,
        compatible_stage_catalogues=base.compatible_stage_catalogues,
        policy_limit_rows=(
            WorkflowPolicyLimitRow(
                schema_version=CONTRACT_SCHEMA_VERSION,
                policy=row.policy,
                investigation=investigation or row.investigation,
                repair=repair or row.repair,
            ),
        ),
        discovery_lane_nodes=base.discovery_lane_nodes,
        discovery_fan_in_node=base.discovery_fan_in_node,
        outcome_guard_node=base.outcome_guard_node,
    )


def test_simultaneous_loop_exhaustion_has_fixed_time_first_precedence() -> None:
    limit = WorkflowLoopLimit(
        schema_version=CONTRACT_SCHEMA_VERSION,
        max_attempts=1,
        max_tokens=1,
        max_tool_calls=1,
        max_elapsed_ms=1,
        max_no_progress=1,
    )
    definition = _definition_with_limit(investigation=limit)
    registry = WorkflowDefinitionRegistry((definition,))
    clock = ManualClock()
    identity = _identity(workflow=definition.component_pin)
    runtime = LocalWorkflowRuntime(registry=registry, clock=clock)
    result = _start(runtime, identity)
    for index in range(4):
        result = _signal(runtime, result, WorkflowSignalKind.COMPLETED, key=f"p-{index}")
    result = _resolve_discovery(runtime, result, candidates=True)
    result = _signal(
        runtime,
        result,
        WorkflowSignalKind.COMPLETED_WITH_CANDIDATES,
        key="normalize",
    )
    result = _signal(runtime, result, WorkflowSignalKind.COMPLETED, key="evidence")
    clock.value += 10
    result = _signal(
        runtime,
        result,
        WorkflowSignalKind.RETRYABLE_FAILURE,
        key="all-limits",
        status=WorkflowReceiptStatus.NON_SUCCESS,
        tokens=1,
        tools=1,
    )
    assert result.transition_event is not None
    assert result.transition_event.exhaustion_reason is WorkflowExhaustionReason.TIME


@pytest.mark.parametrize(
    ("limit", "tokens", "tools", "expected"),
    [
        ((1, 1, 1, 100_000), 1, 1, WorkflowExhaustionReason.TOKENS),
        ((1, 100, 1, 100_000), 0, 1, WorkflowExhaustionReason.TOOL_CALLS),
        ((1, 100, 100, 100_000), 0, 0, WorkflowExhaustionReason.ATTEMPTS),
    ],
)
def test_loop_exhaustion_priority_after_time_is_deterministic(
    limit: tuple[int, int, int, int],
    tokens: int,
    tools: int,
    expected: WorkflowExhaustionReason,
) -> None:
    attempts, token_limit, tool_limit, elapsed_limit = limit
    definition = _definition_with_limit(
        investigation=WorkflowLoopLimit(
            schema_version=CONTRACT_SCHEMA_VERSION,
            max_attempts=attempts,
            max_tokens=token_limit,
            max_tool_calls=tool_limit,
            max_elapsed_ms=elapsed_limit,
            max_no_progress=2,
        )
    )
    runtime = LocalWorkflowRuntime(
        registry=WorkflowDefinitionRegistry((definition,)),
        clock=ManualClock(),
    )
    result = _start(runtime, _identity(workflow=definition.component_pin))
    for index in range(4):
        result = _signal(runtime, result, WorkflowSignalKind.COMPLETED, key=f"q-{index}")
    result = _resolve_discovery(runtime, result, candidates=True)
    result = _signal(
        runtime,
        result,
        WorkflowSignalKind.COMPLETED_WITH_CANDIDATES,
        key="q-normalize",
    )
    result = _signal(runtime, result, WorkflowSignalKind.COMPLETED, key="q-evidence")
    result = _signal(
        runtime,
        result,
        WorkflowSignalKind.RETRYABLE_FAILURE,
        key="q-retry",
        status=WorkflowReceiptStatus.NON_SUCCESS,
        tokens=tokens,
        tools=tools,
    )
    assert result.transition_event is not None
    assert result.transition_event.exhaustion_reason is expected


EXHAUSTION_PRECEDENCE = (
    WorkflowExhaustionReason.TIME,
    WorkflowExhaustionReason.TOKENS,
    WorkflowExhaustionReason.TOOL_CALLS,
    WorkflowExhaustionReason.ATTEMPTS,
    WorkflowExhaustionReason.NO_PROGRESS,
)


@pytest.mark.parametrize("mask", range(1, 1 << len(EXHAUSTION_PRECEDENCE)))
def test_every_simultaneous_exhaustion_combination_uses_fixed_precedence(mask: int) -> None:
    enabled = {reason for index, reason in enumerate(EXHAUSTION_PRECEDENCE) if mask & (1 << index)}
    limit = WorkflowLoopLimit(
        schema_version=CONTRACT_SCHEMA_VERSION,
        max_attempts=2 if WorkflowExhaustionReason.ATTEMPTS in enabled else 3,
        max_tokens=2 if WorkflowExhaustionReason.TOKENS in enabled else 100,
        max_tool_calls=2 if WorkflowExhaustionReason.TOOL_CALLS in enabled else 100,
        max_elapsed_ms=10 if WorkflowExhaustionReason.TIME in enabled else 100_000,
        max_no_progress=1 if WorkflowExhaustionReason.NO_PROGRESS in enabled else 2,
    )
    definition = _definition_with_limit(investigation=limit)
    clock = ManualClock()
    runtime = LocalWorkflowRuntime(
        registry=WorkflowDefinitionRegistry((definition,)),
        clock=clock,
    )
    identity = _identity(workflow=definition.component_pin)
    result = _to_auditor(runtime, identity)
    result = _signal(
        runtime,
        result,
        WorkflowSignalKind.RETRYABLE_FAILURE,
        key="matrix-retry-1",
        status=WorkflowReceiptStatus.NON_SUCCESS,
        output_hashes=(HASH_C,),
        tokens=1,
        tools=1,
        receipt_suffix="matrix-same-receipt",
    )
    assert result.snapshot is not None
    assert result.snapshot.active_nodes == (WorkflowNode.AUDITOR_INVESTIGATION,)
    if WorkflowExhaustionReason.TIME in enabled:
        clock.value += 10
    result = _signal(
        runtime,
        result,
        WorkflowSignalKind.RETRYABLE_FAILURE,
        key="matrix-retry-2",
        status=WorkflowReceiptStatus.NON_SUCCESS,
        output_hashes=(HASH_C,),
        tokens=1,
        tools=1,
        receipt_suffix="matrix-same-receipt",
    )
    assert result.transition_event is not None
    assert result.transition_event.exhaustion_reason is next(
        reason for reason in EXHAUSTION_PRECEDENCE if reason in enabled
    )


@pytest.mark.parametrize("same_receipt", [True, False])
def test_repair_loop_no_progress_uses_active_receipt_and_output_fingerprint(
    same_receipt: bool,
) -> None:
    repair_limit = WorkflowLoopLimit(
        schema_version=CONTRACT_SCHEMA_VERSION,
        max_attempts=3,
        max_tokens=100,
        max_tool_calls=100,
        max_elapsed_ms=100_000,
        max_no_progress=1,
    )
    definition = _definition_with_limit(repair=repair_limit)
    runtime = LocalWorkflowRuntime(registry=WorkflowDefinitionRegistry((definition,)))
    result = _start(runtime, _identity(workflow=definition.component_pin))
    for index in range(4):
        result = _signal(runtime, result, WorkflowSignalKind.COMPLETED, key=f"r-{index}")
    result = _resolve_discovery(runtime, result, candidates=True)
    for signal, key in (
        (WorkflowSignalKind.COMPLETED_WITH_CANDIDATES, "r-normalize"),
        (WorkflowSignalKind.COMPLETED, "r-evidence"),
        (WorkflowSignalKind.COMPLETED, "r-auditor"),
        (WorkflowSignalKind.COMPLETED, "r-skeptic"),
        (WorkflowSignalKind.CONFIRMED_REPAIR_REQUESTED, "r-finding"),
        (WorkflowSignalKind.COMPLETED, "r-root"),
        (WorkflowSignalKind.COMPLETED, "r-test"),
        (WorkflowSignalKind.COMPLETED, "r-architect-1"),
    ):
        result = _signal(runtime, result, signal, key=key)
    result = _signal(
        runtime,
        result,
        WorkflowSignalKind.VALIDATION_FAILED,
        key="r-validation-1",
        status=WorkflowReceiptStatus.NON_SUCCESS,
        output_hashes=(HASH_C,),
        receipt_suffix="same-validation-failure" if same_receipt else "validation-failure-1",
    )
    result = _signal(runtime, result, WorkflowSignalKind.COMPLETED, key="r-architect-2")
    result = _signal(
        runtime,
        result,
        WorkflowSignalKind.VALIDATION_FAILED,
        key="r-validation-2",
        status=WorkflowReceiptStatus.NON_SUCCESS,
        output_hashes=(HASH_C,),
        receipt_suffix="same-validation-failure" if same_receipt else "validation-failure-2",
    )
    assert result.transition_event is not None and result.snapshot is not None
    assert result.transition_event.exhaustion_reason is (
        WorkflowExhaustionReason.NO_PROGRESS if same_receipt else None
    )
    assert result.snapshot.active_nodes == (
        (WorkflowNode.HUMAN_GATE,) if same_receipt else (WorkflowNode.ARCHITECT,)
    )


def test_repair_budget_accumulates_architect_usage_before_retry_boundary() -> None:
    repair_limit = WorkflowLoopLimit(
        schema_version=CONTRACT_SCHEMA_VERSION,
        max_attempts=3,
        max_tokens=1,
        max_tool_calls=100,
        max_elapsed_ms=100_000,
        max_no_progress=2,
    )
    definition = _definition_with_limit(repair=repair_limit)
    runtime = LocalWorkflowRuntime(registry=WorkflowDefinitionRegistry((definition,)))
    result = _start(runtime, _identity(workflow=definition.component_pin))
    for index in range(4):
        result = _signal(runtime, result, WorkflowSignalKind.COMPLETED, key=f"b-{index}")
    result = _resolve_discovery(runtime, result, candidates=True)
    for signal, key in (
        (WorkflowSignalKind.COMPLETED_WITH_CANDIDATES, "b-normalize"),
        (WorkflowSignalKind.COMPLETED, "b-evidence"),
        (WorkflowSignalKind.COMPLETED, "b-auditor"),
        (WorkflowSignalKind.COMPLETED, "b-skeptic"),
        (WorkflowSignalKind.CONFIRMED_REPAIR_REQUESTED, "b-finding"),
        (WorkflowSignalKind.COMPLETED, "b-root"),
        (WorkflowSignalKind.COMPLETED, "b-test"),
    ):
        result = _signal(runtime, result, signal, key=key)

    result = _signal(
        runtime,
        result,
        WorkflowSignalKind.COMPLETED,
        key="b-architect",
        tokens=1,
    )
    assert result.snapshot is not None
    repair_usage = next(
        item for item in result.snapshot.loop_usage if item.loop_kind is WorkflowLoopKind.REPAIR
    )
    assert repair_usage.tokens_used == 1 and repair_usage.attempts == 0

    result = _signal(
        runtime,
        result,
        WorkflowSignalKind.VALIDATION_FAILED,
        key="b-validation",
        status=WorkflowReceiptStatus.NON_SUCCESS,
    )
    assert result.transition_event is not None and result.snapshot is not None
    assert result.transition_event.exhaustion_reason is WorkflowExhaustionReason.TOKENS
    assert result.snapshot.active_nodes == (WorkflowNode.HUMAN_GATE,)


@pytest.mark.parametrize("factory", RUNTIME_FACTORIES)
def test_exact_replay_precedes_terminal_and_cross_operation_reuse_conflicts(
    factory: RuntimeFactory,
) -> None:
    runtime = factory()
    start_request = _start_request(_identity(), key="shared-key")
    start_result = runtime.start(start_request)
    assert start_result.snapshot is not None
    cancel = WorkflowCancelRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        operation=WorkflowOperation.CANCEL,
        request_id="cancel",
        run_id="run",
        tenant_id="tenant",
        execution_identity=start_result.snapshot.execution_identity,
        idempotency_key="cancel-key",
        expected_sequence=start_result.snapshot.journal_sequence,
        expected_journal_head_sha256=start_result.snapshot.journal_head_sha256,
        expected_state_sha256=start_result.snapshot.state_sha256,
    )
    cancelled = runtime.cancel(cancel)
    assert cancelled.operation_status is WorkflowOperationStatus.APPLIED
    replayed_start = runtime.start(start_request)
    assert replayed_start == start_result
    assert replayed_start.model_dump_json() == start_result.model_dump_json()

    conflict = cancel.model_copy(update={"idempotency_key": "shared-key"})
    conflict_result = runtime.cancel(conflict)
    assert conflict_result.error_code is WorkflowErrorCode.IDEMPOTENCY_CONFLICT
    assert conflict_result.transition_event is None


@pytest.mark.parametrize("factory", RUNTIME_FACTORIES)
def test_duplicate_start_different_key_and_semantic_key_conflict_are_stable(
    factory: RuntimeFactory,
) -> None:
    runtime = factory()
    identity = _identity()
    first = runtime.start(_start_request(identity))
    duplicate_request = _start_request(identity, request_id="duplicate", key="other-key")
    duplicate = runtime.start(duplicate_request)
    assert duplicate.error_code is WorkflowErrorCode.RUN_ALREADY_EXISTS
    replayed_duplicate = runtime.start(duplicate_request)
    assert replayed_duplicate == duplicate
    assert replayed_duplicate.model_dump_json() == duplicate.model_dump_json()

    conflict_request = _start_request(identity, request_id="changed", key="start-key")
    conflict = runtime.start(conflict_request)
    assert conflict.error_code is WorkflowErrorCode.IDEMPOTENCY_CONFLICT
    assert first.snapshot is not None and first.snapshot.journal_sequence == 1


@pytest.mark.parametrize("factory", RUNTIME_FACTORIES)
def test_stale_cas_illegal_signal_and_terminal_precedence_add_no_transition(
    factory: RuntimeFactory,
) -> None:
    runtime = factory()
    started = _start(runtime)
    assert started.snapshot is not None
    envelope = _node_envelope(started.snapshot, WorkflowSignalKind.COMPLETED, suffix="valid")
    stale = _signal_request(started.snapshot, envelope, key="stale").model_copy(
        update={"expected_sequence": started.snapshot.journal_sequence + 1}
    )
    assert runtime.signal(stale).error_code is WorkflowErrorCode.STALE_PRECONDITION

    illegal_envelope = envelope.model_copy(update={"node": WorkflowNode.REPORTING})
    illegal = _signal_request(started.snapshot, illegal_envelope, key="illegal")
    assert runtime.signal(illegal).error_code is WorkflowErrorCode.ILLEGAL_OPERATION

    cancel = WorkflowCancelRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        operation=WorkflowOperation.CANCEL,
        request_id="cancel",
        run_id="run",
        tenant_id="tenant",
        execution_identity=started.snapshot.execution_identity,
        idempotency_key="cancel",
        expected_sequence=started.snapshot.journal_sequence,
        expected_journal_head_sha256=started.snapshot.journal_head_sha256,
        expected_state_sha256=started.snapshot.state_sha256,
    )
    cancelled = runtime.cancel(cancel)
    assert cancelled.snapshot is not None
    terminal_stale = cancel.model_copy(
        update={"request_id": "later", "idempotency_key": "later", "expected_sequence": 999}
    )
    assert runtime.cancel(terminal_stale).error_code is WorkflowErrorCode.TERMINAL_STATE
    replayed_cancel = runtime.cancel(cancel)
    assert replayed_cancel == cancelled
    assert replayed_cancel.model_dump_json() == cancelled.model_dump_json()


@pytest.mark.parametrize("factory", RUNTIME_FACTORIES)
def test_supersede_is_terminal_and_keeps_admitted_identity(factory: RuntimeFactory) -> None:
    runtime = factory()
    started = _start(runtime)
    assert started.snapshot is not None
    request = WorkflowSupersedeRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        operation=WorkflowOperation.SUPERSEDE,
        request_id="supersede",
        run_id="run",
        tenant_id="tenant",
        execution_identity=started.snapshot.execution_identity,
        idempotency_key="supersede",
        expected_sequence=started.snapshot.journal_sequence,
        expected_journal_head_sha256=started.snapshot.journal_head_sha256,
        expected_state_sha256=started.snapshot.state_sha256,
        superseding_head_sha=NEW_HEAD_SHA,
    )
    result = runtime.supersede(request)
    assert result.snapshot is not None and result.transition_event is not None
    assert result.snapshot.control_state is WorkflowControlState.SUPERSEDED
    assert result.snapshot.execution_identity == started.snapshot.execution_identity
    assert result.transition_event.superseding_head_sha == NEW_HEAD_SHA


def test_cancel_and_supersede_same_cas_race_has_one_terminal_transition() -> None:
    runtime = LocalWorkflowRuntime()
    started = _start(runtime)
    assert started.snapshot is not None
    snapshot = started.snapshot
    cancel = WorkflowCancelRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        operation=WorkflowOperation.CANCEL,
        request_id="cancel-race",
        run_id="run",
        tenant_id="tenant",
        execution_identity=snapshot.execution_identity,
        idempotency_key="cancel-race",
        expected_sequence=snapshot.journal_sequence,
        expected_journal_head_sha256=snapshot.journal_head_sha256,
        expected_state_sha256=snapshot.state_sha256,
    )
    supersede = WorkflowSupersedeRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        operation=WorkflowOperation.SUPERSEDE,
        request_id="supersede-race",
        run_id="run",
        tenant_id="tenant",
        execution_identity=snapshot.execution_identity,
        idempotency_key="supersede-race",
        expected_sequence=snapshot.journal_sequence,
        expected_journal_head_sha256=snapshot.journal_head_sha256,
        expected_state_sha256=snapshot.state_sha256,
        superseding_head_sha=NEW_HEAD_SHA,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (
            executor.submit(runtime.cancel, cancel),
            executor.submit(runtime.supersede, supersede),
        )
        results = tuple(future.result() for future in futures)
    assert (
        sum(result.operation_status is WorkflowOperationStatus.APPLIED for result in results) == 1
    )
    assert sum(result.error_code is WorkflowErrorCode.TERMINAL_STATE for result in results) == 1
    applied = next(result for result in results if result.snapshot is not None)
    assert applied.snapshot is not None
    assert applied.snapshot.control_state in {
        WorkflowControlState.CANCELLED,
        WorkflowControlState.SUPERSEDED,
    }


@pytest.mark.parametrize("mutation", ["workflow", "catalogue", "policy"])
def test_unknown_definition_catalogue_or_policy_pin_rejects_before_genesis(mutation: str) -> None:
    baseline = _identity()
    identity = _identity(
        workflow=(_pin("unknown-workflow") if mutation == "workflow" else baseline.workflow),
        catalogue=(
            _pin("unknown-catalogue") if mutation == "catalogue" else baseline.stage_catalogue
        ),
        policy=_pin("unknown-policy") if mutation == "policy" else baseline.policy,
    )
    result = LocalWorkflowRuntime().start(_start_request(identity))
    assert result.error_code is WorkflowErrorCode.DEFINITION_MISMATCH
    assert result.snapshot is None and result.transition_event is None


@pytest.mark.parametrize("component", ["workflow", "catalogue", "policy"])
@pytest.mark.parametrize("field", ["component_id", "component_version", "content_sha256"])
def test_each_definition_binding_field_mutation_rejects_even_with_recomputed_identity(
    component: str, field: str
) -> None:
    baseline = _identity()
    original = {
        "workflow": baseline.workflow,
        "catalogue": baseline.stage_catalogue,
        "policy": baseline.policy,
    }[component]
    changed_value = (
        "mutated"
        if field == "component_id"
        else "9.9.9"
        if field == "component_version"
        else HASH_C
    )
    changed = original.model_copy(update={field: changed_value})
    identity = _identity(
        workflow=changed if component == "workflow" else baseline.workflow,
        catalogue=changed if component == "catalogue" else baseline.stage_catalogue,
        policy=changed if component == "policy" else baseline.policy,
    )
    result = LocalWorkflowRuntime().start(_start_request(identity))
    assert result.error_code is WorkflowErrorCode.DEFINITION_MISMATCH


def test_definition_registry_is_immutable_and_revalidates_canonical_bytes() -> None:
    registry = WorkflowDefinitionRegistry((DEFAULT_WORKFLOW_DEFINITION,))
    identity = _identity()
    assert registry.resolve(identity) == DEFAULT_WORKFLOW_DEFINITION
    storage = cast(Any, registry)._definition_bytes
    key = (
        identity.workflow.component_id,
        identity.workflow.component_version,
        identity.workflow.content_sha256,
    )
    with pytest.raises(TypeError):
        storage[key] = DEFAULT_WORKFLOW_DEFINITION.model_dump_json().encode()
    with pytest.raises(AttributeError):
        cast(Any, registry)._definition_bytes = {}
    assert registry.resolve(identity) == DEFAULT_WORKFLOW_DEFINITION

    forged = WorkflowDefinition.build(
        definition_id="forged-definition",
        definition_version=DEFAULT_WORKFLOW_DEFINITION.definition_version,
        nodes=DEFAULT_WORKFLOW_DEFINITION.nodes,
        transitions=DEFAULT_WORKFLOW_DEFINITION.transitions,
        compatible_stage_catalogues=DEFAULT_WORKFLOW_DEFINITION.compatible_stage_catalogues,
        policy_limit_rows=DEFAULT_WORKFLOW_DEFINITION.policy_limit_rows,
        discovery_lane_nodes=DEFAULT_WORKFLOW_DEFINITION.discovery_lane_nodes,
        discovery_fan_in_node=DEFAULT_WORKFLOW_DEFINITION.discovery_fan_in_node,
        outcome_guard_node=DEFAULT_WORKFLOW_DEFINITION.outcome_guard_node,
    )
    object.__setattr__(registry, "_definition_bytes", {key: forged.model_dump_json().encode()})
    with pytest.raises(WorkflowDecisionError) as raised:
        registry.resolve(identity)
    assert raised.value.code is WorkflowErrorCode.DEFINITION_MISMATCH


@pytest.mark.parametrize("factory", RUNTIME_FACTORIES)
def test_resume_rebuilds_exact_snapshot_and_rejects_stale_or_cross_tenant(
    factory: RuntimeFactory,
) -> None:
    runtime = factory()
    result = _start(runtime)
    result = _signal(runtime, result, WorkflowSignalKind.COMPLETED, key="step")
    assert result.snapshot is not None
    request = WorkflowResumeRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        operation=WorkflowOperation.RESUME,
        request_id="resume",
        run_id="run",
        tenant_id="tenant",
        execution_identity=result.snapshot.execution_identity,
        expected_sequence=result.snapshot.journal_sequence,
        expected_journal_head_sha256=result.snapshot.journal_head_sha256,
        expected_state_sha256=result.snapshot.state_sha256,
    )
    resumed = runtime.resume(request)
    assert resumed.operation_status is WorkflowOperationStatus.RESUMED
    assert resumed.snapshot == result.snapshot
    assert (
        runtime.resume(request.model_copy(update={"expected_state_sha256": HASH_A})).error_code
        is WorkflowErrorCode.STALE_PRECONDITION
    )

    other_identity = _identity(tenant_id="other")
    cross_tenant = request.model_copy(
        update={"tenant_id": "other", "execution_identity": other_identity}
    )
    assert runtime.resume(cross_tenant).error_code is WorkflowErrorCode.RUN_NOT_FOUND


@pytest.mark.parametrize("factory", RUNTIME_FACTORIES)
def test_resume_rejects_caller_state_and_cannot_revive_terminal_run(
    factory: RuntimeFactory,
) -> None:
    runtime = factory()
    progressed = _to_auditor(runtime)
    progressed = _signal(
        runtime,
        progressed,
        WorkflowSignalKind.RETRYABLE_FAILURE,
        key="resume-loop-usage",
        status=WorkflowReceiptStatus.NON_SUCCESS,
        tokens=1,
    )
    assert progressed.snapshot is not None
    cancelled = runtime.cancel(_cancel_request(progressed.snapshot, key="resume-terminal"))
    assert cancelled.snapshot is not None
    terminal = cancelled.snapshot
    lowered_usage = tuple(
        item.model_copy(update={"attempts": 0, "tokens_used": 0})
        if item.loop_kind is WorkflowLoopKind.INVESTIGATION
        else item
        for item in terminal.loop_usage
    )
    request = WorkflowResumeRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        operation=WorkflowOperation.RESUME,
        request_id="resume-terminal",
        run_id=terminal.run_id,
        tenant_id=terminal.tenant_id,
        execution_identity=terminal.execution_identity,
        expected_sequence=terminal.journal_sequence,
        expected_journal_head_sha256=terminal.journal_head_sha256,
        expected_state_sha256=terminal.state_sha256,
    )
    forged_state = (
        ("active_nodes", (WorkflowNode.REPORTING,)),
        ("control_state", WorkflowControlState.ACTIVE),
        ("loop_usage", lowered_usage),
        ("journal", ()),
        ("terminal", False),
    )

    for field_name, value in forged_state:
        rejected = runtime.resume(request.model_copy(update={field_name: value}))
        assert rejected.operation_status is WorkflowOperationStatus.REJECTED
        assert rejected.error_code is WorkflowErrorCode.ILLEGAL_OPERATION
        assert rejected.snapshot is None and rejected.transition_event is None

    resumed = runtime.resume(request)
    assert resumed.operation_status is WorkflowOperationStatus.RESUMED
    assert resumed.snapshot == terminal
    assert resumed.snapshot.control_state is WorkflowControlState.CANCELLED


@pytest.mark.parametrize("factory", RUNTIME_FACTORIES)
def test_snapshot_rejects_missing_run_wrong_identity_and_stale_anchor(
    factory: RuntimeFactory,
) -> None:
    runtime = factory()
    started = _start(runtime)
    assert started.snapshot is not None
    snapshot = started.snapshot

    def request(run_id: str, identity: RunExecutionIdentity) -> WorkflowSnapshotRequest:
        return WorkflowSnapshotRequest(
            schema_version=CONTRACT_SCHEMA_VERSION,
            operation=WorkflowOperation.SNAPSHOT,
            request_id=f"snapshot-{run_id}",
            run_id=run_id,
            tenant_id=identity.repository_revision.tenant_id,
            execution_identity=identity,
            expected_sequence=snapshot.journal_sequence,
            expected_journal_head_sha256=snapshot.journal_head_sha256,
            expected_state_sha256=snapshot.state_sha256,
        )

    assert (
        runtime.snapshot(request("missing", snapshot.execution_identity)).error_code
        is WorkflowErrorCode.RUN_NOT_FOUND
    )
    other = RunExecutionIdentity.build(
        repository_revision=snapshot.execution_identity.repository_revision,
        stage_catalogue=snapshot.execution_identity.stage_catalogue,
        workflow=snapshot.execution_identity.workflow,
        policy=snapshot.execution_identity.policy,
        configuration=_pin("other-config"),
        provider_profile=snapshot.execution_identity.provider_profile,
        capability_profile=snapshot.execution_identity.capability_profile,
        egress_profile=snapshot.execution_identity.egress_profile,
    )
    assert runtime.snapshot(request("run", other)).error_code is WorkflowErrorCode.IDENTITY_MISMATCH
    stale = request("run", snapshot.execution_identity).model_copy(
        update={"expected_journal_head_sha256": HASH_C}
    )
    assert runtime.snapshot(stale).error_code is WorkflowErrorCode.STALE_PRECONDITION


@pytest.mark.parametrize("factory", RUNTIME_FACTORIES)
def test_fresh_replay_is_exact_and_gap_reorder_duplicate_tamper_fail(
    factory: RuntimeFactory,
) -> None:
    runtime = factory()
    results = [_start(runtime)]
    results.append(_signal(runtime, results[-1], WorkflowSignalKind.COMPLETED, key="one"))
    results.append(_signal(runtime, results[-1], WorkflowSignalKind.COMPLETED, key="two"))
    journal = tuple(
        result.transition_event for result in results if result.transition_event is not None
    )
    identity = results[-1].snapshot.execution_identity if results[-1].snapshot else _identity()
    replayed = replay_workflow_journal(
        identity,
        "run",
        journal,
        registry=DEFAULT_WORKFLOW_REGISTRY,
    )
    assert replayed == results[-1].snapshot

    mutations = (
        journal[1:],
        (journal[0], journal[2], journal[1]),
        (journal[0], journal[1], journal[1]),
        (*journal[:-1], journal[-1].model_copy(update={"event_sha256": HASH_A})),
        (
            *journal[:-1],
            journal[-1].model_copy(
                update={
                    "resulting_snapshot": journal[-1].resulting_snapshot.model_copy(
                        update={"active_nodes": (WorkflowNode.REPORTING,)}
                    )
                }
            ),
        ),
    )
    for candidate in mutations:
        with pytest.raises(WorkflowDecisionError) as raised:
            replay_workflow_journal(
                identity,
                "run",
                candidate,
                registry=DEFAULT_WORKFLOW_REGISTRY,
            )
        assert raised.value.code is WorkflowErrorCode.JOURNAL_INVALID


@pytest.mark.parametrize("operation", [WorkflowOperation.CANCEL, WorkflowOperation.SUPERSEDE])
@pytest.mark.parametrize("factory", RUNTIME_FACTORIES)
def test_control_transition_replay_is_byte_identical(
    operation: WorkflowOperation,
    factory: RuntimeFactory,
) -> None:
    runtime = factory()
    started = _start(runtime)
    assert started.snapshot is not None and started.transition_event is not None
    snapshot = started.snapshot
    if operation is WorkflowOperation.CANCEL:
        controlled = runtime.cancel(
            WorkflowCancelRequest(
                schema_version=CONTRACT_SCHEMA_VERSION,
                operation=WorkflowOperation.CANCEL,
                request_id="control",
                run_id="run",
                tenant_id="tenant",
                execution_identity=snapshot.execution_identity,
                idempotency_key="control",
                expected_sequence=snapshot.journal_sequence,
                expected_journal_head_sha256=snapshot.journal_head_sha256,
                expected_state_sha256=snapshot.state_sha256,
            )
        )
    else:
        controlled = runtime.supersede(
            WorkflowSupersedeRequest(
                schema_version=CONTRACT_SCHEMA_VERSION,
                operation=WorkflowOperation.SUPERSEDE,
                request_id="control",
                run_id="run",
                tenant_id="tenant",
                execution_identity=snapshot.execution_identity,
                idempotency_key="control",
                expected_sequence=snapshot.journal_sequence,
                expected_journal_head_sha256=snapshot.journal_head_sha256,
                expected_state_sha256=snapshot.state_sha256,
                superseding_head_sha=NEW_HEAD_SHA,
            )
        )
    assert controlled.snapshot is not None and controlled.transition_event is not None
    replayed = replay_workflow_journal(
        snapshot.execution_identity,
        "run",
        (started.transition_event, controlled.transition_event),
        registry=DEFAULT_WORKFLOW_REGISTRY,
    )
    assert replayed == controlled.snapshot
    assert controlled.transition_event.superseding_head_sha == (
        NEW_HEAD_SHA if operation is WorkflowOperation.SUPERSEDE else None
    )
    if operation is WorkflowOperation.SUPERSEDE:
        tampered = controlled.transition_event.model_copy(update={"superseding_head_sha": "c" * 40})
        with pytest.raises(WorkflowDecisionError) as raised:
            replay_workflow_journal(
                snapshot.execution_identity,
                "run",
                (started.transition_event, tampered),
                registry=DEFAULT_WORKFLOW_REGISTRY,
            )
        assert raised.value.code is WorkflowErrorCode.JOURNAL_INVALID


@pytest.mark.parametrize("factory", RUNTIME_FACTORIES)
def test_concurrent_duplicate_start_is_one_exact_effect(factory: RuntimeFactory) -> None:
    runtime = factory()
    request = _start_request(_identity())
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(runtime.start, (request, request)))
    assert results[0] == results[1]
    assert results[0].model_dump_json() == results[1].model_dump_json()
    assert results[0].snapshot is not None
    assert results[0].snapshot.journal_sequence == 1


@pytest.mark.parametrize("factory", RUNTIME_FACTORIES)
def test_concurrent_same_version_signals_linearize_one_transition(
    factory: RuntimeFactory,
) -> None:
    runtime = factory()
    started = _start(runtime)
    assert started.snapshot is not None
    requests = tuple(
        _signal_request(
            started.snapshot,
            _node_envelope(
                started.snapshot,
                WorkflowSignalKind.COMPLETED,
                suffix=f"race-{index}",
            ),
            key=f"race-{index}",
        )
        for index in range(2)
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(runtime.signal, requests))
    statuses = {result.operation_status for result in results}
    errors = {result.error_code for result in results}
    assert statuses == {WorkflowOperationStatus.APPLIED, WorkflowOperationStatus.REJECTED}
    assert WorkflowErrorCode.STALE_PRECONDITION in errors


def test_cross_run_model_receipt_envelope_rejects_without_mutation() -> None:
    runtime = LocalWorkflowRuntime()
    first = _resolve_discovery(runtime, _to_discovery_fork(runtime), candidates=False)
    assert first.snapshot is not None
    other_runtime = LocalWorkflowRuntime()
    other = _to_discovery_fork(other_runtime)
    assert other.snapshot is not None
    envelope = _model_envelope(other.snapshot).model_copy(update={"run_id": "other-run"})
    with pytest.raises(ValidationError, match="receipt scope must match"):
        _signal_request(first.snapshot, envelope, key="cross-run")
    assert (
        _read_snapshot(runtime, first.snapshot, request_id="cross-run").snapshot == first.snapshot
    )


@pytest.mark.parametrize(
    "mutation",
    ["run", "identity", "attempt", "nested_tenant", "nested_head", "nested_profile"],
)
def test_model_receipt_runtime_envelope_rejects_every_scope_replay(mutation: str) -> None:
    runtime = LocalWorkflowRuntime()
    result = _to_discovery_fork(runtime)
    assert result.snapshot is not None
    deterministic = _node_envelope(
        result.snapshot.model_copy(update={"active_nodes": (WorkflowNode.DETERMINISTIC_ANALYSIS,)}),
        WorkflowSignalKind.COMPLETED_ZERO,
        suffix="scope-det",
    )
    result = runtime.signal(_signal_request(result.snapshot, deterministic, key="scope-det"))
    assert result.snapshot is not None
    envelope = _model_envelope(result.snapshot, suffix="scope-model")
    if mutation == "run":
        envelope = envelope.model_copy(update={"run_id": "other-run"})
    elif mutation == "identity":
        envelope = envelope.model_copy(update={"execution_identity_hash": HASH_C})
    elif mutation == "attempt":
        envelope = envelope.model_copy(update={"attempt": envelope.attempt + 1})
    else:
        nested = envelope.model_discovery_receipt
        assert nested is not None
        updates: dict[str, object] = {}
        if mutation == "nested_tenant":
            updates["tenant_id"] = "other"
        elif mutation == "nested_head":
            updates["head_sha"] = NEW_HEAD_SHA
        else:
            updates["model_profile"] = _pin("other-model")
        nested = nested.model_copy(update=updates)
        envelope = WorkflowNodeReceiptEnvelope(
            schema_version=CONTRACT_SCHEMA_VERSION,
            envelope_id=envelope.envelope_id,
            tenant_id=envelope.tenant_id,
            run_id=envelope.run_id,
            execution_identity_hash=envelope.execution_identity_hash,
            node=envelope.node,
            attempt=envelope.attempt,
            producer=nested.model_profile,
            receipt_kind=WorkflowReceiptKind.MODEL_DISCOVERY,
            receipt_sha256=canonical_runtime_sha256(nested.model_dump(mode="json")),
            model_discovery_receipt=nested,
        )
    if mutation in {"run", "identity"}:
        with pytest.raises(ValidationError, match="receipt scope must match"):
            _signal_request(result.snapshot, envelope, key=f"scope-{mutation}")
        return
    request = _signal_request(result.snapshot, envelope, key=f"scope-{mutation}")
    rejected = runtime.signal(request)
    assert rejected.error_code is WorkflowErrorCode.INVALID_RECEIPT
    assert rejected.transition_event is None


def test_model_usage_overflow_is_invalid_receipt_not_internal_error() -> None:
    runtime = LocalWorkflowRuntime()
    result = _to_discovery_fork(runtime)
    assert result.snapshot is not None
    deterministic = _node_envelope(
        result.snapshot.model_copy(update={"active_nodes": (WorkflowNode.DETERMINISTIC_ANALYSIS,)}),
        WorkflowSignalKind.COMPLETED_ZERO,
        suffix="overflow-det",
    )
    result = runtime.signal(_signal_request(result.snapshot, deterministic, key="overflow-det"))
    assert result.snapshot is not None
    envelope = _model_envelope(result.snapshot, suffix="overflow-model")
    receipt = envelope.model_discovery_receipt
    assert receipt is not None
    huge = 10**30
    receipt = receipt.model_copy(
        update={
            "budget_usage": receipt.budget_usage.model_copy(
                update={"token_limit": huge, "tokens_used": huge}
            )
        }
    )
    envelope = envelope.model_copy(
        update={
            "model_discovery_receipt": receipt,
            "receipt_sha256": canonical_runtime_sha256(receipt.model_dump(mode="json")),
        }
    )
    rejected = runtime.signal(_signal_request(result.snapshot, envelope, key="overflow-model"))
    assert rejected.operation_status is WorkflowOperationStatus.REJECTED
    assert rejected.error_code is WorkflowErrorCode.INVALID_RECEIPT
    assert rejected.snapshot is None and rejected.transition_event is None


def test_public_snapshot_and_result_reject_scope_wait_and_operation_mismatch() -> None:
    started = _start(LocalWorkflowRuntime())
    assert started.snapshot is not None
    snapshot_values = started.snapshot.model_dump(mode="json")
    with pytest.raises(ValidationError):
        WorkflowSnapshot.model_validate(
            {**snapshot_values, "wait_reason": "WAITING_FOR_DISCOVERY_LANES"}
        )
    result_values = started.model_dump(mode="json")
    for mutation in (
        {"tenant_id": "other-tenant"},
        {"run_id": "other-run"},
        {"operation": "SNAPSHOT"},
        {"operation_status": "SNAPSHOT", "transition_event": None},
    ):
        with pytest.raises(ValidationError):
            WorkflowRuntimeResult.model_validate({**result_values, **mutation})


def test_runtime_rejects_decreasing_monotonic_elapsed_without_mutation() -> None:
    clock = ManualClock()
    runtime = LocalWorkflowRuntime(clock=clock)
    result = _to_auditor(runtime)
    clock.value += 10
    result = _signal(
        runtime,
        result,
        WorkflowSignalKind.RETRYABLE_FAILURE,
        key="monotonic-first",
        status=WorkflowReceiptStatus.NON_SUCCESS,
    )
    assert result.snapshot is not None
    before = result.snapshot
    clock.value -= 5
    envelope = _node_envelope(
        before,
        WorkflowSignalKind.RETRYABLE_FAILURE,
        status=WorkflowReceiptStatus.NON_SUCCESS,
        suffix="monotonic-second",
    )
    rejected = runtime.signal(_signal_request(before, envelope, key="monotonic-second"))
    assert rejected.error_code is WorkflowErrorCode.STALE_PRECONDITION
    current = runtime.snapshot(
        WorkflowSnapshotRequest(
            schema_version=CONTRACT_SCHEMA_VERSION,
            operation=WorkflowOperation.SNAPSHOT,
            request_id="monotonic-snapshot",
            run_id=before.run_id,
            tenant_id=before.tenant_id,
            execution_identity=before.execution_identity,
            expected_sequence=before.journal_sequence,
            expected_journal_head_sha256=before.journal_head_sha256,
            expected_state_sha256=before.state_sha256,
        )
    )
    assert current.snapshot == before


def test_internal_clock_exception_is_safe_typed_error_with_zero_mutation() -> None:
    secret = "sensitive-canary-value"

    class FailingClock:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self) -> int:
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError(secret)
            return 1

    runtime = LocalWorkflowRuntime(clock=FailingClock())
    started = _start(runtime)
    assert started.snapshot is not None
    envelope = _node_envelope(started.snapshot, WorkflowSignalKind.COMPLETED, suffix="error")
    failed = runtime.signal(_signal_request(started.snapshot, envelope, key="secret-key"))
    assert failed.operation_status is WorkflowOperationStatus.ERROR
    assert failed.error_code is WorkflowErrorCode.INTERNAL_ERROR
    assert failed.transition_event is None and failed.snapshot is None
    serialized = failed.model_dump_json()
    assert secret not in serialized
    assert hashlib.sha256(secret.encode()).hexdigest() not in serialized

    snapshot_request = WorkflowSnapshotRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        operation=WorkflowOperation.SNAPSHOT,
        request_id="snapshot",
        run_id="run",
        tenant_id="tenant",
        execution_identity=started.snapshot.execution_identity,
        expected_sequence=started.snapshot.journal_sequence,
        expected_journal_head_sha256=started.snapshot.journal_head_sha256,
        expected_state_sha256=started.snapshot.state_sha256,
    )
    current = runtime.snapshot(snapshot_request)
    assert current.snapshot == started.snapshot


def test_start_clock_and_read_policy_faults_are_typed_zero_mutation_and_non_echo(
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    canary = "RuntimeFaultCanary123"

    def failing_clock() -> int:
        raise RuntimeError(canary)

    start_runtime = LocalWorkflowRuntime(clock=failing_clock)
    request = _start_request(_identity(), key="fault-start")
    failed_start = start_runtime.start(request)
    assert failed_start.operation_status is WorkflowOperationStatus.ERROR
    assert failed_start.error_code is WorkflowErrorCode.INTERNAL_ERROR
    assert start_runtime.start(request) is failed_start
    second_failure = start_runtime.start(
        _start_request(_identity(), key="fault-start-new-key", request_id="fault-start-new")
    )
    assert second_failure.error_code is WorkflowErrorCode.INTERNAL_ERROR

    registry = ToggleFailureRegistry(canary)
    runtime = LocalWorkflowRuntime(registry=registry)
    started = _start(runtime)
    assert started.snapshot is not None
    snapshot = started.snapshot
    snapshot_request = WorkflowSnapshotRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        operation=WorkflowOperation.SNAPSHOT,
        request_id="fault-snapshot",
        run_id=snapshot.run_id,
        tenant_id=snapshot.tenant_id,
        execution_identity=snapshot.execution_identity,
        expected_sequence=snapshot.journal_sequence,
        expected_journal_head_sha256=snapshot.journal_head_sha256,
        expected_state_sha256=snapshot.state_sha256,
    )
    resume_request = WorkflowResumeRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        operation=WorkflowOperation.RESUME,
        request_id="fault-resume",
        run_id=snapshot.run_id,
        tenant_id=snapshot.tenant_id,
        execution_identity=snapshot.execution_identity,
        expected_sequence=snapshot.journal_sequence,
        expected_journal_head_sha256=snapshot.journal_head_sha256,
        expected_state_sha256=snapshot.state_sha256,
    )
    envelope = _node_envelope(snapshot, WorkflowSignalKind.COMPLETED, suffix="fault-signal")
    registry.fail = True
    failures = (
        failed_start,
        second_failure,
        runtime.snapshot(snapshot_request),
        runtime.resume(resume_request),
        runtime.signal(_signal_request(snapshot, envelope, key="fault-signal")),
    )
    assert all(item.operation_status is WorkflowOperationStatus.ERROR for item in failures)
    assert all(item.error_code is WorkflowErrorCode.INTERNAL_ERROR for item in failures)
    assert all(item.snapshot is None and item.transition_event is None for item in failures)
    registry.fail = False
    assert runtime.snapshot(snapshot_request).snapshot == snapshot

    rendered = "\n".join(
        [*(item.model_dump_json() for item in failures), *(repr(item) for item in failures)]
    )
    captured = capsys.readouterr()
    sinks = "\n".join((rendered, caplog.text, captured.out, captured.err))
    assert canary not in sinks
    assert hashlib.sha256(canary.encode()).hexdigest() not in sinks


def test_forged_top_level_tenant_is_sanitized_and_cannot_create_state() -> None:
    canary = "ForgedTenantCanary123"
    runtime = LocalWorkflowRuntime()
    valid = _start_request(_identity())
    forged = valid.model_copy(update={"tenant_id": canary})
    rejected = runtime.start(forged)
    rendered = "\n".join((rejected.model_dump_json(), repr(rejected), str(rejected)))
    assert rejected.error_code is WorkflowErrorCode.ILLEGAL_OPERATION
    assert rejected.tenant_id == "invalid-tenant"
    assert canary not in rendered
    assert hashlib.sha256(canary.encode()).hexdigest() not in rendered
    assert runtime.start(valid).operation_status is WorkflowOperationStatus.APPLIED


@pytest.mark.parametrize(
    "field_name",
    (
        "route",
        "next_node",
        "outcome",
        "snapshot",
        "journal",
        "usage",
        "progress",
        "terminal",
        "source",
        "raw_prompt",
        "prompt_text",
        "shell",
        "url",
        "free_text",
    ),
)
def test_hidden_forbidden_copy_fields_reject_before_start_and_do_not_echo(
    field_name: str,
) -> None:
    canary = f"HiddenFieldCanary-{field_name}"
    runtime = LocalWorkflowRuntime()
    valid = _start_request(_identity())
    forged = valid.model_copy(update={field_name: canary})

    rejected = runtime.start(forged)

    assert rejected.operation_status is WorkflowOperationStatus.REJECTED
    assert rejected.error_code is WorkflowErrorCode.ILLEGAL_OPERATION
    assert rejected.transition_event is None and rejected.snapshot is None
    rendered = "\n".join((rejected.model_dump_json(), repr(rejected), str(rejected)))
    assert canary not in rendered
    assert hashlib.sha256(canary.encode()).hexdigest() not in rendered
    assert runtime.start(valid).operation_status is WorkflowOperationStatus.APPLIED


def test_hidden_nested_route_and_unadmitted_producer_reject_without_transition() -> None:
    runtime = LocalWorkflowRuntime()
    started = _start(runtime)
    assert started.snapshot is not None
    before = started.snapshot
    valid = _node_envelope(before, WorkflowSignalKind.COMPLETED, suffix="producer")

    hidden_route = valid.model_copy(update={"route": "HiddenNestedRouteCanary"})
    hidden_result = runtime.signal(_signal_request(before, hidden_route, key="hidden-route"))
    assert hidden_result.operation_status is WorkflowOperationStatus.REJECTED
    assert hidden_result.error_code is WorkflowErrorCode.INVALID_RECEIPT
    assert hidden_result.transition_event is None

    unadmitted = valid.model_copy(update={"producer": _pin("unadmitted-producer")})
    producer_result = runtime.signal(_signal_request(before, unadmitted, key="unadmitted-producer"))
    assert producer_result.operation_status is WorkflowOperationStatus.REJECTED
    assert producer_result.error_code is WorkflowErrorCode.INVALID_RECEIPT
    assert producer_result.transition_event is None
    assert _read_snapshot(runtime, before, request_id="producer-snapshot").snapshot == before


def test_public_runtime_methods_reject_cross_operation_requests_without_mutation() -> None:
    runtime = LocalWorkflowRuntime()
    started = _start(runtime)
    assert started.snapshot is not None
    before = started.snapshot
    signal = _signal_request(
        before,
        _node_envelope(before, WorkflowSignalKind.COMPLETED, suffix="method-mismatch"),
        key="method-signal",
    )
    cancel = _cancel_request(before, key="method-cancel")
    supersede = _supersede_request(before, key="method-supersede")
    mismatches = (
        (WorkflowOperation.SIGNAL, cancel),
        (WorkflowOperation.SIGNAL, supersede),
        (WorkflowOperation.CANCEL, signal),
        (WorkflowOperation.CANCEL, supersede),
        (WorkflowOperation.SUPERSEDE, signal),
        (WorkflowOperation.SUPERSEDE, cancel),
    )

    for operation, request in mismatches:
        if operation is WorkflowOperation.SIGNAL:
            result = cast(Any, runtime).signal(request)
        elif operation is WorkflowOperation.CANCEL:
            result = cast(Any, runtime).cancel(request)
        else:
            result = cast(Any, runtime).supersede(request)
        assert result.operation is operation
        assert result.operation_status is WorkflowOperationStatus.REJECTED
        assert result.error_code is WorkflowErrorCode.ILLEGAL_OPERATION
        assert result.transition_event is None and result.snapshot is None

    assert _read_snapshot(runtime, before, request_id="method-snapshot").snapshot == before


def test_invalid_receipt_precedes_clock_failure_without_mutation() -> None:
    canary = "ClockPrecedenceCanary"

    class FailAfterStart:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self) -> int:
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError(canary)
            return 1

    clock = FailAfterStart()
    runtime = LocalWorkflowRuntime(clock=clock)
    started = _start(runtime)
    assert started.snapshot is not None
    before = started.snapshot
    invalid = _node_envelope(before, WorkflowSignalKind.COMPLETED, suffix="clock-invalid")
    invalid = invalid.model_copy(update={"run_id": "other-run"})

    with pytest.raises(ValidationError, match="receipt scope must match"):
        _signal_request(before, invalid, key="clock-invalid")

    assert clock.calls == 1
    assert _read_snapshot(runtime, before, request_id="clock-snapshot").snapshot == before


@pytest.mark.parametrize(
    ("condition", "expected"),
    (
        ("terminal", WorkflowErrorCode.TERMINAL_STATE),
        ("stale", WorkflowErrorCode.STALE_PRECONDITION),
        ("invalid", WorkflowErrorCode.INVALID_RECEIPT),
        ("illegal", WorkflowErrorCode.ILLEGAL_OPERATION),
    ),
)
def test_typed_precedence_beats_registry_failure(
    condition: str,
    expected: WorkflowErrorCode,
) -> None:
    registry = ToggleFailureRegistry("RegistryPrecedenceCanary")
    runtime = LocalWorkflowRuntime(registry=registry)
    started = _start(runtime)
    assert started.snapshot is not None
    before = started.snapshot

    if condition == "terminal":
        cancelled = runtime.cancel(_cancel_request(before, key="precedence-terminal"))
        assert cancelled.snapshot is not None
        before = cancelled.snapshot
        request: object = _cancel_request(before, key="precedence-terminal-new")
    elif condition == "stale":
        request = _cancel_request(before, key="precedence-stale").model_copy(
            update={"expected_sequence": before.journal_sequence + 1}
        )
    else:
        envelope = _node_envelope(before, WorkflowSignalKind.COMPLETED, suffix=condition)
        envelope = envelope.model_copy(
            update={
                "run_id": "other-run" if condition == "invalid" else envelope.run_id,
                "node": WorkflowNode.REPORTING if condition == "illegal" else envelope.node,
            }
        )
        if condition == "invalid":
            with pytest.raises(ValidationError, match="receipt scope must match"):
                _signal_request(before, envelope, key=f"precedence-{condition}")
            return
        request = _signal_request(before, envelope, key=f"precedence-{condition}")

    registry.fail = True
    if isinstance(request, WorkflowSignalRequest):
        result = runtime.signal(request)
    else:
        result = runtime.cancel(cast(WorkflowCancelRequest, request))
    assert result.operation_status is WorkflowOperationStatus.REJECTED
    assert result.error_code is expected
    assert result.transition_event is None

    registry.fail = False
    assert _read_snapshot(runtime, before, request_id=f"{condition}-snapshot").snapshot == before


def test_idempotency_secret_key_and_hash_never_enter_public_result() -> None:
    secret = "SecretKeyMaterial123"
    runtime = LocalWorkflowRuntime()
    result = runtime.start(_start_request(_identity(), key=secret))
    rendered = result.model_dump_json()
    assert secret not in rendered
    assert hashlib.sha256(secret.encode()).hexdigest() not in rendered


def test_runtime_request_inputs_are_not_mutated() -> None:
    runtime = LocalWorkflowRuntime()
    request = _start_request(_identity())
    before = deepcopy(request.model_dump(mode="json"))
    runtime.start(request)
    assert request.model_dump(mode="json") == before
