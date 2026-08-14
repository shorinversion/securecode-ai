"""Deterministic workflow definition, transition, and replay authority."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION, ComponentPin, RunExecutionIdentity
from securecode_ai.contracts.domain import DiscoveryLane, ModelCallStatus
from securecode_ai.contracts.runtime import (
    MAX_SAFE_INTEGER,
    ZERO_SHA256,
    WorkflowActor,
    WorkflowCancelRequest,
    WorkflowControlState,
    WorkflowDefinition,
    WorkflowErrorCode,
    WorkflowExhaustionReason,
    WorkflowLaneResolution,
    WorkflowLoopKind,
    WorkflowLoopLimit,
    WorkflowLoopUsage,
    WorkflowNode,
    WorkflowNodeAttempt,
    WorkflowOperation,
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
    WorkflowTransitionEvent,
    WorkflowTransitionReason,
    WorkflowTransitionRule,
    WorkflowUsageDelta,
    WorkflowWaitReason,
    canonical_runtime_sha256,
)

DEFAULT_STAGE_CATALOGUE_PIN = ComponentPin(
    schema_version=CONTRACT_SCHEMA_VERSION,
    component_id="core-mvp-0.2.0",
    component_version="0.2.0",
    content_sha256="adad2e05fc822485f45ac164299462d360ecb015327b84d09c064a697c193d1d",
)
DEFAULT_POLICY_PIN = ComponentPin(
    schema_version=CONTRACT_SCHEMA_VERSION,
    component_id="private-model-source",
    component_version="1.0.0",
    content_sha256="62fe8bd3406f27b32184603719ab9c80c3e336f49c2405e2f3926e575a18c94f",
)
DEFAULT_WORKER_PIN = ComponentPin(
    schema_version=CONTRACT_SCHEMA_VERSION,
    component_id="worker",
    component_version="1.0.0",
    content_sha256="a" * 64,
)
RUNTIME_COMPONENT_PIN = ComponentPin(
    schema_version=CONTRACT_SCHEMA_VERSION,
    component_id="securecode-workflow-runtime",
    component_version="0.1.0",
    content_sha256=hashlib.sha256(b"securecode-workflow-runtime-0.1.0").hexdigest(),
)


class WorkflowDecisionError(Exception):
    """Internal closed decision error; messages are never public results."""

    def __init__(self, code: WorkflowErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


class WorkflowRuntime(Protocol):
    """Framework-neutral runtime port shared by Local and future Temporal adapters."""

    def start(self, request: WorkflowStartRequest) -> WorkflowRuntimeResult: ...

    def snapshot(self, request: WorkflowSnapshotRequest) -> WorkflowRuntimeResult: ...

    def resume(self, request: WorkflowResumeRequest) -> WorkflowRuntimeResult: ...

    def signal(self, request: WorkflowSignalRequest) -> WorkflowRuntimeResult: ...

    def cancel(self, request: WorkflowCancelRequest) -> WorkflowRuntimeResult: ...

    def supersede(self, request: WorkflowSupersedeRequest) -> WorkflowRuntimeResult: ...


def _rule(
    node: WorkflowNode,
    signal: WorkflowSignalKind,
    *next_nodes: WorkflowNode,
    loop: WorkflowLoopKind | None = None,
    exhausted: tuple[WorkflowNode, ...] = (),
) -> WorkflowTransitionRule:
    return WorkflowTransitionRule(
        schema_version=CONTRACT_SCHEMA_VERSION,
        from_node=node,
        signal_kind=signal,
        producer=None if node is WorkflowNode.MODEL_NATIVE_DISCOVERY else DEFAULT_WORKER_PIN,
        next_nodes=tuple(sorted(next_nodes, key=str)),
        loop_kind=loop,
        loop_boundary=bool(exhausted),
        exhaustion_next_nodes=tuple(sorted(exhausted, key=str)),
    )


def build_default_workflow_definition(
    *, policy_pin: ComponentPin = DEFAULT_POLICY_PIN
) -> WorkflowDefinition:
    """Return the immutable Core-MVP workflow definition used by LocalRuntime tests."""

    transitions = (
        _rule(WorkflowNode.REQUESTED, WorkflowSignalKind.COMPLETED, WorkflowNode.INTAKE),
        _rule(
            WorkflowNode.INTAKE,
            WorkflowSignalKind.COMPLETED,
            WorkflowNode.LANGUAGE_DISCOVERY,
        ),
        _rule(
            WorkflowNode.LANGUAGE_DISCOVERY,
            WorkflowSignalKind.COMPLETED,
            WorkflowNode.DISCOVERY_FORK,
        ),
        _rule(
            WorkflowNode.DISCOVERY_FORK,
            WorkflowSignalKind.COMPLETED,
            WorkflowNode.DETERMINISTIC_ANALYSIS,
            WorkflowNode.MODEL_NATIVE_DISCOVERY,
        ),
        *(
            _rule(lane, signal, WorkflowNode.NORMALIZATION)
            for lane in (
                WorkflowNode.DETERMINISTIC_ANALYSIS,
                WorkflowNode.MODEL_NATIVE_DISCOVERY,
            )
            for signal in (
                WorkflowSignalKind.COMPLETED,
                WorkflowSignalKind.COMPLETED_ZERO,
                WorkflowSignalKind.COMPLETED_WITH_CANDIDATES,
                WorkflowSignalKind.NON_SUCCESS,
            )
        ),
        _rule(
            WorkflowNode.NORMALIZATION,
            WorkflowSignalKind.COMPLETED_ZERO,
            WorkflowNode.COVERAGE_GUARD,
        ),
        _rule(
            WorkflowNode.NORMALIZATION,
            WorkflowSignalKind.COMPLETED_WITH_CANDIDATES,
            WorkflowNode.EVIDENCE_GRAPH,
        ),
        _rule(
            WorkflowNode.EVIDENCE_GRAPH,
            WorkflowSignalKind.COMPLETED,
            WorkflowNode.AUDITOR_INVESTIGATION,
        ),
        _rule(
            WorkflowNode.AUDITOR_INVESTIGATION,
            WorkflowSignalKind.COMPLETED,
            WorkflowNode.SKEPTIC_REVIEW,
            loop=WorkflowLoopKind.INVESTIGATION,
        ),
        _rule(
            WorkflowNode.AUDITOR_INVESTIGATION,
            WorkflowSignalKind.RETRYABLE_FAILURE,
            WorkflowNode.AUDITOR_INVESTIGATION,
            loop=WorkflowLoopKind.INVESTIGATION,
            exhausted=(WorkflowNode.HUMAN_GATE,),
        ),
        _rule(
            WorkflowNode.SKEPTIC_REVIEW,
            WorkflowSignalKind.COMPLETED,
            WorkflowNode.FINDING_GATE,
        ),
        _rule(
            WorkflowNode.FINDING_GATE,
            WorkflowSignalKind.REJECTED_WITH_EVIDENCE,
            WorkflowNode.COVERAGE_GUARD,
        ),
        _rule(
            WorkflowNode.FINDING_GATE,
            WorkflowSignalKind.CONFIRMED_NO_REPAIR,
            WorkflowNode.COVERAGE_GUARD,
        ),
        _rule(
            WorkflowNode.FINDING_GATE,
            WorkflowSignalKind.CONFIRMED_REPAIR_REQUESTED,
            WorkflowNode.ROOT_CAUSE_LOCALIZATION,
        ),
        _rule(
            WorkflowNode.ROOT_CAUSE_LOCALIZATION,
            WorkflowSignalKind.COMPLETED,
            WorkflowNode.SECURITY_TEST_GENERATION,
        ),
        _rule(
            WorkflowNode.SECURITY_TEST_GENERATION,
            WorkflowSignalKind.COMPLETED,
            WorkflowNode.ARCHITECT,
        ),
        _rule(
            WorkflowNode.ARCHITECT,
            WorkflowSignalKind.COMPLETED,
            WorkflowNode.VALIDATION_LADDER,
            loop=WorkflowLoopKind.REPAIR,
        ),
        _rule(
            WorkflowNode.ARCHITECT,
            WorkflowSignalKind.RETRYABLE_FAILURE,
            WorkflowNode.ARCHITECT,
            loop=WorkflowLoopKind.REPAIR,
            exhausted=(WorkflowNode.HUMAN_GATE,),
        ),
        _rule(
            WorkflowNode.VALIDATION_LADDER,
            WorkflowSignalKind.VALIDATED,
            WorkflowNode.HUMAN_GATE,
            loop=WorkflowLoopKind.REPAIR,
        ),
        _rule(
            WorkflowNode.VALIDATION_LADDER,
            WorkflowSignalKind.VALIDATION_FAILED,
            WorkflowNode.ARCHITECT,
            loop=WorkflowLoopKind.REPAIR,
            exhausted=(WorkflowNode.HUMAN_GATE,),
        ),
        _rule(
            WorkflowNode.HUMAN_GATE,
            WorkflowSignalKind.HUMAN_APPROVED,
            WorkflowNode.COVERAGE_GUARD,
        ),
        _rule(
            WorkflowNode.HUMAN_GATE,
            WorkflowSignalKind.HUMAN_REJECTED,
            WorkflowNode.COVERAGE_GUARD,
        ),
    )
    investigation_limit = WorkflowLoopLimit(
        schema_version=CONTRACT_SCHEMA_VERSION,
        max_attempts=3,
        max_tokens=32_000,
        max_tool_calls=32,
        max_elapsed_ms=120_000,
        max_no_progress=2,
    )
    repair_limit = WorkflowLoopLimit(
        schema_version=CONTRACT_SCHEMA_VERSION,
        max_attempts=3,
        max_tokens=48_000,
        max_tool_calls=48,
        max_elapsed_ms=180_000,
        max_no_progress=2,
    )
    return WorkflowDefinition.build(
        definition_id="securecode-core-mvp",
        definition_version="0.2.0",
        nodes=tuple(WorkflowNode),
        transitions=transitions,
        compatible_stage_catalogues=(DEFAULT_STAGE_CATALOGUE_PIN,),
        policy_limit_rows=(
            WorkflowPolicyLimitRow(
                schema_version=CONTRACT_SCHEMA_VERSION,
                policy=policy_pin,
                investigation=investigation_limit,
                repair=repair_limit,
            ),
        ),
        discovery_lane_nodes=(
            WorkflowNode.DETERMINISTIC_ANALYSIS,
            WorkflowNode.MODEL_NATIVE_DISCOVERY,
        ),
        discovery_fan_in_node=WorkflowNode.NORMALIZATION,
        outcome_guard_node=WorkflowNode.COVERAGE_GUARD,
    )


DEFAULT_WORKFLOW_DEFINITION = build_default_workflow_definition()


class WorkflowDefinitionRegistry:
    """Immutable exact-pin registry for admitted workflow definitions."""

    __slots__ = ("_definition_bytes",)

    def __init__(self, definitions: Iterable[WorkflowDefinition]) -> None:
        by_pin: dict[tuple[str, str, str], bytes] = {}
        for definition in definitions:
            encoded = definition.model_dump_json().encode("utf-8")
            try:
                validated = WorkflowDefinition.model_validate_json(encoded)
            except Exception as error:
                raise ValueError("invalid workflow definition registry entry") from error
            pin = validated.component_pin
            key = (pin.component_id, pin.component_version, pin.content_sha256)
            if key in by_pin:
                raise ValueError("duplicate workflow definition pin")
            by_pin[key] = encoded
        if not by_pin:
            raise ValueError("workflow definition registry cannot be empty")
        self._definition_bytes = MappingProxyType(by_pin)

    def __setattr__(self, name: str, value: object) -> None:
        if name == "_definition_bytes" and hasattr(self, name):
            raise AttributeError("workflow definition registry is immutable")
        object.__setattr__(self, name, value)

    @staticmethod
    def _pin_key(pin: ComponentPin) -> tuple[str, str, str]:
        return (pin.component_id, pin.component_version, pin.content_sha256)

    def resolve(self, identity: RunExecutionIdentity) -> WorkflowDefinition:
        encoded = self._definition_bytes.get(self._pin_key(identity.workflow))
        if encoded is None:
            raise WorkflowDecisionError(WorkflowErrorCode.DEFINITION_MISMATCH)
        try:
            definition = WorkflowDefinition.model_validate_json(encoded)
        except Exception as error:
            raise WorkflowDecisionError(WorkflowErrorCode.DEFINITION_MISMATCH) from error
        if definition.component_pin != identity.workflow:
            raise WorkflowDecisionError(WorkflowErrorCode.DEFINITION_MISMATCH)
        if identity.stage_catalogue not in definition.compatible_stage_catalogues:
            raise WorkflowDecisionError(WorkflowErrorCode.DEFINITION_MISMATCH)
        if not any(row.policy == identity.policy for row in definition.policy_limit_rows):
            raise WorkflowDecisionError(WorkflowErrorCode.DEFINITION_MISMATCH)
        return definition

    @staticmethod
    def loop_limit(
        definition: WorkflowDefinition,
        policy: ComponentPin,
        loop_kind: WorkflowLoopKind,
    ) -> WorkflowLoopLimit:
        row = next((item for item in definition.policy_limit_rows if item.policy == policy), None)
        if row is None:
            raise WorkflowDecisionError(WorkflowErrorCode.DEFINITION_MISMATCH)
        return row.investigation if loop_kind is WorkflowLoopKind.INVESTIGATION else row.repair


DEFAULT_WORKFLOW_REGISTRY = WorkflowDefinitionRegistry((DEFAULT_WORKFLOW_DEFINITION,))


@dataclass(frozen=True, slots=True)
class TransitionDecision:
    snapshot: WorkflowSnapshot
    event: WorkflowTransitionEvent


@dataclass(frozen=True, slots=True)
class _SignalMetadata:
    node: WorkflowNode
    attempt: int
    signal_kind: WorkflowSignalKind
    receipt_status: WorkflowReceiptStatus
    receipt_sha256: str
    producer_pins: tuple[ComponentPin, ...]
    usage_delta: WorkflowUsageDelta
    model_call_status: ModelCallStatus | None
    input_hashes: tuple[str, ...]
    output_hashes: tuple[str, ...]


def canonical_workflow_request_hash(
    request: WorkflowStartRequest
    | WorkflowSnapshotRequest
    | WorkflowResumeRequest
    | WorkflowSignalRequest
    | WorkflowCancelRequest
    | WorkflowSupersedeRequest,
) -> str:
    """Return the semantic request hash used by LocalRuntime idempotency."""

    return canonical_runtime_sha256(request.model_dump(mode="json"))


def _event_id(tenant_id: str, run_id: str, sequence: int) -> str:
    material = f"{tenant_id}\0{run_id}\0{sequence}".encode()
    return f"wfe_{hashlib.sha256(material).hexdigest()}"


def _empty_loop_usage(kind: WorkflowLoopKind) -> WorkflowLoopUsage:
    return WorkflowLoopUsage(
        schema_version=CONTRACT_SCHEMA_VERSION,
        loop_kind=kind,
        attempts=0,
        tokens_used=0,
        tool_calls=0,
        started_at_runtime_ms=0,
        elapsed_ms=0,
        no_progress_count=0,
    )


def _lane_resolutions() -> tuple[WorkflowLaneResolution, WorkflowLaneResolution]:
    return (
        WorkflowLaneResolution(
            schema_version=CONTRACT_SCHEMA_VERSION,
            lane=DiscoveryLane.DETERMINISTIC,
            resolved=False,
            satisfied=False,
        ),
        WorkflowLaneResolution(
            schema_version=CONTRACT_SCHEMA_VERSION,
            lane=DiscoveryLane.MODEL_NATIVE,
            resolved=False,
            satisfied=False,
        ),
    )


def _snapshot(
    *,
    previous: WorkflowSnapshot | None,
    identity: RunExecutionIdentity,
    definition: WorkflowDefinition,
    run_id: str,
    active_nodes: tuple[WorkflowNode, ...],
    completed_nodes: tuple[WorkflowNode, ...],
    lane_resolutions: tuple[WorkflowLaneResolution, WorkflowLaneResolution],
    node_attempts: tuple[WorkflowNodeAttempt, ...],
    loop_usage: tuple[WorkflowLoopUsage, WorkflowLoopUsage],
    control_state: WorkflowControlState,
    wait_reason: WorkflowWaitReason,
    runtime_elapsed_ms: int,
) -> WorkflowSnapshot:
    sequence = 1 if previous is None else previous.journal_sequence + 1
    return WorkflowSnapshot.build(
        journal_head_sha256=ZERO_SHA256,
        tenant_id=identity.repository_revision.tenant_id,
        run_id=run_id,
        execution_identity=identity,
        definition=definition.component_pin,
        active_nodes=tuple(sorted(active_nodes, key=str)),
        completed_nodes=tuple(sorted(completed_nodes, key=str)),
        lane_resolutions=lane_resolutions,
        node_attempts=tuple(sorted(node_attempts, key=lambda item: item.node)),
        loop_usage=loop_usage,
        control_state=control_state,
        wait_reason=wait_reason,
        runtime_elapsed_ms=runtime_elapsed_ms,
        journal_sequence=sequence,
    )


def _event(
    *,
    previous: WorkflowSnapshot | None,
    snapshot: WorkflowSnapshot,
    operation: WorkflowOperation,
    operation_semantic_sha256: str,
    actor: WorkflowActor,
    completed_node: WorkflowNode | None,
    attempt: int,
    reason: WorkflowTransitionReason,
    signal: _SignalMetadata | None = None,
    exhaustion_reason: WorkflowExhaustionReason | None = None,
    superseding_head_sha: str | None = None,
) -> WorkflowTransitionEvent:
    event_input_hashes: tuple[str, ...]
    if signal is None:
        if operation is WorkflowOperation.START:
            event_input_hashes = (snapshot.execution_identity.execution_identity_hash,)
        elif previous is not None:
            event_input_hashes = (previous.state_sha256,)
        else:  # pragma: no cover - start is the only valid genesis operation
            raise ValueError("a non-start event requires previous state")
    else:
        event_input_hashes = signal.input_hashes
    return WorkflowTransitionEvent.build(
        schema_version=CONTRACT_SCHEMA_VERSION,
        event_id=_event_id(snapshot.tenant_id, snapshot.run_id, snapshot.journal_sequence),
        tenant_id=snapshot.tenant_id,
        run_id=snapshot.run_id,
        execution_identity_hash=snapshot.execution_identity.execution_identity_hash,
        sequence=snapshot.journal_sequence,
        previous_event_sha256=(ZERO_SHA256 if previous is None else previous.journal_head_sha256),
        operation=operation,
        operation_semantic_sha256=operation_semantic_sha256,
        actor=actor,
        completed_node=completed_node,
        current_nodes=snapshot.active_nodes,
        attempt=attempt,
        producer_pins=() if signal is None else signal.producer_pins,
        receipt_sha256=None if signal is None else signal.receipt_sha256,
        signal_kind=None if signal is None else signal.signal_kind,
        receipt_status=None if signal is None else signal.receipt_status,
        usage_delta=(
            WorkflowUsageDelta(schema_version=CONTRACT_SCHEMA_VERSION)
            if signal is None
            else signal.usage_delta
        ),
        model_call_status=None if signal is None else signal.model_call_status,
        exhaustion_reason=exhaustion_reason,
        superseding_head_sha=superseding_head_sha,
        input_hashes=event_input_hashes,
        output_hashes=(snapshot.state_sha256,) if signal is None else signal.output_hashes,
        reason=reason,
        before_state_sha256=ZERO_SHA256 if previous is None else previous.state_sha256,
        after_state_sha256=snapshot.state_sha256,
        resulting_snapshot=snapshot,
    )


def start_workflow(
    request: WorkflowStartRequest,
    *,
    registry: WorkflowDefinitionRegistry,
    operation_semantic_sha256: str,
) -> TransitionDecision:
    definition = registry.resolve(request.execution_identity)
    initial = _snapshot(
        previous=None,
        identity=request.execution_identity,
        definition=definition,
        run_id=request.run_id,
        active_nodes=(WorkflowNode.REQUESTED,),
        completed_nodes=(),
        lane_resolutions=_lane_resolutions(),
        node_attempts=(
            WorkflowNodeAttempt(
                schema_version=CONTRACT_SCHEMA_VERSION,
                node=WorkflowNode.REQUESTED,
                attempt=1,
            ),
        ),
        loop_usage=(
            _empty_loop_usage(WorkflowLoopKind.INVESTIGATION),
            _empty_loop_usage(WorkflowLoopKind.REPAIR),
        ),
        control_state=WorkflowControlState.ACTIVE,
        wait_reason=WorkflowWaitReason.WAITING_FOR_NODE,
        runtime_elapsed_ms=0,
    )
    event = _event(
        previous=None,
        snapshot=initial,
        operation=WorkflowOperation.START,
        operation_semantic_sha256=operation_semantic_sha256,
        actor=WorkflowActor.SYSTEM,
        completed_node=None,
        attempt=1,
        reason=WorkflowTransitionReason.RUN_STARTED,
    )
    return TransitionDecision(event.resulting_snapshot, event)


def _extract_signal_unchecked(request: WorkflowSignalRequest) -> _SignalMetadata:
    envelope = request.receipt
    if (
        envelope.tenant_id != request.tenant_id
        or envelope.run_id != request.run_id
        or envelope.execution_identity_hash != request.execution_identity.execution_identity_hash
    ):
        raise WorkflowDecisionError(WorkflowErrorCode.INVALID_RECEIPT)
    if envelope.receipt_kind is WorkflowReceiptKind.MODEL_DISCOVERY:
        model_receipt = envelope.model_discovery_receipt
        if model_receipt is None:  # pragma: no cover - guarded by contract validation
            raise WorkflowDecisionError(WorkflowErrorCode.INVALID_RECEIPT)
        if (
            model_receipt.tenant_id != request.tenant_id
            or model_receipt.head_sha != request.execution_identity.repository_revision.head_sha
            or model_receipt.model_profile != request.execution_identity.provider_profile
        ):
            raise WorkflowDecisionError(WorkflowErrorCode.INVALID_RECEIPT)
        status = (
            WorkflowReceiptStatus.SUCCEEDED
            if model_receipt.model_call_status is ModelCallStatus.SUCCEEDED
            else WorkflowReceiptStatus.NON_SUCCESS
        )
        signal = (
            WorkflowSignalKind.COMPLETED_ZERO
            if model_receipt.is_completed_zero
            else WorkflowSignalKind.COMPLETED_WITH_CANDIDATES
            if status is WorkflowReceiptStatus.SUCCEEDED
            else WorkflowSignalKind.NON_SUCCESS
        )
        return _SignalMetadata(
            node=envelope.node,
            attempt=envelope.attempt,
            signal_kind=signal,
            receipt_status=status,
            receipt_sha256=envelope.receipt_sha256,
            producer_pins=(envelope.producer,),
            usage_delta=WorkflowUsageDelta(
                schema_version=CONTRACT_SCHEMA_VERSION,
                tokens_used=model_receipt.budget_usage.tokens_used,
                tool_calls=model_receipt.budget_usage.repository_calls_used,
            ),
            model_call_status=model_receipt.model_call_status,
            input_hashes=(model_receipt.input_sha256,),
            output_hashes=(
                (envelope.receipt_sha256,)
                if model_receipt.output_sha256 is None
                else (model_receipt.output_sha256,)
            ),
        )
    node_receipt = envelope.node_receipt
    if node_receipt is None:  # pragma: no cover - guarded by contract validation
        raise WorkflowDecisionError(WorkflowErrorCode.INVALID_RECEIPT)
    return _SignalMetadata(
        node=envelope.node,
        attempt=envelope.attempt,
        signal_kind=node_receipt.signal_kind,
        receipt_status=node_receipt.status,
        receipt_sha256=envelope.receipt_sha256,
        producer_pins=(envelope.producer,),
        usage_delta=node_receipt.usage_delta,
        model_call_status=None,
        input_hashes=node_receipt.input_hashes,
        output_hashes=node_receipt.output_hashes,
    )


def _extract_signal(request: WorkflowSignalRequest) -> _SignalMetadata:
    try:
        return _extract_signal_unchecked(request)
    except WorkflowDecisionError:
        raise
    except (TypeError, ValueError, OverflowError) as error:
        raise WorkflowDecisionError(WorkflowErrorCode.INVALID_RECEIPT) from error


def _validated_signal_rule(
    previous: WorkflowSnapshot,
    definition: WorkflowDefinition,
    metadata: _SignalMetadata,
) -> WorkflowTransitionRule:
    if metadata.node not in previous.active_nodes:
        raise WorkflowDecisionError(WorkflowErrorCode.ILLEGAL_OPERATION)
    if _attempt_map(previous).get(metadata.node) != metadata.attempt:
        raise WorkflowDecisionError(WorkflowErrorCode.INVALID_RECEIPT)
    rule = next(
        (
            item
            for item in definition.transitions
            if item.from_node is metadata.node and item.signal_kind is metadata.signal_kind
        ),
        None,
    )
    if rule is None:
        raise WorkflowDecisionError(WorkflowErrorCode.ILLEGAL_OPERATION)
    expected_producer = (
        previous.execution_identity.provider_profile if rule.producer is None else rule.producer
    )
    if metadata.producer_pins != (expected_producer,):
        raise WorkflowDecisionError(WorkflowErrorCode.INVALID_RECEIPT)
    return rule


def validate_workflow_signal_preconditions(
    previous: WorkflowSnapshot,
    request: WorkflowSignalRequest,
    *,
    definition: WorkflowDefinition,
) -> None:
    """Validate caller-controlled signal material without consulting runtime services."""

    if request.execution_identity != previous.execution_identity:
        raise WorkflowDecisionError(WorkflowErrorCode.IDENTITY_MISMATCH)
    _validated_signal_rule(previous, definition, _extract_signal(request))


def _attempt_map(snapshot: WorkflowSnapshot) -> dict[WorkflowNode, int]:
    return {item.node: item.attempt for item in snapshot.node_attempts}


def _loop_map(snapshot: WorkflowSnapshot) -> dict[WorkflowLoopKind, WorkflowLoopUsage]:
    return {item.loop_kind: item for item in snapshot.loop_usage}


def _activate(
    previous: WorkflowSnapshot,
    nodes: tuple[WorkflowNode, ...],
    completed_node: WorkflowNode,
    runtime_elapsed_ms: int,
    loops: dict[WorkflowLoopKind, WorkflowLoopUsage],
) -> tuple[tuple[WorkflowNodeAttempt, ...], tuple[WorkflowLoopUsage, WorkflowLoopUsage]]:
    attempts = _attempt_map(previous)
    for node in nodes:
        if node in previous.active_nodes and node is not completed_node:
            continue
        attempts[node] = attempts.get(node, 0) + 1
        loop_kind = (
            WorkflowLoopKind.INVESTIGATION
            if node is WorkflowNode.AUDITOR_INVESTIGATION
            else WorkflowLoopKind.REPAIR
            if node is WorkflowNode.ARCHITECT
            else None
        )
        if loop_kind is not None and loops[loop_kind].attempts == 0:
            loops[loop_kind] = loops[loop_kind].model_copy(
                update={"started_at_runtime_ms": runtime_elapsed_ms}
            )
    return (
        tuple(
            WorkflowNodeAttempt(
                schema_version=CONTRACT_SCHEMA_VERSION,
                node=node,
                attempt=attempt,
            )
            for node, attempt in sorted(attempts.items())
        ),
        (loops[WorkflowLoopKind.INVESTIGATION], loops[WorkflowLoopKind.REPAIR]),
    )


def _update_loop(
    *,
    previous: WorkflowSnapshot,
    definition: WorkflowDefinition,
    metadata: _SignalMetadata,
    loop_kind: WorkflowLoopKind,
    boundary: bool,
    runtime_elapsed_ms: int,
    registry: WorkflowDefinitionRegistry,
) -> tuple[WorkflowLoopUsage, WorkflowExhaustionReason | None]:
    current = _loop_map(previous)[loop_kind]
    tokens = current.tokens_used + metadata.usage_delta.tokens_used
    tools = current.tool_calls + metadata.usage_delta.tool_calls
    attempts = current.attempts + (1 if boundary else 0)
    if max(tokens, tools, attempts, runtime_elapsed_ms) > MAX_SAFE_INTEGER:
        raise WorkflowDecisionError(WorkflowErrorCode.INVALID_RECEIPT)
    progress_hash = (
        canonical_runtime_sha256(
            {
                "active_nodes": [node.value for node in previous.active_nodes],
                "node": metadata.node.value,
                "receipt_sha256": metadata.receipt_sha256,
                "output_hashes": list(metadata.output_hashes),
            }
        )
        if boundary
        else current.last_progress_sha256
    )
    no_progress = (
        (current.no_progress_count + 1 if current.last_progress_sha256 == progress_hash else 0)
        if boundary
        else current.no_progress_count
    )
    elapsed = runtime_elapsed_ms - current.started_at_runtime_ms
    if elapsed < current.elapsed_ms:
        raise WorkflowDecisionError(WorkflowErrorCode.STALE_PRECONDITION)
    updated = WorkflowLoopUsage(
        schema_version=CONTRACT_SCHEMA_VERSION,
        loop_kind=loop_kind,
        attempts=attempts,
        tokens_used=tokens,
        tool_calls=tools,
        started_at_runtime_ms=current.started_at_runtime_ms,
        elapsed_ms=elapsed,
        no_progress_count=no_progress,
        last_progress_sha256=progress_hash,
    )
    if not boundary:
        return updated, None
    limit = registry.loop_limit(definition, previous.execution_identity.policy, loop_kind)
    reason = (
        WorkflowExhaustionReason.TIME
        if updated.elapsed_ms >= limit.max_elapsed_ms
        else WorkflowExhaustionReason.TOKENS
        if updated.tokens_used >= limit.max_tokens
        else WorkflowExhaustionReason.TOOL_CALLS
        if updated.tool_calls >= limit.max_tool_calls
        else WorkflowExhaustionReason.ATTEMPTS
        if updated.attempts >= limit.max_attempts
        else WorkflowExhaustionReason.NO_PROGRESS
        if updated.no_progress_count >= limit.max_no_progress
        else None
    )
    return updated, reason


def _lane_resolution(
    previous: WorkflowSnapshot,
    metadata: _SignalMetadata,
) -> tuple[WorkflowLaneResolution, WorkflowLaneResolution]:
    lane = (
        DiscoveryLane.DETERMINISTIC
        if metadata.node is WorkflowNode.DETERMINISTIC_ANALYSIS
        else DiscoveryLane.MODEL_NATIVE
    )
    values = {item.lane: item for item in previous.lane_resolutions}
    if values[lane].resolved:
        raise WorkflowDecisionError(WorkflowErrorCode.ILLEGAL_OPERATION)
    values[lane] = WorkflowLaneResolution(
        schema_version=CONTRACT_SCHEMA_VERSION,
        lane=lane,
        resolved=True,
        satisfied=metadata.receipt_status is WorkflowReceiptStatus.SUCCEEDED,
        receipt_sha256=metadata.receipt_sha256,
        model_call_status=metadata.model_call_status,
    )
    return (values[DiscoveryLane.DETERMINISTIC], values[DiscoveryLane.MODEL_NATIVE])


def _advance_signal(
    *,
    previous: WorkflowSnapshot,
    definition: WorkflowDefinition,
    metadata: _SignalMetadata,
    operation_semantic_sha256: str,
    runtime_elapsed_ms: int,
    registry: WorkflowDefinitionRegistry,
) -> TransitionDecision:
    if previous.control_state is not WorkflowControlState.ACTIVE:
        raise WorkflowDecisionError(WorkflowErrorCode.TERMINAL_STATE)
    if runtime_elapsed_ms < previous.runtime_elapsed_ms:
        raise WorkflowDecisionError(WorkflowErrorCode.STALE_PRECONDITION)
    rule = _validated_signal_rule(previous, definition, metadata)

    completed = set(previous.completed_nodes)
    completed.add(metadata.node)
    active = set(previous.active_nodes)
    active.remove(metadata.node)
    lanes = previous.lane_resolutions
    loops = _loop_map(previous)
    exhaustion_reason: WorkflowExhaustionReason | None = None
    reason = WorkflowTransitionReason.NODE_COMPLETED

    if metadata.node in definition.discovery_lane_nodes:
        lanes = _lane_resolution(previous, metadata)
        if all(item.resolved for item in lanes):
            active.add(definition.discovery_fan_in_node)
            reason = WorkflowTransitionReason.DISCOVERY_FAN_IN
        else:
            reason = WorkflowTransitionReason.DISCOVERY_LANE_RESOLVED
    else:
        next_nodes = rule.next_nodes
        if rule.loop_kind is not None:
            updated, exhaustion_reason = _update_loop(
                previous=previous,
                definition=definition,
                metadata=metadata,
                loop_kind=rule.loop_kind,
                boundary=rule.loop_boundary,
                runtime_elapsed_ms=runtime_elapsed_ms,
                registry=registry,
            )
            loops[rule.loop_kind] = updated
            if exhaustion_reason is not None:
                next_nodes = rule.exhaustion_next_nodes
                reason = WorkflowTransitionReason.LOOP_EXHAUSTED
            elif rule.loop_boundary:
                reason = WorkflowTransitionReason.LOOP_RETRY
        active.update(next_nodes)

    active_nodes = tuple(sorted(active, key=str))
    wait_reason = (
        WorkflowWaitReason.WAITING_FOR_TRUSTED_OUTCOME_GUARD
        if active_nodes == (definition.outcome_guard_node,)
        else WorkflowWaitReason.WAITING_FOR_DISCOVERY_LANES
        if any(node in definition.discovery_lane_nodes for node in active_nodes)
        else WorkflowWaitReason.WAITING_FOR_NODE
    )
    node_attempts, loop_usage = _activate(
        previous,
        active_nodes,
        metadata.node,
        runtime_elapsed_ms,
        loops,
    )
    snapshot = _snapshot(
        previous=previous,
        identity=previous.execution_identity,
        definition=definition,
        run_id=previous.run_id,
        active_nodes=active_nodes,
        completed_nodes=tuple(completed),
        lane_resolutions=lanes,
        node_attempts=node_attempts,
        loop_usage=loop_usage,
        control_state=WorkflowControlState.ACTIVE,
        wait_reason=wait_reason,
        runtime_elapsed_ms=runtime_elapsed_ms,
    )
    event = _event(
        previous=previous,
        snapshot=snapshot,
        operation=WorkflowOperation.SIGNAL,
        operation_semantic_sha256=operation_semantic_sha256,
        actor=WorkflowActor.WORKER,
        completed_node=metadata.node,
        attempt=metadata.attempt,
        reason=reason,
        signal=metadata,
        exhaustion_reason=exhaustion_reason,
    )
    return TransitionDecision(event.resulting_snapshot, event)


def signal_workflow(
    previous: WorkflowSnapshot,
    request: WorkflowSignalRequest,
    *,
    registry: WorkflowDefinitionRegistry,
    operation_semantic_sha256: str,
    runtime_elapsed_ms: int,
) -> TransitionDecision:
    definition = registry.resolve(request.execution_identity)
    if request.execution_identity != previous.execution_identity:
        raise WorkflowDecisionError(WorkflowErrorCode.IDENTITY_MISMATCH)
    return _advance_signal(
        previous=previous,
        definition=definition,
        metadata=_extract_signal(request),
        operation_semantic_sha256=operation_semantic_sha256,
        runtime_elapsed_ms=runtime_elapsed_ms,
        registry=registry,
    )


def control_workflow(
    previous: WorkflowSnapshot,
    request: WorkflowCancelRequest | WorkflowSupersedeRequest,
    *,
    registry: WorkflowDefinitionRegistry,
    operation_semantic_sha256: str,
    runtime_elapsed_ms: int,
) -> TransitionDecision:
    registry.resolve(request.execution_identity)
    if request.execution_identity != previous.execution_identity:
        raise WorkflowDecisionError(WorkflowErrorCode.IDENTITY_MISMATCH)
    if previous.control_state is not WorkflowControlState.ACTIVE:
        raise WorkflowDecisionError(WorkflowErrorCode.TERMINAL_STATE)
    if runtime_elapsed_ms < previous.runtime_elapsed_ms:
        raise WorkflowDecisionError(WorkflowErrorCode.STALE_PRECONDITION)
    is_cancel = request.operation is WorkflowOperation.CANCEL
    state = WorkflowControlState.CANCELLED if is_cancel else WorkflowControlState.SUPERSEDED
    reason = (
        WorkflowTransitionReason.CANCELLED if is_cancel else WorkflowTransitionReason.SUPERSEDED
    )
    definition = registry.resolve(previous.execution_identity)
    snapshot = _snapshot(
        previous=previous,
        identity=previous.execution_identity,
        definition=definition,
        run_id=previous.run_id,
        active_nodes=(),
        completed_nodes=previous.completed_nodes,
        lane_resolutions=previous.lane_resolutions,
        node_attempts=previous.node_attempts,
        loop_usage=previous.loop_usage,
        control_state=state,
        wait_reason=WorkflowWaitReason.TERMINAL_CONTROL,
        runtime_elapsed_ms=runtime_elapsed_ms,
    )
    event = _event(
        previous=previous,
        snapshot=snapshot,
        operation=request.operation,
        operation_semantic_sha256=operation_semantic_sha256,
        actor=WorkflowActor.USER if is_cancel else WorkflowActor.SYSTEM,
        completed_node=None,
        attempt=1,
        reason=reason,
        superseding_head_sha=(
            request.superseding_head_sha
            if request.operation is WorkflowOperation.SUPERSEDE
            else None
        ),
    )
    return TransitionDecision(event.resulting_snapshot, event)


def _metadata_from_event(event: WorkflowTransitionEvent) -> _SignalMetadata:
    if (
        event.completed_node is None
        or event.signal_kind is None
        or event.receipt_status is None
        or event.receipt_sha256 is None
    ):
        raise WorkflowDecisionError(WorkflowErrorCode.JOURNAL_INVALID)
    return _SignalMetadata(
        node=event.completed_node,
        attempt=event.attempt,
        signal_kind=event.signal_kind,
        receipt_status=event.receipt_status,
        receipt_sha256=event.receipt_sha256,
        producer_pins=event.producer_pins,
        usage_delta=event.usage_delta,
        model_call_status=event.model_call_status,
        input_hashes=event.input_hashes,
        output_hashes=event.output_hashes,
    )


def replay_workflow_journal(
    identity: RunExecutionIdentity,
    run_id: str,
    journal: tuple[WorkflowTransitionEvent, ...],
    *,
    registry: WorkflowDefinitionRegistry,
) -> WorkflowSnapshot:
    """Rebuild one snapshot from canonical genesis and the complete ordered journal."""

    if not journal:
        raise WorkflowDecisionError(WorkflowErrorCode.JOURNAL_INVALID)
    definition = registry.resolve(identity)
    previous: WorkflowSnapshot | None = None
    for expected_sequence, untrusted_record in enumerate(journal, start=1):
        try:
            recorded = WorkflowTransitionEvent.model_validate_json(
                untrusted_record.model_dump_json()
            )
        except Exception as error:
            raise WorkflowDecisionError(WorkflowErrorCode.JOURNAL_INVALID) from error
        if (
            recorded.sequence != expected_sequence
            or recorded.tenant_id != identity.repository_revision.tenant_id
            or recorded.run_id != run_id
            or recorded.execution_identity_hash != identity.execution_identity_hash
            or recorded.previous_event_sha256
            != (ZERO_SHA256 if previous is None else previous.journal_head_sha256)
        ):
            raise WorkflowDecisionError(WorkflowErrorCode.JOURNAL_INVALID)
        try:
            if previous is None:
                if recorded.operation is not WorkflowOperation.START:
                    raise WorkflowDecisionError(WorkflowErrorCode.JOURNAL_INVALID)
                start_request = WorkflowStartRequest(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    operation=WorkflowOperation.START,
                    request_id="replay",
                    run_id=run_id,
                    tenant_id=identity.repository_revision.tenant_id,
                    execution_identity=identity,
                    idempotency_key="replay",
                )
                decision = start_workflow(
                    start_request,
                    registry=registry,
                    operation_semantic_sha256=recorded.operation_semantic_sha256,
                )
                if decision.event != recorded:
                    raise WorkflowDecisionError(WorkflowErrorCode.JOURNAL_INVALID)
            elif recorded.operation is WorkflowOperation.SIGNAL:
                decision = _advance_signal(
                    previous=previous,
                    definition=definition,
                    metadata=_metadata_from_event(recorded),
                    operation_semantic_sha256=recorded.operation_semantic_sha256,
                    runtime_elapsed_ms=recorded.resulting_snapshot.runtime_elapsed_ms,
                    registry=registry,
                )
                if decision.event != recorded:
                    raise WorkflowDecisionError(WorkflowErrorCode.JOURNAL_INVALID)
            elif recorded.operation in {WorkflowOperation.CANCEL, WorkflowOperation.SUPERSEDE}:
                control_request: WorkflowCancelRequest | WorkflowSupersedeRequest
                if recorded.operation is WorkflowOperation.CANCEL:
                    control_request = WorkflowCancelRequest(
                        schema_version=CONTRACT_SCHEMA_VERSION,
                        operation=WorkflowOperation.CANCEL,
                        request_id="replay",
                        run_id=run_id,
                        tenant_id=identity.repository_revision.tenant_id,
                        execution_identity=identity,
                        idempotency_key="replay",
                        expected_sequence=previous.journal_sequence,
                        expected_journal_head_sha256=previous.journal_head_sha256,
                        expected_state_sha256=previous.state_sha256,
                    )
                else:
                    replacement_head = recorded.superseding_head_sha
                    if replacement_head is None:
                        raise WorkflowDecisionError(WorkflowErrorCode.JOURNAL_INVALID)
                    control_request = WorkflowSupersedeRequest(
                        schema_version=CONTRACT_SCHEMA_VERSION,
                        operation=WorkflowOperation.SUPERSEDE,
                        request_id="replay",
                        run_id=run_id,
                        tenant_id=identity.repository_revision.tenant_id,
                        execution_identity=identity,
                        idempotency_key="replay",
                        expected_sequence=previous.journal_sequence,
                        expected_journal_head_sha256=previous.journal_head_sha256,
                        expected_state_sha256=previous.state_sha256,
                        superseding_head_sha=replacement_head,
                    )
                decision = control_workflow(
                    previous,
                    control_request,
                    registry=registry,
                    operation_semantic_sha256=recorded.operation_semantic_sha256,
                    runtime_elapsed_ms=recorded.resulting_snapshot.runtime_elapsed_ms,
                )
                if decision.event != recorded:
                    raise WorkflowDecisionError(WorkflowErrorCode.JOURNAL_INVALID)
            else:
                raise WorkflowDecisionError(WorkflowErrorCode.JOURNAL_INVALID)
        except WorkflowDecisionError:
            raise
        except Exception as error:
            raise WorkflowDecisionError(WorkflowErrorCode.JOURNAL_INVALID) from error
        previous = recorded.resulting_snapshot
    if previous is None:  # pragma: no cover - non-empty journal guarded above
        raise WorkflowDecisionError(WorkflowErrorCode.JOURNAL_INVALID)
    return previous


__all__ = [
    "DEFAULT_POLICY_PIN",
    "DEFAULT_STAGE_CATALOGUE_PIN",
    "DEFAULT_WORKFLOW_DEFINITION",
    "DEFAULT_WORKFLOW_REGISTRY",
    "RUNTIME_COMPONENT_PIN",
    "TransitionDecision",
    "WorkflowDecisionError",
    "WorkflowDefinitionRegistry",
    "WorkflowRuntime",
    "build_default_workflow_definition",
    "canonical_workflow_request_hash",
    "control_workflow",
    "replay_workflow_journal",
    "signal_workflow",
    "start_workflow",
    "validate_workflow_signal_preconditions",
]
