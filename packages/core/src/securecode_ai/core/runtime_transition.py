"""Deterministic workflow definition, transition, and replay authority."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

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
    WorkflowLoopUsage,
    WorkflowNode,
    WorkflowNodeAttempt,
    WorkflowOperation,
    WorkflowReceiptKind,
    WorkflowReceiptStatus,
    WorkflowResumeRequest,
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

from .runtime_definition import WorkflowDecisionError, WorkflowDefinitionRegistry


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
