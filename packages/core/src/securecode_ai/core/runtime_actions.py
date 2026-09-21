"""Deterministic workflow definition, transition, and replay authority."""

from __future__ import annotations

from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION, RunExecutionIdentity
from securecode_ai.contracts.domain import DiscoveryLane
from securecode_ai.contracts.runtime import (
    ZERO_SHA256,
    WorkflowActor,
    WorkflowCancelRequest,
    WorkflowControlState,
    WorkflowDefinition,
    WorkflowErrorCode,
    WorkflowExhaustionReason,
    WorkflowLaneResolution,
    WorkflowNode,
    WorkflowOperation,
    WorkflowReceiptStatus,
    WorkflowSignalRequest,
    WorkflowSnapshot,
    WorkflowStartRequest,
    WorkflowSupersedeRequest,
    WorkflowTransitionEvent,
    WorkflowTransitionReason,
    WorkflowWaitReason,
)

from .runtime_definition import WorkflowDecisionError, WorkflowDefinitionRegistry
from .runtime_transition import (
    TransitionDecision,
    _activate,
    _event,
    _extract_signal,
    _loop_map,
    _SignalMetadata,
    _snapshot,
    _update_loop,
    _validated_signal_rule,
    start_workflow,
)


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
