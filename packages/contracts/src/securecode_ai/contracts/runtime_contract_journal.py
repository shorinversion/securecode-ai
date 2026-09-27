"""Versioned public contracts for the graph-independent workflow runtime."""

from __future__ import annotations

from typing import Any, Self

from pydantic import Field, model_validator

from .base import (
    CONTRACT_SCHEMA_VERSION,
    CommitSha,
    OpaqueId,
    ReasonCode,
    Sha256,
    WireModel,
)
from .domain import (
    ComponentPin,
    DiscoveryLane,
    ModelCallStatus,
    ModelDiscoveryReceipt,
    RunExecutionIdentity,
)
from .runtime_contract_definition import (
    MAX_SAFE_INTEGER,
    ZERO_SHA256,
    WorkflowActor,
    WorkflowControlState,
    WorkflowExhaustionReason,
    WorkflowLoopKind,
    WorkflowNode,
    WorkflowOperation,
    WorkflowReceiptKind,
    WorkflowReceiptStatus,
    WorkflowSignalKind,
    WorkflowTransitionReason,
    WorkflowWaitReason,
    canonical_runtime_sha256,
)


class WorkflowUsageDelta(WireModel):
    tokens_used: int = Field(default=0, ge=0, le=MAX_SAFE_INTEGER)
    tool_calls: int = Field(default=0, ge=0, le=MAX_SAFE_INTEGER)


class WorkflowNodeReceipt(WireModel):
    receipt_id: OpaqueId
    status: WorkflowReceiptStatus
    signal_kind: WorkflowSignalKind
    input_hashes: tuple[Sha256, ...] = Field(min_length=1, max_length=4096)
    output_hashes: tuple[Sha256, ...] = Field(min_length=1, max_length=4096)
    usage_delta: WorkflowUsageDelta
    reason_code: ReasonCode | None = None

    @model_validator(mode="after")
    def _validate_status(self) -> Self:
        if self.status is WorkflowReceiptStatus.SUCCEEDED:
            if self.signal_kind in {
                WorkflowSignalKind.NON_SUCCESS,
                WorkflowSignalKind.RETRYABLE_FAILURE,
                WorkflowSignalKind.VALIDATION_FAILED,
            }:
                raise ValueError("a successful receipt cannot carry a failure signal")
            if self.reason_code is not None:
                raise ValueError("a successful receipt cannot carry a failure reason")
        else:
            if self.reason_code is None:
                raise ValueError("a non-success receipt requires a closed reason code")
            if self.signal_kind not in {
                WorkflowSignalKind.NON_SUCCESS,
                WorkflowSignalKind.RETRYABLE_FAILURE,
                WorkflowSignalKind.VALIDATION_FAILED,
            }:
                raise ValueError("a non-success receipt cannot advance a success route")
        return self


class WorkflowNodeReceiptEnvelope(WireModel):
    envelope_id: OpaqueId
    tenant_id: OpaqueId
    run_id: OpaqueId
    execution_identity_hash: Sha256
    node: WorkflowNode
    attempt: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    producer: ComponentPin
    receipt_kind: WorkflowReceiptKind
    receipt_sha256: Sha256
    node_receipt: WorkflowNodeReceipt | None = None
    model_discovery_receipt: ModelDiscoveryReceipt | None = None

    def nested_receipt(self) -> WorkflowNodeReceipt | ModelDiscoveryReceipt:
        value = self.node_receipt or self.model_discovery_receipt
        if value is None:  # pragma: no cover - guarded by model validation
            raise ValueError("missing nested receipt")
        return value

    @model_validator(mode="after")
    def _validate_receipt_union(self) -> Self:
        if self.receipt_kind is WorkflowReceiptKind.MODEL_DISCOVERY:
            if self.node is not WorkflowNode.MODEL_NATIVE_DISCOVERY:
                raise ValueError("model discovery receipt requires the model-native node")
            if self.model_discovery_receipt is None or self.node_receipt is not None:
                raise ValueError("model discovery envelope requires exactly its receipt")
            if self.producer != self.model_discovery_receipt.model_profile:
                raise ValueError("envelope producer must match the model profile")
        else:
            if self.node is WorkflowNode.MODEL_NATIVE_DISCOVERY:
                raise ValueError("model-native discovery requires its exact model receipt")
            if self.node_receipt is None or self.model_discovery_receipt is not None:
                raise ValueError("node envelope requires exactly a node receipt")
        nested = self.nested_receipt()
        expected_hash = canonical_runtime_sha256(nested.model_dump(mode="json"))
        if self.receipt_sha256 != expected_hash:
            raise ValueError("receipt hash does not match canonical nested receipt")
        return self


class WorkflowLaneResolution(WireModel):
    lane: DiscoveryLane
    resolved: bool
    satisfied: bool
    receipt_sha256: Sha256 | None = None
    model_call_status: ModelCallStatus | None = None

    @model_validator(mode="after")
    def _validate_resolution(self) -> Self:
        if not self.resolved and (
            self.satisfied or self.receipt_sha256 is not None or self.model_call_status is not None
        ):
            raise ValueError("an unresolved lane cannot carry a terminal receipt")
        if self.satisfied and self.receipt_sha256 is None:
            raise ValueError("a satisfied lane requires a receipt hash")
        if self.resolved and self.receipt_sha256 is None:
            raise ValueError("a resolved lane requires a receipt hash")
        if self.lane is DiscoveryLane.DETERMINISTIC and self.model_call_status is not None:
            raise ValueError("the deterministic lane cannot carry model status")
        if self.lane is DiscoveryLane.MODEL_NATIVE and self.resolved:
            if self.model_call_status is None:
                raise ValueError("a resolved model-native lane requires model status")
            if self.satisfied != (self.model_call_status is ModelCallStatus.SUCCEEDED):
                raise ValueError("model lane satisfaction must match native model success")
        return self


class WorkflowNodeAttempt(WireModel):
    node: WorkflowNode
    attempt: int = Field(ge=1, le=MAX_SAFE_INTEGER)


class WorkflowLoopUsage(WireModel):
    loop_kind: WorkflowLoopKind
    attempts: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    tokens_used: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    tool_calls: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    started_at_runtime_ms: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    elapsed_ms: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    no_progress_count: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    last_progress_sha256: Sha256 | None = None


class WorkflowSnapshot(WireModel):
    tenant_id: OpaqueId
    run_id: OpaqueId
    execution_identity: RunExecutionIdentity
    definition: ComponentPin
    active_nodes: tuple[WorkflowNode, ...] = Field(max_length=32)
    completed_nodes: tuple[WorkflowNode, ...] = Field(default=(), max_length=128)
    lane_resolutions: tuple[WorkflowLaneResolution, WorkflowLaneResolution]
    node_attempts: tuple[WorkflowNodeAttempt, ...] = Field(default=(), max_length=128)
    loop_usage: tuple[WorkflowLoopUsage, WorkflowLoopUsage]
    control_state: WorkflowControlState
    wait_reason: WorkflowWaitReason
    runtime_elapsed_ms: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    journal_sequence: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    journal_head_sha256: Sha256
    state_sha256: Sha256

    def _state_material(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            exclude={"journal_head_sha256", "state_sha256"},
        )

    @classmethod
    def build(cls, *, journal_head_sha256: Sha256, **values: Any) -> Self:
        material = {
            "schema_version": values.get("schema_version", CONTRACT_SCHEMA_VERSION),
            "extensions": [],
            **{
                key: value.model_dump(mode="json")
                if isinstance(value, WireModel)
                else [
                    item.model_dump(mode="json") if isinstance(item, WireModel) else item
                    for item in value
                ]
                if isinstance(value, tuple)
                else value
                for key, value in values.items()
                if key != "schema_version"
            },
        }
        return cls(
            schema_version=values.get("schema_version", CONTRACT_SCHEMA_VERSION),
            journal_head_sha256=journal_head_sha256,
            state_sha256=canonical_runtime_sha256(material),
            **{key: value for key, value in values.items() if key != "schema_version"},
        )

    @model_validator(mode="after")
    def _validate_snapshot(self) -> Self:
        if self.tenant_id != self.execution_identity.repository_revision.tenant_id:
            raise ValueError("snapshot tenant must match the execution identity")
        if self.definition != self.execution_identity.workflow:
            raise ValueError("snapshot definition must match the execution identity")
        if tuple(sorted(set(self.active_nodes), key=str)) != self.active_nodes:
            raise ValueError("active_nodes must be unique and canonically sorted")
        if tuple(sorted(set(self.completed_nodes), key=str)) != self.completed_nodes:
            raise ValueError("completed_nodes must be unique and canonically sorted")
        attempt_nodes = [item.node for item in self.node_attempts]
        if attempt_nodes != sorted(set(attempt_nodes)):
            raise ValueError("node attempts must be unique and canonically sorted")
        if tuple(item.loop_kind for item in self.loop_usage) != (
            WorkflowLoopKind.INVESTIGATION,
            WorkflowLoopKind.REPAIR,
        ):
            raise ValueError("loop usage must contain the two canonical loop kinds")
        if tuple(item.lane for item in self.lane_resolutions) != (
            DiscoveryLane.DETERMINISTIC,
            DiscoveryLane.MODEL_NATIVE,
        ):
            raise ValueError("lane resolutions must use canonical lane order")
        if self.control_state is WorkflowControlState.ACTIVE:
            if not self.active_nodes:
                raise ValueError("an active workflow requires at least one active node")
        elif self.active_nodes or self.wait_reason is not WorkflowWaitReason.TERMINAL_CONTROL:
            raise ValueError("a terminal control snapshot cannot retain active nodes")
        if self.control_state is WorkflowControlState.ACTIVE:
            expected_wait = (
                WorkflowWaitReason.WAITING_FOR_TRUSTED_OUTCOME_GUARD
                if self.active_nodes == (WorkflowNode.COVERAGE_GUARD,)
                else WorkflowWaitReason.WAITING_FOR_DISCOVERY_LANES
                if any(
                    node
                    in {
                        WorkflowNode.DETERMINISTIC_ANALYSIS,
                        WorkflowNode.MODEL_NATIVE_DISCOVERY,
                    }
                    for node in self.active_nodes
                )
                else WorkflowWaitReason.WAITING_FOR_NODE
            )
            if self.wait_reason is not expected_wait:
                raise ValueError("wait reason must be derived from the exact active-node set")
        if self.state_sha256 != canonical_runtime_sha256(self._state_material()):
            raise ValueError("state hash does not match canonical snapshot state")
        return self


class WorkflowTransitionEvent(WireModel):
    event_id: OpaqueId
    tenant_id: OpaqueId
    run_id: OpaqueId
    execution_identity_hash: Sha256
    sequence: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    previous_event_sha256: Sha256
    operation: WorkflowOperation
    operation_semantic_sha256: Sha256
    actor: WorkflowActor
    completed_node: WorkflowNode | None = None
    current_nodes: tuple[WorkflowNode, ...] = Field(max_length=32)
    attempt: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    producer_pins: tuple[ComponentPin, ...] = Field(default=(), max_length=32)
    receipt_sha256: Sha256 | None = None
    signal_kind: WorkflowSignalKind | None = None
    receipt_status: WorkflowReceiptStatus | None = None
    usage_delta: WorkflowUsageDelta
    model_call_status: ModelCallStatus | None = None
    exhaustion_reason: WorkflowExhaustionReason | None = None
    superseding_head_sha: CommitSha | None = None
    input_hashes: tuple[Sha256, ...] = Field(min_length=1, max_length=4096)
    output_hashes: tuple[Sha256, ...] = Field(min_length=1, max_length=4096)
    reason: WorkflowTransitionReason
    before_state_sha256: Sha256
    after_state_sha256: Sha256
    resulting_snapshot: WorkflowSnapshot
    event_sha256: Sha256

    def _event_material(self) -> dict[str, Any]:
        material = self.model_dump(mode="json", exclude={"event_sha256"})
        material["resulting_snapshot"]["journal_head_sha256"] = ZERO_SHA256
        return material

    @classmethod
    def build(cls, *, resulting_snapshot: WorkflowSnapshot, **values: Any) -> Self:
        placeholder = resulting_snapshot.model_copy(update={"journal_head_sha256": ZERO_SHA256})
        candidate = cls.model_construct(
            schema_version=values.get("schema_version", CONTRACT_SCHEMA_VERSION),
            extensions=(),
            resulting_snapshot=placeholder,
            event_sha256=ZERO_SHA256,
            **{key: value for key, value in values.items() if key != "schema_version"},
        )
        event_hash = canonical_runtime_sha256(candidate._event_material())
        final_snapshot = resulting_snapshot.model_copy(update={"journal_head_sha256": event_hash})
        return cls(
            schema_version=values.get("schema_version", CONTRACT_SCHEMA_VERSION),
            resulting_snapshot=final_snapshot,
            event_sha256=event_hash,
            **{key: value for key, value in values.items() if key != "schema_version"},
        )

    @model_validator(mode="after")
    def _validate_event(self) -> Self:
        if (
            self.tenant_id != self.resulting_snapshot.tenant_id
            or self.run_id != self.resulting_snapshot.run_id
        ):
            raise ValueError("event scope must match its resulting snapshot")
        if (
            self.execution_identity_hash
            != self.resulting_snapshot.execution_identity.execution_identity_hash
        ):
            raise ValueError("event identity must match its resulting snapshot")
        if self.sequence != self.resulting_snapshot.journal_sequence:
            raise ValueError("event sequence must match its resulting snapshot")
        if self.current_nodes != self.resulting_snapshot.active_nodes:
            raise ValueError("event current nodes must match its resulting snapshot")
        if self.after_state_sha256 != self.resulting_snapshot.state_sha256:
            raise ValueError("event after-state hash must match its resulting snapshot")
        if self.operation is WorkflowOperation.SIGNAL:
            if (
                self.completed_node is None
                or self.receipt_sha256 is None
                or self.signal_kind is None
                or self.receipt_status is None
            ):
                raise ValueError("signal transition requires closed receipt metadata")
            if self.reason not in {
                WorkflowTransitionReason.NODE_COMPLETED,
                WorkflowTransitionReason.DISCOVERY_LANE_RESOLVED,
                WorkflowTransitionReason.DISCOVERY_FAN_IN,
                WorkflowTransitionReason.LOOP_RETRY,
                WorkflowTransitionReason.LOOP_EXHAUSTED,
            }:
                raise ValueError("signal transition requires a signal-specific reason")
            if (
                self.reason is WorkflowTransitionReason.DISCOVERY_LANE_RESOLVED
                and self.completed_node
                not in {
                    WorkflowNode.DETERMINISTIC_ANALYSIS,
                    WorkflowNode.MODEL_NATIVE_DISCOVERY,
                }
            ):
                raise ValueError("discovery lane resolution requires a discovery node")
            if (
                self.reason is WorkflowTransitionReason.DISCOVERY_FAN_IN
                and self.completed_node is not WorkflowNode.NORMALIZATION
            ):
                raise ValueError("discovery fan-in requires the normalization node")
        else:
            if (
                self.completed_node is not None
                or self.signal_kind is not None
                or self.receipt_status is not None
                or self.model_call_status is not None
                or self.exhaustion_reason is not None
                or self.receipt_sha256 is not None
            ):
                raise ValueError("non-signal transition cannot carry receipt metadata")
            expected_reason = {
                WorkflowOperation.START: WorkflowTransitionReason.RUN_STARTED,
                WorkflowOperation.CANCEL: WorkflowTransitionReason.CANCELLED,
                WorkflowOperation.SUPERSEDE: WorkflowTransitionReason.SUPERSEDED,
            }.get(self.operation)
            if expected_reason is None or self.reason is not expected_reason:
                raise ValueError("non-signal reason must match its operation")
        if (self.operation is WorkflowOperation.START) != (self.sequence == 1):
            raise ValueError("only the start transition may be the journal genesis")
        expected_control_state = {
            WorkflowOperation.START: WorkflowControlState.ACTIVE,
            WorkflowOperation.SIGNAL: WorkflowControlState.ACTIVE,
            WorkflowOperation.CANCEL: WorkflowControlState.CANCELLED,
            WorkflowOperation.SUPERSEDE: WorkflowControlState.SUPERSEDED,
        }.get(self.operation)
        if self.resulting_snapshot.control_state is not expected_control_state:
            raise ValueError("resulting control state must match the transition operation")
        if (self.operation is WorkflowOperation.SUPERSEDE) != (
            self.superseding_head_sha is not None
        ):
            raise ValueError("only supersede transitions require the replacement HEAD")
        if self.operation is not WorkflowOperation.SIGNAL and (
            self.usage_delta.tokens_used != 0 or self.usage_delta.tool_calls != 0
        ):
            raise ValueError("non-signal transition cannot carry usage")
        if self.completed_node is WorkflowNode.MODEL_NATIVE_DISCOVERY:
            if self.model_call_status is None:
                raise ValueError("model-native transition requires native model status")
            if self.model_call_status is ModelCallStatus.SUCCEEDED:
                if (
                    self.receipt_status is not WorkflowReceiptStatus.SUCCEEDED
                    or self.signal_kind
                    not in {
                        WorkflowSignalKind.COMPLETED_ZERO,
                        WorkflowSignalKind.COMPLETED_WITH_CANDIDATES,
                    }
                ):
                    raise ValueError(
                        "successful model discovery requires a successful terminal signal"
                    )
            elif (
                self.receipt_status is not WorkflowReceiptStatus.NON_SUCCESS
                or self.signal_kind is not WorkflowSignalKind.NON_SUCCESS
            ):
                raise ValueError("model non-success must remain an unsatisfied lane signal")
        elif self.model_call_status is not None:
            raise ValueError("only model-native transition may carry native model status")
        if (self.reason is WorkflowTransitionReason.LOOP_EXHAUSTED) != (
            self.exhaustion_reason is not None
        ):
            raise ValueError("loop exhaustion reason must match transition reason")
        if self.sequence == 1 and self.previous_event_sha256 != ZERO_SHA256:
            raise ValueError("the genesis transition requires the zero previous hash")
        if self.sequence > 1 and self.previous_event_sha256 == ZERO_SHA256:
            raise ValueError("non-genesis transition requires a previous event hash")
        if self.event_sha256 != canonical_runtime_sha256(self._event_material()):
            raise ValueError("event hash does not match canonical event bytes")
        if self.resulting_snapshot.journal_head_sha256 != self.event_sha256:
            raise ValueError("resulting snapshot must point to this event")
        return self
