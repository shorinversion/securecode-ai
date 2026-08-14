"""Versioned public contracts for the graph-independent workflow runtime."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, Field, RootModel, model_validator

from .base import (
    CONTRACT_SCHEMA_VERSION,
    CommitSha,
    OpaqueId,
    ReasonCode,
    SemVer,
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

MAX_SAFE_INTEGER = 9_007_199_254_740_991
ZERO_SHA256 = "0" * 64


def canonical_runtime_sha256(value: object) -> str:
    """Hash a runtime contract value using the shared canonical JSON profile."""

    payload = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def has_unvalidated_runtime_state(value: object) -> bool:
    """Detect fields hidden by unsafe Pydantic copy/construct operations."""

    if isinstance(value, BaseModel):
        declared = set(type(value).model_fields)
        if set(value.__dict__) - declared:
            return True
        if getattr(value, "__pydantic_extra__", None):
            return True
        return any(
            has_unvalidated_runtime_state(getattr(value, field_name))
            for field_name in declared
            if hasattr(value, field_name)
        )
    if isinstance(value, Mapping):
        return any(
            has_unvalidated_runtime_state(key) or has_unvalidated_runtime_state(item)
            for key, item in value.items()
        )
    if isinstance(value, (tuple, list, set, frozenset)):
        return any(has_unvalidated_runtime_state(item) for item in value)
    return False


class WorkflowNode(StrEnum):
    REQUESTED = "REQUESTED"
    INTAKE = "INTAKE"
    LANGUAGE_DISCOVERY = "LANGUAGE_DISCOVERY"
    DISCOVERY_FORK = "DISCOVERY_FORK"
    DETERMINISTIC_ANALYSIS = "DETERMINISTIC_ANALYSIS"
    MODEL_NATIVE_DISCOVERY = "MODEL_NATIVE_DISCOVERY"
    NORMALIZATION = "NORMALIZATION"
    EVIDENCE_GRAPH = "EVIDENCE_GRAPH"
    AUDITOR_INVESTIGATION = "AUDITOR_INVESTIGATION"
    SKEPTIC_REVIEW = "SKEPTIC_REVIEW"
    FINDING_GATE = "FINDING_GATE"
    ROOT_CAUSE_LOCALIZATION = "ROOT_CAUSE_LOCALIZATION"
    SECURITY_TEST_GENERATION = "SECURITY_TEST_GENERATION"
    ARCHITECT = "ARCHITECT"
    VALIDATION_LADDER = "VALIDATION_LADDER"
    HUMAN_GATE = "HUMAN_GATE"
    COVERAGE_GUARD = "COVERAGE_GUARD"
    REPORTING = "REPORTING"


class WorkflowSignalKind(StrEnum):
    COMPLETED = "COMPLETED"
    COMPLETED_ZERO = "COMPLETED_ZERO"
    COMPLETED_WITH_CANDIDATES = "COMPLETED_WITH_CANDIDATES"
    NON_SUCCESS = "NON_SUCCESS"
    RETRYABLE_FAILURE = "RETRYABLE_FAILURE"
    REJECTED_WITH_EVIDENCE = "REJECTED_WITH_EVIDENCE"
    CONFIRMED_NO_REPAIR = "CONFIRMED_NO_REPAIR"
    CONFIRMED_REPAIR_REQUESTED = "CONFIRMED_REPAIR_REQUESTED"
    VALIDATED = "VALIDATED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    HUMAN_APPROVED = "HUMAN_APPROVED"
    HUMAN_REJECTED = "HUMAN_REJECTED"


class WorkflowReceiptStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    NON_SUCCESS = "NON_SUCCESS"


class WorkflowReceiptKind(StrEnum):
    NODE = "NODE"
    MODEL_DISCOVERY = "MODEL_DISCOVERY"


class WorkflowLoopKind(StrEnum):
    INVESTIGATION = "INVESTIGATION"
    REPAIR = "REPAIR"


class WorkflowExhaustionReason(StrEnum):
    TIME = "TIME"
    TOKENS = "TOKENS"
    TOOL_CALLS = "TOOL_CALLS"
    ATTEMPTS = "ATTEMPTS"
    NO_PROGRESS = "NO_PROGRESS"


class WorkflowControlState(StrEnum):
    ACTIVE = "ACTIVE"
    CANCELLED = "CANCELLED"
    SUPERSEDED = "SUPERSEDED"


class WorkflowWaitReason(StrEnum):
    WAITING_FOR_NODE = "WAITING_FOR_NODE"
    WAITING_FOR_DISCOVERY_LANES = "WAITING_FOR_DISCOVERY_LANES"
    WAITING_FOR_TRUSTED_OUTCOME_GUARD = "WAITING_FOR_TRUSTED_OUTCOME_GUARD"
    TERMINAL_CONTROL = "TERMINAL_CONTROL"


class WorkflowOperation(StrEnum):
    START = "START"
    SNAPSHOT = "SNAPSHOT"
    RESUME = "RESUME"
    SIGNAL = "SIGNAL"
    CANCEL = "CANCEL"
    SUPERSEDE = "SUPERSEDE"


class WorkflowOperationStatus(StrEnum):
    APPLIED = "APPLIED"
    SNAPSHOT = "SNAPSHOT"
    RESUMED = "RESUMED"
    REJECTED = "REJECTED"
    ERROR = "ERROR"


class WorkflowErrorCode(StrEnum):
    RUN_NOT_FOUND = "RUN_NOT_FOUND"
    RUN_ALREADY_EXISTS = "RUN_ALREADY_EXISTS"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    DEFINITION_MISMATCH = "DEFINITION_MISMATCH"
    TERMINAL_STATE = "TERMINAL_STATE"
    STALE_PRECONDITION = "STALE_PRECONDITION"
    INVALID_RECEIPT = "INVALID_RECEIPT"
    ILLEGAL_OPERATION = "ILLEGAL_OPERATION"
    JOURNAL_INVALID = "JOURNAL_INVALID"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class WorkflowActor(StrEnum):
    SYSTEM = "SYSTEM"
    POLICY = "POLICY"
    WORKER = "WORKER"
    USER = "USER"


class WorkflowTransitionReason(StrEnum):
    RUN_STARTED = "RUN_STARTED"
    NODE_COMPLETED = "NODE_COMPLETED"
    DISCOVERY_LANE_RESOLVED = "DISCOVERY_LANE_RESOLVED"
    DISCOVERY_FAN_IN = "DISCOVERY_FAN_IN"
    LOOP_RETRY = "LOOP_RETRY"
    LOOP_EXHAUSTED = "LOOP_EXHAUSTED"
    CANCELLED = "CANCELLED"
    SUPERSEDED = "SUPERSEDED"


class WorkflowLoopLimit(WireModel):
    max_attempts: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    max_tokens: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    max_tool_calls: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    max_elapsed_ms: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    max_no_progress: int = Field(ge=1, le=MAX_SAFE_INTEGER)


class WorkflowPolicyLimitRow(WireModel):
    """Loop limits selected by an existing execution-identity policy pin."""

    policy: ComponentPin
    investigation: WorkflowLoopLimit
    repair: WorkflowLoopLimit


class WorkflowTransitionRule(WireModel):
    from_node: WorkflowNode
    signal_kind: WorkflowSignalKind
    producer: ComponentPin | None
    next_nodes: tuple[WorkflowNode, ...] = Field(min_length=1, max_length=8)
    loop_kind: WorkflowLoopKind | None = None
    loop_boundary: bool = False
    exhaustion_next_nodes: tuple[WorkflowNode, ...] = Field(default=(), max_length=8)

    @model_validator(mode="after")
    def _validate_rule(self) -> Self:
        if self.from_node is WorkflowNode.MODEL_NATIVE_DISCOVERY:
            if self.producer is not None:
                raise ValueError("model-native producer is selected by execution identity")
        elif self.producer is None:
            raise ValueError("every non-model transition requires an admitted producer")
        if tuple(sorted(set(self.next_nodes), key=str)) != self.next_nodes:
            raise ValueError("next_nodes must be unique and canonically sorted")
        if tuple(sorted(set(self.exhaustion_next_nodes), key=str)) != self.exhaustion_next_nodes:
            raise ValueError("exhaustion_next_nodes must be unique and canonically sorted")
        if self.loop_kind is None and (self.loop_boundary or self.exhaustion_next_nodes):
            raise ValueError("only loop rules may define a boundary or exhaustion route")
        if self.loop_boundary != bool(self.exhaustion_next_nodes):
            raise ValueError("only loop boundaries require an exhaustion route")
        return self


class WorkflowDefinition(WireModel):
    """Canonical workflow graph and definition-owned routing policy."""

    definition_id: OpaqueId
    definition_version: SemVer
    nodes: tuple[WorkflowNode, ...] = Field(min_length=1, max_length=128)
    transitions: tuple[WorkflowTransitionRule, ...] = Field(min_length=1, max_length=512)
    compatible_stage_catalogues: tuple[ComponentPin, ...] = Field(min_length=1, max_length=32)
    policy_limit_rows: tuple[WorkflowPolicyLimitRow, ...] = Field(min_length=1, max_length=128)
    discovery_lane_nodes: tuple[WorkflowNode, WorkflowNode]
    discovery_fan_in_node: WorkflowNode
    outcome_guard_node: WorkflowNode
    content_sha256: Sha256

    def _material(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"content_sha256"})

    @property
    def component_pin(self) -> ComponentPin:
        return ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id=self.definition_id,
            component_version=self.definition_version,
            content_sha256=self.content_sha256,
        )

    @classmethod
    def build(
        cls,
        *,
        definition_id: OpaqueId,
        definition_version: SemVer,
        nodes: tuple[WorkflowNode, ...],
        transitions: tuple[WorkflowTransitionRule, ...],
        compatible_stage_catalogues: tuple[ComponentPin, ...],
        policy_limit_rows: tuple[WorkflowPolicyLimitRow, ...],
        discovery_lane_nodes: tuple[WorkflowNode, WorkflowNode],
        discovery_fan_in_node: WorkflowNode,
        outcome_guard_node: WorkflowNode,
        schema_version: SemVer = CONTRACT_SCHEMA_VERSION,
    ) -> Self:
        canonical_nodes = tuple(sorted(set(nodes), key=str))
        canonical_transitions = tuple(
            sorted(transitions, key=lambda item: (item.from_node, item.signal_kind))
        )
        canonical_catalogues = tuple(
            sorted(
                compatible_stage_catalogues,
                key=lambda item: (
                    item.component_id,
                    item.component_version,
                    item.content_sha256,
                ),
            )
        )
        canonical_rows = tuple(
            sorted(
                policy_limit_rows,
                key=lambda item: (
                    item.policy.component_id,
                    item.policy.component_version,
                    item.policy.content_sha256,
                ),
            )
        )
        material = {
            "schema_version": schema_version,
            "extensions": [],
            "definition_id": definition_id,
            "definition_version": definition_version,
            "nodes": [node.value for node in canonical_nodes],
            "transitions": [item.model_dump(mode="json") for item in canonical_transitions],
            "compatible_stage_catalogues": [
                item.model_dump(mode="json") for item in canonical_catalogues
            ],
            "policy_limit_rows": [item.model_dump(mode="json") for item in canonical_rows],
            "discovery_lane_nodes": [node.value for node in discovery_lane_nodes],
            "discovery_fan_in_node": discovery_fan_in_node.value,
            "outcome_guard_node": outcome_guard_node.value,
        }
        return cls(
            schema_version=schema_version,
            definition_id=definition_id,
            definition_version=definition_version,
            nodes=canonical_nodes,
            transitions=canonical_transitions,
            compatible_stage_catalogues=canonical_catalogues,
            policy_limit_rows=canonical_rows,
            discovery_lane_nodes=discovery_lane_nodes,
            discovery_fan_in_node=discovery_fan_in_node,
            outcome_guard_node=outcome_guard_node,
            content_sha256=canonical_runtime_sha256(material),
        )

    @model_validator(mode="after")
    def _validate_definition(self) -> Self:
        if tuple(sorted(set(self.nodes), key=str)) != self.nodes:
            raise ValueError("nodes must be unique and canonically sorted")
        transition_keys = [(item.from_node, item.signal_kind) for item in self.transitions]
        if transition_keys != sorted(set(transition_keys)):
            raise ValueError("transitions must have unique canonical keys")
        catalogue_keys = [
            (item.component_id, item.component_version, item.content_sha256)
            for item in self.compatible_stage_catalogues
        ]
        if catalogue_keys != sorted(set(catalogue_keys)):
            raise ValueError("stage catalogue pins must be unique and canonically sorted")
        policy_keys = [
            (item.policy.component_id, item.policy.component_version, item.policy.content_sha256)
            for item in self.policy_limit_rows
        ]
        if policy_keys != sorted(set(policy_keys)):
            raise ValueError("policy limit rows must be unique and canonically sorted")
        if any(
            row.investigation.max_attempts > 3 or row.repair.max_attempts > 3
            for row in self.policy_limit_rows
        ):
            raise ValueError("policy rows cannot exceed the canonical loop attempt caps")
        node_set = set(self.nodes)
        if any(
            rule.from_node not in node_set
            or not set(rule.next_nodes).issubset(node_set)
            or not set(rule.exhaustion_next_nodes).issubset(node_set)
            for rule in self.transitions
        ):
            raise ValueError("every transition node must belong to the definition")
        if self.discovery_lane_nodes != (
            WorkflowNode.DETERMINISTIC_ANALYSIS,
            WorkflowNode.MODEL_NATIVE_DISCOVERY,
        ):
            raise ValueError("the mandatory discovery lane set is fixed")
        if self.discovery_fan_in_node is not WorkflowNode.NORMALIZATION:
            raise ValueError("the discovery fan-in node must be NORMALIZATION")
        if self.outcome_guard_node is not WorkflowNode.COVERAGE_GUARD:
            raise ValueError("the outcome handoff must remain COVERAGE_GUARD")
        if self.content_sha256 != canonical_runtime_sha256(self._material()):
            raise ValueError("workflow content hash does not match canonical definition bytes")
        return self


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
        elif (
            self.signal_kind is not None
            or self.receipt_status is not None
            or self.model_call_status is not None
            or self.exhaustion_reason is not None
            or self.receipt_sha256 is not None
        ):
            raise ValueError("non-signal transition cannot carry receipt metadata")
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


class WorkflowRequestBase(WireModel):
    request_id: OpaqueId
    run_id: OpaqueId
    tenant_id: OpaqueId
    execution_identity: RunExecutionIdentity

    @model_validator(mode="after")
    def _validate_request_scope(self) -> Self:
        if self.tenant_id != self.execution_identity.repository_revision.tenant_id:
            raise ValueError("request tenant must match the execution identity")
        return self


class WorkflowMutationRequest(WorkflowRequestBase):
    idempotency_key: OpaqueId


class WorkflowCasMutationRequest(WorkflowMutationRequest):
    expected_sequence: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    expected_journal_head_sha256: Sha256
    expected_state_sha256: Sha256


class WorkflowStartRequest(WorkflowMutationRequest):
    operation: Literal[WorkflowOperation.START]


class WorkflowSnapshotRequest(WorkflowRequestBase):
    operation: Literal[WorkflowOperation.SNAPSHOT]
    expected_sequence: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    expected_journal_head_sha256: Sha256
    expected_state_sha256: Sha256


class WorkflowResumeRequest(WorkflowRequestBase):
    operation: Literal[WorkflowOperation.RESUME]
    expected_sequence: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    expected_journal_head_sha256: Sha256
    expected_state_sha256: Sha256


class WorkflowSignalRequest(WorkflowCasMutationRequest):
    operation: Literal[WorkflowOperation.SIGNAL]
    receipt: WorkflowNodeReceiptEnvelope


class WorkflowCancelRequest(WorkflowCasMutationRequest):
    operation: Literal[WorkflowOperation.CANCEL]


class WorkflowSupersedeRequest(WorkflowCasMutationRequest):
    operation: Literal[WorkflowOperation.SUPERSEDE]
    superseding_head_sha: CommitSha

    @model_validator(mode="after")
    def _validate_new_head(self) -> Self:
        if self.superseding_head_sha == self.execution_identity.repository_revision.head_sha:
            raise ValueError("superseding head must differ from the admitted head")
        return self


WorkflowRequestValue = Annotated[
    WorkflowStartRequest
    | WorkflowSnapshotRequest
    | WorkflowResumeRequest
    | WorkflowSignalRequest
    | WorkflowCancelRequest
    | WorkflowSupersedeRequest,
    Field(discriminator="operation"),
]


class WorkflowRuntimeRequest(RootModel[WorkflowRequestValue]):
    """One closed discriminated union for every WorkflowRuntime operation."""


class WorkflowRuntimeResult(WireModel):
    request_id: OpaqueId
    run_id: OpaqueId
    tenant_id: OpaqueId
    operation: WorkflowOperation
    operation_status: WorkflowOperationStatus
    error_code: WorkflowErrorCode | None = None
    retryable: bool = False
    snapshot: WorkflowSnapshot | None = None
    transition_event: WorkflowTransitionEvent | None = None

    @model_validator(mode="after")
    def _validate_result_shape(self) -> Self:
        if self.retryable:
            raise ValueError("P1.9 runtime results are never implicitly retryable")
        if self.operation_status is WorkflowOperationStatus.APPLIED:
            if self.operation not in {
                WorkflowOperation.START,
                WorkflowOperation.SIGNAL,
                WorkflowOperation.CANCEL,
                WorkflowOperation.SUPERSEDE,
            }:
                raise ValueError("only state-changing operations can be APPLIED")
            if (
                self.snapshot is None
                or self.transition_event is None
                or self.error_code is not None
            ):
                raise ValueError("APPLIED requires one snapshot/event and no error")
            if self.snapshot != self.transition_event.resulting_snapshot:
                raise ValueError("result snapshot must equal the transition snapshot")
            if self.transition_event.operation is not self.operation:
                raise ValueError("result operation must match the transition operation")
        elif self.operation_status in {
            WorkflowOperationStatus.SNAPSHOT,
            WorkflowOperationStatus.RESUMED,
        }:
            expected_operation = (
                WorkflowOperation.SNAPSHOT
                if self.operation_status is WorkflowOperationStatus.SNAPSHOT
                else WorkflowOperation.RESUME
            )
            if self.operation is not expected_operation:
                raise ValueError("read result status must match its operation")
            if (
                self.snapshot is None
                or self.transition_event is not None
                or self.error_code is not None
            ):
                raise ValueError("read/resume result requires only a snapshot")
        elif self.operation_status is WorkflowOperationStatus.REJECTED:
            if (
                self.error_code is None
                or self.snapshot is not None
                or self.transition_event is not None
            ):
                raise ValueError("REJECTED requires only a closed error code")
            if self.error_code is WorkflowErrorCode.INTERNAL_ERROR:
                raise ValueError("INTERNAL_ERROR requires ERROR operation status")
        elif (
            self.error_code is not WorkflowErrorCode.INTERNAL_ERROR
            or self.snapshot is not None
            or self.transition_event is not None
        ):
            raise ValueError("ERROR requires only INTERNAL_ERROR")
        if self.snapshot is not None and (
            self.tenant_id != self.snapshot.tenant_id or self.run_id != self.snapshot.run_id
        ):
            raise ValueError("result scope must match its snapshot")
        return self


PUBLIC_RUNTIME_ROOT_MODELS: dict[str, type[WireModel] | type[RootModel[Any]]] = {
    "workflow-definition": WorkflowDefinition,
    "workflow-runtime-request": WorkflowRuntimeRequest,
    "workflow-runtime-result": WorkflowRuntimeResult,
    "workflow-snapshot": WorkflowSnapshot,
    "workflow-transition-event": WorkflowTransitionEvent,
}


__all__ = [
    "MAX_SAFE_INTEGER",
    "PUBLIC_RUNTIME_ROOT_MODELS",
    "ZERO_SHA256",
    "WorkflowActor",
    "WorkflowCancelRequest",
    "WorkflowControlState",
    "WorkflowDefinition",
    "WorkflowErrorCode",
    "WorkflowExhaustionReason",
    "WorkflowLaneResolution",
    "WorkflowLoopKind",
    "WorkflowLoopLimit",
    "WorkflowLoopUsage",
    "WorkflowNode",
    "WorkflowNodeAttempt",
    "WorkflowNodeReceipt",
    "WorkflowNodeReceiptEnvelope",
    "WorkflowOperation",
    "WorkflowOperationStatus",
    "WorkflowPolicyLimitRow",
    "WorkflowReceiptKind",
    "WorkflowReceiptStatus",
    "WorkflowRequestValue",
    "WorkflowResumeRequest",
    "WorkflowRuntimeRequest",
    "WorkflowRuntimeResult",
    "WorkflowSignalKind",
    "WorkflowSignalRequest",
    "WorkflowSnapshot",
    "WorkflowSnapshotRequest",
    "WorkflowStartRequest",
    "WorkflowSupersedeRequest",
    "WorkflowTransitionEvent",
    "WorkflowTransitionReason",
    "WorkflowTransitionRule",
    "WorkflowUsageDelta",
    "WorkflowWaitReason",
    "canonical_runtime_sha256",
    "has_unvalidated_runtime_state",
]
