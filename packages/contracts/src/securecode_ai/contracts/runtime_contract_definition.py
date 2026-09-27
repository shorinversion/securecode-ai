"""Versioned public contracts for the graph-independent workflow runtime."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, Field, model_validator

from .base import (
    CONTRACT_SCHEMA_VERSION,
    OpaqueId,
    SemVer,
    Sha256,
    WireModel,
)
from .domain import (
    ComponentPin,
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
        if not declared.issubset(value.__dict__):
            return True
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
