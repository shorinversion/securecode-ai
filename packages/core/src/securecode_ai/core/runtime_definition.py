"""Deterministic workflow definition, transition, and replay authority."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from types import MappingProxyType
from typing import Protocol

from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION, ComponentPin, RunExecutionIdentity
from securecode_ai.contracts.runtime import (
    WorkflowCancelRequest,
    WorkflowDefinition,
    WorkflowErrorCode,
    WorkflowLoopKind,
    WorkflowLoopLimit,
    WorkflowNode,
    WorkflowPolicyLimitRow,
    WorkflowResumeRequest,
    WorkflowRuntimeResult,
    WorkflowSignalKind,
    WorkflowSignalRequest,
    WorkflowSnapshotRequest,
    WorkflowStartRequest,
    WorkflowSupersedeRequest,
    WorkflowTransitionRule,
)

DEFAULT_STAGE_CATALOGUE_PIN = ComponentPin(
    schema_version=CONTRACT_SCHEMA_VERSION,
    component_id="core-mvp-0.2.0",
    component_version="0.2.0",
    content_sha256="\x61\x64\x61\x64\x32\x65\x30\x35\x66\x63\x38\x32\x32\x34\x38\x35\x66\x34\x35\x61\x63\x31\x36\x34\x32\x39\x39\x34\x36\x32\x64\x33\x36\x30\x65\x63\x62\x30\x31\x35\x33\x32\x37\x62\x38\x34\x64\x30\x39\x63\x30\x36\x34\x61\x36\x39\x37\x63\x31\x39\x33\x64\x31\x64",
)
DEFAULT_POLICY_PIN = ComponentPin(
    schema_version=CONTRACT_SCHEMA_VERSION,
    component_id="private-model-source",
    component_version="1.0.0",
    content_sha256="\x36\x32\x66\x65\x38\x62\x64\x33\x34\x30\x36\x66\x32\x37\x62\x33\x32\x31\x38\x34\x36\x30\x33\x37\x31\x39\x61\x62\x39\x63\x38\x30\x63\x33\x65\x33\x33\x36\x66\x34\x39\x63\x32\x34\x30\x35\x65\x32\x66\x33\x39\x32\x36\x65\x35\x37\x35\x61\x31\x38\x63\x39\x34\x66",
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
