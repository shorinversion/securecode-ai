"""Versioned public contracts for the graph-independent workflow runtime."""

from __future__ import annotations

from typing import Any

from pydantic import RootModel

from .base import (
    WireModel,
)
from .runtime_contract_definition import (
    MAX_SAFE_INTEGER,
    ZERO_SHA256,
    WorkflowActor,
    WorkflowControlState,
    WorkflowDefinition,
    WorkflowErrorCode,
    WorkflowExhaustionReason,
    WorkflowLoopKind,
    WorkflowLoopLimit,
    WorkflowNode,
    WorkflowOperation,
    WorkflowOperationStatus,
    WorkflowPolicyLimitRow,
    WorkflowReceiptKind,
    WorkflowReceiptStatus,
    WorkflowSignalKind,
    WorkflowTransitionReason,
    WorkflowTransitionRule,
    WorkflowWaitReason,
    canonical_runtime_sha256,
    has_unvalidated_runtime_state,
)
from .runtime_contract_journal import (
    WorkflowLaneResolution,
    WorkflowLoopUsage,
    WorkflowNodeAttempt,
    WorkflowNodeReceipt,
    WorkflowNodeReceiptEnvelope,
    WorkflowSnapshot,
    WorkflowTransitionEvent,
    WorkflowUsageDelta,
)
from .runtime_contract_requests import (
    WorkflowCancelRequest,
    WorkflowCasMutationRequest,
    WorkflowMutationRequest,
    WorkflowRequestBase,
    WorkflowRequestValue,
    WorkflowResumeRequest,
    WorkflowRuntimeRequest,
    WorkflowRuntimeResult,
    WorkflowSignalRequest,
    WorkflowSnapshotRequest,
    WorkflowStartRequest,
    WorkflowSupersedeRequest,
)

for _runtime_contract_type in (
    WorkflowLoopLimit,
    WorkflowPolicyLimitRow,
    WorkflowTransitionRule,
    WorkflowDefinition,
    WorkflowUsageDelta,
    WorkflowNodeReceipt,
    WorkflowNodeReceiptEnvelope,
    WorkflowLaneResolution,
    WorkflowNodeAttempt,
    WorkflowLoopUsage,
    WorkflowSnapshot,
    WorkflowTransitionEvent,
    WorkflowRequestBase,
    WorkflowMutationRequest,
    WorkflowCasMutationRequest,
    WorkflowStartRequest,
    WorkflowSnapshotRequest,
    WorkflowResumeRequest,
    WorkflowSignalRequest,
    WorkflowCancelRequest,
    WorkflowSupersedeRequest,
    WorkflowRuntimeRequest,
    WorkflowRuntimeResult,
):
    _runtime_contract_type.__module__ = __name__
del _runtime_contract_type
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
