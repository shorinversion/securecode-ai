"""Versioned public contracts for the graph-independent workflow runtime."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, RootModel, model_validator

from .base import (
    CommitSha,
    OpaqueId,
    Sha256,
    WireModel,
)
from .domain import (
    RunExecutionIdentity,
)
from .runtime_contract_definition import (
    MAX_SAFE_INTEGER,
    WorkflowErrorCode,
    WorkflowOperation,
    WorkflowOperationStatus,
)
from .runtime_contract_journal import (
    WorkflowNodeReceiptEnvelope,
    WorkflowSnapshot,
    WorkflowTransitionEvent,
)


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

    @model_validator(mode="after")
    def _validate_receipt_scope(self) -> Self:
        if (
            self.receipt.tenant_id != self.tenant_id
            or self.receipt.run_id != self.run_id
            or self.receipt.execution_identity_hash
            != self.execution_identity.execution_identity_hash
        ):
            raise ValueError("receipt scope must match the signal request")
        return self


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
            if (
                self.tenant_id != self.transition_event.tenant_id
                or self.run_id != self.transition_event.run_id
            ):
                raise ValueError("result scope must match its transition event")
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
