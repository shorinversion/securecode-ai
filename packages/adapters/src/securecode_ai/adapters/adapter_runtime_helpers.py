"""Process-local, lock-linearized WorkflowRuntime adapter."""

from __future__ import annotations

from securecode_ai.core import (
    CONTRACT_SCHEMA_VERSION,
    RunExecutionIdentity,
    WorkflowErrorCode,
    WorkflowOperation,
    WorkflowOperationStatus,
    WorkflowRuntimeResult,
    WorkflowSnapshot,
    WorkflowTransitionEvent,
)

from .adapter_runtime_state import RuntimeClock, _Reservation, _RunRecord


class _LocalWorkflowRuntimeHelpers:
    __slots__ = ()

    _clock: RuntimeClock
    _idempotency: dict[tuple[str, str, str], _Reservation]

    @staticmethod
    def _run_key(tenant_id: str, run_id: str) -> tuple[str, str]:
        return (tenant_id, run_id)

    @staticmethod
    def _idempotency_key(tenant_id: str, run_id: str, idempotency_key: str) -> tuple[str, str, str]:
        return (tenant_id, run_id, idempotency_key)

    @staticmethod
    def _invalid_request(
        *,
        operation: WorkflowOperation,
        error_code: WorkflowErrorCode,
    ) -> WorkflowRuntimeResult:
        return _LocalWorkflowRuntimeHelpers._rejected(
            request_id="invalid-request",
            run_id="invalid-run",
            tenant_id="invalid-tenant",
            operation=operation,
            error_code=error_code,
        )

    @staticmethod
    def _rejected(
        *,
        request_id: str,
        run_id: str,
        tenant_id: str,
        operation: WorkflowOperation,
        error_code: WorkflowErrorCode,
    ) -> WorkflowRuntimeResult:
        return WorkflowRuntimeResult(
            schema_version=CONTRACT_SCHEMA_VERSION,
            request_id=request_id,
            run_id=run_id,
            tenant_id=tenant_id,
            operation=operation,
            operation_status=WorkflowOperationStatus.REJECTED,
            error_code=error_code,
        )

    @staticmethod
    def _error(
        *,
        request_id: str,
        run_id: str,
        tenant_id: str,
        operation: WorkflowOperation,
    ) -> WorkflowRuntimeResult:
        return WorkflowRuntimeResult(
            schema_version=CONTRACT_SCHEMA_VERSION,
            request_id=request_id,
            run_id=run_id,
            tenant_id=tenant_id,
            operation=operation,
            operation_status=WorkflowOperationStatus.ERROR,
            error_code=WorkflowErrorCode.INTERNAL_ERROR,
        )

    @staticmethod
    def _applied(
        *,
        request_id: str,
        run_id: str,
        tenant_id: str,
        operation: WorkflowOperation,
        event: WorkflowTransitionEvent,
    ) -> WorkflowRuntimeResult:
        return WorkflowRuntimeResult(
            schema_version=CONTRACT_SCHEMA_VERSION,
            request_id=request_id,
            run_id=run_id,
            tenant_id=tenant_id,
            operation=operation,
            operation_status=WorkflowOperationStatus.APPLIED,
            snapshot=event.resulting_snapshot,
            transition_event=event,
        )

    def _existing_reservation(
        self,
        *,
        tenant_id: str,
        run_id: str,
        idempotency_key: str,
        semantic_sha256: str,
        request_id: str,
        operation: WorkflowOperation,
    ) -> WorkflowRuntimeResult | None:
        reservation = self._idempotency.get(
            self._idempotency_key(tenant_id, run_id, idempotency_key)
        )
        if reservation is None:
            return None
        if reservation.semantic_sha256 == semantic_sha256:
            return reservation.result
        return self._rejected(
            request_id=request_id,
            run_id=run_id,
            tenant_id=tenant_id,
            operation=operation,
            error_code=WorkflowErrorCode.IDEMPOTENCY_CONFLICT,
        )

    def _reserve(
        self,
        *,
        tenant_id: str,
        run_id: str,
        idempotency_key: str,
        semantic_sha256: str,
        result: WorkflowRuntimeResult,
    ) -> WorkflowRuntimeResult:
        self._idempotency[self._idempotency_key(tenant_id, run_id, idempotency_key)] = _Reservation(
            semantic_sha256, result
        )
        return result

    @staticmethod
    def _identity_error(
        record: _RunRecord,
        identity: RunExecutionIdentity,
    ) -> WorkflowErrorCode | None:
        return None if record.identity == identity else WorkflowErrorCode.IDENTITY_MISMATCH

    @staticmethod
    def _cas_error(
        snapshot: WorkflowSnapshot,
        *,
        expected_sequence: int,
        expected_journal_head_sha256: str,
        expected_state_sha256: str,
    ) -> WorkflowErrorCode | None:
        if (
            snapshot.journal_sequence != expected_sequence
            or snapshot.journal_head_sha256 != expected_journal_head_sha256
            or snapshot.state_sha256 != expected_state_sha256
        ):
            return WorkflowErrorCode.STALE_PRECONDITION
        return None

    def _runtime_elapsed(self, record: _RunRecord) -> int:
        return max(0, self._clock() - record.started_at_ms)
