"""Process-local, lock-linearized WorkflowRuntime adapter."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from securecode_ai.core import (
    CONTRACT_SCHEMA_VERSION,
    DEFAULT_WORKFLOW_REGISTRY,
    RunExecutionIdentity,
    WorkflowCancelRequest,
    WorkflowControlState,
    WorkflowDecisionError,
    WorkflowDefinition,
    WorkflowDefinitionRegistry,
    WorkflowErrorCode,
    WorkflowOperation,
    WorkflowOperationStatus,
    WorkflowResumeRequest,
    WorkflowRuntimeResult,
    WorkflowSignalRequest,
    WorkflowSnapshot,
    WorkflowSnapshotRequest,
    WorkflowStartRequest,
    WorkflowSupersedeRequest,
    WorkflowTransitionEvent,
    canonical_workflow_request_hash,
    control_workflow,
    has_unvalidated_runtime_state,
    replay_workflow_journal,
    signal_workflow,
    start_workflow,
    validate_workflow_signal_preconditions,
)

RuntimeClock = Callable[[], int]


def _monotonic_milliseconds() -> int:
    return time.monotonic_ns() // 1_000_000


@dataclass(slots=True)
class _RunRecord:
    identity: RunExecutionIdentity
    definition: WorkflowDefinition
    journal: list[WorkflowTransitionEvent]
    started_at_ms: int

    @property
    def snapshot(self) -> WorkflowSnapshot:
        return self.journal[-1].resulting_snapshot


@dataclass(frozen=True, slots=True)
class _Reservation:
    semantic_sha256: str
    result: WorkflowRuntimeResult


class LocalWorkflowRuntime:
    """In-memory runtime with process-local atomic idempotency and CAS."""

    __slots__ = ("_clock", "_idempotency", "_lock", "_registry", "_runs")

    def __init__(
        self,
        *,
        registry: WorkflowDefinitionRegistry = DEFAULT_WORKFLOW_REGISTRY,
        clock: RuntimeClock = _monotonic_milliseconds,
    ) -> None:
        self._registry = registry
        self._clock = clock
        self._lock = threading.RLock()
        self._runs: dict[tuple[str, str], _RunRecord] = {}
        self._idempotency: dict[tuple[str, str, str], _Reservation] = {}

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
        return LocalWorkflowRuntime._rejected(
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

    def start(self, request: WorkflowStartRequest) -> WorkflowRuntimeResult:
        try:
            if has_unvalidated_runtime_state(request):
                raise ValueError("unvalidated request state")
            request = WorkflowStartRequest.model_validate_json(request.model_dump_json())
        except Exception:
            return self._invalid_request(
                operation=WorkflowOperation.START,
                error_code=WorkflowErrorCode.ILLEGAL_OPERATION,
            )
        semantic_hash = canonical_workflow_request_hash(request)
        with self._lock:
            prior = self._existing_reservation(
                tenant_id=request.tenant_id,
                run_id=request.run_id,
                idempotency_key=request.idempotency_key,
                semantic_sha256=semantic_hash,
                request_id=request.request_id,
                operation=request.operation,
            )
            if prior is not None:
                return prior
            run_key = self._run_key(request.tenant_id, request.run_id)
            if run_key in self._runs:
                result = self._rejected(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                    error_code=WorkflowErrorCode.RUN_ALREADY_EXISTS,
                )
                return self._reserve(
                    tenant_id=request.tenant_id,
                    run_id=request.run_id,
                    idempotency_key=request.idempotency_key,
                    semantic_sha256=semantic_hash,
                    result=result,
                )
            try:
                started_at = self._clock()
                decision = start_workflow(
                    request,
                    registry=self._registry,
                    operation_semantic_sha256=semantic_hash,
                )
                definition = self._registry.resolve(request.execution_identity)
                record = _RunRecord(
                    request.execution_identity,
                    definition,
                    [decision.event],
                    started_at,
                )
                result = self._applied(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                    event=decision.event,
                )
                self._runs[run_key] = record
            except WorkflowDecisionError as error:
                result = self._rejected(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                    error_code=error.code,
                )
            except Exception:
                result = self._error(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                )
            return self._reserve(
                tenant_id=request.tenant_id,
                run_id=request.run_id,
                idempotency_key=request.idempotency_key,
                semantic_sha256=semantic_hash,
                result=result,
            )

    def _read_record(
        self,
        *,
        tenant_id: str,
        run_id: str,
        identity: RunExecutionIdentity,
    ) -> tuple[_RunRecord | None, WorkflowErrorCode | None]:
        record = self._runs.get(self._run_key(tenant_id, run_id))
        if record is None:
            return None, WorkflowErrorCode.RUN_NOT_FOUND
        identity_error = self._identity_error(record, identity)
        if identity_error is not None:
            return None, identity_error
        try:
            definition = self._registry.resolve(identity)
        except WorkflowDecisionError as error:
            return None, error.code
        except Exception:
            return record, WorkflowErrorCode.INTERNAL_ERROR
        if definition != record.definition:
            return None, WorkflowErrorCode.DEFINITION_MISMATCH
        return record, None

    def snapshot(self, request: WorkflowSnapshotRequest) -> WorkflowRuntimeResult:
        try:
            if has_unvalidated_runtime_state(request):
                raise ValueError("unvalidated request state")
            request = WorkflowSnapshotRequest.model_validate_json(request.model_dump_json())
        except Exception:
            return self._invalid_request(
                operation=WorkflowOperation.SNAPSHOT,
                error_code=WorkflowErrorCode.ILLEGAL_OPERATION,
            )
        with self._lock:
            record, read_error = self._read_record(
                tenant_id=request.tenant_id,
                run_id=request.run_id,
                identity=request.execution_identity,
            )
            if record is None:
                return self._rejected(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                    error_code=read_error or WorkflowErrorCode.INTERNAL_ERROR,
                )
            error = self._cas_error(
                record.snapshot,
                expected_sequence=request.expected_sequence,
                expected_journal_head_sha256=request.expected_journal_head_sha256,
                expected_state_sha256=request.expected_state_sha256,
            )
            if error is not None:
                return self._rejected(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                    error_code=error,
                )
            if read_error is WorkflowErrorCode.INTERNAL_ERROR:
                return self._error(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                )
            return WorkflowRuntimeResult(
                schema_version=CONTRACT_SCHEMA_VERSION,
                request_id=request.request_id,
                run_id=request.run_id,
                tenant_id=request.tenant_id,
                operation=request.operation,
                operation_status=WorkflowOperationStatus.SNAPSHOT,
                snapshot=record.snapshot,
            )

    def resume(self, request: WorkflowResumeRequest) -> WorkflowRuntimeResult:
        try:
            if has_unvalidated_runtime_state(request):
                raise ValueError("unvalidated request state")
            request = WorkflowResumeRequest.model_validate_json(request.model_dump_json())
        except Exception:
            return self._invalid_request(
                operation=WorkflowOperation.RESUME,
                error_code=WorkflowErrorCode.ILLEGAL_OPERATION,
            )
        with self._lock:
            record, read_error = self._read_record(
                tenant_id=request.tenant_id,
                run_id=request.run_id,
                identity=request.execution_identity,
            )
            if record is None:
                return self._rejected(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                    error_code=read_error or WorkflowErrorCode.INTERNAL_ERROR,
                )
            error = self._cas_error(
                record.snapshot,
                expected_sequence=request.expected_sequence,
                expected_journal_head_sha256=request.expected_journal_head_sha256,
                expected_state_sha256=request.expected_state_sha256,
            )
            if error is not None:
                return self._rejected(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                    error_code=error,
                )
            if read_error is WorkflowErrorCode.INTERNAL_ERROR:
                return self._error(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                )
            try:
                replayed = replay_workflow_journal(
                    record.identity,
                    request.run_id,
                    tuple(record.journal),
                    registry=self._registry,
                )
                if replayed != record.snapshot:
                    raise WorkflowDecisionError(WorkflowErrorCode.JOURNAL_INVALID)
            except WorkflowDecisionError as replay_error:
                return self._rejected(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                    error_code=replay_error.code,
                )
            except Exception:
                return self._error(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                )
            return WorkflowRuntimeResult(
                schema_version=CONTRACT_SCHEMA_VERSION,
                request_id=request.request_id,
                run_id=request.run_id,
                tenant_id=request.tenant_id,
                operation=request.operation,
                operation_status=WorkflowOperationStatus.RESUMED,
                snapshot=replayed,
            )

    def _mutate(
        self,
        request: WorkflowSignalRequest | WorkflowCancelRequest | WorkflowSupersedeRequest,
    ) -> WorkflowRuntimeResult:
        expected_operation = (
            WorkflowOperation.SIGNAL
            if isinstance(request, WorkflowSignalRequest)
            else WorkflowOperation.CANCEL
            if isinstance(request, WorkflowCancelRequest)
            else WorkflowOperation.SUPERSEDE
        )
        try:
            if has_unvalidated_runtime_state(request):
                raise ValueError("unvalidated request state")
            if isinstance(request, WorkflowSignalRequest):
                request = WorkflowSignalRequest.model_validate_json(request.model_dump_json())
            elif isinstance(request, WorkflowCancelRequest):
                request = WorkflowCancelRequest.model_validate_json(request.model_dump_json())
            else:
                request = WorkflowSupersedeRequest.model_validate_json(request.model_dump_json())
        except Exception:
            return self._invalid_request(
                operation=expected_operation,
                error_code=(
                    WorkflowErrorCode.INVALID_RECEIPT
                    if isinstance(request, WorkflowSignalRequest)
                    else WorkflowErrorCode.ILLEGAL_OPERATION
                ),
            )
        semantic_hash = canonical_workflow_request_hash(request)
        with self._lock:
            prior = self._existing_reservation(
                tenant_id=request.tenant_id,
                run_id=request.run_id,
                idempotency_key=request.idempotency_key,
                semantic_sha256=semantic_hash,
                request_id=request.request_id,
                operation=request.operation,
            )
            if prior is not None:
                return prior
            record, read_error = self._read_record(
                tenant_id=request.tenant_id,
                run_id=request.run_id,
                identity=request.execution_identity,
            )
            if record is None:
                result = (
                    self._error(
                        request_id=request.request_id,
                        run_id=request.run_id,
                        tenant_id=request.tenant_id,
                        operation=request.operation,
                    )
                    if read_error is WorkflowErrorCode.INTERNAL_ERROR
                    else self._rejected(
                        request_id=request.request_id,
                        run_id=request.run_id,
                        tenant_id=request.tenant_id,
                        operation=request.operation,
                        error_code=read_error or WorkflowErrorCode.RUN_NOT_FOUND,
                    )
                )
                return self._reserve(
                    tenant_id=request.tenant_id,
                    run_id=request.run_id,
                    idempotency_key=request.idempotency_key,
                    semantic_sha256=semantic_hash,
                    result=result,
                )
            if record.snapshot.control_state is not WorkflowControlState.ACTIVE:
                result = self._rejected(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                    error_code=WorkflowErrorCode.TERMINAL_STATE,
                )
                return self._reserve(
                    tenant_id=request.tenant_id,
                    run_id=request.run_id,
                    idempotency_key=request.idempotency_key,
                    semantic_sha256=semantic_hash,
                    result=result,
                )
            error = self._cas_error(
                record.snapshot,
                expected_sequence=request.expected_sequence,
                expected_journal_head_sha256=request.expected_journal_head_sha256,
                expected_state_sha256=request.expected_state_sha256,
            )
            if error is not None:
                result = self._rejected(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                    error_code=error,
                )
                return self._reserve(
                    tenant_id=request.tenant_id,
                    run_id=request.run_id,
                    idempotency_key=request.idempotency_key,
                    semantic_sha256=semantic_hash,
                    result=result,
                )
            if isinstance(request, WorkflowSignalRequest):
                try:
                    validate_workflow_signal_preconditions(
                        record.snapshot,
                        request,
                        definition=record.definition,
                    )
                except WorkflowDecisionError as validation_error:
                    result = self._rejected(
                        request_id=request.request_id,
                        run_id=request.run_id,
                        tenant_id=request.tenant_id,
                        operation=request.operation,
                        error_code=validation_error.code,
                    )
                    return self._reserve(
                        tenant_id=request.tenant_id,
                        run_id=request.run_id,
                        idempotency_key=request.idempotency_key,
                        semantic_sha256=semantic_hash,
                        result=result,
                    )
                except Exception:
                    read_error = WorkflowErrorCode.INTERNAL_ERROR
            if read_error is WorkflowErrorCode.INTERNAL_ERROR:
                result = self._error(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                )
                return self._reserve(
                    tenant_id=request.tenant_id,
                    run_id=request.run_id,
                    idempotency_key=request.idempotency_key,
                    semantic_sha256=semantic_hash,
                    result=result,
                )
            try:
                elapsed = self._runtime_elapsed(record)
                if isinstance(request, WorkflowSignalRequest):
                    decision = signal_workflow(
                        record.snapshot,
                        request,
                        registry=self._registry,
                        operation_semantic_sha256=semantic_hash,
                        runtime_elapsed_ms=elapsed,
                    )
                else:
                    decision = control_workflow(
                        record.snapshot,
                        request,
                        registry=self._registry,
                        operation_semantic_sha256=semantic_hash,
                        runtime_elapsed_ms=elapsed,
                    )
                result = self._applied(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                    event=decision.event,
                )
                record.journal.append(decision.event)
            except WorkflowDecisionError as decision_error:
                result = self._rejected(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                    error_code=decision_error.code,
                )
            except Exception:
                result = self._error(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    operation=request.operation,
                )
            return self._reserve(
                tenant_id=request.tenant_id,
                run_id=request.run_id,
                idempotency_key=request.idempotency_key,
                semantic_sha256=semantic_hash,
                result=result,
            )

    def signal(self, request: object) -> WorkflowRuntimeResult:
        if not isinstance(request, WorkflowSignalRequest):
            return self._invalid_request(
                operation=WorkflowOperation.SIGNAL,
                error_code=WorkflowErrorCode.ILLEGAL_OPERATION,
            )
        return self._mutate(request)

    def cancel(self, request: object) -> WorkflowRuntimeResult:
        if not isinstance(request, WorkflowCancelRequest):
            return self._invalid_request(
                operation=WorkflowOperation.CANCEL,
                error_code=WorkflowErrorCode.ILLEGAL_OPERATION,
            )
        return self._mutate(request)

    def supersede(self, request: object) -> WorkflowRuntimeResult:
        if not isinstance(request, WorkflowSupersedeRequest):
            return self._invalid_request(
                operation=WorkflowOperation.SUPERSEDE,
                error_code=WorkflowErrorCode.ILLEGAL_OPERATION,
            )
        return self._mutate(request)


__all__ = ["LocalWorkflowRuntime", "RuntimeClock"]
