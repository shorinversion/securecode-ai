"""Source-free reconciliation of Auditor captures with final Core receipts.

This module is an adapter-local collector.  It does not issue authorization,
declare a provider live, or make a conformance/admission decision.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from typing import Final

from securecode_ai.adapters.local_provider_admission import (
    AuditorCandidateEvidence,
    AuditorInvocationEvidence,
    auditor_selection_sha256,
)
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    DiscoveryCandidate,
    ModelCallStatus,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    ModelUsage,
)
from securecode_ai.core.evidence_graph import EvidenceGraph
from securecode_ai.core.evidence_package import (
    DEFAULT_EVIDENCE_PACKAGE_LIMITS,
    EvidencePackage,
    EvidencePackageLimits,
)
from securecode_ai.core.investigation import (
    AuditorAttemptReceipt,
    AuditorInvestigationReceipt,
    InvestigationBudget,
)

from .product_runtime import ProductAuditorInvocationObservation
from .product_scan import ProductCandidateFlow, ProductCandidatePreparationFailure

_MAX_CAPTURES: Final = 4_096
_MAX_CAPTURE_METADATA_BYTES: Final = 32 * 1024 * 1024


class ProductConformanceError(ValueError):
    """A safe, non-echoing recorder failure."""

    safe_message: Final = "product auditor conformance collection failed"

    def __init__(self) -> None:
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class _Capture:
    request: ModelRequest
    package: EvidencePackage
    usage: ModelUsage
    status: ModelCallStatus
    schema_valid: bool


class ProductAuditorEvidenceRecorder:
    """Collect immutable pre-collection captures and reconcile final receipts.

    ``observe`` is suitable as ``ProductAuditorInvoker``'s observer.  It raises
    only the fixed safe error after latching invalid collection state, so the
    invoker can turn a collection fault into its documented non-success result.
    """

    __slots__ = (
        "_budget",
        "_captures",
        "_discovery_request",
        "_failed",
        "_final_flow_key",
        "_finalized",
        "_idempotency_keys",
        "_limits",
        "_metadata_bytes",
        "_request_ids",
        "_result",
    )

    def __init__(
        self,
        *,
        discovery_request: ModelRequest,
        investigation_budget: InvestigationBudget,
        selection_limits: EvidencePackageLimits = DEFAULT_EVIDENCE_PACKAGE_LIMITS,
    ) -> None:
        try:
            if (
                type(discovery_request) is not ModelRequest
                or type(investigation_budget) is not InvestigationBudget
                or type(selection_limits) is not EvidencePackageLimits
            ):
                raise ValueError
            snapshot = ModelRequest.model_validate_json(discovery_request.model_dump_json())
            if (
                snapshot.role is not ModelRole.DISCOVERY
                or snapshot.mode is not ModelPurpose.MODEL_NATIVE_DISCOVERY
                or snapshot.evidence
            ):
                raise ValueError
            self._discovery_request = snapshot
            self._budget = InvestigationBudget(
                investigation_budget.max_attempts,
                investigation_budget.max_tokens,
                investigation_budget.max_tool_calls,
                investigation_budget.max_elapsed_ms,
                investigation_budget.max_no_progress,
                investigation_budget.max_context_rounds,
            )
            self._limits = EvidencePackageLimits(
                selection_limits.max_context_bytes,
                selection_limits.max_input_tokens,
                selection_limits.max_evidence_items,
            )
        except (AttributeError, TypeError, ValueError):
            raise ProductConformanceError() from None
        self._captures: dict[tuple[str, int, int], _Capture] = {}
        self._request_ids = {snapshot.request_id}
        self._idempotency_keys = {snapshot.idempotency_key}
        self._failed = False
        self._finalized = False
        self._final_flow_key: str | None = None
        self._result: tuple[AuditorCandidateEvidence, ...] | None = None
        self._metadata_bytes = 0

    def observe(self, observation: ProductAuditorInvocationObservation) -> None:
        """Snapshot a source-free capture before synchronous collection returns."""

        if self._failed or self._finalized:
            self._failed = True
            raise ProductConformanceError()
        try:
            capture = self._snapshot(observation)
            key = (
                capture.package.candidate_id,
                capture.package.candidate_version,
                capture.request.attempt,
            )
            if (
                len(self._captures) >= _MAX_CAPTURES
                or key in self._captures
                or capture.request.request_id in self._request_ids
                or capture.request.idempotency_key in self._idempotency_keys
            ):
                raise ValueError
            metadata_bytes = self._capture_metadata_bytes(capture)
            if self._metadata_bytes + metadata_bytes > _MAX_CAPTURE_METADATA_BYTES:
                raise ValueError
            self._captures[key] = capture
            self._request_ids.add(capture.request.request_id)
            self._idempotency_keys.add(capture.request.idempotency_key)
            self._metadata_bytes += metadata_bytes
        except (AttributeError, TypeError, ValueError):
            self._failed = True
            raise ProductConformanceError() from None

    def finalize(self, flow: ProductCandidateFlow) -> tuple[AuditorCandidateEvidence, ...]:
        """Return graph-ordered evidence only when captures exactly match Core."""

        try:
            if self._failed or type(flow) is not ProductCandidateFlow:
                raise ValueError
            flow_key = self._flow_key(flow)
            if self._finalized:
                if self._result is None or self._final_flow_key != flow_key:
                    raise ValueError
                return self._result
            if (
                flow.graph.tenant_id != self._discovery_request.tenant_id
                or flow.graph.head_sha != self._discovery_request.head_sha
                or flow.discovery.receipt.tenant_id != self._discovery_request.tenant_id
                or flow.discovery.receipt.head_sha != self._discovery_request.head_sha
                or len(flow.graph.candidates) != len(flow.investigations)
            ):
                raise ValueError
            if not flow.graph.candidates:
                if self._captures:
                    raise ValueError
                self._finalized = True
                self._final_flow_key = flow_key
                self._result = ()
                return self._result
            output: list[AuditorCandidateEvidence] = []
            expected_keys: set[tuple[str, int, int]] = set()
            for candidate, investigation in zip(
                flow.graph.candidates, flow.investigations, strict=True
            ):
                if type(investigation) is ProductCandidatePreparationFailure:
                    raise ValueError
                if type(investigation) is not AuditorInvestigationReceipt:
                    raise ValueError
                self._validate_receipt(
                    candidate.candidate_id, candidate.candidate_version, investigation
                )
                invocations: list[AuditorInvocationEvidence] = []
                for attempt in investigation.attempts:
                    key = (candidate.candidate_id, candidate.candidate_version, attempt.attempt)
                    expected_keys.add(key)
                    capture = self._captures.get(key)
                    if capture is None:
                        raise ValueError
                    self._validate_package_graph(capture.package, candidate, flow.graph)
                    invocations.append(self._reconcile(capture, attempt, investigation))
                if not invocations:
                    raise ValueError
                output.append(
                    AuditorCandidateEvidence(budget=self._budget, invocations=tuple(invocations))
                )
            if set(self._captures) != expected_keys:
                raise ValueError
            self._result = tuple(output)
            self._finalized = True
            self._final_flow_key = flow_key
            return self._result
        except (AttributeError, TypeError, ValueError):
            self._failed = True
            raise ProductConformanceError() from None

    def _snapshot(self, observation: ProductAuditorInvocationObservation) -> _Capture:
        if type(observation) is not ProductAuditorInvocationObservation:
            raise ValueError
        request = ModelRequest.model_validate_json(observation.request.model_dump_json())
        package = copy.deepcopy(observation.package)
        usage = ModelUsage.model_validate_json(
            observation.usage_before_collection.model_dump_json()
        )
        if (
            type(package) is not EvidencePackage
            or type(observation.model_call_status_before_collection) is not ModelCallStatus
            or type(observation.schema_valid_result_before_collection) is not bool
            or request.role is not ModelRole.AUDITOR
            or request.mode is not ModelPurpose.CANDIDATE_INVESTIGATION
            or request.run_id != self._discovery_request.run_id
            or request.execution_identity != self._discovery_request.execution_identity
            or request.tenant_id != self._discovery_request.tenant_id
            or request.head_sha != self._discovery_request.head_sha
            or package.tenant_id != request.tenant_id
            or package.head_sha != request.head_sha
            or package.model_evidence != request.evidence
            or package.selection_sha256 != auditor_selection_sha256(package, self._limits)
            or package.total_context_bytes > self._limits.max_context_bytes
            or package.total_input_tokens > self._limits.max_input_tokens
            or len(package.selected) > self._limits.max_evidence_items
            or package.total_context_bytes > request.budget.max_context_bytes
            or package.total_input_tokens > request.budget.max_input_tokens
        ):
            raise ValueError
        if observation.model_call_status_before_collection is ModelCallStatus.SUCCEEDED and (
            usage.input_tokens > request.budget.max_input_tokens
            or usage.output_tokens > request.budget.max_output_tokens
            or usage.repository_calls > request.budget.max_repository_calls
            or usage.elapsed_ms > request.budget.timeout_ms
        ):
            raise ValueError
        return _Capture(
            request=request,
            package=package,
            usage=usage,
            status=observation.model_call_status_before_collection,
            schema_valid=observation.schema_valid_result_before_collection,
        )

    def _validate_receipt(
        self,
        candidate_id: str,
        candidate_version: int,
        receipt: AuditorInvestigationReceipt,
    ) -> None:
        if (
            receipt.candidate_id != candidate_id
            or receipt.candidate_version != candidate_version
            or receipt.tenant_id != self._discovery_request.tenant_id
            or receipt.head_sha != self._discovery_request.head_sha
            or (
                receipt.attempts
                and receipt.initial_selection_sha256 != receipt.attempts[0].selection_sha256
            )
            or len(receipt.attempts) > self._budget.max_attempts
            or receipt.context_rounds > self._budget.max_context_rounds
            or receipt.no_progress_count > self._budget.max_no_progress
        ):
            raise ValueError
        exceeded = (
            receipt.tokens_used >= self._budget.max_tokens
            or receipt.tool_calls >= self._budget.max_tool_calls
            or receipt.elapsed_ms >= self._budget.max_elapsed_ms
        )
        if exceeded and receipt.final_model_call_status is not ModelCallStatus.BUDGET_EXHAUSTED:
            raise ValueError

    @staticmethod
    def _validate_package_graph(
        package: EvidencePackage,
        candidate: DiscoveryCandidate,
        graph: EvidenceGraph,
    ) -> None:
        if (
            package.graph_id != graph.graph_id
            or package.graph_sha256 != graph.graph_sha256
            or package.candidate_id != candidate.candidate_id
            or package.candidate_version != candidate.candidate_version
            or package.tenant_id != graph.tenant_id
            or package.head_sha != graph.head_sha
        ):
            raise ValueError
        expected_ids = set(candidate.evidence_ids)
        selected_ids = {item.evidence_id for item in package.selected}
        if selected_ids | set(package.omitted_evidence_ids) != expected_ids:
            raise ValueError
        evidence_by_id = {item.evidence_id: item for item in graph.evidence}
        for selected in package.selected:
            evidence = evidence_by_id.get(selected.evidence_id)
            if evidence is None or evidence.artifact_ref is None:
                raise ValueError
            artifact = evidence.artifact_ref
            if (
                selected.content_id != artifact.content_id
                or selected.context_bytes != artifact.size_bytes
                or selected.estimated_tokens != max(1, (artifact.size_bytes + 3) // 4)
                or selected.data_class is not evidence.data_class
                or selected.evidence_sha256 != evidence.evidence_sha256
                or selected.producer_id != evidence.producer.producer_id
                or selected.producer_version != evidence.producer.producer_version
                or selected.producer_sha256 != evidence.producer.producer_sha256
            ):
                raise ValueError

    def _reconcile(
        self,
        capture: _Capture,
        attempt: AuditorAttemptReceipt,
        receipt: AuditorInvestigationReceipt,
    ) -> AuditorInvocationEvidence:
        request, package, usage = capture.request, capture.package, capture.usage
        if (
            request.attempt != attempt.attempt
            or package.selection_sha256 != attempt.selection_sha256
            or usage.input_tokens + usage.output_tokens != attempt.tokens_used
            or usage.repository_calls != attempt.tool_calls
            or attempt.elapsed_ms < usage.elapsed_ms
            or not set(attempt.cited_evidence_ids).issubset(
                item.evidence_id for item in package.model_evidence
            )
            or (
                capture.status is not ModelCallStatus.SUCCEEDED
                and attempt.model_call_status is ModelCallStatus.SUCCEEDED
            )
            or (
                capture.status is ModelCallStatus.SUCCEEDED
                and attempt.model_call_status
                not in {
                    ModelCallStatus.SUCCEEDED,
                    ModelCallStatus.GUARDRAIL_BLOCKED,
                    ModelCallStatus.BUDGET_EXHAUSTED,
                }
            )
            or (
                attempt.model_call_status is ModelCallStatus.SUCCEEDED
                and (
                    not capture.schema_valid
                    or not attempt.schema_valid_result
                    or attempt.elapsed_ms >= request.budget.timeout_ms
                )
            )
        ):
            raise ValueError
        if receipt.final_model_call_status is ModelCallStatus.SUCCEEDED and (
            attempt.model_call_status is not ModelCallStatus.SUCCEEDED
        ):
            raise ValueError
        return AuditorInvocationEvidence(
            request=request,
            package=package,
            selection_limits=self._limits,
            usage=ModelUsage(
                schema_version=CONTRACT_SCHEMA_VERSION,
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                repository_calls=usage.repository_calls,
                elapsed_ms=attempt.elapsed_ms,
            ),
        )

    @staticmethod
    def _capture_metadata_bytes(capture: _Capture) -> int:
        payload = {
            "package": {
                "candidate_id": capture.package.candidate_id,
                "candidate_version": capture.package.candidate_version,
                "graph_id": capture.package.graph_id,
                "graph_sha256": capture.package.graph_sha256,
                "head_sha": capture.package.head_sha,
                "omitted_evidence_ids": list(capture.package.omitted_evidence_ids),
                "selected": [
                    {
                        "content_id": item.content_id,
                        "context_bytes": item.context_bytes,
                        "data_class": item.data_class.value,
                        "estimated_tokens": item.estimated_tokens,
                        "evidence_id": item.evidence_id,
                        "evidence_sha256": item.evidence_sha256,
                        "producer_id": item.producer_id,
                        "producer_sha256": item.producer_sha256,
                        "producer_version": item.producer_version,
                    }
                    for item in capture.package.selected
                ],
                "selection_sha256": capture.package.selection_sha256,
                "tenant_id": capture.package.tenant_id,
                "total_context_bytes": capture.package.total_context_bytes,
                "total_input_tokens": capture.package.total_input_tokens,
                "truncated": capture.package.truncated,
            },
            "request": capture.request.model_dump(mode="json"),
            "schema_valid": capture.schema_valid,
            "status": capture.status.value,
            "usage": capture.usage.model_dump(mode="json"),
        }
        return len(
            json.dumps(
                payload, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
            ).encode("ascii")
        )

    @staticmethod
    def _flow_key(flow: ProductCandidateFlow) -> str:
        investigations: list[dict[str, object]] = []
        for item in flow.investigations:
            if type(item) is ProductCandidatePreparationFailure:
                investigations.append(
                    {
                        "candidate_id": item.candidate_id,
                        "candidate_version": item.candidate_version,
                        "kind": "preparation_failure",
                    }
                )
                continue
            if type(item) is not AuditorInvestigationReceipt:
                raise ValueError
            investigations.append(
                {
                    "attempts": [
                        {
                            "attempt": attempt.attempt,
                            "cited_evidence_ids": list(attempt.cited_evidence_ids),
                            "elapsed_ms": attempt.elapsed_ms,
                            "model_call_status": attempt.model_call_status.value,
                            "schema_valid_result": attempt.schema_valid_result,
                            "selection_sha256": attempt.selection_sha256,
                            "tokens_used": attempt.tokens_used,
                            "tool_calls": attempt.tool_calls,
                        }
                        for attempt in item.attempts
                    ],
                    "candidate_id": item.candidate_id,
                    "candidate_version": item.candidate_version,
                    "context_rounds": item.context_rounds,
                    "elapsed_ms": item.elapsed_ms,
                    "final_model_call_status": item.final_model_call_status.value,
                    "final_selection_sha256": item.final_selection_sha256,
                    "finding_verdict": item.finding_verdict.value,
                    "head_sha": item.head_sha,
                    "initial_selection_sha256": item.initial_selection_sha256,
                    "disposition": item.disposition.value,
                    "no_progress_count": item.no_progress_count,
                    "stop_reason": item.stop_reason.value,
                    "tenant_id": item.tenant_id,
                    "tokens_used": item.tokens_used,
                    "tool_calls": item.tool_calls,
                }
            )
        payload = {
            "candidates": [
                {
                    "candidate_id": candidate.candidate_id,
                    "candidate_version": candidate.candidate_version,
                }
                for candidate in flow.graph.candidates
            ],
            "discovery": {
                "head_sha": flow.discovery.receipt.head_sha,
                "model_call_status": flow.discovery.receipt.model_call_status.value,
                "tenant_id": flow.discovery.receipt.tenant_id,
            },
            "graph": {
                "graph_id": flow.graph.graph_id,
                "graph_sha256": flow.graph.graph_sha256,
                "head_sha": flow.graph.head_sha,
                "tenant_id": flow.graph.tenant_id,
            },
            "investigations": investigations,
        }
        encoded = json.dumps(
            payload, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()


__all__ = ["ProductAuditorEvidenceRecorder", "ProductConformanceError"]
