"""P3.10 model-native discovery boundary tests."""

from __future__ import annotations

import pytest
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ApiDialect,
    ComponentPin,
    DataClass,
    ModelCallBudget,
    ModelCallResult,
    ModelCallStatus,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    ModelSchemaResult,
    ModelSchemaStatus,
    ModelUsage,
    NativeOutcomeMetadata,
    OpaqueContentProvenance,
    PreflightEligibility,
    ProducerRef,
    RepositoryRevision,
    RepositoryTool,
    RunExecutionIdentity,
)
from securecode_ai.core.model_discovery import (
    ModelNativeCandidateDraft,
    ModelNativeDiscoveryError,
    ModelNativeDiscoveryOutcome,
    ModelNativeDiscoveryPayload,
    ModelNativeDiscoveryPlan,
    RepositoryToolSession,
    run_model_native_discovery,
)
from securecode_ai.core.tool_policy import (
    TOOL_ARGUMENT_SCHEMA_VERSION,
    ReadRangeArguments,
    RepositoryToolBudget,
    RepositoryToolOutput,
    RepositoryToolRequest,
    RepositoryToolScope,
    RepositoryToolWindow,
)

HEAD = "1" * 40
SHA_A = "a" * 64
SHA_B = "b" * 64


def _pin(name: str, sha: str = SHA_A) -> ComponentPin:
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=name,
        component_version="1.0.0",
        content_sha256=sha,
    )


def _request() -> ModelRequest:
    provider_profile = _pin("provider-profile", SHA_B)
    identity = RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-a",
            scm_provider="github",
            repository_id="repo-a",
            head_sha=HEAD,
        ),
        stage_catalogue=_pin("stages"),
        workflow=_pin("workflow"),
        policy=_pin("policy"),
        configuration=_pin("config"),
        provider_profile=provider_profile,
        capability_profile=_pin("capabilities"),
        egress_profile=_pin("egress"),
    )
    return ModelRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        request_id="request-1",
        run_id="run-1",
        tenant_id="tenant-a",
        idempotency_key="idem-1",
        attempt=1,
        execution_identity=identity,
        head_sha=HEAD,
        role=ModelRole.DISCOVERY,
        mode=ModelPurpose.MODEL_NATIVE_DISCOVERY,
        provider_profile=provider_profile,
        api_dialect=ApiDialect.FAKE,
        model_id="fixture-model",
        prompt=_pin("prompt"),
        output_schema=_pin("discovery-output"),
        tool_policy=_pin("repository-tools"),
        repository_scope=_pin("repository-scope"),
        repository_view_policy=_pin("repository-view-policy"),
        budget=ModelCallBudget(
            schema_version=CONTRACT_SCHEMA_VERSION,
            max_input_tokens=4096,
            max_output_tokens=1024,
            max_repository_calls=4,
            max_context_bytes=65536,
            timeout_ms=30000,
        ),
    )


def _plan(
    *, eligibility: PreflightEligibility = PreflightEligibility.ELIGIBLE
) -> ModelNativeDiscoveryPlan:
    request = _request()
    return ModelNativeDiscoveryPlan(
        receipt_id="discovery-receipt-1",
        request=request,
        preflight_eligibility=eligibility,
        scope=RepositoryToolScope(
            tenant_id="tenant-a",
            repository_id="repo-a",
            head_sha=HEAD,
            path_prefixes=("packages",),
            evidence_ids=("evidence-1",),
        ),
        tool_budget=RepositoryToolBudget(max_calls=2, max_bytes=100, max_tokens=10),
        producer=ProducerRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            producer_id="model-native-discovery",
            producer_version="1.0.0",
            producer_sha256=SHA_A,
        ),
    )


def _result(
    request: ModelRequest, *, calls: int, status: ModelCallStatus = ModelCallStatus.SUCCEEDED
) -> ModelCallResult:
    succeeded = status is ModelCallStatus.SUCCEEDED
    return ModelCallResult(
        schema_version=CONTRACT_SCHEMA_VERSION,
        request_id=request.request_id,
        run_id=request.run_id,
        tenant_id=request.tenant_id,
        idempotency_key=request.idempotency_key,
        attempt=request.attempt,
        provider_profile=request.provider_profile,
        model_call_status=status,
        native=NativeOutcomeMetadata(
            schema_version=CONTRACT_SCHEMA_VERSION,
            request_code="NATIVE_REQUEST_PRESENT",
            finish_code="COMPLETE" if succeeded else "PROVIDER_FAILURE",
        ),
        schema_result=ModelSchemaResult(
            schema_version=CONTRACT_SCHEMA_VERSION,
            status=ModelSchemaStatus.VALID if succeeded else ModelSchemaStatus.NOT_VALIDATED,
            error_code=None if succeeded else "MODEL_NON_SUCCESS",
            validator=request.output_schema,
        ),
        usage=ModelUsage(
            schema_version=CONTRACT_SCHEMA_VERSION,
            input_tokens=10,
            output_tokens=5,
            repository_calls=calls,
            elapsed_ms=20,
        ),
        retryable=False,
        content_provenance=(
            OpaqueContentProvenance(
                schema_version=CONTRACT_SCHEMA_VERSION,
                content_id="kid:discovery-payload-1",
                tenant_id=request.tenant_id,
                data_class=DataClass.CONFIDENTIAL_SECURITY,
                validator=request.output_schema,
            )
            if succeeded
            else None
        ),
        safe_reason_code=None if succeeded else "MODEL_NON_SUCCESS",
    )


class RecordingView:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.output = RepositoryToolOutput.build("repository data", token_count=1, item_count=1)

    def list_paths(
        self, arguments: object, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        del arguments, window
        self.calls.append("list")
        return self.output

    def lookup_symbol(
        self, arguments: object, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        del arguments, window
        self.calls.append("symbol")
        return self.output

    def read_range(
        self, arguments: ReadRangeArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        del arguments, window
        self.calls.append("range")
        return self.output

    def read_evidence(
        self, arguments: object, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        del arguments, window
        self.calls.append("evidence")
        return self.output


class CandidateBackend:
    def __init__(
        self, *, calls: int = 1, candidates: tuple[ModelNativeCandidateDraft, ...] | None = None
    ) -> None:
        self.calls = calls
        self.candidates = candidates
        self.invocations = 0

    def discover(
        self, *, request: ModelRequest, tools: RepositoryToolSession
    ) -> ModelNativeDiscoveryPayload:
        self.invocations += 1
        for _ in range(self.calls):
            tools.dispatch(_range_request())
        candidates = self.candidates
        if candidates is None:
            candidates = (
                ModelNativeCandidateDraft(
                    candidate_id="native-candidate-1",
                    candidate_version=1,
                    source_id="native-source-1",
                    root_cause_fingerprint=SHA_B,
                ),
            )
        return ModelNativeDiscoveryPayload(
            model_result=_result(request, calls=tools.calls_used),
            candidates=candidates,
        )


def _range_request() -> RepositoryToolRequest:
    return RepositoryToolRequest(
        tool=RepositoryTool.READ_RANGE,
        arguments=ReadRangeArguments(
            TOOL_ARGUMENT_SCHEMA_VERSION,
            HEAD,
            "packages/core/example.py",
            1,
            2,
        ),
    )


def test_zero_scanner_signal_still_runs_native_discovery_and_keeps_lineage() -> None:
    view = RecordingView()
    backend = CandidateBackend()

    outcome = run_model_native_discovery(_plan(), repository=view, backend=backend)

    assert isinstance(outcome, ModelNativeDiscoveryOutcome)
    assert backend.invocations == 1
    assert view.calls == ["range"]
    assert outcome.receipt.model_call_status is ModelCallStatus.SUCCEEDED
    assert outcome.required_terminal_outcome is None
    assert outcome.candidates[0].candidate_origin.value == "model_native"
    assert outcome.candidates[0].lineage[0].lane.value == "model_native"
    assert outcome.receipt.repository_view_call_hashes


def test_completed_zero_is_a_success_receipt_not_a_silent_skip() -> None:
    backend = CandidateBackend(calls=0, candidates=())

    outcome = run_model_native_discovery(_plan(), repository=RecordingView(), backend=backend)

    assert outcome.receipt.is_completed_zero
    assert outcome.receipt.candidate_ids == ()
    assert outcome.required_terminal_outcome is None
    assert backend.invocations == 1


def test_ineligible_profile_stops_before_repository_context_or_backend_call() -> None:
    view = RecordingView()
    backend = CandidateBackend()

    outcome = run_model_native_discovery(
        _plan(eligibility=PreflightEligibility.INELIGIBLE), repository=view, backend=backend
    )

    assert backend.invocations == 0
    assert view.calls == []
    assert outcome.tool_receipts == ()
    assert outcome.receipt.model_call_status is ModelCallStatus.GUARDRAIL_BLOCKED
    assert outcome.required_terminal_outcome is not None
    assert outcome.required_terminal_outcome.value == "INDETERMINATE"


def test_tool_budget_exhaustion_is_indeterminate_and_releases_no_candidate() -> None:
    view = RecordingView()
    backend = CandidateBackend(calls=3)

    outcome = run_model_native_discovery(_plan(), repository=view, backend=backend)

    assert backend.invocations == 1
    assert len(view.calls) == 2
    assert outcome.candidates == ()
    assert outcome.receipt.model_call_status is ModelCallStatus.BUDGET_EXHAUSTED
    assert outcome.required_terminal_outcome is not None
    assert outcome.required_terminal_outcome.value == "INDETERMINATE"


def test_out_of_scope_initial_tool_request_stops_before_provider() -> None:
    backend = CandidateBackend()
    request = RepositoryToolRequest(
        tool=RepositoryTool.READ_RANGE,
        arguments=ReadRangeArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "tests/nope.py", 1, 2),
    )

    outcome = run_model_native_discovery(
        _plan(), repository=RecordingView(), backend=backend, initial_tool_requests=(request,)
    )

    assert backend.invocations == 0
    assert outcome.receipt.model_call_status is ModelCallStatus.GUARDRAIL_BLOCKED
    assert outcome.tool_receipts[0].outcome.value == "NON_SUCCESS"


def test_provider_fault_and_usage_mismatch_are_typed_non_successes() -> None:
    class BrokenBackend:
        def discover(
            self, *, request: ModelRequest, tools: RepositoryToolSession
        ) -> ModelNativeDiscoveryPayload:
            del request, tools
            raise RuntimeError("provider response must not escape")

    fault = run_model_native_discovery(_plan(), repository=RecordingView(), backend=BrokenBackend())
    assert fault.receipt.model_call_status is ModelCallStatus.PROVIDER_ERROR
    assert fault.required_terminal_outcome is not None
    assert fault.required_terminal_outcome.value == "INDETERMINATE"

    class MismatchedBackend:
        def discover(
            self, *, request: ModelRequest, tools: RepositoryToolSession
        ) -> ModelNativeDiscoveryPayload:
            tools.dispatch(_range_request())
            return ModelNativeDiscoveryPayload(
                model_result=_result(request, calls=0), candidates=()
            )

    mismatch = run_model_native_discovery(
        _plan(), repository=RecordingView(), backend=MismatchedBackend()
    )
    assert mismatch.receipt.model_call_status is ModelCallStatus.INVALID_SCHEMA
    assert mismatch.candidates == ()


@pytest.mark.parametrize(
    ("input_tokens", "output_tokens"),
    [(4097, 0), (0, 1025)],
)
def test_per_dimension_model_usage_budget_overrun_is_not_completed_zero(
    input_tokens: int, output_tokens: int
) -> None:
    class OverBudgetBackend:
        def discover(
            self, *, request: ModelRequest, tools: RepositoryToolSession
        ) -> ModelNativeDiscoveryPayload:
            result = _result(request, calls=tools.calls_used)
            result = result.model_copy(
                update={
                    "usage": result.usage.model_copy(
                        update={"input_tokens": input_tokens, "output_tokens": output_tokens}
                    )
                }
            )
            return ModelNativeDiscoveryPayload(model_result=result, candidates=())

    outcome = run_model_native_discovery(
        _plan(), repository=RecordingView(), backend=OverBudgetBackend()
    )

    assert outcome.receipt.model_call_status is ModelCallStatus.INVALID_SCHEMA
    assert not outcome.receipt.is_completed_zero


def test_plan_rejects_non_discovery_or_scope_identity_drift() -> None:
    plan = _plan()
    with pytest.raises(ModelNativeDiscoveryError):
        ModelNativeDiscoveryPlan(
            receipt_id=plan.receipt_id,
            request=plan.request.model_copy(update={"head_sha": "2" * 40}),
            preflight_eligibility=plan.preflight_eligibility,
            scope=plan.scope,
            tool_budget=plan.tool_budget,
            producer=plan.producer,
        )


def test_plan_rejects_tool_token_budget_above_model_input_budget() -> None:
    plan = _plan()
    with pytest.raises(ModelNativeDiscoveryError):
        ModelNativeDiscoveryPlan(
            receipt_id=plan.receipt_id,
            request=plan.request,
            preflight_eligibility=plan.preflight_eligibility,
            scope=plan.scope,
            tool_budget=RepositoryToolBudget(
                max_calls=plan.tool_budget.max_calls,
                max_bytes=plan.tool_budget.max_bytes,
                max_tokens=plan.request.budget.max_input_tokens + 1,
            ),
            producer=plan.producer,
        )
