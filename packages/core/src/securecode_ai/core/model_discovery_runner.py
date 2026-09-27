"""Mandatory bounded model-native discovery execution and receipt construction."""

from __future__ import annotations

from dataclasses import dataclass

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    AuditRunOutcome,
    CandidateOrigin,
    DiscoveryCandidate,
    DiscoveryLane,
    LineageRef,
    ModelBudgetUsage,
    ModelCallResult,
    ModelCallStatus,
    ModelDiscoveryReceipt,
    ModelRequest,
    PreflightEligibility,
)

from .model_discovery_contracts import (
    _MAX_USAGE,
    ModelNativeCandidateDraft,
    ModelNativeDiscoveryBackend,
    ModelNativeDiscoveryError,
    ModelNativeDiscoveryErrorCode,
    ModelNativeDiscoveryOutcome,
    ModelNativeDiscoveryPayload,
    ModelNativeDiscoveryPlan,
    RepositoryToolSession,
    _lineage_id,
    _payload_sha256,
    _receipt_sha256,
)
from .tool_policy import (
    RepositoryToolGuard,
    RepositoryToolReceipt,
    RepositoryToolRequest,
    RepositoryView,
)


def run_model_native_discovery(
    plan: ModelNativeDiscoveryPlan,
    *,
    repository: RepositoryView,
    backend: ModelNativeDiscoveryBackend,
    initial_tool_requests: tuple[RepositoryToolRequest, ...] = (),
) -> ModelNativeDiscoveryOutcome:
    """Run mandatory model-native discovery without a deterministic fallback.

    An ineligible provider/profile short-circuits before *any* repository
    context or backend/provider operation.  Repository-tool denial, malformed
    backend output and every provider non-success become a typed receipt with
    ``INDETERMINATE``; none are allowed to turn into completed-zero.
    """

    if (
        type(plan) is not ModelNativeDiscoveryPlan
        or not _is_repository_view(repository)
        or not _is_discovery_backend(backend)
        or type(initial_tool_requests) is not tuple
        or any(type(item) is not RepositoryToolRequest for item in initial_tool_requests)
    ):
        raise ModelNativeDiscoveryError(ModelNativeDiscoveryErrorCode.INVALID_REQUEST)
    if plan.preflight_eligibility is not PreflightEligibility.ELIGIBLE:
        return _failure_outcome(plan, ModelCallStatus.GUARDRAIL_BLOCKED, ())

    session = RepositoryToolSession(
        guard=RepositoryToolGuard(scope=plan.scope, budget=plan.tool_budget),
        backend=repository,
    )
    for tool_request in initial_tool_requests:
        try:
            session.dispatch(tool_request)
        except Exception:
            # Initial host-guided reads use the same untrusted repository port
            # as provider-triggered reads.  A repository implementation may
            # fail before it can return a typed GuardedToolResult; such a
            # failure must remain an indeterminate discovery receipt rather
            # than escaping as an adapter exception.
            return _failure_outcome(plan, ModelCallStatus.GUARDRAIL_BLOCKED, session.receipts)
        if session.has_non_success:
            return _failure_outcome(plan, session.failure_status, session.receipts)
    try:
        payload = backend.discover(request=plan.request, tools=session)
    except Exception:
        return _failure_outcome(plan, ModelCallStatus.PROVIDER_ERROR, session.receipts)
    if type(payload) is not ModelNativeDiscoveryPayload or session.has_non_success:
        status = (
            session.failure_status if session.has_non_success else ModelCallStatus.PROVIDER_ERROR
        )
        return _failure_outcome(plan, status, session.receipts)
    return _outcome_from_payload(plan, payload, session)


def _outcome_from_payload(
    plan: ModelNativeDiscoveryPlan,
    payload: ModelNativeDiscoveryPayload,
    session: RepositoryToolSession,
) -> ModelNativeDiscoveryOutcome:
    result = payload.model_result
    if not _result_matches_request(result, plan.request) or not _usage_matches_tools(
        result, plan, session
    ):
        return _failure_outcome(plan, ModelCallStatus.INVALID_SCHEMA, session.receipts)
    if result.model_call_status is not ModelCallStatus.SUCCEEDED:
        return _failure_outcome(plan, result.model_call_status, session.receipts, result=result)
    if any(
        not set(item.evidence_ids).issubset(plan.scope.evidence_ids) for item in payload.candidates
    ):
        return _failure_outcome(
            plan, ModelCallStatus.INVALID_SCHEMA, session.receipts, result=result
        )
    try:
        candidates = tuple(_candidate_from_draft(plan, item) for item in payload.candidates)
    except (TypeError, ValueError, ModelNativeDiscoveryError):
        return _failure_outcome(
            plan, ModelCallStatus.INVALID_SCHEMA, session.receipts, result=result
        )
    output_sha256 = _payload_sha256(payload.candidates, session.call_hashes)
    receipt = _receipt(
        plan,
        status=ModelCallStatus.SUCCEEDED,
        schema_valid_result=True,
        output_sha256=output_sha256,
        candidate_ids=tuple(item.candidate_id for item in candidates),
        session=session,
        result=result,
    )
    return ModelNativeDiscoveryOutcome(
        receipt=receipt,
        candidates=candidates,
        tool_receipts=session.receipts,
        required_terminal_outcome=None,
    )


def _candidate_from_draft(
    plan: ModelNativeDiscoveryPlan, draft: ModelNativeCandidateDraft
) -> DiscoveryCandidate:
    lineage = LineageRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        lineage_id=_lineage_id(plan, draft),
        lane=DiscoveryLane.MODEL_NATIVE,
        producer=plan.producer,
        root_cause_fingerprint=draft.root_cause_fingerprint,
        input_candidate_ids=(draft.source_id,),
        evidence_ids=draft.evidence_ids,
    )
    return DiscoveryCandidate(
        schema_version=CONTRACT_SCHEMA_VERSION,
        candidate_id=draft.candidate_id,
        tenant_id=plan.request.tenant_id,
        candidate_version=draft.candidate_version,
        head_sha=plan.request.head_sha,
        root_cause_fingerprint=draft.root_cause_fingerprint,
        candidate_origin=CandidateOrigin.MODEL_NATIVE,
        lineage=(lineage,),
        evidence_ids=draft.evidence_ids,
    )


def _failure_outcome(
    plan: ModelNativeDiscoveryPlan,
    status: ModelCallStatus,
    receipts: tuple[RepositoryToolReceipt, ...],
    *,
    result: ModelCallResult | None = None,
) -> ModelNativeDiscoveryOutcome:
    session = _ReceiptSession(receipts)
    receipt = _receipt(
        plan,
        status=status,
        schema_valid_result=False,
        output_sha256=None,
        candidate_ids=(),
        session=session,
        result=result,
    )
    return ModelNativeDiscoveryOutcome(
        receipt=receipt,
        candidates=(),
        tool_receipts=receipts,
        required_terminal_outcome=AuditRunOutcome.INDETERMINATE,
    )


@dataclass(frozen=True, slots=True)
class _ReceiptSession:
    receipts: tuple[RepositoryToolReceipt, ...]

    @property
    def call_hashes(self) -> tuple[str, ...]:
        return tuple(_receipt_sha256(item) for item in self.receipts)

    @property
    def calls_used(self) -> int:
        return sum(1 for item in self.receipts if item.decision.value == "ALLOW")


def _receipt(
    plan: ModelNativeDiscoveryPlan,
    *,
    status: ModelCallStatus,
    schema_valid_result: bool,
    output_sha256: str | None,
    candidate_ids: tuple[str, ...],
    session: RepositoryToolSession | _ReceiptSession,
    result: ModelCallResult | None,
) -> ModelDiscoveryReceipt:
    tokens_used, elapsed_ms = _safe_usage(result, plan)
    return ModelDiscoveryReceipt(
        schema_version=CONTRACT_SCHEMA_VERSION,
        receipt_id=plan.receipt_id,
        tenant_id=plan.request.tenant_id,
        head_sha=plan.request.head_sha,
        scope_sha256=plan.scope_sha256,
        model_profile=plan.request.provider_profile,
        prompt=plan.request.prompt,
        repository_view_call_hashes=session.call_hashes,
        budget_usage=ModelBudgetUsage(
            schema_version=CONTRACT_SCHEMA_VERSION,
            token_limit=min(
                _MAX_USAGE,
                plan.request.budget.max_input_tokens + plan.request.budget.max_output_tokens,
            ),
            tokens_used=tokens_used,
            repository_call_limit=plan.request.budget.max_repository_calls,
            repository_calls_used=session.calls_used,
            time_limit_ms=plan.request.budget.timeout_ms,
            elapsed_ms=elapsed_ms,
        ),
        model_call_status=status,
        schema_valid_result=schema_valid_result,
        input_sha256=plan.input_sha256,
        output_sha256=output_sha256,
        candidate_ids=candidate_ids,
    )


def _safe_usage(result: ModelCallResult | None, plan: ModelNativeDiscoveryPlan) -> tuple[int, int]:
    """Retain provider usage only when it fits the host-owned request budget.

    A provider result is contract-valid before it is request-budget-valid.  In
    particular, a provider can report counters larger than this request's
    limits.  Passing those counters straight into ``ModelBudgetUsage`` would
    raise while constructing the fail-closed receipt, turning a typed
    non-success into an uncaught exception.  Untrusted out-of-budget counters
    are therefore omitted from the receipt rather than treated as evidence.
    """

    if result is None:
        return 0, 0
    usage = result.usage
    token_limit = min(
        _MAX_USAGE,
        plan.request.budget.max_input_tokens + plan.request.budget.max_output_tokens,
    )
    tokens_used = usage.input_tokens + usage.output_tokens
    if (
        usage.input_tokens > plan.request.budget.max_input_tokens
        or usage.output_tokens > plan.request.budget.max_output_tokens
        or tokens_used > token_limit
        or usage.elapsed_ms > plan.request.budget.timeout_ms
    ):
        return 0, 0
    return tokens_used, usage.elapsed_ms


def _result_matches_request(result: ModelCallResult, request: ModelRequest) -> bool:
    return (
        result.request_id == request.request_id
        and result.run_id == request.run_id
        and result.tenant_id == request.tenant_id
        and result.idempotency_key == request.idempotency_key
        and result.attempt == request.attempt
        and result.provider_profile == request.provider_profile
    )


def _usage_matches_tools(
    result: ModelCallResult, plan: ModelNativeDiscoveryPlan, session: RepositoryToolSession
) -> bool:
    usage = result.usage
    return (
        usage.repository_calls == session.calls_used
        and usage.input_tokens <= plan.request.budget.max_input_tokens
        and usage.output_tokens <= plan.request.budget.max_output_tokens
        and usage.input_tokens + usage.output_tokens
        <= min(
            _MAX_USAGE,
            plan.request.budget.max_input_tokens + plan.request.budget.max_output_tokens,
        )
        and usage.elapsed_ms <= plan.request.budget.timeout_ms
    )


def _is_repository_view(value: object) -> bool:
    return all(
        callable(getattr(value, name, None))
        for name in ("list_paths", "lookup_symbol", "read_range", "read_evidence")
    )


def _is_discovery_backend(value: object) -> bool:
    return callable(getattr(value, "discover", None))
