"""Receipt-bound host admission, not runtime attestation or repository authority.

Only trusted host composition may construct ``TrustedLocalProviderAdmission``
and supply independently reviewed pins. Receipt imports cannot construct that
authority or change its approved hashes. No keys or network effects exist here.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from securecode_ai.contracts import (
    CandidateOrigin,
    FindingVerdict,
    ModelCallStatus,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    ProviderProfile,
    RepositoryTool,
)
from securecode_ai.core.investigation import AuditorInvestigationReceipt
from securecode_ai.core.normalization import normalize_signals
from securecode_ai.core.tool_policy import ToolOutcome

from .local_model_qualification_validation import _copy_tool_receipt, _tool_receipt_sha256
from .local_provider_admission_models import (
    _ID,
    _SHA,
    AdmissionBindings,
    AuditorCandidateEvidence,
    CapabilityCase,
    CapabilityEvidence,
    CoreCase,
    CoreConformanceEvidence,
    EvidenceOrigin,
    LocalProviderEvidenceBundle,
    NativeToolEvidence,
    _reject,
    auditor_selection_sha256,
    evidence_receipt_sha256,
)
from .native_repository_tools import parse_native_tool_calls


def _validate_request(
    request: ModelRequest, profile: ProviderProfile, binding: AdmissionBindings
) -> None:
    if (
        request.provider_profile.content_sha256 != profile.canonical_content_hash()
        or request.provider_profile.component_id != profile.profile_id
        or request.provider_profile.component_version != profile.profile_version
        or request.model_id != profile.model_id
        or request.api_dialect is not profile.api_dialect
        or request.budget.timeout_ms > profile.budgets.timeout_seconds * 1000
        or request.attempt > profile.budgets.max_attempts
        or request.budget.max_input_tokens > profile.capabilities.max_context_tokens
        or request.budget.max_output_tokens > profile.capabilities.max_output_tokens
        or request.budget.max_input_tokens + request.budget.max_output_tokens
        > profile.budgets.max_total_tokens
    ):
        _reject()
    if request.role is ModelRole.DISCOVERY:
        if request.mode is not ModelPurpose.MODEL_NATIVE_DISCOVERY:
            _reject()
        prompt, schema = binding.discovery_prompt_sha256, binding.discovery_schema_sha256
    elif request.role is ModelRole.AUDITOR:
        if request.mode is not ModelPurpose.CANDIDATE_INVESTIGATION:
            _reject()
        prompt, schema = binding.auditor_prompt_sha256, binding.auditor_schema_sha256
    else:
        _reject()
    if request.prompt.content_sha256 != prompt or request.output_schema.content_sha256 != schema:
        _reject()


def _validate_bundle(bundle: LocalProviderEvidenceBundle, profile: ProviderProfile) -> None:
    if (
        {item.case for item in bundle.capabilities} != set(CapabilityCase)
        or len(bundle.capabilities) != len(CapabilityCase)
        or {item.request.tool for item in bundle.native_tools} != set(RepositoryTool)
        or len(bundle.native_tools) != 4
        or {item.case for item in bundle.core_cases} != set(CoreCase)
        or len(bundle.core_cases) != len(CoreCase)
    ):
        _reject()
    refs: set[str] = set()
    all_evidence: tuple[CapabilityEvidence | NativeToolEvidence | CoreConformanceEvidence, ...] = (
        *bundle.capabilities,
        *bundle.native_tools,
        *bundle.core_cases,
    )
    for item in all_evidence:
        expected_origin = (
            EvidenceOrigin.FAULT_INJECTED
            if isinstance(item, CoreConformanceEvidence)
            and item.case in {CoreCase.PROVIDER_FAULT, CoreCase.TOOL_FAULT}
            else EvidenceOrigin.LIVE
        )
        if (
            item.origin is not expected_origin
            or _SHA.fullmatch(item.receipt_sha256) is None
            or item.receipt_sha256 != evidence_receipt_sha256(item)
            or item.receipt_sha256 in refs
        ):
            _reject()
        refs.add(item.receipt_sha256)
    for capability in bundle.capabilities:
        request, result = capability.request, capability.result
        _validate_request(request, profile, bundle.bindings)
        if (
            result.request_id != request.request_id
            or result.run_id != request.run_id
            or result.tenant_id != request.tenant_id
            or result.idempotency_key != request.idempotency_key
            or result.attempt != request.attempt
            or result.provider_profile != request.provider_profile
            or result.schema_result.validator != request.output_schema
            or result.usage.elapsed_ms > request.budget.timeout_ms
            or result.usage.input_tokens > request.budget.max_input_tokens
            or result.usage.output_tokens > request.budget.max_output_tokens
            or result.usage.repository_calls > request.budget.max_repository_calls
        ):
            _reject()
        if capability.case in {
            CapabilityCase.STRUCTURED_DISCOVERY,
            CapabilityCase.STRUCTURED_AUDITOR,
        }:
            expected = (
                ModelRole.DISCOVERY
                if capability.case is CapabilityCase.STRUCTURED_DISCOVERY
                else ModelRole.AUDITOR
            )
            if (
                request.role is not expected
                or result.status is not ModelCallStatus.SUCCEEDED
                or result.usage.input_tokens < 1
                or result.usage.output_tokens < 1
            ):
                _reject()
        elif capability.case is CapabilityCase.NATIVE_REFUSAL:
            if (
                result.status is not ModelCallStatus.REFUSED
                or result.native.refusal_code != "REFUSED"
            ):
                _reject()
        elif result.status not in {
            ModelCallStatus.INCOMPLETE,
            ModelCallStatus.TRUNCATED,
            ModelCallStatus.CONTEXT_EXHAUSTED,
        } or result.native.finish_code not in {
            "INCOMPLETE",
            "MAX_OUTPUT_TOKENS",
            "CONTEXT_EXHAUSTED",
        }:
            _reject()
    for native in bundle.native_tools:
        _validate_request(native.model_request, profile, bundle.bindings)
        receipt = _copy_tool_receipt(native.receipt)
        wire = [
            {
                "id": native.call_id,
                "type": "function",
                "function": {
                    "name": native.request.tool.value,
                    "arguments": json.dumps(asdict(native.request.arguments)),
                },
            }
        ]
        parse_native_tool_calls(wire, head_sha=native.request.arguments.head_sha, max_calls=1)
        if (
            receipt.tool != native.request.tool.value
            or native.request.arguments.head_sha != native.model_request.head_sha
            or receipt.outcome is not ToolOutcome.SUCCEEDED
            or receipt.output_sha256 is None
            or native.usage.repository_calls != 0
            or native.usage.input_tokens < 1
            or native.usage.output_tokens < 1
            or native.usage.elapsed_ms < 1
            or native.usage.input_tokens > native.model_request.budget.max_input_tokens
            or native.usage.output_tokens > native.model_request.budget.max_output_tokens
            or native.usage.input_tokens + native.usage.output_tokens
            > profile.budgets.max_total_tokens
            or native.usage.elapsed_ms > native.model_request.budget.timeout_ms
            or receipt.calls_used > native.model_request.budget.max_repository_calls
            or receipt.bytes_used > native.model_request.budget.max_context_bytes
            or _SHA.fullmatch(native.sent_prompt_sha256) is None
        ):
            _reject()
    request_ids: set[str] = set()
    idempotency_keys: set[str] = set()
    for case in bundle.core_cases:
        _validate_core(case, profile, bundle.bindings, request_ids, idempotency_keys)


def _validate_core(
    case: CoreConformanceEvidence,
    profile: ProviderProfile,
    binding: AdmissionBindings,
    request_ids: set[str],
    idempotency_keys: set[str],
) -> None:
    request, discovery = case.request, case.discovery
    _validate_request(request, profile, binding)
    if (
        request.role is not ModelRole.DISCOVERY
        or request.mode is not ModelPurpose.MODEL_NATIVE_DISCOVERY
        or discovery.tenant_id != request.tenant_id
        or discovery.head_sha != request.head_sha
        or discovery.model_profile != request.provider_profile
        or discovery.prompt != request.prompt
        or discovery.scope_sha256 != request.repository_scope.content_sha256
        or discovery.budget_usage.token_limit
        != request.budget.max_input_tokens + request.budget.max_output_tokens
        or discovery.budget_usage.repository_call_limit != request.budget.max_repository_calls
        or discovery.budget_usage.time_limit_ms != request.budget.timeout_ms
        or discovery.budget_usage.elapsed_ms > request.budget.timeout_ms
        or discovery.budget_usage.tokens_used
        > request.budget.max_input_tokens + request.budget.max_output_tokens
        or discovery.budget_usage.repository_calls_used > request.budget.max_repository_calls
        or len(set(case.normalized_candidate_ids)) != len(case.normalized_candidate_ids)
        or any(
            _ID.fullmatch(value) is None
            for value in (*case.normalized_candidate_ids, *case.scanner_candidate_ids)
        )
        or tuple(item.candidate_id for item in case.native_candidates) != discovery.candidate_ids
        or tuple(item.candidate_id for item in case.scanner_candidates)
        != case.scanner_candidate_ids
        or tuple(item.candidate_id for item in case.normalized_candidates)
        != case.normalized_candidate_ids
        or len(set(discovery.candidate_ids)) != len(case.native_candidates)
        or len(set(case.scanner_candidate_ids)) != len(case.scanner_candidates)
        or any(
            item.candidate_origin is not CandidateOrigin.MODEL_NATIVE
            for item in case.native_candidates
        )
        or any(
            item.candidate_origin is not CandidateOrigin.DETERMINISTIC
            for item in case.scanner_candidates
        )
        or any(
            item.tenant_id != request.tenant_id or item.head_sha != request.head_sha
            for item in (
                *case.native_candidates,
                *case.scanner_candidates,
                *case.normalized_candidates,
            )
        )
        or normalize_signals(
            discovery_candidates=(*case.native_candidates, *case.scanner_candidates)
        )
        != case.normalized_candidates
        or tuple(item.candidate_id for item in case.auditors) != case.normalized_candidate_ids
        or len(case.auditor_invocations) != len(case.auditors)
        or any(
            item.tenant_id != request.tenant_id or item.head_sha != request.head_sha
            for item in case.auditors
        )
    ):
        _reject()
    for candidate, auditor, normalized in zip(
        case.auditor_invocations, case.auditors, case.normalized_candidates, strict=True
    ):
        if (
            auditor.candidate_id != normalized.candidate_id
            or auditor.candidate_version != normalized.candidate_version
        ):
            _reject()
        _validate_auditor(
            candidate, auditor, request, profile, binding, request_ids, idempotency_keys
        )
    for receipt in case.tool_receipts:
        if (
            _tool_receipt_sha256(_copy_tool_receipt(receipt))
            not in discovery.repository_view_call_hashes
        ):
            _reject()
    if case.case is CoreCase.PROVIDER_FAULT:
        if discovery.model_call_status is not ModelCallStatus.PROVIDER_ERROR:
            _reject()
    elif case.case is CoreCase.TOOL_FAULT:
        if discovery.model_call_status not in {
            ModelCallStatus.GUARDRAIL_BLOCKED,
            ModelCallStatus.BUDGET_EXHAUSTED,
        } or not any(item.outcome is ToolOutcome.NON_SUCCESS for item in case.tool_receipts):
            _reject()
    else:
        if discovery.model_call_status is not ModelCallStatus.SUCCEEDED or any(
            item.is_indeterminate for item in case.auditors
        ):
            _reject()
        if (
            case.case.value.endswith(("_safe", "_safe_interfile"))
            or case.case is CoreCase.NATIVE_COMPLETED_ZERO
        ):
            if not discovery.is_completed_zero or case.normalized_candidate_ids:
                _reject()
        elif not discovery.candidate_ids or not case.normalized_candidate_ids:
            _reject()
        if case.case is CoreCase.ZERO_SCANNER_NATIVE_FINDING and case.scanner_candidate_ids:
            _reject()
        if case.case is CoreCase.AUDITOR_ALL_CANDIDATES and len(case.auditors) < 2:
            _reject()
        if case.case is CoreCase.NATIVE_CYCLE and (
            len(case.native_turn_request_hashes) < 3
            or len(set(case.native_turn_request_hashes)) != len(case.native_turn_request_hashes)
            or any(_SHA.fullmatch(value) is None for value in case.native_turn_request_hashes)
        ):
            _reject()
        if (
            case.case.value.endswith(("_vulnerable", "_interfile"))
            and not case.case.value.endswith("_safe_interfile")
            and not any(item.finding_verdict is FindingVerdict.CONFIRMED for item in case.auditors)
        ):
            _reject()


def _validate_auditor(
    candidate: AuditorCandidateEvidence,
    auditor: AuditorInvestigationReceipt,
    discovery_request: ModelRequest,
    profile: ProviderProfile,
    binding: AdmissionBindings,
    request_ids: set[str],
    idempotency_keys: set[str],
) -> None:
    budget = candidate.budget
    if (
        len(candidate.invocations) != len(auditor.attempts)
        or len(auditor.attempts) > budget.max_attempts
        or budget.max_attempts > profile.budgets.max_attempts
        or budget.max_tokens > profile.budgets.max_total_tokens
        or budget.max_elapsed_ms > profile.budgets.timeout_seconds * 1000
        or auditor.tokens_used > budget.max_tokens
        or auditor.tool_calls > budget.max_tool_calls
        or auditor.elapsed_ms > budget.max_elapsed_ms
        or auditor.context_rounds > budget.max_context_rounds
        or auditor.no_progress_count > budget.max_no_progress
        or not candidate.invocations
    ):
        _reject()
    selections: list[str] = []
    for index, (invocation, attempt) in enumerate(
        zip(candidate.invocations, auditor.attempts, strict=True), start=1
    ):
        request, package, usage = invocation.request, invocation.package, invocation.usage
        _validate_request(request, profile, binding)
        limits = invocation.selection_limits
        if (
            request.request_id in request_ids
            or request.idempotency_key in idempotency_keys
            or request.request_id == discovery_request.request_id
            or request.idempotency_key == discovery_request.idempotency_key
            or request.run_id != discovery_request.run_id
            or request.execution_identity != discovery_request.execution_identity
            or request.role is not ModelRole.AUDITOR
            or request.attempt != index
            or attempt.attempt != index
            or request.tenant_id != auditor.tenant_id
            or request.head_sha != auditor.head_sha
            or package.candidate_id != auditor.candidate_id
            or package.candidate_version != auditor.candidate_version
            or package.tenant_id != auditor.tenant_id
            or package.head_sha != auditor.head_sha
            or package.model_evidence != request.evidence
            or package.selection_sha256 != auditor_selection_sha256(package, limits)
            or package.selection_sha256 != attempt.selection_sha256
            or package.total_context_bytes > limits.max_context_bytes
            or package.total_input_tokens > limits.max_input_tokens
            or len(package.selected) > limits.max_evidence_items
            or package.total_context_bytes > request.budget.max_context_bytes
            or package.total_input_tokens > request.budget.max_input_tokens
            or not set(attempt.cited_evidence_ids).issubset(
                item.evidence_id for item in request.evidence
            )
            or usage.input_tokens > request.budget.max_input_tokens
            or usage.output_tokens > request.budget.max_output_tokens
            or usage.repository_calls > request.budget.max_repository_calls
            or usage.elapsed_ms > request.budget.timeout_ms
            or usage.input_tokens + usage.output_tokens != attempt.tokens_used
            or usage.repository_calls != attempt.tool_calls
            or usage.elapsed_ms != attempt.elapsed_ms
        ):
            _reject()
        request_ids.add(request.request_id)
        idempotency_keys.add(request.idempotency_key)
        selections.append(package.selection_sha256)
    if (
        auditor.initial_selection_sha256 != selections[0]
        or auditor.final_selection_sha256 != selections[-1]
        or auditor.context_rounds != len(set(selections))
        or auditor.tokens_used
        != sum(item.usage.input_tokens + item.usage.output_tokens for item in candidate.invocations)
        or auditor.tool_calls != sum(item.usage.repository_calls for item in candidate.invocations)
        or auditor.elapsed_ms != sum(item.usage.elapsed_ms for item in candidate.invocations)
    ):
        _reject()
