"""Synthetic admission oracles only; these fixtures are not live qualification."""

from __future__ import annotations

import hashlib
import pickle
from dataclasses import replace

import pytest
from pydantic import BaseModel
from securecode_ai.adapters.local_model_qualification import _tool_receipt_sha256
from securecode_ai.adapters.local_provider_admission import (
    AdmissionBindings,
    AuditorCandidateEvidence,
    AuditorInvocationEvidence,
    CapabilityCase,
    CapabilityEvidence,
    CoreCase,
    CoreConformanceEvidence,
    EvidenceOrigin,
    HostAdmissionPins,
    LocalProviderAdmissionError,
    LocalProviderEvidenceBundle,
    NativeToolEvidence,
    ReviewedLocalProviderEvidence,
    TrustedLocalProviderAdmission,
    _digest,
    auditor_selection_sha256,
    evidence_receipt_sha256,
)
from securecode_ai.adapters.native_repository_tools import NATIVE_REPOSITORY_TOOLS_JSON
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CandidateOrigin,
    DataClass,
    DiscoveryCandidate,
    DiscoveryLane,
    EvidenceInputRef,
    FindingVerdict,
    LineageRef,
    ModelBudgetUsage,
    ModelCallResult,
    ModelCallStatus,
    ModelDiscoveryReceipt,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    ModelSchemaResult,
    ModelSchemaStatus,
    ModelUsage,
    NativeOutcomeMetadata,
    OpaqueContentProvenance,
    ProducerRef,
    ProviderProfile,
    RepositoryTool,
)
from securecode_ai.core.evidence_package import (
    EvidenceContextRef,
    EvidencePackage,
    EvidencePackageLimits,
    build_evidence_package,
)
from securecode_ai.core.investigation import (
    AuditorAttemptReceipt,
    AuditorInvestigationReceipt,
    InvestigationBudget,
    InvestigationDisposition,
    InvestigationStopReason,
)
from securecode_ai.core.normalization import normalize_signals
from securecode_ai.core.tool_policy import (
    TOOL_ARGUMENT_SCHEMA_VERSION,
    ListPathsArguments,
    LookupSymbolArguments,
    ReadEvidenceArguments,
    ReadRangeArguments,
    RepositoryToolArguments,
    RepositoryToolReceipt,
    RepositoryToolRequest,
    ToolDecision,
    ToolOutcome,
    ToolReason,
)

from tests.unit.test_evidence_package import _evidence as _core_evidence
from tests.unit.test_evidence_package import _graph as _core_graph
from tests.unit.test_provider_preflight import HEAD, SHA, _pin, _policy, _profile, _request


def _updated[Model: BaseModel](value: Model, **updates: object) -> Model:
    data = {name: getattr(value, name) for name in type(value).model_fields}
    data.update(updates)
    result = type(value).model_validate(data)
    if (
        isinstance(result, (CapabilityEvidence, NativeToolEvidence, CoreConformanceEvidence))
        and "receipt_sha256" not in updates
    ):
        data["receipt_sha256"] = evidence_receipt_sha256(result)
        result = type(value).model_validate(data)
    return result


def _usage(**updates: int) -> ModelUsage:
    return ModelUsage(
        schema_version=CONTRACT_SCHEMA_VERSION,
        input_tokens=updates.get("input_tokens", 20),
        output_tokens=updates.get("output_tokens", 8),
        repository_calls=updates.get("repository_calls", 0),
        elapsed_ms=updates.get("elapsed_ms", 25),
    )


def _result(request: ModelRequest, status: ModelCallStatus) -> ModelCallResult:
    success = status is ModelCallStatus.SUCCEEDED
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
            request_code="COMPATIBLE_RESPONSE",
            finish_code="COMPLETE"
            if success
            else "REFUSED"
            if status is ModelCallStatus.REFUSED
            else "MAX_OUTPUT_TOKENS",
            refusal_code="REFUSED" if status is ModelCallStatus.REFUSED else None,
        ),
        schema_result=ModelSchemaResult(
            schema_version=CONTRACT_SCHEMA_VERSION,
            status=ModelSchemaStatus.VALID if success else ModelSchemaStatus.NOT_VALIDATED,
            error_code=None if success else "MODEL_NON_SUCCESS",
            validator=request.output_schema,
        ),
        usage=_usage(),
        retryable=False,
        content_provenance=OpaqueContentProvenance(
            schema_version=CONTRACT_SCHEMA_VERSION,
            content_id="kid:test-result",
            tenant_id=request.tenant_id,
            data_class=DataClass.CONFIDENTIAL_SOURCE,
            validator=request.output_schema,
        )
        if success
        else None,
        safe_reason_code=None if success else "MODEL_NON_SUCCESS",
    )


def _tool(tool: RepositoryTool, *, success: bool = True) -> RepositoryToolReceipt:
    return RepositoryToolReceipt(
        sequence=1,
        tool=tool.value,
        decision=ToolDecision.ALLOW,
        outcome=ToolOutcome.SUCCEEDED if success else ToolOutcome.NON_SUCCESS,
        reason=ToolReason.SUCCEEDED if success else ToolReason.BUDGET_EXHAUSTED,
        calls_used=1,
        bytes_used=24 if success else 0,
        tokens_used=4 if success else 0,
        output_sha256=SHA if success else None,
    )


def _auditor(request: ModelRequest, package: EvidencePackage) -> AuditorInvestigationReceipt:
    return AuditorInvestigationReceipt(
        candidate_id=package.candidate_id,
        candidate_version=package.candidate_version,
        tenant_id=request.tenant_id,
        head_sha=request.head_sha,
        initial_selection_sha256=package.selection_sha256,
        final_selection_sha256=package.selection_sha256,
        attempts=(
            AuditorAttemptReceipt(
                attempt=1,
                selection_sha256=package.selection_sha256,
                model_call_status=ModelCallStatus.SUCCEEDED,
                schema_valid_result=True,
                verdict_id="verdict-1",
                finding_verdict=FindingVerdict.CONFIRMED,
                cited_evidence_ids=("ev-1",),
                rationale_sha256=SHA,
                tokens_used=20,
                tool_calls=1,
                elapsed_ms=25,
            ),
        ),
        context_rounds=1,
        tokens_used=20,
        tool_calls=1,
        elapsed_ms=25,
        no_progress_count=0,
        final_model_call_status=ModelCallStatus.SUCCEEDED,
        finding_verdict=FindingVerdict.CONFIRMED,
        disposition=InvestigationDisposition.CONFIRMED,
        stop_reason=InvestigationStopReason.CONFIRMED,
    )


def _candidate_invocation(
    request: ModelRequest, case: CoreCase, candidate: DiscoveryCandidate
) -> tuple[AuditorInvestigationReceipt, AuditorCandidateEvidence]:
    request = _updated(
        request,
        request_id=f"auditor-{case.value}-{candidate.candidate_id}",
        idempotency_key=f"idem-{case.value}-{candidate.candidate_id}",
    )
    limits = EvidencePackageLimits()
    package = EvidencePackage(
        candidate_id=candidate.candidate_id,
        candidate_version=candidate.candidate_version,
        tenant_id=request.tenant_id,
        head_sha=request.head_sha,
        graph_id=f"graph-{case.value}",
        graph_sha256=SHA,
        selection_sha256=SHA,
        selected=(
            EvidenceContextRef(
                "ev-1",
                "kid:test-evidence",
                DataClass.CONFIDENTIAL_SOURCE,
                SHA,
                "test-producer",
                "1.0.0",
                SHA,
                24,
                4,
            ),
        ),
        omitted_evidence_ids=(),
        total_context_bytes=24,
        total_input_tokens=4,
        truncated=False,
    )
    package = replace(package, selection_sha256=auditor_selection_sha256(package, limits))
    return _auditor(request, package), AuditorCandidateEvidence(
        budget=InvestigationBudget(
            max_attempts=2, max_tokens=4096, max_tool_calls=8, max_elapsed_ms=5000
        ),
        invocations=(
            AuditorInvocationEvidence(
                request=request,
                package=package,
                selection_limits=limits,
                usage=_usage(input_tokens=12, repository_calls=1),
            ),
        ),
    )


def _lane_candidate(
    request: ModelRequest, case: CoreCase, index: int, *, native: bool
) -> DiscoveryCandidate:
    fingerprint = _digest((case.value, index))
    identifier = f"candidate:{fingerprint}" if native else f"scanner:{fingerprint}"
    return DiscoveryCandidate(
        schema_version=CONTRACT_SCHEMA_VERSION,
        candidate_id=identifier,
        tenant_id=request.tenant_id,
        candidate_version=1,
        head_sha=request.head_sha,
        root_cause_fingerprint=fingerprint,
        candidate_origin=CandidateOrigin.MODEL_NATIVE if native else CandidateOrigin.DETERMINISTIC,
        lineage=(
            LineageRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                lineage_id=f"lineage-{identifier}",
                lane=DiscoveryLane.MODEL_NATIVE if native else DiscoveryLane.DETERMINISTIC,
                producer=ProducerRef(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    producer_id="test-native" if native else "test-scanner",
                    producer_version="1.0.0",
                    producer_sha256=SHA,
                ),
                root_cause_fingerprint=fingerprint,
                input_candidate_ids=(identifier,) if native else (),
                input_signal_ids=() if native else (f"signal:{fingerprint}",),
                evidence_ids=("ev-1",),
            ),
        ),
        evidence_ids=("ev-1",),
    )


def _fixture() -> tuple[ProviderProfile, LocalProviderEvidenceBundle]:
    # A separately named synthetic host profile, never the actual installed model.
    profile = _updated(
        _profile("valid.local-openai-compatible.json"),
        profile_id="test-host-gateway",
        model_id="test-model",
        model_snapshot="b" * 64,
    )
    request = _request(
        profile,
        _policy("egress.valid.private-model-source.json"),
        ModelPurpose.MODEL_NATIVE_DISCOVERY,
    )
    auditor_request = _updated(
        request,
        role=ModelRole.AUDITOR,
        mode=ModelPurpose.CANDIDATE_INVESTIGATION,
        evidence=(
            EvidenceInputRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                evidence_id="ev-1",
                content_id="kid:test-evidence",
                data_class=DataClass.CONFIDENTIAL_SOURCE,
            ),
        ),
    )
    binding = AdmissionBindings(
        provider_profile_sha256=profile.canonical_content_hash(),
        endpoint_sha256=_digest(profile.endpoint.model_dump(mode="json")),
        model_id=profile.model_id,
        model_manifest_sha256=profile.model_snapshot,
        ollama_version="0.16.2",
        ollama_artifact_sha256=SHA,
        gateway_policy_sha256=SHA,
        gateway_source_sha256=SHA,
        connector_sha256=SHA,
        native_tool_schema_sha256=hashlib.sha256(NATIVE_REPOSITORY_TOOLS_JSON).hexdigest(),
        discovery_prompt_sha256=SHA,
        discovery_schema_sha256=SHA,
        auditor_prompt_sha256=SHA,
        auditor_schema_sha256=SHA,
        capabilities_sha256=_digest(profile.capabilities.model_dump(mode="json")),
        budgets_sha256=_digest(profile.budgets.model_dump(mode="json")),
    )
    capabilities = tuple(
        CapabilityEvidence(
            case=case,
            origin=EvidenceOrigin.LIVE,
            receipt_sha256=_digest(case.value),
            request=auditor_request if case is CapabilityCase.STRUCTURED_AUDITOR else request,
            result=_result(
                auditor_request if case is CapabilityCase.STRUCTURED_AUDITOR else request,
                ModelCallStatus.REFUSED
                if case is CapabilityCase.NATIVE_REFUSAL
                else ModelCallStatus.INCOMPLETE
                if case is CapabilityCase.NATIVE_INCOMPLETE
                else ModelCallStatus.SUCCEEDED,
            ),
        )
        for case in CapabilityCase
    )
    arguments: tuple[RepositoryToolArguments, ...] = (
        ListPathsArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "", 4),
        LookupSymbolArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "f", "a.py"),
        ReadRangeArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "a.py", 1, 1),
        ReadEvidenceArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "ev-1"),
    )
    native = tuple(
        NativeToolEvidence(
            origin=EvidenceOrigin.LIVE,
            receipt_sha256=_digest(tool.value),
            sent_prompt_sha256=SHA,
            call_id=f"call-{index}",
            model_request=request,
            request=RepositoryToolRequest(tool, args),
            receipt=_tool(tool),
            usage=_usage(),
        )
        for index, (tool, args) in enumerate(zip(RepositoryTool, arguments, strict=True))
    )
    cases: list[CoreConformanceEvidence] = []
    for case in CoreCase:
        fault = case in {CoreCase.PROVIDER_FAULT, CoreCase.TOOL_FAULT}
        zero = (
            fault
            or case.value.endswith(("_safe", "_safe_interfile"))
            or case is CoreCase.NATIVE_COMPLETED_ZERO
        )
        count = 0 if zero else 2 if case is CoreCase.AUDITOR_ALL_CANDIDATES else 1
        native_candidates = tuple(
            _lane_candidate(request, case, index, native=True) for index in range(count)
        )
        scanner_candidates = (
            tuple(_lane_candidate(request, case, index, native=False) for index in range(count))
            if case is not CoreCase.ZERO_SCANNER_NATIVE_FINDING
            else ()
        )
        normalized_candidates = normalize_signals(
            discovery_candidates=(*native_candidates, *scanner_candidates)
        )
        tool_receipts = (_tool(RepositoryTool.READ_RANGE, success=case is not CoreCase.TOOL_FAULT),)
        status = (
            ModelCallStatus.PROVIDER_ERROR
            if case is CoreCase.PROVIDER_FAULT
            else ModelCallStatus.GUARDRAIL_BLOCKED
            if case is CoreCase.TOOL_FAULT
            else ModelCallStatus.SUCCEEDED
        )
        discovery = ModelDiscoveryReceipt(
            schema_version=CONTRACT_SCHEMA_VERSION,
            receipt_id=f"receipt-{case.value}",
            tenant_id=request.tenant_id,
            head_sha=HEAD,
            scope_sha256=SHA,
            model_profile=request.provider_profile,
            prompt=request.prompt,
            repository_view_call_hashes=tuple(_tool_receipt_sha256(item) for item in tool_receipts),
            budget_usage=ModelBudgetUsage(
                schema_version=CONTRACT_SCHEMA_VERSION,
                token_limit=4096,
                tokens_used=28,
                repository_call_limit=8,
                repository_calls_used=1,
                time_limit_ms=5000,
                elapsed_ms=25,
            ),
            model_call_status=status,
            schema_valid_result=not fault,
            input_sha256=SHA,
            output_sha256=None if fault else SHA,
            candidate_ids=tuple(item.candidate_id for item in native_candidates),
        )
        candidate_proofs = tuple(
            _candidate_invocation(auditor_request, case, candidate)
            for candidate in normalized_candidates
        )
        cases.append(
            CoreConformanceEvidence(
                case=case,
                origin=EvidenceOrigin.FAULT_INJECTED if fault else EvidenceOrigin.LIVE,
                receipt_sha256=_digest(case.value),
                recipe=_pin(f"recipe-{case.value}", "1.0.0", SHA),
                request=request,
                discovery=discovery,
                normalized_candidate_ids=tuple(item.candidate_id for item in normalized_candidates),
                scanner_candidate_ids=tuple(item.candidate_id for item in scanner_candidates),
                native_candidates=native_candidates,
                scanner_candidates=scanner_candidates,
                normalized_candidates=normalized_candidates,
                auditors=tuple(item[0] for item in candidate_proofs),
                auditor_invocations=tuple(item[1] for item in candidate_proofs),
                tool_receipts=tool_receipts,
                native_turn_request_hashes=tuple(_digest(i) for i in range(3))
                if case is CoreCase.NATIVE_CYCLE
                else (),
            )
        )
    return profile, LocalProviderEvidenceBundle(
        bindings=binding,
        review_receipt=_pin("test-independent-review", "1.0.0", SHA),
        producer_id="test-producer",
        independent_reviewer_id="test-reviewer",
        capabilities=tuple(_updated(item) for item in capabilities),
        native_tools=tuple(_updated(item) for item in native),
        core_cases=tuple(_updated(item) for item in cases),
    )


def _authority(
    profile: ProviderProfile, bundle: LocalProviderEvidenceBundle
) -> TrustedLocalProviderAdmission:
    return TrustedLocalProviderAdmission(
        approved_profile=profile.model_dump_json().encode(),
        pins=HostAdmissionPins(
            bindings=bundle.bindings,
            approved_bundle_sha256=bundle.content_sha256,
            review_receipt=bundle.review_receipt,
            producer_id=bundle.producer_id,
            independent_reviewer_id=bundle.independent_reviewer_id,
        ),
    )


def test_reviewed_complete_bundle_registers_only_exact_synthetic_profile() -> None:
    profile, bundle = _fixture()
    authority = _authority(profile, bundle)
    seal = authority.review(bundle)
    registry = authority.admit(seal)
    assert registry.select(f"{profile.profile_id}@{profile.profile_version}") == profile
    assert repr(seal) == "ReviewedLocalProviderEvidence(<sealed>)"


@pytest.mark.parametrize("section", ["capabilities", "native_tools", "core_cases"])
def test_even_host_pinned_partial_bundle_rejects(section: str) -> None:
    profile, bundle = _fixture()
    incomplete = _updated(bundle, **{section: getattr(bundle, section)[:-1]})
    with pytest.raises(LocalProviderAdmissionError, match=r"^local provider admission rejected$"):
        _authority(profile, incomplete).review(incomplete)


@pytest.mark.parametrize("section", ["capabilities", "native_tools", "core_cases"])
def test_simulated_receipt_cannot_grant_capability_even_with_approved_hash(section: str) -> None:
    profile, bundle = _fixture()
    items = getattr(bundle, section)
    altered = _updated(
        bundle, **{section: (_updated(items[0], origin=EvidenceOrigin.SIMULATED), *items[1:])}
    )
    with pytest.raises(LocalProviderAdmissionError):
        _authority(profile, altered).review(altered)


def test_imported_bundle_changes_and_review_binding_are_not_authority() -> None:
    profile, bundle = _fixture()
    authority = _authority(profile, bundle)
    for altered in (
        _updated(bundle, review_receipt=_pin("other-review", "1.0.0", SHA)),
        _updated(bundle, independent_reviewer_id="other-reviewer"),
        _updated(bundle, bindings=_updated(bundle.bindings, gateway_source_sha256="f" * 64)),
        _updated(
            bundle,
            native_tools=(
                _updated(bundle.native_tools[0], receipt_sha256="f" * 64),
                *bundle.native_tools[1:],
            ),
        ),
    ):
        with pytest.raises(LocalProviderAdmissionError):
            authority.review(altered)


def test_seal_is_single_authority_immutable_and_not_importable() -> None:
    profile, bundle = _fixture()
    authority = _authority(profile, bundle)
    seal = authority.review(bundle)
    with pytest.raises(LocalProviderAdmissionError):
        _authority(profile, bundle).admit(seal)
    with pytest.raises(TypeError):
        ReviewedLocalProviderEvidence()
    with pytest.raises(TypeError):
        pickle.dumps(seal)
    with pytest.raises(AttributeError):
        seal._bundle_bytes = b"{}"
    with pytest.raises(AttributeError):
        authority._profile_bytes = b"{}"
    with pytest.raises(LocalProviderAdmissionError):
        authority.review(bundle.model_dump())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "change",
    [
        "zero_usage",
        "over_elapsed",
        "tool_mismatch",
        "missing_auditor",
        "missing_cycle",
        "duplicate_ref",
        "wrong_head",
    ],
)
def test_host_approval_does_not_replace_semantic_receipt_validation(change: str) -> None:
    profile, bundle = _fixture()
    if change in {"zero_usage", "over_elapsed", "tool_mismatch"}:
        item = bundle.native_tools[0]
        if change == "tool_mismatch":
            item = _updated(item, receipt=_tool(RepositoryTool.READ_RANGE))
        else:
            item = _updated(
                item,
                usage=_usage(input_tokens=0)
                if change == "zero_usage"
                else _usage(elapsed_ms=60001),
            )
        bundle = _updated(bundle, native_tools=(item, *bundle.native_tools[1:]))
    elif change == "duplicate_ref":
        cap = _updated(bundle.capabilities[0], receipt_sha256=bundle.native_tools[0].receipt_sha256)
        bundle = _updated(bundle, capabilities=(cap, *bundle.capabilities[1:]))
    else:
        index = next(
            i for i, item in enumerate(bundle.core_cases) if item.case is CoreCase.NATIVE_CYCLE
        )
        core = bundle.core_cases[index]
        core = _updated(
            core,
            **(
                {"auditors": ()}
                if change == "missing_auditor"
                else {"native_turn_request_hashes": ()}
                if change == "missing_cycle"
                else {"auditors": (replace(core.auditors[0], head_sha="2" * 40),)}
            ),
        )
        cases = list(bundle.core_cases)
        cases[index] = core
        bundle = _updated(bundle, core_cases=tuple(cases))
    with pytest.raises(LocalProviderAdmissionError):
        _authority(profile, bundle).review(bundle)


@pytest.mark.parametrize(
    "field",
    [
        "provider_profile_sha256",
        "endpoint_sha256",
        "capabilities_sha256",
        "budgets_sha256",
        "native_tool_schema_sha256",
        "model_manifest_sha256",
    ],
)
def test_constructor_rejects_profile_and_compiled_source_drift(field: str) -> None:
    profile, bundle = _fixture()
    bundle = _updated(bundle, bindings=_updated(bundle.bindings, **{field: "f" * 64}))
    with pytest.raises(LocalProviderAdmissionError):
        _authority(profile, bundle)


def test_constructor_rejects_nonindependent_review() -> None:
    profile, bundle = _fixture()
    bundle = _updated(bundle, independent_reviewer_id=bundle.producer_id)
    with pytest.raises(LocalProviderAdmissionError):
        _authority(profile, bundle)


def test_constructor_rejects_unqualified_flags_and_nonindependent_review() -> None:
    profile, bundle = _fixture()
    profile = _updated(
        profile, capabilities=_updated(profile.capabilities, native_refusal_signal=False)
    )
    bundle = _updated(
        bundle,
        bindings=_updated(
            bundle.bindings,
            provider_profile_sha256=profile.canonical_content_hash(),
            capabilities_sha256=_digest(profile.capabilities.model_dump(mode="json")),
        ),
    )
    with pytest.raises(LocalProviderAdmissionError):
        _authority(profile, bundle)


@pytest.mark.parametrize(
    "case", [item for item in CoreCase if item.value.endswith("_safe_interfile")]
)
def test_safe_interfile_control_must_complete_with_no_candidates(case: CoreCase) -> None:
    profile, bundle = _fixture()
    index = next(i for i, item in enumerate(bundle.core_cases) if item.case is case)
    positive = next(item for item in bundle.core_cases if item.case is CoreCase.PYTHON_INTERFILE)
    cases = list(bundle.core_cases)
    cases[index] = _updated(positive, case=case, receipt_sha256=_digest(case.value))
    bundle = _updated(bundle, core_cases=tuple(cases))
    with pytest.raises(LocalProviderAdmissionError):
        _authority(profile, bundle).review(bundle)


@pytest.mark.parametrize("section", ["capabilities", "native_tools", "core_cases"])
def test_fault_injection_origin_cannot_be_substituted_for_live_proof(section: str) -> None:
    profile, bundle = _fixture()
    items = getattr(bundle, section)
    bundle = _updated(
        bundle, **{section: (_updated(items[0], origin=EvidenceOrigin.FAULT_INJECTED), *items[1:])}
    )
    with pytest.raises(LocalProviderAdmissionError):
        _authority(profile, bundle).review(bundle)


@pytest.mark.parametrize("case", [CoreCase.PROVIDER_FAULT, CoreCase.TOOL_FAULT])
def test_fault_cases_require_explicit_fault_injected_provenance(case: CoreCase) -> None:
    profile, bundle = _fixture()
    cases = tuple(
        _updated(item, origin=EvidenceOrigin.LIVE) if item.case is case else item
        for item in bundle.core_cases
    )
    bundle = _updated(bundle, core_cases=cases)
    with pytest.raises(LocalProviderAdmissionError):
        _authority(profile, bundle).review(bundle)


@pytest.mark.parametrize(
    "change",
    ["tool_head", "context_bytes", "unknown_elapsed", "auditor_prompt", "scope", "budget_limits"],
)
def test_request_and_source_bindings_are_mechanical(change: str) -> None:
    profile, bundle = _fixture()
    if change in {"tool_head", "context_bytes", "unknown_elapsed"}:
        native = bundle.native_tools[0]
        if change == "tool_head":
            native = _updated(
                native,
                request=replace(
                    native.request, arguments=replace(native.request.arguments, head_sha="2" * 40)
                ),
            )
        elif change == "context_bytes":
            native = _updated(native, receipt=replace(native.receipt, bytes_used=65537))
        else:
            native = _updated(native, usage=_usage(elapsed_ms=0))
        bundle = _updated(bundle, native_tools=(native, *bundle.native_tools[1:]))
    else:
        core = bundle.core_cases[0]
        if change == "auditor_prompt":
            candidate = core.auditor_invocations[0]
            invocation = candidate.invocations[0]
            core = _updated(
                core,
                auditor_invocations=(
                    _updated(
                        candidate,
                        invocations=(
                            _updated(
                                invocation,
                                request=_updated(
                                    invocation.request,
                                    prompt=_pin("changed-prompt", "1.0.0", "f" * 64),
                                ),
                            ),
                        ),
                    ),
                ),
            )
        elif change == "scope":
            core = _updated(core, discovery=_updated(core.discovery, scope_sha256="f" * 64))
        else:
            core = _updated(
                core,
                discovery=_updated(
                    core.discovery,
                    budget_usage=_updated(core.discovery.budget_usage, token_limit=4097),
                ),
            )
        bundle = _updated(bundle, core_cases=(core, *bundle.core_cases[1:]))
    with pytest.raises(LocalProviderAdmissionError):
        _authority(profile, bundle).review(bundle)


@pytest.mark.parametrize("truncated", [False, True])
def test_selection_digest_interoperates_with_actual_core_producer(truncated: bool) -> None:
    limits = EvidencePackageLimits(
        max_context_bytes=4 if truncated else 65536,
        max_input_tokens=1 if truncated else 16384,
        max_evidence_items=1 if truncated else 128,
    )
    package = build_evidence_package(
        _core_graph(_core_evidence("evidence-b"), _core_evidence("evidence-a")),
        "candidate-a",
        limits=limits,
    )
    assert auditor_selection_sha256(package, limits) == package.selection_sha256
    assert package.truncated is truncated


def _with_core(
    bundle: LocalProviderEvidenceBundle, core: CoreConformanceEvidence
) -> LocalProviderEvidenceBundle:
    return _updated(
        bundle,
        core_cases=tuple(core if item.case is core.case else item for item in bundle.core_cases),
    )


@pytest.mark.parametrize(
    "change",
    [
        "attempt_tools",
        "attempt_tokens",
        "attempt_time",
        "aggregate_tools",
        "aggregate_tokens",
        "aggregate_time",
        "attempt_count",
    ],
)
def test_explicit_auditor_attempt_and_loop_budgets_are_enforced(change: str) -> None:
    profile, bundle = _fixture()
    core = bundle.core_cases[0]
    candidate = core.auditor_invocations[0]
    invocation = candidate.invocations[0]
    auditor = core.auditors[0]
    if change.startswith("aggregate_"):
        candidate = _updated(
            candidate,
            budget=replace(
                candidate.budget,
                **(
                    {"max_tool_calls": 1}
                    if change == "aggregate_tools"
                    else {"max_tokens": 19}
                    if change == "aggregate_tokens"
                    else {"max_elapsed_ms": 24}
                ),
            ),
        )
        if change == "aggregate_tools":
            invocation = _updated(invocation, usage=_usage(input_tokens=12, repository_calls=2))
            attempt = replace(auditor.attempts[0], tool_calls=2)
            auditor = replace(auditor, attempts=(attempt,), tool_calls=2)
            candidate = _updated(candidate, invocations=(invocation,))
    elif change == "attempt_count":
        second = _updated(
            invocation,
            request=_updated(
                invocation.request,
                request_id="second-attempt",
                idempotency_key="second-idem",
                attempt=2,
            ),
        )
        candidate = _updated(
            candidate,
            budget=replace(candidate.budget, max_attempts=1),
            invocations=(invocation, second),
        )
        auditor = replace(
            auditor,
            attempts=(auditor.attempts[0], replace(auditor.attempts[0], attempt=2)),
            tokens_used=40,
            tool_calls=2,
            elapsed_ms=50,
        )
    else:
        if change == "attempt_tools":
            # Both aggregate and attempt are internally consistent, as in the
            # independent 1000-call exploit; the explicit request still caps 8.
            invocation = _updated(invocation, usage=_usage(input_tokens=12, repository_calls=1000))
            auditor = replace(
                auditor, attempts=(replace(auditor.attempts[0], tool_calls=1000),), tool_calls=1000
            )
            candidate = _updated(candidate, budget=replace(candidate.budget, max_tool_calls=1000))
        else:
            budget = invocation.request.budget
            budget = _updated(
                budget,
                **(
                    {"max_input_tokens": 10, "max_output_tokens": 8}
                    if change == "attempt_tokens"
                    else {"timeout_ms": 24}
                ),
            )
            invocation = _updated(invocation, request=_updated(invocation.request, budget=budget))
        candidate = _updated(candidate, invocations=(invocation,))
    core = _updated(core, auditors=(auditor,), auditor_invocations=(candidate,))
    bundle = _with_core(bundle, core)
    with pytest.raises(LocalProviderAdmissionError):
        _authority(profile, bundle).review(bundle)


@pytest.mark.parametrize(
    "change",
    [
        "duplicate_request",
        "duplicate_idempotency",
        "wrong_run",
        "wrong_candidate",
        "wrong_version",
        "wrong_selection",
        "unknown_citation",
        "changed_evidence",
        "split_usage",
    ],
)
def test_each_candidate_request_and_selected_evidence_are_bound(change: str) -> None:
    profile, bundle = _fixture()
    core = next(item for item in bundle.core_cases if item.case is CoreCase.AUDITOR_ALL_CANDIDATES)
    first, candidate = core.auditor_invocations
    invocation = candidate.invocations[0]
    auditor = core.auditors[1]
    if change in {"duplicate_request", "duplicate_idempotency", "wrong_run"}:
        request = _updated(
            invocation.request,
            **(
                {"request_id": first.invocations[0].request.request_id}
                if change == "duplicate_request"
                else {"idempotency_key": first.invocations[0].request.idempotency_key}
                if change == "duplicate_idempotency"
                else {"run_id": "foreign-run"}
            ),
        )
        invocation = _updated(invocation, request=request)
    elif change == "unknown_citation":
        auditor = replace(
            auditor,
            attempts=(replace(auditor.attempts[0], cited_evidence_ids=("unselected-evidence",)),),
        )
    elif change == "changed_evidence":
        invocation = _updated(
            invocation,
            request=_updated(
                invocation.request,
                evidence=(
                    _updated(invocation.request.evidence[0], content_id="kid:other-content"),
                ),
            ),
        )
    elif change == "split_usage":
        # Same total tokens, but output exceeds the exact output budget.
        invocation = _updated(
            invocation,
            request=_updated(
                invocation.request, budget=_updated(invocation.request.budget, max_output_tokens=7)
            ),
        )
    else:
        package = replace(
            invocation.package,
            **(
                {"candidate_id": "other-candidate"}
                if change == "wrong_candidate"
                else {"candidate_version": 2}
                if change == "wrong_version"
                else {"selection_sha256": "f" * 64}
            ),
        )
        invocation = _updated(invocation, package=package)
    candidate = _updated(candidate, invocations=(invocation,))
    core = _updated(
        core, auditors=(core.auditors[0], auditor), auditor_invocations=(first, candidate)
    )
    bundle = _with_core(bundle, core)
    with pytest.raises(LocalProviderAdmissionError):
        _authority(profile, bundle).review(bundle)


@pytest.mark.parametrize("section", ["capabilities", "native_tools", "core_cases"])
def test_host_pinned_metadata_mutation_with_stale_record_digest_rejects(section: str) -> None:
    profile, bundle = _fixture()
    items = getattr(bundle, section)
    original = items[0]
    if section == "capabilities":
        request = _updated(original.request, request_id="changed-capability-request")
        mutated = _updated(
            original,
            request=request,
            result=_updated(original.result, request_id=request.request_id),
            receipt_sha256=original.receipt_sha256,
        )
    elif section == "native_tools":
        mutated = _updated(
            original, call_id="changed-native-call", receipt_sha256=original.receipt_sha256
        )
    else:
        mutated = _updated(
            original,
            recipe=_pin("changed-recipe", "1.0.0", SHA),
            receipt_sha256=original.receipt_sha256,
        )
    assert evidence_receipt_sha256(mutated) != original.receipt_sha256
    bundle = _updated(bundle, **{section: (mutated, *items[1:])})
    with pytest.raises(LocalProviderAdmissionError):
        _authority(profile, bundle).review(bundle)


def test_measured_usage_at_exact_request_and_loop_limits_is_admissible() -> None:
    profile, bundle = _fixture()
    core = bundle.core_cases[0]
    candidate = core.auditor_invocations[0]
    invocation = _updated(
        candidate.invocations[0],
        usage=_usage(input_tokens=3072, output_tokens=1024, repository_calls=8, elapsed_ms=5000),
    )
    auditor = core.auditors[0]
    auditor = replace(
        auditor,
        attempts=(replace(auditor.attempts[0], tokens_used=4096, tool_calls=8, elapsed_ms=5000),),
        tokens_used=4096,
        tool_calls=8,
        elapsed_ms=5000,
    )
    core = _updated(
        core,
        auditors=(auditor,),
        auditor_invocations=(_updated(candidate, invocations=(invocation,)),),
    )
    bundle = _with_core(bundle, core)
    authority = _authority(profile, bundle)
    assert (
        authority.admit(authority.review(bundle)).select(
            f"{profile.profile_id}@{profile.profile_version}"
        )
        == profile
    )


def _with_normalized_records(
    core: CoreConformanceEvidence, normalized: tuple[DiscoveryCandidate, ...]
) -> CoreConformanceEvidence:
    auditor_request = core.auditor_invocations[0].invocations[0].request
    proofs = tuple(_candidate_invocation(auditor_request, core.case, item) for item in normalized)
    return _updated(
        core,
        normalized_candidates=normalized,
        normalized_candidate_ids=tuple(item.candidate_id for item in normalized),
        auditors=tuple(item[0] for item in proofs),
        auditor_invocations=tuple(item[1] for item in proofs),
    )


def test_original_lane_ids_change_and_converge_through_actual_core_lineage() -> None:
    profile, bundle = _fixture()
    core = bundle.core_cases[0]
    original_ids = {core.native_candidates[0].candidate_id, core.scanner_candidates[0].candidate_id}
    assert not original_ids.issubset(core.normalized_candidate_ids)
    assert len(core.normalized_candidates) == 1
    normalized = core.normalized_candidates[0]
    assert (
        normalized
        == normalize_signals(
            discovery_candidates=(*core.native_candidates, *core.scanner_candidates)
        )[0]
    )
    assert normalized.candidate_origin is CandidateOrigin.HYBRID
    assert original_ids.issubset(
        {identifier for lineage in normalized.lineage for identifier in lineage.input_candidate_ids}
    )
    authority = _authority(profile, bundle)
    assert (
        authority.admit(authority.review(bundle)).select(
            f"{profile.profile_id}@{profile.profile_version}"
        )
        == profile
    )


def test_normalized_version_comes_from_actual_core_inputs() -> None:
    profile, bundle = _fixture()
    core = bundle.core_cases[0]
    native = _updated(core.native_candidates[0], candidate_version=2)
    core = _updated(core, native_candidates=(native,))
    normalized = normalize_signals(
        discovery_candidates=(*core.native_candidates, *core.scanner_candidates)
    )
    assert normalized[0].candidate_version == 2
    core = _with_normalized_records(core, normalized)
    assert core.auditors[0].candidate_version == 2
    bundle = _with_core(bundle, core)
    authority = _authority(profile, bundle)
    authority.admit(authority.review(bundle))


@pytest.mark.parametrize(
    "change",
    [
        "id_collision",
        "foreign_tenant",
        "foreign_head",
        "wrong_native_origin",
        "wrong_scanner_origin",
        "declared_native_id",
        "declared_scanner_id",
    ],
)
def test_original_lane_records_and_declared_ids_are_bound(change: str) -> None:
    profile, bundle = _fixture()
    core = bundle.core_cases[0]
    if change == "id_collision":
        scanner = _updated(
            core.scanner_candidates[0], candidate_id=core.native_candidates[0].candidate_id
        )
        core = _updated(
            core, scanner_candidates=(scanner,), scanner_candidate_ids=(scanner.candidate_id,)
        )
    elif change.startswith("foreign_"):
        native = _updated(
            core.native_candidates[0],
            **(
                {"tenant_id": "foreign-tenant"}
                if change == "foreign_tenant"
                else {"head_sha": "2" * 40}
            ),
        )
        core = _updated(core, native_candidates=(native,))
    elif change == "wrong_native_origin":
        scanner = core.scanner_candidates[0]
        core = _updated(
            core,
            native_candidates=(scanner,),
            discovery=_updated(core.discovery, candidate_ids=(scanner.candidate_id,)),
        )
    elif change == "wrong_scanner_origin":
        native = core.native_candidates[0]
        core = _updated(
            core, scanner_candidates=(native,), scanner_candidate_ids=(native.candidate_id,)
        )
    elif change == "declared_native_id":
        core = _updated(
            core, discovery=_updated(core.discovery, candidate_ids=("invented-native-id",))
        )
    else:
        core = _updated(core, scanner_candidate_ids=("invented-scanner-id",))
    bundle = _with_core(bundle, core)
    with pytest.raises(LocalProviderAdmissionError):
        _authority(profile, bundle).review(bundle)


@pytest.mark.parametrize(
    "change",
    [
        "forged_mapping",
        "dropped_lineage",
        "dropped_candidate",
        "forged_version",
        "foreign_normalized",
        "altered_evidence",
    ],
)
def test_recomputing_core_normalization_rejects_forged_mapping(change: str) -> None:
    profile, bundle = _fixture()
    core = bundle.core_cases[0]
    normalized = core.normalized_candidates[0]
    if change == "forged_mapping":
        normalized = _updated(normalized, candidate_id=core.native_candidates[0].candidate_id)
    elif change == "dropped_lineage":
        normalized = _updated(
            normalized,
            lineage=tuple(
                item for item in normalized.lineage if item.lane is DiscoveryLane.MODEL_NATIVE
            ),
            candidate_origin=CandidateOrigin.MODEL_NATIVE,
        )
    elif change == "dropped_candidate":
        # Every declared ID and Auditor binding agrees with the retained output,
        # but actual normalization would also retain this second original input.
        native = _lane_candidate(core.request, core.case, 1, native=True)
        core = _updated(
            core,
            native_candidates=(*core.native_candidates, native),
            discovery=_updated(
                core.discovery, candidate_ids=(*core.discovery.candidate_ids, native.candidate_id)
            ),
        )
    elif change == "forged_version":
        normalized = _updated(normalized, candidate_version=2)
    elif change == "foreign_normalized":
        normalized = _updated(normalized, head_sha="2" * 40)
    else:
        normalized = _updated(
            normalized, evidence_ids=(*normalized.evidence_ids, "unproduced-evidence")
        )
    core = _with_normalized_records(core, (normalized,))
    # Helper rebuilt the Auditor record and package consistently with the forged
    # output; only independent reproduction of the original lanes can accept it.
    assert core.auditors[0].candidate_id == normalized.candidate_id
    assert core.auditors[0].candidate_version == normalized.candidate_version
    bundle = _with_core(bundle, core)
    with pytest.raises(LocalProviderAdmissionError):
        _authority(profile, bundle).review(bundle)


def test_auditor_version_must_match_the_exact_normalized_record() -> None:
    profile, bundle = _fixture()
    core = bundle.core_cases[0]
    candidate = core.auditor_invocations[0]
    invocation = candidate.invocations[0]
    package = replace(invocation.package, candidate_version=2)
    package = replace(
        package, selection_sha256=auditor_selection_sha256(package, invocation.selection_limits)
    )
    auditor = replace(
        core.auditors[0],
        candidate_version=2,
        initial_selection_sha256=package.selection_sha256,
        final_selection_sha256=package.selection_sha256,
        attempts=(
            replace(core.auditors[0].attempts[0], selection_sha256=package.selection_sha256),
        ),
    )
    core = _updated(
        core,
        auditors=(auditor,),
        auditor_invocations=(
            _updated(candidate, invocations=(_updated(invocation, package=package),)),
        ),
    )
    bundle = _with_core(bundle, core)
    with pytest.raises(LocalProviderAdmissionError):
        _authority(profile, bundle).review(bundle)
