"""Public synthetic-Core composition through the existing authorization boundary.

This module composes the existing Core ports. Without an injected transport,
run_public_core_case can invoke the configured local provider. An injected
transport remains SIMULATED; this module never qualifies or admits a provider.
"""

from __future__ import annotations

import hashlib

from securecode_ai.adapters.endpoint import Resolver
from securecode_ai.adapters.model import CredentialSupplier
from securecode_ai.adapters.product_conformance import ProductAuditorEvidenceRecorder
from securecode_ai.adapters.product_runtime import (
    PRODUCT_AUDITOR_PROMPT_PIN,
    GuardedEvidenceResolver,
    ProductAuditorInvoker,
    ProductDiscoveryBackend,
)
from securecode_ai.adapters.product_scan import (
    ProductCandidateFlow,
    run_product_candidate_flow,
)
from securecode_ai.adapters.product_scanner import (
    ProductDeterministicScanResult,
    build_product_auditor_tools,
    scan_product_sources,
)
from securecode_ai.adapters.public_discovery_observation import (
    PublicDiscoveryObservationRecorder,
)
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    EvidenceInputRef,
    ExecutionBoundary,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    PreflightEligibility,
)
from securecode_ai.core.evidence_graph import EvidenceGraph
from securecode_ai.core.model_discovery import ModelNativeDiscoveryPlan
from securecode_ai.core.tool_policy import RepositoryToolBudget, RepositoryToolScope

from .local_provider_admission import CoreCase, EvidenceOrigin
from .public_core_runner_composition import (
    _executor,
    _investigation_budget,
    _native_producer,
    prepare_public_core_case,
)
from .public_core_runner_primitives import (
    _PUBLIC_CONTENT_KEY,
    _RULE_IDS,
    PublicCoreHostInputs,
    PublicCoreRunResult,
    SystemPublicResolver,
    _fail,
)


def run_public_core_case(
    *,
    case: CoreCase,
    inputs: PublicCoreHostInputs,
    simulated_transport: object | None = None,
    resolver: Resolver | None = None,
    credential_supplier: CredentialSupplier | None = None,
) -> PublicCoreRunResult:
    """Compose the real Core ports.  An injected transport remains explicitly simulated."""
    if type(inputs) is not PublicCoreHostInputs:
        _fail()
    inputs = inputs.snapshot()
    prepared = prepare_public_core_case(case=case, inputs=inputs)
    origin = EvidenceOrigin.SIMULATED if simulated_transport is not None else None
    if prepared.preflight.eligibility is not PreflightEligibility.ELIGIBLE:
        return PublicCoreRunResult(case, origin, prepared.preflight, None)
    try:
        selected_resolver = resolver
        if (
            selected_resolver is None
            and inputs.profile.execution_boundary is not ExecutionBoundary.LOCAL_RUNNER
        ):
            selected_resolver = SystemPublicResolver()
        discovery_executor = _executor(
            inputs=inputs,
            connector=simulated_transport,
            native=True,
            resolver=selected_resolver,
            credential_supplier=credential_supplier,
        )
        auditor_executor = _executor(
            inputs=inputs,
            connector=simulated_transport,
            native=False,
            resolver=selected_resolver,
            credential_supplier=credential_supplier,
        )
        catalogue = prepared.fixture.catalogue
        plan = ModelNativeDiscoveryPlan(
            receipt_id=f"public-receipt-{prepared.fixture.head_sha[:16]}",
            request=prepared.request,
            preflight_eligibility=PreflightEligibility.ELIGIBLE,
            scope=RepositoryToolScope(
                prepared.request.tenant_id,
                catalogue.indexes[0].repository_id,
                prepared.fixture.head_sha,
                tuple(sorted(index.path for index in catalogue.indexes)),
                tuple(sorted(anchor.evidence_id for anchor in catalogue.anchors)),
            ),
            tool_budget=RepositoryToolBudget(
                4, 1_048_576, prepared.request.budget.max_input_tokens
            ),
            producer=_native_producer(inputs, simulated=simulated_transport is not None),
        )
        discovery_recorder = PublicDiscoveryObservationRecorder(plan)
        backend = ProductDiscoveryBackend(
            executor=discovery_executor,
            catalogue=catalogue.anchors,
            rule_ids=_RULE_IDS,
            content_key=_PUBLIC_CONTENT_KEY,
            native_cycle=True,
            data_class=catalogue.data_class,
            observer=discovery_recorder.observe,
        )
        investigation_budget = _investigation_budget(inputs, prepared.request)
        recorder = ProductAuditorEvidenceRecorder(
            discovery_request=prepared.request,
            investigation_budget=investigation_budget,
        )
        deterministic: ProductDeterministicScanResult | None = None

        def scanner(selected: object) -> ProductDeterministicScanResult:
            nonlocal deterministic
            if selected is not catalogue:
                _fail()
            deterministic = scan_product_sources(catalogue, tenant_id=prepared.request.tenant_id)
            return deterministic

        def auditor_factory(graph: EvidenceGraph) -> ProductAuditorInvoker:
            selected_deterministic = deterministic
            if selected_deterministic is None:
                _fail()
            tools = build_product_auditor_tools(
                catalogue,
                graph,
                budget=RepositoryToolBudget(4, 1_048_576, prepared.request.budget.max_input_tokens),
                deterministic=selected_deterministic,
            )
            evidence = (
                *catalogue.evidence_records(
                    _native_producer(inputs, simulated=simulated_transport is not None)
                ),
                *selected_deterministic.graph.evidence,
            )
            resolver = GuardedEvidenceResolver(tools=tools, evidence=evidence)

            def auditor_request(package: object, attempt: int, validator: object) -> ModelRequest:
                if type(attempt) is not int or type(validator) is not ComponentPin:
                    _fail()
                selected = getattr(package, "model_evidence", None)
                if type(selected) is not tuple or any(
                    type(item) is not EvidenceInputRef for item in selected
                ):
                    _fail()
                candidate = getattr(package, "candidate_id", "candidate")
                version = getattr(package, "candidate_version", None)
                selection = getattr(package, "selection_sha256", None)
                if (
                    type(candidate) is not str
                    or type(version) is not int
                    or type(selection) is not str
                ):
                    _fail()
                token = hashlib.sha256(
                    f"{prepared.request.run_id}:{candidate}:{version}:{selection}:{attempt}".encode()
                ).hexdigest()[:24]
                return ModelRequest(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    request_id=f"public-auditor-{token}",
                    run_id=prepared.request.run_id,
                    tenant_id=prepared.request.tenant_id,
                    idempotency_key=f"public-auditor-{token}",
                    attempt=attempt,
                    execution_identity=prepared.request.execution_identity,
                    head_sha=prepared.request.head_sha,
                    role=ModelRole.AUDITOR,
                    mode=ModelPurpose.CANDIDATE_INVESTIGATION,
                    provider_profile=inputs.provider_pin,
                    api_dialect=inputs.profile.api_dialect,
                    model_id=inputs.profile.model_id,
                    prompt=PRODUCT_AUDITOR_PROMPT_PIN,
                    output_schema=validator,
                    tool_policy=inputs.artifacts.tool_policy,
                    repository_scope=inputs.artifacts.repository_scope,
                    repository_view_policy=inputs.artifacts.repository_view_policy,
                    evidence=selected,
                    budget=prepared.request.budget,
                )

            return ProductAuditorInvoker(
                executor=auditor_executor,
                resolver=resolver,
                evidence_catalogue=evidence,
                content_key=_PUBLIC_CONTENT_KEY,
                request_factory=auditor_request,
                observer=recorder.observe,
            )

        flow = run_product_candidate_flow(
            catalogue=catalogue,
            model_plan=plan,
            model_backend=backend,
            deterministic_scanner=scanner,
            auditor_factory=auditor_factory,
            investigation_budget=investigation_budget,
        )
        if type(flow) is ProductCandidateFlow:
            try:
                discovery_observation = discovery_recorder.finalize(flow.discovery)
            except (TypeError, ValueError, RuntimeError):
                return PublicCoreRunResult(
                    case, origin, prepared.preflight, flow, (), "DISCOVERY_RECONCILIATION_FAILED"
                )
            try:
                evidence = recorder.finalize(flow)
            except (TypeError, ValueError, RuntimeError):
                return PublicCoreRunResult(
                    case,
                    origin,
                    prepared.preflight,
                    flow,
                    (),
                    "RECONCILIATION_FAILED",
                    discovery_observation,
                )
            return PublicCoreRunResult(
                case,
                origin,
                prepared.preflight,
                flow,
                evidence,
                discovery_observation=discovery_observation,
            )
        return PublicCoreRunResult(case, origin, prepared.preflight, flow)
    except (TypeError, ValueError, RuntimeError):
        return PublicCoreRunResult(case, origin, prepared.preflight, None, (), "COMPOSITION_FAILED")
