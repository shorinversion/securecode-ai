"""Public synthetic-Core composition through the existing authorization boundary.

This module composes the existing Core ports. Without an injected transport,
run_public_core_case can invoke the configured local provider. An injected
transport remains SIMULATED; this module never qualifies or admits a provider.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import cast

from securecode_ai.adapters.config import ProviderProfileRegistry
from securecode_ai.adapters.endpoint import EndpointAuthorizationIssuer, Resolver
from securecode_ai.adapters.model import AuthorizedProviderHarness, CredentialSupplier
from securecode_ai.adapters.openai_compatible_local import OpenAICompatibleLocalHttpConnector
from securecode_ai.adapters.openai_compatible_remote import OpenAICompatibleRemoteHttpsConnector
from securecode_ai.adapters.product_model import MODEL_NATIVE_DISCOVERY_WIRE_PIN
from securecode_ai.adapters.product_runtime import (
    PRODUCT_DISCOVERY_PROMPT_PIN,
    AuthorizedLocalModelExecutor,
)
from securecode_ai.adapters.product_runtime_contracts import ProviderConnector
from securecode_ai.adapters.public_core_fixtures import (
    FixtureProvenance,
    PublicCoreFixture,
    build_public_core_fixture,
)
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    DataClass,
    ExecutionBoundary,
    ModelCallBudget,
    ModelPreflightRequest,
    ModelPreflightResult,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    ProducerRef,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.core import EgressPolicyRegistry, ModelAuthorizationIssuer
from securecode_ai.core.investigation import InvestigationBudget

from .local_provider_admission import CoreCase
from .public_core_runner_primitives import (
    PinnedLiteralLoopbackResolver,
    PreparedPublicCoreCase,
    PublicCoreHostInputs,
    _fail,
)


def _request(
    case: CoreCase, fixture: PublicCoreFixture, inputs: PublicCoreHostInputs
) -> ModelRequest:
    try:
        anchors = fixture.catalogue.anchors
        indexes = fixture.catalogue.indexes
        if (
            not anchors
            or not indexes
            or inputs.policy.tenant_scope != anchors[0].tenant_id
            or any(anchor.tenant_id != inputs.policy.tenant_scope for anchor in anchors)
            or len({item.repository_id for item in indexes}) != 1
        ):
            _fail()
        revision = RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=inputs.policy.tenant_scope,
            scm_provider="synthetic-public",
            repository_id=indexes[0].repository_id,
            head_sha=fixture.head_sha,
        )
        identity = RunExecutionIdentity.build(
            repository_revision=revision,
            stage_catalogue=inputs.artifacts.stage_catalogue,
            workflow=inputs.artifacts.workflow,
            policy=inputs.policy_pin,
            configuration=inputs.artifacts.configuration,
            provider_profile=inputs.provider_pin,
            capability_profile=inputs.capability_pin,
            egress_profile=inputs.egress_pin,
        )
        input_tokens = min(3072, inputs.profile.capabilities.max_context_tokens)
        output_tokens = min(1024, inputs.profile.capabilities.max_output_tokens, input_tokens)
        return ModelRequest(
            schema_version=CONTRACT_SCHEMA_VERSION,
            request_id=f"public-discovery-{case.value}",
            run_id=f"public-core-{fixture.head_sha[:16]}",
            tenant_id=inputs.policy.tenant_scope,
            idempotency_key=f"public-discovery-{fixture.head_sha[:16]}",
            attempt=1,
            execution_identity=identity,
            head_sha=fixture.head_sha,
            role=ModelRole.DISCOVERY,
            mode=ModelPurpose.MODEL_NATIVE_DISCOVERY,
            provider_profile=inputs.provider_pin,
            api_dialect=inputs.profile.api_dialect,
            model_id=inputs.profile.model_id,
            prompt=PRODUCT_DISCOVERY_PROMPT_PIN,
            output_schema=MODEL_NATIVE_DISCOVERY_WIRE_PIN,
            tool_policy=inputs.artifacts.tool_policy,
            repository_scope=inputs.artifacts.repository_scope,
            repository_view_policy=inputs.artifacts.repository_view_policy,
            budget=ModelCallBudget(
                schema_version=CONTRACT_SCHEMA_VERSION,
                max_input_tokens=input_tokens,
                max_output_tokens=output_tokens,
                max_repository_calls=4,
                max_context_bytes=1_048_576,
                timeout_ms=min(120_000, inputs.profile.budgets.timeout_seconds * 1000),
            ),
        )
    except (TypeError, ValueError):
        _fail()


def _preflight(inputs: PublicCoreHostInputs, request: ModelRequest) -> ModelPreflightRequest:
    return ModelPreflightRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        model_request=request,
        required_execution_boundary=inputs.profile.execution_boundary,
        required_data_class=DataClass.PUBLIC,
        required_purpose=request.mode,
        planned_transforms=("bounded_repository_view",),
        required_max_bytes=request.budget.max_context_bytes,
    )


def _issuer(inputs: PublicCoreHostInputs) -> ModelAuthorizationIssuer:
    registry = ProviderProfileRegistry((inputs.profile,))
    return ModelAuthorizationIssuer(
        provider_registry=registry,
        policy_registry=EgressPolicyRegistry((inputs.policy,)),
    )


def prepare_public_core_case(
    *, case: CoreCase, inputs: PublicCoreHostInputs
) -> PreparedPublicCoreCase:
    if type(case) is not CoreCase or type(inputs) is not PublicCoreHostInputs:
        _fail()
    try:
        inputs = inputs.snapshot()
        fixture = build_public_core_fixture(case)
        if fixture.provenance is not FixtureProvenance.SYNTHETIC_DEVELOPMENT:
            _fail()
        request = _request(case, fixture, inputs)
        authorization = _issuer(inputs).authorize_pre_context(
            _preflight(inputs, request), profile=inputs.profile, policy=inputs.policy
        )
        return PreparedPublicCoreCase(case, request, fixture, authorization.result)
    except (TypeError, ValueError):
        _fail()


def preflight_public_core_case(
    *, case: CoreCase, inputs: PublicCoreHostInputs
) -> ModelPreflightResult:
    """Evaluate actual profile and policy eligibility without source context or send."""
    return prepare_public_core_case(case=case, inputs=inputs).preflight


def _executor(
    *,
    inputs: PublicCoreHostInputs,
    connector: object,
    native: bool,
    resolver: Resolver | None = None,
    credential_supplier: CredentialSupplier | None = None,
    connector_factory: Callable[..., object] = OpenAICompatibleLocalHttpConnector,
) -> AuthorizedLocalModelExecutor:
    registry = ProviderProfileRegistry((inputs.profile,))
    if connector is None:
        if inputs.profile.execution_boundary is ExecutionBoundary.LOCAL_RUNNER:
            sampling = inputs.diagnostic_sampling if native else None
            connector = connector_factory(
                profile=inputs.profile,
                temperature=None if sampling is None else sampling.temperature,
                seed=None if sampling is None else sampling.seed,
                native_frames=native,
            )
        else:
            connector = OpenAICompatibleRemoteHttpsConnector(profile=inputs.profile)
    if not callable(getattr(connector, "connect", None)) or not callable(
        getattr(connector, "send", None)
    ):
        _fail()
    return AuthorizedLocalModelExecutor(
        harness=AuthorizedProviderHarness(
            model_issuer=_issuer(inputs),
            endpoint_issuer=EndpointAuthorizationIssuer(provider_registry=registry),
        ),
        registry=registry,
        profile=inputs.profile,
        policy=inputs.policy,
        resolver=(
            PinnedLiteralLoopbackResolver(authority="127.0.0.1", port=inputs.gateway_port)
            if resolver is None
            else resolver
        ),
        connector=cast(ProviderConnector, connector),
        preflight=lambda request: _preflight(inputs, request),
        credential_supplier=credential_supplier,
    )


def _investigation_budget(
    inputs: PublicCoreHostInputs, request: ModelRequest
) -> InvestigationBudget:
    return InvestigationBudget(
        inputs.profile.budgets.max_attempts,
        inputs.profile.budgets.max_total_tokens,
        request.budget.max_repository_calls,
        request.budget.timeout_ms,
    )


def _native_producer(inputs: PublicCoreHostInputs, *, simulated: bool) -> ProducerRef:
    source_sha256 = hashlib.sha256(
        Path(__file__).with_name("product_runtime.py").read_bytes()
    ).hexdigest()
    if source_sha256 != inputs.artifacts.producer.content_sha256:
        _fail()
    return ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="securecode-product-native-discovery",
        producer_version="1.0.0",
        producer_sha256=source_sha256,
    )
