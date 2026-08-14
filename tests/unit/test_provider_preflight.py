"""Joint provider/egress preflight and permit tests for P1.8."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import cast

import pytest
import yaml  # type: ignore[import-untyped]
from pydantic import ValidationError
from securecode_ai.adapters import ProviderProfileRegistry, parse_provider_profile
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ApiDialect,
    AuditRunOutcome,
    ComponentPin,
    DataClass,
    EgressContentRef,
    EgressManifest,
    EgressPolicyDocument,
    ExecutionBoundary,
    ModelCallBudget,
    ModelPreflightRequest,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.core import (
    AuthorizationError,
    EgressPolicyRegistry,
    ModelAuthorizationIssuer,
    PreflightEligibility,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "specs" / "contracts"
PROVIDERS = CONTRACTS / "provider-fixtures"
POLICIES = CONTRACTS / "policy" / "fixtures"
SHA = "a" * 64
HEAD = "1" * 40


def _pin(identifier: str, version: str, digest: str) -> ComponentPin:
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=identifier,
        component_version=version,
        content_sha256=digest,
    )


def _profile(name: str):  # type: ignore[no-untyped-def]
    return parse_provider_profile((PROVIDERS / name).read_bytes())


def _policy(name: str) -> EgressPolicyDocument:
    return EgressPolicyDocument.model_validate_json((POLICIES / name).read_bytes())


def _request(profile, policy: EgressPolicyDocument, mode: ModelPurpose) -> ModelRequest:  # type: ignore[no-untyped-def]
    provider_pin = _pin(
        profile.profile_id, profile.profile_version, profile.canonical_content_hash()
    )
    policy_pin = _pin(policy.policy_id, policy.policy_version, policy.canonical_content_hash())
    egress_pin = _pin(policy.profile.value, policy.policy_version, policy.canonical_content_hash())
    identity = RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=policy.tenant_scope,
            scm_provider="github",
            repository_id="repo-a",
            head_sha=HEAD,
        ),
        stage_catalogue=_pin("stages", "1.0.0", SHA),
        workflow=_pin("workflow", "1.0.0", SHA),
        policy=policy_pin,
        configuration=_pin("config", "1.0.0", SHA),
        provider_profile=provider_pin,
        capability_profile=_pin("capabilities", "1.0.0", SHA),
        egress_profile=egress_pin,
    )
    return ModelRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        request_id="request-1",
        run_id="run-1",
        tenant_id=policy.tenant_scope,
        idempotency_key="idem-1",
        attempt=1,
        execution_identity=identity,
        head_sha=HEAD,
        role=ModelRole.DISCOVERY,
        mode=mode,
        provider_profile=provider_pin,
        api_dialect=profile.api_dialect,
        model_id=profile.model_id,
        prompt=_pin("prompt", "1.0.0", SHA),
        output_schema=_pin("discovery-output", "1.0.0", SHA),
        tool_policy=_pin("repository-tools", "1.0.0", SHA),
        repository_scope=_pin("repository-scope", "1.0.0", SHA),
        repository_view_policy=_pin("repository-view", "1.0.0", SHA),
        budget=ModelCallBudget(
            schema_version=CONTRACT_SCHEMA_VERSION,
            max_input_tokens=3072,
            max_output_tokens=1024,
            max_repository_calls=8,
            max_context_bytes=65536,
            timeout_ms=5000,
        ),
    )


def _issuer(profile, policy: EgressPolicyDocument) -> ModelAuthorizationIssuer:  # type: ignore[no-untyped-def]
    return ModelAuthorizationIssuer(
        provider_registry=ProviderProfileRegistry((profile,)),
        policy_registry=EgressPolicyRegistry((policy,)),
    )


def _preflight_request(request: ModelRequest, case: dict[str, object]) -> ModelPreflightRequest:
    return ModelPreflightRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        model_request=request,
        required_execution_boundary=ExecutionBoundary(str(case["required_execution_boundary"])),
        required_data_class=DataClass(str(case["required_data_class"])),
        required_purpose=ModelPurpose(str(case["required_purpose"])),
        planned_transforms=tuple(case["planned_transforms"]),  # type: ignore[arg-type]
        required_max_bytes=int(str(case["required_max_bytes"])),
    )


def _semantic_cases() -> list[dict[str, object]]:
    document = yaml.safe_load((CONTRACTS / "provider-profile.fixtures.yaml").read_text())
    return cast(list[dict[str, object]], document["semantic_cases"])


@pytest.mark.parametrize("case", _semantic_cases(), ids=lambda case: str(case["id"]))
def test_accepted_provider_egress_semantic_cases_match_g0(case: dict[str, object]) -> None:
    profile = _profile(str(case["provider_instance"]).split("/")[-1])
    policy = _policy(str(case["egress_instance"]).split("/")[-1])
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    authorization = _issuer(profile, policy).authorize_pre_context(
        _preflight_request(request, case), profile=profile, policy=policy
    )
    assert authorization.result.normative_snapshot() == case["expect"]


@pytest.mark.parametrize(
    ("name", "valid"),
    [
        ("egress.valid.air-gap.json", True),
        ("egress.valid.metadata-external.json", True),
        ("egress.valid.private-model-source.json", True),
        ("egress.invalid.air-gap-allow.json", False),
        ("egress.invalid.dc4-allow.json", False),
        ("egress.invalid.no-code-dc3.json", False),
    ],
)
def test_every_accepted_egress_fixture_has_contract_parity(name: str, valid: bool) -> None:
    encoded = (POLICIES / name).read_bytes()
    if valid:
        policy = EgressPolicyDocument.model_validate_json(encoded)
        assert policy.canonical_content_hash()
    else:
        with pytest.raises(ValidationError):
            EgressPolicyDocument.model_validate_json(encoded)


def test_profile_owned_budget_attempt_and_dialect_limits_fail_before_context() -> None:
    case = _semantic_cases()[0]
    profile = _profile("valid.local-openai-compatible.json")
    policy = _policy("egress.valid.private-model-source.json")
    base = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    expected = {
        "eligibility": "ineligible",
        "preflight_context_bytes": 0,
        "preflight_network_bytes": 0,
        "next_action": "STOP_BEFORE_CONTEXT_OR_NETWORK",
        "deterministic_only_fallback": False,
        "audit_run_outcome": "INDETERMINATE",
    }
    budgets = (
        base.budget.model_copy(update={"max_input_tokens": 32769, "max_output_tokens": 1}),
        base.budget.model_copy(update={"max_input_tokens": 8192, "max_output_tokens": 4097}),
        base.budget.model_copy(update={"max_input_tokens": 30000, "max_output_tokens": 4000}),
        base.budget.model_copy(update={"timeout_ms": 60001}),
    )
    mutations = [base.model_copy(update={"budget": budget}) for budget in budgets]
    mutations.extend(
        (
            base.model_copy(update={"attempt": profile.budgets.max_attempts + 1}),
            base.model_copy(update={"api_dialect": ApiDialect.FAKE}),
        )
    )
    for request in mutations:
        result = _issuer(profile, policy).authorize_pre_context(
            _preflight_request(request, case), profile=profile, policy=policy
        )
        assert result.result.normative_snapshot() == expected


def test_equivalent_allow_rules_compose_without_fail_closed_ambiguity() -> None:
    case = _semantic_cases()[0]
    profile = _profile("valid.local-openai-compatible.json")
    data = _policy("egress.valid.private-model-source.json").model_dump(mode="json")
    equivalent = copy.deepcopy(data["rules"][0])
    equivalent["rule_id"] = "EGR-EQUIVALENT-ALLOW"
    equivalent["max_bytes"] += 1024
    data["rules"].append(equivalent)
    policy = EgressPolicyDocument.model_validate_json(json.dumps(data, sort_keys=True))
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    result = _issuer(profile, policy).authorize_pre_context(
        _preflight_request(request, case), profile=profile, policy=policy
    )
    assert result.result.eligibility is PreflightEligibility.ELIGIBLE


def test_preflight_capability_and_policy_mutations_fail_exactly() -> None:
    case = _semantic_cases()[0]
    base_profile = _profile("valid.local-openai-compatible.json")
    base_policy = _policy("egress.valid.private-model-source.json")
    profile_mutations = (
        ("structured_output", False),
        ("native_refusal_signal", False),
        ("native_incomplete_signal", False),
        ("source_code_analysis", False),
        ("repository_tool_calls", False),
    )
    expected = {
        "eligibility": "ineligible",
        "preflight_context_bytes": 0,
        "preflight_network_bytes": 0,
        "next_action": "STOP_BEFORE_CONTEXT_OR_NETWORK",
        "deterministic_only_fallback": False,
        "audit_run_outcome": "INDETERMINATE",
    }
    for field, value in profile_mutations:
        data = base_profile.model_dump(mode="json")
        data["capabilities"][field] = value
        if field == "repository_tool_calls":
            data["capabilities"]["repository_tools"] = []
        mutated = type(base_profile).model_validate(data)
        request = _request(mutated, base_policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
        result = _issuer(mutated, base_policy).authorize_pre_context(
            _preflight_request(request, case), profile=mutated, policy=base_policy
        )
        assert result.result.normative_snapshot() == expected

    for mutate in ("no-rules", "wrong-transform", "superset-transform", "matching-deny"):
        data = base_policy.model_dump(mode="json")
        if mutate == "no-rules":
            data["rules"] = []
        elif mutate == "wrong-transform":
            data["rules"][0]["requires_transforms"] = ["wrong_transform"]
        elif mutate == "superset-transform":
            data["rules"][0]["requires_transforms"] = [
                "bounded_repository_view",
                "secret_redaction",
            ]
        else:
            deny = copy.deepcopy(data["rules"][0])
            deny.update({"rule_id": "EGR-EXACT-DENY", "effect": "deny"})
            data["rules"].append(deny)
        policy = EgressPolicyDocument.model_validate_json(json.dumps(data, sort_keys=True))
        request = _request(base_profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
        result = _issuer(base_profile, policy).authorize_pre_context(
            _preflight_request(request, case), profile=base_profile, policy=policy
        )
        assert result.result.normative_snapshot() == expected


@pytest.mark.parametrize(
    "mutation",
    [
        {"residency": []},
        {"retention_seconds": None},
        {"retention_seconds": 999999},
        {"training_use": "unknown"},
        {"training_use": "provider_declared"},
        {"zero_data_retention": False},
        {"evidence_ref": None},
    ],
)
def test_verified_private_zdr_terms_must_be_complete_and_consistent(
    mutation: dict[str, object],
) -> None:
    case = _semantic_cases()[0]
    base_profile = _profile("valid.local-openai-compatible.json")
    policy = _policy("egress.valid.private-model-source.json")
    profile_data = base_profile.model_dump(mode="json")
    profile_data["data_terms"].update(
        {
            "evidence_status": "verified",
            "residency": ["tenant-region"],
            "retention_seconds": 0,
            "training_use": "none_verified",
            "zero_data_retention": True,
            "evidence_ref": "evidence://provider-terms/verified-private-zdr",
        }
    )
    profile_data["data_terms"].update(mutation)
    profile = type(base_profile).model_validate(profile_data)
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    result = _issuer(profile, policy).authorize_pre_context(
        _preflight_request(request, case), profile=profile, policy=policy
    )
    assert result.result.normative_snapshot() == {
        "eligibility": "ineligible",
        "preflight_context_bytes": 0,
        "preflight_network_bytes": 0,
        "next_action": "STOP_BEFORE_CONTEXT_OR_NETWORK",
        "deterministic_only_fallback": False,
        "audit_run_outcome": "INDETERMINATE",
    }


def test_remote_profile_cannot_claim_local_data_terms_exemption() -> None:
    case = dict(_semantic_cases()[0])
    base_profile = _profile("valid.local-openai-compatible.json")
    policy = _policy("egress.valid.private-model-source.json")
    data = base_profile.model_dump(mode="json")
    data.update(
        {
            "profile_id": "remote-local-exemption",
            "provider_kind": "openai_compatible_remote",
            "execution_boundary": "private_tenant_endpoint",
            "credential_ref": "env://REMOTE_LOCAL_EXEMPTION_KEY",
            "endpoint": {
                "base_url": "https://models.example.com/v1",
                "authority": "models.example.com",
                "allowed_ports": [443],
                "follow_redirects": False,
                "local_plaintext_exception": False,
            },
        }
    )
    data["data_terms"].update(
        {
            "evidence_status": "not_applicable_local",
            "residency": [],
            "retention_seconds": None,
            "training_use": "not_applicable_local",
            "zero_data_retention": None,
            "evidence_ref": None,
        }
    )
    profile = type(base_profile).model_validate(data)
    case["required_execution_boundary"] = profile.execution_boundary.value
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    result = _issuer(profile, policy).authorize_pre_context(
        _preflight_request(request, case), profile=profile, policy=policy
    )
    assert result.result.normative_snapshot() == {
        "eligibility": "ineligible",
        "preflight_context_bytes": 0,
        "preflight_network_bytes": 0,
        "next_action": "STOP_BEFORE_CONTEXT_OR_NETWORK",
        "deterministic_only_fallback": False,
        "audit_run_outcome": "INDETERMINATE",
    }


def test_policy_registry_uses_canonical_bytes_and_rejects_conflicts() -> None:
    policy = _policy("egress.valid.private-model-source.json")
    registry = EgressPolicyRegistry((policy,))
    selected = registry.select(policy.selector)
    selected.__dict__["tenant_scope"] = "attacker"
    assert registry.select(policy.selector).tenant_scope == "tenant-fixture"
    with pytest.raises(AuthorizationError):
        registry.require_registered(selected)

    data = policy.model_dump(mode="json")
    data["rules"][0]["max_bytes"] += 1
    with pytest.raises(AuthorizationError):
        EgressPolicyRegistry(
            (policy, EgressPolicyDocument.model_validate_json(json.dumps(data, sort_keys=True)))
        )


def test_pre_send_binds_actual_manifest_and_consumes_preflight_once() -> None:
    case = _semantic_cases()[0]
    profile = _profile("valid.local-openai-compatible.json")
    policy = _policy("egress.valid.private-model-source.json")
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    issuer = _issuer(profile, policy)
    pre = issuer.authorize_pre_context(
        _preflight_request(request, case), profile=profile, policy=policy
    )
    manifest = EgressManifest.build(
        model_request=request,
        policy=request.execution_identity.policy,
        destination=f"profile://{profile.profile_id}",
        payload_content_id="kid:opaque-payload-1",
        content=(
            EgressContentRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                content_id="kid:opaque-keyed-1",
                data_class=DataClass.CONFIDENTIAL_SOURCE,
            ),
        ),
        applied_transforms=("bounded_repository_view",),
        byte_count=4096,
    )
    send = issuer.authorize_pre_send(pre, manifest)
    assert send.manifest_hash == manifest.manifest_sha256
    assert manifest.execution_identity_hash == request.execution_identity.execution_identity_hash
    with pytest.raises(AuthorizationError):
        issuer.authorize_pre_send(pre, manifest)
    with pytest.raises(TypeError):
        copy.copy(send)
    with pytest.raises(TypeError):
        copy.deepcopy(pre)
    with pytest.raises(TypeError):
        copy.deepcopy(send)
    with pytest.raises(AttributeError, match="immutable"):
        pre._max_bytes = 999999999
    with pytest.raises(AttributeError, match="immutable"):
        send._request_hash = "0" * 64


def test_pre_send_rejects_validly_hashed_manifest_with_wrong_execution_identity() -> None:
    case = _semantic_cases()[0]
    profile = _profile("valid.local-openai-compatible.json")
    policy = _policy("egress.valid.private-model-source.json")
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    issuer = _issuer(profile, policy)
    pre = issuer.authorize_pre_context(
        _preflight_request(request, case), profile=profile, policy=policy
    )
    substituted_identity = request.execution_identity.model_copy(
        update={"execution_identity_hash": "0" * 64}
    )
    substituted_request = request.model_copy(update={"execution_identity": substituted_identity})
    manifest = EgressManifest.build(
        model_request=substituted_request,
        policy=request.execution_identity.policy,
        destination=f"profile://{profile.profile_id}",
        payload_content_id="kid:wrong-execution-identity",
        content=(
            EgressContentRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                content_id="kid:wrong-execution-source",
                data_class=DataClass.CONFIDENTIAL_SOURCE,
            ),
        ),
        applied_transforms=("bounded_repository_view",),
        byte_count=1024,
    )
    with pytest.raises(AuthorizationError, match="EGRESS_MANIFEST_SCOPE_MISMATCH"):
        issuer.authorize_pre_send(pre, manifest)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_id", "request-substituted"),
        ("run_id", "run-substituted"),
        ("tenant_id", "tenant-substituted"),
        ("idempotency_key", "idem-substituted"),
        ("attempt", 2),
    ],
)
def test_pre_send_rejects_manifest_request_scope_substitution(field: str, value: str | int) -> None:
    case = _semantic_cases()[0]
    profile = _profile("valid.local-openai-compatible.json")
    policy = _policy("egress.valid.private-model-source.json")
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    issuer = _issuer(profile, policy)
    pre = issuer.authorize_pre_context(
        _preflight_request(request, case), profile=profile, policy=policy
    )
    substituted = request.model_copy(update={field: value})
    manifest = EgressManifest.build(
        model_request=substituted,
        policy=request.execution_identity.policy,
        destination=f"profile://{profile.profile_id}",
        payload_content_id="kid:opaque-payload-substitution",
        content=(
            EgressContentRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                content_id="kid:opaque-keyed-substitution",
                data_class=DataClass.CONFIDENTIAL_SOURCE,
            ),
        ),
        applied_transforms=("bounded_repository_view",),
        byte_count=4096,
    )
    with pytest.raises(AuthorizationError, match="EGRESS_MANIFEST_SCOPE_MISMATCH"):
        issuer.authorize_pre_send(pre, manifest)


@pytest.mark.parametrize(
    ("transforms", "byte_count", "data_class"),
    [
        ((), 4096, DataClass.CONFIDENTIAL_SOURCE),
        (("bounded_repository_view", "secret_redaction"), 4096, DataClass.CONFIDENTIAL_SOURCE),
        (("bounded_repository_view",), 65537, DataClass.CONFIDENTIAL_SOURCE),
        (("bounded_repository_view",), 4096, DataClass.RESTRICTED),
    ],
)
def test_pre_send_rejects_actual_drift_before_network(
    transforms: tuple[str, ...], byte_count: int, data_class: DataClass
) -> None:
    case = _semantic_cases()[0]
    profile = _profile("valid.local-openai-compatible.json")
    policy = _policy("egress.valid.private-model-source.json")
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    issuer = _issuer(profile, policy)
    pre = issuer.authorize_pre_context(
        _preflight_request(request, case), profile=profile, policy=policy
    )
    try:
        content = (
            EgressContentRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                content_id="kid:opaque-keyed-1",
                data_class=data_class,
            ),
        )
        manifest = EgressManifest.build(
            model_request=request,
            policy=request.execution_identity.policy,
            destination=f"profile://{profile.profile_id}",
            payload_content_id="kid:opaque-payload-mutation",
            content=content,
            applied_transforms=transforms,
            byte_count=byte_count,
        )
    except ValidationError:
        return
    with pytest.raises(AuthorizationError):
        issuer.authorize_pre_send(pre, manifest)


def test_forged_or_cross_issuer_authorization_rejects() -> None:
    case = _semantic_cases()[0]
    profile = _profile("valid.local-openai-compatible.json")
    policy = _policy("egress.valid.private-model-source.json")
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    first = _issuer(profile, policy)
    second = _issuer(profile, policy)
    pre = first.authorize_pre_context(
        _preflight_request(request, case), profile=profile, policy=policy
    )
    manifest = EgressManifest.build(
        model_request=request,
        policy=request.execution_identity.policy,
        destination=f"profile://{profile.profile_id}",
        payload_content_id="kid:opaque-payload-1",
        content=(
            EgressContentRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                content_id="kid:opaque-keyed-1",
                data_class=DataClass.CONFIDENTIAL_SOURCE,
            ),
        ),
        applied_transforms=("bounded_repository_view",),
        byte_count=1024,
    )
    with pytest.raises(AuthorizationError):
        second.authorize_pre_send(pre, manifest)
    assert pre.result.required_terminal_outcome is None
    assert pre.result.eligibility is PreflightEligibility.ELIGIBLE
    assert AuditRunOutcome.INDETERMINATE.value == "INDETERMINATE"
