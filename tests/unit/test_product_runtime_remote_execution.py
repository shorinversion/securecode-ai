"""Remote provider admission at the product-model execution boundary."""

from __future__ import annotations

import json
from typing import cast

import pytest
from securecode_ai.adapters import (
    AuthorizedProviderHarness,
    CredentialLease,
    EndpointAuthorizationIssuer,
    ProviderProfileRegistry,
    parse_provider_profile,
)
from securecode_ai.adapters.model import ConnectedChannel, ProviderAttempt, ProviderAttemptBinding
from securecode_ai.adapters.product_runtime import AuthorizedLocalModelExecutor
from securecode_ai.adapters.product_runtime_contracts import ProviderConnector
from securecode_ai.contracts import (
    DataClass,
    ExecutionBoundary,
    ModelPreflightRequest,
    ModelRequest,
    ProviderProfile,
)
from securecode_ai.core import EgressPolicyRegistry, ModelAuthorizationIssuer

from tests.unit.test_endpoint_policy import ScriptedResolver
from tests.unit.test_provider_preflight import _policy, _profile


class _RemoteConnector:
    def connect(
        self, *, ip_address: str, port: int, server_name: str, timeout_ms: int
    ) -> ConnectedChannel:
        del ip_address, port, server_name, timeout_ms
        raise AssertionError("transport must not run during executor construction")

    def send(
        self,
        channel: ConnectedChannel,
        *,
        credential: str | None,
        payload: bytes,
        model_id: str,
        timeout_ms: int,
        binding: ProviderAttemptBinding,
    ) -> ProviderAttempt:
        del channel, credential, payload, model_id, timeout_ms, binding
        raise AssertionError("transport must not run during executor construction")


def _remote_profile() -> ProviderProfile:
    document = _profile("valid.local-openai-compatible.json").model_dump(mode="json")
    document.update(
        {
            "profile_id": "remote-evaluation",
            "provider_kind": "openai_compatible_remote",
            "execution_boundary": "public_external",
            "credential_ref": "env://REMOTE_EVALUATION_KEY",
            "egress_profiles": ["metadata_external"],
        }
    )
    document["endpoint"] = {
        "base_url": "https://api.example.test/v1",
        "authority": "api.example.test",
        "allowed_ports": [443],
        "follow_redirects": False,
        "local_plaintext_exception": False,
    }
    document["data_terms"].update(
        {
            "evidence_status": "verified",
            "residency": ["policy-selected"],
            "retention_seconds": 0,
            "training_use": "none_verified",
            "zero_data_retention": True,
            "maximum_input_data_class": "DC0_PUBLIC",
            "allowed_purposes": ["evaluation"],
            "evidence_ref": "evidence://provider-terms/remote-evaluation",
        }
    )
    return parse_provider_profile(json.dumps(document, sort_keys=True))


def _preflight(request: ModelRequest) -> ModelPreflightRequest:
    return ModelPreflightRequest(
        schema_version="0.2.0",
        model_request=request,
        required_execution_boundary=ExecutionBoundary.PUBLIC_EXTERNAL,
        required_data_class=DataClass.PUBLIC,
        required_purpose=request.mode,
        planned_transforms=("bounded_repository_view",),
        required_max_bytes=request.budget.max_context_bytes,
    )


def test_remote_executor_requires_a_scoped_credential_supplier() -> None:
    profile = _remote_profile()
    policy = _policy("egress.valid.metadata-external.json")
    registry = ProviderProfileRegistry((profile,))
    issuer = ModelAuthorizationIssuer(
        provider_registry=registry,
        policy_registry=EgressPolicyRegistry((policy,)),
    )
    harness = AuthorizedProviderHarness(
        model_issuer=issuer,
        endpoint_issuer=EndpointAuthorizationIssuer(provider_registry=registry),
    )

    def supplier(_: ProviderProfile) -> CredentialLease:
        return CredentialLease(value="test-credential", profile=profile, registry=registry)

    executor = AuthorizedLocalModelExecutor(
        harness=harness,
        registry=registry,
        profile=profile,
        policy=policy,
        resolver=ScriptedResolver(("1.1.1.1",)),
        connector=cast(ProviderConnector, _RemoteConnector()),
        preflight=_preflight,
        credential_supplier=supplier,
    )

    assert executor._credential_supplier is supplier
    with pytest.raises(ValueError, match="authorized local profile is invalid"):
        AuthorizedLocalModelExecutor(
            harness=harness,
            registry=registry,
            profile=profile,
            policy=policy,
            resolver=ScriptedResolver(("1.1.1.1",)),
            connector=cast(ProviderConnector, _RemoteConnector()),
            preflight=_preflight,
        )
