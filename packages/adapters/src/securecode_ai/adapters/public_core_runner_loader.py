"""Public synthetic-Core composition through the existing authorization boundary.

This module composes the existing Core ports. Without an injected transport,
run_public_core_case can invoke the configured local provider. An injected
transport remains SIMULATED; this module never qualifies or admits a provider.
"""

from __future__ import annotations

from dataclasses import replace

from securecode_ai.adapters.config import parse_provider_profile
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    EgressPolicyDocument,
)

from .public_core_runner_primitives import (
    _MAX_ARTIFACT_BYTES,
    PublicCoreArtifactPins,
    PublicCoreHostInputs,
    _decode_artifacts,
    _diagnostic_sampling,
    _fail,
)


def _validated_artifacts(
    policy: EgressPolicyDocument, decoded: dict[str, bytes]
) -> PublicCoreArtifactPins:
    artifacts = PublicCoreArtifactPins.from_bytes(**decoded)
    policy_pin = ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=policy.policy_id,
        component_version=policy.policy_version,
        content_sha256=policy.canonical_content_hash(),
    )
    if artifacts.policy.content_sha256 != policy_pin.content_sha256:
        _fail()
    return replace(artifacts, policy=policy_pin)


def load_public_core_inputs(
    *, profile_bytes: bytes, policy_bytes: bytes, artifacts_bytes: bytes, gateway_port: int = 11435
) -> PublicCoreHostInputs:
    """Parse actual host bytes and bind them before any fixture context is available."""
    try:
        if (
            type(profile_bytes) is not bytes
            or type(policy_bytes) is not bytes
            or not profile_bytes
            or not policy_bytes
            or len(profile_bytes) > _MAX_ARTIFACT_BYTES
            or len(policy_bytes) > _MAX_ARTIFACT_BYTES
        ):
            _fail()
        profile = parse_provider_profile(profile_bytes)
        policy = EgressPolicyDocument.model_validate_json(policy_bytes)
        decoded = _decode_artifacts(artifacts_bytes)
        return PublicCoreHostInputs(
            profile=profile,
            policy=policy,
            artifacts=_validated_artifacts(policy, decoded),
            diagnostic_sampling=_diagnostic_sampling(
                decoded["configuration"],
                profile,
                ComponentPin(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    component_id=profile.profile_id,
                    component_version=profile.profile_version,
                    content_sha256=profile.canonical_content_hash(),
                ),
            ),
            gateway_port=gateway_port,
            _profile_bytes=profile_bytes,
            _policy_bytes=policy_bytes,
            _configuration_bytes=decoded["configuration"],
            _artifacts_bytes=artifacts_bytes,
        )
    except (TypeError, ValueError):
        _fail()
