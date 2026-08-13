"""Configuration precedence, redaction and credential lease tests for P1.7."""

from __future__ import annotations

import copy
import json
import pickle
from pathlib import Path

import pytest
from securecode_ai.adapters import (
    ConfigDiagnosticCode,
    ConfigError,
    ConfigSource,
    CredentialLease,
    ProviderProfileRegistry,
    parse_provider_profile,
    resolve_configuration,
    resolve_environment_credential,
)
from securecode_ai.contracts import ProviderProfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "specs" / "contracts" / "provider-fixtures"
CANARY = "scai-credential-canary-4f183c"


def _profile(name: str = "valid.remote-openai.json") -> ProviderProfile:
    return parse_provider_profile((FIXTURES / name).read_bytes())


def _registry() -> ProviderProfileRegistry:
    return ProviderProfileRegistry(
        (
            _profile("valid.fake.json"),
            _profile("valid.local-openai-compatible.json"),
            _profile("valid.remote-openai.json"),
        )
    )


def _defaults() -> dict[str, str]:
    return {
        "provider_profile": "fake-hermetic@1.1.0",
        "policy_profile": "advisory-default",
        "egress_profile": "air_gap",
    }


def test_selection_precedence_is_cli_environment_repository_user_defaults() -> None:
    effective = resolve_configuration(
        registry=_registry(),
        defaults=_defaults(),
        user={"policy_profile": "user-policy"},
        repository={"policy_profile": "repository-policy"},
        environment={
            "SECURECODE_POLICY_PROFILE": "environment-policy",
            "OPENAI_API_KEY": CANARY,
        },
        cli={"policy_profile": "cli-policy"},
    )
    assert effective.policy_profile_id == "cli-policy"
    assert effective.provider_profile.selector == "fake-hermetic@1.1.0"
    assert {item.key: item.source for item in effective.provenance} == {
        "egress_profile": ConfigSource.DEFAULTS,
        "policy_profile": ConfigSource.CLI,
        "provider_profile": ConfigSource.DEFAULTS,
    }
    assert CANARY not in json.dumps(effective.safe_snapshot(), sort_keys=True)


def test_environment_can_select_approved_profile_but_not_define_security_fields() -> None:
    effective = resolve_configuration(
        registry=_registry(),
        defaults=_defaults(),
        environment={
            "SECURECODE_PROVIDER_PROFILE": "openai-approved@1.1.0",
            "SECURECODE_EGRESS_PROFILE": "metadata_external",
            "OPENAI_API_KEY": CANARY,
        },
    )
    assert effective.provider_profile.endpoint.base_url == "https://api.openai.com/v1"
    assert effective.egress_profile.value == "metadata_external"

    for forbidden in (
        "SECURECODE_LLM_BASE_URL",
        "SECURECODE_LLM_MODEL",
        "SECURECODE_LLM_API_KEY",
        "SECURECODE_LLM_TIMEOUT_SECONDS",
    ):
        with pytest.raises(ConfigError) as raised:
            resolve_configuration(
                registry=_registry(),
                defaults=_defaults(),
                environment={forbidden: CANARY},
            )
        assert raised.value.diagnostics[0].code is ConfigDiagnosticCode.SECURITY_FIELD_OVERRIDE
        assert CANARY not in str(raised.value)

    with pytest.raises(ConfigError) as case_variant:
        resolve_configuration(
            registry=_registry(),
            defaults=_defaults(),
            environment={"securecode_llm_custom_endpoint": CANARY},
        )
    assert case_variant.value.diagnostics[0].code is ConfigDiagnosticCode.SECURITY_FIELD_OVERRIDE


@pytest.mark.parametrize("source_name", ["user", "repository", "cli"])
@pytest.mark.parametrize(
    "field",
    ["api_key", "endpoint", "model_id", "budgets", "credential_ref", "secret_token"],
)
def test_lower_trust_layers_cannot_inject_secrets_or_provider_security_fields(
    source_name: str, field: str
) -> None:
    arguments: dict[str, object] = {
        "registry": _registry(),
        "defaults": _defaults(),
        source_name: {field: CANARY},
    }
    with pytest.raises(ConfigError) as raised:
        resolve_configuration(**arguments)  # type: ignore[arg-type]
    assert raised.value.diagnostics[0].code is ConfigDiagnosticCode.SECURITY_FIELD_OVERRIDE
    serialized = json.dumps(raised.value.as_dict(), sort_keys=True)
    assert CANARY not in serialized
    assert field not in serialized


def test_unknown_missing_invalid_and_unsupported_selections_fail_closed() -> None:
    cases = (
        ({"unknown": "x"}, ConfigDiagnosticCode.UNKNOWN_CONFIG_KEY),
        ({"policy_profile": " bad "}, ConfigDiagnosticCode.INVALID_CONFIG_VALUE),
    )
    for user, expected in cases:
        with pytest.raises(ConfigError) as raised:
            resolve_configuration(registry=_registry(), defaults=_defaults(), user=user)
        assert raised.value.diagnostics[0].code is expected

    with pytest.raises(ConfigError) as non_string_key:
        resolve_configuration(
            registry=_registry(),
            defaults=_defaults(),
            user={1: "value"},  # type: ignore[dict-item]
        )
    assert non_string_key.value.diagnostics[0].code is ConfigDiagnosticCode.UNKNOWN_CONFIG_KEY

    with pytest.raises(ConfigError) as non_string_selector:
        _registry().select(1)  # type: ignore[arg-type]
    assert (
        non_string_selector.value.diagnostics[0].code is ConfigDiagnosticCode.INVALID_CONFIG_VALUE
    )

    with pytest.raises(ConfigError) as missing:
        resolve_configuration(registry=_registry(), defaults={})
    assert {item.field for item in missing.value.diagnostics} == {
        "provider_profile",
        "policy_profile",
        "egress_profile",
    }

    with pytest.raises(ConfigError) as unknown_profile:
        resolve_configuration(
            registry=_registry(),
            defaults={**_defaults(), "provider_profile": "missing-profile@1.0.0"},
        )
    assert unknown_profile.value.diagnostics[0].code is ConfigDiagnosticCode.UNKNOWN_PROFILE

    with pytest.raises(ConfigError) as unsupported_egress:
        resolve_configuration(
            registry=_registry(),
            defaults={**_defaults(), "egress_profile": "metadata_external"},
        )
    assert (
        unsupported_egress.value.diagnostics[0].code
        is ConfigDiagnosticCode.UNSUPPORTED_EGRESS_PROFILE
    )


def test_precedence_and_configuration_hash_are_mapping_order_independent() -> None:
    first = resolve_configuration(registry=_registry(), defaults=_defaults())
    second = resolve_configuration(
        registry=_registry(), defaults=dict(reversed(tuple(_defaults().items())))
    )
    assert first == second
    assert first.canonical_content_hash() == second.canonical_content_hash()


def test_environment_credential_lease_is_host_bound_redacted_and_zeroizable() -> None:
    profile = _profile()
    lease = resolve_environment_credential(
        profile, {"OPENAI_API_KEY": CANARY}, registry=_registry()
    )
    assert lease is not None
    assert (
        lease.reveal_for(
            profile_selector=profile.selector,
            authority=profile.endpoint.authority,
        )
        == CANARY
    )
    sinks = (
        repr(lease),
        str(lease),
        json.dumps(lease.safe_snapshot(), sort_keys=True),
    )
    assert all(CANARY not in sink for sink in sinks)
    assert all("<redacted>" in sink for sink in sinks)
    with pytest.raises(TypeError):
        pickle.dumps(lease)
    with pytest.raises(TypeError):
        copy.copy(lease)
    with pytest.raises(TypeError):
        copy.deepcopy(lease)
    for field in (
        "authority",
        "profile_selector",
        "reference",
        "_authority",
        "_profile_selector",
        "_reference",
    ):
        with pytest.raises(AttributeError):
            setattr(lease, field, "attacker-controlled")

    for selector, authority in (
        ("other-profile@1.0.0", profile.endpoint.authority),
        (profile.selector, "other.example"),
    ):
        with pytest.raises(ConfigError) as mismatch:
            lease.reveal_for(profile_selector=selector, authority=authority)
        assert mismatch.value.diagnostics[0].code is ConfigDiagnosticCode.CREDENTIAL_SCOPE_MISMATCH
        assert CANARY not in str(mismatch.value)

    lease.close()
    assert all(byte == 0 for byte in lease._buffer)
    with pytest.raises(ConfigError) as closed:
        lease.reveal_for(profile_selector=profile.selector, authority=profile.endpoint.authority)
    assert closed.value.diagnostics[0].code is ConfigDiagnosticCode.CREDENTIAL_CLOSED


@pytest.mark.parametrize(
    "environment",
    [
        {},
        {"OPENAI_API_KEY": ""},
        {"OPENAI_API_KEY": "   "},
        {"OPENAI_API_KEY": "bad\x00secret"},
        {"OPENAI_API_KEY": "bad\nsecret"},
        {"OPENAI_API_KEY": "x" * (64 * 1024 + 1)},
    ],
)
def test_missing_or_invalid_credentials_produce_safe_diagnostics(
    environment: dict[str, str],
) -> None:
    with pytest.raises(ConfigError) as raised:
        resolve_environment_credential(_profile(), environment, registry=_registry())
    rendered = json.dumps(raised.value.as_dict(), sort_keys=True)
    assert "bad" not in rendered
    assert "secret" not in rendered.lower()
    assert "x" * 128 not in rendered


def test_credential_free_and_unavailable_backend_profiles() -> None:
    assert (
        resolve_environment_credential(_profile("valid.fake.json"), {}, registry=_registry())
        is None
    )

    profile = ProviderProfile.model_validate(
        {
            **_profile().model_dump(mode="python"),
            "credential_ref": "secret://prod/openai",
        }
    )
    with pytest.raises(ConfigError) as raised:
        resolve_environment_credential(profile, {}, registry=ProviderProfileRegistry((profile,)))
    assert raised.value.diagnostics[0].code is ConfigDiagnosticCode.UNSUPPORTED_CREDENTIAL_BACKEND

    forged = _profile().model_copy(
        update={"endpoint": _profile().endpoint.model_copy(update={"authority": "other.example"})}
    )
    with pytest.raises(ConfigError) as invalid_profile:
        resolve_environment_credential(forged, {"OPENAI_API_KEY": CANARY}, registry=_registry())
    assert invalid_profile.value.diagnostics[0].code is ConfigDiagnosticCode.INVALID_PROFILE


def test_non_string_environment_credential_fails_with_safe_diagnostic() -> None:
    with pytest.raises(ConfigError) as raised:
        resolve_environment_credential(
            _profile(),
            {"OPENAI_API_KEY": object()},  # type: ignore[dict-item]
            registry=_registry(),
        )
    assert raised.value.diagnostics[0].code is ConfigDiagnosticCode.INVALID_CREDENTIAL


def test_credential_resolution_requires_exact_approved_registry_identity() -> None:
    registry = _registry()
    original = _profile()
    raw = original.model_dump(mode="python")
    raw["profile_id"] = "unregistered-provider"
    endpoint = raw["endpoint"]
    assert isinstance(endpoint, dict)
    endpoint.update({"base_url": "https://evil.example/v1", "authority": "evil.example"})
    unregistered = ProviderProfile.model_validate(raw)

    with pytest.raises(ConfigError) as unknown:
        resolve_environment_credential(unregistered, {"OPENAI_API_KEY": CANARY}, registry=registry)
    assert unknown.value.diagnostics[0].code is ConfigDiagnosticCode.UNKNOWN_PROFILE
    with pytest.raises(ConfigError):
        CredentialLease(value=CANARY, profile=unregistered, registry=registry)

    conflicting = original.model_copy(update={"model_id": "forged-model"})
    with pytest.raises(ConfigError) as conflict:
        resolve_environment_credential(conflicting, {"OPENAI_API_KEY": CANARY}, registry=registry)
    assert conflict.value.diagnostics[0].code is ConfigDiagnosticCode.IMMUTABLE_PROFILE_CONFLICT


def test_context_manager_closes_credential_after_use() -> None:
    profile = _profile()
    lease = resolve_environment_credential(
        profile, {"OPENAI_API_KEY": CANARY}, registry=_registry()
    )
    assert lease is not None
    with lease as active:
        assert (
            active.reveal_for(
                profile_selector=profile.selector,
                authority=profile.endpoint.authority,
            )
            == CANARY
        )
    assert lease.safe_snapshot()["closed"] is True
    assert all(byte == 0 for byte in lease._buffer)
