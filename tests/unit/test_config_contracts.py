"""Provider-profile contract and static endpoint security tests for P1.7."""

from __future__ import annotations

import json
import traceback
from pathlib import Path

import pytest
from pydantic import ValidationError
from securecode_ai.adapters import (
    ConfigDiagnosticCode,
    ConfigError,
    ProviderProfileRegistry,
    parse_provider_profile,
)
from securecode_ai.contracts import ProviderProfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "specs" / "contracts" / "provider-fixtures"


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _profile_dict(name: str = "valid.remote-openai.json") -> dict[str, object]:
    value = json.loads(_fixture(name))
    assert isinstance(value, dict)
    return value


@pytest.mark.parametrize(
    "name",
    ["valid.fake.json", "valid.local-openai-compatible.json", "valid.remote-openai.json"],
)
def test_every_normative_valid_provider_fixture_loads(name: str) -> None:
    profile = parse_provider_profile(_fixture(name))
    assert profile.schema_version == "0.2.0"
    assert len(profile.canonical_content_hash()) == 64
    assert profile.credential_ref is None or "://" in profile.credential_ref


@pytest.mark.parametrize("name", ["invalid.remote-http.json", "invalid.fake-credential.json"])
def test_every_normative_invalid_provider_fixture_fails_closed(name: str) -> None:
    canary = _fixture(name)
    with pytest.raises(ConfigError) as raised:
        parse_provider_profile(canary)
    assert raised.value.diagnostics[0].code is ConfigDiagnosticCode.INVALID_PROFILE
    assert canary.decode("utf-8") not in str(raised.value)


def test_profile_parser_rejects_duplicate_unknown_and_oversized_input_without_echo() -> None:
    duplicate = b'{"schema_version":"0.2.0","schema_version":"9.9.9"}'
    unknown = _profile_dict()
    unknown["api_key"] = "credential-canary"
    for payload in (duplicate, json.dumps(unknown), b"x" * (1024 * 1024 + 1)):
        with pytest.raises(ConfigError) as raised:
            parse_provider_profile(payload)
        rendered = json.dumps(raised.value.as_dict(), sort_keys=True)
        assert "credential-canary" not in rendered
        assert "provider profile failed closed validation" in rendered

    secret_bearing = json.dumps(unknown)
    try:
        parse_provider_profile(secret_bearing)
    except ConfigError as error:
        rendered_traceback = "".join(traceback.format_exception(error))
    else:  # pragma: no cover - the assertion above requires rejection
        raise AssertionError("secret-bearing profile unexpectedly passed")
    assert "credential-canary" not in rendered_traceback


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("endpoint", "allowed_ports"), ["443"]),
        (("endpoint", "follow_redirects"), 0),
        (("capabilities", "max_context_tokens"), "100000"),
        (("capabilities", "structured_output"), 1),
        (("budgets", "timeout_seconds"), "60"),
        (("data_terms", "retention_seconds"), "0"),
    ],
)
def test_profile_scalars_do_not_coerce_across_json_types(
    path: tuple[str, ...], value: object
) -> None:
    profile = _profile_dict()
    target: dict[str, object] = profile
    for part in path[:-1]:
        nested = target[part]
        assert isinstance(nested, dict)
        target = nested
    target[path[-1]] = value
    with pytest.raises(ConfigError):
        parse_provider_profile(json.dumps(profile))


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("endpoint", "base_url"), "http://api.openai.com/v1"),
        (("endpoint", "base_url"), "HTTPS://api.openai.com/v1"),
        (("endpoint", "base_url"), "https://user:pass@api.openai.com/v1"),
        (("endpoint", "base_url"), "https://api.openai.com/v1?token=x"),
        (("endpoint", "base_url"), "https://api.openai.com/v1#fragment"),
        (("endpoint", "authority"), "other.example"),
        (("endpoint", "allowed_ports"), [8443]),
        (("endpoint", "follow_redirects"), True),
        (("endpoint", "local_plaintext_exception"), True),
        (("provider_kind",), "anthropic"),
        (("api_dialect",), "anthropic_messages"),
    ],
)
def test_remote_endpoint_and_provider_mutations_fail_before_io(
    path: tuple[str, ...], value: object
) -> None:
    profile = _profile_dict()
    target: dict[str, object] = profile
    for part in path[:-1]:
        nested = target[part]
        assert isinstance(nested, dict)
        target = nested
    target[path[-1]] = value
    with pytest.raises(ConfigError):
        parse_provider_profile(json.dumps(profile))


@pytest.mark.parametrize(
    ("base_url", "authority"),
    [
        ("https://127.0.0.1/v1", "127.0.0.1"),
        ("https://169.254.169.254/v1", "169.254.169.254"),
        ("https://10.0.0.1/v1", "10.0.0.1"),
        ("https://chatgpt.com/backend-api", "chatgpt.com"),
        ("https://chat.openai.com/backend-api", "chat.openai.com"),
        ("https://platform.openai.com/api", "platform.openai.com"),
        ("https://subdomain.claude.ai/api", "subdomain.claude.ai"),
        ("https://console.anthropic.com/api", "console.anthropic.com"),
        ("https://aistudio.google.com/api", "aistudio.google.com"),
        ("https://copilot.github.com/api", "copilot.github.com"),
        ("https://copilot.microsoft.com/api", "copilot.microsoft.com"),
    ],
)
def test_remote_literal_special_ips_and_consumer_products_reject(
    base_url: str, authority: str
) -> None:
    profile = _profile_dict()
    endpoint = profile["endpoint"]
    assert isinstance(endpoint, dict)
    endpoint.update({"base_url": base_url, "authority": authority})
    with pytest.raises(ConfigError):
        parse_provider_profile(json.dumps(profile))


@pytest.mark.parametrize(
    ("base_url", "authority", "local_exception"),
    [
        ("http://10.0.0.2:11434/v1", "10.0.0.2", True),
        ("http://localhost:11434/v1", "localhost", True),
        ("http://127.0.0.1:11434/v1", "127.0.0.1", False),
    ],
)
def test_local_plaintext_requires_exact_loopback_profile(
    base_url: str, authority: str, local_exception: bool
) -> None:
    profile = _profile_dict("valid.local-openai-compatible.json")
    endpoint = profile["endpoint"]
    assert isinstance(endpoint, dict)
    endpoint.update(
        {
            "base_url": base_url,
            "authority": authority,
            "local_plaintext_exception": local_exception,
        }
    )
    with pytest.raises(ConfigError):
        parse_provider_profile(json.dumps(profile))


def test_repository_tool_capability_is_closed_and_bounded() -> None:
    profile = _profile_dict("valid.local-openai-compatible.json")
    capabilities = profile["capabilities"]
    assert isinstance(capabilities, dict)
    capabilities["repository_tools"] = ["read_range"]
    with pytest.raises(ConfigError):
        parse_provider_profile(json.dumps(profile))


@pytest.mark.parametrize(
    "credential_ref",
    ["env://NOT/AN/ENV", "env://1STARTS_WITH_DIGIT", "secret://prod/../openai"],
)
def test_credential_reference_names_are_bounded_for_their_backend(
    credential_ref: str,
) -> None:
    profile = _profile_dict()
    profile["credential_ref"] = credential_ref
    with pytest.raises(ConfigError):
        parse_provider_profile(json.dumps(profile))

    profile = _profile_dict()
    capabilities = profile["capabilities"]
    assert isinstance(capabilities, dict)
    capabilities["max_output_tokens"] = 200000
    with pytest.raises(ConfigError):
        parse_provider_profile(json.dumps(profile))


def test_profile_is_immutable_and_canonicalizes_set_like_fields() -> None:
    raw = _profile_dict("valid.fake.json")
    capabilities = raw["capabilities"]
    assert isinstance(capabilities, dict)
    capabilities["repository_tools"] = list(reversed(capabilities["repository_tools"]))
    egress_profiles = raw["egress_profiles"]
    assert isinstance(egress_profiles, list)
    raw["egress_profiles"] = list(reversed(egress_profiles))
    reordered = parse_provider_profile(json.dumps(raw))
    canonical = parse_provider_profile(_fixture("valid.fake.json"))
    assert reordered == canonical
    assert reordered.canonical_content_hash() == canonical.canonical_content_hash()
    with pytest.raises(ValidationError):
        ProviderProfile.model_validate({**canonical.model_dump(mode="python"), "unknown": 1})
    with pytest.raises(ValidationError):
        canonical.model_id = "mutated"


def test_registry_revalidates_profiles_and_rejects_content_conflicting_version() -> None:
    original = parse_provider_profile(_fixture("valid.remote-openai.json"))
    same = ProviderProfile.model_validate(original.model_dump(mode="python"))
    registry = ProviderProfileRegistry((original, same))
    assert registry.select(original.selector) == original
    assert registry.safe_inventory()[0]["content_sha256"] == original.canonical_content_hash()

    conflict = original.model_copy(update={"model_id": "different-approved-model"})
    with pytest.raises(ConfigError) as raised:
        ProviderProfileRegistry((original, conflict))
    assert raised.value.diagnostics[0].code is ConfigDiagnosticCode.IMMUTABLE_PROFILE_CONFLICT

    forged = original.model_copy(update={"credential_ref": None})
    with pytest.raises(ConfigError) as forged_error:
        ProviderProfileRegistry((forged,))
    assert forged_error.value.diagnostics[0].code is ConfigDiagnosticCode.INVALID_PROFILE

    with pytest.raises(TypeError):
        registry._profiles["attacker@1.0.0"] = original  # type: ignore[index]
    for field in ("_profiles", "_hashes"):
        with pytest.raises(AttributeError):
            setattr(registry, field, {})

    selected = registry.select(original.selector)
    selected.__dict__["model_id"] = "attacker-model"
    selected.endpoint.__dict__["base_url"] = "https://evil.example/v1"
    selected.endpoint.__dict__["authority"] = "evil.example"
    pristine = registry.select(original.selector)
    assert pristine.model_id == original.model_id
    assert pristine.endpoint.authority == original.endpoint.authority


def test_profile_hash_mutates_for_every_execution_semantic_component() -> None:
    original = parse_provider_profile(_fixture("valid.remote-openai.json"))
    mutations = (
        original.model_copy(update={"model_id": "other-model"}),
        original.model_copy(
            update={"budgets": original.budgets.model_copy(update={"timeout_seconds": 61})}
        ),
        original.model_copy(
            update={
                "capabilities": original.capabilities.model_copy(
                    update={"max_context_tokens": 100001}
                )
            }
        ),
        original.model_copy(update={"credential_ref": "env://OTHER_API_KEY"}),
    )
    assert all(
        mutation.canonical_content_hash() != original.canonical_content_hash()
        for mutation in mutations
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", None),
        ("profile_id", "ABC"),
        ("profile_id", "a"),
        ("profile_id", "abc:def"),
        ("profile_id", "a" * 100),
    ],
)
def test_frozen_provider_wire_rejects_schema_and_profile_id_drift(
    field: str, value: object
) -> None:
    profile = _profile_dict()
    if value is None:
        del profile[field]
    else:
        profile[field] = value
    with pytest.raises(ConfigError):
        parse_provider_profile(json.dumps(profile))


def test_provider_wire_rejects_restricted_input_data_class() -> None:
    profile = _profile_dict()
    terms = profile["data_terms"]
    assert isinstance(terms, dict)
    terms["maximum_input_data_class"] = "DC4_RESTRICTED"
    with pytest.raises(ConfigError):
        parse_provider_profile(json.dumps(profile))


def test_frozen_provider_wire_accepts_64_character_profile_id() -> None:
    profile = _profile_dict()
    profile["profile_id"] = "a" * 64
    parsed = parse_provider_profile(json.dumps(profile))
    assert parsed.profile_id == "a" * 64
