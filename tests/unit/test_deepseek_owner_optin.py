"""Explicit owner consent permits only the scoped DeepSeek opt-in profile."""

import json

import pytest
from securecode_ai.adapters import parse_provider_profile
from securecode_ai.contracts import EgressPolicyDocument, ModelPurpose

from tests.unit.test_provider_preflight import (
    _issuer,
    _policy,
    _preflight_request,
    _profile,
    _request,
)


@pytest.mark.parametrize(
    "change,allowed",
    [
        ("none", True),
        ("approval", False),
        ("authority", False),
        ("consent", False),
        ("zdr", False),
        ("provider_id", False),
    ],
)
def test_owner_optin_is_scoped(change: str, allowed: bool) -> None:
    profile = _profile("valid.local-openai-compatible.json").model_dump(mode="json")
    profile["protocol_framing_token_upper_bound"] = 4096
    profile.update(
        profile_id="deepseek-owner-authorized",
        provider_kind="openai_compatible_remote",
        execution_boundary="public_external",
        credential_ref="env://DEEPSEEK_API_KEY",
        egress_profiles=["managed_scan_opt_in"],
    )
    profile["endpoint"] = {
        "base_url": "https://api.deepseek.com",
        "authority": "api.deepseek.com",
        "allowed_ports": [443],
        "follow_redirects": False,
        "local_plaintext_exception": False,
    }
    profile["data_terms"].update(
        evidence_status="unverified",
        residency=[],
        retention_seconds=None,
        training_use="unknown",
        zero_data_retention=None,
        evidence_ref="consent://project-owner/deepseek-private-source/2026-09-27",
    )
    policy = _policy("egress.valid.private-model-source.json").model_dump(mode="json")
    policy["profile"] = "managed_scan_opt_in"
    policy["rules"][0].update(
        destinations=["profile://deepseek-owner-authorized"], tenant_admin_approval=True
    )
    if change == "approval":
        policy["rules"][0]["tenant_admin_approval"] = False
    if change == "authority":
        profile["endpoint"].update(base_url="https://other.example", authority="other.example")
    if change == "consent":
        profile["data_terms"]["evidence_ref"] = None
    if change == "provider_id":
        profile["profile_id"] = "another-provider"
        policy["rules"][0]["destinations"] = ["profile://another-provider"]
    if change == "zdr":
        policy["profile"] = "private_model_zdr"
        profile["egress_profiles"] = ["private_model_zdr"]
    parsed_profile = parse_provider_profile(json.dumps(profile))
    parsed_policy = EgressPolicyDocument.model_validate_json(json.dumps(policy))
    request = _request(parsed_profile, parsed_policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    preflight = _preflight_request(
        request,
        {
            "required_execution_boundary": "public_external",
            "required_data_class": "DC3_CONFIDENTIAL_SOURCE",
            "required_purpose": "model_native_discovery",
            "planned_transforms": ["bounded_repository_view"],
            "required_max_bytes": 65536,
        },
    )
    result = _issuer(parsed_profile, parsed_policy).authorize_pre_context(
        preflight, profile=parsed_profile, policy=parsed_policy
    )
    assert result.result.eligibility.value == ("eligible" if allowed else "ineligible")
