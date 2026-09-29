from __future__ import annotations

import json

import pytest
from securecode_ai.adapters.config import parse_provider_profile
from securecode_ai.adapters.openai_compatible_remote import (
    OpenAICompatibleRemoteHttpsConnector,
    _canonicalize_remote_envelope,
)
from securecode_ai.contracts import ProviderProfile


def _profile() -> ProviderProfile:
    return parse_provider_profile(
        json.dumps(
            {
                "schema_version": "0.2.0",
                "profile_id": "public-deepseek",
                "profile_version": "1.0.0",
                "provider_kind": "openai_compatible_remote",
                "protocol_framing_token_upper_bound": 8192,
                "api_dialect": "openai_compatible",
                "endpoint": {
                    "base_url": "https://api.deepseek.com/v1",
                    "authority": "api.deepseek.com",
                    "allowed_ports": [443],
                    "follow_redirects": False,
                    "local_plaintext_exception": False,
                },
                "execution_boundary": "public_external",
                "model_id": "deepseek-flash",
                "capabilities": {
                    "structured_output": True,
                    "native_refusal_signal": True,
                    "native_incomplete_signal": True,
                    "tool_calling": False,
                    "source_code_analysis": True,
                    "repository_tool_calls": False,
                    "repository_tools": [],
                    "max_context_tokens": 8192,
                    "max_output_tokens": 1024,
                },
                "data_terms": {
                    "evidence_status": "unverified",
                    "residency": ["provider-declared"],
                    "retention_seconds": None,
                    "training_use": "provider_declared",
                    "zero_data_retention": None,
                    "maximum_input_data_class": "DC0_PUBLIC",
                    "allowed_purposes": ["evaluation"],
                    "evidence_ref": "https://api-docs.deepseek.com/",
                },
                "credential_ref": "env://DEEPSEEK_API_KEY",
                "egress_profiles": ["metadata_external"],
                "budgets": {"timeout_seconds": 60, "max_attempts": 1, "max_total_tokens": 16384},
            }
        )
    )


def test_remote_connector_accepts_only_remote_https_profile() -> None:
    connector = OpenAICompatibleRemoteHttpsConnector(profile=_profile())
    assert "redacted" in repr(connector)
    assert connector._valid_connect_arguments(
        ip_address="1.1.1.1", port=443, server_name="api.deepseek.com", timeout_ms=60_000
    )
    assert not connector._valid_connect_arguments(
        ip_address="127.0.0.1", port=443, server_name="api.deepseek.com", timeout_ms=60_000
    )


def test_remote_envelope_is_reduced_to_the_contract_subset() -> None:
    payload = json.dumps(
        {
            "id": "chatcmpl-test",
            "model": "deepseek-flash",
            "object": "chat.completion",
            "choices": [
                {
                    "message": {"role": "assistant", "content": '{"candidates":[]}'},
                    "finish_reason": "stop",
                    "index": 0,
                }
            ],
            "usage": {"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17},
        }
    ).encode()
    normalized = json.loads(
        _canonicalize_remote_envelope(payload, expected_model_id="deepseek-flash")
    )
    assert normalized["choices"][0]["message"]["refusal"] is None
    assert normalized["usage"] == {"completion_tokens": 5, "prompt_tokens": 12}


def test_remote_envelope_rejects_model_drift() -> None:
    with pytest.raises(ValueError):
        _canonicalize_remote_envelope(b'{"model":"other"}', expected_model_id="deepseek-flash")


def _deepseek_envelope(**changes: object) -> bytes:
    # Shape of a real DeepSeek chat completion (recorded 2026-09-29, public CWE-89 fixture).
    choice: dict[str, object] = {
        "index": 0,
        "message": {"role": "assistant", "content": '{"candidates":[]}'},
        "logprobs": None,
        "finish_reason": "stop",
    }
    usage: dict[str, object] = {
        "prompt_tokens": 374,
        "completion_tokens": 25,
        "total_tokens": 399,
        "prompt_tokens_details": {"cached_tokens": 128},
        "prompt_cache_hit_tokens": 128,
        "prompt_cache_miss_tokens": 246,
    }
    for key, value in changes.items():
        target = choice if key == "logprobs" else usage
        if value is ...:
            target.pop(key)
        else:
            target[key] = value
    document = {
        "id": "response-1",
        "object": "chat.completion",
        "created": 1,
        "model": "deepseek-flash",
        "choices": [choice],
        "usage": usage,
        "system_fingerprint": "fingerprint",
    }
    return json.dumps(document).encode()


def test_real_deepseek_envelope_is_accepted_and_accounting_details_dropped() -> None:
    canonical = json.loads(
        _canonicalize_remote_envelope(_deepseek_envelope(), expected_model_id="deepseek-flash")
    )

    assert canonical["usage"] == {"prompt_tokens": 374, "completion_tokens": 25}
    assert canonical["choices"][0]["message"]["content"] == '{"candidates":[]}'


@pytest.mark.parametrize(
    "changes",
    [
        {"logprobs": {"content": []}},
        {"prompt_cache_hit_tokens": 1},
        {"prompt_cache_miss_tokens": "246"},
        {"prompt_tokens_details": {"cached_tokens": -1}},
        {"prompt_tokens_details": "cached"},
    ],
)
def test_deepseek_envelope_rejects_inconsistent_accounting_details(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        _canonicalize_remote_envelope(
            _deepseek_envelope(**changes), expected_model_id="deepseek-flash"
        )
