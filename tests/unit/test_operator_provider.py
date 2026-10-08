"""An operator-named OpenAI-compatible endpoint (D-118)."""

from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from securecode_ai.adapters import ProviderProfileRegistry
from securecode_ai.adapters import local_product_trial as trial
from securecode_ai.adapters.local_product_trial import TrialAnalysisError, operator_endpoint
from securecode_ai.adapters.openai_compatible_remote import (
    OpenAICompatibleRemoteHttpsConnector,
    _canonicalize_remote_envelope,
    _request_payload,
    token_limit_field,
)
from securecode_ai.cli.analyze import _summary, run_analyze_command
from securecode_ai.contracts import DataClass, ExecutionBoundary, ModelPurpose
from securecode_ai.core import EgressPolicyRegistry, ModelAuthorizationIssuer

from tests.unit.test_provider_preflight import _preflight_request, _request

_ENVIRONMENT = {
    "SECURECODE_MODEL_BASE_URL": "https://api.example-llm.com/v1/",
    "SECURECODE_MODEL": "vendor/model-small",
    "SECURECODE_MODEL_API_KEY": "x" * 16,
}


def test_operator_endpoint_reads_the_three_settings() -> None:
    endpoint = operator_endpoint(_ENVIRONMENT)

    assert endpoint.base_url == "https://api.example-llm.com/v1"
    assert (endpoint.authority, endpoint.port) == ("api.example-llm.com", 443)
    assert endpoint.model_id == "vendor/model-small"
    assert endpoint.reasoning_effort == "default"
    assert endpoint.prices is None


def test_operator_prices_are_usd_per_million_tokens() -> None:
    endpoint = operator_endpoint(
        _ENVIRONMENT
        | {"SECURECODE_MODEL_PRICE_INPUT": "0.15", "SECURECODE_MODEL_PRICE_OUTPUT": "0.6"}
    )

    assert endpoint.prices == (150_000, 600_000)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"SECURECODE_MODEL_BASE_URL": ""}, "SECURECODE_MODEL_BASE_URL is not set"),
        ({"SECURECODE_MODEL_BASE_URL": "http://api.example-llm.com/v1"}, "https://"),
        (
            {"SECURECODE_MODEL_BASE_URL": "https://" + "user:" + "pw" + "@api.example-llm.com"},
            "https://",
        ),
        ({"SECURECODE_MODEL_BASE_URL": "https://api.example-llm.com/v1?x=1"}, "https://"),
        ({"SECURECODE_MODEL": ""}, "SECURECODE_MODEL is not set"),
        ({"SECURECODE_MODEL": "bad model"}, "SECURECODE_MODEL is invalid"),
        ({"SECURECODE_MODEL_API_KEY": ""}, "SECURECODE_MODEL_API_KEY is not set"),
        ({"SECURECODE_MODEL_REASONING_EFFORT": "max"}, "REASONING_EFFORT"),
        ({"SECURECODE_MODEL_PRICE_INPUT": "0.1"}, "both needed"),
        ({"SECURECODE_MODEL_CONTEXT_TOKENS": "100"}, "CONTEXT_TOKENS"),
    ],
)
def test_operator_endpoint_explains_a_wrong_setting(changes: dict[str, str], message: str) -> None:
    with pytest.raises(TrialAnalysisError, match=message):
        operator_endpoint(_ENVIRONMENT | changes)


def test_operator_profile_refuses_private_and_consumer_hosts() -> None:
    for url in ("https://10.0.0.5/v1", "https://chatgpt.com/v1"):
        with pytest.raises(TrialAnalysisError, match="not accepted"):
            trial._operator_profile(
                operator_endpoint(_ENVIRONMENT | {"SECURECODE_MODEL_BASE_URL": url})
            )


def _eligibility(*, approval: bool = True, consent: str | None = None) -> str:
    profile = trial._operator_profile(operator_endpoint(_ENVIRONMENT))
    if consent is not None:
        data = profile.model_dump(mode="json")
        data["data_terms"]["evidence_ref"] = consent
        profile = type(profile).model_validate_json(json.dumps(data))
    policy = trial._policy(profile, "managed_scan_opt_in", approval=approval)
    issuer = ModelAuthorizationIssuer(
        provider_registry=ProviderProfileRegistry((profile,)),
        policy_registry=EgressPolicyRegistry((policy,)),
    )
    purpose = ModelPurpose.MODEL_NATIVE_DISCOVERY
    preflight = _preflight_request(
        _request(profile, policy, purpose),
        {
            "required_execution_boundary": ExecutionBoundary.PUBLIC_EXTERNAL.value,
            "required_data_class": DataClass.CONFIDENTIAL_SOURCE.value,
            "required_purpose": purpose.value,
            "planned_transforms": ["bounded_repository_view"],
            "required_max_bytes": 65536,
        },
    )
    result = issuer.authorize_pre_context(preflight, profile=profile, policy=policy)
    return result.result.eligibility.value


def test_operator_profile_is_admitted_with_its_consent_and_approval() -> None:
    assert _eligibility() == "eligible"


def test_operator_admission_is_scoped_to_the_named_host() -> None:
    assert _eligibility(approval=False) == "ineligible"
    assert (
        _eligibility(consent="consent://operator/openai-compatible/other.example.com")
        == "ineligible"
    )


def test_operator_payload_has_only_standard_fields() -> None:
    plain = _request_payload(
        model_id="m", prompt="{}", native_frame=None, max_tokens=64, dialect="openai"
    )
    reasoning = _request_payload(
        model_id="m",
        prompt="{}",
        native_frame=None,
        max_tokens=64,
        reasoning_effort="medium",
        dialect="openai",
        token_field="max_completion_tokens",
    )

    assert {"thinking", "temperature", "reasoning_effort"}.isdisjoint(plain)
    assert plain["max_tokens"] == 64
    assert reasoning["reasoning_effort"] == "medium"
    assert reasoning["max_completion_tokens"] == 64 and "max_tokens" not in reasoning
    assert token_limit_field("api.openai.com") == "max_completion_tokens"
    assert token_limit_field("api.deepseek.com") == "max_tokens"


def test_operator_connector_refuses_a_deepseek_only_effort() -> None:
    profile = trial._operator_profile(operator_endpoint(_ENVIRONMENT))
    with pytest.raises(ValueError, match="REASONING"):
        OpenAICompatibleRemoteHttpsConnector(
            profile=profile, reasoning_effort="max", dialect="openai"
        )


def _openai_envelope(message: dict[str, object], **extra: object) -> bytes:
    # Shape of an OpenAI chat completion: dated model snapshot, empty annotations,
    # detailed usage; a gateway adds its own accounting fields.
    usage: dict[str, object] = {
        "prompt_tokens": 20,
        "completion_tokens": 5,
        "total_tokens": 25,
        "prompt_tokens_details": {"cached_tokens": 0, "audio_tokens": 0},
        "completion_tokens_details": {"reasoning_tokens": 0},
    } | extra
    return json.dumps(
        {
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "model": "gpt-4o-mini-2024-07-18",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": '{"candidates":[]}'} | message,
                    "logprobs": None,
                    "finish_reason": "stop",
                }
            ],
            "usage": usage,
            "service_tier": "default",
        }
    ).encode()


def test_openai_envelope_with_standard_extras_is_accepted() -> None:
    envelope = _openai_envelope(
        {"refusal": None, "annotations": [], "reasoning": "hidden"}, cost=0.00002, is_byok=False
    )

    canonical = json.loads(_canonicalize_remote_envelope(envelope, expected_model_id="gpt-4o-mini"))

    assert canonical["choices"][0]["message"]["content"] == '{"candidates":[]}'
    assert b"hidden" not in _canonicalize_remote_envelope(envelope, expected_model_id="gpt-4o-mini")


@pytest.mark.parametrize(
    ("message", "extra", "model"),
    [
        ({"annotations": [{"type": "url_citation"}]}, {}, "gpt-4o-mini"),
        ({"audio": {"id": "a"}}, {}, "gpt-4o-mini"),
        ({}, {"note": "text"}, "gpt-4o-mini"),
        ({}, {}, "gpt-4o"),
    ],
)
def test_openai_envelope_rejects_content_it_cannot_use(
    message: dict[str, object], extra: dict[str, object], model: str
) -> None:
    with pytest.raises(ValueError):
        _canonicalize_remote_envelope(_openai_envelope(message, **extra), expected_model_id=model)


def test_analyze_reads_operator_settings_from_dotenv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "SECURECODE_MODEL_BASE_URL=http://api.example-llm.com/v1\n", encoding="utf-8"
    )
    stdout, stderr = io.StringIO(), io.StringIO()

    code = run_analyze_command(
        ("analyze", ".", "--provider", "openai-compatible"),
        stdout=stdout,
        stderr=stderr,
        environment={},
    )

    assert code == 4
    assert "must be an https:// URL" in stderr.getvalue()


def test_unpriced_run_reports_an_unknown_cost() -> None:
    analysis = SimpleNamespace(
        provider="openai-compatible",
        model_id="vendor/model-small",
        result=SimpleNamespace(sarif_rendered=b'{"runs":[{"results":[]}]}', exit_code=0),
    )

    summary = _summary(analysis, None)  # type: ignore[arg-type]

    assert "cost=unknown" in summary and "outcome=PASS" in summary
