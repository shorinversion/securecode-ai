"""Trial analysis (securecode analyze) and DeepSeek reasoning configuration."""

from __future__ import annotations

import io
import json

import pytest
from securecode_ai.adapters import local_product_trial as trial
from securecode_ai.adapters.openai_compatible_remote import (
    OpenAICompatibleRemoteHttpsConnector,
    _canonicalize_remote_envelope,
    _canonicalize_remote_envelope_with_usage,
    _request_payload,
)
from securecode_ai.cli.analyze import run_analyze_command
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    DataClass,
    ExecutionBoundary,
    ModelPurpose,
)
from securecode_ai.core import EgressPolicyRegistry, ModelAuthorizationIssuer


def test_reasoning_payload_enables_thinking_without_sampling_parameters() -> None:
    payload = _request_payload(
        model_id="deepseek-flash",
        prompt="{}",
        native_frame=None,
        max_tokens=32768,
        reasoning_effort="high",
    )

    assert payload["thinking"] == {"type": "enabled"}
    assert payload["reasoning_effort"] == "high"
    assert "temperature" not in payload
    assert payload["max_tokens"] == 32768


def test_default_payload_keeps_deterministic_non_thinking_mode() -> None:
    payload = _request_payload(
        model_id="deepseek-flash", prompt="{}", native_frame=None, max_tokens=64
    )

    assert payload["thinking"] == {"type": "disabled"}
    assert payload["temperature"] == 0


def test_unknown_reasoning_effort_is_rejected() -> None:
    with pytest.raises(ValueError, match="REASONING"):
        OpenAICompatibleRemoteHttpsConnector(
            profile=trial._deepseek_profile("deepseek-flash"), reasoning_effort="extreme"
        )


def test_reasoning_trace_is_accepted_and_never_retained() -> None:
    envelope = {
        "id": "response-1",
        "model": "deepseek-flash",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": '{"candidates":[]}',
                    "reasoning_content": "private chain of thought",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 90,
            "total_tokens": 100,
            "completion_tokens_details": {"reasoning_tokens": 80},
        },
    }

    canonical = _canonicalize_remote_envelope(
        json.dumps(envelope).encode(), expected_model_id="deepseek-flash"
    )

    assert b"private chain of thought" not in canonical
    assert json.loads(canonical)["choices"][0]["message"]["content"] == '{"candidates":[]}'


def test_trial_deepseek_profile_is_admitted_by_the_owner_consent_policy() -> None:
    purpose = ModelPurpose.MODEL_NATIVE_DISCOVERY
    from securecode_ai.adapters import ProviderProfileRegistry

    from tests.unit.test_provider_preflight import _preflight_request, _request

    profile = trial._deepseek_profile("deepseek-flash")
    policy = trial._policy(profile, "managed_scan_opt_in", approval=True)
    issuer = ModelAuthorizationIssuer(
        provider_registry=ProviderProfileRegistry((profile,)),
        policy_registry=EgressPolicyRegistry((policy,)),
    )
    request = _request(profile, policy, purpose)
    preflight = _preflight_request(
        request,
        {
            "required_execution_boundary": ExecutionBoundary.PUBLIC_EXTERNAL.value,
            "required_data_class": DataClass.CONFIDENTIAL_SOURCE.value,
            "required_purpose": purpose.value,
            "planned_transforms": ["bounded_repository_view"],
            "required_max_bytes": 65536,
        },
    )
    result = issuer.authorize_pre_context(preflight, profile=profile, policy=policy)

    assert CONTRACT_SCHEMA_VERSION
    assert result.result.eligibility.value == "eligible"


def test_trial_host_pins_the_installed_workflow_and_prompts() -> None:
    profile = trial._deepseek_profile("deepseek-flash")
    host = trial._host(profile, trial._policy(profile, "managed_scan_opt_in", approval=True))

    assert host.approval_record_sha256 == "0" * 64
    assert set(host.artifact_manifest) >= {
        "workflow_sha256",
        "discovery_prompt_sha256",
        "auditor_prompt_sha256",
        "skeptic_prompt_sha256",
    }


def test_analyze_without_a_key_explains_what_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    monkeypatch.chdir(str(tmp_path))
    stdout, stderr = io.StringIO(), io.StringIO()

    code = run_analyze_command(("analyze", "."), stdout=stdout, stderr=stderr, environment={})

    assert code == 4
    assert "DEEPSEEK_API_KEY" in stderr.getvalue()
    assert stdout.getvalue() == ""


def _native_envelope(content: str) -> bytes:
    return json.dumps(
        {
            "id": "response-2",
            "model": "deepseek-flash",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
    ).encode()


def test_tool_call_written_as_text_becomes_a_native_call() -> None:
    head = "a" * 40
    arguments = json.dumps(
        {
            "end_line": 40,
            "head_sha": head,
            "path": "app.py",
            "schema_version": "0.1.0",
            "start_line": 1,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    content = json.dumps({"tool": "read_range", "arguments_json": arguments})

    canonical, _, _ = _canonicalize_remote_envelope_with_usage(
        _native_envelope(content),
        expected_model_id="deepseek-flash",
        native=True,
        expected_head_sha=head,
    )

    choice = json.loads(canonical)["choices"][0]
    assert choice["finish_reason"] == "tool_calls"
    assert choice["message"]["content"] is None
    assert choice["message"]["tool_calls"][0]["function"] == {
        "name": "read_range",
        "arguments": arguments,
    }


@pytest.mark.parametrize(
    "content",
    ['{"candidates":[]}', '{"tool":"delete_repo","arguments_json":"{}"}', "not json"],
)
def test_final_answers_and_unknown_tools_stay_text(content: str) -> None:
    canonical, _, _ = _canonicalize_remote_envelope_with_usage(
        _native_envelope(content),
        expected_model_id="deepseek-flash",
        native=True,
        expected_head_sha="a" * 40,
    )

    choice = json.loads(canonical)["choices"][0]
    assert choice["finish_reason"] == "stop"
    assert choice["message"]["content"] == content
