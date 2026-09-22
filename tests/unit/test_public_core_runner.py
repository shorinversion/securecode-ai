"""Focused public Core composition boundary tests."""

from __future__ import annotations

import base64
import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import cast

import pytest
from securecode_ai.adapters.config import parse_provider_profile
from securecode_ai.adapters.local_provider_admission import CoreCase
from securecode_ai.adapters.local_provider_gateway import GatewayPolicy
from securecode_ai.adapters.model import (
    ProviderAttempt,
    ProviderAttemptBinding,
    ProviderStreamState,
)
from securecode_ai.adapters.public_core_fixtures import PublicCoreFixture
from securecode_ai.adapters.public_core_runner import (
    PublicCoreHostInputs,
    PublicCoreRunnerError,
    load_public_core_inputs,
    preflight_public_core_case,
    prepare_public_core_case,
)
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    DataClass,
    EgressPolicyDocument,
    PreflightEligibility,
)

_ROOT = Path(__file__).resolve().parents[2]
_NAMES = (
    "stage_catalogue",
    "workflow",
    "policy",
    "configuration",
    "tool_policy",
    "repository_scope",
    "repository_view_policy",
    "producer",
)


def _inputs(
    *,
    source_analysis: bool = True,
    timeout_seconds: int = 60,
    max_output_tokens: int | None = None,
    diagnostic_sampling: bool = False,
) -> PublicCoreHostInputs:
    profile = json.loads(
        (
            _ROOT / "specs/contracts/provider-fixtures/valid.local-openai-compatible.json"
        ).read_bytes()
    )
    profile["budgets"]["timeout_seconds"] = timeout_seconds
    profile["endpoint"]["base_url"] = "http://127.0.0.1:11435/v1"
    profile["endpoint"]["allowed_ports"] = [11435]
    profile["capabilities"]["source_code_analysis"] = source_analysis
    if max_output_tokens is not None:
        profile["capabilities"]["max_output_tokens"] = max_output_tokens
    if diagnostic_sampling:
        profile["model_id"] = "llama3.1:8b-instruct-q3_K_M"
        profile["model_snapshot"] = "d" * 64
    profile_bytes = json.dumps(profile).encode()
    policy = json.loads(
        (
            _ROOT / "specs/contracts/policy/fixtures/egress.valid.private-model-source.json"
        ).read_bytes()
    )
    policy["tenant_scope"] = "synthetic-public-development"
    policy["rules"][0]["purposes"].append("candidate_investigation")
    policy["rules"][0]["data_classes"].append(DataClass.PUBLIC.value)
    policy_bytes = EgressPolicyDocument.model_validate_json(json.dumps(policy)).canonical_bytes()
    configuration = (
        _diagnostic_configuration(profile_bytes)
        if diagnostic_sampling
        else b"actual host artifact:configuration"
    )
    document = {
        name: base64.b64encode(
            policy_bytes
            if name == "policy"
            else configuration
            if name == "configuration"
            else (
                (
                    _ROOT / "packages/adapters/src/securecode_ai/adapters/product_runtime.py"
                ).read_bytes()
                if name == "producer"
                else f"actual host artifact:{name}".encode()
            )
        ).decode("ascii")
        for name in _NAMES
    }
    return load_public_core_inputs(
        profile_bytes=profile_bytes,
        policy_bytes=policy_bytes,
        artifacts_bytes=json.dumps(document).encode(),
        gateway_port=11435,
    )


def _diagnostic_configuration(profile_bytes: bytes) -> bytes:
    profile = parse_provider_profile(profile_bytes)
    provider = ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=profile.profile_id,
        component_version=profile.profile_version,
        content_sha256=profile.canonical_content_hash(),
    )
    return json.dumps(
        {
            "schema_version": "securecode.public-core-diagnostic-sampling.v1",
            "diagnostic": {
                "provider_profile": provider.model_dump(mode="json"),
                "model_id": profile.model_id,
                "model_snapshot": profile.model_snapshot,
                "role": "DISCOVERY",
                "native": True,
                "sampling": {"temperature": 0.0, "seed": 7},
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _artifact_document(inputs: PublicCoreHostInputs, configuration: bytes) -> bytes:
    document = {
        name: base64.b64encode(
            inputs._policy_bytes
            if name == "policy"
            else configuration
            if name == "configuration"
            else (
                (
                    _ROOT / "packages/adapters/src/securecode_ai/adapters/product_runtime.py"
                ).read_bytes()
                if name == "producer"
                else f"actual host artifact:{name}".encode()
            )
        ).decode("ascii")
        for name in _NAMES
    }
    return json.dumps(document).encode()


def test_public_runner_accepts_a_pinned_remote_public_profile() -> None:
    profile = json.loads(
        (
            _ROOT / "specs/contracts/provider-fixtures/valid.local-openai-compatible.json"
        ).read_bytes()
    )
    profile.update(
        {
            "profile_id": "public-remote-model",
            "provider_kind": "openai_compatible_remote",
            "execution_boundary": "public_external",
            "credential_ref": "env://PUBLIC_REMOTE_KEY",
            "egress_profiles": ["metadata_external"],
        }
    )
    profile["endpoint"] = {
        "base_url": "https://api.example.test/v1",
        "authority": "api.example.test",
        "allowed_ports": [443],
        "follow_redirects": False,
        "local_plaintext_exception": False,
    }
    profile["data_terms"].update(
        {
            "evidence_status": "verified",
            "residency": ["policy-selected"],
            "training_use": "none_verified",
            "maximum_input_data_class": DataClass.PUBLIC.value,
            "evidence_ref": "evidence://provider-terms/public-remote",
        }
    )
    profile_bytes = json.dumps(profile, sort_keys=True).encode()
    policy = json.loads(
        (_ROOT / "specs/contracts/policy/fixtures/egress.valid.metadata-external.json").read_bytes()
    )
    policy.update({"tenant_scope": "synthetic-public-development"})
    policy["rules"][0].update(
        {
            "data_classes": [DataClass.PUBLIC.value],
            "destinations": ["profile://public-remote-model"],
            "purposes": ["model_native_discovery", "candidate_investigation"],
            "requires_transforms": ["bounded_repository_view"],
        }
    )
    policy_bytes = EgressPolicyDocument.model_validate_json(json.dumps(policy)).canonical_bytes()
    artifacts = {
        name: base64.b64encode(
            policy_bytes
            if name == "policy"
            else b"public remote configuration"
            if name == "configuration"
            else (
                _ROOT / "packages/adapters/src/securecode_ai/adapters/product_runtime.py"
            ).read_bytes()
            if name == "producer"
            else f"actual host artifact:{name}".encode()
        ).decode("ascii")
        for name in _NAMES
    }

    inputs = load_public_core_inputs(
        profile_bytes=profile_bytes,
        policy_bytes=policy_bytes,
        artifacts_bytes=json.dumps(artifacts).encode(),
        gateway_port=443,
    )

    assert inputs.profile.execution_boundary.value == "public_external"
    assert inputs.snapshot().profile.selector == "public-remote-model@1.0.0"


def test_actual_preflight_preserves_profile_capabilities_and_binds_full_identity() -> None:
    inputs = _inputs()
    prepared = prepare_public_core_case(case=CoreCase.PYTHON_INTERFILE, inputs=inputs)

    assert prepared.preflight.eligibility is PreflightEligibility.ELIGIBLE
    assert prepared.request.execution_identity.policy == inputs.policy_pin
    assert prepared.request.execution_identity.capability_profile == inputs.capability_pin
    assert prepared.request.execution_identity.repository_revision.repository_id == (
        prepared.fixture.catalogue.indexes[0].repository_id
    )
    assert prepared.request.budget.timeout_ms == inputs.profile.budgets.timeout_seconds * 1000
    assert prepared.fixture.catalogue.snapshot.head_sha == prepared.request.head_sha


def test_profile_output_cap_propagates_to_prepared_model_request() -> None:
    inputs = _inputs(max_output_tokens=256)

    prepared = prepare_public_core_case(case=CoreCase.PYTHON_SAFE, inputs=inputs)

    assert inputs.profile.capabilities.max_output_tokens == 256
    assert prepared.request.budget.max_output_tokens == 256


def test_ordinary_profile_prepares_standard_output_ceiling() -> None:
    inputs = _inputs()

    prepared = prepare_public_core_case(case=CoreCase.PYTHON_SAFE, inputs=inputs)

    assert inputs.profile.capabilities.max_output_tokens == 4096
    assert prepared.request.budget.max_output_tokens == 1024


def test_ineligible_profile_stops_before_fixture_context_or_transport() -> None:
    inputs = _inputs(source_analysis=False)

    result = preflight_public_core_case(case=CoreCase.GO_SAFE, inputs=inputs)

    assert result.eligibility is PreflightEligibility.INELIGIBLE
    assert result.preflight_context_bytes == 0
    assert result.preflight_network_bytes == 0
    assert inputs.profile.capabilities.source_code_analysis is False


def test_opt_in_sampling_is_limited_to_native_discovery_connector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import securecode_ai.adapters.public_core_runner as runner

    inputs = _inputs(diagnostic_sampling=True)
    observed: list[dict[str, object]] = []

    class Connector:
        def connect(self, **kwargs: object) -> object:
            del kwargs
            raise AssertionError("connector must not connect during construction")

        def send(self, channel: object, **kwargs: object) -> object:
            del channel, kwargs
            raise AssertionError("connector must not send during construction")

    def factory(**kwargs: object) -> Connector:
        observed.append(kwargs)
        return Connector()

    monkeypatch.setattr(runner, "OpenAICompatibleLocalHttpConnector", factory)
    runner._executor(inputs=inputs, connector=None, native=True)
    runner._executor(inputs=inputs, connector=None, native=False)

    assert inputs.diagnostic_sampling is not None
    assert observed == [
        {
            "profile": inputs.profile,
            "temperature": 0.0,
            "seed": 7,
            "native_frames": True,
        },
        {
            "profile": inputs.profile,
            "temperature": None,
            "seed": None,
            "native_frames": False,
        },
    ]


def test_ordinary_configuration_leaves_sampling_unset() -> None:
    assert _inputs().diagnostic_sampling is None


@pytest.mark.parametrize("fault", ["malformed", "extra", "foreign", "copied", "mutated"])
def test_diagnostic_configuration_rejects_before_fixture_context(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    import securecode_ai.adapters.public_core_runner as runner

    inputs = _inputs(diagnostic_sampling=True)
    configuration = _diagnostic_configuration(inputs._profile_bytes)
    profile_bytes = inputs._profile_bytes
    if fault == "malformed":
        configuration = b'{"schema_version":"securecode.public-core-diagnostic-sampling.v1"'
    else:
        document = json.loads(configuration)
        diagnostic = document["diagnostic"]
        if fault == "extra":
            document["extra"] = True
        elif fault == "foreign":
            diagnostic["provider_profile"]["content_sha256"] = "f" * 64
        elif fault == "copied":
            profile = json.loads(profile_bytes)
            profile["profile_version"] = "1.0.1"
            profile_bytes = json.dumps(profile).encode()
        else:
            diagnostic["sampling"]["seed"] = 8
        configuration = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()

    def unexpected_fixture(_: object) -> object:
        pytest.fail("invalid diagnostic configuration reached fixture context")

    monkeypatch.setattr(runner, "build_public_core_fixture", unexpected_fixture)
    with pytest.raises(PublicCoreRunnerError):
        load_public_core_inputs(
            profile_bytes=profile_bytes,
            policy_bytes=inputs._policy_bytes,
            artifacts_bytes=_artifact_document(inputs, configuration),
            gateway_port=11435,
        )


def test_direct_constructor_rejects_copied_mutated_or_forged_configuration_binding() -> None:
    inputs = _inputs(diagnostic_sampling=True)
    ordinary = _inputs()
    mutated = bytearray(inputs._configuration_bytes)
    mutated[mutated.index(b"7")] = ord("8")

    with pytest.raises(PublicCoreRunnerError):
        replace(inputs, _configuration_bytes=ordinary._configuration_bytes)
    with pytest.raises(PublicCoreRunnerError):
        replace(inputs, _configuration_bytes=bytes(mutated))
    with pytest.raises(PublicCoreRunnerError):
        replace(
            inputs,
            artifacts=replace(inputs.artifacts, configuration=ordinary.artifacts.configuration),
        )


def test_in_place_configuration_pin_mutation_rejects_before_fixture_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import securecode_ai.adapters.public_core_runner as runner

    inputs = _inputs(diagnostic_sampling=True)
    inputs.artifacts.configuration.__dict__["content_sha256"] = "f" * 64

    def unexpected_fixture(_: object) -> object:
        pytest.fail("mutated pin reached fixture context")

    monkeypatch.setattr(runner, "build_public_core_fixture", unexpected_fixture)
    with pytest.raises(PublicCoreRunnerError):
        prepare_public_core_case(case=CoreCase.PYTHON_SAFE, inputs=inputs)


def test_artifact_document_rejects_duplicate_key_and_foreign_policy_pin() -> None:
    inputs = _inputs()
    profile = inputs._profile_bytes
    policy = inputs._policy_bytes
    duplicate = b'{"stage_catalogue":"YQ==","stage_catalogue":"Yg=="}'
    with pytest.raises(PublicCoreRunnerError):
        load_public_core_inputs(
            profile_bytes=profile, policy_bytes=policy, artifacts_bytes=duplicate
        )

    document = {
        name: base64.b64encode(f"foreign:{name}".encode()).decode("ascii") for name in _NAMES
    }
    with pytest.raises(PublicCoreRunnerError):
        load_public_core_inputs(
            profile_bytes=profile,
            policy_bytes=policy,
            artifacts_bytes=json.dumps(document).encode(),
        )


class _Channel:
    peer_ip = "127.0.0.1"


class _ScriptedTransport:
    def __init__(self, bodies: list[bytes]) -> None:
        self._bodies = list(bodies)
        self.connects = 0
        self.sends = 0

    def connect(self, **kwargs: object) -> _Channel:
        del kwargs
        self.connects += 1
        return _Channel()

    def send(self, channel: object, **kwargs: object) -> ProviderAttempt:
        from securecode_ai.contracts import ApiDialect

        del channel
        binding = kwargs["binding"]
        if not self._bodies:
            raise AssertionError("unexpected provider send")
        self.sends += 1
        return ProviderAttempt(
            dialect=ApiDialect.OPENAI_COMPATIBLE,
            http_status=200,
            response_bytes=self._bodies.pop(0),
            transport_failure=None,
            stream_state=ProviderStreamState.COMPLETE,
            binding=cast(ProviderAttemptBinding, binding),
            elapsed_ms=1,
        )


def _reply(payload: object) -> bytes:
    return json.dumps(
        {
            "id": "chatcmpl_public",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": json.dumps(payload), "refusal": None},
                }
            ],
            "usage": {"prompt_tokens": 4, "completion_tokens": 3},
        },
        separators=(",", ":"),
    ).encode()


def _native_selection(fixture: PublicCoreFixture, call_id: str) -> bytes:
    catalogue = fixture.catalogue
    request = catalogue.anchors[0].request
    return json.dumps(
        {
            "id": f"chatcmpl_{call_id}",
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "refusal": None,
                        "tool_calls": [
                            {
                                "id": call_id,
                                "type": "function",
                                "function": {
                                    "name": request.tool.value,
                                    "arguments": json.dumps(
                                        asdict(request.arguments),
                                        separators=(",", ":"),
                                    ),
                                },
                            }
                        ],
                    },
                }
            ],
            "usage": {"prompt_tokens": 4, "completion_tokens": 3},
        },
        separators=(",", ":"),
    ).encode()


def test_simulated_completed_zero_uses_actual_harness_and_stays_non_admitted() -> None:
    from securecode_ai.adapters.local_provider_admission import EvidenceOrigin
    from securecode_ai.adapters.product_scan import ProductCandidateFlow
    from securecode_ai.adapters.public_core_fixtures import build_public_core_fixture
    from securecode_ai.adapters.public_core_runner import run_public_core_case

    fixture = build_public_core_fixture(CoreCase.PYTHON_SAFE)
    transport = _ScriptedTransport(
        [
            _native_selection(fixture, "call-discovery-1"),
            _native_selection(fixture, "call-discovery-2"),
            _reply({"candidates": []}),
        ]
    )
    result = run_public_core_case(
        case=CoreCase.PYTHON_SAFE, inputs=_inputs(), simulated_transport=transport
    )

    assert type(result.flow) is ProductCandidateFlow
    assert result.origin is EvidenceOrigin.SIMULATED
    assert result.flow_constructed and result.completed
    assert result.production_admitted is False
    assert result.auditor_evidence == () and result.failure_code is None
    assert transport.connects == transport.sends == 3


@pytest.mark.parametrize("count", [1, 2])
def test_simulated_native_candidates_receive_auditor_receipts(count: int) -> None:
    from securecode_ai.adapters.product_scan import ProductCandidateFlow
    from securecode_ai.adapters.public_core_fixtures import build_public_core_fixture
    from securecode_ai.adapters.public_core_runner import run_public_core_case

    fixture = build_public_core_fixture(CoreCase.PYTHON_SAFE)
    anchors = fixture.catalogue.anchors[:count]
    discovery = {
        "candidates": [
            {
                "rule_id": "cwe-89-sql-interpolation",
                "root_evidence_id": anchor.evidence_id,
                "evidence_ids": sorted(item.evidence_id for item in anchors),
            }
            for anchor in anchors
        ]
    }
    auditor = {
        "finding_verdict": "CONFIRMED",
        "cited_evidence_ids": sorted(item.evidence_id for item in anchors),
        "rationale": "bounded synthetic evidence",
    }
    transport = _ScriptedTransport(
        [
            _native_selection(fixture, "call-discovery-1"),
            _native_selection(fixture, "call-discovery-2"),
            _reply(discovery),
            *(_reply(auditor) for _ in anchors),
        ]
    )

    result = run_public_core_case(
        case=CoreCase.PYTHON_SAFE, inputs=_inputs(), simulated_transport=transport
    )

    assert type(result.flow) is ProductCandidateFlow
    assert result.completed and result.failure_code is None
    assert len(result.flow.graph.candidates) == count
    assert len(result.auditor_evidence) == count
    assert transport.connects == transport.sends == count + 3


@pytest.mark.parametrize(
    "seconds,expected_ms", [(1, 1000), (20, 20000), (60, 60000), (120, 120000), (600, 120000)]
)
def test_public_cycle_deadline_respects_profile_and_harness_ceiling(
    seconds: int, expected_ms: int
) -> None:

    inputs = _inputs(timeout_seconds=seconds)
    prepared = prepare_public_core_case(case=CoreCase.PYTHON_SAFE, inputs=inputs)
    assert prepared.request.budget.timeout_ms == expected_ms
    assert prepared.request.budget.timeout_ms <= seconds * 1000
    from securecode_ai.adapters.public_core_runner import _investigation_budget

    assert _investigation_budget(inputs, prepared.request).max_elapsed_ms == expected_ms
    assert GatewayPolicy(inputs.profile.model_id, "b" * 64).timeout_seconds == 30
