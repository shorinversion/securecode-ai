"""Focused identity and source-free execution wrapper tests."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from securecode_ai.adapters.local_provider_admission import CoreCase
from securecode_ai.adapters.model import ProviderAttempt, ProviderAttemptBinding
from securecode_ai.adapters.public_core_execution import (
    BackendIdentity,
    BackendObservation,
    ExecutionOrigin,
    execute_public_core_case,
    source_free_execution_document,
)
from securecode_ai.adapters.public_core_runner import PublicCoreHostInputs, load_public_core_inputs
from securecode_ai.contracts import DataClass, EgressPolicyDocument

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
_SHA = "a" * 64


def _inputs() -> PublicCoreHostInputs:
    profile = json.loads(
        (
            _ROOT / "specs/contracts/provider-fixtures/valid.local-openai-compatible.json"
        ).read_bytes()
    )
    profile["endpoint"]["base_url"] = "http://127.0.0.1:11435/v1"
    profile["endpoint"]["allowed_ports"] = [11435]
    profile["model_snapshot"] = _SHA
    policy = json.loads(
        (
            _ROOT / "specs/contracts/policy/fixtures/egress.valid.private-model-source.json"
        ).read_bytes()
    )
    policy["tenant_scope"] = "synthetic-public-development"
    policy["rules"][0]["purposes"].append("candidate_investigation")
    policy["rules"][0]["data_classes"].append(DataClass.PUBLIC.value)
    policy_bytes = EgressPolicyDocument.model_validate_json(json.dumps(policy)).canonical_bytes()
    artifacts = {
        name: base64.b64encode(
            policy_bytes
            if name == "policy"
            else (
                (
                    _ROOT / "packages/adapters/src/securecode_ai/adapters/product_runtime.py"
                ).read_bytes()
                if name == "producer"
                else f"host-artifact:{name}".encode()
            )
        ).decode()
        for name in _NAMES
    }
    return load_public_core_inputs(
        profile_bytes=json.dumps(profile).encode(),
        policy_bytes=policy_bytes,
        artifacts_bytes=json.dumps(artifacts).encode(),
    )


def _identity(
    *,
    model_id: str = "approved-local-model",
    model_manifest_sha256: str = _SHA,
    backend_authority: str = "127.0.0.1",
    backend_port: int = 11434,
    gateway_policy_sha256: str = "d" * 64,
) -> BackendIdentity:
    return BackendIdentity(
        model_id=model_id,
        model_manifest_sha256=model_manifest_sha256,
        backend_version="0.16.2",
        backend_executable_sha256="b" * 64,
        gateway_source_sha256="c" * 64,
        gateway_policy_sha256=gateway_policy_sha256,
        connector_source_sha256="e" * 64,
        backend_authority=backend_authority,
        backend_port=backend_port,
        gateway_port=11435,
    )


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return value


def _sequence(value: object) -> list[object]:
    assert isinstance(value, list)
    return value


def _observation(identity: BackendIdentity, pid: int = 42) -> BackendObservation:
    return BackendObservation(identity, pid, identity.backend_executable_sha256)


def test_pre_identity_mismatch_prevents_runner_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    import securecode_ai.adapters.public_core_execution as execution

    called = False

    def forbidden(**kwargs: object) -> None:
        nonlocal called
        called = True
        raise AssertionError("runner called")

    monkeypatch.setattr(execution, "run_public_core_case", forbidden)
    expected = _identity()
    result = execute_public_core_case(
        case=CoreCase.PYTHON_SAFE,
        inputs=_inputs(),
        expected_backend=expected,
        observe_backend=lambda: _observation(_identity(model_manifest_sha256="f" * 64)),
    )

    assert not called and result.failure_code == "PRE_IDENTITY_MISMATCH"
    document = source_free_execution_document(result)
    assert _mapping(document["fixture"])["head_sha"] is None
    assert document["discovery_usage"] == {"known": False, "tokens_used": None, "elapsed_ms": None}


def test_mutated_nested_configuration_pin_stops_before_backend_observation() -> None:
    from securecode_ai.adapters.public_core_execution import PublicCoreExecutionError

    inputs = _inputs()
    inputs.artifacts.configuration.__dict__["content_sha256"] = "f" * 64
    observed = False

    def observer() -> BackendObservation:
        nonlocal observed
        observed = True
        return _observation(_identity())

    with pytest.raises(PublicCoreExecutionError):
        execute_public_core_case(
            case=CoreCase.PYTHON_SAFE,
            inputs=inputs,
            expected_backend=_identity(),
            observe_backend=observer,
        )
    assert observed is False


def test_post_listener_change_invalidates_preserved_run(monkeypatch: pytest.MonkeyPatch) -> None:
    import securecode_ai.adapters.public_core_execution as execution

    expected = _identity()
    observations = iter((_observation(expected, 42), _observation(expected, 43)))
    monkeypatch.setattr(execution, "run_public_core_case", lambda **kwargs: None)
    result = execute_public_core_case(
        case=CoreCase.PYTHON_SAFE,
        inputs=_inputs(),
        expected_backend=expected,
        observe_backend=lambda: next(observations),
        simulated_transport=object(),
    )

    assert result.origin is ExecutionOrigin.SIMULATED
    assert result.failure_code == "POST_LISTENER_CHANGED"
    assert not result.measurement_valid and result.production_admitted is False


def test_identity_requires_distinct_literal_backend_and_gateway_ports() -> None:
    with pytest.raises(ValueError):
        _identity(backend_port=11435)
    with pytest.raises(ValueError):
        _identity(backend_authority="localhost")


@pytest.mark.parametrize("phase", ["before", "after"])
def test_observer_fault_is_a_safe_phase_failure(
    monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    import http.client

    import securecode_ai.adapters.public_core_execution as execution

    expected = _identity()
    calls = 0

    def observer() -> BackendObservation:
        nonlocal calls
        calls += 1
        if phase == "before" or calls == 2:
            raise http.client.HTTPException("hidden backend detail")
        return _observation(expected)

    monkeypatch.setattr(execution, "run_public_core_case", lambda **kwargs: None)
    result = execute_public_core_case(
        case=CoreCase.PYTHON_SAFE,
        inputs=_inputs(),
        expected_backend=expected,
        observe_backend=observer,
    )

    assert result.failure_code == (
        "PRE_OBSERVATION_FAILED" if phase == "before" else "POST_OBSERVATION_FAILED"
    )
    document = source_free_execution_document(result)
    assert "hidden backend detail" not in json.dumps(document)
    assert _mapping(document["identity"])["after_listener_pid"] is None


class _Channel:
    peer_ip = "127.0.0.1"


class _CompletedZeroTransport:
    def __init__(self) -> None:
        self.calls = 0
        from securecode_ai.adapters.public_core_fixtures import build_public_core_fixture

        from tests.unit.test_public_core_runner import _native_selection

        fixture = build_public_core_fixture(CoreCase.PYTHON_SAFE)
        self._bodies = [
            _native_selection(fixture, "call-discovery-1"),
            _native_selection(fixture, "call-discovery-2"),
            json.dumps(
                {
                    "id": "chatcmpl_execution",
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"content": '{"candidates":[]}', "refusal": None},
                        }
                    ],
                    "usage": {"prompt_tokens": 4, "completion_tokens": 3},
                },
                separators=(",", ":"),
            ).encode(),
        ]

    def connect(self, **kwargs: object) -> _Channel:
        del kwargs
        self.calls += 1
        return _Channel()

    def send(
        self,
        channel: object,
        *,
        binding: ProviderAttemptBinding,
        **kwargs: object,
    ) -> ProviderAttempt:
        from securecode_ai.adapters.model import ProviderStreamState
        from securecode_ai.contracts import ApiDialect

        del channel
        if not self._bodies:
            raise AssertionError("unexpected provider send")
        body = self._bodies.pop(0)
        return ProviderAttempt(
            dialect=ApiDialect.OPENAI_COMPATIBLE,
            http_status=200,
            response_bytes=body,
            transport_failure=None,
            stream_state=ProviderStreamState.COMPLETE,
            binding=binding,
            elapsed_ms=1,
        )


def test_matching_observations_wrap_actual_simulated_core_and_whitelist_result() -> None:
    expected = _identity()
    transport = _CompletedZeroTransport()
    result = execute_public_core_case(
        case=CoreCase.PYTHON_SAFE,
        inputs=_inputs(),
        expected_backend=expected,
        observe_backend=lambda: _observation(expected),
        simulated_transport=transport,
    )

    document = source_free_execution_document(result)
    assert result.measurement_valid and result.origin is ExecutionOrigin.SIMULATED
    assert result.production_admitted is False and transport.calls == 3
    assert _mapping(document["discovery"])["state"] == "SUCCEEDED"
    assert _mapping(document["fixture"])["manifest"]
    assert "candidates" not in json.dumps(document)


def test_source_free_receipt_binds_opt_in_sampling_provider_and_configuration() -> None:
    from tests.unit.test_public_core_runner import _inputs as diagnostic_inputs

    inputs = diagnostic_inputs(diagnostic_sampling=True)
    assert inputs.profile.model_snapshot is not None
    expected = _identity(
        model_id=inputs.profile.model_id,
        model_manifest_sha256=inputs.profile.model_snapshot,
    )
    result = execute_public_core_case(
        case=CoreCase.PYTHON_SAFE,
        inputs=inputs,
        expected_backend=expected,
        observe_backend=lambda: _observation(expected),
        simulated_transport=_CompletedZeroTransport(),
    )

    document = source_free_execution_document(result)
    assert document["provider_profile"] == {
        "component_id": inputs.provider_pin.component_id,
        "component_version": inputs.provider_pin.component_version,
        "content_sha256": inputs.provider_pin.content_sha256,
    }
    assert document["configuration"] == {
        "component_id": inputs.artifacts.configuration.component_id,
        "component_version": inputs.artifacts.configuration.component_version,
        "content_sha256": inputs.artifacts.configuration.content_sha256,
    }
    assert document["sampling"] == {
        "enabled": True,
        "applies_to": "native_discovery",
        "temperature": 0.0,
        "seed": 7,
        "model_id": inputs.profile.model_id,
        "model_snapshot": inputs.profile.model_snapshot,
    }
    assert "host artifact" not in json.dumps(document)


class _ScriptedTransport:
    def __init__(self, bodies: list[bytes]) -> None:
        self._bodies = list(bodies)
        self.calls = 0

    def connect(self, **kwargs: object) -> _Channel:
        del kwargs
        self.calls += 1
        return _Channel()

    def send(
        self,
        channel: object,
        *,
        binding: ProviderAttemptBinding,
        **kwargs: object,
    ) -> ProviderAttempt:
        from securecode_ai.adapters.model import ProviderStreamState
        from securecode_ai.contracts import ApiDialect

        del channel
        if not self._bodies:
            raise AssertionError("unexpected provider send")
        return ProviderAttempt(
            dialect=ApiDialect.OPENAI_COMPATIBLE,
            http_status=200,
            response_bytes=self._bodies.pop(0),
            transport_failure=None,
            stream_state=ProviderStreamState.COMPLETE,
            binding=binding,
            elapsed_ms=1,
        )


def _reply(payload: object) -> bytes:
    return json.dumps(
        {
            "id": "chatcmpl_execution",
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


@pytest.mark.parametrize("post_fault", [None, OSError, TimeoutError])
def test_native_candidate_and_auditor_are_retained_without_source_or_rationale(
    post_fault: type[OSError] | None,
) -> None:
    from securecode_ai.adapters.public_core_fixtures import build_public_core_fixture

    from tests.unit.test_public_core_runner import _native_selection

    expected = _identity()
    fixture = build_public_core_fixture(CoreCase.PYTHON_SAFE)
    anchor = fixture.catalogue.anchors[0]
    discovery = {
        "candidates": [
            {
                "rule_id": "cwe-89-sql-interpolation",
                "root_evidence_id": anchor.evidence_id,
                "evidence_ids": [anchor.evidence_id],
            }
        ]
    }
    auditor = {
        "finding_verdict": "CONFIRMED",
        "cited_evidence_ids": [anchor.evidence_id],
        "rationale": "provider text must not be retained",
    }
    transport = _ScriptedTransport(
        [
            _native_selection(fixture, "call-discovery-1"),
            _native_selection(fixture, "call-discovery-2"),
            _reply(discovery),
            _reply(auditor),
        ]
    )
    calls = 0

    def observer() -> BackendObservation:
        nonlocal calls
        calls += 1
        if post_fault and calls == 2:
            raise post_fault("hidden listener detail")
        return _observation(expected)

    result = execute_public_core_case(
        case=CoreCase.PYTHON_SAFE,
        inputs=_inputs(),
        expected_backend=expected,
        observe_backend=observer,
        simulated_transport=transport,
    )

    document = source_free_execution_document(result)
    assert result.run is not None and transport.calls == 4
    discovery_document = _mapping(document["discovery"])
    auditors = _sequence(document["auditors"])
    assert discovery_document["candidate_count"] == len(auditors) == 1
    assert _mapping(auditors[0])["finding_verdict"] == "CONFIRMED"
    retained = json.dumps(document, ensure_ascii=True, sort_keys=True)
    assert "provider text must not be retained" not in retained
    assert "candidate_id" not in retained and "package" not in retained
    if post_fault:
        assert result.failure_code == "POST_OBSERVATION_FAILED"
        assert discovery_document["state"] == "SUCCEEDED"
    else:
        assert result.measurement_valid
