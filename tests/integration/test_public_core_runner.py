"""Independent exact-destination boundary checks for public Core composition."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("authority", "port"),
    [
        ("127.0.0.1", 11434),
        ("localhost", 11435),
        ("127.0.0.2", 11435),
        ("::1", 11435),
        ("example.com", 11435),
        ("10.0.0.1", 11435),
        ("127.0.0.1", True),
    ],
)
def test_public_resolver_rejects_unpinned_destination_without_dns(
    monkeypatch: pytest.MonkeyPatch, authority: str, port: int
) -> None:
    def unexpected_dns(*args: object, **kwargs: object) -> None:
        pytest.fail("literal resolver consulted DNS")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected_dns)
    from securecode_ai.adapters.public_core_runner import PinnedLiteralLoopbackResolver

    resolver = PinnedLiteralLoopbackResolver(authority="127.0.0.1", port=11435)
    with pytest.raises(ValueError):
        resolver.resolve(authority, port)


def test_public_resolver_returns_only_pinned_literal_without_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_dns(*args: object, **kwargs: object) -> None:
        pytest.fail("literal resolver consulted DNS")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected_dns)
    from securecode_ai.adapters.public_core_runner import PinnedLiteralLoopbackResolver

    resolver = PinnedLiteralLoopbackResolver(authority="127.0.0.1", port=11435)
    assert resolver.resolve("127.0.0.1", 11435) == ("127.0.0.1",)


@pytest.mark.parametrize("size", [0, 1024 * 1024 + 1])
def test_cli_bounds_host_input_bytes(tmp_path: Path, size: int) -> None:
    from scripts.public_core_conformance import _read_host_input

    path = tmp_path / "invalid-host-input.json"
    path.write_bytes(b"x" * size)
    with pytest.raises(ValueError, match=r"^public Core host input is invalid$"):
        _read_host_input(path)


def test_cli_reports_only_fixed_error_for_invalid_host_documents(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from scripts.public_core_conformance import main

    path = tmp_path / "invalid-host-input.json"
    path.write_bytes(b"invalid-private-shaped-canary")
    status = main(
        [
            "--preflight",
            "--profile",
            str(path),
            "--policy",
            str(path),
            "--artifacts",
            str(path),
            "--case",
            "python_vulnerable",
        ]
    )
    output = capsys.readouterr()
    assert status == 3
    assert output.out == ""
    assert output.err == "PUBLIC_CORE_PREFLIGHT_INPUT_OR_EVALUATION_FAILED\n"


@pytest.mark.parametrize("eligible", [False, True])
def test_cli_preflight_never_reports_product_success_or_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    eligible: bool,
) -> None:
    import json
    import sys
    from types import ModuleType

    from securecode_ai.adapters.local_provider_admission import CoreCase
    from securecode_ai.contracts import (
        AuditRunOutcome,
        ModelPreflightResult,
        PreflightEligibility,
        PreflightNextAction,
    )

    from scripts.public_core_conformance import main

    result = ModelPreflightResult(
        schema_version="0.2.0",
        eligibility=PreflightEligibility.ELIGIBLE if eligible else PreflightEligibility.INELIGIBLE,
        preflight_context_bytes=0,
        preflight_network_bytes=0,
        next_action=(
            PreflightNextAction.CONTINUE_DUAL_LANE
            if eligible
            else PreflightNextAction.STOP_BEFORE_CONTEXT_OR_NETWORK
        ),
        deterministic_only_fallback=False,
        required_terminal_outcome=None if eligible else AuditRunOutcome.INDETERMINATE,
        reason_codes=() if eligible else ("PREFLIGHT_INELIGIBLE",),
    )
    marker = object()
    observed: list[dict[str, object]] = []
    seam = ModuleType("securecode_ai.adapters.public_core_runner")

    def load(**kwargs: object) -> object:
        observed.append(kwargs)
        return marker

    def preflight(*, case: CoreCase, inputs: object) -> ModelPreflightResult:
        assert inputs is marker
        assert case.value == "python_vulnerable"
        return result

    # This is a presenter-only seam; it does not establish actual Core qualification.
    seam.__dict__["load_public_core_inputs"] = load
    seam.__dict__["preflight_public_core_case"] = preflight
    monkeypatch.setitem(sys.modules, seam.__name__, seam)
    path = tmp_path / "host-input.json"
    path.write_bytes(b"{}")
    status = main(
        [
            "--preflight",
            "--profile",
            str(path),
            "--policy",
            str(path),
            "--artifacts",
            str(path),
            "--case",
            "python_vulnerable",
        ]
    )
    output = capsys.readouterr()
    document = json.loads(output.out)
    assert output.err == ""
    assert status == (0 if eligible else 2)
    assert len(observed) == 1
    assert document["model_invocations"] == 0
    assert document["production_admitted"] is False
    assert document["product_outcome"] == "NOT_EVALUATED"
    assert document["preflight"]["preflight_context_bytes"] == 0
    assert document["preflight"]["preflight_network_bytes"] == 0
    if not eligible:
        assert document["preflight"]["required_terminal_outcome"] == "INDETERMINATE"


@pytest.mark.parametrize("eligible", [False, True])
@pytest.mark.parametrize(
    "exercise_core, foreign_producer", [(False, False), (True, False), (True, True)]
)
def test_actual_host_factory_preflight_matches_declared_profile_without_network(
    monkeypatch: pytest.MonkeyPatch,
    eligible: bool,
    exercise_core: bool,
    foreign_producer: bool,
) -> None:
    import base64
    import json
    from pathlib import Path

    from securecode_ai.adapters.local_provider_admission import CoreCase
    from securecode_ai.adapters.public_core_runner import (
        load_public_core_inputs,
        prepare_public_core_case,
    )
    from securecode_ai.contracts import EgressPolicyDocument, PreflightEligibility

    root = Path(__file__).resolve().parents[2]
    profile_data = json.loads(
        (root / "specs/contracts/provider-fixtures/valid.local-openai-compatible.json").read_bytes()
    )
    profile_data["endpoint"]["base_url"] = "http://127.0.0.1:11435/v1"
    profile_data["endpoint"]["allowed_ports"] = [11435]
    profile_data["capabilities"]["source_code_analysis"] = eligible
    policy_data = json.loads(
        (
            root / "specs/contracts/policy/fixtures/egress.valid.private-model-source.json"
        ).read_bytes()
    )
    policy_data["tenant_scope"] = "synthetic-public-development"
    policy_data["rules"][0]["purposes"].append("candidate_investigation")
    policy = EgressPolicyDocument.model_validate_json(json.dumps(policy_data))
    policy_bytes = policy.canonical_bytes()
    names = (
        "stage_catalogue",
        "workflow",
        "policy",
        "configuration",
        "tool_policy",
        "repository_scope",
        "repository_view_policy",
        "producer",
    )
    document = {
        name: base64.b64encode(
            policy_bytes
            if name == "policy"
            else (
                (
                    root / "packages/adapters/src/securecode_ai/adapters/product_runtime.py"
                ).read_bytes()
                if name == "producer" and not foreign_producer
                else f"explicit simulated artifact: {name}".encode()
            )
        ).decode("ascii")
        for name in names
    }

    def unexpected_socket(*args: object, **kwargs: object) -> None:
        pytest.fail("preflight opened a provider socket")

    monkeypatch.setattr(socket, "socket", unexpected_socket)
    inputs = load_public_core_inputs(
        profile_bytes=json.dumps(profile_data).encode(),
        policy_bytes=policy_bytes,
        artifacts_bytes=json.dumps(document).encode(),
        gateway_port=11435,
    )
    prepared = prepare_public_core_case(case=CoreCase.PYTHON_VULNERABLE, inputs=inputs)
    assert prepared.preflight.eligibility is (
        PreflightEligibility.ELIGIBLE if eligible else PreflightEligibility.INELIGIBLE
    )
    assert inputs.profile.capabilities.source_code_analysis is eligible
    assert prepared.request.head_sha == prepared.fixture.head_sha
    assert prepared.request.tenant_id == prepared.fixture.catalogue.anchors[0].tenant_id
    assert prepared.preflight.preflight_context_bytes == 0
    assert prepared.preflight.preflight_network_bytes == 0

    if exercise_core:
        from securecode_ai.adapters.local_provider_admission import EvidenceOrigin
        from securecode_ai.adapters.product_scan import ProductCandidateFlow
        from securecode_ai.adapters.public_core_runner import run_public_core_case
        from securecode_ai.contracts import AuditRunOutcome

        class FailingSimulatedTransport:
            def __init__(self) -> None:
                self.calls = 0

            def connect(self, **kwargs: object) -> None:
                self.calls += 1
                raise RuntimeError("simulated provider unavailable")

            def send(self, *args: object, **kwargs: object) -> None:
                pytest.fail("unconnected provider was sent context")

        transport = FailingSimulatedTransport()
        run = run_public_core_case(
            case=CoreCase.PYTHON_VULNERABLE, inputs=inputs, simulated_transport=transport
        )
        assert run.origin is EvidenceOrigin.SIMULATED
        assert run.production_admitted is False
        if eligible and foreign_producer:
            assert transport.calls == 0
            assert run.flow is None
            assert run.failure_code == "COMPOSITION_FAILED"
            assert not run.completed
        elif eligible:
            assert transport.calls > 0
            assert type(run.flow) is ProductCandidateFlow
            assert run.flow.required_terminal_outcome is AuditRunOutcome.INDETERMINATE
        else:
            assert transport.calls == 0
            assert run.flow is None
