"""Actual immutable local runner composition and source-free boundaries."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
from securecode_ai.adapters import local_product_host as host_module
from securecode_ai.adapters import local_product_runner as runner

from tests.unit.test_local_product_host import synthetic_anchor


def test_local_configuration_uses_admitted_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    anchor = synthetic_anchor()
    monkeypatch.setattr(host_module, "_read_platform_anchor", lambda: anchor)
    host = host_module.load_local_product_host()
    selected = runner.resolve_local_product_configuration(host)
    assert selected.provider_profile == host.profile


def test_config_selection_precedence_and_security_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    anchor = synthetic_anchor()
    monkeypatch.setattr(host_module, "_read_platform_anchor", lambda: anchor)
    host = host_module.load_local_product_host()
    selections = {"provider_profile": host.profile.selector}
    selected = runner.resolve_local_product_configuration(
        host,
        user=selections,
        repository=selections,
        environment={"SECURECODE_PROVIDER_PROFILE": host.profile.selector},
        cli=selections,
    )
    assert (
        next(item.source.value for item in selected.provenance if item.key == "provider_profile")
        == "cli"
    )
    selected = runner.resolve_local_product_configuration(
        host,
        user=selections,
        repository=selections,
        environment={"SECURECODE_PROVIDER_PROFILE": host.profile.selector},
    )
    assert (
        next(item.source.value for item in selected.provenance if item.key == "provider_profile")
        == "environment"
    )
    with pytest.raises(runner.LocalProductConfigurationError):
        runner.resolve_local_product_configuration(
            host, repository={"data_class": "DC1_PUBLIC"}, cli=selections
        )


@pytest.mark.parametrize(
    "purpose", ["model_native_discovery", "candidate_investigation", "skeptic_review"]
)
def test_each_missing_dc3_purpose_denies_before_source_objects(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, purpose: str
) -> None:
    from securecode_ai.contracts import EgressPolicyDocument
    from securecode_ai.core.reports import ReportFormat
    from securecode_ai.core.runtime import build_default_workflow_definition

    anchor = synthetic_anchor()
    monkeypatch.setattr(host_module, "_read_platform_anchor", lambda: anchor)
    host = host_module.load_local_product_host()
    data = host.policy.model_dump(mode="json")
    data["rules"][0]["purposes"].remove(purpose)
    policy = EgressPolicyDocument.model_validate_json(json.dumps(data))
    pin = runner._pin(policy.policy_id, policy.policy_version, policy.canonical_content_hash())
    host = replace(
        host,
        policy=policy,
        artifact_manifest={
            **host.artifact_manifest,
            "workflow_sha256": build_default_workflow_definition(
                policy_pin=pin
            ).component_pin.content_sha256,
        },
    )
    monkeypatch.setattr(
        runner, "verify_local_git_executable", lambda digest: Path(__file__).absolute()
    )
    monkeypatch.setattr(
        runner,
        "_git",
        lambda root, executable, *args: str(tmp_path) if "--show-toplevel" in args else "a" * 40,
    )
    monkeypatch.setattr(
        runner, "OfflineGitObjectReader", lambda **kwargs: pytest.fail("source reader admitted")
    )
    with pytest.raises(runner.LocalProductUnavailableError):
        runner.run_local_product_scan(
            host=host,
            target=str(tmp_path),
            report_format=ReportFormat.JSON,
            configuration=runner.resolve_local_product_configuration(host),
        )


def test_retained_graph_reference_uses_flow_identity_not_run_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A finding must cite the actual retained graph, never a derived run label."""
    from tests.unit.test_evidence_graph import HEAD, TENANT, _graph

    graph = _graph(graph_id="retained-graph-1")
    graph_bytes, reference = runner._retain_evidence_graph(
        graph=graph, tenant_id=TENANT, head_sha=HEAD
    )
    assert reference.content_id == graph.graph_id
    assert reference.content_id != "local-run-1-graph"
    assert reference.content_sha256 == graph.graph_sha256
    assert reference.size_bytes == len(graph_bytes)


def test_retained_graph_reference_rejects_foreign_revision_binding() -> None:
    from tests.unit.test_evidence_graph import HEAD, TENANT, _graph

    with pytest.raises(runner.LocalProductUnavailableError):
        runner._retain_evidence_graph(graph=_graph(), tenant_id=TENANT, head_sha="b" * len(HEAD))
