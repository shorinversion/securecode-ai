"""Findings of the 1.2.7 E2E series: chat sites, foreign-owned checkouts, opaque failures."""

from __future__ import annotations

import io
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from securecode_ai.adapters import git_trust
from securecode_ai.adapters.config import parse_provider_profile
from securecode_ai.adapters.local_product_runner_config import LocalProductUnavailableError
from securecode_ai.adapters.local_product_trial import TrialAnalysisError, operator_endpoint
from securecode_ai.cli import analyze

from tests.unit.test_operator_provider import _ENVIRONMENT


@pytest.mark.parametrize("url", ["https://chat.deepseek.com", "https://chat.example-vendor.ai/v1"])
def test_operator_endpoint_refuses_a_chat_site(url: str) -> None:
    with pytest.raises(TrialAnalysisError, match="chat web site"):
        operator_endpoint(_ENVIRONMENT | {"SECURECODE_MODEL_BASE_URL": url})


def test_contract_refuses_vendor_chat_products_but_not_their_apis() -> None:
    from securecode_ai.adapters import local_product_trial as trial

    profile = trial._operator_profile(operator_endpoint(_ENVIRONMENT)).model_dump(mode="json")

    def parse(host: str) -> object:
        data = json.loads(json.dumps(profile))
        data["endpoint"].update(base_url=f"https://{host}/v1", authority=host)
        return parse_provider_profile(json.dumps(data))

    for host in ("chat.deepseek.com", "kimi.com", "www.perplexity.ai"):
        with pytest.raises(ValueError):
            parse(host)
    for host in ("api.deepseek.com", "api.perplexity.ai", "openrouter.ai"):
        parse(host)


def _run(monkeypatch: pytest.MonkeyPatch, error: Exception) -> tuple[int, str]:
    def fail(*_args: object, **_kwargs: object) -> object:
        raise error

    monkeypatch.setattr(analyze, "run_trial_analysis", fail)
    stdout, stderr = io.StringIO(), io.StringIO()
    code = analyze.run_analyze_command(
        ("analyze", "."), stdout=stdout, stderr=stderr, environment={}
    )
    return code, stderr.getvalue()


def test_a_revision_without_supported_source_is_explained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code, message = _run(monkeypatch, LocalProductUnavailableError("NO_SUPPORTED_SOURCE"))

    assert code == 4
    assert "NO_SUPPORTED_SOURCE" in message and "no supported source file" in message


def test_a_failed_git_command_names_the_reason_and_the_remedy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code, message = _run(monkeypatch, LocalProductUnavailableError("GIT_COMMAND_FAILED"))

    assert code == 3
    assert "GIT_COMMAND_FAILED" in message and "safe.directory" in message


def test_an_unknown_reason_is_still_printed(monkeypatch: pytest.MonkeyPatch) -> None:
    code, message = _run(monkeypatch, LocalProductUnavailableError("WORKFLOW_START_FAILED"))

    assert code == 3 and "WORKFLOW_START_FAILED" in message


def _trust(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, owned: bool, accepted: bool
) -> dict[str, str]:
    git_trust.operator_safe_directory.cache_clear()
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> object:
        calls.append(command)
        sealed = "GIT_CONFIG_GLOBAL" in (kwargs.get("env") or {})  # type: ignore[operator]
        refused = (not owned) if sealed else (not accepted)
        return SimpleNamespace(returncode=128 if refused else 0)

    monkeypatch.setattr(subprocess, "run", run)
    if hasattr(os, "geteuid"):
        uid = tmp_path.stat().st_uid
        monkeypatch.setattr(os, "geteuid", lambda: uid if owned else uid + 1)
    return git_trust.operator_safe_directory(tmp_path, Path("git"))


def test_own_checkout_keeps_git_configuration_sealed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert _trust(monkeypatch, tmp_path, owned=True, accepted=True) == {"GIT_CONFIG_COUNT": "0"}


def test_foreign_checkout_trusted_by_the_operator_gets_only_safe_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entries = _trust(monkeypatch, tmp_path, owned=False, accepted=True)

    assert entries == {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": str(tmp_path.resolve()),
    }


def test_foreign_checkout_the_operator_does_not_trust_stays_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert _trust(monkeypatch, tmp_path, owned=False, accepted=False) == {"GIT_CONFIG_COUNT": "0"}
    git_trust.operator_safe_directory.cache_clear()


def test_machine_json_carries_the_model_cost() -> None:
    composition = SimpleNamespace(flow=None, review=None, host_inputs=None)
    known = json.loads(analyze._machine_json(b'{"findings": []}', composition, 12_500))  # type: ignore[arg-type]
    unknown = json.loads(analyze._machine_json(b'{"findings": []}', composition, None))  # type: ignore[arg-type]

    assert known["model_cost"] == {"usd": 0.0125, "known": True}
    assert unknown["model_cost"] == {"usd": None, "known": False}
    assert known["covered_candidates"] == [] and known["undecided_covered"] == 0
