"""Subprocess golden matrix for the installed P1.10 module entry point."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

_REAL_POPEN = subprocess.Popen


@pytest.fixture(autouse=True)
def _allow_bounded_cli_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)


def _invoke(*args: str) -> subprocess.CompletedProcess[str]:
    environment = {
        key: value for key, value in os.environ.items() if not key.upper().startswith("SECURECODE_")
    }
    return subprocess.run(
        [sys.executable, "-I", "-m", "securecode_ai.cli", *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        env=environment,
        timeout=30,
    )


@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_module_entrypoint_help(flag: str) -> None:
    completed = _invoke(flag)
    assert completed.returncode == 0
    assert "doctor" in completed.stdout
    assert completed.stderr == ""


def test_module_entrypoint_machine_doctor() -> None:
    completed = _invoke("doctor", "--json")
    assert completed.returncode == 0
    assert completed.stderr == ""
    assert completed.stdout.count("\n") == 1
    assert json.loads(completed.stdout)["scan_readiness"] == "NOT_EVALUATED"


def test_module_entrypoint_machine_missing_subcommand() -> None:
    completed = _invoke("--json")
    assert completed.returncode == 5
    assert completed.stderr == ""
    assert completed.stdout.count("\n") == 1
    payload = json.loads(completed.stdout)
    assert payload["command"] is None
    assert payload["error"]["error_code"] == "INVALID_USAGE"
