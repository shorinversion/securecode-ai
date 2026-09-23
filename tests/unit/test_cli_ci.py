"""P5.1 connected CI command: terminal outcome to stable process status."""

from __future__ import annotations

import json
from collections.abc import Mapping
from io import StringIO

import pytest
from securecode_ai.cli import application
from securecode_ai.cli.connected import (
    ConnectedCliError,
    ConnectedCliErrorCode,
    ConnectedRunReceipt,
    ConnectedRunSettings,
)
from securecode_ai.contracts import CliCommand, CliErrorCode, CliErrorResult, CliExitCode

_ENVIRONMENT = {
    "SECURECODE_CONTROL_PLANE_URL": "http://127.0.0.1:8080",
    "SECURECODE_CONTROL_PLANE_TOKEN": "t" * 40,
    "SECURECODE_TENANT_ID": "tenant",
    "SECURECODE_REPOSITORY_ID": "repo",
    "SECURECODE_HEAD_SHA": "a" * 40,
}


def _receipt(outcome: str) -> ConnectedRunReceipt:
    return ConnectedRunReceipt(
        run_id="run-1",
        disposition="ADMITTED",
        lifecycle="COMPLETED",
        head_sha="a" * 40,
        outcome=outcome,
        state_version=2,
    )


def _invoke(
    argv: list[str], *, environment: Mapping[str, str] = _ENVIRONMENT
) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    code = application.main(
        argv,
        stdout=stdout,
        stderr=stderr,
        environment=environment,
        correlation_id_factory=lambda: "ci-correlation",
    )
    return code, stdout.getvalue(), stderr.getvalue()


@pytest.mark.parametrize(
    ("outcome", "expected"),
    (
        ("PASS", CliExitCode.COMPLETED),
        ("FAIL", CliExitCode.POLICY_FAIL),
        ("INDETERMINATE", CliExitCode.INDETERMINATE),
        ("ERROR", CliExitCode.OPERATIONAL_ERROR),
        ("CANCELLED", CliExitCode.CANCELLED_OR_SUPERSEDED),
        ("SUPERSEDED", CliExitCode.CANCELLED_OR_SUPERSEDED),
        ("FUTURE_OUTCOME", CliExitCode.INDETERMINATE),
    ),
)
def test_ci_waits_and_maps_terminal_outcomes(
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
    expected: CliExitCode,
) -> None:
    observed: dict[str, object] = {}

    def run(
        settings: ConnectedRunSettings,
        *,
        poll_status: bool,
        attempts: int,
        sleeper: object,
    ) -> ConnectedRunReceipt:
        observed["settings"] = settings
        observed["poll_status"] = poll_status
        observed["attempts"] = attempts
        observed["sleeper"] = sleeper
        return _receipt(outcome)

    monkeypatch.setattr(application, "run_connected", run)
    code, stdout, stderr = _invoke(["ci", "--json"])

    assert code == expected
    assert json.loads(stdout)["outcome"] == outcome
    assert stdout.endswith("\n") and stdout.count("\n") == 1
    assert stderr == ""
    assert observed["poll_status"] is True
    assert observed["attempts"] == 40
    assert callable(observed["sleeper"])


@pytest.mark.parametrize(
    ("error_code", "expected_error", "expected_exit"),
    (
        (
            ConnectedCliErrorCode.INVALID_CONFIGURATION,
            CliErrorCode.INVALID_CONFIG,
            CliExitCode.INVALID_USAGE_OR_CONFIG,
        ),
        (
            ConnectedCliErrorCode.RUN_NOT_TERMINAL,
            CliErrorCode.ANALYSIS_INDETERMINATE,
            CliExitCode.INDETERMINATE,
        ),
        (
            ConnectedCliErrorCode.PROTOCOL_INVALID,
            CliErrorCode.ANALYSIS_INDETERMINATE,
            CliExitCode.INDETERMINATE,
        ),
        (
            ConnectedCliErrorCode.UNREACHABLE,
            CliErrorCode.OPERATIONAL_ERROR,
            CliExitCode.OPERATIONAL_ERROR,
        ),
    ),
)
def test_ci_failures_use_the_ci_error_contract(
    monkeypatch: pytest.MonkeyPatch,
    error_code: ConnectedCliErrorCode,
    expected_error: CliErrorCode,
    expected_exit: CliExitCode,
) -> None:
    def fail(
        _settings: ConnectedRunSettings,
        *,
        poll_status: bool,
        attempts: int,
        sleeper: object,
    ) -> ConnectedRunReceipt:
        assert poll_status and attempts == 40 and callable(sleeper)
        raise ConnectedCliError(error_code)

    monkeypatch.setattr(application, "run_connected", fail)
    code, stdout, stderr = _invoke(["ci", "--json"])

    result = CliErrorResult.model_validate_json(stdout)
    assert code == expected_exit
    assert result.command is CliCommand.CI
    assert result.error.error_code is expected_error
    assert stderr == ""


def test_ci_requires_configuration_and_help_is_available() -> None:
    code, stdout, stderr = _invoke(["ci", "--json"], environment={})
    result = CliErrorResult.model_validate_json(stdout)
    assert code == CliExitCode.INVALID_USAGE_OR_CONFIG
    assert result.command is CliCommand.CI
    assert result.error.error_code is CliErrorCode.INVALID_CONFIG
    assert stderr == ""

    help_code, help_text, help_error = _invoke(["ci", "--help"])
    assert help_code == CliExitCode.COMPLETED
    assert help_text.startswith("usage: securecode ci ")
    assert help_error == ""
