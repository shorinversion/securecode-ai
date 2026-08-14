"""In-process grammar, stream, redaction, and zero-effect CLI oracles."""

from __future__ import annotations

import json
import socket
import subprocess
from collections.abc import Iterator, Mapping
from io import StringIO
from pathlib import Path
from typing import Any, cast

import pytest
from securecode_ai.cli.application import (
    CLI_VERSION,
    FOUNDATION_PROFILE_CONTENT_SHA256,
    FOUNDATION_PROFILE_SELECTOR,
    FoundationDoctor,
    build_foundation_profile,
    main,
)
from securecode_ai.contracts import CliCommand, CliErrorCode, CliErrorResult, CliExitCode


def _run(
    argv: list[str],
    *,
    environment: Mapping[str, str] | None = None,
    doctor: object | None = None,
) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    code = main(
        argv,
        stdout=stdout,
        stderr=stderr,
        environment={} if environment is None else environment,
        doctor=doctor,  # type: ignore[arg-type]
        correlation_id_factory=lambda: "correlation",
    )
    return code, stdout.getvalue(), stderr.getvalue()


def _machine_result(stdout: str) -> dict[str, Any]:
    assert stdout.endswith("\n")
    assert stdout.count("\n") == 1
    return cast(dict[str, Any], json.loads(stdout))


@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_help_is_bounded_human_stdout(flag: str) -> None:
    code, stdout, stderr = _run([flag])
    assert code == CliExitCode.COMPLETED
    assert "doctor" in stdout
    assert "scan" not in stdout
    assert "fix" not in stdout
    assert stderr == ""


def test_version_is_bounded_human_stdout() -> None:
    code, stdout, stderr = _run(["--version"])
    assert (code, stdout, stderr) == (0, f"securecode {CLI_VERSION}\n", "")


def test_human_doctor_success_uses_only_one_stderr_line() -> None:
    code, stdout, stderr = _run(["doctor"])
    assert code == 0
    assert stdout == ""
    assert stderr == (
        "foundation configuration diagnostics completed; scan readiness was not evaluated\n"
    )


@pytest.mark.parametrize("argv", [["doctor", "--json"], ["--json", "doctor"]])
def test_machine_doctor_success_is_one_json_line(argv: list[str]) -> None:
    code, stdout, stderr = _run(argv)
    payload = _machine_result(stdout)
    assert code == 0
    assert stderr == ""
    assert payload["command"] == "doctor"
    assert payload["scan_readiness"] == "NOT_EVALUATED"
    assert len(payload["checks"]) == 4


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["unknown"],
        ["doctor", "--unknown"],
        ["doctor", "extra"],
        ["--json", "--json", "doctor"],
        ["doctor", "--help"],
    ],
)
def test_invalid_human_or_nonmachine_grammar_is_safe(argv: list[str]) -> None:
    code, stdout, stderr = _run(argv)
    assert code == 5
    assert stdout == ""
    assert stderr == "command-line usage is invalid\n"
    assert not any(token in stderr for token in argv if token not in {"doctor"})


@pytest.mark.parametrize(
    "argv",
    [
        ["--json"],
        ["--json", "unknown"],
        ["unknown", "--json"],
        ["doctor", "--unknown", "--json"],
        ["--json", "--help"],
        ["--json", "--version"],
    ],
)
def test_invalid_machine_grammar_is_one_safe_error_object(argv: list[str]) -> None:
    code, stdout, stderr = _run(argv)
    _machine_result(stdout)
    assert code == 5
    assert stderr == ""
    result = CliErrorResult.model_validate_json(stdout)
    assert result.error.error_code is CliErrorCode.INVALID_USAGE
    stripped = [token for token in argv if token != "--json"]
    try:
        expected = CliCommand(stripped[0]) if stripped else None
    except ValueError:
        expected = None
    assert result.command is expected
    assert not any(token in stdout for token in argv if token not in {"--json", "doctor"})


@pytest.mark.parametrize(
    "environment",
    [
        {"SECURECODE_PROVIDER_PROFILE": "unknown-canary"},
        {"SECURECODE_EGRESS_PROFILE": "private-model-canary"},
        {"SECURECODE_POLICY_PROFILE": ""},
        {"SECURECODE_LLM_URL": "secret-canary"},
    ],
)
def test_invalid_environment_is_redacted_and_fail_closed(environment: dict[str, str]) -> None:
    code, stdout, stderr = _run(["doctor", "--json"], environment=environment)
    _machine_result(stdout)
    result = CliErrorResult.model_validate_json(stdout)
    assert code == 5
    assert stderr == ""
    assert result.error.error_code is CliErrorCode.INVALID_CONFIG
    assert not any(value and value in stdout for value in environment.values())


@pytest.mark.parametrize(
    ("argv", "expected_command"),
    [
        (["unknown-canary", "doctor", "--json"], None),
        (["--json", "unknown-canary", "doctor"], None),
        (["scan", "--json"], CliCommand.SCAN),
        (["doctor", "unknown-canary", "--json"], CliCommand.DOCTOR),
    ],
)
def test_invalid_machine_command_attribution_uses_only_command_position(
    argv: list[str], expected_command: CliCommand | None
) -> None:
    code, stdout, stderr = _run(argv)
    result = CliErrorResult.model_validate_json(stdout)
    assert code == 5
    assert stderr == ""
    assert result.command is expected_command
    assert "unknown-canary" not in stdout


@pytest.mark.parametrize(
    "capability",
    [
        "structured_output",
        "native_refusal_signal",
        "native_incomplete_signal",
        "source_code_analysis",
    ],
)
def test_each_required_capability_false_is_incompatible(capability: str) -> None:
    profile = build_foundation_profile()
    changed_capabilities = profile.capabilities.model_copy(update={capability: False})
    changed = profile.model_copy(update={"capabilities": changed_capabilities})
    code, stdout, stderr = _run(["doctor", "--json"], doctor=FoundationDoctor(profile=changed))
    _machine_result(stdout)
    result = CliErrorResult.model_validate_json(stdout)
    assert code == 5
    assert stderr == ""
    assert result.error.error_code is CliErrorCode.CAPABILITY_INCOMPATIBLE


def test_foundation_profile_selector_and_hash_are_exact_and_mutation_rejects() -> None:
    profile = build_foundation_profile()
    assert profile.selector == FOUNDATION_PROFILE_SELECTOR
    assert profile.canonical_content_hash() == FOUNDATION_PROFILE_CONTENT_SHA256
    changed = profile.model_copy(update={"model_id": "mutated-profile"})
    code, stdout, stderr = _run(["doctor", "--json"], doctor=FoundationDoctor(profile=changed))
    _machine_result(stdout)
    result = CliErrorResult.model_validate_json(stdout)
    assert code == 5
    assert stderr == ""
    assert result.error.error_code is CliErrorCode.INVALID_CONFIG


class _ExplodingDoctor:
    def __init__(self, error: BaseException) -> None:
        self._error = error

    def run(self, environment: Mapping[str, str]) -> Any:
        raise self._error


class _StaticDoctor:
    def __init__(self, result: object) -> None:
        self._result = result

    def run(self, environment: Mapping[str, str]) -> Any:
        return self._result


@pytest.mark.parametrize(
    ("error", "expected_code", "expected_exit"),
    [
        (RuntimeError("exception-canary"), CliErrorCode.INTERNAL_ERROR, 4),
        (KeyboardInterrupt("interrupt-canary"), CliErrorCode.CANCELLED, 6),
    ],
)
def test_exception_and_interrupt_are_typed_and_never_echoed(
    error: BaseException, expected_code: CliErrorCode, expected_exit: int
) -> None:
    code, stdout, stderr = _run(["doctor", "--json"], doctor=_ExplodingDoctor(error))
    _machine_result(stdout)
    result = CliErrorResult.model_validate_json(stdout)
    assert code == expected_exit
    assert stderr == ""
    assert result.error.error_code is expected_code
    assert "canary" not in stdout


def _forged_doctor_results() -> tuple[object, ...]:
    valid = FoundationDoctor().run({})
    hidden_check = valid.checks[0].model_copy(update={"hidden_canary": "secret"})
    return (
        valid.model_copy(update={"scan_readiness": "READY"}),
        valid.model_copy(update={"checks": ()}),
        valid.model_copy(update={"checks": tuple(reversed(valid.checks))}),
        valid.model_copy(update={"exit_code": 0}),
        valid.model_copy(update={"exit_code": True}),
        valid.model_copy(update={"hidden_canary": "secret"}),
        valid.model_copy(update={"checks": (hidden_check, *valid.checks[1:])}),
        {"scan_readiness": "NOT_EVALUATED"},
    )


@pytest.mark.parametrize("forged", _forged_doctor_results())
def test_forged_retained_doctor_state_is_internal_error_without_echo(forged: object) -> None:
    code, stdout, stderr = _run(["doctor", "--json"], doctor=_StaticDoctor(forged))
    result = CliErrorResult.model_validate_json(stdout)
    assert code == 4
    assert stderr == ""
    assert result.error.error_code is CliErrorCode.INTERNAL_ERROR
    assert "READY" not in stdout
    assert "canary" not in stdout


class _ReadSpyEnvironment(Mapping[str, str]):
    def __init__(self) -> None:
        self.read_keys: list[str] = []
        self._values = {"OPENAI_API_KEY": "credential-canary", "UNRELATED": "value"}

    def __getitem__(self, key: str) -> str:
        self.read_keys.append(key)
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


def test_doctor_has_zero_network_process_source_or_credential_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def bomb(*args: object, **kwargs: object) -> None:
        raise AssertionError("zero-effect probe was touched")

    monkeypatch.setattr(socket, "getaddrinfo", bomb)
    monkeypatch.setattr(socket, "socket", bomb)
    monkeypatch.setattr(subprocess, "Popen", bomb)
    monkeypatch.setattr(subprocess, "run", bomb)
    monkeypatch.setattr("builtins.open", bomb)
    monkeypatch.setattr(Path, "open", bomb)
    monkeypatch.setattr(Path, "read_bytes", bomb)
    monkeypatch.setattr(Path, "read_text", bomb)
    environment = _ReadSpyEnvironment()
    result = FoundationDoctor().run(environment)
    assert result.exit_code is CliExitCode.COMPLETED
    assert "OPENAI_API_KEY" not in environment.read_keys
    assert set(environment.read_keys) <= {
        "SECURECODE_PROVIDER_PROFILE",
        "SECURECODE_POLICY_PROFILE",
        "SECURECODE_EGRESS_PROFILE",
    }


def test_explicit_empty_environment_does_not_fall_back_to_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURECODE_LLM_URL", "process-environment-canary")
    code, stdout, stderr = _run(["doctor", "--json"], environment={})
    assert code == 0
    assert stderr == ""
    assert "canary" not in stdout


def test_explicit_empty_defaults_fail_as_invalid_configuration() -> None:
    code, stdout, stderr = _run(["doctor", "--json"], doctor=FoundationDoctor(defaults={}))
    result = CliErrorResult.model_validate_json(stdout)
    assert code == 5
    assert stderr == ""
    assert result.error.error_code is CliErrorCode.INVALID_CONFIG
