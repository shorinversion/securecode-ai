"""Fail-closed CLI foundation with explicit non-product diagnostic composition."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import TextIO

from securecode_ai.adapters import ConfigError
from securecode_ai.contracts import (
    CliCommand,
    CliErrorCode,
    CliExitCode,
)

from .application_commands import (
    _canonical_json,
    _command_help,
    _default_correlation_id,
    _error_result,
    _parser,
    _revalidate_doctor_result,
    _run_diagnostic_scan,
    _run_installed_product_scan,
    _run_repair_command,
    _write_error,
)
from .application_profiles import (
    _HUMAN_SUCCESS,
    CLI_VERSION,
    FOUNDATION_DEFAULTS,
    FOUNDATION_PROFILE_CONTENT_SHA256,
    FOUNDATION_PROFILE_SELECTOR,
    Doctor,
    FoundationCapabilityError,
    FoundationConfigurationError,
    FoundationDoctor,
    _DiagnosticScanArguments,
    build_foundation_profile,
)
from .approval import run_patch_approval_command
from .connected import (
    ConnectedCliError,
    cancel_run,
    fetch_results,
    fetch_run,
    parse_connected_arguments,
    parse_results_arguments,
    parse_run_arguments,
    run_connected,
    settings_from_environment,
)
from .connected import (
    render_receipt as render_connected_receipt,
)
from .diagnostic import (
    DeterministicDiagnostic,
)
from .release import run_release_command
from .repair import RepairCli
from .scan import execute_installed_product_scan

for _application_type in (
    FoundationConfigurationError,
    FoundationCapabilityError,
    _DiagnosticScanArguments,
    FoundationDoctor,
):
    _application_type.__module__ = __name__
del _application_type


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    environment: Mapping[str, str] | None = None,
    doctor: Doctor | None = None,
    diagnostic: DeterministicDiagnostic | None = None,
    repair: RepairCli | None = None,
    correlation_id_factory: Callable[[], str] = _default_correlation_id,
) -> int:
    """Execute the bounded P1.10 grammar and return one stable process code."""

    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    tokens = tuple(sys.argv[1:] if argv is None else argv)
    machine_count = sum(token == "--json" for token in tokens if isinstance(token, str))
    machine = machine_count == 1

    if any(not isinstance(token, str) for token in tokens):
        return _write_error(
            _error_result(CliErrorCode.INVALID_USAGE, None, correlation_id_factory),
            machine=False,
            stdout=output,
            stderr=errors,
        )

    stripped = tuple(token for token in tokens if token != "--json")
    selected_environment = os.environ if environment is None else environment
    try:
        command = CliCommand(stripped[0]) if stripped else None
    except ValueError:
        command = None
    if machine_count > 1 or (
        machine and any(token in {"-h", "--help", "--version"} for token in stripped)
    ):
        return _write_error(
            _error_result(CliErrorCode.INVALID_USAGE, command, correlation_id_factory),
            machine=machine,
            stdout=output,
            stderr=errors,
        )

    parser = _parser()
    if stripped in (("--help",), ("-h",)):
        output.write(parser.format_help())
        return int(CliExitCode.COMPLETED)
    if stripped == ("--version",):
        output.write(f"securecode {CLI_VERSION}\n")
        return int(CliExitCode.COMPLETED)
    if (
        len(stripped) == 2
        and stripped[1] in {"-h", "--help"}
        and stripped[0]
        in {
            "doctor",
            "scan",
            "fix",
            "validate",
            "approve",
            "release",
            "connect",
            "status",
            "cancel",
            "results",
        }
    ):
        output.write(_command_help(stripped[0]))
        return int(CliExitCode.COMPLETED)
    if stripped and stripped[0] == "results":
        return run_connected_results(
            stripped,
            stdout=output,
            stderr=errors,
            environment=selected_environment,
        )
    if stripped and stripped[0] in {"status", "cancel"}:
        return run_connected_inspection(
            stripped,
            stdout=output,
            stderr=errors,
            environment=selected_environment,
        )
    if stripped and stripped[0] == "connect":
        return run_connect_command(
            stripped,
            stdout=output,
            stderr=errors,
            environment=selected_environment,
        )
    if stripped and stripped[0] == "release":
        return run_release_command(stripped, stdout=output, stderr=errors)
    if stripped and stripped[0] == "approve":
        return run_patch_approval_command(
            stripped,
            stdout=output,
            stderr=errors,
            environment=selected_environment,
        )
    if stripped and stripped[0] == CliCommand.SCAN.value:
        if "--diagnostic" not in stripped:
            if repair is not None:
                return _run_repair_command(
                    stripped,
                    machine=machine,
                    stdout=output,
                    stderr=errors,
                    correlation_id_factory=correlation_id_factory,
                    repair=repair,
                    environment=selected_environment,
                )
            if diagnostic is not None:
                return _run_diagnostic_scan(
                    stripped,
                    machine=machine,
                    stdout=output,
                    stderr=errors,
                    correlation_id_factory=correlation_id_factory,
                    diagnostic=diagnostic,
                )
            return _run_installed_product_scan(
                stripped,
                machine=machine,
                stdout=output,
                stderr=errors,
                correlation_id_factory=correlation_id_factory,
                environment=selected_environment,
                executor=execute_installed_product_scan,
            )
        return _run_diagnostic_scan(
            stripped,
            machine=machine,
            stdout=output,
            stderr=errors,
            correlation_id_factory=correlation_id_factory,
            diagnostic=diagnostic,
        )
    if stripped and stripped[0] in {CliCommand.FIX.value, CliCommand.VALIDATE.value}:
        return _run_repair_command(
            stripped,
            machine=machine,
            stdout=output,
            stderr=errors,
            correlation_id_factory=correlation_id_factory,
            repair=repair,
            environment=selected_environment,
        )
    if stripped != ("doctor",):
        return _write_error(
            _error_result(CliErrorCode.INVALID_USAGE, command, correlation_id_factory),
            machine=machine,
            stdout=output,
            stderr=errors,
        )

    try:
        parser.parse_args(stripped)
        candidate = (doctor or FoundationDoctor()).run(selected_environment)
        result = _revalidate_doctor_result(candidate)
        rendered = _canonical_json(result) if machine else None
    except FoundationCapabilityError:
        return _write_error(
            _error_result(CliErrorCode.CAPABILITY_INCOMPATIBLE, command, correlation_id_factory),
            machine=machine,
            stdout=output,
            stderr=errors,
        )
    except (ConfigError, FoundationConfigurationError):
        return _write_error(
            _error_result(CliErrorCode.INVALID_CONFIG, command, correlation_id_factory),
            machine=machine,
            stdout=output,
            stderr=errors,
        )
    except KeyboardInterrupt:
        return _write_error(
            _error_result(CliErrorCode.CANCELLED, command, correlation_id_factory),
            machine=machine,
            stdout=output,
            stderr=errors,
        )
    except Exception:
        return _write_error(
            _error_result(CliErrorCode.INTERNAL_ERROR, command, correlation_id_factory),
            machine=machine,
            stdout=output,
            stderr=errors,
        )

    if machine:
        if rendered is None:  # pragma: no cover - guarded by the machine branch above
            raise RuntimeError("machine result rendering was not prepared")
        output.write(rendered + "\n")
    else:
        errors.write(_HUMAN_SUCCESS + "\n")
    return int(result.exit_code)


def run_connected_results(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Print one bounded, source-free run collection document."""

    try:
        run_id, kind = parse_results_arguments(tokens[1:])
        settings = settings_from_environment(environment)
        collection = fetch_results(settings, run_id, kind)
    except ConnectedCliError as error:
        stderr.write("connected read was rejected (" + error.code.value + ")" + chr(10))
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    except Exception:
        stderr.write("connected read failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    stdout.write(collection.render() + chr(10))
    return int(CliExitCode.COMPLETED)


def run_connected_inspection(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Read one run's state, or cancel it against an exact precondition."""

    command = tokens[0]
    try:
        run_id, if_match = parse_run_arguments(tokens[1:])
        settings = settings_from_environment(environment)
        if command == "status":
            receipt = fetch_run(settings, run_id)
        else:
            receipt = cancel_run(settings, run_id, if_match=if_match or "")
    except ConnectedCliError as error:
        stderr.write("connected run was rejected (" + error.code.value + ")" + chr(10))
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    except Exception:
        stderr.write("connected run failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    render_connected_receipt(receipt, stdout)
    return int(CliExitCode.COMPLETED)


def run_connect_command(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Submit one exact revision to the control plane and print its reference."""

    try:
        _target, wait = parse_connected_arguments(tokens[1:])
        settings = settings_from_environment(environment)
        receipt = run_connected(settings, poll_status=wait)
    except ConnectedCliError as error:
        stderr.write("connected run was rejected (" + error.code.value + ")" + chr(10))
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    except Exception:
        stderr.write("connected run failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    render_connected_receipt(receipt, stdout)
    return int(CliExitCode.COMPLETED)


__all__ = [
    "CLI_VERSION",
    "FOUNDATION_DEFAULTS",
    "FOUNDATION_PROFILE_CONTENT_SHA256",
    "FOUNDATION_PROFILE_SELECTOR",
    "Doctor",
    "FoundationCapabilityError",
    "FoundationConfigurationError",
    "FoundationDoctor",
    "build_foundation_profile",
    "main",
    "run_connect_command",
    "run_connected_inspection",
    "run_connected_results",
]
