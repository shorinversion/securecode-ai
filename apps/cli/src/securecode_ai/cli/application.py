"""Fail-closed CLI foundation with explicit non-product diagnostic composition."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType
from typing import TextIO

from securecode_ai.adapters import ConfigError
from securecode_ai.contracts import (
    CliCommand,
    CliErrorCode,
    CliExitCode,
)

from .application_commands import (
    _canonical_json,
    _default_correlation_id,
    _error_result,
    _revalidate_doctor_result,
    _run_diagnostic_scan,
    _run_installed_product_scan,
    _run_repair_command,
    _write_error,
)
from .application_parser import COMMAND_DESCRIPTIONS, _command_help, _parser
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
from .connected import run_connected
from .connected_ci_commands import run_ci_command as _run_ci_command
from .connected_ci_commands import run_connect_command as _run_connect_command
from .connected_cli_commands import (
    run_connected_approval,
    run_connected_assurance,
    run_connected_backups,
    run_connected_decision,
    run_connected_deletions,
    run_connected_events,
    run_connected_feedback,
    run_connected_inspection,
    run_connected_readout,
    run_connected_results,
    run_connected_secrets,
)
from .diagnostic import (
    DeterministicDiagnostic,
)
from .release import run_release_command
from .repair import RepairCli
from .scan import execute_installed_product_scan

_CONNECTED_COMMAND_HANDLERS: Mapping[str, Callable[..., int]] = MappingProxyType(
    {
        "finding": run_connected_readout,
        "policies": run_connected_readout,
        "health": run_connected_readout,
        "secrets": run_connected_secrets,
        "decisions": run_connected_decision,
        "assurance": run_connected_assurance,
        "feedback": run_connected_feedback,
        "deletions": run_connected_deletions,
        "backups": run_connected_backups,
        "events": run_connected_events,
        "approvals": run_connected_approval,
        "results": run_connected_results,
        "status": run_connected_inspection,
        "cancel": run_connected_inspection,
    }
)

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
        and stripped[0] in COMMAND_DESCRIPTIONS
    ):
        output.write(_command_help(stripped[0]))
        return int(CliExitCode.COMPLETED)
    if stripped and stripped[0] in _CONNECTED_COMMAND_HANDLERS:
        return _CONNECTED_COMMAND_HANDLERS[stripped[0]](
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
    if stripped and stripped[0] == "ci":
        return run_ci_command(
            stripped,
            machine=machine,
            stdout=output,
            stderr=errors,
            environment=selected_environment,
            correlation_id_factory=correlation_id_factory,
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


def run_ci_command(
    tokens: tuple[str, ...],
    *,
    machine: bool,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
    correlation_id_factory: Callable[[], str],
) -> int:
    """Keep the application-level executor seam used by CI integrations."""

    return _run_ci_command(
        tokens,
        machine=machine,
        stdout=stdout,
        stderr=stderr,
        environment=environment,
        correlation_id_factory=correlation_id_factory,
        run_executor=run_connected,
    )


def run_connect_command(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Keep the application-level executor seam for connected submissions."""

    return _run_connect_command(
        tokens,
        stdout=stdout,
        stderr=stderr,
        environment=environment,
        run_executor=run_connected,
    )


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
    "run_ci_command",
    "run_connect_command",
    "run_connected_approval",
    "run_connected_assurance",
    "run_connected_backups",
    "run_connected_decision",
    "run_connected_deletions",
    "run_connected_events",
    "run_connected_feedback",
    "run_connected_inspection",
    "run_connected_readout",
    "run_connected_results",
    "run_connected_secrets",
]
