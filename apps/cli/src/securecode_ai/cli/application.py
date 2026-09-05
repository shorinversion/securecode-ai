"""Fail-closed CLI foundation with explicit non-product diagnostic composition."""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol, TextIO, cast

from securecode_ai.adapters import ConfigError, ProviderProfileRegistry, resolve_configuration
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CliCommand,
    CliDiagnosticScope,
    CliDoctorCheck,
    CliDoctorCheckId,
    CliDoctorCheckOutcome,
    CliDoctorOutcome,
    CliDoctorReasonCode,
    CliDoctorResult,
    CliErrorCode,
    CliErrorResult,
    CliExitCode,
    CliScanReadiness,
    ContractExtension,
    ProviderProfile,
    cli_error_result,
)
from securecode_ai.core import CONTRACT_SCHEMA_VERSION as CORE_CONTRACT_SCHEMA_VERSION

from .diagnostic import (
    DeterministicDiagnostic,
    DiagnosticError,
    DiagnosticErrorCode,
    DiagnosticFormat,
    LocalDeterministicDiagnostic,
    canonical_diagnostic_json,
    run_deterministic_diagnostic,
)

CLI_VERSION: Final = "0.1.0a0"
FOUNDATION_PROFILE_SELECTOR: Final = "securecode-foundation-fake@0.2.0"
FOUNDATION_PROFILE_CONTENT_SHA256: Final = (
    "b70483bdddf742b6610f9aed77305294b698a51da8c8e60f0901c1b2865e9862"
)
FOUNDATION_DEFAULTS: Final = {
    "provider_profile": FOUNDATION_PROFILE_SELECTOR,
    "policy_profile": "foundation-advisory",
    "egress_profile": "air_gap",
}
_HUMAN_SUCCESS: Final = (
    "foundation configuration diagnostics completed; scan readiness was not evaluated"
)
_HUMAN_DIAGNOSTIC_SUCCESS: Final = (
    "deterministic diagnostic completed; product scan outcome was not evaluated"
)


class Doctor(Protocol):
    def run(self, environment: Mapping[str, str]) -> CliDoctorResult: ...


class FoundationConfigurationError(ValueError):
    """Safe closed signal; never stores or renders rejected configuration."""


class FoundationCapabilityError(ValueError):
    """Safe closed signal for declaration-only capability incompatibility."""


@dataclass(frozen=True, slots=True)
class _DiagnosticScanArguments:
    target: str
    report_format: DiagnosticFormat
    output: Path | None


def build_foundation_profile() -> ProviderProfile:
    return ProviderProfile.model_validate(
        {
            "schema_version": "0.2.0",
            "profile_id": "securecode-foundation-fake",
            "profile_version": "0.2.0",
            "provider_kind": "fake",
            "api_dialect": "fake",
            "endpoint": {
                "base_url": "fake://local",
                "authority": "local",
                "allowed_ports": [1],
                "follow_redirects": False,
                "local_plaintext_exception": False,
            },
            "execution_boundary": "local_runner",
            "model_id": "securecode-foundation-fake",
            "model_snapshot": "0.2.0",
            "capabilities": {
                "structured_output": True,
                "native_refusal_signal": True,
                "native_incomplete_signal": True,
                "tool_calling": False,
                "source_code_analysis": True,
                "repository_tool_calls": False,
                "repository_tools": [],
                "max_context_tokens": 32768,
                "max_output_tokens": 4096,
            },
            "data_terms": {
                "evidence_status": "not_applicable_local",
                "residency": ["local"],
                "retention_seconds": 0,
                "training_use": "not_applicable_local",
                "zero_data_retention": True,
                "maximum_input_data_class": "DC3_CONFIDENTIAL_SOURCE",
                "allowed_purposes": ["model_native_discovery"],
                "evidence_ref": None,
            },
            "credential_ref": None,
            "egress_profiles": ["air_gap"],
            "budgets": {
                "timeout_seconds": 30,
                "max_attempts": 1,
                "max_total_tokens": 32768,
            },
        }
    )


class FoundationDoctor:
    """Run exactly four source-free structural diagnostics with no provider call."""

    __slots__ = ("_defaults", "_profile", "_repository", "_user")

    def __init__(
        self,
        *,
        profile: ProviderProfile | None = None,
        defaults: Mapping[str, object] | None = None,
        user: Mapping[str, object] | None = None,
        repository: Mapping[str, object] | None = None,
    ) -> None:
        self._profile = profile or build_foundation_profile()
        self._defaults = dict(FOUNDATION_DEFAULTS if defaults is None else defaults)
        self._user = dict(user or {})
        self._repository = dict(repository or {})

    def run(self, environment: Mapping[str, str]) -> CliDoctorResult:
        profile = self._profile
        capabilities = profile.capabilities
        if not all(
            (
                capabilities.structured_output,
                capabilities.native_refusal_signal,
                capabilities.native_incomplete_signal,
                capabilities.source_code_analysis,
            )
        ):
            raise FoundationCapabilityError
        if (
            profile.selector != FOUNDATION_PROFILE_SELECTOR
            or profile.canonical_content_hash() != FOUNDATION_PROFILE_CONTENT_SHA256
            or CORE_CONTRACT_SCHEMA_VERSION != CONTRACT_SCHEMA_VERSION
        ):
            raise FoundationConfigurationError

        registry = ProviderProfileRegistry((profile,))
        configuration = resolve_configuration(
            registry=registry,
            defaults=self._defaults,
            user=self._user,
            repository=self._repository,
            environment=environment,
        )
        if (
            configuration.provider_profile.selector != FOUNDATION_PROFILE_SELECTOR
            or configuration.provider_profile.canonical_content_hash()
            != FOUNDATION_PROFILE_CONTENT_SHA256
            or configuration.egress_profile not in configuration.provider_profile.egress_profiles
        ):
            raise FoundationConfigurationError

        checks = (
            CliDoctorCheck(
                schema_version=CONTRACT_SCHEMA_VERSION,
                check_id=CliDoctorCheckId.CONFIGURATION_RESOLUTION,
                check_outcome=CliDoctorCheckOutcome.READY,
                reason_code=CliDoctorReasonCode.CONFIGURATION_VALID,
            ),
            CliDoctorCheck(
                schema_version=CONTRACT_SCHEMA_VERSION,
                check_id=CliDoctorCheckId.FOUNDATION_PROFILE_IDENTITY,
                check_outcome=CliDoctorCheckOutcome.READY,
                reason_code=CliDoctorReasonCode.PROFILE_IDENTITY_VALID,
            ),
            CliDoctorCheck(
                schema_version=CONTRACT_SCHEMA_VERSION,
                check_id=CliDoctorCheckId.SELECTED_EGRESS_MEMBERSHIP,
                check_outcome=CliDoctorCheckOutcome.READY,
                reason_code=CliDoctorReasonCode.EGRESS_MEMBERSHIP_VALID,
            ),
            CliDoctorCheck(
                schema_version=CONTRACT_SCHEMA_VERSION,
                check_id=CliDoctorCheckId.SOURCE_FREE_CAPABILITY_DECLARATION,
                check_outcome=CliDoctorCheckOutcome.READY,
                reason_code=CliDoctorReasonCode.CAPABILITY_DECLARATION_VALID,
            ),
        )
        return CliDoctorResult(
            schema_version=CONTRACT_SCHEMA_VERSION,
            command=CliCommand.DOCTOR,
            diagnostic_scope=CliDiagnosticScope.FOUNDATION_CONFIGURATION_ONLY,
            cli_outcome=CliDoctorOutcome.DIAGNOSTIC_COMPLETED,
            exit_code=CliExitCode.COMPLETED,
            scan_readiness=CliScanReadiness.NOT_EVALUATED,
            checks=checks,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securecode",
        add_help=False,
        description="SecureCode AI foundation CLI (analysis commands are not implemented yet).",
    )
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--version", action="store_true")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser(
        "doctor",
        add_help=False,
        help="validate foundation configuration without source or network access",
    )
    return parser


def _canonical_json(result: CliDoctorResult | CliErrorResult) -> str:
    return json.dumps(
        result.model_dump(mode="json"),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _default_correlation_id() -> str:
    return f"cli-{uuid.uuid4().hex}"


def _same_runtime_state(actual: object, expected: object) -> bool:
    """Reject unsafe copied/retained Pydantic state before trusting a result."""

    if type(actual) is not type(expected):
        return False
    if isinstance(expected, (CliDoctorResult, CliDoctorCheck, ContractExtension)):
        fields = type(expected).model_fields
        if set(actual.__dict__) != set(fields):
            return False
        return all(
            _same_runtime_state(getattr(actual, field), getattr(expected, field))
            for field in fields
        )
    if isinstance(expected, tuple):
        actual_tuple = cast(tuple[object, ...], actual)
        return len(actual_tuple) == len(expected) and all(
            _same_runtime_state(actual_item, expected_item)
            for actual_item, expected_item in zip(actual_tuple, expected, strict=True)
        )
    return actual == expected


def _revalidate_doctor_result(candidate: object) -> CliDoctorResult:
    if not isinstance(candidate, CliDoctorResult):
        raise ValueError("doctor returned an invalid result type")
    validated = CliDoctorResult.model_validate_json(candidate.model_dump_json())
    if not _same_runtime_state(candidate, validated):
        raise ValueError("doctor returned noncanonical retained state")
    return validated


def _error_result(
    code: CliErrorCode,
    command: CliCommand | None,
    correlation_id_factory: Callable[[], str],
) -> CliErrorResult:
    return cli_error_result(
        code,
        correlation_id=correlation_id_factory(),
        command=command,
    )


def _write_error(
    result: CliErrorResult,
    *,
    machine: bool,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    if machine:
        stdout.write(_canonical_json(result) + "\n")
    else:
        stderr.write(result.error.safe_message.value + "\n")
    return int(result.exit_code)


def _parse_diagnostic_scan(tokens: tuple[str, ...]) -> _DiagnosticScanArguments:
    """Parse the deliberately narrow scan diagnostic grammar without echoing argv."""

    if not tokens or tokens[0] != CliCommand.SCAN.value:
        raise ValueError("diagnostic scan grammar is invalid")
    target: str | None = None
    report_format = DiagnosticFormat.JSON
    format_selected = False
    output: Path | None = None
    diagnostic_requested = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--diagnostic":
            if diagnostic_requested:
                raise ValueError("diagnostic scan grammar is invalid")
            diagnostic_requested = True
        elif token == "--format":
            index += 1
            if index >= len(tokens) or format_selected:
                raise ValueError("diagnostic scan grammar is invalid")
            try:
                report_format = DiagnosticFormat(tokens[index])
            except ValueError:
                raise ValueError("diagnostic scan grammar is invalid") from None
            format_selected = True
        elif token == "--output":
            index += 1
            if index >= len(tokens) or output is not None or not tokens[index]:
                raise ValueError("diagnostic scan grammar is invalid")
            output = Path(tokens[index])
        elif token.startswith("-") or target is not None or not token:
            raise ValueError("diagnostic scan grammar is invalid")
        else:
            target = token
        index += 1
    if not diagnostic_requested or target is None:
        raise ValueError("diagnostic scan grammar is invalid")
    return _DiagnosticScanArguments(target=target, report_format=report_format, output=output)


def _run_diagnostic_scan(
    tokens: tuple[str, ...],
    *,
    machine: bool,
    stdout: TextIO,
    stderr: TextIO,
    correlation_id_factory: Callable[[], str],
    diagnostic: DeterministicDiagnostic | None,
) -> int:
    """Execute only the explicit deterministic diagnostic scope of ``scan``."""

    command = CliCommand.SCAN
    try:
        arguments = _parse_diagnostic_scan(tokens)
        result = run_deterministic_diagnostic(
            diagnostic or LocalDeterministicDiagnostic(),
            target=arguments.target,
            report_format=arguments.report_format,
            output=arguments.output,
        )
    except ValueError:
        return _write_error(
            _error_result(CliErrorCode.INVALID_USAGE, command, correlation_id_factory),
            machine=machine,
            stdout=stdout,
            stderr=stderr,
        )
    except DiagnosticError as error:
        error_code = (
            CliErrorCode.OPERATIONAL_ERROR
            if error.code is DiagnosticErrorCode.OUTPUT_UNAVAILABLE
            else CliErrorCode.ANALYSIS_INDETERMINATE
        )
        return _write_error(
            _error_result(error_code, command, correlation_id_factory),
            machine=machine,
            stdout=stdout,
            stderr=stderr,
        )
    except KeyboardInterrupt:
        return _write_error(
            _error_result(CliErrorCode.CANCELLED, command, correlation_id_factory),
            machine=machine,
            stdout=stdout,
            stderr=stderr,
        )
    except Exception:
        return _write_error(
            _error_result(CliErrorCode.INTERNAL_ERROR, command, correlation_id_factory),
            machine=machine,
            stdout=stdout,
            stderr=stderr,
        )
    if machine:
        stdout.write(canonical_diagnostic_json(result) + "\n")
    else:
        stderr.write(_HUMAN_DIAGNOSTIC_SUCCESS + "\n")
    return int(CliExitCode.COMPLETED)


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    environment: Mapping[str, str] | None = None,
    doctor: Doctor | None = None,
    diagnostic: DeterministicDiagnostic | None = None,
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
    if stripped and stripped[0] == CliCommand.SCAN.value:
        return _run_diagnostic_scan(
            stripped,
            machine=machine,
            stdout=output,
            stderr=errors,
            correlation_id_factory=correlation_id_factory,
            diagnostic=diagnostic,
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
        selected_environment = os.environ if environment is None else environment
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
]
