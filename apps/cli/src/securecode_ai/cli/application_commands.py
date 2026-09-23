"""Fail-closed CLI foundation with explicit non-product diagnostic composition."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Protocol, TextIO, cast

from securecode_ai.adapters.local_product_runner import (
    LocalProductCancelledError,
    LocalProductScanResult,
    LocalProductSupersededError,
    LocalProductUnavailableError,
)
from securecode_ai.contracts import (
    CliCommand,
    CliDoctorCheck,
    CliDoctorResult,
    CliErrorCode,
    CliErrorResult,
    CliExitCode,
    ContractExtension,
    cli_error_result,
)
from securecode_ai.core.classification import FindingSeverity

from .application_profiles import (
    _HUMAN_DIAGNOSTIC_SUCCESS,
    _DiagnosticScanArguments,
)
from .atomic_output import write_new_output
from .diagnostic import (
    DeterministicDiagnostic,
    DiagnosticError,
    DiagnosticErrorCode,
    DiagnosticFormat,
    LocalDeterministicDiagnostic,
    canonical_diagnostic_json,
    run_deterministic_diagnostic,
)
from .repair import RepairCli, RepairFormat, build_installed_repair_cli, render_receipt
from .scan import (
    ProductScanArguments,
    ProductScanConfigurationError,
    ProductScanUnavailableError,
    execute_installed_product_scan,
    parse_product_scan,
)


class _ProductScanExecutor(Protocol):
    def __call__(
        self,
        arguments: ProductScanArguments,
        *,
        environment: Mapping[str, str],
    ) -> LocalProductScanResult: ...


def _parse_repair(
    tokens: tuple[str, ...],
) -> tuple[CliCommand, str, RepairFormat, Path | None, str | None]:
    if not tokens or tokens[0] not in {"scan", "fix", "validate"} or len(tokens) < 2:
        raise ValueError
    command = CliCommand(tokens[0])
    target = tokens[1]
    if not target or target.startswith("-"):
        raise ValueError
    report_format = RepairFormat.JSON
    output: Path | None = None
    patch_selector: str | None = None
    index = 2
    while index < len(tokens):
        token = tokens[index]
        if token == "--format" and index + 1 < len(tokens):
            index += 1
            report_format = RepairFormat(tokens[index])
        elif token == "--output" and index + 1 < len(tokens) and output is None:
            index += 1
            if not tokens[index]:
                raise ValueError
            output = Path(tokens[index])
        elif token == "--patch":
            index += 1
            if (
                command is not CliCommand.VALIDATE
                or index >= len(tokens)
                or patch_selector is not None
                or not tokens[index]
                or tokens[index].startswith("-")
            ):
                raise ValueError
            patch_selector = tokens[index]
        else:
            raise ValueError
        index += 1
    return command, target, report_format, output, patch_selector


def _run_repair_command(
    tokens: tuple[str, ...],
    *,
    machine: bool,
    stdout: TextIO,
    stderr: TextIO,
    correlation_id_factory: Callable[[], str],
    repair: RepairCli | None,
    environment: Mapping[str, str],
) -> int:
    try:
        command, target, report_format, output, patch_selector = _parse_repair(tokens)
        selected_repair = repair
        if selected_repair is None:
            selected_repair = build_installed_repair_cli(
                environment=environment,
                patch_selector=patch_selector,
            )
        receipt = selected_repair.run(command, target)
        rendered = render_receipt(receipt, report_format)
        if output is not None:
            if output.is_symlink():
                raise OSError
            _write_new_output(output, rendered)
        if machine or output is None:
            stdout.write(rendered.decode("utf-8") + ("" if rendered.endswith(b"\n") else "\n"))
        if not machine:
            stderr.write(
                f"{command.value} operation completed; product outcome was not evaluated\n"
            )
        return int(receipt.exit_code)
    except ValueError:
        return _write_error(
            _error_result(CliErrorCode.INVALID_USAGE, CliCommand.SCAN, correlation_id_factory),
            machine=machine,
            stdout=stdout,
            stderr=stderr,
        )
    except KeyboardInterrupt:
        return _write_error(
            _error_result(CliErrorCode.CANCELLED, None, correlation_id_factory),
            machine=machine,
            stdout=stdout,
            stderr=stderr,
        )
    except Exception:
        return _write_error(
            _error_result(CliErrorCode.OPERATIONAL_ERROR, None, correlation_id_factory),
            machine=machine,
            stdout=stdout,
            stderr=stderr,
        )


def _write_new_output(output: Path, rendered: bytes) -> None:
    write_new_output(output, rendered)


def _publish_product_output(
    output: Path,
    rendered: bytes,
    result: LocalProductScanResult,
) -> None:
    write_new_output(
        output,
        rendered,
        before_publish=result.require_publication,
        after_publish=result.require_publication,
    )


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


def _run_installed_product_scan(
    tokens: tuple[str, ...],
    *,
    machine: bool,
    stdout: TextIO,
    stderr: TextIO,
    correlation_id_factory: Callable[[], str],
    environment: Mapping[str, str],
    executor: _ProductScanExecutor = execute_installed_product_scan,
) -> int:
    try:
        arguments = parse_product_scan(tokens)
        result = executor(arguments, environment=environment)
        result.require_publication()
        rendered = result.rendered
        exit_code = result.exit_code
        if type(rendered) is not bytes or type(exit_code) is not int:
            raise TypeError("product scan result is invalid")
        if arguments.fail_on is not None and exit_code == int(CliExitCode.COMPLETED):
            threshold = _severity_rank(arguments.fail_on)
            if any(
                _severity_rank(item.classification.severity) >= threshold
                for item in result.composition.report.findings
            ):
                exit_code = int(CliExitCode.POLICY_FAIL)
        if arguments.output is not None:
            _publish_product_output(arguments.output, rendered, result)
        if machine or arguments.output is None:
            result.require_publication()
            stdout.write(rendered.decode("utf-8") + ("" if rendered.endswith(b"\n") else "\n"))
        if not machine:
            stderr.write("product scan completed\n")
        return exit_code
    except ProductScanConfigurationError:
        return _write_error(
            _error_result(CliErrorCode.INVALID_CONFIG, CliCommand.SCAN, correlation_id_factory),
            machine=machine,
            stdout=stdout,
            stderr=stderr,
        )
    except (ProductScanUnavailableError, LocalProductUnavailableError):
        return _write_error(
            _error_result(
                CliErrorCode.ANALYSIS_INDETERMINATE, CliCommand.SCAN, correlation_id_factory
            ),
            machine=machine,
            stdout=stdout,
            stderr=stderr,
        )
    except (KeyboardInterrupt, LocalProductCancelledError):
        code = CliErrorCode.CANCELLED
    except LocalProductSupersededError:
        code = CliErrorCode.SUPERSEDED
    except Exception:
        code = CliErrorCode.OPERATIONAL_ERROR
    return _write_error(
        _error_result(code, CliCommand.SCAN, correlation_id_factory),
        machine=machine,
        stdout=stdout,
        stderr=stderr,
    )


def _severity_rank(severity: FindingSeverity) -> int:
    if type(severity) is not FindingSeverity:
        raise TypeError("product scan severity is invalid")
    return {
        FindingSeverity.LOW: 1,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.HIGH: 3,
        FindingSeverity.CRITICAL: 4,
    }[severity]
