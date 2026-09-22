"""Fail-closed CLI foundation with explicit non-product diagnostic composition."""

from __future__ import annotations

import argparse
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securecode",
        add_help=False,
        description="SecureCode AI local audit and safe repair CLI.",
    )
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--version", action="store_true")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser(
        "doctor",
        add_help=False,
        help="validate foundation configuration without source or network access",
    )
    subparsers.add_parser(
        "scan",
        add_help=False,
        help="audit one local checkout",
    )
    subparsers.add_parser(
        "fix",
        add_help=False,
        help="propose a bounded repair for one local checkout",
    )
    subparsers.add_parser(
        "validate",
        add_help=False,
        help="validate one retained repair artifact in isolation",
    )
    subparsers.add_parser(
        "approve",
        add_help=False,
        help="record explicit approval for one exact validated repair artifact",
    )
    subparsers.add_parser(
        "release",
        add_help=False,
        help="dry-run or explicitly authorize immutable local release publication",
    )
    subparsers.add_parser(
        "connect",
        add_help=False,
        help="submit one checkout to a control plane and follow the run",
    )
    subparsers.add_parser(
        "status",
        add_help=False,
        help="read one run's current durable state from the control plane",
    )
    subparsers.add_parser(
        "cancel",
        add_help=False,
        help="request cancellation of one run with an exact state precondition",
    )
    return parser


def _command_help(command: str) -> str:
    descriptions = {
        "doctor": "validate foundation configuration without source or network access",
        "scan": "audit one local checkout",
        "fix": "propose a bounded repair for one local checkout",
        "validate": "validate one retained repair artifact in isolation",
        "approve": "record explicit approval for one exact validated repair artifact",
        "release": "dry-run or explicitly authorize immutable local release publication",
        "connect": "submit one checkout to a control plane and follow the run",
        "status": "read one run's current durable state from the control plane",
        "cancel": "request cancellation of one run with an exact state precondition",
    }
    description = descriptions.get(command)
    if description is None:
        raise ValueError("command is invalid")
    parser = argparse.ArgumentParser(prog=f"securecode {command}", description=description)
    if command in {"scan", "fix", "validate", "approve"}:
        parser.add_argument("target", help="absolute or relative checkout path")
        parser.add_argument("--output", help="create a new output file")
        if command != "approve":
            formats = (
                tuple(item.value for item in RepairFormat if item is not RepairFormat.DIFF)
                if command == "scan"
                else tuple(item.value for item in RepairFormat)
            )
            parser.add_argument(
                "--format",
                choices=formats,
                default=RepairFormat.JSON.value,
            )
        if command == "scan":
            parser.add_argument("--config", help="host approval configuration for product scan")
            parser.add_argument("--diagnostic", action="store_true")
        if command == "validate":
            parser.add_argument("--patch", help="retained patch selector")
        elif command == "approve":
            parser.add_argument("--patch", required=True)
            parser.add_argument("--artifact-sha256", required=True)
            parser.add_argument("--capability", required=True)
            parser.add_argument("--approval-id", required=True)
            parser.add_argument("--approver-id", required=True)
    elif command == "release":
        parser.add_argument("--config", required=True)
        parser.add_argument("--publish", action="store_true")
        parser.add_argument("--authorization")
    elif command == "connect":
        parser.add_argument("target", nargs="?", help="optional local checkout path")
        parser.add_argument(
            "--wait",
            action="store_true",
            help="poll until the control plane reports a terminal outcome",
        )
    elif command in {"status", "cancel"}:
        parser.add_argument("run_id", help="control plane run identifier")
        if command == "cancel":
            parser.add_argument(
                "--if-match",
                required=True,
                help="observed state version or etag the cancellation must match",
            )
    return parser.format_help()


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
