"""Connected scan and CI process exit-code commands."""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TextIO

from securecode_ai.contracts import CliCommand, CliErrorCode, CliExitCode

from .application_commands import _error_result, _write_error
from .connected import (
    ConnectedCliError,
    ConnectedCliErrorCode,
    ConnectedRunReceipt,
    parse_connected_arguments,
    parse_connected_arguments_with_operation,
    run_connected,
    settings_from_environment,
)
from .connected import (
    render_receipt as render_connected_receipt,
)


def run_connect_command(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
    run_executor: Callable[..., ConnectedRunReceipt] | None = None,
) -> int:
    """Submit one exact revision to the control plane and print its reference."""

    try:
        target, wait, fresh, operation = parse_connected_arguments_with_operation(tokens[1:])
        settings = settings_from_environment(environment, fresh=fresh, operation=operation)
        if target is not None:
            _require_target_head(target, settings.head_sha)
        execute = run_connected if run_executor is None else run_executor
        receipt = execute(
            settings,
            poll_status=wait,
            attempts=40 if wait else 1,
            sleeper=time.sleep,
        )
    except ConnectedCliError as error:
        stderr.write("connected run was rejected (" + error.code.value + ")" + chr(10))
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    except KeyboardInterrupt:
        stderr.write("connected run cancelled" + chr(10))
        return int(CliExitCode.CANCELLED_OR_SUPERSEDED)
    except Exception:
        stderr.write("connected run failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    render_connected_receipt(receipt, stdout)
    return int(CliExitCode.COMPLETED)


def _require_target_head(target: Path, expected_head: str) -> None:
    """Ensure an optional local checkout is exactly the submitted revision."""

    try:
        path = target.resolve(strict=True)
        if not path.is_dir():
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        environment = {
            name: os.environ[name]
            for name in ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR")
            if name in os.environ
        }
        environment["GIT_CONFIG_GLOBAL"] = os.devnull
        environment["GIT_CONFIG_NOSYSTEM"] = "1"
        environment["GIT_OPTIONAL_LOCKS"] = "0"
        environment["GIT_TERMINAL_PROMPT"] = "0"
        result = subprocess.run(
            ("git", "rev-parse", "--verify", "HEAD"),
            cwd=path,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            shell=False,
            check=False,
            timeout=5,
        )
        actual_head = result.stdout.decode("ascii", "strict").strip()
    except ConnectedCliError:
        raise
    except (OSError, UnicodeError, subprocess.SubprocessError):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION) from None
    if result.returncode != 0 or actual_head != expected_head:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)


def run_ci_command(
    tokens: tuple[str, ...],
    *,
    machine: bool,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
    correlation_id_factory: Callable[[], str],
    run_executor: Callable[..., ConnectedRunReceipt] | None = None,
) -> int:
    """Run one connected scan and map its terminal outcome to the CI contract."""

    try:
        target, wait, fresh = parse_connected_arguments(tokens[1:])
        if target is not None or wait:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        settings = settings_from_environment(environment, fresh=fresh)
        execute = run_connected if run_executor is None else run_executor
        receipt = execute(
            settings,
            poll_status=True,
            attempts=40,
            sleeper=time.sleep,
        )
    except ConnectedCliError as error:
        error_code = {
            ConnectedCliErrorCode.INVALID_CONFIGURATION: CliErrorCode.INVALID_CONFIG,
            ConnectedCliErrorCode.PROTOCOL_INVALID: CliErrorCode.ANALYSIS_INDETERMINATE,
            ConnectedCliErrorCode.RUN_NOT_TERMINAL: CliErrorCode.ANALYSIS_INDETERMINATE,
            ConnectedCliErrorCode.REJECTED: CliErrorCode.OPERATIONAL_ERROR,
            ConnectedCliErrorCode.UNREACHABLE: CliErrorCode.OPERATIONAL_ERROR,
        }[error.code]
        return _write_error(
            _error_result(error_code, CliCommand.CI, correlation_id_factory),
            machine=machine,
            stdout=stdout,
            stderr=stderr,
        )
    except KeyboardInterrupt:
        return _write_error(
            _error_result(CliErrorCode.CANCELLED, CliCommand.CI, correlation_id_factory),
            machine=machine,
            stdout=stdout,
            stderr=stderr,
        )
    except Exception:
        return _write_error(
            _error_result(CliErrorCode.OPERATIONAL_ERROR, CliCommand.CI, correlation_id_factory),
            machine=machine,
            stdout=stdout,
            stderr=stderr,
        )

    render_connected_receipt(receipt, stdout)
    return {
        "PASS": int(CliExitCode.COMPLETED),
        "FAIL": int(CliExitCode.POLICY_FAIL),
        "INDETERMINATE": int(CliExitCode.INDETERMINATE),
        "ERROR": int(CliExitCode.OPERATIONAL_ERROR),
        "CANCELLED": int(CliExitCode.CANCELLED_OR_SUPERSEDED),
        "SUPERSEDED": int(CliExitCode.CANCELLED_OR_SUPERSEDED),
    }.get(receipt.outcome or "", int(CliExitCode.INDETERMINATE))


__all__ = ["run_ci_command", "run_connect_command"]
