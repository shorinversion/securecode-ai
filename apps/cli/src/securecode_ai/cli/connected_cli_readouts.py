"""Connected command-line operations grouped by operator workflow."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TextIO

from securecode_ai.contracts import CliExitCode

from .connected import (
    ApprovalDraft,
    ConnectedCliError,
    ConnectedCliErrorCode,
    cancel_run,
    check_health,
    create_approval,
    decide_approval,
    fetch_events,
    fetch_finding,
    fetch_policies,
    fetch_results,
    fetch_run,
    parse_approval_arguments,
    parse_event_arguments,
    parse_health_arguments,
    parse_results_arguments,
    parse_run_arguments,
    parse_single_argument,
    read_approval,
    settings_from_environment,
)
from .connected import (
    render_receipt as render_connected_receipt,
)


def run_connected_events(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Print one page of a run's event feed."""

    try:
        run_id, cursor, limit = parse_event_arguments(tokens[1:])
        settings = settings_from_environment(environment)
        collection = fetch_events(settings, run_id, cursor=cursor, limit=limit)
    except ConnectedCliError as error:
        stderr.write("connected read was rejected (" + error.code.value + ")" + chr(10))
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    except Exception:
        stderr.write("connected read failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    stdout.write(collection.render() + chr(10))
    return int(CliExitCode.COMPLETED)


def run_connected_readout(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Read one finding, the policy documents, or the control-plane health."""

    try:
        command = tokens[0]
        settings = settings_from_environment(environment)
        if command == "finding":
            collection = fetch_finding(settings, parse_single_argument(tokens[1:]))
        elif command == "policies":
            if len(tokens) != 1:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            collection = fetch_policies(settings)
        else:
            collection = check_health(settings, live=parse_health_arguments(tokens[1:]))
    except ConnectedCliError as error:
        stderr.write("connected read was rejected (" + error.code.value + ")" + chr(10))
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    except Exception:
        stderr.write("connected read failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    stdout.write(collection.render() + chr(10))
    return int(CliExitCode.COMPLETED)


def run_connected_approval(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Open, read or decide one approval through the control plane."""

    try:
        if len(tokens) < 2:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        action = tokens[1]
        settings = settings_from_environment(environment)
        if action == "create":
            fields = parse_approval_arguments(tokens[2:])
            missing = {
                "approval-id",
                "repository",
                "run",
                "finding",
                "identity-hash",
                "expires-at",
            } - set(fields)
            if missing:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            collection = create_approval(
                settings,
                ApprovalDraft(
                    approval_id=fields["approval-id"],
                    repository_id=fields["repository"],
                    run_id=fields["run"],
                    finding_id=fields["finding"],
                    execution_identity_hash=fields["identity-hash"],
                    expires_at=fields["expires-at"],
                ),
            )
        elif action == "show":
            fields = parse_approval_arguments(tokens[2:])
            if set(fields) != {"approval-id"}:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            collection = read_approval(settings, fields["approval-id"])
        elif action == "decide":
            fields = parse_approval_arguments(tokens[2:])
            required = {"approval-id", "if-match", "decision", "reason", "rationale"}
            if set(fields) != required:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            decision = fields["decision"]
            if decision not in {"approved", "rejected"}:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            collection = decide_approval(
                settings,
                fields["approval-id"],
                approve=decision == "approved",
                reason_code=fields["reason"],
                rationale=fields["rationale"],
                if_match=fields["if-match"],
            )
        else:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    except ConnectedCliError as error:
        stderr.write("connected approval was rejected (" + error.code.value + ")" + chr(10))
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    except Exception:
        stderr.write("connected approval failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    stdout.write(collection.render() + chr(10))
    return int(CliExitCode.COMPLETED)


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
