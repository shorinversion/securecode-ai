"""Connected command-line operations grouped by operator workflow."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import TextIO

from securecode_ai.contracts import CliExitCode

from .atomic_output import write_new_output
from .connected import (
    ApprovalDraft,
    ConnectedCliError,
    ConnectedCliErrorCode,
    cancel_run,
    check_health,
    create_approval,
    decide_approval,
    download_artifact,
    download_repair_patch,
    fetch_events,
    fetch_audit,
    fetch_finding,
    fetch_policies,
    fetch_results,
    fetch_run,
    parse_approval_arguments,
    parse_download_arguments,
    parse_repair_download_arguments,
    parse_event_arguments,
    parse_audit_arguments,
    parse_health_arguments,
    parse_results_arguments_with_page,
    parse_run_arguments,
    parse_single_argument,
    read_approval,
    repair_approval_id,
    settings_from_environment,
    import_repair_patch_bundle,
)
from .connected import (
    render_receipt as render_connected_receipt,
)


def _connected_error_exit(
    error: ConnectedCliError,
    *,
    operation: str,
    stderr: TextIO,
) -> int:
    """Keep local argument errors distinct from control-plane failures."""

    if error.code is ConnectedCliErrorCode.INVALID_CONFIGURATION:
        stderr.write(
            "connected " + operation + " was rejected (" + error.code.value + ")" + chr(10)
        )
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    stderr.write("connected " + operation + " failed (" + error.code.value + ")" + chr(10))
    return int(CliExitCode.OPERATIONAL_ERROR)


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
        return _connected_error_exit(error, operation="read", stderr=stderr)
    except Exception:
        stderr.write("connected read failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    stdout.write(collection.render() + chr(10))
    return int(CliExitCode.COMPLETED)


def run_connected_audit(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Print one verified, bounded page of a run's immutable audit chain."""

    try:
        run_id, start, end = parse_audit_arguments(tokens[1:])
        settings = settings_from_environment(environment)
        collection = fetch_audit(settings, run_id, start=start, end=end)
    except ConnectedCliError as error:
        return _connected_error_exit(error, operation="audit read", stderr=stderr)
    except Exception:
        stderr.write("connected audit read failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    stdout.write(collection.render() + chr(10))
    return int(CliExitCode.COMPLETED)


def run_connected_download(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Download one bounded artifact into a new local file."""

    try:
        run_id, content_sha256, destination = parse_download_arguments(tokens[1:])
        settings = settings_from_environment(environment)
        content = download_artifact(settings, run_id, content_sha256)
        write_new_output(destination, content)
    except ConnectedCliError as error:
        return _connected_error_exit(error, operation="download", stderr=stderr)
    except (OSError, ValueError):
        stderr.write("connected download failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    except Exception:
        stderr.write("connected download failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    stdout.write(
        json.dumps(
            {
                "content_sha256": content_sha256,
                "output": str(destination),
                "size_bytes": len(content),
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + chr(10)
    )
    return int(CliExitCode.COMPLETED)


def run_connected_repair_download(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Download and re-import one server-authorized repair patch bundle."""

    try:
        run_id, finding_id, patch_sha256, target = parse_repair_download_arguments(tokens[1:])
        settings = settings_from_environment(environment)
        content = download_repair_patch(
            settings,
            run_id,
            finding_id,
            patch_sha256,
        )
        imported = import_repair_patch_bundle(
            environment,
            target,
            content,
            expected={
                "finding_id": finding_id,
                "head_sha": settings.head_sha,
                "repository_id": settings.repository_id,
                "run_id": run_id,
                "tenant_id": settings.tenant_id,
                "patch_sha256": patch_sha256,
            },
        )
    except ConnectedCliError as error:
        return _connected_error_exit(error, operation="repair-download", stderr=stderr)
    except (OSError, ValueError):
        stderr.write("connected repair download failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    except Exception:
        stderr.write("connected repair download failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    stdout.write(json.dumps(imported.document(), ensure_ascii=True, sort_keys=True) + chr(10))
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
        if not tokens or tokens[0] not in {"finding", "policies", "health"}:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
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
        return _connected_error_exit(error, operation="read", stderr=stderr)
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
            required = {
                "repository",
                "run",
                "finding",
                "identity-hash",
                "expires-at",
            }
            repair_hash_flags = {
                "patch-sha256",
                "validation-result-sha256",
                "manifest-sha256",
                "patch-status-sha256",
            }
            if not required.issubset(fields) or frozenset(
                set(fields) - required - {"approval-id"}
            ) not in {
                frozenset(),
                frozenset(repair_hash_flags),
            }:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            has_repair_binding = repair_hash_flags.issubset(fields)
            if has_repair_binding:
                derived_approval_id = repair_approval_id(
                    fields["run"],
                    fields["finding"],
                    fields["patch-sha256"],
                )
                if "approval-id" in fields and fields["approval-id"] != derived_approval_id:
                    raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
                fields["approval-id"] = derived_approval_id
            elif "approval-id" not in fields:
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
                    patch_sha256=fields.get("patch-sha256"),
                    validation_result_sha256=fields.get("validation-result-sha256"),
                    manifest_sha256=fields.get("manifest-sha256"),
                    patch_status_sha256=fields.get("patch-status-sha256"),
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
        return _connected_error_exit(error, operation="approval", stderr=stderr)
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
        run_id, kind, content_sha256, cursor, limit = parse_results_arguments_with_page(
            tokens[1:]
        )
        settings = settings_from_environment(environment)
        collection = fetch_results(
            settings,
            run_id,
            kind,
            content_sha256=content_sha256,
            cursor=cursor,
            limit=limit,
        )
    except ConnectedCliError as error:
        return _connected_error_exit(error, operation="read", stderr=stderr)
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

    try:
        if not tokens or tokens[0] not in {"status", "cancel"}:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        command = tokens[0]
        run_id, if_match = parse_run_arguments(tokens[1:])
        if command == "status" and if_match is not None:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if command == "cancel" and if_match is None:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        settings = settings_from_environment(environment)
        if command == "status":
            receipt = fetch_run(settings, run_id)
        else:
            receipt = cancel_run(settings, run_id, if_match=if_match or "")
    except ConnectedCliError as error:
        return _connected_error_exit(error, operation="run", stderr=stderr)
    except Exception:
        stderr.write("connected run failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    render_connected_receipt(receipt, stdout)
    return int(CliExitCode.COMPLETED)
