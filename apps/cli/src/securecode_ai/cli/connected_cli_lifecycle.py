"""Connected command-line operations grouped by operator workflow."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TextIO

from securecode_ai.contracts import CliExitCode

from .connected import (
    AssuranceDraft,
    BackupDraft,
    ConnectedCliError,
    ConnectedCliErrorCode,
    DeletionDraft,
    FeedbackDraft,
    SecretGrantDraft,
    append_assurance,
    approve_deletion,
    create_backup,
    create_deletion,
    decide_finding,
    execute_deletion,
    grant_secret,
    hold_deletion,
    parse_approval_arguments,
    parse_payload,
    read_assurance,
    read_backup,
    read_deletion,
    read_feedback_metrics,
    read_secret_grant,
    settings_from_environment,
    submit_feedback,
    transition_backup,
)


def run_connected_secrets(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Grant or read one bounded secret reference; never handles secret values."""

    try:
        if len(tokens) < 2:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        action = tokens[1]
        if action == "grant":
            fields = parse_approval_arguments(tokens[2:])
            required = {"repository", "workload", "reference", "purpose"}
            if not required.issubset(fields):
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            settings = settings_from_environment(environment)
            collection = grant_secret(
                settings,
                SecretGrantDraft(
                    repository_id=fields["repository"],
                    workload_id=fields["workload"],
                    reference=fields["reference"],
                    purpose=fields["purpose"],
                ),
            )
        elif action == "show":
            fields = parse_approval_arguments(tokens[2:])
            if set(fields) != {"grant-id"}:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            settings = settings_from_environment(environment)
            collection = read_secret_grant(settings, fields["grant-id"])
        else:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    except ConnectedCliError as error:
        stderr.write("connected secret operation was rejected (" + error.code.value + ")" + chr(10))
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    except Exception:
        stderr.write("connected secret operation failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    stdout.write(collection.render() + chr(10))
    return int(CliExitCode.COMPLETED)


def run_connected_decision(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Record one operator decision on a finding."""

    try:
        if len(tokens) < 2:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        finding_id = tokens[1]
        fields = parse_approval_arguments(tokens[2:])
        required = {"if-match", "run", "revision", "decision", "reason"}
        if not required.issubset(fields):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        settings = settings_from_environment(environment)
        collection = decide_finding(
            settings,
            finding_id,
            run_id=fields["run"],
            revision_sha=fields["revision"],
            decision_type=fields["decision"],
            reason=fields["reason"],
            if_match=fields["if-match"],
        )
    except ConnectedCliError as error:
        stderr.write("connected decision was rejected (" + error.code.value + ")" + chr(10))
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    except Exception:
        stderr.write("connected decision failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    stdout.write(collection.render() + chr(10))
    return int(CliExitCode.COMPLETED)


def run_connected_assurance(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Append or read assurance records for one repository."""

    try:
        if len(tokens) < 2:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        action = tokens[1]
        settings = settings_from_environment(environment)
        if action == "append":
            fields = parse_approval_arguments(tokens[2:])
            required = {
                "repository",
                "identity-hash",
                "record-id",
                "kind",
                "outcome",
                "payload",
                "if-match",
            }
            if not required.issubset(fields):
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            collection = append_assurance(
                settings,
                AssuranceDraft(
                    repository_id=fields["repository"],
                    identity_hash=fields["identity-hash"],
                    record_id=fields["record-id"],
                    kind=fields["kind"],
                    outcome=fields["outcome"],
                    payload=parse_payload(fields["payload"]),
                ),
                if_match=fields["if-match"],
            )
        elif action == "show":
            fields = parse_approval_arguments(tokens[2:])
            if set(fields) - {"repository"}:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            collection = read_assurance(settings, repository_id=fields.get("repository"))
        else:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    except ConnectedCliError as error:
        stderr.write(
            "connected assurance operation was rejected (" + error.code.value + ")" + chr(10)
        )
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    except Exception:
        stderr.write("connected assurance operation failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    stdout.write(collection.render() + chr(10))
    return int(CliExitCode.COMPLETED)


def run_connected_feedback(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Submit one pilot review, or read the aggregated feedback metrics."""

    try:
        if len(tokens) < 2:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        action = tokens[1]
        settings = settings_from_environment(environment)
        if action == "submit":
            fields = parse_approval_arguments(tokens[2:])
            required = {
                "repository",
                "run",
                "finding",
                "head",
                "identity-hash",
                "decision",
                "reason",
                "rationale",
                "if-match",
            }
            if not required.issubset(fields):
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            collection = submit_feedback(
                settings,
                FeedbackDraft(
                    repository_id=fields["repository"],
                    run_id=fields["run"],
                    finding_id=fields["finding"],
                    head_sha=fields["head"],
                    identity_hash=fields["identity-hash"],
                    decision=fields["decision"],
                    reason=fields["reason"],
                    rationale=fields["rationale"],
                    incident_id=fields.get("incident-id"),
                ),
                if_match=fields["if-match"],
            )
        elif action == "metrics":
            fields = parse_approval_arguments(tokens[2:])
            if set(fields) - {"repository"}:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            collection = read_feedback_metrics(settings, repository_id=fields.get("repository"))
        else:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    except ConnectedCliError as error:
        stderr.write(
            "connected feedback operation was rejected (" + error.code.value + ")" + chr(10)
        )
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    except Exception:
        stderr.write("connected feedback operation failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    stdout.write(collection.render() + chr(10))
    return int(CliExitCode.COMPLETED)


def run_connected_deletions(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Open, approve, hold, execute or read one erasure request."""

    try:
        if len(tokens) < 2:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        action = tokens[1]
        settings = settings_from_environment(environment)
        if action == "create":
            fields = parse_approval_arguments(tokens[2:])
            required = {"deletion-id", "repository", "content-hash", "identity-hash"}
            if not required.issubset(fields):
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            collection = create_deletion(
                settings,
                DeletionDraft(
                    deletion_id=fields["deletion-id"],
                    repository_id=fields["repository"],
                    content_sha256=fields["content-hash"],
                    identity_hash=fields["identity-hash"],
                ),
            )
        elif action == "show":
            fields = parse_approval_arguments(tokens[2:])
            if set(fields) != {"deletion-id"}:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            collection = read_deletion(settings, fields["deletion-id"])
        elif action == "approve":
            fields = parse_approval_arguments(tokens[2:])
            if set(fields) != {"deletion-id", "if-match"}:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            collection = approve_deletion(
                settings, fields["deletion-id"], if_match=fields["if-match"]
            )
        elif action == "hold":
            fields = parse_approval_arguments(tokens[2:])
            required = {"deletion-id", "if-match", "enabled", "identity-hash", "reason"}
            if set(fields) != required or fields["enabled"] not in {"true", "false"}:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            collection = hold_deletion(
                settings,
                fields["deletion-id"],
                enabled=fields["enabled"] == "true",
                identity_hash=fields["identity-hash"],
                reason=fields["reason"],
                if_match=fields["if-match"],
            )
        elif action == "execute":
            fields = parse_approval_arguments(tokens[2:])
            if set(fields) != {"deletion-id", "if-match", "identity-hash"}:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            collection = execute_deletion(
                settings,
                fields["deletion-id"],
                identity_hash=fields["identity-hash"],
                if_match=fields["if-match"],
            )
        else:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    except ConnectedCliError as error:
        stderr.write(
            "connected deletion operation was rejected (" + error.code.value + ")" + chr(10)
        )
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    except Exception:
        stderr.write("connected deletion operation failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    stdout.write(collection.render() + chr(10))
    return int(CliExitCode.COMPLETED)


def run_connected_backups(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Create, read, execute or restore one backup through the control plane."""

    try:
        if len(tokens) < 2:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        action = tokens[1]
        settings = settings_from_environment(environment)
        if action == "create":
            fields = parse_approval_arguments(tokens[2:])
            required = {"backup-id", "repository", "region", "key-ref", "components"}
            if not required.issubset(fields):
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            collection = create_backup(
                settings,
                BackupDraft(
                    backup_id=fields["backup-id"],
                    repository_id=fields["repository"],
                    component_hashes=tuple(
                        item for item in fields["components"].split(",") if item
                    ),
                    region=fields["region"],
                    key_reference=fields["key-ref"],
                ),
            )
        elif action == "show":
            fields = parse_approval_arguments(tokens[2:])
            if set(fields) != {"backup-id"}:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            collection = read_backup(settings, fields["backup-id"])
        elif action in {"execute", "restore"}:
            fields = parse_approval_arguments(tokens[2:])
            if set(fields) != {"backup-id", "if-match"}:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            collection = transition_backup(
                settings,
                fields["backup-id"],
                restore=action == "restore",
                if_match=fields["if-match"],
            )
        else:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    except ConnectedCliError as error:
        stderr.write("connected backup operation was rejected (" + error.code.value + ")" + chr(10))
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    except Exception:
        stderr.write("connected backup operation failed" + chr(10))
        return int(CliExitCode.OPERATIONAL_ERROR)
    stdout.write(collection.render() + chr(10))
    return int(CliExitCode.COMPLETED)
