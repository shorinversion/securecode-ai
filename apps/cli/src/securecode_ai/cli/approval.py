"""Explicit installed CLI flow for durable local patch approval."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import TextIO

from .atomic_output import write_new_output

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FAILURE_REASON = re.compile(r"[A-Z0-9_]{1,64}\Z")


def run_patch_approval_command(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Approve an exact validated artifact, without apply or SCM authority."""

    try:
        values, output = _parse(tokens)
    except ValueError:
        stderr.write("invalid approve command usage\n")
        return 5
    try:
        from securecode_ai.adapters.local_repair import (
            approve_local_repair_artifact,
            repair_failure_receipt,
        )

        from .scan import load_installed_product_host

        try:
            _require_connected_repair_approval(
                target=values["target"],
                selector=values["patch"],
                approval_id=values["approval_id"],
                approver_id=values["approver_id"],
                execution_identity_hash=values.get("execution_identity_hash")
                or environment.get("SECURECODE_EXECUTION_IDENTITY_HASH"),
                environment=environment,
            )
            result = approve_local_repair_artifact(
                target=values["target"],
                selector=values["patch"],
                artifact_sha256=values["artifact_sha256"],
                capability=values["capability"],
                approval_id=values["approval_id"],
                approver_id=values["approver_id"],
                host=load_installed_product_host(),
                environment=environment,
            )
        except Exception as error:
            result = repair_failure_receipt(error)
        result = _safe_receipt(result)
        rendered = _canonical(result) + b"\n"
        if output is not None:
            write_new_output(output, rendered)
        else:
            stdout.write(rendered.decode("ascii"))
        return result["exit_code"]
    except KeyboardInterrupt:
        stderr.write("approve operation cancelled\n")
        return 6
    except Exception:
        stderr.write("approve operation failed\n")
        return 4


_CONNECTED_APPROVAL_CONFIGURATION = (
    "SECURECODE_CONTROL_PLANE_URL",
    "SECURECODE_CONTROL_PLANE_TOKEN",
    "SECURECODE_TENANT_ID",
    "SECURECODE_REPOSITORY_ID",
)


def _require_connected_repair_approval(
    *,
    target: str,
    selector: str,
    approval_id: str,
    approver_id: str,
    execution_identity_hash: str | None,
    environment: Mapping[str, str],
) -> None:
    """Require a durable control-plane approval before local promotion.

    ``LocalPatchStatusStore`` binds the exact validated patch and capability.
    When connected mode is configured, the server approval is an additional
    prerequisite bound to the same tenant, repository, run, finding and
    execution identity. The local status transition is never promoted from a
    merely pending server request.
    """

    configured = any(environment.get(name) for name in _CONNECTED_APPROVAL_CONFIGURATION)
    if not configured:
        return
    from securecode_ai.adapters.local_patch_status import LocalPatchStatusError
    from securecode_ai.adapters.patch_artifact import (
        PatchArtifactStore,
        default_patch_artifact_root,
    )

    if any(not environment.get(name) for name in _CONNECTED_APPROVAL_CONFIGURATION):
        raise LocalPatchStatusError("CONNECTED_APPROVAL_CONFIGURATION_REQUIRED")
    if (
        type(execution_identity_hash) is not str
        or _SHA256.fullmatch(execution_identity_hash) is None
    ):
        raise LocalPatchStatusError("CONNECTED_APPROVAL_IDENTITY_REQUIRED")
    environment_identity = environment.get("SECURECODE_EXECUTION_IDENTITY_HASH")
    if (
        environment_identity is not None
        and environment_identity != execution_identity_hash
    ):
        raise LocalPatchStatusError("CONNECTED_APPROVAL_SCOPE_MISMATCH")
    try:
        artifact = PatchArtifactStore(
            root=default_patch_artifact_root(environment),
            checkout=Path(target).absolute(),
        ).load(selector)
        from securecode_ai.adapters.local_patch_status import LocalPatchStatusStore

        local_state = LocalPatchStatusStore().load(artifact)
        if (
            local_state.patch.patch_status.value != "VALIDATED"
            or local_state.validation is None
        ):
            raise LocalPatchStatusError("CONNECTED_APPROVAL_LOCAL_VALIDATION_REQUIRED")
        revision = artifact.finding.repository_revision
        supplied_head = environment.get("SECURECODE_HEAD_SHA")
        if supplied_head is not None and supplied_head != revision.head_sha:
            raise LocalPatchStatusError("CONNECTED_APPROVAL_SCOPE_MISMATCH")
        connected_environment = dict(environment)
        connected_environment["SECURECODE_HEAD_SHA"] = revision.head_sha
        from .connected_approvals import read_approval, repair_approval_id
        from .connected_runs import settings_from_environment

        settings = settings_from_environment(connected_environment)
        if (
            settings.tenant_id != revision.tenant_id
            or settings.repository_id != revision.repository_id
            or settings.head_sha != revision.head_sha
        ):
            raise LocalPatchStatusError("CONNECTED_APPROVAL_SCOPE_MISMATCH")
        projection = read_approval(settings, approval_id).document
        run_id = projection.get("run_id")
        expected_approval_id = (
            repair_approval_id(
                run_id,
                artifact.finding.finding_id,
                artifact.architect_result.patch_candidate.unified_diff_sha256,
            )
            if type(run_id) is str and _ID.fullmatch(run_id) is not None
            else None
        )
        if (
            projection.get("approval_id") != approval_id
            or projection.get("tenant_id") != revision.tenant_id
            or projection.get("repository_id") != revision.repository_id
            or expected_approval_id != approval_id
            or projection.get("finding_id") != artifact.finding.finding_id
            or projection.get("state") != "APPROVED"
            or projection.get("execution_identity_hash") != execution_identity_hash
            or projection.get("patch_sha256")
            != artifact.architect_result.patch_candidate.unified_diff_sha256
            or projection.get("manifest_sha256") != artifact.manifest_sha256
            or type(projection.get("validation_result_sha256")) is not str
            or _SHA256.fullmatch(projection["validation_result_sha256"]) is None
            or type(projection.get("patch_status_sha256")) is not str
            or _SHA256.fullmatch(projection["patch_status_sha256"]) is None
        ):
            raise LocalPatchStatusError("CONNECTED_APPROVAL_REQUIRED")
        decision = projection.get("decision")
        if not isinstance(decision, Mapping) or decision.get("actor_id") != approver_id:
            raise LocalPatchStatusError("CONNECTED_APPROVAL_SCOPE_MISMATCH")
    except LocalPatchStatusError:
        raise
    except Exception:
        raise LocalPatchStatusError("CONNECTED_APPROVAL_UNAVAILABLE") from None


def _parse(tokens: tuple[str, ...]) -> tuple[dict[str, str], Path | None]:
    if len(tokens) < 2 or tokens[0] != "approve" or not tokens[1] or tokens[1].startswith("-"):
        raise ValueError
    values = {"target": tokens[1]}
    output: Path | None = None
    flags = {
        "--patch": "patch",
        "--artifact-sha256": "artifact_sha256",
        "--capability": "capability",
        "--approval-id": "approval_id",
        "--approver-id": "approver_id",
        "--execution-identity-hash": "execution_identity_hash",
    }
    index = 2
    while index < len(tokens):
        flag = tokens[index]
        index += 1
        if index >= len(tokens) or not tokens[index] or tokens[index].startswith("-"):
            raise ValueError
        value = tokens[index]
        if flag == "--output":
            if output is not None:
                raise ValueError
            output = Path(value)
        elif flag in flags:
            key = flags[flag]
            if key in values:
                raise ValueError
            values[key] = value
        else:
            raise ValueError
        index += 1
    if set(values) != {
        "target",
        "patch",
        "artifact_sha256",
        "capability",
        "approval_id",
        "approver_id",
    } and set(values) != {
        "target",
        "patch",
        "artifact_sha256",
        "capability",
        "approval_id",
        "approver_id",
        "execution_identity_hash",
    }:
        raise ValueError
    if (
        _SHA256.fullmatch(values["artifact_sha256"]) is None
        or _SHA256.fullmatch(values["capability"]) is None
        or not values["patch"].endswith(values["artifact_sha256"])
        or _ID.fullmatch(values["approval_id"]) is None
        or _ID.fullmatch(values["approver_id"]) is None
        or (
            "execution_identity_hash" in values
            and _SHA256.fullmatch(values["execution_identity_hash"]) is None
        )
    ):
        raise ValueError
    return values, output


def _canonical(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        dict(value), ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _safe_receipt(value: object) -> dict[str, object]:
    """Accept only bounded local approval receipts before writing output."""

    if not isinstance(value, Mapping):
        raise ValueError
    if set(value) == {"exit_code", "reason", "suggestion_only"}:
        if (
            type(value.get("exit_code")) is not int
            or value["exit_code"] != 2
            or type(value.get("reason")) is not str
            or _FAILURE_REASON.fullmatch(value["reason"]) is None
            or value.get("suggestion_only") is not True
        ):
            raise ValueError
        return dict(value)
    required = {
        "exit_code",
        "artifact_selector",
        "artifact_sha256",
        "patch_sha256",
        "manifest_sha256",
        "validation_result_sha256",
        "patch_status",
        "patch_status_sha256",
        "approval_id",
        "approval_receipt_sha256",
        "artifact_retained",
        "applied",
        "published",
    }
    if set(value) != required:
        raise ValueError
    if (
        type(value.get("exit_code")) is not int
        or value["exit_code"] != 0
        or type(value.get("artifact_selector")) is not str
        or not value["artifact_selector"]
        or type(value.get("artifact_sha256")) is not str
        or _SHA256.fullmatch(value["artifact_sha256"]) is None
        or type(value.get("patch_sha256")) is not str
        or _SHA256.fullmatch(value["patch_sha256"]) is None
        or value["patch_sha256"] != value["artifact_sha256"]
        or type(value.get("manifest_sha256")) is not str
        or _SHA256.fullmatch(value["manifest_sha256"]) is None
        or type(value.get("validation_result_sha256")) is not str
        or _SHA256.fullmatch(value["validation_result_sha256"]) is None
        or value.get("patch_status") != "APPROVED"
        or type(value.get("patch_status_sha256")) is not str
        or _SHA256.fullmatch(value["patch_status_sha256"]) is None
        or type(value.get("approval_id")) is not str
        or _ID.fullmatch(value["approval_id"]) is None
        or type(value.get("approval_receipt_sha256")) is not str
        or _SHA256.fullmatch(value["approval_receipt_sha256"]) is None
        or value.get("artifact_retained") is not True
        or value.get("applied") is not False
        or value.get("published") is not False
    ):
        raise ValueError
    return dict(value)


__all__ = ["run_patch_approval_command"]
