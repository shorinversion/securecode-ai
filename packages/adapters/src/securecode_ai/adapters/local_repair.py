"""Installed local proposal and validation operations for the CLI."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from securecode_ai.contracts import ComponentPin, PatchStatus, ValidationResult

from .local_patch_status import LocalPatchStatusError, LocalPatchStatusStore
from .local_product_host import LocalProductHost
from .local_product_runner_config import LocalProductScanResult
from .local_repair_contracts import (
    LocalRepairContractError,
    build_local_repair_binding,
    confirmed_blocking_findings,
    parse_retained_graph,
)
from .local_repair_model import LocalRepairModelError, generate_local_patch
from .local_repair_validation import (
    FailClosedLocalRepairValidationPort,
    LocalRepairValidationError,
    LocalRepairValidationPort,
    validate_local_patch,
)
from .patch_artifact import (
    PatchArtifactError,
    PatchArtifactStore,
    default_patch_artifact_root,
)


def propose_local_repairs(
    *,
    target: str,
    host: LocalProductHost,
    scan_result: LocalProductScanResult,
    environment: Mapping[str, str],
) -> dict[str, object]:
    """Generate content-addressed suggestions for confirmed blocking findings only."""

    checkout = Path(target).absolute()
    scan_result.require_publication()
    findings = confirmed_blocking_findings(scan_result)
    if not findings:
        return {
            "exit_code": scan_result.exit_code,
            "proposal_count": 0,
            "artifact_selectors": [],
            "finding_ids": [],
            "parent_head_sha": scan_result.composition.run.execution_identity.repository_revision.head_sha,
            "reason": "NO_CONFIRMED_BLOCKING_FINDINGS",
        }
    store = PatchArtifactStore(
        root=default_patch_artifact_root(environment),
        checkout=checkout,
    )
    selectors: list[str] = []
    completed: list[str] = []
    blocked: list[dict[str, str]] = []
    for finding in findings:
        try:
            graph = parse_retained_graph(scan_result.graph_artifact, finding)
            binding = build_local_repair_binding(finding, graph)
            scan_result.require_publication()
            proposal = generate_local_patch(
                target=target,
                host=host,
                scan_result=scan_result,
                binding=binding,
                evidence=graph.evidence,
            )
            scan_result.require_publication()
            stored = store.put(
                patch_bytes=proposal.patch_bytes,
                architect_result=proposal.result,
                finding=binding.finding,
                root_cause=binding.root_cause,
                invariant=binding.invariant,
                regression=binding.regression,
                author=proposal.author,
            )
            selectors.append(stored.selector)
            completed.append(finding.finding_id)
        except (LocalRepairContractError, LocalRepairModelError, PatchArtifactError) as error:
            blocked.append({"finding_id": finding.finding_id, "reason": error.reason})
        except Exception:
            blocked.append({"finding_id": finding.finding_id, "reason": "REPAIR_OPERATION_FAILED"})
    scan_result.require_publication()
    return {
        "exit_code": 0 if selectors and not blocked else 2,
        "proposal_count": len(selectors),
        "artifact_selectors": selectors,
        "finding_ids": completed,
        "blocked_findings": blocked,
        "parent_head_sha": scan_result.composition.run.execution_identity.repository_revision.head_sha,
        "suggestion_only": True,
        "checkout_modified": False,
    }


def validate_local_repair_artifact(
    *,
    target: str,
    selector: str,
    host: LocalProductHost,
    environment: Mapping[str, str],
    validation_port: LocalRepairValidationPort | None = None,
) -> dict[str, object]:
    checkout = Path(target).absolute()
    store = PatchArtifactStore(
        root=default_patch_artifact_root(environment),
        checkout=checkout,
    )
    artifact = store.load(selector)
    status_store = LocalPatchStatusStore()
    recorded: dict[str, object] = {}

    def record_validated(validation: ValidationResult) -> None:
        state, capability = status_store.record_validated(artifact, validation)
        recorded.update(
            {
                "approval_capability": capability,
                "patch_status": state.patch.patch_status.value,
                "patch_status_sha256": state.state_sha256,
            }
        )

    result = validate_local_patch(
        target=target,
        host=host,
        patch=artifact,
        port=validation_port or FailClosedLocalRepairValidationPort(environment),
        validated_sink=record_validated,
    )
    result.update(recorded)
    approval_pending = result.get("approval_state") == "PENDING"
    terminal_failure = result.get("validation_outcome") == "FAILED"
    delete_artifact = terminal_failure and not approval_pending
    if delete_artifact:
        store.delete(selector)
    result["artifact_deleted"] = delete_artifact
    result["artifact_retained"] = not delete_artifact
    return result


def approve_local_repair_artifact(
    *,
    target: str,
    selector: str,
    artifact_sha256: str,
    capability: str,
    approval_id: str,
    approver_id: str,
    host: LocalProductHost,
    environment: Mapping[str, str],
) -> dict[str, object]:
    """Record explicit local approval without applying or publishing the patch."""

    store = PatchArtifactStore(
        root=default_patch_artifact_root(environment),
        checkout=Path(target).absolute(),
    )
    artifact = store.load(selector)
    state = LocalPatchStatusStore().approve(
        artifact,
        artifact_sha256=artifact_sha256,
        capability=capability,
        approval_id=approval_id,
        approver_id=approver_id,
        policy=ComponentPin(
            schema_version="0.2.0",
            component_id="installed-local-approval-policy",
            component_version="1.0.0",
            content_sha256=host.approval_record_sha256,
        ),
        approved_at=datetime.now(UTC),
    )
    if state.patch.patch_status is not PatchStatus.APPROVED or state.approval is None:
        raise LocalPatchStatusError("PATCH_APPROVAL_FAILED")
    return {
        "exit_code": 0,
        "artifact_selector": artifact.selector,
        "artifact_sha256": artifact_sha256,
        "patch_status": state.patch.patch_status.value,
        "patch_status_sha256": state.state_sha256,
        "approval_id": state.approval.approval_id,
        "approval_receipt_sha256": state.approval.receipt_sha256,
        "artifact_retained": True,
        "applied": False,
        "published": False,
    }


def repair_failure_receipt(error: Exception) -> dict[str, object]:
    if isinstance(
        error,
        (
            LocalRepairContractError,
            LocalRepairModelError,
            LocalRepairValidationError,
            LocalPatchStatusError,
            PatchArtifactError,
        ),
    ):
        reason = error.reason
    else:
        reason = "REPAIR_OPERATION_FAILED"
    return {"exit_code": 2, "reason": reason, "suggestion_only": True}


__all__ = [
    "LocalRepairValidationPort",
    "approve_local_repair_artifact",
    "propose_local_repairs",
    "repair_failure_receipt",
    "validate_local_repair_artifact",
]
