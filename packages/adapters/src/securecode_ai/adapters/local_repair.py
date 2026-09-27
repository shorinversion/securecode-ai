"""Installed local proposal and validation operations for the CLI."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path

from securecode_ai.contracts import (
    ComponentPin,
    ModelUsage,
    PatchStatus,
    ValidationOutcome,
    ValidationResult,
)
from securecode_ai.core.repair_loop import (
    AttemptUsage,
    RepairState,
    RetryFeedback,
    run_repair_loop,
)
from securecode_ai.core.validation import ValidationLadderResult

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
from .product_audit import compose_product_repair_audit
from .product_audit_types import ProductAuditComposition, ProductRepairReceipt
from .product_provider_runtime import ProductProviderRuntime
from .remote_provider_budget import RemoteProviderCostReceipt


_CANCELLATION_REASONS = frozenset(
    {
        "REPAIR_CANCELLED",
        "REPAIR_CANCELLATION_UNAVAILABLE",
        "VALIDATION_CANCELLED",
        "VALIDATION_CANCELLATION_UNAVAILABLE",
    }
)


def propose_local_repairs(
    *,
    target: str,
    host: LocalProductHost,
    scan_result: LocalProductScanResult,
    environment: Mapping[str, str],
    _include_usage: bool = False,
    cancelled: Callable[[], bool] | None = None,
    usage_observer: Callable[[ModelUsage], None] | None = None,
    cost_observer: Callable[[RemoteProviderCostReceipt], None] | None = None,
    provider_runtime: ProductProviderRuntime | None = None,
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
    usages: list[dict[str, object]] = []
    for finding in findings:
        try:
            _check_cancelled(cancelled)
            graph = parse_retained_graph(scan_result.graph_artifact, finding)
            binding = build_local_repair_binding(finding, graph)
            scan_result.require_publication()
            proposal = generate_local_patch(
                target=target,
                host=host,
                scan_result=scan_result,
                binding=binding,
                evidence=graph.evidence,
                cancelled=cancelled,
                usage_observer=usage_observer,
                cost_observer=cost_observer,
                provider_runtime=provider_runtime,
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
            usages.append(
                {
                    "selector": stored.selector,
                    "patch_id": proposal.result.patch_candidate.patch_id,
                    "usage": proposal.usage,
                    "architect_model_result_sha256": proposal.model_result_sha256,
                    "architect_model_call_status": proposal.model_call_status,
                    "architect_schema_valid_result": proposal.schema_valid_result,
                    "architect_receipt_id": proposal.model_receipt_id,
                }
            )
        except (LocalRepairContractError, LocalRepairModelError, PatchArtifactError) as error:
            if getattr(error, "reason", None) in _CANCELLATION_REASONS:
                raise
            _check_cancelled(cancelled)
            blocked.append({"finding_id": finding.finding_id, "reason": error.reason})
        except Exception as error:
            if getattr(error, "reason", None) in _CANCELLATION_REASONS:
                raise
            _check_cancelled(cancelled)
            blocked.append({"finding_id": finding.finding_id, "reason": "REPAIR_OPERATION_FAILED"})
    scan_result.require_publication()
    receipt: dict[str, object] = {
        "exit_code": 0 if selectors and not blocked else 2,
        "proposal_count": len(selectors),
        "artifact_selectors": selectors,
        "finding_ids": completed,
        "blocked_findings": blocked,
        "parent_head_sha": scan_result.composition.run.execution_identity.repository_revision.head_sha,
        "suggestion_only": True,
        "checkout_modified": False,
    }
    if _include_usage:
        receipt["_proposal_usage"] = usages
    return receipt


def run_local_repair_journey(
    *,
    target: str,
    host: LocalProductHost,
    scan_result: LocalProductScanResult,
    environment: Mapping[str, str],
    validation_port: LocalRepairValidationPort | None = None,
    cancelled: Callable[[], bool] | None = None,
    on_cancel: Callable[[Callable[[], None]], None] | None = None,
    usage_observer: Callable[[ModelUsage], None] | None = None,
    cost_observer: Callable[[RemoteProviderCostReceipt], None] | None = None,
    provider_runtime: ProductProviderRuntime | None = None,
) -> dict[str, object]:
    """Propose, validate and retry confirmed findings through the bounded Core loop."""
    scan_result.require_publication()
    proposal_receipt = propose_local_repairs(
        target=target,
        host=host,
        scan_result=scan_result,
        environment=environment,
        _include_usage=True,
        cancelled=cancelled,
        usage_observer=usage_observer,
        cost_observer=cost_observer,
        provider_runtime=provider_runtime,
    )
    selectors = proposal_receipt.get("artifact_selectors", [])
    finding_ids = proposal_receipt.get("finding_ids", [])
    usage_rows = proposal_receipt.get("_proposal_usage", [])
    if (
        not isinstance(selectors, list)
        or not isinstance(finding_ids, list)
        or not isinstance(usage_rows, list)
        or len(selectors) != len(finding_ids)
        or len(selectors) != len(usage_rows)
    ):
        return repair_failure_receipt(LocalRepairContractError("REPAIR_BINDING_INVALID"))
    initial_blocked = list(proposal_receipt.get("blocked_findings", []))
    if not selectors and not initial_blocked:
        return {
            "exit_code": int(proposal_receipt.get("exit_code", 2)),
            "run_id": scan_result.composition.run.run_id,
            "proposal_count": 0,
            "completed_repairs": [],
            "blocked_findings": [],
            "reason": proposal_receipt.get("reason", "NO_CONFIRMED_BLOCKING_FINDINGS"),
            "suggestion_only": True,
            "checkout_modified": False,
            "product_pass": False,
        }
    store = PatchArtifactStore(root=default_patch_artifact_root(environment), checkout=Path(target).absolute())
    findings = {item.finding_id: item for item in confirmed_blocking_findings(scan_result)}
    usages = {
        item["selector"]: item["usage"]
        for item in usage_rows
        if isinstance(item, dict) and isinstance(item.get("selector"), str)
    }
    architect_receipts: dict[str, dict[str, object]] = {
        item["patch_id"]: item
        for item in usage_rows
        if isinstance(item, dict)
        and isinstance(item.get("patch_id"), str)
        and isinstance(item.get("architect_model_result_sha256"), str)
    }
    completed: list[dict[str, object]] = []
    repair_receipts: list[ProductRepairReceipt] = []
    blocked = initial_blocked
    final_diffs: list[str] = []
    all_validated = bool(finding_ids) and not blocked
    status_store = LocalPatchStatusStore()
    port = validation_port or FailClosedLocalRepairValidationPort(environment)
    for selector, finding_id in zip(selectors, finding_ids, strict=True):
        finding = findings.get(finding_id)
        if finding is None or not isinstance(selector, str):
            blocked.append({"finding_id": str(finding_id), "reason": "REPAIR_BINDING_INVALID"})
            all_validated = False
            continue
        artifacts: dict[str, object] = {}
        validations: dict[str, ValidationLadderResult] = {}
        try:
            graph = parse_retained_graph(scan_result.graph_artifact, finding)
            binding = build_local_repair_binding(finding, graph)
            initial = store.load(selector)
            if (
                initial.finding != binding.finding
                or initial.root_cause != binding.root_cause
                or initial.invariant != binding.invariant
                or initial.regression != binding.regression
            ):
                raise LocalRepairContractError("PATCH_BINDING_MISMATCH")
            artifacts[initial.architect_result.patch_candidate.patch_id] = initial
            initial_usage = usages.get(selector)
            if type(initial_usage) is not AttemptUsage:
                raise LocalRepairContractError("REPAIR_USAGE_MISSING")
            if initial.architect_result.patch_candidate.patch_id not in architect_receipts:
                raise LocalRepairContractError("REPAIR_ARCHITECT_RECEIPT_MISSING")

            def validate_patch(patch, attempt):
                _check_cancelled(cancelled)
                artifact = artifacts.get(patch.patch_candidate.patch_id)
                if artifact is None or artifact.architect_result != patch:
                    raise LocalRepairContractError("PATCH_BINDING_MISMATCH")
                captured: list[ValidationLadderResult] = []
                validate_local_patch(
                    target=target,
                    host=host,
                    patch=artifact,
                    port=port,
                    ladder_sink=captured.append,
                    cancelled=cancelled,
                    on_cancel=on_cancel,
                )
                if len(captured) != 1:
                    raise LocalRepairContractError("VALIDATION_RESULT_MISSING")
                validations[captured[0].validation.validation_id] = captured[0]
                return captured[0], AttemptUsage()

            def propose_patch(feedback: RetryFeedback, attempt: int):
                proposal = generate_local_patch(
                    target=target,
                    host=host,
                    scan_result=scan_result,
                    binding=binding,
                    evidence=graph.evidence,
                    attempt=attempt,
                    retry_feedback=feedback,
                    cancelled=cancelled,
                    usage_observer=usage_observer,
                    cost_observer=cost_observer,
                    provider_runtime=provider_runtime,
                )
                stored = store.put(
                    patch_bytes=proposal.patch_bytes,
                    architect_result=proposal.result,
                    finding=binding.finding,
                    root_cause=binding.root_cause,
                    invariant=binding.invariant,
                    regression=binding.regression,
                    author=proposal.author,
                )
                artifacts[proposal.result.patch_candidate.patch_id] = stored
                architect_receipts[proposal.result.patch_candidate.patch_id] = {
                    "patch_id": proposal.result.patch_candidate.patch_id,
                    "architect_model_result_sha256": proposal.model_result_sha256,
                    "architect_model_call_status": proposal.model_call_status,
                    "architect_schema_valid_result": proposal.schema_valid_result,
                    "architect_receipt_id": proposal.model_receipt_id,
                }
                return proposal.result, proposal.usage

            loop = run_repair_loop(
                initial.architect_result,
                validate_patch,
                propose_patch,
                initial_usage=initial_usage,
            )
            final_attempt = loop.attempts[-1]
            final_artifact = artifacts[final_attempt.patch_id]
            final_validation = validations.get(final_attempt.validation_id)
            final_architect = architect_receipts.get(final_attempt.patch_id)
            if final_architect is None or final_validation is None:
                raise LocalRepairContractError("REPAIR_RECEIPTS_INCOMPLETE")
            repair_receipts.append(
                ProductRepairReceipt(
                    finding_id=finding_id,
                    candidate_id=finding.candidate_id,
                    candidate_version=finding.candidate_version,
                    run_id=scan_result.composition.run.run_id,
                    execution_identity_hash=(
                        scan_result.composition.run.execution_identity.execution_identity_hash
                    ),
                    root_cause=binding.root_cause,
                    regression=binding.regression,
                    architect=final_artifact.architect_result,
                    architect_model_result_sha256=final_architect[
                        "architect_model_result_sha256"
                    ],
                    architect_model_call_status=final_architect[
                        "architect_model_call_status"
                    ],
                    architect_schema_valid_result=final_architect[
                        "architect_schema_valid_result"
                    ],
                    architect_receipt_id=final_architect["architect_receipt_id"],
                    validation=final_validation,
                    repair_loop=loop,
                )
            )
            validated = (
                loop.final_state is RepairState.VALIDATED_CANDIDATE
                and final_validation is not None
                and final_validation.validation.validation_outcome.value == "VALIDATED"
            )
            if validated and final_validation is not None:
                state, capability = status_store.record_validated(
                    final_artifact, final_validation.validation
                )
                status_metadata = {
                    "approval_state": "PENDING",
                    "approval_capability": capability,
                    "patch_status": state.patch.patch_status.value,
                    "patch_status_sha256": state.state_sha256,
                }
                final_diffs.append(final_artifact.patch_bytes.decode("utf-8", errors="strict"))
            else:
                status_metadata = {}
                all_validated = False
                if (
                    final_validation is not None
                    and final_validation.validation.validation_outcome is ValidationOutcome.FAILED
                ):
                    for artifact in artifacts.values():
                        store.delete(artifact.selector)
                    blocked.append(
                        {
                            "finding_id": finding_id,
                            "reason": "REPAIR_ARTIFACT_DISCARDED",
                        }
                    )
                    continue
                else:
                    final_diffs.append(final_artifact.patch_bytes.decode("utf-8", errors="strict"))
            for artifact in artifacts.values():
                if artifact.selector != final_artifact.selector:
                    try:
                        store.delete(artifact.selector)
                    except Exception:
                        pass
            completed.append(
                {
                    "finding_id": finding_id,
                    "artifact_selector": final_artifact.selector,
                    "patch_sha256": final_artifact.architect_result.patch_candidate.unified_diff_sha256,
                    "manifest_sha256": final_artifact.manifest_sha256,
                    "validation_result_sha256": final_attempt.validation_result_sha256,
                    "patch_id": final_attempt.patch_id,
                    "loop_stop_reason": loop.stop_reason.value,
                    "loop_receipt_sha256": loop.receipt_sha256,
                    "attempts": [
                        {
                            "attempt": item.attempt,
                            "state": item.state.value,
                            "patch_id": item.patch_id,
                            "validation_id": item.validation_id,
                            "validation_result_sha256": item.validation_result_sha256,
                            "feedback_sha256": item.feedback.feedback_sha256 if item.feedback else None,
                        }
                        for item in loop.attempts
                    ],
                    **status_metadata,
                }
            )
        except Exception as error:
            if getattr(error, "reason", None) in _CANCELLATION_REASONS:
                raise
            _check_cancelled(cancelled)
            all_validated = False
            reason = getattr(error, "reason", "REPAIR_OPERATION_FAILED")
            blocked.append({"finding_id": finding_id, "reason": reason})
    scan_result.require_publication()
    repair_audit = _compose_repair_audit(scan_result.composition, repair_receipts)
    return {
        "exit_code": 0 if all_validated and completed and not blocked else 2,
        "run_id": scan_result.composition.run.run_id,
        "execution_identity_hash": (
            scan_result.composition.run.execution_identity.execution_identity_hash
        ),
        "proposal_count": len(selectors),
        "completed_repairs": completed,
        "blocked_findings": blocked,
        "repair_diff": "\n".join(final_diffs) if final_diffs else None,
        "diff_sha256": hashlib.sha256("\n".join(final_diffs).encode("utf-8")).hexdigest()
        if final_diffs
        else None,
        "suggestion_only": True,
        "checkout_modified": False,
        "product_pass": False,
        "repair_audit": repair_audit,
        "_model_tokens": _repair_model_tokens(
            selectors=selectors,
            finding_ids=finding_ids,
            usage_rows=usage_rows,
            receipts=repair_receipts,
        ),
    }


def _check_cancelled(cancelled: Callable[[], bool] | None) -> None:
    if cancelled is None:
        return
    try:
        requested = cancelled()
    except Exception:
        raise LocalRepairContractError("REPAIR_CANCELLATION_UNAVAILABLE") from None
    if requested:
        raise LocalRepairContractError("REPAIR_CANCELLED")


def _repair_model_tokens(
    *,
    selectors: list[object],
    finding_ids: list[object],
    usage_rows: list[object],
    receipts: list[ProductRepairReceipt],
) -> int:
    """Count architect tokens exactly once for the source-free worker meter."""

    receipt_finding_ids = {item.finding_id for item in receipts}
    total = sum(item.repair_loop.usage.tokens_used for item in receipts)
    for selector, finding_id, row in zip(selectors, finding_ids, usage_rows, strict=True):
        if finding_id in receipt_finding_ids or not isinstance(row, Mapping):
            continue
        if row.get("selector") != selector:
            continue
        usage = row.get("usage")
        if isinstance(usage, AttemptUsage):
            total += usage.tokens_used
    return total


def _compose_repair_audit(
    composition: ProductAuditComposition,
    receipts: list[ProductRepairReceipt],
) -> dict[str, object]:
    """Attach real repair receipts to the originating product audit."""

    if not receipts:
        return {"state": "NOT_AVAILABLE", "reason": "REPAIR_RECEIPTS_MISSING"}
    result = compose_product_repair_audit(composition, tuple(receipts))
    if not isinstance(result, ProductAuditComposition):
        return {"state": "INDETERMINATE", "reason": result.code}
    return {
        "state": "COMPOSED",
        "run_id": result.run.run_id,
        "execution_identity_hash": result.run.execution_identity.execution_identity_hash,
        "audit_outcome": result.run.audit_outcome.value,
        "coverage_complete": result.run.coverage_manifest.coverage_complete,
        "finding_gate_state": result.run.finding_gate_state.value,
        "json_report_sha256": hashlib.sha256(result.json_report).hexdigest(),
        "repair_requested_candidate_ids": list(
            result.run.coverage_manifest.repair_requested_candidate_ids
        ),
        "repair_coverage_units": [
            item.model_dump(mode="json")
            for item in result.run.coverage_manifest.units
            if item.stage_id
            in {
                "root_cause_localization",
                "security_test_generation",
                "architect",
                "validation_ladder",
            }
        ],
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
        "patch_sha256": artifact.architect_result.patch_candidate.unified_diff_sha256,
        "manifest_sha256": artifact.manifest_sha256,
        "validation_result_sha256": (
            state.validation.result_sha256 if state.validation is not None else None
        ),
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
    "run_local_repair_journey",
    "validate_local_repair_artifact",
]
