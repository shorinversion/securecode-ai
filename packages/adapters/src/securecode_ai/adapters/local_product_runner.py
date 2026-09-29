"""Installed host-owned private-source Core composition.

The OS approval loader is the sole production authority entry point. This module
does not provision approval, promote evidence, start providers or scan worktree
file contents. Scripted peers can test plumbing, not provider qualification.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping

from securecode_ai.contracts import ModelUsage, RunExecutionIdentity
from securecode_ai.core.reports import ReportFormat

from . import local_product_runner_execution as _execution_module
from .config import EffectiveConfiguration
from .dependency_scanning import ApprovedOsvScanner
from .git_snapshot import OfflineGitObjectReader as OfflineGitObjectReader
from .local_product_host import (
    LocalProductHost,
    verify_local_git_executable,
)
from .local_product_runner_config import (
    LocalProductCancelledError,
    LocalProductConfigurationError,
    LocalProductRepairResult,
    LocalProductScanResult,
    LocalProductSupersededError,
    LocalProductUnavailableError,
)
from .local_product_runner_config import _git as _git
from .local_product_runner_config import _pin as _pin
from .local_product_runner_config import _retain_evidence_graph as _retain_evidence_graph
from .local_product_runner_config import (
    resolve_local_product_configuration as resolve_local_product_configuration,
)
from .product_provider_runtime import ProductProviderRuntime
from .remote_provider_budget import RemoteProviderCostReceipt

for _local_product_type in (
    LocalProductConfigurationError,
    LocalProductUnavailableError,
    LocalProductCancelledError,
    LocalProductSupersededError,
    LocalProductRepairResult,
    LocalProductScanResult,
):
    _local_product_type.__module__ = __name__
del _local_product_type


def run_local_product_scan(
    *,
    host: LocalProductHost,
    target: str,
    report_format: ReportFormat,
    configuration: EffectiveConfiguration,
    execution_identity: RunExecutionIdentity | None = None,
    run_id: str | None = None,
    cancelled: Callable[[], bool] | None = None,
    on_cancel: Callable[[Callable[[], None]], None] | None = None,
    usage_observer: Callable[[ModelUsage], None] | None = None,
    cost_observer: Callable[[RemoteProviderCostReceipt], None] | None = None,
    dependency_scanner: ApprovedOsvScanner | None = None,
    provider_runtime: ProductProviderRuntime | None = None,
) -> LocalProductScanResult:
    """Execute the installed actual Core composition on one immutable HEAD."""
    try:
        return _run_local_product_scan(
            host,
            target,
            report_format,
            configuration,
            execution_identity=execution_identity,
            run_id=run_id,
            cancelled=cancelled,
            on_cancel=on_cancel,
            usage_observer=usage_observer,
            cost_observer=cost_observer,
            dependency_scanner=dependency_scanner,
            provider_runtime=provider_runtime,
        )
    except (
        LocalProductConfigurationError,
        LocalProductUnavailableError,
        LocalProductCancelledError,
        LocalProductSupersededError,
        KeyboardInterrupt,
    ):
        raise
    except Exception:
        raise LocalProductUnavailableError() from None


def run_local_product_repair(
    *,
    target: str,
    host: LocalProductHost,
    scan_result: LocalProductScanResult,
    environment: Mapping[str, str],
    cancelled: Callable[[], bool] | None = None,
    on_cancel: Callable[[Callable[[], None]], None] | None = None,
    usage_observer: Callable[[ModelUsage], None] | None = None,
    cost_observer: Callable[[RemoteProviderCostReceipt], None] | None = None,
    provider_runtime: ProductProviderRuntime | None = None,
) -> LocalProductRepairResult:
    """Run the bounded repair sidecar after one immutable product scan.

    The sidecar stores suggestions through the existing patch-artifact port and
    never mutates the checkout.  Only a source-free summary crosses this
    adapter boundary; raw diffs and model text are deliberately discarded.
    """

    from .local_repair import repair_failure_receipt, run_local_repair_journey

    try:
        value = run_local_repair_journey(
            target=target,
            host=host,
            scan_result=scan_result,
            environment=environment,
            cancelled=cancelled,
            on_cancel=on_cancel,
            usage_observer=usage_observer,
            cost_observer=cost_observer,
            provider_runtime=provider_runtime,
        )
    except Exception as error:
        value = repair_failure_receipt(error)
    summary, exit_code = _source_free_repair_summary(value)
    model_tokens = value.get("_model_tokens", 0) if isinstance(value, Mapping) else 0
    if type(model_tokens) is not int or model_tokens < 0:
        model_tokens = 0
    return LocalProductRepairResult(
        summary=summary,
        exit_code=exit_code,
        model_tokens=model_tokens,
        model_cost_microunits=0,
    )


def _run_local_product_scan(
    host: LocalProductHost,
    target: str,
    report_format: ReportFormat,
    configuration: EffectiveConfiguration,
    *,
    execution_identity: RunExecutionIdentity | None = None,
    run_id: str | None = None,
    cancelled: Callable[[], bool] | None = None,
    on_cancel: Callable[[Callable[[], None]], None] | None = None,
    usage_observer: Callable[[ModelUsage], None] | None = None,
    cost_observer: Callable[[RemoteProviderCostReceipt], None] | None = None,
    dependency_scanner: ApprovedOsvScanner | None = None,
    provider_runtime: ProductProviderRuntime | None = None,
) -> LocalProductScanResult:
    return _execution_module._run_local_product_scan(
        host,
        target,
        report_format,
        configuration,
        execution_identity=execution_identity,
        run_id=run_id,
        cancelled=cancelled,
        on_cancel=on_cancel,
        usage_observer=usage_observer,
        cost_observer=cost_observer,
        dependency_scanner=dependency_scanner,
        provider_runtime=provider_runtime,
        git_verifier=verify_local_git_executable,
        git_command=_git,
        reader_factory=OfflineGitObjectReader,
    )


__all__ = [
    "LocalProductCancelledError",
    "LocalProductConfigurationError",
    "LocalProductRepairResult",
    "LocalProductScanResult",
    "LocalProductSupersededError",
    "LocalProductUnavailableError",
    "ProductProviderRuntime",
    "resolve_local_product_configuration",
    "run_local_product_repair",
    "run_local_product_scan",
]


_SUMMARY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SUMMARY_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _source_free_repair_summary(value: object) -> tuple[bytes, int]:
    """Project the local repair receipt without retaining source-bearing data."""

    if not isinstance(value, Mapping):
        value = {"exit_code": 2, "reason": "REPAIR_OPERATION_FAILED"}
    raw_exit = value.get("exit_code")
    exit_code = raw_exit if type(raw_exit) is int and raw_exit in {0, 2} else 2
    proposal_count = value.get("proposal_count", 0)
    if type(proposal_count) is not int or not 0 <= proposal_count <= 4096:
        proposal_count = 0
    completed_repairs = _completed_repairs(value.get("completed_repairs"))
    blocked_findings = _blocked_findings(value.get("blocked_findings"))
    suggestion_only = value.get("suggestion_only") is True
    checkout_modified = value.get("checkout_modified") is True
    raw_reason = value.get("reason")
    reason = (
        raw_reason
        if isinstance(raw_reason, str)
        and raw_reason.isascii()
        and _SUMMARY_ID.fullmatch(raw_reason)
        else None
    )
    if exit_code == 0 and not _repair_summary_is_validated(
        proposal_count=proposal_count,
        completed_repairs=completed_repairs,
        blocked_findings=blocked_findings,
        suggestion_only=suggestion_only,
        checkout_modified=checkout_modified,
        reason=reason,
    ):
        exit_code = 2
    summary: dict[str, object] = {
        "exit_code": exit_code,
        "suggestion_only": suggestion_only,
        "checkout_modified": checkout_modified,
        "proposal_count": proposal_count,
        "run_id": _summary_id(value.get("run_id")),
        "finding_ids": _summary_ids(value.get("finding_ids")),
        "completed_repairs": completed_repairs,
        "blocked_findings": blocked_findings,
    }
    if reason is not None:
        summary["reason"] = reason
    elif exit_code == 2 and raw_exit == 0:
        summary["reason"] = "REPAIR_NOT_VALIDATED"
    repair_audit = value.get("repair_audit")
    projected_audit = _repair_audit(repair_audit)
    if projected_audit is not None:
        summary["repair_audit"] = projected_audit
    encoded = json.dumps(
        summary,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if not encoded or len(encoded) > 1_048_576:
        raise LocalProductUnavailableError()
    return encoded, exit_code


def _repair_summary_is_validated(
    *,
    proposal_count: int,
    completed_repairs: list[dict[str, object]],
    blocked_findings: list[dict[str, str]],
    suggestion_only: bool,
    checkout_modified: bool,
    reason: str | None,
) -> bool:
    if proposal_count == 0:
        return (
            reason == "NO_CONFIRMED_BLOCKING_FINDINGS"
            and not completed_repairs
            and not blocked_findings
            and suggestion_only
            and not checkout_modified
        )
    if (
        not suggestion_only
        or checkout_modified
        or len(completed_repairs) != proposal_count
        or blocked_findings
    ):
        return False
    for repair in completed_repairs:
        if (
            repair.get("loop_stop_reason") != "VALIDATED"
            or repair.get("loop_receipt_sha256") is None
            or _summary_sha(repair.get("patch_sha256")) is None
            or _summary_sha(repair.get("validation_result_sha256")) is None
            or _summary_sha(repair.get("manifest_sha256")) is None
            or _summary_sha(repair.get("patch_status_sha256")) is None
        ):
            return False
        attempts = repair.get("attempts")
        if not isinstance(attempts, list) or not attempts:
            return False
        final_attempt = attempts[-1]
        if not isinstance(final_attempt, Mapping):
            return False
        final_validation_sha = _summary_sha(final_attempt.get("validation_result_sha256"))
        if (
            _summary_id(final_attempt.get("validation_id")) is None
            or final_validation_sha is None
            or repair.get("validation_result_sha256") != final_validation_sha
        ):
            return False
    return True


def _summary_id(value: object) -> str | None:
    return value if isinstance(value, str) and _SUMMARY_ID.fullmatch(value) else None


def _summary_sha(value: object) -> str | None:
    return value if isinstance(value, str) and _SUMMARY_SHA256.fullmatch(value) else None


def _summary_patch_sha(selector: str) -> str | None:
    if not selector.startswith("sha256:"):
        return None
    return _summary_sha(selector.removeprefix("sha256:"))


def _summary_ids(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        identifier = _summary_id(item)
        if identifier is not None:
            result.append(identifier)
    return result


def _blocked_findings(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        finding_id = _summary_id(item.get("finding_id"))
        reason = item.get("reason")
        if (
            finding_id is None
            or not isinstance(reason, str)
            or not reason.isascii()
            or _SUMMARY_ID.fullmatch(reason) is None
        ):
            continue
        result.append({"finding_id": finding_id, "reason": reason})
    return result


def _completed_repairs(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        finding_id = _summary_id(item.get("finding_id"))
        patch_id = _summary_id(item.get("patch_id"))
        selector = _summary_id(item.get("artifact_selector"))
        if finding_id is None or patch_id is None or selector is None:
            continue
        patch_sha256 = _summary_patch_sha(selector)
        projected: dict[str, object] = {
            "finding_id": finding_id,
            "patch_id": patch_id,
            "artifact_selector": selector,
            "patch_sha256": patch_sha256,
            "validation_result_sha256": _summary_sha(item.get("validation_result_sha256")),
            "manifest_sha256": _summary_sha(item.get("manifest_sha256")),
            "patch_status_sha256": _summary_sha(item.get("patch_status_sha256")),
            "loop_receipt_sha256": _summary_sha(item.get("loop_receipt_sha256")),
        }
        for name in ("loop_stop_reason", "approval_state", "patch_status"):
            text = item.get(name)
            if isinstance(text, str) and text.isascii() and _SUMMARY_ID.fullmatch(text):
                projected[name] = text
        attempts = item.get("attempts")
        if isinstance(attempts, list):
            projected_attempts: list[dict[str, object]] = []
            for attempt in attempts:
                if not isinstance(attempt, Mapping) or type(attempt.get("attempt")) is not int:
                    continue
                attempt_value: dict[str, object] = {"attempt": attempt["attempt"]}
                for name in ("patch_id", "validation_id"):
                    identifier = _summary_id(attempt.get(name))
                    if identifier is not None:
                        attempt_value[name] = identifier
                for name in ("validation_result_sha256", "feedback_sha256"):
                    digest = _summary_sha(attempt.get(name))
                    if digest is not None:
                        attempt_value[name] = digest
                projected_attempts.append(attempt_value)
            projected["attempts"] = projected_attempts
        result.append(projected)
    return result


def _repair_audit(value: object) -> dict[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    projected: dict[str, object] = {}
    for name in ("state", "audit_outcome", "finding_gate_state"):
        text = value.get(name)
        if isinstance(text, str) and text.isascii() and _SUMMARY_ID.fullmatch(text):
            projected[name] = text
    for name in ("run_id", "execution_identity_hash", "json_report_sha256"):
        identifier = (
            _summary_sha(value.get(name)) if "sha" in name else _summary_id(value.get(name))
        )
        if identifier is not None:
            projected[name] = identifier
    for name in ("coverage_complete",):
        if type(value.get(name)) is bool:
            projected[name] = value[name]
    for name in ("repair_requested_candidate_ids",):
        projected[name] = _summary_ids(value.get(name))
    units = value.get("repair_coverage_units")
    if isinstance(units, list):
        projected_units: list[dict[str, object]] = []
        for unit in units:
            if not isinstance(unit, Mapping):
                continue
            unit_value: dict[str, object] = {}
            for name in ("coverage_unit_id", "stage_id", "subject_id", "reason_code", "receipt_id"):
                identifier = _summary_id(unit.get(name))
                if identifier is not None:
                    unit_value[name] = identifier
            for name in ("required", "applicable", "schema_valid_result"):
                if type(unit.get(name)) is bool:
                    unit_value[name] = unit[name]
            for name in ("coverage_status", "model_call_status"):
                text = unit.get(name)
                if isinstance(text, str) and text.isascii() and _SUMMARY_ID.fullmatch(text):
                    unit_value[name] = text
            for name in ("input_hashes", "output_hashes"):
                hashes = unit.get(name, [])
                if isinstance(hashes, (list, tuple)):
                    unit_value[name] = [
                        digest for item in hashes if (digest := _summary_sha(item)) is not None
                    ]
            if unit_value:
                projected_units.append(unit_value)
        projected["repair_coverage_units"] = projected_units
    return projected
