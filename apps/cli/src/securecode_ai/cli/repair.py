"""Safe composition boundary for the Core scan/fix/validate commands.

The CLI deliberately consumes receipts, not source or patch bytes.  Core
workers can be injected by the application (and by the eventual integration
layer); this module only validates the receipt and renders a bounded,
metadata-only document.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol

from securecode_ai.contracts import CliCommand, CliExitCode

if TYPE_CHECKING:
    from securecode_ai.adapters.local_repair_validation import LocalRepairValidationPort


class RepairFormat(StrEnum):
    JSON = "json"
    SARIF = "sarif"
    MARKDOWN = "markdown"
    HTML = "html"
    DIFF = "diff"


class RepairOutcome(StrEnum):
    COMPLETED = "COMPLETED"
    POLICY_FAIL = "POLICY_FAIL"
    INDETERMINATE = "INDETERMINATE"
    OPERATIONAL_ERROR = "OPERATIONAL_ERROR"
    INVALID_USAGE_OR_CONFIG = "INVALID_USAGE_OR_CONFIG"
    CANCELLED_OR_SUPERSEDED = "CANCELLED_OR_SUPERSEDED"


_EXIT_TO_OUTCOME = {
    CliExitCode.COMPLETED: RepairOutcome.COMPLETED,
    CliExitCode.POLICY_FAIL: RepairOutcome.POLICY_FAIL,
    CliExitCode.INDETERMINATE: RepairOutcome.INDETERMINATE,
    CliExitCode.OPERATIONAL_ERROR: RepairOutcome.OPERATIONAL_ERROR,
    CliExitCode.INVALID_USAGE_OR_CONFIG: RepairOutcome.INVALID_USAGE_OR_CONFIG,
    CliExitCode.CANCELLED_OR_SUPERSEDED: RepairOutcome.CANCELLED_OR_SUPERSEDED,
}
_UNSAFE_KEYS = frozenset(
    {"source", "source_text", "diff", "repair_diff", "patch", "content", "secret", "raw"}
)
_MAX_DIFF_OUTPUT_BYTES = 1_048_576
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


class RepairWorker(Protocol):
    def __call__(self, target: str) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class RepairReceipt:
    """Stable operation receipt; ``product_outcome`` is never a product PASS."""

    command: CliCommand
    operation_outcome: RepairOutcome
    exit_code: CliExitCode
    product_outcome: str
    metadata: Mapping[str, Any]
    artifact_sha256: str
    diff_output: str | None = field(default=None, repr=False)

    def document(self) -> dict[str, Any]:
        return {
            "artifact_sha256": self.artifact_sha256,
            "command": self.command.value,
            "exit_code": int(self.exit_code),
            "metadata": dict(self.metadata),
            "operation_outcome": self.operation_outcome.value,
            "product_outcome": self.product_outcome,
            "schema_version": "0.2.0",
        }


class RepairCli:
    """Run a Core receipt producer without granting it output authority."""

    def __init__(
        self,
        *,
        scan: RepairWorker | None = None,
        fix: RepairWorker | None = None,
        validate: RepairWorker | None = None,
        environment: Mapping[str, str] | None = None,
        validation_port: LocalRepairValidationPort | None = None,
        patch_selector: str | None = None,
    ) -> None:
        if (
            scan is None
            and fix is None
            and validate is None
            and (
                environment is not None or validation_port is not None or patch_selector is not None
            )
        ):
            fix, validate = _installed_workers(
                os.environ if environment is None else environment,
                validation_port=validation_port,
                patch_selector=patch_selector,
            )
        self._workers = {CliCommand.SCAN: scan, CliCommand.FIX: fix, CliCommand.VALIDATE: validate}

    def run(self, command: CliCommand, target: str) -> RepairReceipt:
        if (
            type(command) is not CliCommand
            or command not in self._workers
            or type(target) is not str
            or not target
        ):
            return _receipt(
                command if type(command) is CliCommand else CliCommand.SCAN,
                RepairOutcome.INVALID_USAGE_OR_CONFIG,
                CliExitCode.INVALID_USAGE_OR_CONFIG,
                {},
            )
        worker = self._workers[command]
        if worker is None:
            return _receipt(
                command,
                RepairOutcome.INDETERMINATE,
                CliExitCode.INDETERMINATE,
                {"reason": "worker_unavailable"},
            )
        try:
            raw = worker(target)
            if not isinstance(raw, Mapping):
                raise ValueError
            diff_output = None
            if command is CliCommand.FIX and raw.get("repair_diff") is not None:
                candidate = raw.get("repair_diff")
                digest = raw.get("diff_sha256")
                if (
                    type(candidate) is not str
                    or len(candidate) > _MAX_DIFF_OUTPUT_BYTES
                    or len(candidate.encode("utf-8", errors="strict")) > _MAX_DIFF_OUTPUT_BYTES
                    or _CONTROL.search(candidate)
                    or type(digest) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                    or hashlib.sha256(candidate.encode("utf-8")).hexdigest() != digest
                ):
                    raise ValueError
                diff_output = candidate
            safe = _safe_metadata(raw)
            code = CliExitCode(int(raw.get("exit_code", CliExitCode.COMPLETED)))
            outcome = _EXIT_TO_OUTCOME[code]
            # A successful CLI operation is not evidence of a product PASS.
            safe["product_pass"] = False
            return _receipt(command, outcome, code, safe, diff_output=diff_output)
        except KeyboardInterrupt:
            return _receipt(
                command,
                RepairOutcome.CANCELLED_OR_SUPERSEDED,
                CliExitCode.CANCELLED_OR_SUPERSEDED,
                {},
            )
        except Exception:
            return _receipt(
                command, RepairOutcome.OPERATIONAL_ERROR, CliExitCode.OPERATIONAL_ERROR, {}
            )


def _receipt(
    command: CliCommand,
    outcome: RepairOutcome,
    code: CliExitCode,
    metadata: Mapping[str, Any],
    *,
    diff_output: str | None = None,
) -> RepairReceipt:
    document = {
        "command": command.value,
        "operation_outcome": outcome.value,
        "metadata": dict(metadata),
    }
    digest = hashlib.sha256(_canonical(document)).hexdigest()
    return RepairReceipt(
        command, outcome, code, "NOT_EVALUATED", dict(metadata), digest, diff_output
    )


def _installed_workers(
    environment: Mapping[str, str],
    *,
    validation_port: LocalRepairValidationPort | None,
    patch_selector: str | None,
) -> tuple[RepairWorker, RepairWorker]:
    selected_environment = {
        key: value for key, value in environment.items() if type(key) is str and type(value) is str
    }

    def fix(target: str) -> Mapping[str, Any]:
        from securecode_ai.adapters.local_repair import (
            repair_failure_receipt,
            run_local_repair_journey,
        )

        from .scan import (
            ProductScanArguments,
            _execute_installed_product_scan,
            load_installed_product_host,
            _remote_provider_requested,
        )
        from securecode_ai.adapters.product_provider_runtime import (
            load_product_provider_runtime,
        )
        from securecode_ai.adapters.local_provider_gateway_server import (
            _running_approved_gateway,
            gateway_observation_path,
        )

        try:
            host = load_installed_product_host()
            if _remote_provider_requested(host, selected_environment):
                provider_runtime = load_product_provider_runtime(
                    profile_path=selected_environment.get("SECURECODE_REMOTE_PROFILE_FILE", ""),
                    policy_path=selected_environment.get("SECURECODE_REMOTE_POLICY_FILE", ""),
                    environment=selected_environment,
                    tenant_id=selected_environment.get("SECURECODE_REMOTE_TENANT_ID", ""),
                    expected_profile_sha256=selected_environment.get(
                        "SECURECODE_REMOTE_PROFILE_SHA256"
                    ),
                    expected_policy_sha256=selected_environment.get(
                        "SECURECODE_REMOTE_POLICY_SHA256"
                    ),
                    expected_egress_sha256=selected_environment.get(
                        "SECURECODE_REMOTE_EGRESS_SHA256"
                    ),
                    expected_configuration_sha256=selected_environment.get(
                        "SECURECODE_REMOTE_CONFIGURATION_SHA256"
                    ),
                )
                try:
                    provider_runtime.repair()
                    scan_result = _execute_installed_product_scan(
                        ProductScanArguments(target, RepairFormat.JSON, None),
                        environment=selected_environment,
                        host=host,
                        gateway_already_running=False,
                    )
                    scan_result.require_publication()
                    identity = scan_result.composition.run.execution_identity
                    if (
                        identity.provider_profile.content_sha256
                        != provider_runtime.profile.canonical_content_hash()
                        or identity.policy.content_sha256
                        != provider_runtime.policy.canonical_content_hash()
                        or identity.egress_profile.content_sha256
                        != provider_runtime.policy.canonical_content_hash()
                        or identity.configuration.content_sha256
                        != provider_runtime.configuration.canonical_content_hash()
                    ):
                        raise ValueError("remote repair identity mismatch")
                    result = run_local_repair_journey(
                        target=target,
                        host=host,
                        scan_result=scan_result,
                        environment=selected_environment,
                        validation_port=validation_port,
                        provider_runtime=provider_runtime,
                    )
                    return result
                finally:
                    provider_runtime.close()
            with _running_approved_gateway(
                host.profile,
                host.ollama_version,
                observation_path=gateway_observation_path(selected_environment),
            ):
                scan_result = _execute_installed_product_scan(
                    ProductScanArguments(target, RepairFormat.JSON, None),
                    environment=selected_environment,
                    host=host,
                    gateway_already_running=True,
                )
                scan_result.require_publication()
                result = run_local_repair_journey(
                    target=target,
                    host=host,
                    scan_result=scan_result,
                    environment=selected_environment,
                    validation_port=validation_port,
                )
                return result
        except Exception as error:
            return repair_failure_receipt(error)

    def validate(target: str) -> Mapping[str, Any]:
        from securecode_ai.adapters.local_repair import (
            repair_failure_receipt,
            validate_local_repair_artifact,
        )

        from .scan import load_installed_product_host

        selector = patch_selector or selected_environment.get("SECURECODE_AI_PATCH_SELECTOR")
        if not selector:
            return {"exit_code": 4, "reason": "PATCH_SELECTOR_REQUIRED"}
        try:
            host = load_installed_product_host()
            return validate_local_repair_artifact(
                target=target,
                selector=selector,
                host=host,
                environment=selected_environment,
                validation_port=validation_port,
            )
        except Exception as error:
            return repair_failure_receipt(error)

    return fix, validate


def build_installed_repair_cli(
    *,
    environment: Mapping[str, str],
    patch_selector: str | None = None,
    validation_port: LocalRepairValidationPort | None = None,
) -> RepairCli:
    """Compose installed workers while preserving direct injected-worker construction."""

    return RepairCli(
        environment=environment,
        patch_selector=patch_selector,
        validation_port=validation_port,
    )


def _safe_metadata(value: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in value.items():
        if type(key) is not str or key.lower() in _UNSAFE_KEYS or _CONTROL.search(key):
            continue
        result[key] = _safe_value(item)
    return result


def _safe_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _safe_metadata(value)
    if isinstance(value, (tuple, list)):
        return [_safe_value(item) for item in value[:256]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str):
            return _CONTROL.sub("", value)[:512]
        return value
    return str(type(value).__name__)


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def render_receipt(receipt: RepairReceipt, report_format: RepairFormat) -> bytes:
    if type(receipt) is not RepairReceipt or type(report_format) is not RepairFormat:
        raise ValueError("repair receipt or format is invalid")
    document = receipt.document()
    if report_format is RepairFormat.DIFF:
        if receipt.diff_output is not None:
            return receipt.diff_output.encode("utf-8")
        return _canonical(document) + b"\n"
    if report_format is RepairFormat.JSON:
        return _canonical(document) + b"\n"
    if report_format is RepairFormat.SARIF:
        return (
            _canonical(
                {
                    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {"driver": {"name": "SecureCode AI CLI", "rules": []}},
                            "results": [],
                            "properties": document,
                        }
                    ],
                }
            )
            + b"\n"
        )
    if report_format is RepairFormat.MARKDOWN:
        rendered = (
            "# SecureCode AI operation\n\n"
            + "- command: "
            + _md(receipt.command.value)
            + "\n"
            + "- outcome: "
            + _md(receipt.operation_outcome.value)
            + "\n"
            + "- product outcome: NOT_EVALUATED\n"
        )
        audit = _repair_audit_fields(receipt.metadata)
        if audit:
            rendered += "\n## Repaired audit\n\n"
            rendered += "".join(
                f"- {key}: {_md(value)}\n" for key, value in audit.items()
            )
        return rendered.encode()
    rendered_html = (
        '<!doctype html><meta charset="utf-8"><title>SecureCode AI operation</title><h1>SecureCode AI operation</h1><dl><dt>command</dt><dd>'
        + html.escape(receipt.command.value)
        + "</dd><dt>outcome</dt><dd>"
        + html.escape(receipt.operation_outcome.value)
        + "</dd><dt>product outcome</dt><dd>NOT_EVALUATED</dd></dl>"
    )
    audit = _repair_audit_fields(receipt.metadata)
    if audit:
        rendered_html += "<h2>Repaired audit</h2><dl>"
        rendered_html += "".join(
            f"<dt>{html.escape(key)}</dt><dd>{html.escape(value)}</dd>"
            for key, value in audit.items()
        )
        rendered_html += "</dl>"
    return rendered_html.encode()


def _repair_audit_fields(metadata: Mapping[str, Any]) -> dict[str, str]:
    """Select bounded audit summary fields for human-readable reports."""

    audit = metadata.get("repair_audit")
    if not isinstance(audit, Mapping):
        return {}
    safe = _safe_metadata(audit)
    fields: dict[str, str] = {}
    for key in (
        "state",
        "run_id",
        "audit_outcome",
        "finding_gate_state",
        "json_report_sha256",
    ):
        value = safe.get(key)
        if type(value) is str:
            fields[key] = value
    coverage_complete = safe.get("coverage_complete")
    if type(coverage_complete) is bool:
        fields["coverage_complete"] = str(coverage_complete).lower()
    return fields


def _md(value: str) -> str:
    return value.replace("\\", "\\\\").replace("`", "\\`").replace("[", "\\[").replace("]", "\\]")


__all__ = [
    "RepairCli",
    "RepairFormat",
    "RepairOutcome",
    "RepairReceipt",
    "RepairWorker",
    "build_installed_repair_cli",
    "render_receipt",
]
