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
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from securecode_ai.contracts import CliCommand, CliExitCode


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
_UNSAFE_KEYS = frozenset({"source", "source_text", "diff", "patch", "content", "secret", "raw"})
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
    ) -> None:
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
                {"reason": "backend_unavailable"},
            )
        try:
            raw = worker(target)
            if not isinstance(raw, Mapping):
                raise ValueError
            safe = _safe_metadata(raw)
            code = CliExitCode(int(raw.get("exit_code", CliExitCode.COMPLETED)))
            outcome = _EXIT_TO_OUTCOME[code]
            # A successful CLI operation is not evidence of a product PASS.
            safe["product_pass"] = False
            return _receipt(command, outcome, code, safe)
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
    command: CliCommand, outcome: RepairOutcome, code: CliExitCode, metadata: Mapping[str, Any]
) -> RepairReceipt:
    document = {
        "command": command.value,
        "operation_outcome": outcome.value,
        "metadata": dict(metadata),
    }
    digest = hashlib.sha256(_canonical(document)).hexdigest()
    return RepairReceipt(command, outcome, code, "NOT_EVALUATED", dict(metadata), digest)


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
    if report_format is RepairFormat.JSON or report_format is RepairFormat.DIFF:
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
        return (
            "# SecureCode AI operation\n\n"
            + "- command: "
            + _md(receipt.command.value)
            + "\n"
            + "- outcome: "
            + _md(receipt.operation_outcome.value)
            + "\n"
            + "- product outcome: NOT_EVALUATED\n"
        ).encode()
    return (
        '<!doctype html><meta charset="utf-8"><title>SecureCode AI operation</title><h1>SecureCode AI operation</h1><dl><dt>command</dt><dd>'
        + html.escape(receipt.command.value)
        + "</dd><dt>outcome</dt><dd>"
        + html.escape(receipt.operation_outcome.value)
        + "</dd><dt>product outcome</dt><dd>NOT_EVALUATED</dd></dl>"
    ).encode()


def _md(value: str) -> str:
    return value.replace("\\", "\\\\").replace("`", "\\`").replace("[", "\\[").replace("]", "\\]")


__all__ = [
    "RepairCli",
    "RepairFormat",
    "RepairOutcome",
    "RepairReceipt",
    "RepairWorker",
    "render_receipt",
]
