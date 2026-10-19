"""Why a stage of a trial run did not complete, as fixed source-free codes.

The coverage manifest names the unit that did not complete (for example
``DETERMINISTIC_CHILD_EXECUTION_INCOMPLETE``) but not the cause. The causes are kept by the
deterministic execution of the run; this module reads them for the machine report
(``coverage_diagnostics``) and the readable report. It never exposes paths, source text or
exception messages: only fixed codes and exception type names.
"""

from __future__ import annotations

import json
from typing import Final

from .product_audit_types import ProductAuditComposition

_INCOMPLETE_UNIT: Final = "DETERMINISTIC_CHILD_EXECUTION_INCOMPLETE"


def deterministic_reasons(composition: ProductAuditComposition) -> tuple[str, ...]:
    """Reason codes of an incomplete deterministic execution; empty when it completed."""

    host = composition.host_inputs
    execution = None if host is None else host.deterministic_execution
    if execution is None:
        return ()
    return execution.incompleteness_reasons()


def coverage_diagnostics(composition: ProductAuditComposition) -> dict[str, object]:
    """Causes behind the unfinished units of the run, for the JSON report."""

    host = composition.host_inputs
    execution = None if host is None else host.deterministic_execution
    diagnostics: dict[str, object] = {}
    if execution is not None:
        diagnostics["deterministic"] = {
            "complete": execution.is_complete,
            "reasons": list(execution.incompleteness_reasons()),
            "obstacles": list(execution.obstacles),
            "obstacle_errors": [
                {"obstacle": obstacle, "error": error}
                for obstacle, error in execution.obstacle_errors
            ],
            "scanner_files": len(execution.scan.receipts),
            "scanner_files_expected": len(execution.catalogue.indexes),
        }
    return diagnostics


def discovery_mode(composition: ProductAuditComposition) -> dict[str, object]:
    """How much of the revision Discovery read: all windows, or the seed that fit the budget."""

    host = composition.host_inputs
    if host is None:
        return {"discovery_seed": "full", "seed_windows": 0, "total_windows": 0}
    total = len(host.source_catalogue.anchors)
    seed = host.discovery_seed
    return {
        "discovery_seed": seed,
        "seed_windows": len(host.discovery_seed_evidence_ids) if seed == "scanner" else total,
        "total_windows": total,
    }


def attach_diagnostics_to_json(rendered: bytes, composition: ProductAuditComposition) -> bytes:
    """Add ``coverage_diagnostics`` to a JSON report when something explains a gap."""

    diagnostics = coverage_diagnostics(composition)
    document = json.loads(rendered)
    manifest = document.get("coverage_manifest", {})
    unfinished = [
        {
            "stage_id": unit.get("stage_id"),
            "coverage_status": unit.get("coverage_status"),
            "reason_code": unit.get("reason_code"),
        }
        for unit in manifest.get("units", [])
        if isinstance(unit, dict)
        and unit.get("required")
        and unit.get("coverage_status") not in {"COMPLETED", "NOT_APPLICABLE"}
    ]
    if unfinished:
        diagnostics["unfinished_units"] = unfinished
    if not diagnostics:
        return rendered
    document["coverage_diagnostics"] = diagnostics
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def gap_detail(reason_code: object, reasons: tuple[str, ...]) -> str:
    """The cause of a skipped deterministic unit, for the readable report."""

    if reason_code == _INCOMPLETE_UNIT and reasons:
        return "; ".join(reasons)
    return str(reason_code)


__all__ = [
    "attach_diagnostics_to_json",
    "coverage_diagnostics",
    "deterministic_reasons",
    "discovery_mode",
    "gap_detail",
]
