"""Bounded, source-free public receipt fields for persisted audit runs."""

from __future__ import annotations

from typing import Final


_RUN_STATE_RECEIPTS: Final = {
    "ADMISSION_PENDING": ("PENDING", "ADMITTED", None),
    "ADMISSION_BLOCKED": ("BLOCKED", "COMPLETED", None),
    "ADMISSION_FAILED": ("FAILED", "COMPLETED", None),
    "REQUESTED": ("ADMITTED", "ADMITTED", None),
    "RUNNING": ("ADMITTED", "ADMITTED", None),
    "CANCEL_REQUESTED": ("ADMITTED", "ADMITTED", None),
    "SUPERSEDE_REQUESTED": ("ADMITTED", "ADMITTED", None),
    "SUCCEEDED": ("COMPLETED", "COMPLETED", "PASS"),
    "FAILED": ("COMPLETED", "COMPLETED", "FAIL"),
    "INDETERMINATE": ("COMPLETED", "COMPLETED", "INDETERMINATE"),
    "CANCELLED": ("COMPLETED", "COMPLETED", "CANCELLED"),
    "SUPERSEDED": ("SUPERSEDED", "SUPERSEDED", "SUPERSEDED"),
}


def run_receipt_fields(state: str, version: int) -> dict[str, object]:
    """Project persisted state into the CLI receipt contract without source data."""

    if type(state) is not str or type(version) is not int or version < 0:
        raise ValueError("run receipt state is invalid")
    try:
        disposition, lifecycle, outcome = _RUN_STATE_RECEIPTS[state]
    except KeyError:
        raise ValueError("run receipt state is invalid") from None
    return {
        "disposition": disposition,
        "lifecycle": lifecycle,
        "outcome": outcome,
        "state_version": version,
    }
