"""Compatibility facade for connected operator command handlers."""

from __future__ import annotations

from .connected_cli_lifecycle import (
    run_connected_assurance,
    run_connected_backups,
    run_connected_decision,
    run_connected_deletions,
    run_connected_feedback,
    run_connected_secrets,
)
from .connected_cli_readouts import (
    run_connected_approval,
    run_connected_events,
    run_connected_inspection,
    run_connected_readout,
    run_connected_results,
)

__all__ = [
    "run_connected_approval",
    "run_connected_assurance",
    "run_connected_backups",
    "run_connected_decision",
    "run_connected_deletions",
    "run_connected_events",
    "run_connected_feedback",
    "run_connected_inspection",
    "run_connected_readout",
    "run_connected_results",
    "run_connected_secrets",
]
