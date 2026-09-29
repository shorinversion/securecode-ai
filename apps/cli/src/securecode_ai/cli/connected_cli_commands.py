"""Compatibility facade for connected operator command handlers."""

from __future__ import annotations

from .connected_cli_lifecycle import (
    run_connected_assurance,
    run_connected_backups,
    run_connected_decision,
    run_connected_deletions,
    run_connected_feedback,
    run_connected_secrets,
    run_connected_waivers,
)
from .connected_cli_readouts import (
    run_connected_approval,
    run_connected_audit,
    run_connected_download,
    run_connected_events,
    run_connected_inspection,
    run_connected_readout,
    run_connected_repair_download,
    run_connected_results,
)
from .connected_policy_admin import run_connected_policy_admin

__all__ = [
    "run_connected_approval",
    "run_connected_assurance",
    "run_connected_audit",
    "run_connected_backups",
    "run_connected_decision",
    "run_connected_deletions",
    "run_connected_download",
    "run_connected_events",
    "run_connected_feedback",
    "run_connected_inspection",
    "run_connected_policy_admin",
    "run_connected_readout",
    "run_connected_repair_download",
    "run_connected_results",
    "run_connected_secrets",
    "run_connected_waivers",
]
