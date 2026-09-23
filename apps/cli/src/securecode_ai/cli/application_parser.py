"""CLI grammar and per-command help construction."""

from __future__ import annotations

import argparse
from types import MappingProxyType
from typing import Final

from securecode_ai.core.classification import FindingSeverity

from .repair import RepairFormat

_GRANT_HELP = "grant or read a bounded credential reference through the control plane"


COMMAND_DESCRIPTIONS: Final = MappingProxyType(
    {
        "doctor": "validate foundation configuration without source or network access",
        "scan": "audit one local checkout",
        "fix": "propose a bounded repair for one local checkout",
        "validate": "validate one retained repair artifact in isolation",
        "approve": "record explicit approval for one exact validated repair artifact",
        "release": "dry-run or explicitly authorize immutable local release publication",
        "connect": "submit one checkout to a control plane and follow the run",
        "ci": "submit one revision, wait for the terminal outcome, and return its CI exit code",
        "status": "read one run's current durable state from the control plane",
        "cancel": "request cancellation of one run with an exact state precondition",
        "results": "read one run's findings, artifacts or events from the control plane",
        "approvals": "open, read or decide a control-plane approval request",
        "finding": "read one finding from the control plane",
        "policies": "read the control plane's effective policy documents",
        "health": "check readiness or liveness of the configured control plane",
        "decisions": "record an operator decision on one finding",
        "secrets": _GRANT_HELP,
        "events": "read one page of a run's event feed from the control plane",
        "backups": "create, read, execute or restore a backup through the control plane",
        "deletions": "open, approve, hold, execute or read an erasure request",
        "feedback": "submit a pilot review or read aggregated feedback metrics",
        "assurance": "append or read assurance records for one repository",
    }
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securecode",
        add_help=False,
        description="SecureCode AI local audit and safe repair CLI.",
    )
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--version", action="store_true")
    subparsers = parser.add_subparsers(dest="command")
    for command, description in COMMAND_DESCRIPTIONS.items():
        subparsers.add_parser(command, add_help=False, help=description)
    return parser


def _command_help(command: str) -> str:
    description = COMMAND_DESCRIPTIONS.get(command)
    if description is None:
        raise ValueError("command is invalid")
    parser = argparse.ArgumentParser(prog=f"securecode {command}", description=description)
    if command in {"scan", "fix", "validate", "approve"}:
        parser.add_argument("target", help="absolute or relative checkout path")
        parser.add_argument("--output", help="create a new output file")
        if command != "approve":
            formats = (
                tuple(item.value for item in RepairFormat if item is not RepairFormat.DIFF)
                if command == "scan"
                else tuple(item.value for item in RepairFormat)
            )
            parser.add_argument(
                "--format",
                choices=formats,
                default=RepairFormat.JSON.value,
            )
        if command == "scan":
            parser.add_argument("--config", help="host approval configuration for product scan")
            parser.add_argument("--diagnostic", action="store_true")
            parser.add_argument(
                "--fail-on",
                choices=tuple(item.value.lower() for item in FindingSeverity),
                help="return a failing exit code when a finding meets this severity",
            )
        if command == "validate":
            parser.add_argument("--patch", help="retained patch selector")
        elif command == "approve":
            parser.add_argument("--patch", required=True)
            parser.add_argument("--artifact-sha256", required=True)
            parser.add_argument("--capability", required=True)
            parser.add_argument("--approval-id", required=True)
            parser.add_argument("--approver-id", required=True)
    elif command == "release":
        parser.add_argument("--config", required=True)
        parser.add_argument("--publish", action="store_true")
        parser.add_argument("--authorization")
    elif command == "connect":
        parser.add_argument("target", nargs="?", help="optional local checkout path")
        parser.add_argument(
            "--wait",
            action="store_true",
            help="poll until the control plane reports a terminal outcome",
        )
        parser.add_argument(
            "--new-run",
            action="store_true",
            help="open a new run instead of resuming the recorded one for this revision",
        )
    elif command == "ci":
        parser.add_argument(
            "--new-run",
            action="store_true",
            help="open a new run instead of resuming the recorded one for this revision",
        )
    elif command == "finding":
        parser.add_argument("finding_id", help="control plane finding identifier")
    elif command == "policies":
        pass
    elif command == "assurance":
        parser.add_argument(
            "action",
            choices=("append", "show"),
            help="assurance operation to perform",
        )
        parser.add_argument("args", nargs=argparse.REMAINDER, help="operation arguments")
    elif command == "feedback":
        parser.add_argument(
            "action",
            choices=("submit", "metrics"),
            help="feedback operation to perform",
        )
        parser.add_argument("args", nargs=argparse.REMAINDER, help="operation arguments")
    elif command == "deletions":
        parser.add_argument(
            "action",
            choices=("create", "show", "approve", "hold", "execute"),
            help="erasure operation to perform",
        )
        parser.add_argument("args", nargs=argparse.REMAINDER, help="operation arguments")
    elif command == "backups":
        parser.add_argument(
            "action",
            choices=("create", "show", "execute", "restore"),
            help="backup operation to perform",
        )
        parser.add_argument("args", nargs=argparse.REMAINDER, help="operation arguments")
    elif command == "events":
        parser.add_argument("run_id", help="control plane run identifier")
        parser.add_argument("--cursor", help="server-issued page cursor")
        parser.add_argument("--limit", type=int, help="page size (1-500)")
    elif command == "secrets":
        parser.add_argument("action", choices=("grant", "show"), help="secret operation")
        parser.add_argument("args", nargs=argparse.REMAINDER, help="operation arguments")
    elif command == "decisions":
        parser.add_argument("finding_id", help="control plane finding identifier")
        parser.add_argument("--if-match", required=True, help="observed finding state")
        parser.add_argument("--run", required=True, help="owning run identifier")
        parser.add_argument(
            "--revision", required=True, help="exact revision the decision binds to"
        )
        parser.add_argument("--decision", required=True, help="decision type to record")
        parser.add_argument("--reason", required=True, help="short bounded reason")
    elif command == "health":
        parser.add_argument(
            "--live",
            action="store_true",
            help="check liveness instead of readiness",
        )
    elif command == "approvals":
        parser.add_argument(
            "action",
            choices=("create", "show", "decide"),
            help="approval operation to perform",
        )
        parser.add_argument("args", nargs=argparse.REMAINDER, help="operation arguments")
    elif command == "results":
        parser.add_argument("run_id", help="control plane run identifier")
        parser.add_argument(
            "--kind",
            choices=("findings", "artifacts", "events"),
            default="findings",
            help="which run collection to read",
        )
    elif command in {"status", "cancel"}:
        parser.add_argument("run_id", help="control plane run identifier")
        if command == "cancel":
            parser.add_argument(
                "--if-match",
                required=True,
                help="observed state version or etag the cancellation must match",
            )
    return parser.format_help()
