"""Explicit installed CLI flow for durable local patch approval."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import TextIO

from .atomic_output import write_new_output

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def run_patch_approval_command(
    tokens: tuple[str, ...],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    """Approve an exact validated artifact, without apply or SCM authority."""

    try:
        values, output = _parse(tokens)
    except ValueError:
        stderr.write("invalid approve command usage\n")
        return 5
    try:
        from securecode_ai.adapters.local_repair import (
            approve_local_repair_artifact,
            repair_failure_receipt,
        )

        from .scan import load_installed_product_host

        try:
            result = approve_local_repair_artifact(
                target=values["target"],
                selector=values["patch"],
                artifact_sha256=values["artifact_sha256"],
                capability=values["capability"],
                approval_id=values["approval_id"],
                approver_id=values["approver_id"],
                host=load_installed_product_host(),
                environment=environment,
            )
        except Exception as error:
            result = repair_failure_receipt(error)
        rendered = _canonical(result) + b"\n"
        if output is not None:
            write_new_output(output, rendered)
        else:
            stdout.write(rendered.decode("ascii"))
        exit_code = result.get("exit_code")
        if type(exit_code) is not int:
            raise ValueError
        return exit_code
    except KeyboardInterrupt:
        stderr.write("approve operation cancelled\n")
        return 6
    except Exception:
        stderr.write("approve operation failed\n")
        return 4


def _parse(tokens: tuple[str, ...]) -> tuple[dict[str, str], Path | None]:
    if len(tokens) < 2 or tokens[0] != "approve" or not tokens[1] or tokens[1].startswith("-"):
        raise ValueError
    values = {"target": tokens[1]}
    output: Path | None = None
    flags = {
        "--patch": "patch",
        "--artifact-sha256": "artifact_sha256",
        "--capability": "capability",
        "--approval-id": "approval_id",
        "--approver-id": "approver_id",
    }
    index = 2
    while index < len(tokens):
        flag = tokens[index]
        index += 1
        if index >= len(tokens) or not tokens[index] or tokens[index].startswith("-"):
            raise ValueError
        value = tokens[index]
        if flag == "--output":
            if output is not None:
                raise ValueError
            output = Path(value)
        elif flag in flags:
            key = flags[flag]
            if key in values:
                raise ValueError
            values[key] = value
        else:
            raise ValueError
        index += 1
    if set(values) != {
        "target",
        "patch",
        "artifact_sha256",
        "capability",
        "approval_id",
        "approver_id",
    }:
        raise ValueError
    if (
        _SHA256.fullmatch(values["artifact_sha256"]) is None
        or _SHA256.fullmatch(values["capability"]) is None
        or not values["patch"].endswith(values["artifact_sha256"])
        or _ID.fullmatch(values["approval_id"]) is None
        or _ID.fullmatch(values["approver_id"]) is None
    ):
        raise ValueError
    return values, output


def _canonical(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        dict(value), ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


__all__ = ["run_patch_approval_command"]
