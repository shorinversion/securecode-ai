"""Bind a trusted control-plane identity to a verified local checkout."""

from __future__ import annotations

import re

from securecode_ai.contracts import RunExecutionIdentity

_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def select_run_identity(
    derived: RunExecutionIdentity,
    supplied: RunExecutionIdentity | None,
) -> RunExecutionIdentity:
    """Use a trusted remote repository identity only when every pin matches."""

    if type(derived) is not RunExecutionIdentity:
        raise ValueError("derived execution identity is invalid")
    if supplied is None:
        return derived
    if type(supplied) is not RunExecutionIdentity:
        raise ValueError("supplied execution identity is invalid")
    derived_revision = derived.repository_revision
    supplied_revision = supplied.repository_revision
    if (
        supplied_revision != derived_revision
        or supplied.stage_catalogue != derived.stage_catalogue
        or supplied.workflow != derived.workflow
        or supplied.policy != derived.policy
        or supplied.configuration != derived.configuration
        or supplied.provider_profile != derived.provider_profile
        or supplied.capability_profile != derived.capability_profile
        or supplied.egress_profile != derived.egress_profile
    ):
        raise ValueError("supplied execution identity does not match local authority")
    return RunExecutionIdentity.model_validate_json(supplied.model_dump_json())


def select_run_id(supplied: str | None, fallback: str) -> str:
    value = fallback if supplied is None else supplied
    if type(value) is not str or _RUN_ID.fullmatch(value) is None:
        raise ValueError("run identifier is invalid")
    return value


__all__ = ["select_run_id", "select_run_identity"]
