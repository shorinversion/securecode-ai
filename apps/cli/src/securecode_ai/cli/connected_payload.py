"""Bounded JSON payload parsing for connected CLI commands."""

from __future__ import annotations

import json

from .connected_transport import ConnectedCliError, ConnectedCliErrorCode


def parse_payload(value: str) -> dict[str, object]:
    """Parse one bounded JSON object supplied on the command line."""

    if not isinstance(value, str) or not 2 <= len(value) <= 16_384:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    try:
        parsed = json.loads(
            value,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION) from None
    if not isinstance(parsed, dict) or not parsed:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return parsed


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    parsed: dict[str, object] = {}
    for key, item in pairs:
        if key in parsed:
            raise ValueError
        parsed[key] = item
    return parsed


def _reject_json_constant(_value: str) -> object:
    raise ValueError
