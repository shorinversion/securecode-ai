"""Bounded JSON payload parsing for connected CLI commands."""

from __future__ import annotations

import json

from .connected_transport import ConnectedCliError, ConnectedCliErrorCode


def parse_payload(value: str) -> dict[str, object]:
    """Parse one bounded JSON object supplied on the command line."""

    if not isinstance(value, str) or not 2 <= len(value) <= 16_384:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION) from None
    if not isinstance(parsed, dict) or not parsed:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return parsed
