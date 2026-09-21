"""Bounded JSON decoding for untrusted SCM webhook payloads."""

from __future__ import annotations

import json
from typing import Final, cast

MAX_JSON_DEPTH: Final = 8
MAX_JSON_ITEMS: Final = 128
MAX_JSON_SCALAR_BYTES: Final = 2_048


class WebhookPayloadError(ValueError):
    """The payload is malformed or exceeds the webhook resource budget."""


def load_webhook_object(raw_body: bytes) -> dict[str, object]:
    try:
        parsed: object = json.loads(
            raw_body.decode("utf-8", "strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        _validate_bounds(parsed, depth=0)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        WebhookPayloadError,
    ):
        raise WebhookPayloadError from None
    if type(parsed) is not dict:
        raise WebhookPayloadError
    return cast(dict[str, object], parsed)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    if len(pairs) > MAX_JSON_ITEMS:
        raise WebhookPayloadError
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WebhookPayloadError
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise WebhookPayloadError


def _validate_bounds(value: object, *, depth: int) -> None:
    if depth > MAX_JSON_DEPTH:
        raise WebhookPayloadError
    if type(value) is str:
        if len(value.encode("utf-8")) > MAX_JSON_SCALAR_BYTES:
            raise WebhookPayloadError
        return
    if type(value) is int:
        if not -(2**53 - 1) <= value <= 2**53 - 1:
            raise WebhookPayloadError
        return
    if type(value) in {type(None), bool}:
        return
    if type(value) is list:
        if len(value) > MAX_JSON_ITEMS:
            raise WebhookPayloadError
        for item in value:
            _validate_bounds(item, depth=depth + 1)
        return
    if type(value) is dict:
        if len(value) > MAX_JSON_ITEMS:
            raise WebhookPayloadError
        for key, item in value.items():
            if type(key) is not str or len(key.encode("utf-8")) > MAX_JSON_SCALAR_BYTES:
                raise WebhookPayloadError
            _validate_bounds(item, depth=depth + 1)
        return
    raise WebhookPayloadError


__all__ = [
    "MAX_JSON_DEPTH",
    "MAX_JSON_ITEMS",
    "MAX_JSON_SCALAR_BYTES",
    "WebhookPayloadError",
    "load_webhook_object",
]
