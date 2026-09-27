"""Strict bounded JSON decoding for authenticated control-plane requests."""

from __future__ import annotations

import json
from typing import cast


class JsonBoundaryError(ValueError):
    """The document is malformed, ambiguous, or exceeds structural limits."""


def load_json_object(
    raw: bytes,
    *,
    max_depth: int = 32,
    max_items: int = 4096,
    max_scalar_bytes: int = 262_144,
) -> dict[str, object]:
    if type(raw) is not bytes or not raw:
        raise JsonBoundaryError

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        if len(pairs) > max_items:
            raise JsonBoundaryError
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise JsonBoundaryError
            result[key] = value
        return result

    try:
        value: object = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: _reject(),
        )
        _validate(
            value,
            depth=0,
            max_depth=max_depth,
            max_items=max_items,
            max_scalar_bytes=max_scalar_bytes,
        )
    except (ValueError, RecursionError):
        raise JsonBoundaryError from None
    if type(value) is not dict:
        raise JsonBoundaryError
    return cast(dict[str, object], value)


def _validate(
    value: object,
    *,
    depth: int,
    max_depth: int,
    max_items: int,
    max_scalar_bytes: int,
) -> None:
    if depth > max_depth:
        raise JsonBoundaryError
    if type(value) is str:
        if len(value.encode("utf-8")) > max_scalar_bytes:
            raise JsonBoundaryError
        return
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            raise JsonBoundaryError
        return
    if type(value) in {type(None), bool}:
        return
    if type(value) is list:
        if len(value) > max_items:
            raise JsonBoundaryError
        for item in value:
            _validate(
                item,
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
                max_scalar_bytes=max_scalar_bytes,
            )
        return
    if type(value) is dict:
        if len(value) > max_items:
            raise JsonBoundaryError
        for key, item in value.items():
            if len(key.encode("utf-8")) > max_scalar_bytes:
                raise JsonBoundaryError
            _validate(
                item,
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
                max_scalar_bytes=max_scalar_bytes,
            )
        return
    raise JsonBoundaryError


def _reject() -> object:
    raise JsonBoundaryError


__all__ = ["JsonBoundaryError", "load_json_object"]
