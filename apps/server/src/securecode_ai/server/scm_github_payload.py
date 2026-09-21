"""GitHub JSON decoding without bounds on unrelated provider fields."""

from __future__ import annotations

import json


class GithubPayloadError(ValueError):
    """Malformed UTF-8, JSON, constants, roots, or duplicate object keys."""


def parse_github_payload(raw_body: bytes) -> dict[str, object]:
    try:
        parsed = json.loads(
            raw_body.decode("utf-8", "strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, GithubPayloadError):
        raise GithubPayloadError() from None
    if type(parsed) is not dict:
        raise GithubPayloadError()
    return parsed


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GithubPayloadError()
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise GithubPayloadError()


__all__ = ["GithubPayloadError", "parse_github_payload"]
