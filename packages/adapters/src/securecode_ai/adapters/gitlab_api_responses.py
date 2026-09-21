"""Strict response validation for GitLab publication reconciliation."""

from __future__ import annotations

import json
import re
from typing import cast

from .gitlab_ci import GitlabExternalStatusProjection
from .gitlab_discussions import GitlabDiscussionProjection

_INTEGER_ID = re.compile(r"[1-9][0-9]{0,18}\Z")
_DISCUSSION_ID = re.compile(r"[0-9a-f]{40}\Z")
_MAX_BYTES = 16_384
_MAX_DEPTH = 8
_MAX_ITEMS = 100


def integer_id(value: object) -> str | None:
    if type(value) is not dict:
        return None
    raw = value.get("id")
    if type(raw) is not int or raw < 1:
        return None
    identifier = str(raw)
    return identifier if _INTEGER_ID.fullmatch(identifier) is not None else None


def discussion_id(
    value: object,
    body: str,
    projection: GitlabDiscussionProjection,
    old_path: str,
) -> str | None:
    if type(value) is not dict or type(value.get("id")) is not str:
        return None
    identifier = cast(str, value["id"])
    notes = value.get("notes")
    if _DISCUSSION_ID.fullmatch(identifier) is None or type(notes) is not list:
        return None
    expected = {
        "base_sha": projection.base_sha,
        "head_sha": projection.head_sha,
        "new_line": projection.new_line,
        "new_path": projection.new_path,
        "old_path": old_path,
        "position_type": "text",
        "start_sha": projection.start_sha,
    }
    for note in notes:
        if (
            type(note) is dict
            and note.get("body") == body
            and type(note.get("position")) is dict
            and all(note["position"].get(key) == item for key, item in expected.items())
        ):
            return identifier
    return None


def status_matches(
    value: object,
    projection: GitlabExternalStatusProjection,
    state: str,
    name: str,
) -> bool:
    return (
        type(value) is dict
        and value.get("sha") == projection.head_sha
        and value.get("name") == name
        and value.get("status") == state
        and value.get("description") == projection.safe_summary
    )


def safe_path(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 1024
        and value.isascii()
        and not value.startswith("/")
        and "//" not in value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def bounded_json(body: bytes) -> object:
    if not body or len(body) > 65_536:
        raise ValueError
    try:
        value = json.loads(
            body.decode("utf-8", "strict"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=lambda _value: _reject(),
        )
        _validate_bounds(value, 0)
        return value
    except (UnicodeDecodeError, json.JSONDecodeError, _Rejected):
        raise ValueError from None


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    if len(pairs) > _MAX_ITEMS:
        raise _Rejected
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _Rejected
        result[key] = value
    return result


def _validate_bounds(value: object, depth: int) -> None:
    if depth > _MAX_DEPTH:
        raise _Rejected
    if type(value) is str:
        if len(value.encode("utf-8")) > _MAX_BYTES:
            raise _Rejected
    elif type(value) in {int, bool, type(None)}:
        return
    elif type(value) is list:
        sequence = cast(list[object], value)
        if len(sequence) > _MAX_ITEMS:
            raise _Rejected
        for item in sequence:
            _validate_bounds(item, depth + 1)
    elif type(value) is dict:
        mapping = cast(dict[str, object], value)
        if len(mapping) > _MAX_ITEMS:
            raise _Rejected
        for key, item in mapping.items():
            _validate_bounds(key, depth + 1)
            _validate_bounds(item, depth + 1)
    else:
        raise _Rejected


def _reject() -> None:
    raise _Rejected


class _Rejected(ValueError):
    pass


__all__ = ["bounded_json", "discussion_id", "integer_id", "safe_path", "status_matches"]
