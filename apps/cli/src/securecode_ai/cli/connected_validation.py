"""Shared bounded value validators for connected operator inputs."""

from __future__ import annotations


def _sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _text(value: object, *, maximum: int) -> bool:
    """Free text: printable characters and spaces, bounded and control-free."""

    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        return False
    return all(32 <= ord(character) <= 126 for character in value)


def _printable(value: object, *, maximum: int) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        return False
    return all(33 <= ord(character) <= 126 for character in value)
