"""Lexical path normalization that does not hide symbolic-link components."""

from __future__ import annotations

from pathlib import Path


def lexical_absolute_path(path: Path) -> Path:
    """Return an absolute normalized path without resolving filesystem links."""

    if not isinstance(path, Path):
        raise TypeError("path must be a pathlib path")
    candidate = path if path.is_absolute() else Path.cwd() / path
    if not candidate.is_absolute() or not candidate.anchor:
        raise ValueError("path cannot be made absolute")

    components: list[str] = []
    for part in candidate.parts[1:]:
        if part in {"", "."}:
            continue
        if part == "..":
            if components:
                components.pop()
            continue
        components.append(part)
    return Path(candidate.anchor).joinpath(*components)
