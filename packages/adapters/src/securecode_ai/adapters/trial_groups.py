"""Which confirmed findings describe one weakness.

The scanner lane and model Discovery may both confirm one weakness; they share a group so
a consumer counts and alerts once. For code weaknesses (injection, path traversal) the
group is the CWE in one file: the model may cite another line of the same flow, and the
Architect proposes one fix per file. A hard-coded credential is different: each value is
rotated on its own, so two keys of one file are two weaknesses and the group is the CWE
at overlapping lines. Narrow locations seed those groups; a wide model location joins the
first group it overlaps and never merges two of them.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence

WEAKNESS_FINGERPRINT: str = "securecodeWeakness/v2"
# Weaknesses where every place is its own instance: each credential is rotated alone.
PER_PLACE_CWES: frozenset[str] = frozenset({"CWE-259", "CWE-321", "CWE-798"})


def weakness_group(cwe_id: str, path: str, line: int) -> str:
    """The group id of a weakness: CWE, file and the first line of the place seeding it."""

    digest = hashlib.sha256(f"{cwe_id}\x00{path}\x00{line}".encode()).hexdigest()
    return "weakness-" + digest[:32]


def finding_groups(findings: Sequence[object]) -> list[str | None]:
    """The group id of every finding of a JSON report, in order; None without a place."""

    places: list[tuple[str, str, int, int] | None] = [_place(item) for item in findings]
    groups: list[str | None] = [None] * len(places)
    seeds: dict[tuple[str, str], list[tuple[int, int]]] = {}
    order = sorted(
        (index for index, place in enumerate(places) if place is not None),
        key=lambda index: (places[index][3] - places[index][2], places[index][2]),  # type: ignore[index]
    )
    for index in order:
        cwe_id, path, start, end = places[index]  # type: ignore[misc]
        clusters = seeds.setdefault((cwe_id, path), [])
        seed = next((s for s, e in clusters if start <= e and s <= end), None)
        if seed is None:
            clusters.append((start, end))
            seed = start
        groups[index] = weakness_group(cwe_id, path, seed)
    return groups


def _place(item: object) -> tuple[str, str, int, int] | None:
    if not isinstance(item, Mapping) or not isinstance(item.get("cwe_id"), str):
        return None
    locations = [
        location
        for location in item.get("locations", [])
        if isinstance(location, Mapping) and isinstance(location.get("path"), str)
    ]
    if not locations:
        return None
    path = locations[0]["path"]
    spans = [
        (_line(location, "start"), max(_line(location, "start"), _line(location, "end")))
        for location in locations
        if location["path"] == path
    ]
    if item["cwe_id"] not in PER_PLACE_CWES:
        return item["cwe_id"], path, 0, 0
    # The whole cited range: a model finding citing the file and the line is one place,
    # wider than the scanner's line, and joins the scanner's group.
    return item["cwe_id"], path, min(s for s, _ in spans), max(e for _, e in spans)


def _line(location: Mapping[str, object], key: str) -> int:
    point = location.get(key)
    line = point.get("line") if isinstance(point, Mapping) else None
    return line if isinstance(line, int) else 1


__all__ = ["WEAKNESS_FINGERPRINT", "finding_groups", "weakness_group"]
