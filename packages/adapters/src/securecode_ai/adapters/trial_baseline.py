"""Known findings of a repository: a file of accepted weaknesses that no longer fail a run.

A team adopting the tool has findings it cannot fix at once. A baseline lists the weakness
groups (``trial_groups``) that are accepted or known false positives; a later run reports
them as known and fails only on a confirmed weakness that is not in the file. The audit
core is untouched: its ``outcome`` stays what the models and detectors decided, and the
baseline is applied afterwards (D-125) as ``effective_outcome``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Final

from .trial_groups import finding_groups

SCHEMA: Final = "securecode-baseline/v1"
REASONS: Final = frozenset({"accepted", "false_positive"})
_MAX_BYTES: Final = 1_048_576
_GROUP: Final = re.compile(r"weakness-[0-9a-f]{32}\Z")


class BaselineError(ValueError):
    """The baseline file cannot be read, is not the documented format, or cannot be written."""


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    weakness_group: str
    cwe_id: str
    path: str
    reason: str
    expires: datetime | None


@dataclass(frozen=True, slots=True)
class Baseline:
    created: str
    head_sha: str
    entries: tuple[BaselineEntry, ...]


@dataclass(frozen=True, slots=True)
class BaselineApplication:
    """What a baseline did to one report."""

    # weakness group -> (reason, since) of every known finding group present in the run.
    suppressed: Mapping[str, tuple[str, str]]
    # Entries ignored because they expired.
    expired: tuple[BaselineEntry, ...]
    # Confirmed finding groups that the baseline does not know.
    new_groups: frozenset[str]

    @property
    def active(self) -> bool:
        return bool(self.suppressed)


def load_baseline(path: Path) -> Baseline:
    """Read and validate a baseline file; any deviation is a ``BaselineError``."""

    try:
        raw = path.read_bytes()
    except OSError as error:
        raise BaselineError(f"baseline cannot be read: {type(error).__name__}") from None
    if len(raw) > _MAX_BYTES:
        raise BaselineError("baseline is larger than 1 MiB")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise BaselineError("baseline is not valid JSON") from None
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise BaselineError(f"baseline schema must be {SCHEMA}")
    created, head_sha, items = (
        document.get("created"),
        document.get("head_sha", ""),
        document.get("weaknesses"),
    )
    if (
        not isinstance(created, str)
        or not isinstance(head_sha, str)
        or not isinstance(items, list)
        or len(items) > 10_000
    ):
        raise BaselineError("baseline needs created, head_sha and a weaknesses list")
    entries = tuple(_entry(item) for item in items)
    if len({entry.weakness_group for entry in entries}) != len(entries):
        raise BaselineError("baseline lists a weakness group twice")
    return Baseline(created, head_sha, entries)


def _entry(item: object) -> BaselineEntry:
    if not isinstance(item, dict):
        raise BaselineError("a baseline entry is not an object")
    group, cwe_id, path, reason, expires = (
        item.get("weakness_group"),
        item.get("cwe_id"),
        item.get("path"),
        item.get("reason"),
        item.get("expires"),
    )
    if (
        not isinstance(group, str)
        or _GROUP.fullmatch(group) is None
        or not isinstance(cwe_id, str)
        or not cwe_id
        or not isinstance(path, str)
        or not path
        or reason not in REASONS
    ):
        raise BaselineError(
            "a baseline entry needs weakness_group, cwe_id, path and a valid reason"
        )
    return BaselineEntry(group, cwe_id, path, str(reason), _expiry(expires))


def _expiry(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise BaselineError("expires must be an ISO date or null")
    try:
        moment = (
            datetime.fromisoformat(value)
            if "T" in value
            else datetime.combine(date.fromisoformat(value), datetime.max.time())
        )
    except ValueError:
        raise BaselineError("expires must be an ISO date or null") from None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def apply_baseline(
    findings: Sequence[object], baseline: Baseline, *, now: datetime
) -> BaselineApplication:
    """Match the confirmed findings of a JSON report to the unexpired baseline entries."""

    groups = finding_groups(findings)
    live = {
        entry.weakness_group: entry
        for entry in baseline.entries
        if entry.expires is None or entry.expires > now
    }
    expired = tuple(
        entry for entry in baseline.entries if entry.expires is not None and entry.expires <= now
    )
    suppressed: dict[str, tuple[str, str]] = {}
    new: set[str] = set()
    for item, group in zip(findings, groups, strict=True):
        if not isinstance(item, Mapping) or item.get("verdict") != "CONFIRMED" or group is None:
            continue
        entry = live.get(group)
        if entry is None:
            new.add(group)
        else:
            suppressed[group] = (entry.reason, baseline.created)
    return BaselineApplication(suppressed, expired, frozenset(new - suppressed.keys()))


def baseline_document(findings: Sequence[object], head_sha: str, *, now: datetime) -> bytes:
    """A baseline of every confirmed weakness group of a JSON report."""

    seen: dict[str, BaselineEntry] = {}
    for item, group in zip(findings, finding_groups(findings), strict=True):
        if not isinstance(item, Mapping) or item.get("verdict") != "CONFIRMED" or group is None:
            continue
        locations = [value for value in item.get("locations", []) if isinstance(value, Mapping)]
        path = str(locations[0].get("path")) if locations else ""
        seen.setdefault(
            group, BaselineEntry(group, str(item.get("cwe_id")), path, "accepted", None)
        )
    document = {
        "schema": SCHEMA,
        "created": now.astimezone(UTC).isoformat(timespec="seconds"),
        "head_sha": head_sha,
        "weaknesses": [
            {
                "weakness_group": entry.weakness_group,
                "cwe_id": entry.cwe_id,
                "path": entry.path,
                "reason": entry.reason,
                "expires": None,
            }
            for entry in sorted(seen.values(), key=lambda value: (value.path, value.weakness_group))
        ],
    }
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def effective_exit(
    core_exit: int, application: BaselineApplication, *, complete: bool, undecided: int
) -> int:
    """The exit code after the baseline: FAIL only for a confirmed weakness it does not know.

    When a core FAIL is fully explained by known findings, the run is a PASS if every stage
    completed and no candidate is undecided, otherwise INDETERMINATE (exit code 3).
    """

    if core_exit != 2 or not application.active or application.new_groups:
        return core_exit
    return 0 if complete and undecided == 0 else 3


__all__ = [
    "Baseline",
    "BaselineApplication",
    "BaselineEntry",
    "BaselineError",
    "apply_baseline",
    "baseline_document",
    "effective_exit",
    "load_baseline",
]
