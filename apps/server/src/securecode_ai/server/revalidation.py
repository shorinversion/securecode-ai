from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CurrentPins:
    source: str
    policy: str
    dependency: str
    environment: str
    operational: str


def stale_reasons(
    recorded: CurrentPins,
    current: CurrentPins,
) -> tuple[str, ...]:
    pin_names = (
        "source",
        "policy",
        "dependency",
        "environment",
        "operational",
    )
    return tuple(name for name in pin_names if getattr(recorded, name) != getattr(current, name))
