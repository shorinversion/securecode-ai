"""Deduplicated alert state machine for validated SLI windows."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .sli import SliWindow


class AlertState(StrEnum):
    FIRING = "FIRING"
    RESOLVED = "RESOLVED"


@dataclass(frozen=True, slots=True)
class Alert:
    key: str
    state: AlertState
    value: float | None


class Alerts:
    """Emit only state transitions so polling cannot create alert floods."""

    def __init__(self) -> None:
        self._state: dict[str, AlertState] = {}

    def evaluate(
        self,
        *,
        key: str,
        sli: SliWindow,
        metric: str,
        threshold: float,
    ) -> Alert | None:
        if (
            type(key) is not str
            or not key
            or len(key) > 128
            or type(sli) is not SliWindow
            or type(metric) is not str
            or type(threshold) not in {int, float}
        ):
            raise ValueError("alert request is invalid")
        value = sli.value(metric)
        if value is None:
            return None
        state = AlertState.FIRING if value > float(threshold) else AlertState.RESOLVED
        if self._state.get(key) is state:
            return None
        self._state[key] = state
        return Alert(key, state, value)


__all__ = ["Alert", "AlertState", "Alerts"]
