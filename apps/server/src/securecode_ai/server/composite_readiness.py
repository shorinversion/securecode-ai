"""Fail-closed composition of independent server readiness sources."""

from __future__ import annotations

from .ports import ReadinessPort


class CompositeReadiness:
    """Require every configured dependency to report ready."""

    __slots__ = ("_sources",)

    def __init__(self, *sources: ReadinessPort) -> None:
        if not sources or not all(callable(getattr(source, "ready", None)) for source in sources):
            raise ValueError("readiness sources are invalid")
        self._sources = sources

    def ready(self) -> bool:
        for source in self._sources:
            try:
                if source.ready() is not True:
                    return False
            except Exception:
                return False
        return True


__all__ = ["CompositeReadiness"]
