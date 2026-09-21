"""Cooperative cancellation guard for installed product execution."""

from __future__ import annotations

from collections.abc import Callable

from .local_product_runner_config import LocalProductCancelledError


class LocalProductCancellationGuard:
    __slots__ = ("_probe",)

    def __init__(self, probe: Callable[[], bool] | None) -> None:
        self._probe = probe

    def __call__(self) -> bool:
        if self._probe is None:
            return False
        try:
            return self._probe() is True
        except Exception:
            return True

    def checkpoint(self) -> None:
        if self():
            raise LocalProductCancelledError()


__all__ = ["LocalProductCancellationGuard"]
