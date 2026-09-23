"""Fail-closed identity verifier reloads for rotated local credentials."""

from __future__ import annotations

from collections.abc import Callable
from threading import Lock

from .ports import IdentityVerifier, VerifiedIdentity

IdentityVerifierLoader = Callable[[], IdentityVerifier | None]


class ReloadingIdentityVerifier:
    """Rebuild a verifier for every admission so file rotation is immediate."""

    __slots__ = ("_loader", "_lock")

    def __init__(self, loader: IdentityVerifierLoader) -> None:
        if not callable(loader):
            raise ValueError("identity verifier loader is invalid")
        initial = loader()
        if initial is None or not callable(getattr(initial, "verify_bearer", None)):
            raise ValueError("identity verifier is not configured")
        self._loader = loader
        self._lock = Lock()

    def verify_bearer(self, token: str) -> VerifiedIdentity | None:
        try:
            with self._lock:
                verifier = self._load()
                if verifier is None:
                    return None
                return verifier.verify_bearer(token)
        except Exception:
            return None

    def ready(self) -> bool:
        """Report whether the configured identity source reloads successfully now."""

        return self._reload() is not None

    def _reload(self) -> IdentityVerifier | None:
        try:
            with self._lock:
                return self._load()
        except Exception:
            return None

    def _load(self) -> IdentityVerifier | None:
        verifier = self._loader()
        if verifier is None or not callable(getattr(verifier, "verify_bearer", None)):
            return None
        return verifier


__all__ = ["IdentityVerifierLoader", "ReloadingIdentityVerifier"]
