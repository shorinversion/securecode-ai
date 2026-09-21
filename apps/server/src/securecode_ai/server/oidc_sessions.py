"""OIDC replay nonce ledger and injected safe session issuer."""

from __future__ import annotations

import heapq
from collections.abc import Callable
from datetime import UTC, datetime
from threading import Lock
from typing import Protocol

from .identity import Principal
from .oidc import OidcDenied, OidcReceipt

_DEFAULT_MAX_ENTRIES = 100_000
_MAX_NONCE_LENGTH = 1_024
_MAX_SUBJECT_LENGTH = 2_048


class SessionIssuer(Protocol):
    def issue(self, principal: Principal) -> OidcReceipt: ...


class NonceReplayLedger:
    def __init__(
        self,
        *,
        now: Callable[[], int] = lambda: int(datetime.now(UTC).timestamp()),
        max_entries: int = _DEFAULT_MAX_ENTRIES,
    ) -> None:
        if (
            not callable(now)
            or type(max_entries) is not int
            or not 1 <= max_entries <= _DEFAULT_MAX_ENTRIES
        ):
            raise OidcDenied()

        self._now = now
        self._max_entries = max_entries
        self._values: dict[tuple[str, str], int] = {}
        self._expiry_heap: list[tuple[int, str, str]] = []
        self._lock = Lock()

    def consume(self, receipt: OidcReceipt, nonce: str) -> None:
        if (
            type(receipt) is not OidcReceipt
            or type(receipt.subject_id) is not str
            or not 0 < len(receipt.subject_id) <= _MAX_SUBJECT_LENGTH
            or type(receipt.expires_at) is not int
            or type(nonce) is not str
            or not 0 < len(nonce) <= _MAX_NONCE_LENGTH
        ):
            raise OidcDenied()

        key = (receipt.subject_id, nonce)
        with self._lock:
            try:
                current_time = self._now()
            except Exception:
                raise OidcDenied() from None
            if type(current_time) is not int or current_time < 0:
                raise OidcDenied()

            self._discard_expired(current_time)
            if receipt.expires_at <= current_time or key in self._values:
                raise OidcDenied()
            if len(self._values) >= self._max_entries:
                raise OidcDenied()

            self._values[key] = receipt.expires_at
            heapq.heappush(
                self._expiry_heap,
                (receipt.expires_at, receipt.subject_id, nonce),
            )

    def _discard_expired(self, current_time: int) -> None:
        while self._expiry_heap and self._expiry_heap[0][0] <= current_time:
            expires_at, subject_id, nonce = heapq.heappop(self._expiry_heap)
            key = (subject_id, nonce)
            if self._values.get(key) == expires_at:
                del self._values[key]
