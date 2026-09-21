"""Canonical execution-envelope evidence for offline optimization."""

from __future__ import annotations

import hashlib
import json
from typing import Protocol

_DOMAIN = b"securecode-ai/offline-optimization-envelope/v1\x00"


class _Envelope(Protocol):
    @property
    def network_disabled(self) -> bool: ...
    @property
    def credentials_disabled(self) -> bool: ...
    @property
    def production_alias_access(self) -> bool: ...
    @property
    def locked_expectations_access(self) -> bool: ...
    @property
    def max_cases(self) -> int: ...
    @property
    def max_cost_microunits(self) -> int: ...
    @property
    def max_tokens(self) -> int: ...
    @property
    def max_elapsed_ms(self) -> int: ...


def optimization_envelope_hash(envelope: _Envelope) -> str:
    material = {
        "credentials_disabled": envelope.credentials_disabled,
        "locked_expectations_access": envelope.locked_expectations_access,
        "max_cases": envelope.max_cases,
        "max_cost_microunits": envelope.max_cost_microunits,
        "max_elapsed_ms": envelope.max_elapsed_ms,
        "max_tokens": envelope.max_tokens,
        "network_disabled": envelope.network_disabled,
        "production_alias_access": envelope.production_alias_access,
    }
    encoded = json.dumps(
        material, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(_DOMAIN + encoded).hexdigest()


__all__ = ["optimization_envelope_hash"]
