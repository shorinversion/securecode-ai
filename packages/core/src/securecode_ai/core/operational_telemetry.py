"""Source-free operational observations shared by server and exporters."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

_ALLOWED_ATTRIBUTES = frozenset(
    {
        "tenant_id",
        "run_id",
        "execution_identity_hash",
        "operation",
        "outcome",
        "error_code",
    }
)


@dataclass(frozen=True, slots=True)
class OperationalObservation:
    """Bounded low-cardinality event metadata; source and secret fields are rejected."""

    name: str
    attributes: Mapping[str, str]
    duration_ms: int | None = None

    def __post_init__(self) -> None:
        try:
            attributes = dict(self.attributes)
        except Exception:
            raise ValueError("observation is unsafe") from None
        if (
            type(self.name) is not str
            or not self.name
            or len(self.name) > 128
            or set(attributes) - _ALLOWED_ATTRIBUTES
            or len(attributes) > 8
            or any(
                type(key) is not str
                or type(value) is not str
                or len(key) > 64
                or len(value) > 128
                or "\n" in value
                or "\r" in value
                for key, value in attributes.items()
            )
            or (
                self.duration_ms is not None
                and (type(self.duration_ms) is not int or self.duration_ms < 0)
            )
        ):
            raise ValueError("observation is unsafe")
        object.__setattr__(self, "attributes", MappingProxyType(attributes))


__all__ = ["OperationalObservation"]
