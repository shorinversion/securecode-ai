"""Source-free operational observations shared by server and exporters."""

from __future__ import annotations

import re
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
_ALLOWED_OUTCOMES = frozenset(
    {
        "1xx",
        "2xx",
        "3xx",
        "4xx",
        "5xx",
        "success",
        "error",
        "cancelled",
        "superseded",
        "pass",
        "fail",
        "indeterminate",
    }
)
_RESOURCE_FIELDS = frozenset(
    {"tokens", "cost_microunits", "cpu_ms", "peak_memory_bytes", "wall_ms"}
)
_MAX_RESOURCE_VALUE = 9_223_372_036_854_775_807
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


@dataclass(frozen=True, slots=True)
class OperationalObservation:
    """Bounded low-cardinality event metadata; source and secret fields are rejected."""

    name: str
    attributes: Mapping[str, str]
    duration_ms: int | None = None
    resource_usage: Mapping[str, int] | None = None

    def __post_init__(self) -> None:
        try:
            attributes = dict(self.attributes)
        except Exception:
            raise ValueError("observation is unsafe") from None
        resource_usage: dict[str, int] | None = None
        if self.resource_usage is not None:
            try:
                resource_usage = dict(self.resource_usage)
            except Exception:
                raise ValueError("observation is unsafe") from None
        if (
            type(self.name) is not str
            or _SAFE_NAME.fullmatch(self.name) is None
            or set(attributes) - _ALLOWED_ATTRIBUTES
            or len(attributes) > 8
            or any(
                type(key) is not str
                or type(value) is not str
                or len(key) > 64
                or len(value) > 128
                or "\n" in value
                or "\r" in value
                or (key == "outcome" and value not in _ALLOWED_OUTCOMES)
                for key, value in attributes.items()
            )
            or (
                self.duration_ms is not None
                and (type(self.duration_ms) is not int or self.duration_ms < 0)
            )
            or (
                resource_usage is not None
                and (
                    set(resource_usage) != _RESOURCE_FIELDS
                    or any(
                        type(key) is not str
                        or type(value) is not int
                        or not 0 <= value <= _MAX_RESOURCE_VALUE
                        for key, value in resource_usage.items()
                    )
                )
            )
        ):
            raise ValueError("observation is unsafe")
        object.__setattr__(self, "attributes", MappingProxyType(attributes))
        if resource_usage is not None:
            object.__setattr__(self, "resource_usage", MappingProxyType(resource_usage))


__all__ = ["OperationalObservation"]
