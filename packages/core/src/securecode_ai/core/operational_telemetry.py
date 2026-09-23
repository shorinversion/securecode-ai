"""Source-free operational observations shared by server and exporters."""

from __future__ import annotations

from dataclasses import dataclass

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
    attributes: dict[str, str]
    duration_ms: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or not self.name
            or len(self.name) > 128
            or type(self.attributes) is not dict
            or set(self.attributes) - _ALLOWED_ATTRIBUTES
            or len(self.attributes) > 8
            or any(
                type(key) is not str
                or type(value) is not str
                or len(key) > 64
                or len(value) > 128
                or "\n" in value
                or "\r" in value
                for key, value in self.attributes.items()
            )
            or (
                self.duration_ms is not None
                and (type(self.duration_ms) is not int or self.duration_ms < 0)
            )
        ):
            raise ValueError("observation is unsafe")


__all__ = ["OperationalObservation"]
