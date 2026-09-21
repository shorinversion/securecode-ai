"""OpenTelemetry-compatible source-free projection ports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

_ALLOWED = frozenset(
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
class Observation:
    name: str
    attributes: dict[str, str]
    duration_ms: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or not self.name
            or len(self.name) > 128
            or type(self.attributes) is not dict
            or set(self.attributes) - _ALLOWED
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


class Exporter(Protocol):
    def export(self, observations: tuple[Observation, ...]) -> bool: ...


@dataclass(frozen=True, slots=True)
class ExportResult:
    accepted: bool
    count: int


class RedactedExporter:
    """Reject malformed telemetry and collapse exporter failures to metadata."""

    def __init__(self, exporter: Exporter) -> None:
        if not callable(getattr(exporter, "export", None)):
            raise TypeError("telemetry exporter is invalid")
        self._exporter = exporter

    def export(self, observations: tuple[Observation, ...]) -> ExportResult:
        if type(observations) is not tuple or any(
            type(item) is not Observation for item in observations
        ):
            raise ValueError("observations are invalid")
        try:
            accepted = self._exporter.export(observations)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            return ExportResult(False, 0)
        return ExportResult(accepted is True, len(observations) if accepted is True else 0)


__all__ = ["ExportResult", "Exporter", "Observation", "RedactedExporter"]
