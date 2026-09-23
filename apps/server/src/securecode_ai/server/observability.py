"""OpenTelemetry-compatible source-free projection ports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from securecode_ai.core.operational_telemetry import OperationalObservation as Observation


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
