"""Bounded OTLP/HTTP JSON export for source-free operational observations."""

from __future__ import annotations

import http.client
import json
import time
from collections.abc import Callable
from contextlib import suppress
from typing import Final, Protocol
from urllib.parse import urlsplit

from securecode_ai.core.operational_telemetry import OperationalObservation

_MAX_BATCH: Final = 256
_MAX_PAYLOAD_BYTES: Final = 65_536
_ALLOWED_PORTS: Final = frozenset({443, 4318})
_DEFAULT_MAX_ATTEMPTS: Final = 3
_MAX_ATTEMPTS: Final = 5


class OtlpTransport(Protocol):
    """Transport that owns any client credentials outside telemetry records."""

    def post_json(self, *, endpoint: str, payload: bytes, timeout_ms: int) -> int: ...


class StdlibOtlpTransport:
    """One HTTPS request with no redirect handling or response retention."""

    def post_json(self, *, endpoint: str, payload: bytes, timeout_ms: int) -> int:
        parsed = urlsplit(endpoint)
        host = parsed.hostname
        if host is None:
            raise ValueError("OTLP_ENDPOINT_REJECTED")
        connection = http.client.HTTPSConnection(
            host,
            parsed.port or 443,
            timeout=timeout_ms / 1_000,
        )
        try:
            connection.request(
                "POST",
                parsed.path,
                body=payload,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(payload)),
                },
            )
            response = connection.getresponse()
            response.read(1)
            return response.status
        finally:
            with suppress(Exception):
                connection.close()


class OtlpHttpExporter:
    """Export only bounded, source-free observations to a configured collector."""

    __slots__ = ("_clock_ns", "_endpoint", "_max_attempts", "_timeout_ms", "_transport")

    def __init__(
        self,
        *,
        endpoint: str,
        transport: OtlpTransport | None = None,
        timeout_ms: int = 5_000,
        max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
        clock_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        if not _valid_endpoint(endpoint):
            raise ValueError("OTLP_ENDPOINT_REJECTED")
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 60_000:
            raise ValueError("OTLP_TIMEOUT_REJECTED")
        if type(max_attempts) is not int or not 1 <= max_attempts <= _MAX_ATTEMPTS:
            raise ValueError("OTLP_MAX_ATTEMPTS_REJECTED")
        if not callable(clock_ns):
            raise TypeError("OTLP_CLOCK_REJECTED")
        resolved_transport = StdlibOtlpTransport() if transport is None else transport
        if not callable(getattr(resolved_transport, "post_json", None)):
            raise TypeError("OTLP_TRANSPORT_REJECTED")
        self._endpoint = endpoint
        self._transport = resolved_transport
        self._timeout_ms = timeout_ms
        self._max_attempts = max_attempts
        self._clock_ns = clock_ns

    def __repr__(self) -> str:
        return "OtlpHttpExporter(<configured>)"

    def export(self, observations: tuple[OperationalObservation, ...]) -> bool:
        if (
            type(observations) is not tuple
            or not observations
            or len(observations) > _MAX_BATCH
            or any(type(item) is not OperationalObservation for item in observations)
        ):
            return False
        try:
            now = self._clock_ns()
            if type(now) is not int or now < 0:
                return False
            payload = _payload(observations, observed_at_ns=now)
            if len(payload) > _MAX_PAYLOAD_BYTES:
                return False
            return self._post_with_retries(payload)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            return False

    def _post_with_retries(self, payload: bytes) -> bool:
        """Retry only bounded transient failures with an unchanged payload."""

        for attempt in range(self._max_attempts):
            try:
                status = self._transport.post_json(
                    endpoint=self._endpoint,
                    payload=payload,
                    timeout_ms=self._timeout_ms,
                )
            except (KeyboardInterrupt, SystemExit, GeneratorExit):
                raise
            except Exception:
                if attempt + 1 == self._max_attempts:
                    return False
                continue
            if type(status) is not int:
                return False
            if 200 <= status < 300:
                return True
            if not _retryable_status(status) or attempt + 1 == self._max_attempts:
                return False
        return False


def _valid_endpoint(value: object) -> bool:
    if type(value) is not str or not 1 <= len(value) <= 2_048:
        return False
    parsed = urlsplit(value)
    return (
        parsed.scheme == "https"
        and parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
        and parsed.path == "/v1/logs"
        and (parsed.port or 443) in _ALLOWED_PORTS
    )


def _retryable_status(status: int) -> bool:
    return status == 408 or status == 429 or 500 <= status <= 599


def _payload(observations: tuple[OperationalObservation, ...], *, observed_at_ns: int) -> bytes:
    records: list[dict[str, object]] = []
    for item in observations:
        attributes = [
            {"key": key, "value": {"stringValue": value}}
            for key, value in sorted(item.attributes.items())
        ]
        records.append(
            {
                "attributes": attributes,
                "body": {"stringValue": item.name},
                "observedTimeUnixNano": str(observed_at_ns),
                "timeUnixNano": str(observed_at_ns),
                **(
                    {}
                    if item.duration_ms is None
                    else {
                        "attributes": [
                            *attributes,
                            {"key": "duration_ms", "value": {"intValue": str(item.duration_ms)}},
                        ]
                    }
                ),
            }
        )
    document = {
        "resourceLogs": [
            {
                "scopeLogs": [
                    {
                        "logRecords": records,
                        "scope": {"name": "securecode-ai", "version": "1.0.0"},
                    }
                ]
            }
        ]
    }
    return json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


__all__ = ["OtlpHttpExporter", "OtlpTransport", "StdlibOtlpTransport"]
