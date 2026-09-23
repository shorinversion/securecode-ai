"""Offline contracts for the bounded OTLP/HTTP exporter."""

from __future__ import annotations

import json

import pytest
from securecode_ai.adapters.otlp_http import OtlpHttpExporter
from securecode_ai.server.observability import Observation, RedactedExporter


class _Transport:
    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.calls: list[tuple[str, bytes, int]] = []

    def post_json(self, *, endpoint: str, payload: bytes, timeout_ms: int) -> int:
        self.calls.append((endpoint, payload, timeout_ms))
        return self.status


def _observation(*, duration_ms: int | None = None) -> Observation:
    return Observation(
        name="securecode.run.completed",
        attributes={"operation": "run", "outcome": "success", "tenant_id": "tenant-1"},
        duration_ms=duration_ms,
    )


def test_exporter_emits_canonical_source_free_otlp_json() -> None:
    transport = _Transport()
    exporter = OtlpHttpExporter(
        endpoint="https://collector.example/v1/logs",
        transport=transport,
        timeout_ms=321,
        clock_ns=lambda: 123,
    )

    assert exporter.export((_observation(duration_ms=17),))
    assert "configured" in repr(exporter)
    assert transport.calls[0][0] == "https://collector.example/v1/logs"
    assert transport.calls[0][2] == 321
    document = json.loads(transport.calls[0][1])
    record = document["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    assert record["body"] == {"stringValue": "securecode.run.completed"}
    assert record["timeUnixNano"] == "123"
    assert {item["key"] for item in record["attributes"]} == {
        "duration_ms",
        "operation",
        "outcome",
        "tenant_id",
    }
    assert b"exfiltrate" not in transport.calls[0][1]


@pytest.mark.parametrize(
    "endpoint",
    (
        "http://collector.example/v1/logs",
        "https://collector.example/other",
        "https://collector-user@collector.example/v1/logs",
        "https://collector.example/v1/logs?redirect=yes",
        "https://collector.example:444/v1/logs",
    ),
)
def test_exporter_rejects_unsafe_or_non_otlp_endpoints(endpoint: str) -> None:
    with pytest.raises(ValueError, match="OTLP_ENDPOINT_REJECTED"):
        OtlpHttpExporter(endpoint=endpoint)


def test_failed_transport_and_non_success_are_not_export_success() -> None:
    failing = OtlpHttpExporter(
        endpoint="https://collector.example/v1/logs",
        transport=_Transport(503),
        clock_ns=lambda: 1,
    )
    assert not failing.export((_observation(),))

    class _BrokenTransport:
        def post_json(self, *, endpoint: str, payload: bytes, timeout_ms: int) -> int:
            del endpoint, payload, timeout_ms
            raise RuntimeError("network unavailable")

    broken = OtlpHttpExporter(
        endpoint="https://collector.example/v1/logs",
        transport=_BrokenTransport(),
        clock_ns=lambda: 1,
    )
    assert not broken.export((_observation(),))


def test_redacted_exporter_can_consume_otlp_exporter() -> None:
    transport = _Transport()
    exporter = RedactedExporter(
        OtlpHttpExporter(
            endpoint="https://collector.example/v1/logs",
            transport=transport,
            clock_ns=lambda: 1,
        )
    )

    result = exporter.export((_observation(),))

    assert result.accepted
    assert result.count == 1


def test_observation_snapshots_attributes_before_export() -> None:
    attributes = {"operation": "run", "outcome": "success"}
    observation = Observation(name="securecode.run.completed", attributes=attributes)
    attributes["source"] = "private source"
    attributes["operation"] = "changed"

    with pytest.raises(TypeError):
        observation.attributes["source"] = "private source"  # type: ignore[index]

    transport = _Transport()
    exporter = OtlpHttpExporter(
        endpoint="https://collector.example/v1/logs",
        transport=transport,
        clock_ns=lambda: 1,
    )
    assert exporter.export((observation,))
    record = json.loads(transport.calls[0][1])["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    exported = {item["key"]: item["value"]["stringValue"] for item in record["attributes"]}
    assert exported == {"operation": "run", "outcome": "success"}
    assert b"private source" not in transport.calls[0][1]


def test_empty_and_oversized_batches_fail_without_network() -> None:
    transport = _Transport()
    exporter = OtlpHttpExporter(
        endpoint="https://collector.example/v1/logs", transport=transport, clock_ns=lambda: 1
    )

    assert not exporter.export(())
    assert not exporter.export(tuple(_observation() for _ in range(257)))
    assert transport.calls == []
