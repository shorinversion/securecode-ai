"""Closed public gateway-observation recorder checks."""

from __future__ import annotations

import json

import pytest
from securecode_ai.adapters.local_provider_gateway import (
    GatewayExchangeFailure,
    GatewayExchangeObservation,
    GatewayExchangeOperation,
    GatewayExchangePhase,
    GatewayNormalizationObservation,
    GatewayPolicy,
    GatewayResponseNormalization,
)
from securecode_ai.adapters.native_repository_tools import NativeToolCallRejection
from securecode_ai.adapters.public_gateway_observation import (
    PublicGatewayExchangeRecorder,
    PublicGatewayObservationError,
)

POLICY = GatewayPolicy("qwen-test", "a" * 64, timeout_seconds=0.2)


def _observation(policy: GatewayPolicy = POLICY) -> GatewayExchangeObservation:
    return GatewayExchangeObservation(
        policy_sha256=policy.content_sha256,
        request_sha256="b" * 64,
        operation=GatewayExchangeOperation.VERSION,
        phase=GatewayExchangePhase.COMPLETE,
        mapped_status=200,
        observed_http_status=200,
        elapsed_known=True,
        elapsed_ms=7,
        deadline_expired=False,
        backend_dispatched=False,
        received_bytes=21,
        response_overflow=False,
        failure=GatewayExchangeFailure.NONE,
    )


def test_recorder_rejects_foreign_policy_and_documents_only_closed_metadata() -> None:
    recorder = PublicGatewayExchangeRecorder(POLICY)
    recorder.observe(_observation())
    with pytest.raises(PublicGatewayObservationError):
        recorder.observe(_observation(GatewayPolicy("qwen-test", "b" * 64, timeout_seconds=0.2)))

    for _ in range(64):
        recorder.observe(_observation())
    document = recorder.snapshot_document()
    assert document["coverage"] == "BACKEND_EXCHANGES_ONLY"
    assert document["client_delivery_known"] is False
    assert document["overflow"] and document["incomplete"]
    encoded = json.dumps(document, sort_keys=True)
    assert "public synthetic fixture" not in encoded and "response_bytes" not in encoded


def test_recorder_marks_failed_or_unfinished_exchanges_incomplete() -> None:
    recorder = PublicGatewayExchangeRecorder(POLICY)
    recorder.observe(
        GatewayExchangeObservation(
            policy_sha256=POLICY.content_sha256,
            request_sha256="c" * 64,
            operation=GatewayExchangeOperation.GENERATION,
            phase=GatewayExchangePhase.HEADERS,
            mapped_status=502,
            observed_http_status=None,
            elapsed_known=False,
            elapsed_ms=None,
            deadline_expired=True,
            backend_dispatched=True,
            received_bytes=0,
            response_overflow=False,
            failure=GatewayExchangeFailure.TIMEOUT,
        )
    )

    document = recorder.snapshot_document()
    exchanges = document["exchanges"]
    assert isinstance(exchanges, list)
    assert exchanges and isinstance(exchanges[0], dict)
    assert document["incomplete"]
    assert exchanges[0]["phase"] == "HEADERS"
    assert exchanges[0]["elapsed_ms"] is None


def test_recorder_preserves_the_bounded_one_byte_response_overrun() -> None:
    recorder = PublicGatewayExchangeRecorder(POLICY)
    recorder.observe(
        GatewayExchangeObservation(
            policy_sha256=POLICY.content_sha256,
            request_sha256="d" * 64,
            operation=GatewayExchangeOperation.TAGS,
            phase=GatewayExchangePhase.BODY,
            mapped_status=502,
            observed_http_status=200,
            elapsed_known=True,
            elapsed_ms=8,
            deadline_expired=False,
            backend_dispatched=False,
            received_bytes=8 * 1024 * 1024 + 1,
            response_overflow=True,
            failure=GatewayExchangeFailure.TRANSPORT,
        )
    )

    document = recorder.snapshot_document()
    exchanges = document["exchanges"]
    assert isinstance(exchanges, list)
    assert exchanges and isinstance(exchanges[0], dict)
    exchange = exchanges[0]
    assert exchange["received_bytes"] == 8 * 1024 * 1024 + 1
    assert exchange["response_overflow"] and document["incomplete"]


def test_recorder_serializes_only_closed_normalization_status() -> None:
    recorder = PublicGatewayExchangeRecorder(POLICY)
    recorder.observe_normalization(
        GatewayNormalizationObservation(
            POLICY.content_sha256,
            "e" * 64,
            GatewayResponseNormalization.NATIVE,
        )
    )
    document = recorder.snapshot_document()
    assert document["normalizations"] == [
        {
            "request_sha256": "e" * 64,
            "status": "NATIVE",
            "native_shape": "NOT_APPLICABLE",
            "native_arguments_shape": "NOT_APPLICABLE",
            "native_arguments_rejection": "NOT_APPLICABLE",
        }
    ]
    assert "raw response" not in json.dumps(document, sort_keys=True)


def test_recorder_serializes_only_closed_native_parser_rejection() -> None:
    from securecode_ai.adapters.local_provider_gateway import (
        GatewayNativeArgumentsShape,
        GatewayNativeEnvelopeShape,
    )

    recorder = PublicGatewayExchangeRecorder(POLICY)
    recorder.observe_normalization(
        GatewayNormalizationObservation(
            POLICY.content_sha256,
            "f" * 64,
            GatewayResponseNormalization.REJECTED,
            GatewayNativeEnvelopeShape.ARGUMENTS_REJECTED,
            GatewayNativeArgumentsShape.STRING,
            NativeToolCallRejection.JSON_DUPLICATE,
        )
    )
    document = recorder.snapshot_document()
    assert document["normalizations"] == [
        {
            "request_sha256": "f" * 64,
            "status": "REJECTED",
            "native_shape": "ARGUMENTS_REJECTED",
            "native_arguments_shape": "STRING",
            "native_arguments_rejection": "JSON_DUPLICATE",
        }
    ]
    encoded = json.dumps(document, sort_keys=True)
    assert "private key" not in encoded and "private value" not in encoded


def test_normalization_observation_rejects_non_enum_parser_classification() -> None:
    with pytest.raises(ValueError):
        GatewayNormalizationObservation(
            POLICY.content_sha256,
            "f" * 64,
            GatewayResponseNormalization.REJECTED,
            native_arguments_rejection="JSON_DUPLICATE",  # type: ignore[arg-type]
        )
