"""Bounded source-free observations of the local gateway backend exchanges."""

from __future__ import annotations

import threading
from dataclasses import dataclass

from .local_provider_gateway import (
    GatewayExchangeObservation,
    GatewayExchangePhase,
    GatewayNormalizationObservation,
    GatewayPolicy,
)

_MAX_OBSERVATIONS = 64


class PublicGatewayObservationError(ValueError):
    """Gateway exchange metadata is not bound to this recorder's policy."""


@dataclass(frozen=True, slots=True)
class PublicGatewayObservationSnapshot:
    """Immutable bounded recorder state, with no request or response payloads."""

    policy_sha256: str
    observations: tuple[GatewayExchangeObservation, ...]
    overflow: bool

    def __post_init__(self) -> None:
        if (
            not _sha256(self.policy_sha256)
            or type(self.observations) is not tuple
            or len(self.observations) > _MAX_OBSERVATIONS
            or any(type(item) is not GatewayExchangeObservation for item in self.observations)
            or type(self.overflow) is not bool
        ):
            raise PublicGatewayObservationError("invalid gateway observation snapshot")


class PublicGatewayExchangeRecorder:
    """Thread-safe, capped collector for actual backend exchanges only."""

    __slots__ = ("_lock", "_normalizations", "_observations", "_overflow", "_policy_sha256")

    def __init__(self, policy: GatewayPolicy) -> None:
        if type(policy) is not GatewayPolicy:
            raise PublicGatewayObservationError("invalid gateway observation policy")
        self._policy_sha256 = policy.content_sha256
        self._observations: list[GatewayExchangeObservation] = []
        self._normalizations: list[GatewayNormalizationObservation] = []
        self._overflow = False
        self._lock = threading.Lock()

    def observe(self, observation: GatewayExchangeObservation) -> None:
        """Capture an immutable observation or fail the associated successful exchange."""

        if type(observation) is not GatewayExchangeObservation:
            raise PublicGatewayObservationError("invalid gateway exchange observation")
        copied = _copy(observation)
        if copied.policy_sha256 != self._policy_sha256:
            raise PublicGatewayObservationError("foreign gateway observation policy")
        with self._lock:
            if len(self._observations) >= _MAX_OBSERVATIONS:
                self._overflow = True
                return
            self._observations.append(copied)

    def observe_normalization(self, observation: GatewayNormalizationObservation) -> None:
        if type(observation) is not GatewayNormalizationObservation:
            raise PublicGatewayObservationError("invalid gateway normalization observation")
        copied = GatewayNormalizationObservation(
            observation.policy_sha256,
            observation.request_sha256,
            observation.status,
            observation.native_shape,
            observation.native_arguments_shape,
            observation.native_arguments_rejection,
        )
        if copied.policy_sha256 != self._policy_sha256:
            raise PublicGatewayObservationError("foreign gateway normalization policy")
        with self._lock:
            if len(self._normalizations) >= _MAX_OBSERVATIONS:
                self._overflow = True
                return
            self._normalizations.append(copied)

    def snapshot_document(self) -> dict[str, object]:
        """Return only the fixed public metadata whitelist after host cleanup."""

        with self._lock:
            snapshot = PublicGatewayObservationSnapshot(
                policy_sha256=self._policy_sha256,
                observations=tuple(self._observations),
                overflow=self._overflow,
            )
            normalizations_snapshot = tuple(self._normalizations)
        exchanges = [_document(item) for item in snapshot.observations]
        normalizations = [
            {
                "request_sha256": item.request_sha256,
                "status": item.status.value,
                "native_shape": item.native_shape.value,
                "native_arguments_shape": item.native_arguments_shape.value,
                "native_arguments_rejection": item.native_arguments_rejection.value,
            }
            for item in normalizations_snapshot
        ]
        incomplete = (
            snapshot.overflow
            or not exchanges
            or any(
                item.phase is not GatewayExchangePhase.COMPLETE
                or item.mapped_status != 200
                or item.deadline_expired
                or item.response_overflow
                for item in snapshot.observations
            )
        )
        return {
            "schema_version": "public-gateway-exchange-observation.v1",
            "coverage": "BACKEND_EXCHANGES_ONLY",
            "client_delivery_known": False,
            "policy_sha256": snapshot.policy_sha256,
            "observation_count": len(exchanges),
            "overflow": snapshot.overflow,
            "incomplete": incomplete,
            "exchanges": exchanges,
            "normalizations": normalizations,
        }


def _copy(value: GatewayExchangeObservation) -> GatewayExchangeObservation:
    return GatewayExchangeObservation(
        policy_sha256=value.policy_sha256,
        request_sha256=value.request_sha256,
        operation=value.operation,
        phase=value.phase,
        mapped_status=value.mapped_status,
        observed_http_status=value.observed_http_status,
        elapsed_known=value.elapsed_known,
        elapsed_ms=value.elapsed_ms,
        deadline_expired=value.deadline_expired,
        backend_dispatched=value.backend_dispatched,
        received_bytes=value.received_bytes,
        response_overflow=value.response_overflow,
        failure=value.failure,
    )


def _document(value: GatewayExchangeObservation) -> dict[str, object]:
    return {
        "request_sha256": value.request_sha256,
        "operation": value.operation.value,
        "phase": value.phase.value,
        "mapped_status": value.mapped_status,
        "observed_http_status": value.observed_http_status,
        "elapsed_known": value.elapsed_known,
        "elapsed_ms": value.elapsed_ms,
        "deadline_expired": value.deadline_expired,
        "backend_dispatched": value.backend_dispatched,
        "received_bytes": value.received_bytes,
        "response_overflow": value.response_overflow,
        "failure": value.failure.value,
    }


def _sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


__all__ = [
    "PublicGatewayExchangeRecorder",
    "PublicGatewayObservationError",
    "PublicGatewayObservationSnapshot",
]
