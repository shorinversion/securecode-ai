"""Sealed execution-result authority for offline optimization."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import asdict, dataclass
from typing import Final

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH: Final = re.compile(r"[0-9a-f]{64}\Z")
_RESULT_DOMAIN: Final = b"securecode-ai/offline-optimization-result/v2\x00"


class OfflineOptimizationError(ValueError):
    def __init__(self) -> None:
        super().__init__("Offline optimization request was rejected")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class OptimizationMetrics:
    quality_score: float
    cost_microunits: int
    latency_ms: int
    security_regressions: int
    passed_cases: int
    failed_cases: int
    invalid_outputs: int
    tokens_used: int

    def __post_init__(self) -> None:
        counts = (self.passed_cases, self.failed_cases, self.invalid_outputs)
        if (
            type(self.quality_score) is not float
            or not 0.0 <= self.quality_score <= 1.0
            or any(
                type(value) is not int or value < 0
                for value in (
                    self.cost_microunits,
                    self.latency_ms,
                    self.security_regressions,
                    self.tokens_used,
                    *counts,
                )
            )
            or sum(counts) < 1
        ):
            raise OfflineOptimizationError()

    @property
    def denominator_cases(self) -> int:
        return self.passed_cases + self.failed_cases + self.invalid_outputs


@dataclass(frozen=True, slots=True)
class OptimizationExecutionResult:
    run_id: str
    metrics: OptimizationMetrics
    envelope_sha256: str
    network_accessed: bool
    credentials_accessed: bool
    production_alias_accessed: bool
    locked_expectations_accessed: bool
    key_id: str
    signature_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.run_id) is not str
            or _ID.fullmatch(self.run_id) is None
            or type(self.metrics) is not OptimizationMetrics
            or type(self.envelope_sha256) is not str
            or _HASH.fullmatch(self.envelope_sha256) is None
            or any(
                type(value) is not bool
                for value in (
                    self.network_accessed,
                    self.credentials_accessed,
                    self.production_alias_accessed,
                    self.locked_expectations_accessed,
                )
            )
            or type(self.key_id) is not str
            or _ID.fullmatch(self.key_id) is None
            or type(self.signature_sha256) is not str
            or _HASH.fullmatch(self.signature_sha256) is None
        ):
            raise OfflineOptimizationError()


class OptimizationResultAuthority:
    __slots__ = ("_key", "_key_check", "_key_id")

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("OptimizationResultAuthority is immutable")
        object.__setattr__(self, name, value)

    def __init__(self, key: bytes, key_id: str) -> None:
        if (
            type(key) is not bytes
            or len(key) < 32
            or type(key_id) is not str
            or not _ID.fullmatch(key_id)
        ):
            raise OfflineOptimizationError()
        self._key = bytes(key)
        self._key_check = hashlib.sha256(key).digest()
        self._key_id = key_id

    def issue(
        self,
        run_id: str,
        metrics: OptimizationMetrics,
        *,
        envelope_sha256: str,
        network_accessed: bool,
        credentials_accessed: bool,
        production_alias_accessed: bool,
        locked_expectations_accessed: bool,
    ) -> OptimizationExecutionResult:
        if not self._intact():
            raise OfflineOptimizationError()
        result = OptimizationExecutionResult(
            run_id,
            copy_metrics(metrics),
            envelope_sha256,
            network_accessed,
            credentials_accessed,
            production_alias_accessed,
            locked_expectations_accessed,
            self._key_id,
            "0" * 64,
        )
        return OptimizationExecutionResult(
            result.run_id,
            result.metrics,
            result.envelope_sha256,
            result.network_accessed,
            result.credentials_accessed,
            result.production_alias_accessed,
            result.locked_expectations_accessed,
            result.key_id,
            self._signature(result),
        )

    def verify(self, result: OptimizationExecutionResult) -> bool:
        try:
            self.verify_and_copy(result)
        except OfflineOptimizationError:
            return False
        return True

    def verify_and_copy(self, result: OptimizationExecutionResult) -> OptimizationExecutionResult:
        if not self._intact() or type(result) is not OptimizationExecutionResult:
            raise OfflineOptimizationError()
        snapshot = OptimizationExecutionResult(
            result.run_id,
            copy_metrics(result.metrics),
            result.envelope_sha256,
            result.network_accessed,
            result.credentials_accessed,
            result.production_alias_accessed,
            result.locked_expectations_accessed,
            result.key_id,
            result.signature_sha256,
        )
        if snapshot.key_id != self._key_id or not hmac.compare_digest(
            snapshot.signature_sha256, self._signature(snapshot)
        ):
            raise OfflineOptimizationError()
        return snapshot

    def _signature(self, result: OptimizationExecutionResult) -> str:
        if not self._intact():
            raise OfflineOptimizationError()
        material = {
            "credentials_accessed": result.credentials_accessed,
            "envelope_sha256": result.envelope_sha256,
            "locked_expectations_accessed": result.locked_expectations_accessed,
            "metrics": asdict(result.metrics),
            "network_accessed": result.network_accessed,
            "production_alias_accessed": result.production_alias_accessed,
            "run_id": result.run_id,
        }
        encoded = json.dumps(
            material, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
        return hmac.new(self._key, _RESULT_DOMAIN + encoded, hashlib.sha256).hexdigest()

    def _intact(self) -> bool:
        try:
            return (
                type(self) is OptimizationResultAuthority
                and type(self._key) is bytes
                and len(self._key) >= 32
                and type(self._key_id) is str
                and _ID.fullmatch(self._key_id) is not None
                and hmac.compare_digest(hashlib.sha256(self._key).digest(), self._key_check)
            )
        except Exception:
            return False


def copy_metrics(metrics: OptimizationMetrics) -> OptimizationMetrics:
    if type(metrics) is not OptimizationMetrics:
        raise OfflineOptimizationError()
    return OptimizationMetrics(
        **{name: getattr(metrics, name) for name in OptimizationMetrics.__dataclass_fields__}
    )


__all__ = [
    "OfflineOptimizationError",
    "OptimizationExecutionResult",
    "OptimizationMetrics",
    "OptimizationResultAuthority",
    "copy_metrics",
]
