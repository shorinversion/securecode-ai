"""Offline prompt and skill optimization experiment contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final

from .offline_optimization_authority import (
    OfflineOptimizationError,
    OptimizationExecutionResult,
    OptimizationMetrics,
    OptimizationResultAuthority,
)
from .offline_optimization_authority import (
    copy_metrics as _copy_metrics,
)
from .offline_optimization_evidence import optimization_envelope_hash
from .optimization_candidates import (
    OptimizationActor,
    OptimizationCandidateHandle,
    OptimizationCandidateKind,
    OptimizationCandidateStore,
)

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH: Final = re.compile(r"[0-9a-f]{64}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/offline-optimization/v1\x00"
FIXED_MAX_CASES: Final = 100
FIXED_MAX_COST_MICROUNITS: Final = 10_000_000
FIXED_MAX_TOKENS: Final = 100_000
FIXED_MAX_ELAPSED_MS: Final = 60_000


class OptimizationPhase(StrEnum):
    TRAIN = "TRAIN"
    DEV = "DEV"
    CALIBRATION = "CALIBRATION"


class OptimizationRunDisposition(StrEnum):
    RECORDED = "RECORDED"
    IDEMPOTENT = "IDEMPOTENT"


@dataclass(frozen=True, slots=True)
class OptimizationProvenance:
    optimizer_id: str
    optimizer_version: str
    model_sha256: str
    dataset_sha256: str
    profile_sha256: str
    budget_sha256: str
    seed: int

    def __post_init__(self) -> None:
        if (
            type(self.optimizer_id) is not str
            or _ID.fullmatch(self.optimizer_id) is None
            or type(self.optimizer_version) is not str
            or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.optimizer_version) is None
            or any(
                type(value) is not str or _HASH.fullmatch(value) is None
                for value in (
                    self.model_sha256,
                    self.dataset_sha256,
                    self.profile_sha256,
                    self.budget_sha256,
                )
            )
            or type(self.seed) is not int
            or self.seed < 0
        ):
            raise OfflineOptimizationError()


@dataclass(frozen=True, slots=True)
class OfflineOptimizationEnvelope:
    network_disabled: bool
    credentials_disabled: bool
    production_alias_access: bool
    locked_expectations_access: bool
    max_cases: int = FIXED_MAX_CASES
    max_cost_microunits: int = FIXED_MAX_COST_MICROUNITS
    max_tokens: int = FIXED_MAX_TOKENS
    max_elapsed_ms: int = FIXED_MAX_ELAPSED_MS

    def __post_init__(self) -> None:
        if (
            self.network_disabled is not True
            or self.credentials_disabled is not True
            or self.production_alias_access is not False
            or self.locked_expectations_access is not False
            or self.max_cases != FIXED_MAX_CASES
            or self.max_cost_microunits != FIXED_MAX_COST_MICROUNITS
            or self.max_tokens != FIXED_MAX_TOKENS
            or self.max_elapsed_ms != FIXED_MAX_ELAPSED_MS
        ):
            raise OfflineOptimizationError()


@dataclass(frozen=True, slots=True)
class OptimizationRunRequest:
    actor: OptimizationActor
    candidate_key: str
    phase: OptimizationPhase
    provenance: OptimizationProvenance

    def __post_init__(self) -> None:
        if (
            self.actor is not OptimizationActor.OPTIMIZER
            or type(self.candidate_key) is not str
            or _ID.fullmatch(self.candidate_key) is None
            or type(self.phase) is not OptimizationPhase
            or type(self.provenance) is not OptimizationProvenance
        ):
            raise OfflineOptimizationError()


@dataclass(frozen=True, slots=True)
class OptimizationRunReceipt:
    disposition: OptimizationRunDisposition
    run_id: str
    candidate: OptimizationCandidateHandle
    phase: OptimizationPhase
    provenance: OptimizationProvenance
    metrics: OptimizationMetrics
    envelope: OfflineOptimizationEnvelope
    execution_key_id: str | None = None
    execution_signature_sha256: str | None = None
    execution_envelope_sha256: str | None = None
    network_accessed: bool = False
    credentials_accessed: bool = False
    production_alias_accessed: bool = False
    locked_expectations_accessed: bool = False


class OfflineOptimizationLab:
    """Record exact offline experiments and return deterministic Pareto comparisons."""

    __slots__ = ("_candidate_store", "_lock", "_result_authority", "_runs")

    def __init__(
        self,
        candidate_store: OptimizationCandidateStore,
        result_authority: OptimizationResultAuthority,
    ) -> None:
        if (
            type(candidate_store) is not OptimizationCandidateStore
            or type(result_authority) is not OptimizationResultAuthority
        ):
            raise OfflineOptimizationError()
        self._candidate_store = candidate_store
        self._result_authority = result_authority
        self._runs: dict[str, OptimizationRunReceipt] = {}
        self._lock = RLock()

    def launch(self, request: OptimizationRunRequest) -> OptimizationRunReceipt:
        if type(request) is not OptimizationRunRequest:
            raise OfflineOptimizationError()
        try:
            candidate = self._candidate_store.resolve(request.candidate_key)
        except Exception:
            raise OfflineOptimizationError() from None
        run_id = _run_id(request, candidate)
        return OptimizationRunReceipt(
            OptimizationRunDisposition.RECORDED,
            run_id,
            candidate,
            request.phase,
            request.provenance,
            OptimizationMetrics(0.0, 0, 0, 0, 0, 0, 1, 0),
            OfflineOptimizationEnvelope(True, True, False, False),
        )

    def record(
        self,
        request: OptimizationRunRequest,
        result: OptimizationExecutionResult,
    ) -> OptimizationRunReceipt:
        if (
            type(request) is not OptimizationRunRequest
            or type(result) is not OptimizationExecutionResult
        ):
            raise OfflineOptimizationError()
        result = self._result_authority.verify_and_copy(result)
        pending = self.launch(request)
        metrics = result.metrics
        if (
            result.run_id != pending.run_id
            or result.envelope_sha256 != optimization_envelope_hash(pending.envelope)
            or result.network_accessed
            or result.credentials_accessed
            or result.production_alias_accessed
            or result.locked_expectations_accessed
            or metrics.denominator_cases > pending.envelope.max_cases
            or metrics.cost_microunits > pending.envelope.max_cost_microunits
            or metrics.tokens_used > pending.envelope.max_tokens
            or metrics.latency_ms > pending.envelope.max_elapsed_ms
        ):
            raise OfflineOptimizationError()
        receipt = OptimizationRunReceipt(
            OptimizationRunDisposition.RECORDED,
            pending.run_id,
            pending.candidate,
            pending.phase,
            pending.provenance,
            metrics,
            pending.envelope,
            result.key_id,
            result.signature_sha256,
            result.envelope_sha256,
            result.network_accessed,
            result.credentials_accessed,
            result.production_alias_accessed,
            result.locked_expectations_accessed,
        )
        with self._lock:
            existing = self._runs.get(receipt.run_id)
            if existing is None:
                self._runs[receipt.run_id] = _copy_run_receipt(receipt)
                return _copy_run_receipt(receipt)
            if existing == receipt:
                return _copy_run_receipt(
                    existing,
                    disposition=OptimizationRunDisposition.IDEMPOTENT,
                )
        raise OfflineOptimizationError()

    def resolve(self, run_id: str) -> OptimizationRunReceipt:
        if type(run_id) is not str or _ID.fullmatch(run_id) is None:
            raise OfflineOptimizationError()
        with self._lock:
            try:
                receipt = _copy_run_receipt(self._runs[run_id])
            except KeyError:
                raise OfflineOptimizationError() from None
        if (
            receipt.execution_key_id is None
            or receipt.execution_signature_sha256 is None
            or receipt.execution_envelope_sha256 is None
        ):
            raise OfflineOptimizationError()
        verified = self._result_authority.verify_and_copy(
            OptimizationExecutionResult(
                receipt.run_id,
                receipt.metrics,
                receipt.execution_envelope_sha256,
                receipt.network_accessed,
                receipt.credentials_accessed,
                receipt.production_alias_accessed,
                receipt.locked_expectations_accessed,
                receipt.execution_key_id,
                receipt.execution_signature_sha256,
            )
        )
        if verified.run_id != receipt.run_id or verified.metrics != receipt.metrics:
            raise OfflineOptimizationError()
        return receipt


def pareto_front(
    receipts: tuple[OptimizationRunReceipt, ...],
) -> tuple[OptimizationRunReceipt, ...]:
    if not receipts or any(type(item) is not OptimizationRunReceipt for item in receipts):
        raise OfflineOptimizationError()
    unique = {item.run_id: item for item in receipts}
    if len(unique) != len(receipts):
        raise OfflineOptimizationError()
    return tuple(
        item
        for item in sorted(receipts, key=lambda value: value.run_id)
        if not any(
            _dominates(other.metrics, item.metrics) for other in receipts if other is not item
        )
    )


def _dominates(left: OptimizationMetrics, right: OptimizationMetrics) -> bool:
    no_worse = (
        left.quality_score >= right.quality_score
        and left.cost_microunits <= right.cost_microunits
        and left.latency_ms <= right.latency_ms
        and left.security_regressions <= right.security_regressions
    )
    return no_worse and (
        left.quality_score > right.quality_score
        or left.cost_microunits < right.cost_microunits
        or left.latency_ms < right.latency_ms
        or left.security_regressions < right.security_regressions
    )


def _run_id(request: OptimizationRunRequest, candidate: OptimizationCandidateHandle) -> str:
    material = {
        "candidate": candidate.candidate_key,
        "phase": request.phase.value,
        "provenance": {
            "budget": request.provenance.budget_sha256,
            "dataset": request.provenance.dataset_sha256,
            "model": request.provenance.model_sha256,
            "optimizer": request.provenance.optimizer_id,
            "optimizer_version": request.provenance.optimizer_version,
            "profile": request.provenance.profile_sha256,
            "seed": request.provenance.seed,
        },
    }
    return (
        "opt-run-"
        + hashlib.sha256(
            _HASH_DOMAIN
            + json.dumps(
                material, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
            ).encode("ascii")
        ).hexdigest()[:40]
    )


def _copy_run_receipt(
    receipt: OptimizationRunReceipt,
    *,
    disposition: OptimizationRunDisposition | None = None,
) -> OptimizationRunReceipt:
    if (
        type(receipt) is not OptimizationRunReceipt
        or type(receipt.disposition) is not OptimizationRunDisposition
        or type(receipt.run_id) is not str
        or _ID.fullmatch(receipt.run_id) is None
        or type(receipt.phase) is not OptimizationPhase
        or (
            receipt.execution_key_id is not None
            and (
                type(receipt.execution_key_id) is not str
                or _ID.fullmatch(receipt.execution_key_id) is None
            )
        )
        or (
            receipt.execution_signature_sha256 is not None
            and (
                type(receipt.execution_signature_sha256) is not str
                or _HASH.fullmatch(receipt.execution_signature_sha256) is None
            )
        )
        or (
            receipt.execution_envelope_sha256 is not None
            and (
                type(receipt.execution_envelope_sha256) is not str
                or _HASH.fullmatch(receipt.execution_envelope_sha256) is None
            )
        )
        or type(receipt.network_accessed) is not bool
        or type(receipt.credentials_accessed) is not bool
        or type(receipt.production_alias_accessed) is not bool
        or type(receipt.locked_expectations_accessed) is not bool
    ):
        raise OfflineOptimizationError()
    candidate = receipt.candidate
    if (
        type(candidate) is not OptimizationCandidateHandle
        or type(candidate.candidate_key) is not str
        or _ID.fullmatch(candidate.candidate_key) is None
        or type(candidate.candidate_id) is not str
        or _ID.fullmatch(candidate.candidate_id) is None
        or type(candidate.version) is not int
        or candidate.version < 1
        or type(candidate.owner_id) is not str
        or _ID.fullmatch(candidate.owner_id) is None
        or type(candidate.kind) is not OptimizationCandidateKind
        or type(candidate.content_sha256) is not str
        or _HASH.fullmatch(candidate.content_sha256) is None
        or type(candidate.size_bytes) is not int
        or candidate.size_bytes < 1
        or candidate.candidate_key
        != "opt-candidate-"
        + hashlib.sha256(
            f"{candidate.candidate_id}\x00{candidate.version}\x00{candidate.content_sha256}".encode(
                "ascii"
            )
        ).hexdigest()[:40]
    ):
        raise OfflineOptimizationError()
    candidate_copy = OptimizationCandidateHandle(
        candidate.candidate_key,
        candidate.candidate_id,
        candidate.version,
        candidate.owner_id,
        candidate.kind,
        candidate.content_sha256,
        candidate.size_bytes,
    )
    provenance = receipt.provenance
    provenance_copy = OptimizationProvenance(
        provenance.optimizer_id,
        provenance.optimizer_version,
        provenance.model_sha256,
        provenance.dataset_sha256,
        provenance.profile_sha256,
        provenance.budget_sha256,
        provenance.seed,
    )
    envelope = receipt.envelope
    envelope_copy = OfflineOptimizationEnvelope(
        envelope.network_disabled,
        envelope.credentials_disabled,
        envelope.production_alias_access,
        envelope.locked_expectations_access,
        envelope.max_cases,
        envelope.max_cost_microunits,
        envelope.max_tokens,
        envelope.max_elapsed_ms,
    )
    expected_run = _run_id(
        OptimizationRunRequest(
            OptimizationActor.OPTIMIZER,
            candidate_copy.candidate_key,
            receipt.phase,
            provenance_copy,
        ),
        candidate_copy,
    )
    if receipt.run_id != expected_run:
        raise OfflineOptimizationError()
    return OptimizationRunReceipt(
        receipt.disposition if disposition is None else disposition,
        receipt.run_id,
        candidate_copy,
        receipt.phase,
        provenance_copy,
        _copy_metrics(receipt.metrics),
        envelope_copy,
        receipt.execution_key_id,
        receipt.execution_signature_sha256,
        receipt.execution_envelope_sha256,
        receipt.network_accessed,
        receipt.credentials_accessed,
        receipt.production_alias_accessed,
        receipt.locked_expectations_accessed,
    )


__all__ = [
    "FIXED_MAX_CASES",
    "FIXED_MAX_COST_MICROUNITS",
    "FIXED_MAX_ELAPSED_MS",
    "FIXED_MAX_TOKENS",
    "OfflineOptimizationEnvelope",
    "OfflineOptimizationError",
    "OfflineOptimizationLab",
    "OptimizationExecutionResult",
    "OptimizationMetrics",
    "OptimizationPhase",
    "OptimizationProvenance",
    "OptimizationResultAuthority",
    "OptimizationRunDisposition",
    "OptimizationRunReceipt",
    "OptimizationRunRequest",
    "pareto_front",
]
