"""Governed promotion of offline optimization candidates."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final

from .evaluation_authority import EvaluationSecurityReceipt
from .evaluation_lab import EvaluationLab
from .evaluation_lab_evidence import AuthoritativePromotionEvidence
from .offline_optimization import (
    FIXED_MAX_CASES,
    FIXED_MAX_COST_MICROUNITS,
    FIXED_MAX_ELAPSED_MS,
    FIXED_MAX_TOKENS,
    OfflineOptimizationLab,
    OptimizationRunReceipt,
)
from .offline_optimization_evidence import optimization_envelope_hash
from .optimization_candidates import (
    OptimizationActor,
    OptimizationCandidateHandle,
    OptimizationCandidateStore,
)

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class OptimizationPromotionError(ValueError):
    """Safe promotion error without candidate content or locked expectations."""

    def __init__(self) -> None:
        super().__init__("Optimization promotion was rejected")
        self.__cause__ = None
        self.__context__ = None


class OptimizationPromotionDecision(StrEnum):
    PROMOTE = "PROMOTE"
    NO_PROMOTION = "NO_PROMOTION"


class OptimizationPromotionDisposition(StrEnum):
    PROMOTED = "PROMOTED"
    NO_PROMOTION = "NO_PROMOTION"
    IDEMPOTENT = "IDEMPOTENT"


@dataclass(frozen=True, slots=True)
class OptimizationPromotionRequest:
    actor: OptimizationActor
    reviewer_id: str
    decision: OptimizationPromotionDecision
    candidate_key: str
    optimization_run_id: str
    held_out_candidate_key: str
    held_out_run_id: str
    appsec_approval: EvaluationSecurityReceipt

    def __post_init__(self) -> None:
        if (
            self.actor is not OptimizationActor.PROMOTION_REVIEWER
            or type(self.reviewer_id) is not str
            or _ID.fullmatch(self.reviewer_id) is None
            or type(self.decision) is not OptimizationPromotionDecision
            or any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (
                    self.candidate_key,
                    self.optimization_run_id,
                    self.held_out_candidate_key,
                    self.held_out_run_id,
                )
            )
            or type(self.appsec_approval) is not EvaluationSecurityReceipt
        ):
            raise OptimizationPromotionError()


@dataclass(frozen=True, slots=True)
class OptimizationPromotionReceipt:
    disposition: OptimizationPromotionDisposition
    candidate_key: str
    optimization_run_id: str
    held_out_run_id: str
    appsec_receipt_sha256: str | None
    production_alias_updated: bool = False
    locked_expectations_disclosed: bool = False


class OptimizationPromotionGovernor:
    """Allow a reviewed candidate promotion without granting production write authority."""

    __slots__ = ("_candidate_store", "_evaluation_lab", "_lab", "_lock", "_promotions")

    def __init__(
        self,
        *,
        candidate_store: OptimizationCandidateStore,
        lab: OfflineOptimizationLab,
        evaluation_lab: EvaluationLab,
    ) -> None:
        if (
            type(candidate_store) is not OptimizationCandidateStore
            or type(lab) is not OfflineOptimizationLab
            or type(evaluation_lab) is not EvaluationLab
        ):
            raise OptimizationPromotionError()
        self._candidate_store = candidate_store
        self._lab = lab
        self._evaluation_lab = evaluation_lab
        self._lock = RLock()
        self._promotions: dict[str, OptimizationPromotionReceipt] = {}

    def decide(self, request: OptimizationPromotionRequest) -> OptimizationPromotionReceipt:
        if type(request) is not OptimizationPromotionRequest:
            raise OptimizationPromotionError()
        request = OptimizationPromotionRequest(
            request.actor,
            request.reviewer_id,
            request.decision,
            request.candidate_key,
            request.optimization_run_id,
            request.held_out_candidate_key,
            request.held_out_run_id,
            request.appsec_approval,
        )
        try:
            candidate = _candidate_snapshot(self._candidate_store.resolve(request.candidate_key))
            experiment = self._lab.resolve(request.optimization_run_id)
        except Exception:
            raise OptimizationPromotionError() from None
        if request.decision is OptimizationPromotionDecision.NO_PROMOTION:
            return OptimizationPromotionReceipt(
                OptimizationPromotionDisposition.NO_PROMOTION,
                candidate.candidate_key,
                experiment.run_id,
                request.held_out_run_id,
                None,
            )
        try:
            held_out = self._evaluation_lab.require_authoritative_promotion_evidence(
                candidate_key=request.held_out_candidate_key,
                held_out_run_id=request.held_out_run_id,
                reviewer_id=request.reviewer_id,
                security_receipt=request.appsec_approval,
            )
        except Exception:
            raise OptimizationPromotionError() from None
        if not _eligible(
            candidate.owner_id, candidate.content_sha256, experiment, held_out, request
        ):
            raise OptimizationPromotionError()
        receipt = OptimizationPromotionReceipt(
            OptimizationPromotionDisposition.PROMOTED,
            candidate.candidate_key,
            experiment.run_id,
            held_out.run_id,
            held_out.security_receipt_sha256,
        )
        with self._lock:
            existing = self._promotions.get(candidate.candidate_key)
            if existing is None:
                self._promotions[candidate.candidate_key] = receipt
                return receipt
            if existing == receipt:
                return OptimizationPromotionReceipt(
                    OptimizationPromotionDisposition.IDEMPOTENT,
                    existing.candidate_key,
                    existing.optimization_run_id,
                    existing.held_out_run_id,
                    existing.appsec_receipt_sha256,
                )
        raise OptimizationPromotionError()


def _eligible(
    owner_id: str,
    content_sha256: str,
    experiment: OptimizationRunReceipt,
    held_out: AuthoritativePromotionEvidence,
    request: OptimizationPromotionRequest,
) -> bool:
    return (
        request.reviewer_id != owner_id
        and experiment.candidate.candidate_key == request.candidate_key
        and experiment.candidate.content_sha256 == content_sha256
        and experiment.metrics.security_regressions == 0
        and experiment.metrics.denominator_cases <= FIXED_MAX_CASES
        and experiment.metrics.cost_microunits <= FIXED_MAX_COST_MICROUNITS
        and experiment.metrics.tokens_used <= FIXED_MAX_TOKENS
        and experiment.metrics.latency_ms <= FIXED_MAX_ELAPSED_MS
        and experiment.execution_envelope_sha256 == optimization_envelope_hash(experiment.envelope)
        and not experiment.network_accessed
        and not experiment.credentials_accessed
        and not experiment.production_alias_accessed
        and not experiment.locked_expectations_accessed
        and held_out.candidate_key == request.held_out_candidate_key
        and held_out.run_id == request.held_out_run_id
        and held_out.candidate_content_sha256 == content_sha256
        and bool(held_out.security_receipt_sha256)
    )


def _candidate_snapshot(candidate: object) -> OptimizationCandidateHandle:
    if type(candidate) is not OptimizationCandidateHandle:
        raise OptimizationPromotionError()
    snapshot = OptimizationCandidateHandle(
        candidate.candidate_key,
        candidate.candidate_id,
        candidate.version,
        candidate.owner_id,
        candidate.kind,
        candidate.content_sha256,
        candidate.size_bytes,
    )
    expected_key = (
        "opt-candidate-"
        + hashlib.sha256(
            f"{snapshot.candidate_id}\x00{snapshot.version}\x00{snapshot.content_sha256}".encode(
                "ascii"
            )
        ).hexdigest()[:40]
    )
    if (
        type(snapshot.candidate_key) is not str
        or snapshot.candidate_key != expected_key
        or type(snapshot.candidate_id) is not str
        or _ID.fullmatch(snapshot.candidate_id) is None
        or type(snapshot.version) is not int
        or snapshot.version < 1
        or type(snapshot.owner_id) is not str
        or _ID.fullmatch(snapshot.owner_id) is None
        or type(snapshot.content_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", snapshot.content_sha256) is None
        or type(snapshot.size_bytes) is not int
        or snapshot.size_bytes < 1
    ):
        raise OptimizationPromotionError()
    return snapshot


__all__ = [
    "OptimizationPromotionDecision",
    "OptimizationPromotionDisposition",
    "OptimizationPromotionError",
    "OptimizationPromotionGovernor",
    "OptimizationPromotionReceipt",
    "OptimizationPromotionRequest",
]
