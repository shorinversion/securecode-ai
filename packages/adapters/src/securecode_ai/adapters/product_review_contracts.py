"""Candidate-local Skeptic and Finding Gate composition for a product flow.

This adapter deliberately returns only candidate-local review evidence.  It
does not construct an ``AuditRun`` or a ``CoverageManifest`` because the
mandatory intake, reporting, and execution-identity stages are outside this
bounded seam.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from securecode_ai.contracts import (
    CoverageUnit,
    FindingGateState,
    ModelCallStatus,
)
from securecode_ai.core.finding_gate import (
    FindingGateDecision,
)
from securecode_ai.core.model_discovery import ModelNativeDiscoveryOutcome
from securecode_ai.core.skeptic import (
    AuditorSnapshot,
    SkepticOutput,
    SkepticReview,
)


class ProductReviewFailureCode(StrEnum):
    """Closed, source-free reasons a candidate cannot complete this seam."""

    AUDITOR_PREPARATION_FAILED = "AUDITOR_PREPARATION_FAILED"
    AUDITOR_RECEIPT_INVALID = "AUDITOR_RECEIPT_INVALID"
    AUDITOR_NON_SUCCESS = "AUDITOR_NON_SUCCESS"
    SKEPTIC_PORT_INVALID = "SKEPTIC_PORT_INVALID"
    SKEPTIC_REVIEW_INVALID = "SKEPTIC_REVIEW_INVALID"
    FINDING_GATE_INVALID = "FINDING_GATE_INVALID"


@dataclass(frozen=True, slots=True)
class SkepticInvocation:
    """A host-owned, parsed Skeptic result without provider or source content."""

    skeptic_identity: str
    model_call_status: ModelCallStatus
    output: SkepticOutput | object | None


class SkepticReviewPort(Protocol):
    """The only effectful dependency of this composition seam."""

    def review(self, snapshot: AuditorSnapshot) -> SkepticInvocation: ...


@dataclass(frozen=True, slots=True)
class ProductCandidateReviewOutcome:
    """Identity-bound, source-free review and route information for one candidate."""

    candidate_id: str
    candidate_version: int
    tenant_id: str
    head_sha: str
    skeptic_review: SkepticReview | None
    finding_gate: FindingGateDecision | None
    coverage_units: tuple[CoverageUnit, ...]
    failure_code: ProductReviewFailureCode | None

    @property
    def has_known_blocking_finding(self) -> bool:
        return (
            self.finding_gate is not None
            and self.finding_gate.finding_gate_state is FindingGateState.BLOCKING
        )


@dataclass(frozen=True, slots=True)
class ProductReviewResult:
    """Candidate-local composition result, intentionally not a product outcome."""

    tenant_id: str
    head_sha: str
    discovery: ModelNativeDiscoveryOutcome
    upstream_incomplete: bool
    outcomes: tuple[ProductCandidateReviewOutcome, ...]

    @property
    def coverage_units(self) -> tuple[CoverageUnit, ...]:
        return tuple(unit for outcome in self.outcomes for unit in outcome.coverage_units)

    @property
    def candidate_coverage_complete(self) -> bool:
        """Whether this seam completed every present candidate review unit.

        A completed-zero flow has no candidate review units and therefore never
        reports this partial property as complete. It is not whole-run coverage
        and cannot be used as a clean product outcome.
        """

        return bool(self.outcomes) and all(
            unit.satisfies_required_coverage for unit in self.coverage_units
        )

    @property
    def has_known_blocking_finding(self) -> bool:
        """Preserve a known block even when another candidate has degraded coverage."""

        return any(outcome.has_known_blocking_finding for outcome in self.outcomes)
