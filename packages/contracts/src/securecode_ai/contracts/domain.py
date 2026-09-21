"""Versioned, provider-neutral domain contracts for SecureCode AI."""

from __future__ import annotations

from .base import (
    DataClass,
    WireModel,
)
from .domain_coverage import (
    ArtifactRef,
    CoverageManifest,
    CoverageUnit,
    LineageRef,
    ProducerRef,
    RunExecutionIdentity,
    SourceLocation,
    SourcePosition,
)
from .domain_discovery import (
    CandidateInterpretationReceipt,
    DiscoveryCandidate,
    Evidence,
    ModelBudgetUsage,
    ModelDiscoveryReceipt,
    RawSignal,
)
from .domain_primitives import (
    ACCEPTED_STAGE_CATALOGUE_PIN as ACCEPTED_STAGE_CATALOGUE_PIN,
)
from .domain_primitives import (
    AnalysisHealth,
    AuditRunOutcome,
    CandidateOrigin,
    ComponentPin,
    CoverageStatus,
    DecisionOutcome,
    DiscoveryLane,
    EvidenceKind,
    FindingGateState,
    FindingVerdict,
    ModelCallStatus,
    PatchStatus,
    RepositoryRevision,
    TrustLabel,
    ValidationGateOutcome,
    ValidationOutcome,
)
from .domain_primitives import (
    CoverageScenario as CoverageScenario,
)
from .domain_results import (
    AuditRun,
    Decision,
    FindingCase,
    PatchCandidate,
    ResourceUsage,
    ValidationGateResult,
    ValidationResult,
)

_domain_types_namespace = globals()
for _model in (
    CoverageManifest,
    RawSignal,
    DiscoveryCandidate,
    ModelDiscoveryReceipt,
    CandidateInterpretationReceipt,
    Evidence,
    FindingCase,
    PatchCandidate,
    ValidationResult,
    AuditRun,
):
    _model.model_rebuild(_types_namespace=_domain_types_namespace)
del _domain_types_namespace, _model

for _domain_type in (
    ModelCallStatus,
    FindingVerdict,
    AuditRunOutcome,
    CandidateOrigin,
    DiscoveryLane,
    CoverageStatus,
    AnalysisHealth,
    FindingGateState,
    TrustLabel,
    EvidenceKind,
    PatchStatus,
    ValidationGateOutcome,
    ValidationOutcome,
    DecisionOutcome,
    CoverageScenario,
    ComponentPin,
    RepositoryRevision,
    CoverageUnit,
    CoverageManifest,
    RawSignal,
    DiscoveryCandidate,
    ModelBudgetUsage,
    ModelDiscoveryReceipt,
    CandidateInterpretationReceipt,
    Evidence,
    FindingCase,
    PatchCandidate,
    ResourceUsage,
    ValidationGateResult,
    ValidationResult,
    Decision,
    AuditRun,
):
    _domain_type.__module__ = __name__
del _domain_type
PUBLIC_ROOT_MODELS: dict[str, type[WireModel]] = {
    "audit-run": AuditRun,
    "evidence": Evidence,
    "finding-case": FindingCase,
    "patch-candidate": PatchCandidate,
    "validation-result": ValidationResult,
}

__all__ = [
    "ACCEPTED_STAGE_CATALOGUE_PIN",
    "PUBLIC_ROOT_MODELS",
    "AnalysisHealth",
    "ArtifactRef",
    "AuditRun",
    "AuditRunOutcome",
    "CandidateInterpretationReceipt",
    "CandidateOrigin",
    "ComponentPin",
    "CoverageManifest",
    "CoverageStatus",
    "CoverageUnit",
    "DataClass",
    "Decision",
    "DecisionOutcome",
    "DiscoveryCandidate",
    "DiscoveryLane",
    "Evidence",
    "EvidenceKind",
    "FindingCase",
    "FindingGateState",
    "FindingVerdict",
    "LineageRef",
    "ModelBudgetUsage",
    "ModelCallStatus",
    "ModelDiscoveryReceipt",
    "PatchCandidate",
    "PatchStatus",
    "ProducerRef",
    "RawSignal",
    "RepositoryRevision",
    "ResourceUsage",
    "RunExecutionIdentity",
    "SourceLocation",
    "SourcePosition",
    "TrustLabel",
    "ValidationGateOutcome",
    "ValidationGateResult",
    "ValidationOutcome",
    "ValidationResult",
]
