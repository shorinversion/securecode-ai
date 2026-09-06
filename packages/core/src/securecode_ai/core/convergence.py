"""Fail-closed convergence for the mandatory discovery lanes.

The deterministic and model-native lanes are deliberately kept independent
until this boundary.  Their candidates are normalized through the existing
P2.9 normalizer, so a cross-lane merge retains every source candidate and
lineage reference instead of treating either lane as an oracle for the other.

This module does not publish an :class:`~securecode_ai.contracts.AuditRunOutcome`
of ``PASS``.  It can establish only whether the mandatory discovery and
Auditor-interpretation coverage is complete.  Finding policy and the remaining
required stages retain ownership of the final run outcome.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.contracts import (
    AuditRunOutcome,
    CandidateInterpretationReceipt,
    CandidateOrigin,
    CoverageManifest,
    DiscoveryCandidate,
    ModelCallStatus,
    ModelDiscoveryReceipt,
    RunExecutionIdentity,
)

from .evidence_graph import EvidenceGraph, EvidenceGraphError
from .normalization import NormalizationError, normalize_signals


class ConvergenceErrorCode(StrEnum):
    """Closed, source-free reasons trusted convergence input is refused."""

    INVALID_INPUT = "INVALID_INPUT"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class ConvergenceError(ValueError):
    """A safe boundary error that never renders candidates or model content."""

    __slots__ = ("code",)

    def __init__(self, code: ConvergenceErrorCode) -> None:
        if type(code) is not ConvergenceErrorCode:
            raise TypeError("convergence error code is invalid")
        self.code = code
        super().__init__("dual-lane convergence failed")
        self.__cause__ = None
        self.__context__ = None


class ConvergenceCoverageState(StrEnum):
    """Coverage state, intentionally separate from product run outcomes."""

    COMPLETE = "COMPLETE"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True, slots=True)
class DualLaneConvergenceInput:
    """Typed inputs produced by the two discovery lanes and the Auditor.

    ``coverage_manifest`` is intentionally optional so that an incomplete or
    faulted run can still be represented.  Its absence can never be upgraded
    into complete coverage.
    """

    execution_identity: RunExecutionIdentity
    deterministic_candidates: tuple[DiscoveryCandidate, ...]
    model_native_candidates: tuple[DiscoveryCandidate, ...]
    model_discovery_receipt: ModelDiscoveryReceipt | None
    interpretation_receipts: tuple[CandidateInterpretationReceipt, ...]
    coverage_manifest: CoverageManifest | None
    evidence_graph: EvidenceGraph | None

    def __post_init__(self) -> None:
        if (
            type(self.execution_identity) is not RunExecutionIdentity
            or type(self.deterministic_candidates) is not tuple
            or type(self.model_native_candidates) is not tuple
            or any(type(item) is not DiscoveryCandidate for item in self.deterministic_candidates)
            or any(type(item) is not DiscoveryCandidate for item in self.model_native_candidates)
            or (
                self.model_discovery_receipt is not None
                and type(self.model_discovery_receipt) is not ModelDiscoveryReceipt
            )
            or type(self.interpretation_receipts) is not tuple
            or any(
                type(item) is not CandidateInterpretationReceipt
                for item in self.interpretation_receipts
            )
            or (
                self.coverage_manifest is not None
                and type(self.coverage_manifest) is not CoverageManifest
            )
            or (self.evidence_graph is not None and type(self.evidence_graph) is not EvidenceGraph)
        ):
            raise ConvergenceError(ConvergenceErrorCode.INVALID_INPUT)


@dataclass(frozen=True, slots=True)
class DualLaneConvergenceResult:
    """Normalized candidates plus the mandatory-stage coverage determination."""

    candidates: tuple[DiscoveryCandidate, ...]
    coverage_state: ConvergenceCoverageState
    required_terminal_outcome: AuditRunOutcome | None

    def __post_init__(self) -> None:
        if (
            type(self.candidates) is not tuple
            or any(type(item) is not DiscoveryCandidate for item in self.candidates)
            or type(self.coverage_state) is not ConvergenceCoverageState
            or self.required_terminal_outcome not in {None, AuditRunOutcome.INDETERMINATE}
            or (
                self.coverage_state is ConvergenceCoverageState.COMPLETE
                and self.required_terminal_outcome is not None
            )
            or (
                self.coverage_state is ConvergenceCoverageState.INDETERMINATE
                and self.required_terminal_outcome is not AuditRunOutcome.INDETERMINATE
            )
        ):
            raise ConvergenceError(ConvergenceErrorCode.INTEGRITY_FAILURE)

    @property
    def mandatory_coverage_complete(self) -> bool:
        """Whether this boundary has complete discovery/Auditor coverage."""

        return self.coverage_state is ConvergenceCoverageState.COMPLETE


def converge_dual_lanes(request: DualLaneConvergenceInput) -> DualLaneConvergenceResult:
    """Converge both lanes and fail closed on incomplete mandatory coverage.

    A model-native receipt is mandatory even if that lane found no candidates.
    A ``SUCCEEDED`` completed-zero receipt is valid coverage; every absent,
    non-success or malformed result is not.  Every resulting candidate must
    have exactly one current terminal Auditor receipt.  The supplied manifest
    is rebound to the exact repository, execution and policy identity through
    ``RunExecutionIdentity.execution_identity_hash`` before it can contribute
    complete coverage.
    """

    if type(request) is not DualLaneConvergenceInput:
        raise ConvergenceError(ConvergenceErrorCode.INVALID_INPUT)
    identity = _validated_identity(request.execution_identity)
    deterministic = _validated_candidates(request.deterministic_candidates)
    model_native = _validated_candidates(request.model_native_candidates)
    _validate_lane_inputs(identity, deterministic, model_native)

    try:
        candidates = normalize_signals(
            discovery_candidates=(*deterministic, *model_native),
        )
    except NormalizationError as error:
        if error.code.value == "IDENTITY_MISMATCH":
            raise ConvergenceError(ConvergenceErrorCode.IDENTITY_MISMATCH) from None
        raise ConvergenceError(ConvergenceErrorCode.INTEGRITY_FAILURE) from None

    receipt = _validated_discovery_receipt(request.model_discovery_receipt)
    interpretations = _validated_interpretations(request.interpretation_receipts)
    manifest = _validated_manifest(request.coverage_manifest)
    graph = _validated_evidence_graph(request.evidence_graph)
    complete = _has_complete_coverage(
        identity=identity,
        candidates=candidates,
        model_native_candidates=model_native,
        receipt=receipt,
        interpretations=interpretations,
        manifest=manifest,
        graph=graph,
    )
    return DualLaneConvergenceResult(
        candidates=candidates,
        coverage_state=(
            ConvergenceCoverageState.COMPLETE
            if complete
            else ConvergenceCoverageState.INDETERMINATE
        ),
        required_terminal_outcome=None if complete else AuditRunOutcome.INDETERMINATE,
    )


def _validated_identity(value: RunExecutionIdentity) -> RunExecutionIdentity:
    try:
        return RunExecutionIdentity.model_validate(value.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError):
        raise ConvergenceError(ConvergenceErrorCode.INTEGRITY_FAILURE) from None


def _validated_candidates(
    values: tuple[DiscoveryCandidate, ...],
) -> tuple[DiscoveryCandidate, ...]:
    try:
        candidates = tuple(
            DiscoveryCandidate.model_validate(item.model_dump(mode="python")) for item in values
        )
    except (AttributeError, TypeError, ValueError):
        raise ConvergenceError(ConvergenceErrorCode.INTEGRITY_FAILURE) from None
    if len({item.candidate_id for item in candidates}) != len(candidates):
        raise ConvergenceError(ConvergenceErrorCode.INTEGRITY_FAILURE)
    return candidates


def _validated_discovery_receipt(
    value: ModelDiscoveryReceipt | None,
) -> ModelDiscoveryReceipt | None:
    if value is None:
        return None
    try:
        return ModelDiscoveryReceipt.model_validate(value.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError):
        raise ConvergenceError(ConvergenceErrorCode.INTEGRITY_FAILURE) from None


def _validated_interpretations(
    values: tuple[CandidateInterpretationReceipt, ...],
) -> tuple[CandidateInterpretationReceipt, ...]:
    try:
        receipts = tuple(
            CandidateInterpretationReceipt.model_validate(item.model_dump(mode="python"))
            for item in values
        )
    except (AttributeError, TypeError, ValueError):
        raise ConvergenceError(ConvergenceErrorCode.INTEGRITY_FAILURE) from None
    if len({item.receipt_id for item in receipts}) != len(receipts):
        raise ConvergenceError(ConvergenceErrorCode.INTEGRITY_FAILURE)
    return receipts


def _validated_manifest(value: CoverageManifest | None) -> CoverageManifest | None:
    if value is None:
        return None
    try:
        return CoverageManifest.model_validate(value.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError):
        raise ConvergenceError(ConvergenceErrorCode.INTEGRITY_FAILURE) from None


def _validated_evidence_graph(value: EvidenceGraph | None) -> EvidenceGraph | None:
    """Copy/revalidate the graph before using its candidate binding."""

    if value is None:
        return None
    try:
        return EvidenceGraph(
            graph_id=value.graph_id,
            tenant_id=value.tenant_id,
            head_sha=value.head_sha,
            candidates=value.candidates,
            evidence=value.evidence,
            edges=value.edges,
            schema_version=value.schema_version,
        )
    except (AttributeError, TypeError, ValueError, EvidenceGraphError):
        raise ConvergenceError(ConvergenceErrorCode.INTEGRITY_FAILURE) from None


def _validate_lane_inputs(
    identity: RunExecutionIdentity,
    deterministic: tuple[DiscoveryCandidate, ...],
    model_native: tuple[DiscoveryCandidate, ...],
) -> None:
    tenant_id = identity.repository_revision.tenant_id
    head_sha = identity.repository_revision.head_sha
    for candidate in deterministic:
        if (
            candidate.candidate_origin is not CandidateOrigin.DETERMINISTIC
            or candidate.tenant_id != tenant_id
            or candidate.head_sha != head_sha
        ):
            raise ConvergenceError(ConvergenceErrorCode.IDENTITY_MISMATCH)
    for candidate in model_native:
        if (
            candidate.candidate_origin is not CandidateOrigin.MODEL_NATIVE
            or candidate.tenant_id != tenant_id
            or candidate.head_sha != head_sha
        ):
            raise ConvergenceError(ConvergenceErrorCode.IDENTITY_MISMATCH)
    if {item.candidate_id for item in deterministic} & {item.candidate_id for item in model_native}:
        raise ConvergenceError(ConvergenceErrorCode.INTEGRITY_FAILURE)


def _has_complete_coverage(
    *,
    identity: RunExecutionIdentity,
    candidates: tuple[DiscoveryCandidate, ...],
    model_native_candidates: tuple[DiscoveryCandidate, ...],
    receipt: ModelDiscoveryReceipt | None,
    interpretations: tuple[CandidateInterpretationReceipt, ...],
    manifest: CoverageManifest | None,
    graph: EvidenceGraph | None,
) -> bool:
    if receipt is None or manifest is None or graph is None:
        return False
    if (
        graph.tenant_id != identity.repository_revision.tenant_id
        or graph.head_sha != identity.repository_revision.head_sha
        or graph.candidates != candidates
    ):
        return False
    if (
        receipt.tenant_id != identity.repository_revision.tenant_id
        or receipt.head_sha != identity.repository_revision.head_sha
        or receipt.model_call_status is not ModelCallStatus.SUCCEEDED
        or not receipt.schema_valid_result
        or receipt.candidate_ids
        != tuple(sorted(item.candidate_id for item in model_native_candidates))
    ):
        return False

    # ``normalize_signals`` intentionally replaces lane-local candidate IDs
    # with a stable fingerprint-derived ID.  Prove that every *input*
    # model-native candidate survives under a MODEL_NATIVE lineage rather than
    # requiring the pre-normalization receipt to lie about its source IDs.
    if not _model_inputs_retained(model_native_candidates, candidates):
        return False
    model_output_ids = tuple(
        sorted(
            item.candidate_id
            for item in candidates
            if item.candidate_origin in {CandidateOrigin.MODEL_NATIVE, CandidateOrigin.HYBRID}
        )
    )
    if not _manifest_binds_converged_model_receipt(manifest, receipt, model_output_ids):
        return False

    expected_versions = {(item.candidate_id, item.candidate_version): item for item in candidates}
    receipt_keys = {(item.candidate_id, item.candidate_version): item for item in interpretations}
    if set(receipt_keys) != set(expected_versions) or len(receipt_keys) != len(interpretations):
        return False
    if any(
        item.tenant_id != identity.repository_revision.tenant_id
        or item.head_sha != identity.repository_revision.head_sha
        or item.model_call_status is not ModelCallStatus.SUCCEEDED
        or not item.schema_valid_result
        for item in interpretations
    ):
        return False
    return (
        manifest.execution_identity_hash == identity.execution_identity_hash
        and manifest.discovery_candidates == candidates
        and manifest.candidate_interpretation_receipts == interpretations
        and manifest.coverage_complete
    )


def _model_inputs_retained(
    model_native_candidates: tuple[DiscoveryCandidate, ...],
    candidates: tuple[DiscoveryCandidate, ...],
) -> bool:
    """Prove each P3.10 source candidate reached a model-native lineage."""

    for source in model_native_candidates:
        if not any(
            output.root_cause_fingerprint == source.root_cause_fingerprint
            and any(
                lineage.lane.value == "model_native"
                and source.candidate_id in lineage.input_candidate_ids
                for lineage in output.lineage
            )
            for output in candidates
        ):
            return False
    return True


def _manifest_binds_converged_model_receipt(
    manifest: CoverageManifest,
    source_receipt: ModelDiscoveryReceipt,
    model_output_ids: tuple[str, ...],
) -> bool:
    """Bind source-lane receipt to its normalized manifest representation.

    The public manifest contract records current normalized candidate IDs,
    while P3.10's receipt correctly records the model lane's pre-normalization
    source IDs.  All non-candidate receipt fields must remain byte-identical;
    lineage above is the explicit, lossless mapping between the two ID sets.
    """

    if len(manifest.model_discovery_receipts) != 1:
        return False
    normalized_receipt = manifest.model_discovery_receipts[0]
    if normalized_receipt.candidate_ids != model_output_ids:
        return False
    source_material = source_receipt.model_dump(mode="python")
    normalized_material = normalized_receipt.model_dump(mode="python")
    source_material.pop("candidate_ids")
    normalized_material.pop("candidate_ids")
    return source_material == normalized_material


__all__ = [
    "ConvergenceCoverageState",
    "ConvergenceError",
    "ConvergenceErrorCode",
    "DualLaneConvergenceInput",
    "DualLaneConvergenceResult",
    "converge_dual_lanes",
]
