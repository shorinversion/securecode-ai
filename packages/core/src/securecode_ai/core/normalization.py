"""Deterministic convergence of scanner facts and discovery candidates.

Normalization deliberately does not interpret a scanner fact as a finding or a
verdict.  It creates the stable, provenance-complete candidate representation
which later stages can use for evidence construction and interpretation.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.contracts import (
    CandidateOrigin,
    CommandOperationEvidence,
    ContractExtension,
    DiscoveryCandidate,
    DiscoveryLane,
    LineageRef,
    ProducerRef,
    RawSignal,
    SourceLocation,
)

_OPAQUE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_FINGERPRINT_DOMAIN = b"securecode-ai/root-cause-fingerprint/v1\x00"
_CANDIDATE_ID_PREFIX = "candidate-"
_LINEAGE_ID_PREFIX = "lineage-"
_MAX_INPUT_ITEMS = 100_000
_MAX_LINEAGES = 4_096


class NormalizationErrorCode(StrEnum):
    """Closed, source-free reasons for normalization refusal."""

    REQUEST_INVALID = "REQUEST_INVALID"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"


class NormalizationError(RuntimeError):
    """Fixed, non-echoing normalization failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: NormalizationErrorCode) -> None:
        if type(code) is not NormalizationErrorCode:
            raise TypeError("normalization error code is invalid")
        self.code = code
        self.safe_message = "signal normalization failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class NormalizationLimits:
    """Hard limits for an in-memory deterministic normalization batch."""

    max_raw_signals: int = _MAX_INPUT_ITEMS
    max_input_candidates: int = _MAX_INPUT_ITEMS
    max_output_candidates: int = _MAX_INPUT_ITEMS
    max_lineages_per_candidate: int = _MAX_LINEAGES

    def __post_init__(self) -> None:
        values = (
            self.max_raw_signals,
            self.max_input_candidates,
            self.max_output_candidates,
            self.max_lineages_per_candidate,
        )
        if (
            any(type(value) is not int for value in values)
            or any(value < 1 or value > _MAX_INPUT_ITEMS for value in values)
            or self.max_lineages_per_candidate > _MAX_LINEAGES
        ):
            raise ValueError("normalization limits are invalid")


DEFAULT_NORMALIZATION_LIMITS = NormalizationLimits()


def root_cause_fingerprint(signal: RawSignal) -> str:
    """Derive a domain-separated, revision-independent root-cause fingerprint.

    The material intentionally excludes ``head_sha``, scanner identity and raw
    signal ID.  It instead binds the tenant-scoped source identity, rule and
    exact source location including its content hash.  Consequently, the same
    unchanged root cause has the same identifier across commits, while a moved
    location or changed source bytes does not silently collapse into it.
    """

    validated_signal = _validated_signal(signal)
    return root_cause_location_fingerprint(
        tenant_id=validated_signal.tenant_id,
        rule_id=validated_signal.rule_id,
        location=validated_signal.location,
    )


def root_cause_location_fingerprint(
    *, tenant_id: str, rule_id: str, location: SourceLocation
) -> str:
    """Compute host-owned identity without creating a synthetic scanner fact.

    Both discovery lanes use the unchanged v1 domain and exact location/rule
    material. This proves identity equivalence only, never vulnerability truth.
    """
    if (
        type(tenant_id) is not str
        or _OPAQUE_ID.fullmatch(tenant_id) is None
        or type(rule_id) is not str
        or _OPAQUE_ID.fullmatch(rule_id) is None
        or type(location) is not SourceLocation
    ):
        raise NormalizationError(NormalizationErrorCode.REQUEST_INVALID)
    try:
        location = SourceLocation.model_validate_json(location.model_dump_json())
    except (AttributeError, TypeError, ValueError, RecursionError):
        raise NormalizationError(NormalizationErrorCode.INTEGRITY_FAILURE) from None
    material = {
        "location": {
            "content_sha256": location.content_sha256,
            "end": {"column": location.end.column, "line": location.end.line},
            "path": location.path,
            "start": {"column": location.start.column, "line": location.start.line},
        },
        "rule_id": rule_id,
        "tenant_id": tenant_id,
    }
    return hashlib.sha256(_FINGERPRINT_DOMAIN + _canonical_json_bytes(material)).hexdigest()


def normalize_raw_signal(signal: RawSignal) -> DiscoveryCandidate:
    """Normalize one deterministic scanner fact into one candidate.

    This convenience function has the same canonicalization and validation as
    ``normalize_signals``; batch callers should prefer the latter so duplicate
    facts and model-native candidates can converge together.
    """

    return normalize_signals(raw_signals=(signal,))[0]


def normalize_signals(
    *,
    raw_signals: tuple[RawSignal, ...] = (),
    discovery_candidates: tuple[DiscoveryCandidate, ...] = (),
    limits: NormalizationLimits = DEFAULT_NORMALIZATION_LIMITS,
) -> tuple[DiscoveryCandidate, ...]:
    """Return canonical candidates with complete deterministic/model lineage.

    Inputs must describe one tenant-scoped immutable revision and one accepted
    schema version.  Candidates converge only when their root-cause
    fingerprints are byte-for-byte equal; nearby locations or merely similar
    rules remain separate candidates.  Every input raw-signal or candidate ID,
    producer and evidence reference survives in output lineage.
    """

    if (
        type(raw_signals) is not tuple
        or type(discovery_candidates) is not tuple
        or type(limits) is not NormalizationLimits
    ):
        raise NormalizationError(NormalizationErrorCode.REQUEST_INVALID)
    if (
        len(raw_signals) > limits.max_raw_signals
        or len(discovery_candidates) > limits.max_input_candidates
    ):
        raise NormalizationError(NormalizationErrorCode.RESOURCE_LIMIT)
    if not raw_signals and not discovery_candidates:
        return ()

    signals = _unique_signals(raw_signals)
    candidates = _unique_candidates(discovery_candidates)
    _validate_batch_identity(signals, candidates)

    grouped: dict[str, list[_CandidateMaterial]] = {}
    for signal in signals:
        fingerprint = root_cause_fingerprint(signal)
        grouped.setdefault(fingerprint, []).append(
            _CandidateMaterial(
                fingerprint=fingerprint,
                tenant_id=signal.tenant_id,
                head_sha=signal.head_sha,
                schema_version=signal.schema_version,
                extensions=signal.extensions,
                candidate_version=1,
                lineages=(_lineage_for_signal(signal, fingerprint),),
                evidence_ids=(),
                command_operation_evidence=(
                    (signal.command_operation_evidence,)
                    if signal.command_operation_evidence is not None
                    else ()
                ),
            )
        )
    for candidate in candidates:
        grouped.setdefault(candidate.root_cause_fingerprint, []).append(
            _material_for_candidate(candidate)
        )

    if len(grouped) > limits.max_output_candidates:
        raise NormalizationError(NormalizationErrorCode.RESOURCE_LIMIT)
    output = tuple(
        _merge_materials(fingerprint, grouped[fingerprint], limits)
        for fingerprint in sorted(grouped)
    )
    return output


@dataclass(frozen=True, slots=True)
class _CandidateMaterial:
    fingerprint: str
    tenant_id: str
    head_sha: str
    schema_version: str
    extensions: tuple[ContractExtension, ...]
    candidate_version: int
    lineages: tuple[LineageRef, ...]
    evidence_ids: tuple[str, ...]
    command_operation_evidence: tuple[CommandOperationEvidence, ...]


def _validated_signal(signal: RawSignal) -> RawSignal:
    if type(signal) is not RawSignal:
        raise NormalizationError(NormalizationErrorCode.REQUEST_INVALID)
    try:
        return RawSignal.model_validate(signal.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError, RecursionError):
        raise NormalizationError(NormalizationErrorCode.INTEGRITY_FAILURE) from None


def _validated_candidate(candidate: DiscoveryCandidate) -> DiscoveryCandidate:
    if type(candidate) is not DiscoveryCandidate:
        raise NormalizationError(NormalizationErrorCode.REQUEST_INVALID)
    try:
        return DiscoveryCandidate.model_validate(candidate.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError, RecursionError):
        raise NormalizationError(NormalizationErrorCode.INTEGRITY_FAILURE) from None


def _unique_signals(raw_signals: tuple[RawSignal, ...]) -> tuple[RawSignal, ...]:
    signals_by_id: dict[str, RawSignal] = {}
    for raw_signal in raw_signals:
        signal = _validated_signal(raw_signal)
        previous = signals_by_id.get(signal.raw_signal_id)
        if previous is not None and previous != signal:
            raise NormalizationError(NormalizationErrorCode.INTEGRITY_FAILURE)
        signals_by_id[signal.raw_signal_id] = signal
    return tuple(signals_by_id[signal_id] for signal_id in sorted(signals_by_id))


def _unique_candidates(
    discovery_candidates: tuple[DiscoveryCandidate, ...],
) -> tuple[DiscoveryCandidate, ...]:
    candidates_by_id: dict[str, DiscoveryCandidate] = {}
    for unvalidated_candidate in discovery_candidates:
        candidate = _validated_candidate(unvalidated_candidate)
        previous = candidates_by_id.get(candidate.candidate_id)
        if previous is not None and previous != candidate:
            raise NormalizationError(NormalizationErrorCode.INTEGRITY_FAILURE)
        candidates_by_id[candidate.candidate_id] = candidate
    return tuple(candidate for _, candidate in sorted(candidates_by_id.items()))


def _validate_batch_identity(
    signals: tuple[RawSignal, ...],
    candidates: tuple[DiscoveryCandidate, ...],
) -> None:
    identities = {(signal.tenant_id, signal.head_sha, signal.schema_version) for signal in signals}
    identities.update(
        (candidate.tenant_id, candidate.head_sha, candidate.schema_version)
        for candidate in candidates
    )
    if len(identities) != 1:
        raise NormalizationError(NormalizationErrorCode.IDENTITY_MISMATCH)


def _lineage_for_signal(signal: RawSignal, fingerprint: str) -> LineageRef:
    lineage_material = {
        "lane": DiscoveryLane.DETERMINISTIC.value,
        "producer": _producer_material(signal.producer),
        "raw_signal_id": signal.raw_signal_id,
        "root_cause_fingerprint": fingerprint,
    }
    lineage_id = (
        _LINEAGE_ID_PREFIX
        + hashlib.sha256(_FINGERPRINT_DOMAIN + _canonical_json_bytes(lineage_material)).hexdigest()
    )
    return LineageRef(
        schema_version=signal.schema_version,
        extensions=signal.extensions,
        lineage_id=lineage_id,
        lane=DiscoveryLane.DETERMINISTIC,
        producer=signal.producer,
        root_cause_fingerprint=fingerprint,
        input_signal_ids=(signal.raw_signal_id,),
    )


def _material_for_candidate(candidate: DiscoveryCandidate) -> _CandidateMaterial:
    lineages = tuple(
        _lineage_with_input_candidate(lineage, candidate.candidate_id)
        for lineage in candidate.lineage
    )
    return _CandidateMaterial(
        fingerprint=candidate.root_cause_fingerprint,
        tenant_id=candidate.tenant_id,
        head_sha=candidate.head_sha,
        schema_version=candidate.schema_version,
        extensions=candidate.extensions,
        candidate_version=candidate.candidate_version,
        lineages=lineages,
        evidence_ids=candidate.evidence_ids,
        command_operation_evidence=candidate.command_operation_evidence,
    )


def _lineage_with_input_candidate(lineage: LineageRef, candidate_id: str) -> LineageRef:
    try:
        material = lineage.model_dump(mode="python")
        material["input_signal_ids"] = tuple(sorted(lineage.input_signal_ids))
        material["input_candidate_ids"] = tuple(
            sorted({*lineage.input_candidate_ids, candidate_id})
        )
        material["evidence_ids"] = tuple(sorted(lineage.evidence_ids))
        return LineageRef(**material)
    except (AttributeError, TypeError, ValueError, RecursionError):
        raise NormalizationError(NormalizationErrorCode.INTEGRITY_FAILURE) from None


def _merge_materials(
    fingerprint: str,
    materials: list[_CandidateMaterial],
    limits: NormalizationLimits,
) -> DiscoveryCandidate:
    identity = {
        (material.tenant_id, material.head_sha, material.schema_version) for material in materials
    }
    if len(identity) != 1 or any(material.fingerprint != fingerprint for material in materials):
        raise NormalizationError(NormalizationErrorCode.INTEGRITY_FAILURE)
    tenant_id, head_sha, schema_version = next(iter(identity))
    lineages = _merged_lineages(materials)
    if not lineages:
        raise NormalizationError(NormalizationErrorCode.INTEGRITY_FAILURE)
    if len(lineages) > limits.max_lineages_per_candidate:
        raise NormalizationError(NormalizationErrorCode.RESOURCE_LIMIT)
    lanes = {lineage.lane for lineage in lineages}
    origin = _origin_for_lanes(lanes)
    evidence_ids = tuple(
        sorted(
            {evidence_id for material in materials for evidence_id in material.evidence_ids}
            | {
                evidence_id
                for material in materials
                for lineage in material.lineages
                for evidence_id in lineage.evidence_ids
            }
        )
    )
    extensions = _merged_extensions(materials)
    command_operation_evidence = _merged_command_operation_evidence(materials)
    try:
        return DiscoveryCandidate(
            schema_version=schema_version,
            extensions=extensions,
            candidate_id=_CANDIDATE_ID_PREFIX + fingerprint,
            tenant_id=tenant_id,
            candidate_version=max(material.candidate_version for material in materials),
            head_sha=head_sha,
            root_cause_fingerprint=fingerprint,
            candidate_origin=origin,
            lineage=lineages,
            evidence_ids=evidence_ids,
            command_operation_evidence=command_operation_evidence,
        )
    except (AttributeError, TypeError, ValueError, RecursionError):
        raise NormalizationError(NormalizationErrorCode.INTEGRITY_FAILURE) from None


def _merged_lineages(materials: list[_CandidateMaterial]) -> tuple[LineageRef, ...]:
    lineages_by_id: dict[str, LineageRef] = {}
    for material in materials:
        for lineage in material.lineages:
            if lineage.root_cause_fingerprint != material.fingerprint:
                raise NormalizationError(NormalizationErrorCode.INTEGRITY_FAILURE)
            previous = lineages_by_id.get(lineage.lineage_id)
            if previous is not None and previous != lineage:
                raise NormalizationError(NormalizationErrorCode.INTEGRITY_FAILURE)
            lineages_by_id[lineage.lineage_id] = lineage
    return tuple(
        sorted(
            lineages_by_id.values(),
            key=lambda item: (
                item.lane.value,
                item.producer.producer_id,
                item.producer.producer_version,
                item.producer.producer_sha256,
                item.lineage_id,
            ),
        )
    )


def _merged_extensions(materials: list[_CandidateMaterial]) -> tuple[ContractExtension, ...]:
    extensions_by_namespace: dict[str, ContractExtension] = {}
    for material in materials:
        for extension in material.extensions:
            previous = extensions_by_namespace.get(extension.namespace)
            if previous is not None and previous != extension:
                raise NormalizationError(NormalizationErrorCode.INTEGRITY_FAILURE)
            extensions_by_namespace[extension.namespace] = extension
    return tuple(extension for _, extension in sorted(extensions_by_namespace.items()))


def _merged_command_operation_evidence(
    materials: list[_CandidateMaterial],
) -> tuple[CommandOperationEvidence, ...]:
    evidence_by_signal: dict[str, CommandOperationEvidence] = {}
    for material in materials:
        for evidence in material.command_operation_evidence:
            previous = evidence_by_signal.get(evidence.scanner_signal_id)
            if previous is not None and previous != evidence:
                raise NormalizationError(NormalizationErrorCode.INTEGRITY_FAILURE)
            evidence_by_signal[evidence.scanner_signal_id] = evidence
    return tuple(evidence_by_signal[key] for key in sorted(evidence_by_signal))


def _origin_for_lanes(lanes: set[DiscoveryLane]) -> CandidateOrigin:
    if lanes == {DiscoveryLane.DETERMINISTIC}:
        return CandidateOrigin.DETERMINISTIC
    if lanes == {DiscoveryLane.MODEL_NATIVE}:
        return CandidateOrigin.MODEL_NATIVE
    if lanes == {DiscoveryLane.DETERMINISTIC, DiscoveryLane.MODEL_NATIVE}:
        return CandidateOrigin.HYBRID
    raise NormalizationError(NormalizationErrorCode.INTEGRITY_FAILURE)


def _producer_material(producer: ProducerRef) -> dict[str, str]:
    return {
        "producer_id": producer.producer_id,
        "producer_sha256": producer.producer_sha256,
        "producer_version": producer.producer_version,
    }


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


__all__ = [
    "DEFAULT_NORMALIZATION_LIMITS",
    "NormalizationError",
    "NormalizationErrorCode",
    "NormalizationLimits",
    "normalize_raw_signal",
    "normalize_signals",
    "root_cause_fingerprint",
    "root_cause_location_fingerprint",
]
