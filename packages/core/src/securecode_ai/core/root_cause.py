"""Fail-closed, metadata-only root-cause localization for confirmed findings.

The localizer never reads repository content.  It accepts only the existing
``FindingCase`` and ``EvidenceGraph`` contract values plus three graph-local
evidence identifiers: attacker-controlled source, propagation, and sensitive
sink.  A result is confirming only when all identities, graph bindings, and
causal evidence roles agree.  Surface locations alone are intentionally not a
root-cause record.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from securecode_ai.contracts import EvidenceKind, FindingCase, FindingVerdict

from .evidence_graph import EvidenceGraph

_SCHEMA_VERSION: Final = "1.0.0"
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")


class RootCauseContractError(ValueError):
    """Safe boundary error for malformed retained contract values."""

    def __init__(self) -> None:
        super().__init__("root-cause localization contract validation failed")
        self.__cause__ = None
        self.__context__ = None


class RootCauseLocalizationStatus(StrEnum):
    """The localizer never converts insufficient evidence into confirmation."""

    CONFIRMED = "CONFIRMED"
    NON_CONFIRMING = "NON_CONFIRMING"


class RootCauseLocalizationReason(StrEnum):
    """Closed reasons which do not echo repository or model content."""

    CONFIRMED = "CONFIRMED"
    FINDING_NOT_CONFIRMED = "FINDING_NOT_CONFIRMED"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    GRAPH_MISMATCH = "GRAPH_MISMATCH"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"
    EVIDENCE_OUT_OF_SCOPE = "EVIDENCE_OUT_OF_SCOPE"
    EVIDENCE_KIND_MISMATCH = "EVIDENCE_KIND_MISMATCH"
    EVIDENCE_LOCATION_MISSING = "EVIDENCE_LOCATION_MISSING"
    CAUSAL_ROLE_CONFLICT = "CAUSAL_ROLE_CONFLICT"


@dataclass(frozen=True, slots=True)
class RootCauseEvidenceRefs:
    """Three distinct evidence references composing one causal explanation."""

    source_evidence_id: str
    propagation_evidence_id: str
    sink_evidence_id: str

    def __post_init__(self) -> None:
        values = (
            self.source_evidence_id,
            self.propagation_evidence_id,
            self.sink_evidence_id,
        )
        if any(type(value) is not str or _ID.fullmatch(value) is None for value in values):
            raise RootCauseContractError()
        if len(set(values)) != len(values):
            raise RootCauseContractError()


@dataclass(frozen=True, slots=True)
class RootCauseRecord:
    """Immutable source-free localization bound to exactly one finding revision."""

    record_id: str
    schema_version: str
    finding_id: str
    candidate_id: str
    candidate_version: int
    tenant_id: str
    repository_id: str
    head_sha: str
    root_cause_fingerprint: str
    evidence_graph_id: str
    evidence_graph_sha256: str
    evidence: RootCauseEvidenceRefs

    def __post_init__(self) -> None:
        identifiers = (
            self.record_id,
            self.finding_id,
            self.candidate_id,
            self.tenant_id,
            self.repository_id,
            self.evidence_graph_id,
        )
        if (
            self.schema_version != _SCHEMA_VERSION
            or any(type(value) is not str or _ID.fullmatch(value) is None for value in identifiers)
            or type(self.candidate_version) is not int
            or self.candidate_version < 1
            or type(self.head_sha) is not str
            or _COMMIT_SHA.fullmatch(self.head_sha) is None
            or any(
                type(value) is not str or _SHA256.fullmatch(value) is None
                for value in (self.root_cause_fingerprint, self.evidence_graph_sha256)
            )
            or type(self.evidence) is not RootCauseEvidenceRefs
            or self.record_id
            != _record_id(
                finding_id=self.finding_id,
                candidate_id=self.candidate_id,
                candidate_version=self.candidate_version,
                tenant_id=self.tenant_id,
                repository_id=self.repository_id,
                head_sha=self.head_sha,
                root_cause_fingerprint=self.root_cause_fingerprint,
                evidence_graph_id=self.evidence_graph_id,
                evidence_graph_sha256=self.evidence_graph_sha256,
                evidence=self.evidence,
            )
        ):
            raise RootCauseContractError()


@dataclass(frozen=True, slots=True)
class RootCauseLocalizationReceipt:
    """Deterministic receipt for a localization attempt, never source content."""

    finding_id: str
    candidate_id: str
    candidate_version: int
    tenant_id: str
    repository_id: str
    head_sha: str
    root_cause_fingerprint: str
    evidence_graph_id: str
    evidence_graph_sha256: str
    status: RootCauseLocalizationStatus
    reason: RootCauseLocalizationReason
    record: RootCauseRecord | None

    def __post_init__(self) -> None:
        identifiers = (
            self.finding_id,
            self.candidate_id,
            self.tenant_id,
            self.repository_id,
            self.evidence_graph_id,
        )
        if (
            any(type(value) is not str or _ID.fullmatch(value) is None for value in identifiers)
            or type(self.candidate_version) is not int
            or self.candidate_version < 1
            or type(self.head_sha) is not str
            or _COMMIT_SHA.fullmatch(self.head_sha) is None
            or any(
                type(value) is not str or _SHA256.fullmatch(value) is None
                for value in (self.root_cause_fingerprint, self.evidence_graph_sha256)
            )
            or type(self.status) is not RootCauseLocalizationStatus
            or type(self.reason) is not RootCauseLocalizationReason
            or (self.status is RootCauseLocalizationStatus.CONFIRMED)
            != (self.reason is RootCauseLocalizationReason.CONFIRMED)
            or (self.status is RootCauseLocalizationStatus.CONFIRMED) != (self.record is not None)
        ):
            raise RootCauseContractError()
        if self.record is not None and (
            type(self.record) is not RootCauseRecord
            or (
                self.record.finding_id,
                self.record.candidate_id,
                self.record.candidate_version,
                self.record.tenant_id,
                self.record.repository_id,
                self.record.head_sha,
                self.record.root_cause_fingerprint,
                self.record.evidence_graph_id,
                self.record.evidence_graph_sha256,
            )
            != (
                self.finding_id,
                self.candidate_id,
                self.candidate_version,
                self.tenant_id,
                self.repository_id,
                self.head_sha,
                self.root_cause_fingerprint,
                self.evidence_graph_id,
                self.evidence_graph_sha256,
            )
        ):
            raise RootCauseContractError()


def localize_root_cause(
    finding: FindingCase,
    graph: EvidenceGraph,
    evidence: RootCauseEvidenceRefs,
) -> RootCauseLocalizationReceipt:
    """Localize a confirmed finding only when a complete causal chain is proven.

    The three references are metadata-only graph nodes.  ``source`` and ``sink``
    require distinct source-location evidence, while ``propagation`` requires a
    data-flow evidence node.  Any absent, conflicting, or cross-scope evidence
    returns a non-confirming receipt rather than a root-cause record.
    """

    copied_finding = _copy_finding(finding)
    copied_graph = _copy_graph(graph)
    if type(evidence) is not RootCauseEvidenceRefs:
        raise RootCauseContractError()

    receipt_identity = _receipt_identity(copied_finding, copied_graph)
    if copied_finding.finding_verdict is not FindingVerdict.CONFIRMED:
        return _non_confirming(receipt_identity, RootCauseLocalizationReason.FINDING_NOT_CONFIRMED)
    if not _matching_graph_identity(copied_finding, copied_graph):
        return _non_confirming(receipt_identity, RootCauseLocalizationReason.GRAPH_MISMATCH)

    candidate = next(
        (
            item
            for item in copied_graph.candidates
            if item.candidate_id == copied_finding.candidate_id
        ),
        None,
    )
    if candidate is None or (
        candidate.candidate_version != copied_finding.candidate_version
        or candidate.root_cause_fingerprint != copied_finding.root_cause_fingerprint
        or candidate.tenant_id != copied_finding.repository_revision.tenant_id
        or candidate.head_sha != copied_finding.repository_revision.head_sha
    ):
        return _non_confirming(receipt_identity, RootCauseLocalizationReason.IDENTITY_MISMATCH)

    evidence_by_id = {item.evidence_id: item for item in copied_graph.evidence}
    requested_ids = {
        evidence.source_evidence_id,
        evidence.propagation_evidence_id,
        evidence.sink_evidence_id,
    }
    if not requested_ids.issubset(evidence_by_id):
        return _non_confirming(receipt_identity, RootCauseLocalizationReason.EVIDENCE_MISSING)
    if not requested_ids.issubset(set(copied_finding.evidence_ids)) or not requested_ids.issubset(
        set(candidate.evidence_ids)
    ):
        return _non_confirming(receipt_identity, RootCauseLocalizationReason.EVIDENCE_OUT_OF_SCOPE)

    source = evidence_by_id[evidence.source_evidence_id]
    propagation = evidence_by_id[evidence.propagation_evidence_id]
    sink = evidence_by_id[evidence.sink_evidence_id]
    if (
        source.evidence_kind is not EvidenceKind.SOURCE_LOCATION
        or propagation.evidence_kind is not EvidenceKind.DATA_FLOW
        or sink.evidence_kind is not EvidenceKind.SOURCE_LOCATION
    ):
        return _non_confirming(
            receipt_identity,
            RootCauseLocalizationReason.EVIDENCE_KIND_MISMATCH,
        )
    if source.location is None or sink.location is None:
        return _non_confirming(
            receipt_identity,
            RootCauseLocalizationReason.EVIDENCE_LOCATION_MISSING,
        )
    if source.location == sink.location:
        return _non_confirming(receipt_identity, RootCauseLocalizationReason.CAUSAL_ROLE_CONFLICT)

    record = RootCauseRecord(
        record_id=_record_id(
            finding_id=copied_finding.finding_id,
            candidate_id=copied_finding.candidate_id,
            candidate_version=copied_finding.candidate_version,
            tenant_id=copied_finding.repository_revision.tenant_id,
            repository_id=copied_finding.repository_revision.repository_id,
            head_sha=copied_finding.repository_revision.head_sha,
            root_cause_fingerprint=copied_finding.root_cause_fingerprint,
            evidence_graph_id=copied_graph.graph_id,
            evidence_graph_sha256=copied_graph.graph_sha256,
            evidence=evidence,
        ),
        schema_version=_SCHEMA_VERSION,
        finding_id=copied_finding.finding_id,
        candidate_id=copied_finding.candidate_id,
        candidate_version=copied_finding.candidate_version,
        tenant_id=copied_finding.repository_revision.tenant_id,
        repository_id=copied_finding.repository_revision.repository_id,
        head_sha=copied_finding.repository_revision.head_sha,
        root_cause_fingerprint=copied_finding.root_cause_fingerprint,
        evidence_graph_id=copied_graph.graph_id,
        evidence_graph_sha256=copied_graph.graph_sha256,
        evidence=evidence,
    )
    return RootCauseLocalizationReceipt(
        *receipt_identity,
        RootCauseLocalizationStatus.CONFIRMED,
        RootCauseLocalizationReason.CONFIRMED,
        record,
    )


def _copy_finding(finding: FindingCase) -> FindingCase:
    if type(finding) is not FindingCase:
        raise RootCauseContractError()
    try:
        return FindingCase.model_validate(finding.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError):
        raise RootCauseContractError() from None


def _copy_graph(graph: EvidenceGraph) -> EvidenceGraph:
    if type(graph) is not EvidenceGraph:
        raise RootCauseContractError()
    try:
        return EvidenceGraph(
            graph_id=graph.graph_id,
            tenant_id=graph.tenant_id,
            head_sha=graph.head_sha,
            candidates=graph.candidates,
            evidence=graph.evidence,
            edges=graph.edges,
            schema_version=graph.schema_version,
        )
    except (AttributeError, TypeError, ValueError):
        raise RootCauseContractError() from None


def _receipt_identity(
    finding: FindingCase, graph: EvidenceGraph
) -> tuple[str, str, int, str, str, str, str, str, str]:
    revision = finding.repository_revision
    return (
        finding.finding_id,
        finding.candidate_id,
        finding.candidate_version,
        revision.tenant_id,
        revision.repository_id,
        revision.head_sha,
        finding.root_cause_fingerprint,
        graph.graph_id,
        graph.graph_sha256,
    )


def _matching_graph_identity(finding: FindingCase, graph: EvidenceGraph) -> bool:
    revision = finding.repository_revision
    return (
        graph.tenant_id == revision.tenant_id
        and graph.head_sha == revision.head_sha
        and finding.evidence_graph_ref.content_id == graph.graph_id
        and finding.evidence_graph_ref.content_sha256 == graph.graph_sha256
    )


def _non_confirming(
    identity: tuple[str, str, int, str, str, str, str, str, str],
    reason: RootCauseLocalizationReason,
) -> RootCauseLocalizationReceipt:
    return RootCauseLocalizationReceipt(
        *identity,
        RootCauseLocalizationStatus.NON_CONFIRMING,
        reason,
        None,
    )


def _record_id(
    *,
    finding_id: str,
    candidate_id: str,
    candidate_version: int,
    tenant_id: str,
    repository_id: str,
    head_sha: str,
    root_cause_fingerprint: str,
    evidence_graph_id: str,
    evidence_graph_sha256: str,
    evidence: RootCauseEvidenceRefs,
) -> str:
    material = {
        "candidate_id": candidate_id,
        "candidate_version": candidate_version,
        "evidence": {
            "propagation_evidence_id": evidence.propagation_evidence_id,
            "sink_evidence_id": evidence.sink_evidence_id,
            "source_evidence_id": evidence.source_evidence_id,
        },
        "evidence_graph_id": evidence_graph_id,
        "evidence_graph_sha256": evidence_graph_sha256,
        "finding_id": finding_id,
        "head_sha": head_sha,
        "repository_id": repository_id,
        "root_cause_fingerprint": root_cause_fingerprint,
        "schema_version": _SCHEMA_VERSION,
        "tenant_id": tenant_id,
    }
    digest = hashlib.sha256(
        json.dumps(
            material,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()
    return f"root-cause-{digest}"


__all__ = [
    "RootCauseContractError",
    "RootCauseEvidenceRefs",
    "RootCauseLocalizationReason",
    "RootCauseLocalizationReceipt",
    "RootCauseLocalizationStatus",
    "RootCauseRecord",
    "localize_root_cause",
]
