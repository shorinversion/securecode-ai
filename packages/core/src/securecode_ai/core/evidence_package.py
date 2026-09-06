"""Bounded, provenance-preserving context selection for Auditor work.

This module deliberately selects metadata-only ``ArtifactRef`` values.  Reading
the referenced bytes, deciding egress, and invoking a model are owned by later
ports; an ``EvidencePackage`` cannot provide any of those capabilities.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    DataClass,
    DiscoveryCandidate,
    Evidence,
    EvidenceInputRef,
)

from .evidence_graph import EvidenceGraph

_MAX_CONTEXT_BYTES = 64 * 1024 * 1024
_MAX_INPUT_TOKENS = 4_000_000
_MAX_EVIDENCE_ITEMS = 4_096


class EvidencePackageErrorCode(StrEnum):
    """Closed, source-free reasons why context cannot be assembled."""

    REQUEST_INVALID = "REQUEST_INVALID"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    EVIDENCE_UNAVAILABLE = "EVIDENCE_UNAVAILABLE"
    FORBIDDEN_DATA_CLASS = "FORBIDDEN_DATA_CLASS"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EvidencePackageError(RuntimeError):
    """A fixed boundary error that never echoes candidate or evidence content."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: EvidencePackageErrorCode) -> None:
        if type(code) is not EvidencePackageErrorCode:
            raise TypeError("evidence package error code is invalid")
        self.code = code
        self.safe_message = "evidence context selection failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EvidencePackageLimits:
    """Host-owned hard ceilings for one candidate's selected context."""

    max_context_bytes: int = 65_536
    max_input_tokens: int = 16_384
    max_evidence_items: int = 128

    def __post_init__(self) -> None:
        values = (self.max_context_bytes, self.max_input_tokens, self.max_evidence_items)
        ceilings = (_MAX_CONTEXT_BYTES, _MAX_INPUT_TOKENS, _MAX_EVIDENCE_ITEMS)
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, ceilings, strict=True)
        ):
            raise ValueError("evidence package limits are invalid")


DEFAULT_EVIDENCE_PACKAGE_LIMITS = EvidencePackageLimits()


@dataclass(frozen=True, slots=True)
class EvidenceContextRef:
    """One selected, source-free content reference and its immutable provenance."""

    evidence_id: str
    content_id: str
    data_class: DataClass
    evidence_sha256: str
    producer_id: str
    producer_version: str
    producer_sha256: str
    context_bytes: int
    estimated_tokens: int

    def __post_init__(self) -> None:
        if (
            type(self.evidence_id) is not str
            or not self.evidence_id
            or type(self.content_id) is not str
            or not self.content_id
            or type(self.data_class) is not DataClass
            or self.data_class is DataClass.RESTRICTED
            or any(
                type(value) is not str or len(value) != 64
                for value in (self.evidence_sha256, self.producer_sha256)
            )
            or any(character not in "0123456789abcdef" for character in self.evidence_sha256)
            or any(character not in "0123456789abcdef" for character in self.producer_sha256)
            or type(self.producer_id) is not str
            or not self.producer_id
            or type(self.producer_version) is not str
            or not self.producer_version
            or type(self.context_bytes) is not int
            or self.context_bytes < 0
            or type(self.estimated_tokens) is not int
            or self.estimated_tokens < 1
        ):
            raise ValueError("evidence context reference is invalid")

    def as_model_input(self) -> EvidenceInputRef:
        """Return the existing public metadata-only evidence reference."""

        return EvidenceInputRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            evidence_id=self.evidence_id,
            content_id=self.content_id,
            data_class=self.data_class,
        )


@dataclass(frozen=True, slots=True)
class EvidencePackage:
    """Immutable selected context for exactly one candidate and graph revision."""

    candidate_id: str
    candidate_version: int
    tenant_id: str
    head_sha: str
    graph_id: str
    graph_sha256: str
    selection_sha256: str
    selected: tuple[EvidenceContextRef, ...]
    omitted_evidence_ids: tuple[str, ...]
    total_context_bytes: int
    total_input_tokens: int
    truncated: bool

    def __post_init__(self) -> None:
        selected_ids = tuple(item.evidence_id for item in self.selected)
        all_ids = (*selected_ids, *self.omitted_evidence_ids)
        if (
            any(
                type(value) is not str or not value for value in (self.candidate_id, self.tenant_id)
            )
            or type(self.candidate_version) is not int
            or self.candidate_version < 1
            or type(self.head_sha) is not str
            or len(self.head_sha) != 40
            or type(self.graph_id) is not str
            or not self.graph_id
            or any(
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
                for value in (self.graph_sha256, self.selection_sha256)
            )
            or type(self.selected) is not tuple
            or not self.selected
            or any(type(item) is not EvidenceContextRef for item in self.selected)
            or selected_ids != tuple(sorted(selected_ids))
            or self.omitted_evidence_ids != tuple(sorted(self.omitted_evidence_ids))
            or len(all_ids) != len(set(all_ids))
            or type(self.total_context_bytes) is not int
            or self.total_context_bytes != sum(item.context_bytes for item in self.selected)
            or type(self.total_input_tokens) is not int
            or self.total_input_tokens != sum(item.estimated_tokens for item in self.selected)
            or type(self.truncated) is not bool
            or self.truncated != bool(self.omitted_evidence_ids)
        ):
            raise ValueError("evidence package is invalid")

    @property
    def model_evidence(self) -> tuple[EvidenceInputRef, ...]:
        """Yield canonical existing model-contract references, not source content."""

        return tuple(item.as_model_input() for item in self.selected)


def build_evidence_package(
    graph: EvidenceGraph,
    candidate_id: str,
    *,
    limits: EvidencePackageLimits = DEFAULT_EVIDENCE_PACKAGE_LIMITS,
) -> EvidencePackage:
    """Select deterministic admissible evidence for one graph candidate.

    Candidate evidence is considered in canonical evidence-ID order.  Oversized
    entries are omitted rather than partially represented; the result records
    every omission.  A package with no admissible selected reference is a typed
    failure, never an implicit empty Auditor context.
    """

    if (
        type(graph) is not EvidenceGraph
        or type(candidate_id) is not str
        or not candidate_id
        or type(limits) is not EvidencePackageLimits
    ):
        raise EvidencePackageError(EvidencePackageErrorCode.REQUEST_INVALID)
    candidate = _candidate_for(graph, candidate_id)
    evidence_by_id = {item.evidence_id: item for item in graph.evidence}
    selected: list[EvidenceContextRef] = []
    omitted: list[str] = []
    total_bytes = 0
    total_tokens = 0

    for evidence_id in sorted(candidate.evidence_ids):
        evidence = evidence_by_id.get(evidence_id)
        if evidence is None:
            raise EvidencePackageError(EvidencePackageErrorCode.INTEGRITY_FAILURE)
        reference = _context_ref_for(evidence, graph)
        if (
            len(selected) >= limits.max_evidence_items
            or total_bytes + reference.context_bytes > limits.max_context_bytes
            or total_tokens + reference.estimated_tokens > limits.max_input_tokens
        ):
            omitted.append(evidence_id)
            continue
        selected.append(reference)
        total_bytes += reference.context_bytes
        total_tokens += reference.estimated_tokens

    if not selected:
        raise EvidencePackageError(EvidencePackageErrorCode.BUDGET_EXHAUSTED)
    selected_tuple = tuple(selected)
    omitted_tuple = tuple(omitted)
    selection_sha256 = _selection_sha256(
        graph=graph,
        candidate=candidate,
        selected=selected_tuple,
        omitted=omitted_tuple,
        limits=limits,
    )
    return EvidencePackage(
        candidate_id=candidate.candidate_id,
        candidate_version=candidate.candidate_version,
        tenant_id=candidate.tenant_id,
        head_sha=candidate.head_sha,
        graph_id=graph.graph_id,
        graph_sha256=graph.graph_sha256,
        selection_sha256=selection_sha256,
        selected=selected_tuple,
        omitted_evidence_ids=omitted_tuple,
        total_context_bytes=total_bytes,
        total_input_tokens=total_tokens,
        truncated=bool(omitted_tuple),
    )


def _candidate_for(graph: EvidenceGraph, candidate_id: str) -> DiscoveryCandidate:
    candidate = next((item for item in graph.candidates if item.candidate_id == candidate_id), None)
    if candidate is None:
        raise EvidencePackageError(EvidencePackageErrorCode.EVIDENCE_UNAVAILABLE)
    if candidate.tenant_id != graph.tenant_id or candidate.head_sha != graph.head_sha:
        raise EvidencePackageError(EvidencePackageErrorCode.IDENTITY_MISMATCH)
    return candidate


def _context_ref_for(evidence: Evidence, graph: EvidenceGraph) -> EvidenceContextRef:
    if evidence.tenant_id != graph.tenant_id or evidence.head_sha != graph.head_sha:
        raise EvidencePackageError(EvidencePackageErrorCode.IDENTITY_MISMATCH)
    if evidence.data_class is DataClass.RESTRICTED:
        raise EvidencePackageError(EvidencePackageErrorCode.FORBIDDEN_DATA_CLASS)
    artifact = evidence.artifact_ref
    if artifact is None:
        raise EvidencePackageError(EvidencePackageErrorCode.EVIDENCE_UNAVAILABLE)
    if artifact.tenant_id != evidence.tenant_id or artifact.data_class is not evidence.data_class:
        raise EvidencePackageError(EvidencePackageErrorCode.INTEGRITY_FAILURE)
    return EvidenceContextRef(
        evidence_id=evidence.evidence_id,
        content_id=artifact.content_id,
        data_class=evidence.data_class,
        evidence_sha256=evidence.evidence_sha256,
        producer_id=evidence.producer.producer_id,
        producer_version=evidence.producer.producer_version,
        producer_sha256=evidence.producer.producer_sha256,
        context_bytes=artifact.size_bytes,
        estimated_tokens=max(1, (artifact.size_bytes + 3) // 4),
    )


def _selection_sha256(
    *,
    graph: EvidenceGraph,
    candidate: DiscoveryCandidate,
    selected: tuple[EvidenceContextRef, ...],
    omitted: tuple[str, ...],
    limits: EvidencePackageLimits,
) -> str:
    payload = {
        "candidate_id": candidate.candidate_id,
        "candidate_version": candidate.candidate_version,
        "graph_id": graph.graph_id,
        "graph_sha256": graph.graph_sha256,
        "head_sha": candidate.head_sha,
        "limits": {
            "max_context_bytes": limits.max_context_bytes,
            "max_evidence_items": limits.max_evidence_items,
            "max_input_tokens": limits.max_input_tokens,
        },
        "omitted_evidence_ids": list(omitted),
        "selected": [
            {
                "content_id": item.content_id,
                "context_bytes": item.context_bytes,
                "data_class": item.data_class.value,
                "evidence_id": item.evidence_id,
                "evidence_sha256": item.evidence_sha256,
                "estimated_tokens": item.estimated_tokens,
                "producer_id": item.producer_id,
                "producer_sha256": item.producer_sha256,
                "producer_version": item.producer_version,
            }
            for item in selected
        ],
        "tenant_id": candidate.tenant_id,
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


__all__ = [
    "DEFAULT_EVIDENCE_PACKAGE_LIMITS",
    "EvidenceContextRef",
    "EvidencePackage",
    "EvidencePackageError",
    "EvidencePackageErrorCode",
    "EvidencePackageLimits",
    "build_evidence_package",
]
