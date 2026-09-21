"""Governed synthetic security case candidates and private source artifact storage."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final

from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION, ArtifactRef, DataClass

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH: Final = re.compile(r"[0-9a-f]{64}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/synthetic-case/v1\x00"
MAX_SYNTHETIC_SOURCE_BYTES: Final = 65_536


class SyntheticCaseError(ValueError):
    """Safe synthetic-case error that never contains source bytes."""

    def __init__(self) -> None:
        super().__init__("Synthetic case request was rejected")
        self.__cause__ = None
        self.__context__ = None


class SyntheticCaseKind(StrEnum):
    VULNERABLE = "VULNERABLE"
    FIXED_SAFE = "FIXED_SAFE"


class SyntheticCaseState(StrEnum):
    CANDIDATE = "CANDIDATE"
    ADMITTED = "ADMITTED"


class SyntheticCandidateDisposition(StrEnum):
    CREATED = "CREATED"
    IDEMPOTENT = "IDEMPOTENT"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True, slots=True)
class SyntheticGeneratorProvenance:
    seed: int
    generator_id: str
    generator_version: str
    profile_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.seed) is not int
            or self.seed < 0
            or type(self.generator_id) is not str
            or _ID.fullmatch(self.generator_id) is None
            or type(self.generator_version) is not str
            or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.generator_version) is None
            or type(self.profile_sha256) is not str
            or _HASH.fullmatch(self.profile_sha256) is None
        ):
            raise SyntheticCaseError()


@dataclass(frozen=True, slots=True)
class SyntheticCaseCandidate:
    """Candidate-only case metadata with source bytes behind an artifact reference."""

    case_id: str
    tenant_id: str
    provenance: SyntheticGeneratorProvenance
    kind: SyntheticCaseKind
    language: str
    cwe_id: str
    label: str
    topology_sha256: str
    root_cause_sha256: str
    near_duplicate_group_sha256: str
    source_artifact: ArtifactRef
    state: SyntheticCaseState = SyntheticCaseState.CANDIDATE

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (self.case_id, self.tenant_id, self.language, self.cwe_id, self.label)
            )
            or type(self.provenance) is not SyntheticGeneratorProvenance
            or type(self.kind) is not SyntheticCaseKind
            or any(
                type(value) is not str or _HASH.fullmatch(value) is None
                for value in (
                    self.topology_sha256,
                    self.root_cause_sha256,
                    self.near_duplicate_group_sha256,
                )
            )
            or type(self.source_artifact) is not ArtifactRef
            or self.source_artifact.tenant_id != self.tenant_id
            or self.source_artifact.data_class is not DataClass.CONFIDENTIAL_SOURCE
            or type(self.state) is not SyntheticCaseState
            or self.state is not SyntheticCaseState.CANDIDATE
        ):
            raise SyntheticCaseError()


@dataclass(frozen=True, slots=True)
class SyntheticCandidateReceipt:
    disposition: SyntheticCandidateDisposition
    case_id: str
    source_sha256: str
    source_size_bytes: int
    state: SyntheticCaseState


class SyntheticArtifactStore:
    """Private content-addressed source store. Metadata never reveals source bytes."""

    __slots__ = ("_artifacts", "_lock")

    def __init__(self) -> None:
        self._artifacts: dict[str, bytes] = {}
        self._lock = RLock()

    def store_source(self, *, tenant_id: str, source: bytes) -> ArtifactRef:
        if (
            type(tenant_id) is not str
            or _ID.fullmatch(tenant_id) is None
            or type(source) is not bytes
            or not source
            or len(source) > MAX_SYNTHETIC_SOURCE_BYTES
        ):
            raise SyntheticCaseError()
        digest = hashlib.sha256(source).hexdigest()
        content_id = "synthetic-source-" + _artifact_key(tenant_id, digest)[:40]
        reference = ArtifactRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=tenant_id,
            content_id=content_id,
            content_sha256=digest,
            size_bytes=len(source),
            data_class=DataClass.CONFIDENTIAL_SOURCE,
        )
        with self._lock:
            existing = self._artifacts.get(content_id)
            if existing is not None and existing != source:
                raise SyntheticCaseError()
            self._artifacts[content_id] = bytes(source)
        return reference


class SyntheticCandidateStore:
    """Immutable candidate metadata store with deterministic replay behavior."""

    __slots__ = ("_candidates", "_lock")

    def __init__(self) -> None:
        self._candidates: dict[str, SyntheticCaseCandidate] = {}
        self._lock = RLock()

    def submit(self, candidate: SyntheticCaseCandidate) -> SyntheticCandidateReceipt:
        if type(candidate) is not SyntheticCaseCandidate:
            raise SyntheticCaseError()
        with self._lock:
            existing = self._candidates.get(candidate.case_id)
            if existing is None:
                self._candidates[candidate.case_id] = candidate
                disposition = SyntheticCandidateDisposition.CREATED
            elif existing == candidate:
                disposition = SyntheticCandidateDisposition.IDEMPOTENT
            else:
                disposition = SyntheticCandidateDisposition.CONFLICT
                candidate = existing
        return SyntheticCandidateReceipt(
            disposition,
            candidate.case_id,
            candidate.source_artifact.content_sha256,
            candidate.source_artifact.size_bytes,
            candidate.state,
        )

    def resolve(self, case_id: str) -> SyntheticCaseCandidate:
        if type(case_id) is not str or _ID.fullmatch(case_id) is None:
            raise SyntheticCaseError()
        with self._lock:
            try:
                return self._candidates[case_id]
            except KeyError:
                raise SyntheticCaseError() from None


def _artifact_key(tenant_id: str, digest: str) -> str:
    return hashlib.sha256(
        _HASH_DOMAIN + tenant_id.encode("ascii") + b"\x00" + digest.encode("ascii")
    ).hexdigest()


__all__ = [
    "MAX_SYNTHETIC_SOURCE_BYTES",
    "SyntheticArtifactStore",
    "SyntheticCandidateDisposition",
    "SyntheticCandidateReceipt",
    "SyntheticCandidateStore",
    "SyntheticCaseCandidate",
    "SyntheticCaseError",
    "SyntheticCaseKind",
    "SyntheticCaseState",
    "SyntheticGeneratorProvenance",
]
