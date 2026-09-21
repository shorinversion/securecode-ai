"""Versioned, fail-closed comparison of normalized finding fingerprints."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from securecode_ai.contracts import DiscoveryCandidate

BASELINE_FINGERPRINT_SCHEMA_VERSION: Final = "1.0.0"
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_FINGERPRINT: Final = re.compile(r"[0-9a-f]{64}\Z")
_MAX_FINDINGS: Final = 100_000


class BaselineFingerprintErrorCode(StrEnum):
    """Closed failure codes for metadata-only baseline comparison."""

    INVALID_INPUT = "INVALID_INPUT"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    STALE_HEAD = "STALE_HEAD"
    DUPLICATE_FINGERPRINT = "DUPLICATE_FINGERPRINT"
    UNKNOWN_LINEAGE = "UNKNOWN_LINEAGE"


class BaselineFingerprintError(ValueError):
    """Boundary failure that intentionally never echoes finding metadata."""

    __slots__ = ("code",)

    def __init__(self, code: BaselineFingerprintErrorCode) -> None:
        if type(code) is not BaselineFingerprintErrorCode:
            raise TypeError("baseline fingerprint error code is invalid")
        self.code = code
        super().__init__("baseline fingerprint comparison failed")
        self.__cause__ = None
        self.__context__ = None


class BaselineFindingRelation(StrEnum):
    """Stable relation of a head finding to the exact baseline."""

    LEGACY = "LEGACY"
    NEW = "NEW"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class BaselineFingerprintSnapshot:
    """One exact revision's P2.9-normalized finding metadata."""

    schema_version: str
    tenant_id: str
    revision_sha: str
    findings: tuple[DiscoveryCandidate, ...]

    def __post_init__(self) -> None:
        _validate_snapshot_shape(self)
        validated = tuple(_validated_candidate(item) for item in self.findings)
        if len(validated) > _MAX_FINDINGS:
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
        if any(item.tenant_id != self.tenant_id for item in validated):
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.IDENTITY_MISMATCH)
        if any(item.head_sha != self.revision_sha for item in validated):
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.IDENTITY_MISMATCH)
        object.__setattr__(
            self,
            "findings",
            tuple(sorted(validated, key=lambda item: item.root_cause_fingerprint)),
        )


@dataclass(frozen=True, slots=True)
class BaselineFingerprintComparison:
    """Source-free exact base/head comparison consumed by later policy code."""

    schema_version: str
    tenant_id: str
    base_sha: str
    head_sha: str
    baseline_fingerprints: tuple[str, ...]
    head_fingerprints: tuple[str, ...]
    new_fingerprints: tuple[str, ...]

    def relation_for(self, fingerprint: str) -> BaselineFindingRelation:
        """Classify only a normalized fingerprint present at this exact head."""

        if type(fingerprint) is not str or _FINGERPRINT.fullmatch(fingerprint) is None:
            return BaselineFindingRelation.UNKNOWN
        if fingerprint not in self.head_fingerprints:
            return BaselineFindingRelation.UNKNOWN
        if fingerprint in self.new_fingerprints:
            return BaselineFindingRelation.NEW
        return BaselineFindingRelation.LEGACY


def compare_baseline_fingerprints(
    *,
    baseline: BaselineFingerprintSnapshot,
    head: BaselineFingerprintSnapshot,
    current_head_sha: str,
    commit_lineage: tuple[str, ...],
) -> BaselineFingerprintComparison:
    """Compare P2.9 fingerprints on a trusted, exact ``base -> head`` lineage.

    The SCM adapter supplies a verified lineage and current head. Any ref move,
    missing ancestry proof, duplicate fingerprint, or invalid normalized candidate
    refuses classification rather than treating a finding as legacy or new.
    """

    if (
        type(baseline) is not BaselineFingerprintSnapshot
        or type(head) is not BaselineFingerprintSnapshot
    ):
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
    if type(current_head_sha) is not str or _COMMIT_SHA.fullmatch(current_head_sha) is None:
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
    if baseline.tenant_id != head.tenant_id:
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.IDENTITY_MISMATCH)
    if current_head_sha != head.revision_sha:
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.STALE_HEAD)
    _validate_commit_lineage(
        commit_lineage,
        base_sha=baseline.revision_sha,
        head_sha=head.revision_sha,
    )

    baseline_fingerprints = _unique_fingerprints(baseline.findings)
    head_fingerprints = _unique_fingerprints(head.findings)
    baseline_set = set(baseline_fingerprints)
    new_fingerprints = tuple(
        fingerprint for fingerprint in head_fingerprints if fingerprint not in baseline_set
    )
    return BaselineFingerprintComparison(
        schema_version=BASELINE_FINGERPRINT_SCHEMA_VERSION,
        tenant_id=head.tenant_id,
        base_sha=baseline.revision_sha,
        head_sha=head.revision_sha,
        baseline_fingerprints=baseline_fingerprints,
        head_fingerprints=head_fingerprints,
        new_fingerprints=new_fingerprints,
    )


def _validate_snapshot_shape(snapshot: BaselineFingerprintSnapshot) -> None:
    if (
        type(snapshot.schema_version) is not str
        or snapshot.schema_version != BASELINE_FINGERPRINT_SCHEMA_VERSION
        or type(snapshot.tenant_id) is not str
        or not snapshot.tenant_id
        or type(snapshot.revision_sha) is not str
        or _COMMIT_SHA.fullmatch(snapshot.revision_sha) is None
        or type(snapshot.findings) is not tuple
    ):
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)


def _validated_candidate(candidate: DiscoveryCandidate) -> DiscoveryCandidate:
    if type(candidate) is not DiscoveryCandidate:
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
    try:
        validated = DiscoveryCandidate.model_validate(candidate.model_dump(mode="python"))
    except (TypeError, ValueError):
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.UNKNOWN_LINEAGE) from None
    if not validated.lineage or any(
        item.root_cause_fingerprint != validated.root_cause_fingerprint
        for item in validated.lineage
    ):
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.UNKNOWN_LINEAGE)
    return validated


def _validate_commit_lineage(
    lineage: tuple[str, ...],
    *,
    base_sha: str,
    head_sha: str,
) -> None:
    if type(lineage) is not tuple or not lineage:
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.UNKNOWN_LINEAGE)
    if (
        any(type(commit) is not str or _COMMIT_SHA.fullmatch(commit) is None for commit in lineage)
        or len(lineage) != len(set(lineage))
        or lineage[0] != base_sha
        or lineage[-1] != head_sha
    ):
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.UNKNOWN_LINEAGE)
    if base_sha == head_sha and lineage != (base_sha,):
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.UNKNOWN_LINEAGE)
    if base_sha != head_sha and len(lineage) < 2:
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.UNKNOWN_LINEAGE)


def _unique_fingerprints(findings: tuple[DiscoveryCandidate, ...]) -> tuple[str, ...]:
    fingerprints: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        fingerprint = finding.root_cause_fingerprint
        if fingerprint in seen:
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.DUPLICATE_FINGERPRINT)
        seen.add(fingerprint)
        fingerprints.append(fingerprint)
    return tuple(sorted(fingerprints))


__all__ = [
    "BASELINE_FINGERPRINT_SCHEMA_VERSION",
    "BaselineFindingRelation",
    "BaselineFingerprintComparison",
    "BaselineFingerprintError",
    "BaselineFingerprintErrorCode",
    "BaselineFingerprintSnapshot",
    "compare_baseline_fingerprints",
]
