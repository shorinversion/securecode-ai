"""Versioned, fail-closed comparison of normalized finding fingerprints."""

from __future__ import annotations

import re
import unicodedata
from bisect import bisect_left
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Final

from securecode_ai.contracts import DiscoveryCandidate

BASELINE_FINGERPRINT_SCHEMA_VERSION: Final = "1.0.0"
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_FINGERPRINT: Final = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MAX_FINDINGS: Final = 100_000
_MAX_SCOPE_LINES: Final = 100_000
_MAX_SCOPE_LOCATIONS: Final = 100_000
_MAX_LOCATIONS_PER_FINGERPRINT: Final = 4_096
_MAX_PATH_LENGTH: Final = 1_024
_UNSET: Final = object()


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
class BaselineChangedScope:
    """Trusted, source-free metadata proving a finding intersects changed code.

    ``changed_lines`` is the exact changed-line set for ``base_sha -> head_sha``.
    The two location indexes are keyed by the verified finding fingerprint. A
    finding is in scope when any finding or data-flow location intersects that
    exact changed-line set. No source text is retained here.
    """

    tenant_id: str
    base_sha: str
    head_sha: str
    changed_lines: tuple[tuple[str, int], ...]
    finding_locations: tuple[tuple[str, tuple[tuple[str, int, int], ...]], ...]
    data_flow_locations: tuple[tuple[str, tuple[tuple[str, int, int], ...]], ...] = ()
    _changed_lines_index: Mapping[str, tuple[int, ...]] = field(
        init=False, repr=False, compare=False
    )
    _locations_index: Mapping[str, tuple[tuple[str, int, int], ...]] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if (
            type(self.tenant_id) is not str
            or _IDENTIFIER.fullmatch(self.tenant_id) is None
            or type(self.base_sha) is not str
            or _COMMIT_SHA.fullmatch(self.base_sha) is None
            or type(self.head_sha) is not str
            or _COMMIT_SHA.fullmatch(self.head_sha) is None
        ):
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
        changed_lines = _validated_changed_lines(self.changed_lines)
        finding_locations = _validated_location_index(self.finding_locations)
        data_flow_locations = _validated_location_index(self.data_flow_locations)
        object.__setattr__(self, "changed_lines", changed_lines)
        object.__setattr__(self, "finding_locations", finding_locations)
        object.__setattr__(self, "data_flow_locations", data_flow_locations)
        object.__setattr__(
            self,
            "_changed_lines_index",
            MappingProxyType(_changed_lines_by_path(changed_lines)),
        )
        object.__setattr__(
            self,
            "_locations_index",
            MappingProxyType(
                _locations_by_fingerprint(finding_locations, data_flow_locations)
            ),
        )

    def proves_changed(self, fingerprint: str) -> bool:
        """Return whether a verified fingerprint has a changed-line relation."""

        if type(fingerprint) is not str or _FINGERPRINT.fullmatch(fingerprint) is None:
            return False
        return _scope_proves_changed(
            fingerprint,
            changed_by_path=self._changed_lines_index,
            locations_by_fingerprint=self._locations_index,
        )

    def validate_for(self, comparison: BaselineFingerprintComparison) -> None:
        """Bind this proof to one exact tenant and base/head comparison."""

        if type(comparison) is not BaselineFingerprintComparison:
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
        if (
            self.tenant_id != comparison.tenant_id
            or self.base_sha != comparison.base_sha
            or self.head_sha != comparison.head_sha
        ):
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.IDENTITY_MISMATCH)
        head_fingerprints = set(comparison.head_fingerprints)
        if any(
            fingerprint not in head_fingerprints
            for index in (self.finding_locations, self.data_flow_locations)
            for fingerprint, _ in index
        ):
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.IDENTITY_MISMATCH)


@dataclass(frozen=True, slots=True)
class BaselineFingerprintSnapshot:
    """One exact revision's P2.9-normalized finding metadata."""

    schema_version: str
    tenant_id: str
    revision_sha: str
    findings: tuple[DiscoveryCandidate, ...]

    def __post_init__(self) -> None:
        _validate_snapshot_shape(self)
        if len(self.findings) > _MAX_FINDINGS:
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
        validated = tuple(_validated_candidate(item) for item in self.findings)
        if any(item.tenant_id != self.tenant_id for item in validated):
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.IDENTITY_MISMATCH)
        if any(item.head_sha != self.revision_sha for item in validated):
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.IDENTITY_MISMATCH)
        fingerprints = tuple(item.root_cause_fingerprint for item in validated)
        if len(fingerprints) != len(set(fingerprints)):
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.DUPLICATE_FINGERPRINT)
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

    def relation_for(
        self,
        fingerprint: str,
        *,
        changed_scope: BaselineChangedScope | None | object = _UNSET,
    ) -> BaselineFindingRelation:
        """Classify one head fingerprint, optionally requiring changed-line proof.

        The no-argument form preserves the original exact fingerprint relation.
        Callers enforcing new-code policy must pass ``changed_scope``. An
        explicit ``None`` then fails closed for a baseline-absent fingerprint,
        while a legacy fingerprint remains ``LEGACY``.
        """

        if type(fingerprint) is not str or _FINGERPRINT.fullmatch(fingerprint) is None:
            return BaselineFindingRelation.UNKNOWN
        if fingerprint not in self.head_fingerprints:
            return BaselineFindingRelation.UNKNOWN
        if fingerprint in self.baseline_fingerprints:
            return BaselineFindingRelation.LEGACY
        if fingerprint not in self.new_fingerprints:
            return BaselineFindingRelation.UNKNOWN
        if changed_scope is _UNSET:
            return BaselineFindingRelation.NEW
        if changed_scope is None:
            return BaselineFindingRelation.UNKNOWN
        if type(changed_scope) is not BaselineChangedScope:
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
        changed_scope.validate_for(self)
        if changed_scope.proves_changed(fingerprint):
            return BaselineFindingRelation.NEW
        return BaselineFindingRelation.UNKNOWN

    def relation_for_new_code(
        self,
        fingerprint: str,
        *,
        changed_scope: BaselineChangedScope | None,
    ) -> BaselineFindingRelation:
        """Classify a finding only when the exact changed scope is available.

        ``relation_for`` intentionally keeps its historical baseline-only
        behavior for callers that are evaluating legacy debt. New-code policy
        must use this entry point (or ``new_code_fingerprints``) because a
        baseline-absent fingerprint is not evidence that the finding was
        introduced by the current change. Missing or stale scope therefore
        yields ``UNKNOWN`` and cannot be promoted to ``NEW``.
        """

        if changed_scope is not None:
            if type(changed_scope) is not BaselineChangedScope:
                return BaselineFindingRelation.UNKNOWN
            try:
                changed_scope.validate_for(self)
            except (TypeError, ValueError):
                return BaselineFindingRelation.UNKNOWN
        baseline_relation = self.relation_for(fingerprint)
        if baseline_relation is not BaselineFindingRelation.NEW:
            return baseline_relation
        if changed_scope is None:
            return BaselineFindingRelation.UNKNOWN
        return (
            BaselineFindingRelation.NEW
            if changed_scope.proves_changed(fingerprint)
            else BaselineFindingRelation.UNKNOWN
        )

    def new_code_fingerprints(
        self,
        *,
        changed_scope: BaselineChangedScope | None = None,
    ) -> tuple[str, ...]:
        """Return only new fingerprints proven to intersect changed code."""

        if changed_scope is None:
            return ()
        if type(changed_scope) is not BaselineChangedScope:
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
        changed_scope.validate_for(self)
        return tuple(
            fingerprint
            for fingerprint in self.new_fingerprints
            if _scope_proves_changed(
                fingerprint,
                changed_by_path=changed_scope._changed_lines_index,
                locations_by_fingerprint=changed_scope._locations_index,
            )
        )

    def has_proven_new_code(
        self,
        fingerprint: str,
        *,
        changed_scope: BaselineChangedScope | None,
    ) -> bool:
        """Return true only for a baseline-absent finding proven in changed code."""

        return (
            self.relation_for_new_code(
                fingerprint,
                changed_scope=changed_scope,
            )
            is BaselineFindingRelation.NEW
        )


def compare_baseline_fingerprints(
    *,
    baseline: BaselineFingerprintSnapshot,
    head: BaselineFingerprintSnapshot,
    current_head_sha: str,
    commit_lineage: tuple[str, ...],
    changed_scope: BaselineChangedScope | None = None,
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
    comparison = BaselineFingerprintComparison(
        schema_version=BASELINE_FINGERPRINT_SCHEMA_VERSION,
        tenant_id=head.tenant_id,
        base_sha=baseline.revision_sha,
        head_sha=head.revision_sha,
        baseline_fingerprints=baseline_fingerprints,
        head_fingerprints=head_fingerprints,
        new_fingerprints=new_fingerprints,
    )
    if changed_scope is not None:
        if type(changed_scope) is not BaselineChangedScope:
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
        changed_scope.validate_for(comparison)
    return comparison


def _changed_lines_by_path(
    changed_lines: tuple[tuple[str, int], ...],
) -> dict[str, tuple[int, ...]]:
    grouped: dict[str, list[int]] = {}
    for path, line in changed_lines:
        grouped.setdefault(path, []).append(line)
    return {path: tuple(lines) for path, lines in grouped.items()}


def _locations_by_fingerprint(
    *indexes: tuple[tuple[str, tuple[tuple[str, int, int], ...]], ...],
) -> dict[str, tuple[tuple[str, int, int], ...]]:
    grouped: dict[str, list[tuple[str, int, int]]] = {}
    for index in indexes:
        for fingerprint, locations in index:
            grouped.setdefault(fingerprint, []).extend(locations)
    return {fingerprint: tuple(locations) for fingerprint, locations in grouped.items()}


def _scope_proves_changed(
    fingerprint: str,
    *,
    changed_by_path: Mapping[str, tuple[int, ...]],
    locations_by_fingerprint: Mapping[str, tuple[tuple[str, int, int], ...]],
) -> bool:
    for path, start_line, end_line in locations_by_fingerprint.get(fingerprint, ()):
        lines = changed_by_path.get(path, ())
        position = bisect_left(lines, start_line)
        if position < len(lines) and lines[position] <= end_line:
            return True
    return False


def _validated_changed_lines(value: object) -> tuple[tuple[str, int], ...]:
    if type(value) is not tuple or len(value) > _MAX_SCOPE_LINES:
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
    lines: list[tuple[str, int]] = []
    for item in value:
        if type(item) is not tuple or len(item) != 2:
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
        path, line = item
        _validate_scope_path(path)
        if type(line) is not int or line < 1:
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
        lines.append((path, line))
    if len(lines) != len(set(lines)):
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
    return tuple(sorted(lines))


def _validated_location_index(
    value: object,
) -> tuple[tuple[str, tuple[tuple[str, int, int], ...]], ...]:
    if type(value) is not tuple or len(value) > _MAX_FINDINGS:
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
    entries: list[tuple[str, tuple[tuple[str, int, int], ...]]] = []
    seen_fingerprints: set[str] = set()
    total_locations = 0
    for item in value:
        if type(item) is not tuple or len(item) != 2:
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
        fingerprint, locations = item
        if (
            type(fingerprint) is not str
            or _FINGERPRINT.fullmatch(fingerprint) is None
            or fingerprint in seen_fingerprints
            or type(locations) is not tuple
            or not locations
            or len(locations) > _MAX_LOCATIONS_PER_FINGERPRINT
        ):
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
        seen_fingerprints.add(fingerprint)
        spans: list[tuple[str, int, int]] = []
        for location in locations:
            if type(location) is not tuple or len(location) != 3:
                raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
            path, start_line, end_line = location
            _validate_scope_path(path)
            if (
                type(start_line) is not int
                or start_line < 1
                or type(end_line) is not int
                or end_line < start_line
            ):
                raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
            spans.append((path, start_line, end_line))
        if len(spans) != len(set(spans)):
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
        total_locations += len(spans)
        if total_locations > _MAX_SCOPE_LOCATIONS:
            raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
        entries.append((fingerprint, tuple(sorted(spans))))
    return tuple(sorted(entries, key=lambda item: item[0]))


def _validate_scope_path(path: object) -> None:
    if type(path) is not str or not path:
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)
    normalized = PurePosixPath(path)
    if (
        path != path.strip()
        or len(path) > _MAX_PATH_LENGTH
        or "\\" in path
        or any(not character.isprintable() for character in path)
        or unicodedata.normalize("NFC", path) != path
        or normalized.is_absolute()
        or normalized.as_posix() != path
        or not normalized.parts
        or any(part in {"", ".", ".."} for part in normalized.parts)
        or normalized.parts[0].endswith(":")
    ):
        raise BaselineFingerprintError(BaselineFingerprintErrorCode.INVALID_INPUT)


def _validate_snapshot_shape(snapshot: BaselineFingerprintSnapshot) -> None:
    if (
        type(snapshot.schema_version) is not str
        or snapshot.schema_version != BASELINE_FINGERPRINT_SCHEMA_VERSION
        or type(snapshot.tenant_id) is not str
        or _IDENTIFIER.fullmatch(snapshot.tenant_id) is None
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
    "BaselineChangedScope",
    "BaselineFindingRelation",
    "BaselineFingerprintComparison",
    "BaselineFingerprintError",
    "BaselineFingerprintErrorCode",
    "BaselineFingerprintSnapshot",
    "compare_baseline_fingerprints",
]
