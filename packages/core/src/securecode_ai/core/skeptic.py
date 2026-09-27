"""Read-only, typed Skeptic review boundary.

The Skeptic is deliberately a pure reducer over an immutable Auditor snapshot
and a parsed structured response.  It receives neither repository handles nor
policy, tool, budget, verdict, or evidence mutation capabilities.  Integration
code can adapt its P3.1/P3.2 values to :class:`AuditorSnapshot` without making
this component depend on an in-progress public contract.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from securecode_ai.contracts import FindingVerdict, ModelCallStatus

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_MAX_EVIDENCE_IDS: Final = 4_096
_MAX_OBJECTIONS: Final = 1_024
_VALID_AUDITOR_VERDICTS: Final = frozenset(
    {
        FindingVerdict.CONFIRMED,
        FindingVerdict.REJECTED_WITH_EVIDENCE,
        FindingVerdict.NEEDS_MORE_EVIDENCE,
    }
)


class SkepticErrorCode(StrEnum):
    """Closed, non-echoing caller-side Skeptic contract failures."""

    INVALID_INPUT = "INVALID_INPUT"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class SkepticContractError(ValueError):
    """Safe boundary error; it intentionally never includes supplied content."""

    __slots__ = ("code",)

    def __init__(self, code: SkepticErrorCode) -> None:
        if type(code) is not SkepticErrorCode:
            raise TypeError("skeptic error code is invalid")
        self.code = code
        super().__init__("skeptic contract validation failed")
        self.__cause__ = None
        self.__context__ = None


class SkepticObjectionKind(StrEnum):
    """The complete, source-free vocabulary for a Skeptic objection."""

    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    EVIDENCE_INTEGRITY = "EVIDENCE_INTEGRITY"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    UNSUPPORTED_INFERENCE = "UNSUPPORTED_INFERENCE"


@dataclass(frozen=True, slots=True)
class AuditorSnapshot:
    """Minimal immutable bridge from the P3.2 Auditor result.

    The snapshot deliberately retains only identity, verdict and evidence
    references.  It does not expose mutable evidence, a repository view,
    policy, tools, budgets or an Auditor callable to the Skeptic.
    """

    candidate_id: str
    candidate_version: int
    head_sha: str
    auditor_identity: str
    auditor_output_sha256: str
    model_call_status: ModelCallStatus
    finding_verdict: FindingVerdict
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.candidate_id) is not str
            or _ID.fullmatch(self.candidate_id) is None
            or type(self.candidate_version) is not int
            or isinstance(self.candidate_version, bool)
            or self.candidate_version < 1
            or type(self.head_sha) is not str
            or _COMMIT_SHA.fullmatch(self.head_sha) is None
            or type(self.auditor_identity) is not str
            or _ID.fullmatch(self.auditor_identity) is None
            or type(self.auditor_output_sha256) is not str
            or _SHA256.fullmatch(self.auditor_output_sha256) is None
            or type(self.model_call_status) is not ModelCallStatus
            or type(self.finding_verdict) is not FindingVerdict
            or type(self.evidence_ids) is not tuple
            or not self.evidence_ids
            or len(self.evidence_ids) > _MAX_EVIDENCE_IDS
            or any(
                type(item) is not str or _ID.fullmatch(item) is None for item in self.evidence_ids
            )
            or len(self.evidence_ids) != len(set(self.evidence_ids))
        ):
            raise SkepticContractError(SkepticErrorCode.INVALID_INPUT)
        if self.model_call_status is not ModelCallStatus.SUCCEEDED:
            raise SkepticContractError(SkepticErrorCode.INTEGRITY_FAILURE)
        if self.finding_verdict not in _VALID_AUDITOR_VERDICTS:
            raise SkepticContractError(SkepticErrorCode.INTEGRITY_FAILURE)
        object.__setattr__(self, "evidence_ids", tuple(sorted(self.evidence_ids)))


@dataclass(frozen=True, slots=True)
class SkepticObjection:
    """An evidence-cited, typed objection; raw model prose is never retained."""

    kind: SkepticObjectionKind
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.kind) is not SkepticObjectionKind
            or type(self.evidence_ids) is not tuple
            or not self.evidence_ids
            or len(self.evidence_ids) > _MAX_EVIDENCE_IDS
            or any(
                type(item) is not str or _ID.fullmatch(item) is None for item in self.evidence_ids
            )
            or len(self.evidence_ids) != len(set(self.evidence_ids))
        ):
            raise SkepticContractError(SkepticErrorCode.INVALID_INPUT)
        object.__setattr__(self, "evidence_ids", tuple(sorted(self.evidence_ids)))


@dataclass(frozen=True, slots=True)
class SkepticOutput:
    """Validated-shape model output supplied by an integration boundary.

    This is intentionally a local value object until the P3.2 structured
    Auditor schema is integrated.  It keeps the Skeptic's wire dependency
    direction one-way and makes malformed output a typed non-success.
    """

    finding_verdict: FindingVerdict
    objections: tuple[SkepticObjection, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.finding_verdict) is not FindingVerdict
            or type(self.objections) is not tuple
            or len(self.objections) > _MAX_OBJECTIONS
            or any(type(item) is not SkepticObjection for item in self.objections)
        ):
            raise SkepticContractError(SkepticErrorCode.INVALID_INPUT)
        canonical = tuple(
            sorted(
                self.objections,
                key=lambda item: (item.kind.value, item.evidence_ids),
            )
        )
        if len(canonical) != len(set(canonical)):
            raise SkepticContractError(SkepticErrorCode.INVALID_INPUT)
        if not canonical and self.finding_verdict is FindingVerdict.CONFLICTING:
            raise SkepticContractError(SkepticErrorCode.INVALID_INPUT)
        object.__setattr__(self, "objections", canonical)

    @property
    def cited_evidence_ids(self) -> tuple[str, ...]:
        """Return stable distinct citation IDs, never evidence content."""

        return tuple(sorted({item_id for item in self.objections for item_id in item.evidence_ids}))


@dataclass(frozen=True, slots=True)
class SkepticReview:
    """A durable-safe review result with both original and Skeptic verdicts.

    ``effective_verdict`` is never a product ``PASS``.  A model non-success or
    malformed output is represented as ``NOT_EVALUATED`` so a later Finding
    Gate must route it to an explicit non-success path.
    """

    candidate_id: str
    candidate_version: int
    head_sha: str
    auditor_identity: str
    skeptic_identity: str
    auditor_verdict: FindingVerdict
    skeptic_verdict: FindingVerdict
    effective_verdict: FindingVerdict
    model_call_status: ModelCallStatus
    objections: tuple[SkepticObjection, ...]
    cited_evidence_ids: tuple[str, ...]

    @property
    def is_indeterminate(self) -> bool:
        return self.model_call_status is not ModelCallStatus.SUCCEEDED

    @property
    def has_conflict(self) -> bool:
        return self.effective_verdict is FindingVerdict.CONFLICTING

    def __post_init__(self) -> None:
        if (
            type(self.candidate_id) is not str
            or _ID.fullmatch(self.candidate_id) is None
            or type(self.candidate_version) is not int
            or isinstance(self.candidate_version, bool)
            or self.candidate_version < 1
            or type(self.head_sha) is not str
            or _COMMIT_SHA.fullmatch(self.head_sha) is None
            or type(self.auditor_identity) is not str
            or _ID.fullmatch(self.auditor_identity) is None
            or type(self.skeptic_identity) is not str
            or _ID.fullmatch(self.skeptic_identity) is None
            or self.auditor_identity == self.skeptic_identity
            or type(self.auditor_verdict) is not FindingVerdict
            or type(self.skeptic_verdict) is not FindingVerdict
            or type(self.effective_verdict) is not FindingVerdict
            or type(self.model_call_status) is not ModelCallStatus
            or type(self.objections) is not tuple
            or type(self.cited_evidence_ids) is not tuple
            or any(type(item) is not SkepticObjection for item in self.objections)
            or any(
                type(item) is not str or _ID.fullmatch(item) is None
                for item in self.cited_evidence_ids
            )
            or len(self.cited_evidence_ids) != len(set(self.cited_evidence_ids))
        ):
            raise SkepticContractError(SkepticErrorCode.INVALID_INPUT)
        if self.auditor_verdict not in _VALID_AUDITOR_VERDICTS:
            raise SkepticContractError(SkepticErrorCode.INTEGRITY_FAILURE)
        canonical_objections = tuple(
            sorted(self.objections, key=lambda item: (item.kind.value, item.evidence_ids))
        )
        cited_evidence_ids = tuple(
            sorted({item_id for item in canonical_objections for item_id in item.evidence_ids})
        )
        if self.model_call_status is ModelCallStatus.SUCCEEDED:
            expected_effective_verdict = (
                FindingVerdict.CONFLICTING
                if canonical_objections or self.skeptic_verdict is not self.auditor_verdict
                else self.auditor_verdict
            )
            if (
                self.skeptic_verdict is FindingVerdict.NOT_EVALUATED
                or self.effective_verdict is not expected_effective_verdict
                or self.cited_evidence_ids != cited_evidence_ids
            ):
                raise SkepticContractError(SkepticErrorCode.INTEGRITY_FAILURE)
        elif (
            self.skeptic_verdict is not FindingVerdict.NOT_EVALUATED
            or self.effective_verdict is not FindingVerdict.NOT_EVALUATED
            or canonical_objections
            or self.cited_evidence_ids
        ):
            raise SkepticContractError(SkepticErrorCode.INTEGRITY_FAILURE)
        object.__setattr__(self, "objections", canonical_objections)
        object.__setattr__(self, "cited_evidence_ids", cited_evidence_ids)


def review_auditor_snapshot(
    snapshot: AuditorSnapshot,
    *,
    skeptic_identity: str,
    model_call_status: ModelCallStatus,
    output: SkepticOutput | object | None,
) -> SkepticReview:
    """Reduce a structured Skeptic response without granting mutation authority.

    The function is pure: it opens no files, sends no network traffic, receives
    no repository/policy/tool/budget object and never mutates the Auditor
    snapshot.  Bad model output becomes ``INVALID_SCHEMA`` and a non-success
    review, rather than a clean result or an exception containing model text.
    """

    if type(snapshot) is not AuditorSnapshot or type(model_call_status) is not ModelCallStatus:
        raise SkepticContractError(SkepticErrorCode.INVALID_INPUT)
    snapshot = _validated_snapshot(snapshot)
    if type(skeptic_identity) is not str or _ID.fullmatch(skeptic_identity) is None:
        raise SkepticContractError(SkepticErrorCode.INVALID_INPUT)
    if skeptic_identity == snapshot.auditor_identity:
        raise SkepticContractError(SkepticErrorCode.IDENTITY_MISMATCH)

    if model_call_status is not ModelCallStatus.SUCCEEDED:
        return _non_success_review(snapshot, skeptic_identity, model_call_status)
    if type(output) is not SkepticOutput:
        return _non_success_review(snapshot, skeptic_identity, ModelCallStatus.INVALID_SCHEMA)
    try:
        output = _validated_output(output)
    except SkepticContractError:
        return _non_success_review(snapshot, skeptic_identity, ModelCallStatus.INVALID_SCHEMA)
    if not set(output.cited_evidence_ids).issubset(snapshot.evidence_ids):
        return _non_success_review(snapshot, skeptic_identity, ModelCallStatus.INVALID_SCHEMA)
    if output.finding_verdict is FindingVerdict.NOT_EVALUATED:
        return _non_success_review(snapshot, skeptic_identity, ModelCallStatus.INVALID_SCHEMA)
    if not output.objections and output.finding_verdict is not snapshot.finding_verdict:
        return _non_success_review(snapshot, skeptic_identity, ModelCallStatus.INVALID_SCHEMA)

    effective_verdict = (
        FindingVerdict.CONFLICTING
        if output.objections or output.finding_verdict is not snapshot.finding_verdict
        else snapshot.finding_verdict
    )
    return SkepticReview(
        candidate_id=snapshot.candidate_id,
        candidate_version=snapshot.candidate_version,
        head_sha=snapshot.head_sha,
        auditor_identity=snapshot.auditor_identity,
        skeptic_identity=skeptic_identity,
        auditor_verdict=snapshot.finding_verdict,
        skeptic_verdict=output.finding_verdict,
        effective_verdict=effective_verdict,
        model_call_status=ModelCallStatus.SUCCEEDED,
        objections=output.objections,
        cited_evidence_ids=output.cited_evidence_ids,
    )


def _non_success_review(
    snapshot: AuditorSnapshot,
    skeptic_identity: str,
    model_call_status: ModelCallStatus,
) -> SkepticReview:
    return SkepticReview(
        candidate_id=snapshot.candidate_id,
        candidate_version=snapshot.candidate_version,
        head_sha=snapshot.head_sha,
        auditor_identity=snapshot.auditor_identity,
        skeptic_identity=skeptic_identity,
        auditor_verdict=snapshot.finding_verdict,
        skeptic_verdict=FindingVerdict.NOT_EVALUATED,
        effective_verdict=FindingVerdict.NOT_EVALUATED,
        model_call_status=model_call_status,
        objections=(),
        cited_evidence_ids=(),
    )


def _validated_snapshot(snapshot: AuditorSnapshot) -> AuditorSnapshot:
    """Copy through constructor validation before retaining a caller-owned value."""

    try:
        return AuditorSnapshot(
            candidate_id=snapshot.candidate_id,
            candidate_version=snapshot.candidate_version,
            head_sha=snapshot.head_sha,
            auditor_identity=snapshot.auditor_identity,
            auditor_output_sha256=snapshot.auditor_output_sha256,
            model_call_status=snapshot.model_call_status,
            finding_verdict=snapshot.finding_verdict,
            evidence_ids=snapshot.evidence_ids,
        )
    except (AttributeError, TypeError, ValueError):
        raise SkepticContractError(SkepticErrorCode.INTEGRITY_FAILURE) from None


def _validated_output(output: SkepticOutput) -> SkepticOutput:
    """Copy parsed output through local validation without retaining raw content."""

    try:
        objections = tuple(
            SkepticObjection(kind=item.kind, evidence_ids=item.evidence_ids)
            for item in output.objections
        )
        return SkepticOutput(finding_verdict=output.finding_verdict, objections=objections)
    except (AttributeError, TypeError, ValueError):
        raise SkepticContractError(SkepticErrorCode.INTEGRITY_FAILURE) from None


__all__ = [
    "AuditorSnapshot",
    "SkepticContractError",
    "SkepticErrorCode",
    "SkepticObjection",
    "SkepticObjectionKind",
    "SkepticOutput",
    "SkepticReview",
    "review_auditor_snapshot",
]
