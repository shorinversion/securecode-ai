"""Fail-closed structured Auditor response contract.

Provider transport and payload decoding are intentionally outside this module.
It accepts a bounded metadata-only ``EvidencePackage`` and retains only a
schema-valid verdict plus its evidence citations, never model rationale text.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.contracts import FindingVerdict, ModelCallStatus

from .evidence_package import EvidencePackage


class AuditorContractErrorCode(StrEnum):
    """Closed, source-free reasons a structured Auditor output is refused."""

    REQUEST_INVALID = "REQUEST_INVALID"
    INVALID_SCHEMA = "INVALID_SCHEMA"
    INVALID_CITATION = "INVALID_CITATION"
    STATUS_CONFLICT = "STATUS_CONFLICT"


class AuditorContractError(RuntimeError):
    """A fixed error that cannot disclose model output or evidence content."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: AuditorContractErrorCode) -> None:
        if type(code) is not AuditorContractErrorCode:
            raise TypeError("auditor contract error code is invalid")
        self.code = code
        self.safe_message = "auditor response validation failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class AuditorVerdict:
    """A schema-valid verdict whose claims cite selected evidence identifiers."""

    verdict_id: str
    finding_verdict: FindingVerdict
    cited_evidence_ids: tuple[str, ...]
    rationale_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.verdict_id) is not str
            or not self.verdict_id
            or type(self.finding_verdict) is not FindingVerdict
            or type(self.cited_evidence_ids) is not tuple
            or not self.cited_evidence_ids
            or any(type(item) is not str or not item for item in self.cited_evidence_ids)
            or self.cited_evidence_ids != tuple(sorted(self.cited_evidence_ids))
            or len(self.cited_evidence_ids) != len(set(self.cited_evidence_ids))
            or type(self.rationale_sha256) is not str
            or len(self.rationale_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.rationale_sha256)
        ):
            raise ValueError("auditor verdict is invalid")


@dataclass(frozen=True, slots=True)
class AuditorResponse:
    """Model-call and verdict results remain intentionally disjoint fields."""

    model_call_status: ModelCallStatus
    schema_valid_result: bool
    verdict: AuditorVerdict | None

    def __post_init__(self) -> None:
        succeeded = self.model_call_status is ModelCallStatus.SUCCEEDED
        if (
            type(self.model_call_status) is not ModelCallStatus
            or type(self.schema_valid_result) is not bool
            or (self.verdict is not None and type(self.verdict) is not AuditorVerdict)
            or (succeeded and (not self.schema_valid_result or self.verdict is None))
            or (not succeeded and (self.schema_valid_result or self.verdict is not None))
        ):
            raise ValueError("auditor response is invalid")


def validate_auditor_response(
    package: EvidencePackage,
    model_call_status: ModelCallStatus,
    payload: Mapping[str, object] | None,
) -> AuditorResponse:
    """Validate one ephemeral structured model payload without retaining it.

    A provider success with malformed output is normalized to the independent
    ``INVALID_SCHEMA`` model-call status.  Every other model non-success must
    arrive without a payload and therefore cannot be reclassified as a verdict.
    """

    if type(package) is not EvidencePackage or type(model_call_status) is not ModelCallStatus:
        raise AuditorContractError(AuditorContractErrorCode.REQUEST_INVALID)
    if model_call_status is not ModelCallStatus.SUCCEEDED:
        if payload is not None:
            raise AuditorContractError(AuditorContractErrorCode.STATUS_CONFLICT)
        return AuditorResponse(
            model_call_status=model_call_status,
            schema_valid_result=False,
            verdict=None,
        )
    try:
        verdict = parse_auditor_verdict(package, payload)
    except AuditorContractError:
        return AuditorResponse(
            model_call_status=ModelCallStatus.INVALID_SCHEMA,
            schema_valid_result=False,
            verdict=None,
        )
    return AuditorResponse(
        model_call_status=ModelCallStatus.SUCCEEDED,
        schema_valid_result=True,
        verdict=verdict,
    )


def parse_auditor_verdict(
    package: EvidencePackage,
    payload: Mapping[str, object] | None,
) -> AuditorVerdict:
    """Parse the closed Auditor output shape and bind citations to context."""

    if type(package) is not EvidencePackage or payload is None or not isinstance(payload, Mapping):
        raise AuditorContractError(AuditorContractErrorCode.INVALID_SCHEMA)
    expected_keys = {"verdict_id", "finding_verdict", "cited_evidence_ids", "rationale_sha256"}
    if set(payload) != expected_keys:
        raise AuditorContractError(AuditorContractErrorCode.INVALID_SCHEMA)
    verdict_value = payload["finding_verdict"]
    citations_value = payload["cited_evidence_ids"]
    if (
        type(payload["verdict_id"]) is not str
        or type(verdict_value) is not str
        or not isinstance(citations_value, (tuple, list))
        or type(payload["rationale_sha256"]) is not str
        or any(type(item) is not str for item in citations_value)
    ):
        raise AuditorContractError(AuditorContractErrorCode.INVALID_SCHEMA)
    try:
        finding_verdict = FindingVerdict(verdict_value)
        verdict = AuditorVerdict(
            verdict_id=payload["verdict_id"],
            finding_verdict=finding_verdict,
            cited_evidence_ids=tuple(citations_value),
            rationale_sha256=payload["rationale_sha256"],
        )
    except (TypeError, ValueError):
        raise AuditorContractError(AuditorContractErrorCode.INVALID_SCHEMA) from None
    selected_ids = {item.evidence_id for item in package.selected}
    if not set(verdict.cited_evidence_ids).issubset(selected_ids):
        raise AuditorContractError(AuditorContractErrorCode.INVALID_CITATION)
    return verdict


__all__ = [
    "AuditorContractError",
    "AuditorContractErrorCode",
    "AuditorResponse",
    "AuditorVerdict",
    "parse_auditor_verdict",
    "validate_auditor_response",
]
