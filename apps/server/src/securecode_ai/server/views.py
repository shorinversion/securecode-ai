"""Deterministic source-free developer/AppSec API view dataclasses."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum


class ViewOutcome(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INDETERMINATE = "INDETERMINATE"
    ERROR = "ERROR"
    CANCELLED = "CANCELLED"
    SUPERSEDED = "SUPERSEDED"


@dataclass(frozen=True, slots=True)
class RunView:
    tenant_id: str
    repository_id: str
    run_id: str
    execution_identity_hash: str
    head_sha: str
    outcome: ViewOutcome
    coverage_complete: bool
    approval_status: str | None = None
    waiver_status: str | None = None

    @property
    def clean(self) -> bool:
        return self.outcome is ViewOutcome.PASS and self.coverage_complete

    def json_ready(self) -> dict[str, object]:
        value = asdict(self)
        value["outcome"] = self.outcome.value
        value["clean"] = self.clean
        return value


@dataclass(frozen=True, slots=True)
class FindingView:
    tenant_id: str
    repository_id: str
    run_id: str
    finding_id: str
    head_sha: str
    fingerprint: str
    outcome: ViewOutcome
    evidence_metadata: tuple[dict[str, object], ...] = ()
    approval_status: str | None = None
    waiver_status: str | None = None

    def __post_init__(self) -> None:
        if len(self.evidence_metadata) > 64:
            raise ValueError("too many evidence records")

    def json_ready(self) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "repository_id": self.repository_id,
            "run_id": self.run_id,
            "finding_id": self.finding_id,
            "head_sha": self.head_sha,
            "fingerprint": self.fingerprint,
            "outcome": self.outcome.value,
            "evidence_metadata": self.evidence_metadata,
            "approval_status": self.approval_status,
            "waiver_status": self.waiver_status,
        }
