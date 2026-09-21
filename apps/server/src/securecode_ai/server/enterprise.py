"""Validated enterprise composition receipts with metadata-only projections."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Final

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")


class EnterpriseReceiptError(ValueError):
    """A safe validation error for malformed enterprise receipt metadata."""


class EnterpriseOutcome(StrEnum):
    ACCEPTED = "ACCEPTED"
    INDETERMINATE = "INDETERMINATE"
    CANCELLED = "CANCELLED"
    SUPERSEDED = "SUPERSEDED"
    DENIED = "DENIED"


@dataclass(frozen=True, slots=True)
class EnterpriseReceipt:
    tenant_id: str
    repository_id: str
    run_id: str
    execution_identity_hash: str
    outcome: EnterpriseOutcome
    profile_sha256: str
    workflow_version: int
    published: bool
    evidence_manifest_sha256: str | None = None

    def __post_init__(self) -> None:
        if any(
            not _identifier(value) for value in (self.tenant_id, self.repository_id, self.run_id)
        ):
            raise EnterpriseReceiptError()
        if (
            not _sha256(self.execution_identity_hash)
            or type(self.outcome) is not EnterpriseOutcome
            or not _sha256(self.profile_sha256)
            or type(self.workflow_version) is not int
            or self.workflow_version < 0
            or type(self.published) is not bool
            or (
                self.evidence_manifest_sha256 is not None
                and not _sha256(self.evidence_manifest_sha256)
            )
        ):
            raise EnterpriseReceiptError()
        if self.outcome is EnterpriseOutcome.DENIED:
            if self.workflow_version != 0 or self.profile_sha256 != "0" * 64:
                raise EnterpriseReceiptError()
        elif self.workflow_version < 1:
            raise EnterpriseReceiptError()
        if self.published and self.outcome is not EnterpriseOutcome.ACCEPTED:
            raise EnterpriseReceiptError()

    def metadata(self) -> dict[str, object]:
        document: dict[str, object] = {
            "tenant_id": self.tenant_id,
            "repository_id": self.repository_id,
            "run_id": self.run_id,
            "execution_identity_hash": self.execution_identity_hash,
            "outcome": self.outcome.value,
            "profile_sha256": self.profile_sha256,
            "workflow_version": self.workflow_version,
            "published": self.published,
            "evidence_manifest_sha256": self.evidence_manifest_sha256,
        }
        document["receipt_sha256"] = self.receipt_sha256()
        return document

    def receipt_sha256(self) -> str:
        material = asdict(self)
        material["outcome"] = self.outcome.value
        canonical = json.dumps(
            material,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        return hashlib.sha256(b"securecode-ai/enterprise-receipt/v1\x00" + canonical).hexdigest()


def _identifier(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


__all__ = [
    "EnterpriseOutcome",
    "EnterpriseReceipt",
    "EnterpriseReceiptError",
]
