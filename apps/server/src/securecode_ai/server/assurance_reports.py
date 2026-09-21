"""Deterministic source-free receipts derived from assurance ledger hashes."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Final

from .revalidation import CurrentPins, stale_reasons

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_STALE_REASONS: Final = frozenset({"source", "policy", "dependency", "environment", "operational"})


class AssuranceReportError(ValueError):
    """Report material is invalid or includes unsafe unbounded metadata."""


@dataclass(frozen=True, slots=True)
class AssuranceReport:
    tenant_id: str
    repository_id: str
    ledger_hashes: tuple[str, ...]
    pins: CurrentPins
    stale_reasons: tuple[str, ...]
    complete: bool
    content_sha256: str
    storage_ref: str | None
    authority: str = "NONE"

    def __post_init__(self) -> None:
        if not _identifier(self.tenant_id) or not _identifier(self.repository_id):
            raise AssuranceReportError()
        if (
            type(self.ledger_hashes) is not tuple
            or any(not _sha256(value) for value in self.ledger_hashes)
            or len(set(self.ledger_hashes)) != len(self.ledger_hashes)
        ):
            raise AssuranceReportError()
        _validate_pins(self.pins)
        if (
            type(self.stale_reasons) is not tuple
            or any(reason not in _STALE_REASONS for reason in self.stale_reasons)
            or type(self.complete) is not bool
            or not _sha256(self.content_sha256)
            or self.authority != "NONE"
        ):
            raise AssuranceReportError()
        if self.storage_ref is not None and not _safe_reference(self.storage_ref):
            raise AssuranceReportError()


def generate(
    *,
    tenant_id: str,
    repository_id: str,
    ledger_hashes: tuple[str, ...],
    recorded: CurrentPins,
    current: CurrentPins,
    storage_ref: str | None = None,
) -> AssuranceReport:
    if not _identifier(tenant_id) or not _identifier(repository_id):
        raise AssuranceReportError()
    if (
        type(ledger_hashes) is not tuple
        or any(not _sha256(value) for value in ledger_hashes)
        or len(set(ledger_hashes)) != len(ledger_hashes)
    ):
        raise AssuranceReportError()
    _validate_pins(recorded)
    _validate_pins(current)
    if storage_ref is not None and not _safe_reference(storage_ref):
        raise AssuranceReportError()

    ordered_hashes = tuple(sorted(ledger_hashes))
    stale = stale_reasons(recorded, current)
    if any(reason not in _STALE_REASONS for reason in stale):
        raise AssuranceReportError()
    complete = bool(ordered_hashes) and not stale
    material = {
        "authority": "NONE",
        "complete": complete,
        "ledger_hashes": ordered_hashes,
        "pins": asdict(current),
        "repository_id": repository_id,
        "schema_version": "1.0.0",
        "stale_reasons": stale,
        "storage_ref": storage_ref,
        "tenant_id": tenant_id,
    }
    canonical = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    digest = hashlib.sha256(b"securecode-ai/assurance-report/v1\x00" + canonical).hexdigest()
    return AssuranceReport(
        tenant_id=tenant_id,
        repository_id=repository_id,
        ledger_hashes=ordered_hashes,
        pins=current,
        stale_reasons=stale,
        complete=complete,
        content_sha256=digest,
        storage_ref=storage_ref,
    )


def _validate_pins(value: object) -> None:
    if type(value) is not CurrentPins:
        raise AssuranceReportError()
    for pin in asdict(value).values():
        if type(pin) is not str or not pin or len(pin) > 256 or any(ord(char) < 32 for char in pin):
            raise AssuranceReportError()


def _safe_reference(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 512
        and all(32 <= ord(char) < 127 for char in value)
    )


def _identifier(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


__all__ = ["AssuranceReport", "AssuranceReportError", "generate"]
