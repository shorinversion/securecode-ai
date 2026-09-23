"""Canonical audit export; output is evidence, never an authorization decision."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from .audit_log import AuditConflict, AuditLog

MAX_AUDIT_EXPORT_EVENTS = 10_000


def export_audit(
    log: AuditLog,
    *,
    tenant_id: str,
    run_id: str,
    start: int = 1,
    end: int | None = None,
) -> dict[str, object]:
    if (
        type(start) is not int
        or start < 1
        or (end is not None and (type(end) is not int or end < start))
    ):
        raise AuditConflict("audit export range is invalid")
    log.require_valid(tenant_id=tenant_id, run_id=run_id)
    head = log.head_sequence(tenant_id=tenant_id, run_id=run_id)
    upper_bound = head if end is None else min(end, head)
    if upper_bound >= start and upper_bound - start + 1 > MAX_AUDIT_EXPORT_EVENTS:
        raise ValueError("audit export range exceeds the event limit")
    events = log.range(tenant_id, run_id, start, end)
    document = {
        "tenant_id": tenant_id,
        "run_id": run_id,
        "range_start": start,
        "range_end": start + len(events) - 1 if events else start - 1,
        "chain_head": events[-1].event_hash if events else "0" * 64,
        "events": [asdict(event) for event in events],
        "authority": "NONE",
    }
    payload = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return {
        "manifest_sha256": hashlib.sha256(payload.encode("ascii")).hexdigest(),
        "document": document,
    }


__all__ = ["MAX_AUDIT_EXPORT_EVENTS", "export_audit"]
