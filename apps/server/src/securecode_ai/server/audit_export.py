"""Canonical audit export; output is evidence, never an authorization decision."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from .audit_log import AuditLog


def export_audit(
    log: AuditLog,
    *,
    tenant_id: str,
    run_id: str,
    start: int = 1,
    end: int | None = None,
) -> dict[str, object]:
    log.require_valid(tenant_id=tenant_id, run_id=run_id)
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
