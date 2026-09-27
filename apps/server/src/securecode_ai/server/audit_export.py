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
    head = log.head_sequence(tenant_id=tenant_id, run_id=run_id)
    if start > head and not (head == 0 and start == 1 and end is None):
        raise AuditConflict("audit export range exceeds the audit head")
    if end is not None and end > head:
        raise AuditConflict("audit export range exceeds the audit head")
    # An omitted end is a request for the next bounded page, rather than an
    # instruction to materialize the entire chain in one response.
    bounded_end = (
        None
        if end is None and head == 0
        else min(head, start + MAX_AUDIT_EXPORT_EVENTS - 1)
        if end is None
        else end
    )
    events = log.verified_range(
        tenant_id=tenant_id,
        run_id=run_id,
        start=start,
        end=bounded_end,
        maximum_events=MAX_AUDIT_EXPORT_EVENTS,
    )
    range_end = start + len(events) - 1 if events else start - 1
    # Capture the current head after the verified page.  The chain is
    # append-only, so a concurrent append can only move this value forward;
    # it cannot invalidate the already verified page.  Returning the snapshot
    # head gives callers a safe cursor for the next bounded request instead of
    # making them guess whether another page exists.
    snapshot_head = log.head_sequence(tenant_id=tenant_id, run_id=run_id)
    if snapshot_head < range_end:
        # A durable audit head must never move backwards. Treat a concurrent
        # deletion or rewrite as an invalid evidence snapshot instead of
        # returning a page whose cursor no longer describes the chain.
        raise AuditConflict("audit head changed during export")
    has_more = snapshot_head > range_end
    document = {
        "tenant_id": tenant_id,
        "run_id": run_id,
        "range_start": start,
        "range_end": range_end,
        "head_sequence": snapshot_head,
        "has_more": has_more,
        "next_start": range_end + 1 if has_more else None,
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


def export_resource_audit(
    log: AuditLog,
    *,
    tenant_id: str,
    resource_type: str,
    resource_key_sha256: str,
    resource_scope: str,
    start: int = 1,
    end: int | None = None,
    maximum_events: int = MAX_AUDIT_EXPORT_EVENTS,
) -> dict[str, object]:
    if (
        type(start) is not int
        or start < 1
        or (end is not None and (type(end) is not int or end < start))
        or type(maximum_events) is not int
        or not 1 <= maximum_events <= MAX_AUDIT_EXPORT_EVENTS
        or resource_scope not in {"tenant", "resource"}
    ):
        raise AuditConflict("resource audit export range is invalid")
    head = log.resource_head_sequence(
        tenant_id=tenant_id,
        resource_type=resource_type,
        resource_key_sha256=resource_key_sha256,
    )
    if start > head or (end is not None and end > head):
        raise AuditConflict("resource audit export range exceeds the audit head")
    bounded_end = (
        None
        if end is None and head == 0
        else min(head, start + maximum_events - 1)
        if end is None
        else end
    )
    events = log.verified_resource_range(
        tenant_id=tenant_id,
        resource_type=resource_type,
        resource_key_sha256=resource_key_sha256,
        start=start,
        end=bounded_end,
        maximum_events=maximum_events,
    )
    range_end = start + len(events) - 1 if events else start - 1
    snapshot_head = log.resource_head_sequence(
        tenant_id=tenant_id,
        resource_type=resource_type,
        resource_key_sha256=resource_key_sha256,
    )
    if snapshot_head < range_end:
        raise AuditConflict("resource audit head changed during export")
    has_more = snapshot_head > range_end
    document = {
        "tenant_id": tenant_id,
        "resource_type": resource_type,
        "resource_scope": resource_scope,
        "resource_key_sha256": resource_key_sha256,
        "range_start": start,
        "range_end": range_end,
        "head_sequence": snapshot_head,
        "has_more": has_more,
        "next_start": range_end + 1 if has_more else None,
        "chain_head": events[-1].event_hash if events else "0" * 64,
        "events": [asdict(event) for event in events],
        "authority": "NONE",
    }
    payload = json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return {
        "manifest_sha256": hashlib.sha256(payload.encode("ascii")).hexdigest(),
        "document": document,
    }


__all__ = ["MAX_AUDIT_EXPORT_EVENTS", "export_audit", "export_resource_audit"]
