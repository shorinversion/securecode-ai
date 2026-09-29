"""Pilot-feedback and repository-assurance operations."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from .connected_runs import (
    ConnectedCollection,
    ConnectedRunSettings,
    ResultKind,
)
from .connected_transport import (
    ConnectedApi,
    ConnectedCliError,
    ConnectedCliErrorCode,
    HttpConnectedApi,
    _commit,
    _idempotency_key,
    _identifier,
    _version_precondition,
)
from .connected_validation import _sha256, _text

_ASSURANCE_PIN_NAMES = frozenset({"source", "policy", "dependency", "environment", "operational"})
_ASSURANCE_STALE_ORDER = ("source", "policy", "dependency", "environment", "operational")
_FEEDBACK_DECISIONS = frozenset({"accept", "reject"})
_FEEDBACK_REASONS = frozenset({"accepted_risk", "false_positive", "incident", "patch_rejected"})
_ASSURANCE_REPORT_KEYS = frozenset(
    {
        "tenant_id",
        "repository_id",
        "ledger_hashes",
        "pins",
        "stale_reasons",
        "complete",
        "content_sha256",
        "storage_ref",
        "authority",
    }
)
_ASSURANCE_RECORD_KEYS = frozenset(
    {
        "tenant_id",
        "repository_id",
        "execution_identity_hash",
        "record_id",
        "kind",
        "outcome",
        "verifier_id",
        "verifier_sha256",
        "sequence",
        "previous_hash",
        "record_hash",
    }
)
_ASSURANCE_INPUT_KEYS = frozenset(
    {
        "tenant_id",
        "repository_id",
        "execution_identity_hash",
        "records",
        "denominator",
        "successful",
        "failed_or_incomplete",
        "ledger_head_sha256",
        "complete",
        "authority",
    }
)


def _request_idempotency_key(
    settings: ConnectedRunSettings,
    *,
    operation: str,
    document: Mapping[str, object],
    if_match: str,
) -> str:
    try:
        material = json.dumps(
            {
                "document": document,
                "if_match": if_match,
                "operation": operation,
                "tenant_id": settings.tenant_id,
            },
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION) from None
    return "cli-" + hashlib.sha256(material).hexdigest()[:48]


@dataclass(frozen=True, slots=True)
class FeedbackDraft:
    """Operator-supplied review of one finding during a pilot."""

    repository_id: str
    run_id: str
    finding_id: str
    head_sha: str
    identity_hash: str
    decision: str
    reason: str
    rationale: str
    incident_id: str | None = None

    def __post_init__(self) -> None:
        for value in (
            self.repository_id,
            self.run_id,
            self.finding_id,
            self.decision,
            self.reason,
        ):
            if not _identifier(value) or len(value) > 256:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if not _commit(self.head_sha) or not _sha256(self.identity_hash):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if self.decision not in _FEEDBACK_DECISIONS or self.reason not in _FEEDBACK_REASONS:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if self.reason == "incident" and self.incident_id is None:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if not _text(self.rationale, maximum=1024):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if self.incident_id is not None and (
            not _identifier(self.incident_id) or len(self.incident_id) > 256
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)


def submit_feedback(
    settings: ConnectedRunSettings,
    draft: FeedbackDraft,
    *,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Record one reviewer decision and its reason for a finding."""

    if not _version_precondition(if_match, minimum=0, maximum=0):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    document: dict[str, object] = {
        "repository_id": draft.repository_id,
        "run_id": draft.run_id,
        "finding_id": draft.finding_id,
        "head_sha": draft.head_sha,
        "identity_hash": draft.identity_hash,
        "decision": draft.decision,
        "reason": draft.reason,
        "rationale": draft.rationale,
    }
    if draft.incident_id is not None:
        document["incident_id"] = draft.incident_id
    key = idempotency_key or _request_idempotency_key(
        settings,
        operation="feedback-submit",
        document=document,
        if_match=if_match,
    )
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    response = client.mutate(
        "/api/v1/feedback",
        document=document,
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    document = _validated_feedback_receipt(
        response,
        settings=settings,
        draft=draft,
    )
    return ConnectedCollection(run_id=draft.run_id, kind=ResultKind.FINDINGS, document=document)


def read_feedback_metrics(
    settings: ConnectedRunSettings,
    *,
    repository_id: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read the pilot feedback metrics the control plane aggregates."""

    selected_repository = settings.repository_id if repository_id is None else repository_id
    if not _identifier(selected_repository):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    query = {"repository_id": selected_repository}
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read(
        "/api/v1/feedback/metrics",
        token=settings.token,
        query=query or None,
    )
    safe_document = _validated_feedback_metrics(
        document,
        tenant_id=settings.tenant_id,
        repository_id=selected_repository,
    )
    return ConnectedCollection(run_id="feedback", kind=ResultKind.FINDINGS, document=safe_document)


def _validated_feedback_receipt(
    document: object,
    *,
    settings: ConnectedRunSettings,
    draft: FeedbackDraft,
) -> dict[str, object]:
    """Whitelist the durable feedback receipt before it reaches stdout."""

    fields = {
        "tenant_id",
        "repository_id",
        "run_id",
        "finding_id",
        "head_sha",
        "identity_hash",
        "decision",
        "reason",
        "rationale_sha256",
        "incident_id",
        "version",
        "receipt_sha256",
    }
    if not isinstance(document, Mapping) or set(document) != fields:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if (
        not _identifier(document.get("tenant_id"))
        or document.get("tenant_id") != settings.tenant_id
        or not _identifier(document.get("repository_id"))
        or document.get("repository_id") != draft.repository_id
        or not _identifier(document.get("run_id"))
        or document.get("run_id") != draft.run_id
        or not _identifier(document.get("finding_id"))
        or document.get("finding_id") != draft.finding_id
        or not _commit(document.get("head_sha"))
        or document.get("head_sha") != draft.head_sha
        or not _sha256(document.get("identity_hash"))
        or document.get("identity_hash") != draft.identity_hash
        or document.get("decision") not in _FEEDBACK_DECISIONS
        or document.get("decision") != draft.decision
        or document.get("reason") not in _FEEDBACK_REASONS
        or document.get("reason") != draft.reason
        or not _sha256(document.get("rationale_sha256"))
        or type(document.get("version")) is not int
        or document.get("version") != 1
        or not _sha256(document.get("receipt_sha256"))
        or document.get("incident_id") != draft.incident_id
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if document["reason"] == "incident" and not _identifier(document.get("incident_id")):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if document["incident_id"] is not None and not _identifier(document["incident_id"]):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return {name: document[name] for name in fields}


def _validated_feedback_metrics(
    document: object,
    *,
    tenant_id: str,
    repository_id: str,
) -> dict[str, object]:
    """Accept only the bounded, source-free feedback aggregate projection."""

    fields = {
        "tenant_id",
        "repository_id",
        "count",
        "accepted",
        "rejected",
        "incidents",
        "reason_counts",
        "receipt_hashes",
    }
    if not isinstance(document, Mapping) or set(document) != fields:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    count = document.get("count")
    accepted = document.get("accepted")
    rejected = document.get("rejected")
    incidents = document.get("incidents")
    if any(
        type(value) is not int or not 0 <= value <= 1_000_000
        for value in (count, accepted, rejected, incidents)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    count = cast(int, count)
    accepted = cast(int, accepted)
    rejected = cast(int, rejected)
    incidents = cast(int, incidents)
    if (
        document.get("tenant_id") != tenant_id
        or document.get("repository_id") != repository_id
        or not _identifier(tenant_id)
        or not _identifier(repository_id)
        or accepted + rejected != count
        or incidents > count
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    reason_counts = document.get("reason_counts")
    if (
        not isinstance(reason_counts, Mapping)
        or set(reason_counts) != _FEEDBACK_REASONS
        or any(
            type(value) is not int or not 0 <= value <= count for value in reason_counts.values()
        )
        or sum(cast(int, value) for value in reason_counts.values()) != count
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    receipt_hashes = document.get("receipt_hashes")
    if (
        type(receipt_hashes) is not list
        or len(receipt_hashes) != count
        or any(not _sha256(value) for value in receipt_hashes)
        or len(set(receipt_hashes)) != len(receipt_hashes)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return {
        "tenant_id": tenant_id,
        "repository_id": repository_id,
        "count": count,
        "accepted": accepted,
        "rejected": rejected,
        "incidents": incidents,
        "reason_counts": dict(reason_counts),
        "receipt_hashes": list(receipt_hashes),
    }


@dataclass(frozen=True, slots=True)
class AssuranceDraft:
    """Operator-supplied assurance record for one repository."""

    repository_id: str
    identity_hash: str
    verifier_sha256: str
    record_id: str
    kind: str
    outcome: str
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        for value in (self.repository_id, self.record_id, self.kind, self.outcome):
            if not _identifier(value) or len(value) > 256:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if not _sha256(self.identity_hash) or not _sha256(self.verifier_sha256):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if not isinstance(self.payload, Mapping) or not self.payload:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if len(self.payload) > 128:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)


def append_assurance(
    settings: ConnectedRunSettings,
    draft: AssuranceDraft,
    *,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Append one assurance record at an exact observed state."""

    if not _version_precondition(if_match, minimum=0):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    document: dict[str, object] = {
        "repository_id": draft.repository_id,
        "execution_identity_hash": draft.identity_hash,
        "verifier_sha256": draft.verifier_sha256,
        "record_id": draft.record_id,
        "kind": draft.kind,
        "outcome": draft.outcome,
        "payload": dict(draft.payload),
    }
    key = idempotency_key or _request_idempotency_key(
        settings,
        operation="assurance-append",
        document=document,
        if_match=if_match,
    )
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/assurance",
        document=document,
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    expected_sequence = _assurance_version(if_match) + 1
    safe_document = _validated_assurance_record(
        document,
        tenant_id=settings.tenant_id,
        repository_id=draft.repository_id,
        execution_identity_hash=draft.identity_hash,
        expected_sequence=expected_sequence,
    )
    return ConnectedCollection(
        run_id=draft.repository_id, kind=ResultKind.FINDINGS, document=safe_document
    )


def read_assurance(
    settings: ConnectedRunSettings,
    *,
    repository_id: str,
    execution_identity_hash: str,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read assurance records for one exact repository and execution identity."""

    if not _identifier(repository_id) or not _sha256(execution_identity_hash):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    query = {
        "repository_id": repository_id,
        "execution_identity_hash": execution_identity_hash,
    }
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read("/api/v1/assurance", token=settings.token, query=query)
    safe_document = _validated_assurance_inputs(
        document,
        tenant_id=settings.tenant_id,
        repository_id=repository_id,
        execution_identity_hash=execution_identity_hash,
    )
    return ConnectedCollection(run_id="assurance", kind=ResultKind.FINDINGS, document=safe_document)


def _assurance_version(value: str) -> int:
    if value.startswith('W/"') and value.endswith('"'):
        value = value[3:-1]
    elif value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return int(value)


def _validated_assurance_record(
    document: object,
    *,
    tenant_id: str,
    repository_id: str,
    execution_identity_hash: str,
    expected_sequence: int | None = None,
) -> dict[str, object]:
    if (
        not isinstance(document, Mapping)
        or frozenset(document) != _ASSURANCE_RECORD_KEYS
        or document.get("tenant_id") != tenant_id
        or document.get("repository_id") != repository_id
        or document.get("execution_identity_hash") != execution_identity_hash
        or not _identifier(document.get("record_id"))
        or not _identifier(document.get("kind"))
        or not _identifier(document.get("outcome"))
        or not _identifier(document.get("verifier_id"))
        or not _sha256(document.get("verifier_sha256"))
        or type(document.get("sequence")) is not int
        or not 1 <= document["sequence"] <= 2_147_483_647
        or not _sha256(document.get("previous_hash"))
        or not _sha256(document.get("record_hash"))
        or (expected_sequence is not None and document["sequence"] != expected_sequence)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return {name: document[name] for name in _ASSURANCE_RECORD_KEYS}


def _validated_assurance_inputs(
    document: object,
    *,
    tenant_id: str,
    repository_id: str,
    execution_identity_hash: str,
) -> dict[str, object]:
    if (
        not isinstance(document, Mapping)
        or frozenset(document) != _ASSURANCE_INPUT_KEYS
        or document.get("tenant_id") != tenant_id
        or document.get("repository_id") != repository_id
        or document.get("execution_identity_hash") != execution_identity_hash
        or document.get("authority") != "SUPPORTING_EVIDENCE_ONLY"
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    records = document.get("records")
    if type(records) is not list or len(records) > 10_000:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    safe_records = [
        _validated_assurance_record(
            record,
            tenant_id=tenant_id,
            repository_id=repository_id,
            execution_identity_hash=execution_identity_hash,
        )
        for record in records
    ]
    for index, record in enumerate(safe_records, start=1):
        previous_hash = "0" * 64 if index == 1 else safe_records[index - 2]["record_hash"]
        if record["sequence"] != index or record["previous_hash"] != previous_hash:
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    denominator = document.get("denominator")
    successful = document.get("successful")
    failed = document.get("failed_or_incomplete")
    if (
        any(
            type(value) is not int or not 0 <= value <= 10_000
            for value in (denominator, successful, failed)
        )
        or denominator != len(safe_records)
        or type(successful) is not int
        or type(failed) is not int
        or successful + failed != denominator
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    ledger_head = document.get("ledger_head_sha256")
    expected_head = safe_records[-1]["record_hash"] if safe_records else "0" * 64
    if ledger_head != expected_head or not _sha256(ledger_head):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    complete = document.get("complete")
    if type(complete) is not bool or complete != (bool(safe_records) and failed == 0):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return {
        "tenant_id": tenant_id,
        "repository_id": repository_id,
        "execution_identity_hash": execution_identity_hash,
        "records": safe_records,
        "denominator": denominator,
        "successful": successful,
        "failed_or_incomplete": failed,
        "ledger_head_sha256": ledger_head,
        "complete": complete,
        "authority": "SUPPORTING_EVIDENCE_ONLY",
    }


def read_assurance_report(
    settings: ConnectedRunSettings,
    *,
    repository_id: str,
    execution_identity_hash: str,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read one server-generated assurance report without accepting client pins."""

    if not _identifier(repository_id) or not _sha256(execution_identity_hash):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    query = {
        "repository_id": repository_id,
        "execution_identity_hash": execution_identity_hash,
        "view": "report",
    }
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read("/api/v1/assurance", token=settings.token, query=query)
    if not _valid_assurance_report(
        document,
        tenant_id=settings.tenant_id,
        repository_id=repository_id,
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return ConnectedCollection(run_id="assurance", kind=ResultKind.FINDINGS, document=document)


def _valid_assurance_report(
    document: object,
    *,
    tenant_id: str,
    repository_id: str,
) -> bool:
    """Accept only the source-free, canonical report projection."""

    if (
        not isinstance(document, Mapping)
        or set(document) != _ASSURANCE_REPORT_KEYS
        or document.get("tenant_id") != tenant_id
        or document.get("repository_id") != repository_id
        or document.get("authority") != "NONE"
        or type(document.get("complete")) is not bool
        or not _sha256(document.get("content_sha256"))
    ):
        return False
    ledger_hashes = document.get("ledger_hashes")
    if (
        type(ledger_hashes) is not list
        or len(ledger_hashes) > 4096
        or any(not _sha256(value) for value in ledger_hashes)
        or len(set(ledger_hashes)) != len(ledger_hashes)
        or ledger_hashes != sorted(ledger_hashes)
    ):
        return False
    pins = document.get("pins")
    if (
        not isinstance(pins, Mapping)
        or set(pins) != _ASSURANCE_PIN_NAMES
        or any(not _text(pins.get(name), maximum=256) for name in _ASSURANCE_PIN_NAMES)
    ):
        return False
    stale_reasons = document.get("stale_reasons")
    if (
        type(stale_reasons) is not list
        or any(
            type(reason) is not str or reason not in _ASSURANCE_PIN_NAMES
            for reason in stale_reasons
        )
        or len(set(stale_reasons)) != len(stale_reasons)
        or stale_reasons != [reason for reason in _ASSURANCE_STALE_ORDER if reason in stale_reasons]
        or document.get("complete") != (bool(ledger_hashes) and not stale_reasons)
    ):
        return False
    storage_ref = document.get("storage_ref")
    return storage_ref is None or _text(storage_ref, maximum=512)
