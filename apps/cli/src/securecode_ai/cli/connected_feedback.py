"""Pilot-feedback and repository-assurance operations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .connected_runs import (
    ConnectedCollection,
    ConnectedRunSettings,
    ResultKind,
    new_idempotency_key,
)
from .connected_transport import (
    ConnectedApi,
    ConnectedCliError,
    ConnectedCliErrorCode,
    HttpConnectedApi,
    _commit,
    _idempotency_key,
    _identifier,
    _precondition,
)
from .connected_validation import _sha256, _text


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

    if not _precondition(if_match):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
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
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    response = client.mutate(
        "/api/v1/feedback",
        document=document,
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    return ConnectedCollection(run_id=draft.run_id, kind=ResultKind.FINDINGS, document=response)


def read_feedback_metrics(
    settings: ConnectedRunSettings,
    *,
    repository_id: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read the pilot feedback metrics the control plane aggregates."""

    query: dict[str, str] = {}
    if repository_id is not None:
        if not _identifier(repository_id):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        query["repository_id"] = repository_id
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read(
        "/api/v1/feedback/metrics",
        token=settings.token,
        query=query or None,
    )
    return ConnectedCollection(run_id="feedback", kind=ResultKind.FINDINGS, document=document)


@dataclass(frozen=True, slots=True)
class AssuranceDraft:
    """Operator-supplied assurance record for one repository."""

    repository_id: str
    identity_hash: str
    record_id: str
    kind: str
    outcome: str
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        for value in (self.repository_id, self.record_id, self.kind, self.outcome):
            if not _identifier(value) or len(value) > 256:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if not _sha256(self.identity_hash):
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

    if not _precondition(if_match):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/assurance",
        document={
            "repository_id": draft.repository_id,
            "execution_identity_hash": draft.identity_hash,
            "record_id": draft.record_id,
            "kind": draft.kind,
            "outcome": draft.outcome,
            "payload": dict(draft.payload),
        },
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    return ConnectedCollection(
        run_id=draft.repository_id, kind=ResultKind.FINDINGS, document=document
    )


def read_assurance(
    settings: ConnectedRunSettings,
    *,
    repository_id: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read the assurance records and failure summary for a repository."""

    query: dict[str, str] = {}
    if repository_id is not None:
        if not _identifier(repository_id):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        query["repository_id"] = repository_id
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read("/api/v1/assurance", token=settings.token, query=query or None)
    return ConnectedCollection(run_id="assurance", kind=ResultKind.FINDINGS, document=document)
