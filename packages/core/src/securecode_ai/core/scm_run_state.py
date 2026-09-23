"""Fail-closed, SHA-bound in-memory state for SCM workflow runs.

The state belongs behind an authenticated SCM adapter.  Callers supply a fresh
authoritative source head on every admission and publication decision; this
module neither resolves branches nor performs SCM writes.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final

from securecode_ai.contracts import AuditRunOutcome, RunExecutionIdentity

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/scm-run-state/v1\x00"


class SCMRunStateErrorCode(StrEnum):
    """Stable bounded reasons for fail-closed SCM run-state rejection."""

    INVALID_REQUEST = "INVALID_REQUEST"
    DELIVERY_CONFLICT = "DELIVERY_CONFLICT"
    SEMANTIC_CONFLICT = "SEMANTIC_CONFLICT"
    RUN_UNKNOWN = "RUN_UNKNOWN"
    TRANSITION_CONFLICT = "TRANSITION_CONFLICT"


class SCMRunStateError(ValueError):
    """Metadata-only boundary error that never includes repository content."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: SCMRunStateErrorCode) -> None:
        if type(code) is not SCMRunStateErrorCode:
            raise TypeError("SCM run-state error code is invalid")
        self.code = code
        self.safe_message = "SCM run-state request was rejected"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class SCMRunLifecycle(StrEnum):
    """Monotonic local lifecycle; a superseded run cannot regain authority."""

    ADMITTED = "ADMITTED"
    COMPLETED = "COMPLETED"
    SUPERSEDED = "SUPERSEDED"


class AdmissionDisposition(StrEnum):
    ADMITTED = "ADMITTED"
    DUPLICATE = "DUPLICATE"
    SUPERSEDED = "SUPERSEDED"


class PublicationDisposition(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    COMPLETED = "COMPLETED"
    DUPLICATE = "DUPLICATE"
    SUPERSEDED = "SUPERSEDED"


@dataclass(frozen=True, slots=True)
class SCMRunAdmissionRequest:
    """Authenticated-delivery metadata after exact revision verification."""

    delivery_id: str
    installation_id: str
    execution_identity: RunExecutionIdentity
    authorized_head_sha: str

    def __post_init__(self) -> None:
        if (
            type(self.delivery_id) is not str
            or _ID.fullmatch(self.delivery_id) is None
            or type(self.installation_id) is not str
            or _ID.fullmatch(self.installation_id) is None
            or type(self.execution_identity) is not RunExecutionIdentity
            or type(self.authorized_head_sha) is not str
            or _COMMIT_SHA.fullmatch(self.authorized_head_sha) is None
            or self.authorized_head_sha != self.execution_identity.repository_revision.head_sha
        ):
            raise SCMRunStateError(SCMRunStateErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class SCMRunAdmissionReceipt:
    """Idempotent admission result; contains metadata only."""

    disposition: AdmissionDisposition
    run_id: str
    execution_identity_hash: str
    head_sha: str
    lifecycle: SCMRunLifecycle
    state_version: int
    superseded_run_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SCMRunPublicationReceipt:
    """Exact-HEAD publication authorization or durable supersession receipt."""

    disposition: PublicationDisposition
    run_id: str
    execution_identity_hash: str
    head_sha: str
    current_head_sha: str
    lifecycle: SCMRunLifecycle
    outcome: AuditRunOutcome | None
    state_version: int


@dataclass(slots=True)
class _RunRecord:
    installation_id: str
    execution_identity: RunExecutionIdentity
    lifecycle: SCMRunLifecycle
    outcome: AuditRunOutcome | None
    state_version: int


class SCMRunState:
    """Bounded process-local state for delivery deduplication and stale-run control."""

    __slots__ = (
        "_deliveries",
        "_lock",
        "_repository_heads",
        "_runs",
        "_semantic_runs",
        "_stale_delivery_receipts",
    )

    def __init__(self) -> None:
        self._lock = RLock()
        self._deliveries: dict[str, tuple[str, str]] = {}
        self._stale_delivery_receipts: dict[str, SCMRunAdmissionReceipt] = {}
        self._repository_heads: dict[tuple[str, str, str], str] = {}
        self._semantic_runs: dict[tuple[str, str, str, str], str] = {}
        self._runs: dict[str, _RunRecord] = {}

    def admit(
        self,
        request: SCMRunAdmissionRequest,
        *,
        current_head_sha: str,
    ) -> SCMRunAdmissionReceipt:
        """Admit exactly one semantic run or return its duplicate receipt.

        ``current_head_sha`` must be freshly obtained by the authenticated
        adapter from the SCM source of truth.  A mismatch creates no new run.
        """

        if type(request) is not SCMRunAdmissionRequest or not _is_commit_sha(current_head_sha):
            raise SCMRunStateError(SCMRunStateErrorCode.INVALID_REQUEST)
        with self._lock:
            material_hash = _admission_hash(request)
            recorded_delivery = self._deliveries.get(request.delivery_id)
            if recorded_delivery is not None:
                delivery_hash, recorded_run_id = recorded_delivery
                if delivery_hash != material_hash:
                    raise SCMRunStateError(SCMRunStateErrorCode.DELIVERY_CONFLICT)
                stale_receipt = self._stale_delivery_receipts.get(request.delivery_id)
                if stale_receipt is not None:
                    return stale_receipt
                return self._admission_receipt(
                    AdmissionDisposition.DUPLICATE,
                    recorded_run_id,
                    (),
                )
            scope = _repository_scope(request)
            self._repository_heads[scope] = current_head_sha
            if current_head_sha != request.authorized_head_sha:
                receipt = SCMRunAdmissionReceipt(
                    disposition=AdmissionDisposition.SUPERSEDED,
                    run_id=_run_id(_semantic_key(request)),
                    execution_identity_hash=request.execution_identity.execution_identity_hash,
                    head_sha=request.authorized_head_sha,
                    lifecycle=SCMRunLifecycle.SUPERSEDED,
                    state_version=0,
                )
                self._deliveries[request.delivery_id] = (material_hash, receipt.run_id)
                self._stale_delivery_receipts[request.delivery_id] = receipt
                return receipt
            semantic_key = _semantic_key(request)
            existing_run_id = self._semantic_runs.get(semantic_key)
            if existing_run_id is not None:
                existing = self._runs[existing_run_id]
                if existing.execution_identity != request.execution_identity:
                    raise SCMRunStateError(SCMRunStateErrorCode.SEMANTIC_CONFLICT)
                self._deliveries[request.delivery_id] = (material_hash, existing_run_id)
                return self._admission_receipt(AdmissionDisposition.DUPLICATE, existing_run_id, ())
            superseded = self._supersede_other_heads(scope, current_head_sha)
            run_id = _run_id(semantic_key)
            self._runs[run_id] = _RunRecord(
                installation_id=request.installation_id,
                execution_identity=request.execution_identity,
                lifecycle=SCMRunLifecycle.ADMITTED,
                outcome=None,
                state_version=1,
            )
            self._semantic_runs[semantic_key] = run_id
            self._deliveries[request.delivery_id] = (material_hash, run_id)
            return self._admission_receipt(AdmissionDisposition.ADMITTED, run_id, superseded)

    def authorize_publication(
        self,
        run_id: str,
        *,
        current_head_sha: str,
    ) -> SCMRunPublicationReceipt:
        """Authorize publication only for a still-current, nonterminal run."""

        record = self._record(run_id, current_head_sha)
        with self._lock:
            record = self._runs[run_id]
            current = self._observe_current_head(record, current_head_sha)
            if current != record.execution_identity.repository_revision.head_sha:
                self._supersede(record)
            if record.lifecycle is SCMRunLifecycle.SUPERSEDED:
                return _publication_receipt(
                    PublicationDisposition.SUPERSEDED, run_id, record, current
                )
            if record.lifecycle is SCMRunLifecycle.COMPLETED:
                raise SCMRunStateError(SCMRunStateErrorCode.TRANSITION_CONFLICT)
            return _publication_receipt(PublicationDisposition.AUTHORIZED, run_id, record, current)

    def complete(
        self,
        run_id: str,
        outcome: AuditRunOutcome,
        *,
        current_head_sha: str,
    ) -> SCMRunPublicationReceipt:
        """Record one terminal outcome after an exact-HEAD publication check."""

        if type(outcome) is not AuditRunOutcome or outcome is AuditRunOutcome.SUPERSEDED:
            raise SCMRunStateError(SCMRunStateErrorCode.INVALID_REQUEST)
        self._record(run_id, current_head_sha)
        with self._lock:
            record = self._runs[run_id]
            current = self._observe_current_head(record, current_head_sha)
            if current != record.execution_identity.repository_revision.head_sha:
                self._supersede(record)
            if record.lifecycle is SCMRunLifecycle.SUPERSEDED:
                return _publication_receipt(
                    PublicationDisposition.SUPERSEDED, run_id, record, current
                )
            if record.lifecycle is SCMRunLifecycle.COMPLETED:
                if record.outcome is not outcome:
                    raise SCMRunStateError(SCMRunStateErrorCode.TRANSITION_CONFLICT)
                return _publication_receipt(
                    PublicationDisposition.DUPLICATE, run_id, record, current
                )
            record.lifecycle = SCMRunLifecycle.COMPLETED
            record.outcome = outcome
            record.state_version += 1
            return _publication_receipt(PublicationDisposition.COMPLETED, run_id, record, current)

    def _record(self, run_id: str, current_head_sha: str) -> _RunRecord:
        if (
            type(run_id) is not str
            or _ID.fullmatch(run_id) is None
            or not _is_commit_sha(current_head_sha)
        ):
            raise SCMRunStateError(SCMRunStateErrorCode.INVALID_REQUEST)
        with self._lock:
            try:
                return self._runs[run_id]
            except KeyError as error:
                raise SCMRunStateError(SCMRunStateErrorCode.RUN_UNKNOWN) from error

    def _observe_current_head(self, record: _RunRecord, current_head_sha: str) -> str:
        revision = record.execution_identity.repository_revision
        scope = (revision.tenant_id, record.installation_id, revision.repository_id)
        self._repository_heads[scope] = current_head_sha
        return current_head_sha

    def _supersede_other_heads(
        self,
        scope: tuple[str, str, str],
        current_head_sha: str,
    ) -> tuple[str, ...]:
        superseded: list[str] = []
        for run_id, record in self._runs.items():
            revision = record.execution_identity.repository_revision
            record_scope = (revision.tenant_id, record.installation_id, revision.repository_id)
            if (
                record_scope == scope
                and revision.head_sha != current_head_sha
                and record.lifecycle is not SCMRunLifecycle.SUPERSEDED
            ):
                self._supersede(record)
                superseded.append(run_id)
        return tuple(sorted(superseded))

    @staticmethod
    def _supersede(record: _RunRecord) -> None:
        if record.lifecycle is SCMRunLifecycle.SUPERSEDED:
            return
        record.lifecycle = SCMRunLifecycle.SUPERSEDED
        record.outcome = AuditRunOutcome.SUPERSEDED
        record.state_version += 1

    def _admission_receipt(
        self,
        disposition: AdmissionDisposition,
        run_id: str,
        superseded: tuple[str, ...],
    ) -> SCMRunAdmissionReceipt:
        record = self._runs[run_id]
        identity = record.execution_identity
        return SCMRunAdmissionReceipt(
            disposition=disposition,
            run_id=run_id,
            execution_identity_hash=identity.execution_identity_hash,
            head_sha=identity.repository_revision.head_sha,
            lifecycle=record.lifecycle,
            state_version=record.state_version,
            superseded_run_ids=superseded,
        )


def _is_commit_sha(value: object) -> bool:
    return type(value) is str and _COMMIT_SHA.fullmatch(value) is not None


def _repository_scope(request: SCMRunAdmissionRequest) -> tuple[str, str, str]:
    revision = request.execution_identity.repository_revision
    return (revision.tenant_id, request.installation_id, revision.repository_id)


def _semantic_key(request: SCMRunAdmissionRequest) -> tuple[str, str, str, str]:
    revision = request.execution_identity.repository_revision
    return (
        revision.tenant_id,
        request.installation_id,
        revision.repository_id,
        request.execution_identity.execution_identity_hash,
    )


def _admission_hash(request: SCMRunAdmissionRequest) -> str:
    return _hash(
        {
            "authorized_head_sha": request.authorized_head_sha,
            "execution_identity": request.execution_identity.model_dump(mode="json"),
            "installation_id": request.installation_id,
        }
    )


def _run_id(semantic_key: tuple[str, str, str, str]) -> str:
    return "scm-run-" + _hash({"semantic_key": semantic_key})[:40]


def _hash(material: dict[str, object]) -> str:
    payload = json.dumps(
        material,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(_HASH_DOMAIN + payload).hexdigest()


def _publication_receipt(
    disposition: PublicationDisposition,
    run_id: str,
    record: _RunRecord,
    current_head_sha: str,
) -> SCMRunPublicationReceipt:
    identity = record.execution_identity
    return SCMRunPublicationReceipt(
        disposition=disposition,
        run_id=run_id,
        execution_identity_hash=identity.execution_identity_hash,
        head_sha=identity.repository_revision.head_sha,
        current_head_sha=current_head_sha,
        lifecycle=record.lifecycle,
        outcome=record.outcome,
        state_version=record.state_version,
    )


__all__ = [
    "AdmissionDisposition",
    "PublicationDisposition",
    "SCMRunAdmissionReceipt",
    "SCMRunAdmissionRequest",
    "SCMRunLifecycle",
    "SCMRunPublicationReceipt",
    "SCMRunState",
    "SCMRunStateError",
    "SCMRunStateErrorCode",
]
