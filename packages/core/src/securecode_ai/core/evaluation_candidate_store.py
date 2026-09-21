"""Immutable content-addressed candidate storage for the Evaluation Lab."""

from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final

from .evaluation_access import (
    EvaluationAccessAuthority,
    EvaluationAccessGrant,
    EvaluationCapability,
    EvaluationRole,
    require_access,
)

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH: Final = re.compile(r"[0-9a-f]{64}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/evaluation-candidate/v1\x00"
MAX_CANDIDATE_BYTES: Final = 65_536


class EvaluationCandidateStoreError(ValueError):
    """Safe candidate-store error that never includes candidate bytes."""

    def __init__(self) -> None:
        super().__init__("Evaluation candidate store request was rejected")
        self.__cause__ = None
        self.__context__ = None


class CandidateStoreDisposition(StrEnum):
    CREATED = "CREATED"
    IDEMPOTENT = "IDEMPOTENT"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True, slots=True)
class EvaluationCandidateSubmission:
    """Immutable candidate bytes plus source-free lineage metadata."""

    candidate_id: str
    submitted_by: str
    lineage_sha256: str
    content: bytes

    def __post_init__(self) -> None:
        if (
            type(self.candidate_id) is not str
            or _ID.fullmatch(self.candidate_id) is None
            or type(self.submitted_by) is not str
            or _ID.fullmatch(self.submitted_by) is None
            or type(self.lineage_sha256) is not str
            or _HASH.fullmatch(self.lineage_sha256) is None
            or type(self.content) is not bytes
            or not self.content
            or len(self.content) > MAX_CANDIDATE_BYTES
        ):
            raise EvaluationCandidateStoreError()


@dataclass(frozen=True, slots=True)
class EvaluationCandidateHandle:
    """Content-addressed metadata exposed to the optimizer and Evaluation Lab."""

    candidate_key: str
    candidate_id: str
    submitted_by: str
    lineage_sha256: str
    content_sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class CandidateStoreReceipt:
    disposition: CandidateStoreDisposition
    candidate: EvaluationCandidateHandle


@dataclass(frozen=True, slots=True)
class _StoredCandidate:
    handle: EvaluationCandidateHandle
    content: bytes


class EvaluationCandidateStore:
    """Append-only in-memory candidate store with idempotent content identity."""

    __slots__ = ("_access_authority", "_by_id", "_by_key", "_lock")

    def __init__(self, access_authority: EvaluationAccessAuthority) -> None:
        if type(access_authority) is not EvaluationAccessAuthority:
            raise EvaluationCandidateStoreError()
        self._access_authority = access_authority
        self._by_id: dict[str, _StoredCandidate] = {}
        self._by_key: dict[str, _StoredCandidate] = {}
        self._lock = RLock()

    def submit(
        self,
        submission: EvaluationCandidateSubmission,
        *,
        role: EvaluationRole,
        actor_id: str,
        access_grant: EvaluationAccessGrant,
    ) -> CandidateStoreReceipt:
        if (
            type(submission) is not EvaluationCandidateSubmission
            or type(role) is not EvaluationRole
            or type(actor_id) is not str
        ):
            raise EvaluationCandidateStoreError()
        digest = hashlib.sha256(submission.content).hexdigest()
        candidate_key = _candidate_key(submission, digest)
        require_access(
            self._access_authority,
            access_grant,
            capability=EvaluationCapability.SUBMIT_CANDIDATE,
            actor_id=actor_id,
            candidate_key=candidate_key,
            dataset_id=None,
            dataset_sha256=None,
            run_id=None,
        )
        if access_grant.role is not role or submission.submitted_by != actor_id:
            raise EvaluationCandidateStoreError()
        handle = EvaluationCandidateHandle(
            candidate_key=candidate_key,
            candidate_id=submission.candidate_id,
            submitted_by=submission.submitted_by,
            lineage_sha256=submission.lineage_sha256,
            content_sha256=digest,
            size_bytes=len(submission.content),
        )
        with self._lock:
            existing = self._by_id.get(submission.candidate_id)
            if existing is not None:
                disposition = (
                    CandidateStoreDisposition.IDEMPOTENT
                    if existing.handle == handle and existing.content == submission.content
                    else CandidateStoreDisposition.CONFLICT
                )
                return CandidateStoreReceipt(disposition, deepcopy(existing.handle))
            stored = _StoredCandidate(handle, bytes(submission.content))
            self._by_id[submission.candidate_id] = stored
            self._by_key[handle.candidate_key] = stored
            return CandidateStoreReceipt(CandidateStoreDisposition.CREATED, deepcopy(handle))

    def resolve(self, candidate_key: str) -> EvaluationCandidateHandle:
        """Expose immutable metadata only. Candidate bytes stay store-private."""

        if type(candidate_key) is not str or _ID.fullmatch(candidate_key) is None:
            raise EvaluationCandidateStoreError()
        with self._lock:
            try:
                return deepcopy(self._by_key[candidate_key].handle)
            except KeyError:
                raise EvaluationCandidateStoreError() from None


def _digest(candidate_id: str, lineage_sha256: str, content_sha256: str) -> str:
    material = "\x00".join((candidate_id, lineage_sha256, content_sha256)).encode("ascii")
    return hashlib.sha256(_HASH_DOMAIN + material).hexdigest()


def evaluation_candidate_key(submission: EvaluationCandidateSubmission) -> str:
    """Return the exact content-bound key an access authority must grant."""

    if type(submission) is not EvaluationCandidateSubmission:
        raise EvaluationCandidateStoreError()
    digest = hashlib.sha256(submission.content).hexdigest()
    return _candidate_key(submission, digest)


def _candidate_key(submission: EvaluationCandidateSubmission, content_sha256: str) -> str:
    return (
        "candidate-"
        + _digest(submission.candidate_id, submission.lineage_sha256, content_sha256)[:40]
    )


__all__ = [
    "MAX_CANDIDATE_BYTES",
    "CandidateStoreDisposition",
    "CandidateStoreReceipt",
    "EvaluationCandidateHandle",
    "EvaluationCandidateStore",
    "EvaluationCandidateStoreError",
    "EvaluationCandidateSubmission",
    "evaluation_candidate_key",
]
