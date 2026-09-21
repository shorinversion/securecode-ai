"""Immutable prompt and skill candidates for offline optimization only."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH: Final = re.compile(r"[0-9a-f]{64}\Z")
MAX_OPTIMIZATION_CONTENT_BYTES: Final = 32_768


class OptimizationCandidateError(ValueError):
    """Safe candidate-store error that excludes prompt and skill bytes."""

    def __init__(self) -> None:
        super().__init__("Optimization candidate request was rejected")
        self.__cause__ = None
        self.__context__ = None


class OptimizationActor(StrEnum):
    OPTIMIZER = "OPTIMIZER"
    PRODUCTION_AGENT = "PRODUCTION_AGENT"
    APPSEC_REVIEWER = "APPSEC_REVIEWER"
    PROMOTION_REVIEWER = "PROMOTION_REVIEWER"


class OptimizationCandidateKind(StrEnum):
    PROMPT = "PROMPT"
    SKILL = "SKILL"


class OptimizationCandidateDisposition(StrEnum):
    CREATED = "CREATED"
    IDEMPOTENT = "IDEMPOTENT"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True, slots=True)
class OptimizationCandidateSubmission:
    candidate_id: str
    version: int
    owner_id: str
    kind: OptimizationCandidateKind
    content: bytes

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (self.candidate_id, self.owner_id)
            )
            or type(self.version) is not int
            or self.version < 1
            or type(self.kind) is not OptimizationCandidateKind
            or type(self.content) is not bytes
            or not self.content
            or len(self.content) > MAX_OPTIMIZATION_CONTENT_BYTES
        ):
            raise OptimizationCandidateError()


@dataclass(frozen=True, slots=True)
class OptimizationCandidateHandle:
    candidate_key: str
    candidate_id: str
    version: int
    owner_id: str
    kind: OptimizationCandidateKind
    content_sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class OptimizationCandidateReceipt:
    disposition: OptimizationCandidateDisposition
    candidate: OptimizationCandidateHandle
    production_alias_updated: bool = False


class OptimizationCandidateStore:
    """Content-addressed versioned candidate metadata with no production alias API."""

    __slots__ = ("_by_id_version", "_by_key", "_lock")

    def __init__(self) -> None:
        self._by_id_version: dict[tuple[str, int], OptimizationCandidateHandle] = {}
        self._by_key: dict[str, OptimizationCandidateHandle] = {}
        self._lock = RLock()

    def submit(
        self,
        submission: OptimizationCandidateSubmission,
        *,
        actor: OptimizationActor,
    ) -> OptimizationCandidateReceipt:
        if (
            type(submission) is not OptimizationCandidateSubmission
            or actor is not OptimizationActor.OPTIMIZER
        ):
            raise OptimizationCandidateError()
        digest = hashlib.sha256(submission.content).hexdigest()
        handle = OptimizationCandidateHandle(
            "opt-candidate-"
            + hashlib.sha256(
                f"{submission.candidate_id}\x00{submission.version}\x00{digest}".encode("ascii")
            ).hexdigest()[:40],
            submission.candidate_id,
            submission.version,
            submission.owner_id,
            submission.kind,
            digest,
            len(submission.content),
        )
        key = (submission.candidate_id, submission.version)
        with self._lock:
            existing = self._by_id_version.get(key)
            if existing is None:
                self._by_id_version[key] = handle
                self._by_key[handle.candidate_key] = handle
                return OptimizationCandidateReceipt(
                    OptimizationCandidateDisposition.CREATED, handle
                )
            return OptimizationCandidateReceipt(
                OptimizationCandidateDisposition.IDEMPOTENT
                if existing == handle
                else OptimizationCandidateDisposition.CONFLICT,
                existing,
            )

    def resolve(self, candidate_key: str) -> OptimizationCandidateHandle:
        if type(candidate_key) is not str or _ID.fullmatch(candidate_key) is None:
            raise OptimizationCandidateError()
        with self._lock:
            try:
                return self._by_key[candidate_key]
            except KeyError:
                raise OptimizationCandidateError() from None


__all__ = [
    "MAX_OPTIMIZATION_CONTENT_BYTES",
    "OptimizationActor",
    "OptimizationCandidateDisposition",
    "OptimizationCandidateError",
    "OptimizationCandidateHandle",
    "OptimizationCandidateKind",
    "OptimizationCandidateReceipt",
    "OptimizationCandidateStore",
    "OptimizationCandidateSubmission",
]
