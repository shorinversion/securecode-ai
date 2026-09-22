"""Closed worker-side models for the connected control-plane protocol."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Final

from securecode_ai.contracts import ArtifactRef, DataClass, RunExecutionIdentity

from .usage import WorkerResourceUsage

_OPAQUE_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")


class ProtocolError(ValueError):
    """A safe, non-echoing control-plane protocol failure."""


class WorkerCommand(StrEnum):
    CONTINUE = "CONTINUE"
    CANCEL = "CANCEL"
    SUPERSEDE = "SUPERSEDE"


@dataclass(frozen=True, slots=True)
class WorkerJob:
    session_id: str
    run_id: str
    version: int
    lease_seconds: int
    command: WorkerCommand
    execution_identity: RunExecutionIdentity

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> WorkerJob:
        allowed = {
            "schema_version",
            "session_id",
            "run_id",
            "version",
            "lease_seconds",
            "command",
            "execution_identity",
            "execution_identity_hash",
        }
        if set(document) - allowed:
            raise ProtocolError("worker job is invalid")
        try:
            session_id = document["session_id"]
            run_id = document["run_id"]
            version = document["version"]
            lease_seconds = document.get("lease_seconds", 30)
            command_value = document.get("command", WorkerCommand.CONTINUE.value)
            if type(command_value) is not str:
                raise ProtocolError("worker job is invalid")
            command = WorkerCommand(command_value)
            identity_document = document["execution_identity"]
            if not isinstance(identity_document, Mapping):
                raise ProtocolError("worker job is invalid")
            identity = RunExecutionIdentity.model_validate(dict(identity_document))
            identity_hash = document.get(
                "execution_identity_hash", identity.execution_identity_hash
            )
        except (KeyError, TypeError, ValueError):
            raise ProtocolError("worker job is invalid") from None
        if (
            type(session_id) is not str
            or _OPAQUE_ID.fullmatch(session_id) is None
            or type(run_id) is not str
            or _OPAQUE_ID.fullmatch(run_id) is None
            or type(version) is not int
            or version < 1
            or type(lease_seconds) is not int
            or not 5 <= lease_seconds <= 3600
            or type(identity_hash) is not str
            or _SHA256.fullmatch(identity_hash) is None
            or identity_hash != identity.execution_identity_hash
        ):
            raise ProtocolError("worker job is invalid")
        return cls(session_id, run_id, version, lease_seconds, command, identity)


@dataclass(frozen=True, slots=True)
class WorkerEvent:
    event_id: str
    sequence: int
    event_hash: str
    kind: str

    @classmethod
    def build(
        cls,
        *,
        run_id: str,
        execution_identity_hash: str,
        sequence: int,
        kind: str,
    ) -> WorkerEvent:
        if (
            _OPAQUE_ID.fullmatch(run_id) is None
            or _SHA256.fullmatch(execution_identity_hash) is None
            or type(sequence) is not int
            or sequence < 1
            or kind
            not in {
                "RUN_STARTED",
                "RUN_COMPLETED",
                "RUN_CANCELLED",
                "RUN_SUPERSEDED",
                "RUN_FAILED",
            }
        ):
            raise ProtocolError("worker event is invalid")
        material = {
            "execution_identity_hash": execution_identity_hash,
            "kind": kind,
            "run_id": run_id,
            "sequence": sequence,
        }
        digest = _canonical_sha256(material)
        return cls(
            event_id=f"worker-{sequence}-{digest[:32]}",
            sequence=sequence,
            event_hash=digest,
            kind=kind,
        )

    def document(self) -> dict[str, object]:
        return {
            "event_hash": self.event_hash,
            "event_id": self.event_id,
            "kind": self.kind,
            "sequence": self.sequence,
        }


@dataclass(frozen=True, slots=True)
class WorkerArtifact:
    reference: ArtifactRef
    purpose: str
    content: bytes

    def __post_init__(self) -> None:
        if (
            type(self.reference) is not ArtifactRef
            or self.purpose not in {"audit-report", "audit-run", "evidence-graph", "sarif-report"}
            or type(self.content) is not bytes
            or not self.content
            or len(self.content) != self.reference.size_bytes
            or hashlib.sha256(self.content).hexdigest() != self.reference.content_sha256
        ):
            raise ProtocolError("worker artifact is invalid")


@dataclass(frozen=True, slots=True)
class WorkerFindingLocation:
    path: str
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        normalized = PurePosixPath(self.path) if isinstance(self.path, str) and self.path else None
        if (
            type(self.path) is not str
            or not self.path
            or self.path != self.path.strip()
            or len(self.path) > 1024
            or "\\" in self.path
            or any(not character.isprintable() for character in self.path)
            or unicodedata.normalize("NFC", self.path) != self.path
            or normalized is None
            or normalized.is_absolute()
            or normalized.as_posix() != self.path
            or not normalized.parts
            or any(part in {"", ".", ".."} for part in normalized.parts)
            or normalized.parts[0].endswith(":")
            or type(self.start_line) is not int
            or self.start_line < 1
            or type(self.end_line) is not int
            or self.end_line < self.start_line
        ):
            raise ProtocolError("worker finding location is invalid")

    def document(self) -> dict[str, object]:
        return {
            "end_line": self.end_line,
            "path": self.path,
            "start_line": self.start_line,
        }


@dataclass(frozen=True, slots=True)
class WorkerFinding:
    finding_id: str
    revision_sha: str
    cwe_id: str
    severity: str
    confidence: str
    verdict: str
    blocking: bool
    locations: tuple[WorkerFindingLocation, ...]
    evidence_graph_ref: ArtifactRef
    root_cause_fingerprint: str

    def __post_init__(self) -> None:
        if (
            type(self.finding_id) is not str
            or _OPAQUE_ID.fullmatch(self.finding_id) is None
            or type(self.revision_sha) is not str
            or re.fullmatch(r"[0-9a-f]{40}", self.revision_sha) is None
            or type(self.cwe_id) is not str
            or re.fullmatch(r"CWE-[1-9][0-9]{0,5}", self.cwe_id) is None
            or type(self.severity) is not str
            or self.severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
            or type(self.confidence) is not str
            or self.confidence != "UNSCORED"
            or type(self.verdict) is not str
            or self.verdict
            not in {
                "CONFIRMED",
                "REJECTED_WITH_EVIDENCE",
                "NEEDS_MORE_EVIDENCE",
                "CONFLICTING",
                "NOT_EVALUATED",
            }
            or type(self.blocking) is not bool
            or not self.locations
            or len(self.locations) > 4096
            or any(type(item) is not WorkerFindingLocation for item in self.locations)
            or type(self.evidence_graph_ref) is not ArtifactRef
            or self.evidence_graph_ref.data_class is not DataClass.CONFIDENTIAL_SECURITY
            or type(self.root_cause_fingerprint) is not str
            or _SHA256.fullmatch(self.root_cause_fingerprint) is None
            or len({(item.path, item.start_line, item.end_line) for item in self.locations})
            != len(self.locations)
        ):
            raise ProtocolError("worker finding is invalid")

    def document(self) -> dict[str, object]:
        return {
            "blocking": self.blocking,
            "confidence": self.confidence,
            "cwe_id": self.cwe_id,
            "evidence_graph_ref": self.evidence_graph_ref.model_dump(mode="json"),
            "finding_id": self.finding_id,
            "locations": [item.document() for item in self.locations],
            "revision_sha": self.revision_sha,
            "root_cause_fingerprint": self.root_cause_fingerprint,
            "severity": self.severity,
            "verdict": self.verdict,
        }


def _canonical_sha256(document: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


__all__ = [
    "ProtocolError",
    "WorkerArtifact",
    "WorkerCommand",
    "WorkerEvent",
    "WorkerFinding",
    "WorkerFindingLocation",
    "WorkerJob",
    "WorkerResourceUsage",
]
