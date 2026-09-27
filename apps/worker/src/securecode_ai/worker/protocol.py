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
_MAX_ARTIFACT_BYTES: Final = 16_777_216
_MAX_VERSION: Final = 2_147_483_647
_MAX_SEQUENCE: Final = 2_147_483_647
_MAX_SOURCE_LINE: Final = 2_147_483_647
_SCHEMA_VERSION: Final = "0.2.0"
_WORKER_ARTIFACT_DATA_CLASSES: Final = frozenset(
    {
        DataClass.PUBLIC,
        DataClass.INTERNAL_METADATA,
        DataClass.CONFIDENTIAL_SECURITY,
        DataClass.CONFIDENTIAL_SOURCE,
    }
)


class ProtocolError(ValueError):
    """A safe, non-echoing control-plane protocol failure."""


class WorkerCommand(StrEnum):
    CONTINUE = "CONTINUE"
    CANCEL = "CANCEL"
    SUPERSEDE = "SUPERSEDE"


class WorkerOperation(StrEnum):
    """Internal product operation selected for one leased worker run.

    The control-plane payload may omit this optional field, in which case the
    historical scan operation remains the only active path.  ``REPAIR`` never
    authorizes applying or publishing a patch; it only enables the local,
    suggestion-only repair journey after the immutable scan.
    """

    SCAN = "SCAN"
    REPAIR = "REPAIR"


class WorkerContributionTrust(StrEnum):
    NOT_SCM = "NOT_SCM"
    TRUSTED_SAME_REPOSITORY = "TRUSTED_SAME_REPOSITORY"
    UNTRUSTED_FORK = "UNTRUSTED_FORK"
    UNTRUSTED_SAME_REPOSITORY = "UNTRUSTED_SAME_REPOSITORY"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class WorkerResourceBudget:
    """The reservation bound delivered with a claimed worker job."""

    profile_sha256: str
    reservation_id: str
    reservation_version: int
    reserved: WorkerResourceUsage

    def __post_init__(self) -> None:
        if (
            _SHA256.fullmatch(self.profile_sha256) is None
            or _OPAQUE_ID.fullmatch(self.reservation_id) is None
            or type(self.reservation_version) is not int
            or self.reservation_version < 1
            or type(self.reserved) is not WorkerResourceUsage
        ):
            raise ProtocolError("worker resource budget is invalid")


@dataclass(frozen=True, slots=True)
class WorkerJob:
    session_id: str
    run_id: str
    version: int
    lease_seconds: int
    command: WorkerCommand
    execution_identity: RunExecutionIdentity
    contribution_trust: WorkerContributionTrust = WorkerContributionTrust.NOT_SCM
    next_event_sequence: int = 1
    operation: WorkerOperation = WorkerOperation.SCAN
    resource_budget: WorkerResourceBudget | None = None

    def __post_init__(self) -> None:
        """Refuse a forged trust label before it can affect worker isolation."""

        if (
            type(self.session_id) is not str
            or _OPAQUE_ID.fullmatch(self.session_id) is None
            or type(self.run_id) is not str
            or _OPAQUE_ID.fullmatch(self.run_id) is None
            or type(self.version) is not int
            or not 1 <= self.version <= _MAX_VERSION
            or type(self.lease_seconds) is not int
            or not 5 <= self.lease_seconds <= 3600
            or type(self.command) is not WorkerCommand
            or type(self.execution_identity) is not RunExecutionIdentity
            or type(self.contribution_trust) is not WorkerContributionTrust
            or type(self.next_event_sequence) is not int
            or not 1 <= self.next_event_sequence <= _MAX_SEQUENCE
            or type(self.operation) is not WorkerOperation
            or (
                self.resource_budget is not None
                and type(self.resource_budget) is not WorkerResourceBudget
            )
        ):
            raise ProtocolError("worker job is invalid")

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
            "contribution_trust",
            "next_event_sequence",
            "resource_budget",
            "operation",
        }
        required = {
            "schema_version",
            "session_id",
            "run_id",
            "version",
            "lease_seconds",
            "command",
            "execution_identity",
            "execution_identity_hash",
            "contribution_trust",
            "next_event_sequence",
            "resource_budget",
        }
        if set(document) - allowed or not required.issubset(document):
            raise ProtocolError("worker job is invalid")
        try:
            if document["schema_version"] != _SCHEMA_VERSION:
                raise ProtocolError("worker job is invalid")
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
            identity = RunExecutionIdentity.model_validate_json(
                json.dumps(dict(identity_document), separators=(",", ":"), sort_keys=True)
            )
            identity_hash = document.get(
                "execution_identity_hash", identity.execution_identity_hash
            )
            trust_value = document.get("contribution_trust", WorkerContributionTrust.NOT_SCM.value)
            next_event_sequence = document["next_event_sequence"]
            if type(trust_value) is not str:
                raise ProtocolError("worker job is invalid")
            contribution_trust = WorkerContributionTrust(trust_value)
            operation_value = document.get("operation", WorkerOperation.SCAN.value)
            resource_budget = _resource_budget(document.get("resource_budget"))
            if type(operation_value) is not str:
                raise ProtocolError("worker job is invalid")
            operation = WorkerOperation(operation_value)
        except (KeyError, TypeError, ValueError):
            raise ProtocolError("worker job is invalid") from None
        if (
            type(session_id) is not str
            or _OPAQUE_ID.fullmatch(session_id) is None
            or type(run_id) is not str
            or _OPAQUE_ID.fullmatch(run_id) is None
            or type(version) is not int
            or not 1 <= version <= _MAX_VERSION
            or type(lease_seconds) is not int
            or not 5 <= lease_seconds <= 3600
            or type(identity_hash) is not str
            or _SHA256.fullmatch(identity_hash) is None
            or identity_hash != identity.execution_identity_hash
            or type(next_event_sequence) is not int
            or not 1 <= next_event_sequence <= _MAX_SEQUENCE
        ):
            raise ProtocolError("worker job is invalid")
        if resource_budget is None:
            raise ProtocolError("worker resource budget is unavailable")
        return cls(
            session_id,
            run_id,
            version,
            lease_seconds,
            command,
            identity,
            contribution_trust,
            next_event_sequence,
            operation,
            resource_budget,
        )


def _resource_budget(value: object) -> WorkerResourceBudget | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != {
        "profile_sha256",
        "reservation_id",
        "reservation_version",
        "reserved",
    }:
        raise ProtocolError("worker resource budget is invalid")
    reserved = value["reserved"]
    if not isinstance(reserved, Mapping) or set(reserved) != {
        "tokens",
        "cost_microunits",
        "cpu_ms",
        "peak_memory_bytes",
        "wall_ms",
    }:
        raise ProtocolError("worker resource budget is invalid")
    try:
        usage = WorkerResourceUsage(
            tokens=reserved["tokens"],
            cost_microunits=reserved["cost_microunits"],
            cpu_ms=reserved["cpu_ms"],
            peak_memory_bytes=reserved["peak_memory_bytes"],
            wall_ms=reserved["wall_ms"],
        )
        return WorkerResourceBudget(
            profile_sha256=value["profile_sha256"],
            reservation_id=value["reservation_id"],
            reservation_version=value["reservation_version"],
            reserved=usage,
        )
    except (TypeError, ValueError):
        raise ProtocolError("worker resource budget is invalid") from None


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
            or not 1 <= sequence <= _MAX_SEQUENCE
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
class WorkerRepairPatchBinding:
    """Durable source-bearing repair binding carried beside one patch bundle."""

    tenant_id: str
    repository_id: str
    run_id: str
    finding_id: str
    head_sha: str
    execution_identity_hash: str
    patch_sha256: str
    patch_size_bytes: int
    manifest_sha256: str
    validation_result_sha256: str
    patch_status_sha256: str

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not str or _OPAQUE_ID.fullmatch(value) is None
                for value in (
                    self.tenant_id,
                    self.repository_id,
                    self.run_id,
                    self.finding_id,
                )
            )
            or type(self.head_sha) is not str
            or re.fullmatch(r"[0-9a-f]{40}", self.head_sha) is None
            or type(self.execution_identity_hash) is not str
            or _SHA256.fullmatch(self.execution_identity_hash) is None
            or type(self.patch_sha256) is not str
            or _SHA256.fullmatch(self.patch_sha256) is None
            or type(self.manifest_sha256) is not str
            or _SHA256.fullmatch(self.manifest_sha256) is None
            or type(self.validation_result_sha256) is not str
            or _SHA256.fullmatch(self.validation_result_sha256) is None
            or type(self.patch_status_sha256) is not str
            or _SHA256.fullmatch(self.patch_status_sha256) is None
            or type(self.patch_size_bytes) is not int
            or not 1 <= self.patch_size_bytes <= 131_072
        ):
            raise ProtocolError("worker repair patch binding is invalid")

    def document(self) -> dict[str, object]:
        return {
            "execution_identity_hash": self.execution_identity_hash,
            "finding_id": self.finding_id,
            "head_sha": self.head_sha,
            "manifest_sha256": self.manifest_sha256,
            "patch_size_bytes": self.patch_size_bytes,
            "patch_sha256": self.patch_sha256,
            "patch_status_sha256": self.patch_status_sha256,
            "repository_id": self.repository_id,
            "run_id": self.run_id,
            "tenant_id": self.tenant_id,
            "validation_result_sha256": self.validation_result_sha256,
        }


@dataclass(frozen=True, slots=True)
class WorkerArtifact:
    reference: ArtifactRef
    purpose: str
    content: bytes
    binding: WorkerRepairPatchBinding | None = None

    def __post_init__(self) -> None:
        if (
            type(self.reference) is not ArtifactRef
            or self.reference.data_class not in _WORKER_ARTIFACT_DATA_CLASSES
            or type(self.purpose) is not str
            or self.purpose
            not in {
                "audit-report",
                "audit-run",
                "evidence-graph",
                "repair-patch",
                "repair-report",
                "sarif-report",
            }
            or type(self.content) is not bytes
            or not self.content
            or len(self.content) > _MAX_ARTIFACT_BYTES
            or len(self.content) != self.reference.size_bytes
            or hashlib.sha256(self.content).hexdigest() != self.reference.content_sha256
            or (
                self.purpose == "repair-patch"
                and (
                    self.reference.data_class is not DataClass.CONFIDENTIAL_SOURCE
                    or type(self.binding) is not WorkerRepairPatchBinding
                )
            )
            or (
                self.purpose != "repair-patch"
                and (
                    self.reference.data_class is DataClass.CONFIDENTIAL_SOURCE
                    or self.binding is not None
                )
            )
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
            or not 1 <= self.start_line <= _MAX_SOURCE_LINE
            or type(self.end_line) is not int
            or not self.start_line <= self.end_line <= _MAX_SOURCE_LINE
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
    "WorkerRepairPatchBinding",
    "WorkerCommand",
    "WorkerContributionTrust",
    "WorkerEvent",
    "WorkerFinding",
    "WorkerFindingLocation",
    "WorkerJob",
    "WorkerOperation",
    "WorkerResourceBudget",
    "WorkerResourceUsage",
]
