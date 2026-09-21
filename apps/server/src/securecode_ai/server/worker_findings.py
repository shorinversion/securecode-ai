"""Closed source-free finding metadata accepted from connected workers."""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

from securecode_ai.contracts import ArtifactRef, DataClass

from .worker_queue_models import WorkerQueueConflict

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_COMMIT: Final = re.compile(r"[0-9a-f]{40}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_CWE: Final = re.compile(r"CWE-[1-9][0-9]{0,5}\Z")
_SEVERITIES: Final = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
_CONFIDENCES: Final = frozenset({"UNSCORED"})
_VERDICTS: Final = frozenset(
    {
        "CONFIRMED",
        "REJECTED_WITH_EVIDENCE",
        "NEEDS_MORE_EVIDENCE",
        "CONFLICTING",
        "NOT_EVALUATED",
    }
)
_FINDING_KEYS: Final = frozenset(
    {
        "blocking",
        "confidence",
        "cwe_id",
        "evidence_graph_ref",
        "finding_id",
        "locations",
        "revision_sha",
        "root_cause_fingerprint",
        "severity",
        "verdict",
    }
)
_LOCATION_KEYS: Final = frozenset({"end_line", "path", "start_line"})


@dataclass(frozen=True, slots=True)
class WorkerFindingLocation:
    path: str
    start_line: int
    end_line: int

    def document(self) -> dict[str, object]:
        return {
            "end_line": self.end_line,
            "path": self.path,
            "start_line": self.start_line,
        }


@dataclass(frozen=True, slots=True)
class WorkerFindingRecord:
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

    def metadata_document(self) -> dict[str, object]:
        return {
            "blocking": self.blocking,
            "confidence": self.confidence,
            "cwe_id": self.cwe_id,
            "evidence_graph_ref": self.evidence_graph_ref.model_dump(mode="json"),
            "locations": [item.document() for item in self.locations],
            "root_cause_fingerprint": self.root_cause_fingerprint,
            "severity": self.severity,
            "verdict": self.verdict,
        }

    def document(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "revision_sha": self.revision_sha,
            **self.metadata_document(),
        }


def parse_worker_findings(
    value: object,
    *,
    required: bool,
    supplied: bool,
) -> tuple[WorkerFindingRecord, ...]:
    if not required:
        if supplied:
            raise WorkerQueueConflict()
        return ()
    if not supplied or not isinstance(value, list) or len(value) > 100_000:
        raise WorkerQueueConflict()
    findings = tuple(_finding(item) for item in value)
    finding_ids = tuple(item.finding_id for item in findings)
    if finding_ids != tuple(sorted(finding_ids)) or len(finding_ids) != len(set(finding_ids)):
        raise WorkerQueueConflict()
    return findings


def _finding(value: object) -> WorkerFindingRecord:
    if not isinstance(value, Mapping) or set(value) != _FINDING_KEYS:
        raise WorkerQueueConflict()
    finding_id = value["finding_id"]
    revision_sha = value["revision_sha"]
    cwe_id = value["cwe_id"]
    severity = value["severity"]
    confidence = value["confidence"]
    verdict = value["verdict"]
    blocking = value["blocking"]
    fingerprint = value["root_cause_fingerprint"]
    if (
        type(finding_id) is not str
        or _ID.fullmatch(finding_id) is None
        or type(revision_sha) is not str
        or _COMMIT.fullmatch(revision_sha) is None
        or type(cwe_id) is not str
        or _CWE.fullmatch(cwe_id) is None
        or type(severity) is not str
        or severity not in _SEVERITIES
        or type(confidence) is not str
        or confidence not in _CONFIDENCES
        or type(verdict) is not str
        or verdict not in _VERDICTS
        or type(blocking) is not bool
        or type(fingerprint) is not str
        or _SHA256.fullmatch(fingerprint) is None
    ):
        raise WorkerQueueConflict()
    locations = _locations(value["locations"])
    reference = _artifact_reference(value["evidence_graph_ref"])
    return WorkerFindingRecord(
        finding_id=finding_id,
        revision_sha=revision_sha,
        cwe_id=cwe_id,
        severity=severity,
        confidence=confidence,
        verdict=verdict,
        blocking=blocking,
        locations=locations,
        evidence_graph_ref=reference,
        root_cause_fingerprint=fingerprint,
    )


def _locations(value: object) -> tuple[WorkerFindingLocation, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 4096:
        raise WorkerQueueConflict()
    locations = tuple(_location(item) for item in value)
    if len({(item.path, item.start_line, item.end_line) for item in locations}) != len(locations):
        raise WorkerQueueConflict()
    return locations


def _location(value: object) -> WorkerFindingLocation:
    if not isinstance(value, Mapping) or set(value) != _LOCATION_KEYS:
        raise WorkerQueueConflict()
    path = value["path"]
    start_line = value["start_line"]
    end_line = value["end_line"]
    if type(path) is not str or not path:
        raise WorkerQueueConflict()
    normalized = PurePosixPath(path)
    if (
        path != path.strip()
        or len(path) > 1024
        or "\\" in path
        or any(not character.isprintable() for character in path)
        or unicodedata.normalize("NFC", path) != path
        or normalized.is_absolute()
        or normalized.as_posix() != path
        or not normalized.parts
        or any(part in {"", ".", ".."} for part in normalized.parts)
        or normalized.parts[0].endswith(":")
        or type(start_line) is not int
        or start_line < 1
        or type(end_line) is not int
        or end_line < start_line
    ):
        raise WorkerQueueConflict()
    return WorkerFindingLocation(path, start_line, end_line)


def _artifact_reference(value: object) -> ArtifactRef:
    if not isinstance(value, Mapping):
        raise WorkerQueueConflict()
    try:
        reference = ArtifactRef.model_validate_json(
            json.dumps(
                dict(value),
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    except (TypeError, ValueError):
        raise WorkerQueueConflict() from None
    if reference.data_class is not DataClass.CONFIDENTIAL_SECURITY:
        raise WorkerQueueConflict()
    return reference


__all__ = ["WorkerFindingRecord", "parse_worker_findings"]
