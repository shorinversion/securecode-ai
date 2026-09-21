"""Immutable, signed v1 release candidate metadata."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Final

_HASH: Final = re.compile(r"[0-9a-f]{64}\Z")
_SEMVER: Final = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+\Z")
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/release-candidate/v1\x00"


class ReleaseCandidateError(ValueError):
    """Safe release candidate error that excludes artifact contents."""

    def __init__(self) -> None:
        super().__init__("Release candidate was rejected")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class ReleaseArtifact:
    artifact_id: str
    checksum_sha256: str
    signature_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.artifact_id) is not str
            or _ID.fullmatch(self.artifact_id) is None
            or any(
                type(value) is not str or _HASH.fullmatch(value) is None
                for value in (
                    self.checksum_sha256,
                    self.signature_sha256,
                )
            )
        ):
            raise ReleaseCandidateError()


@dataclass(frozen=True, slots=True)
class ReleaseCandidate:
    version: str
    source_tree_sha256: str
    closure_activation_sha256: str
    sbom_sha256: str
    provenance_sha256: str
    checksums_sha256: str
    server_image_digest: str
    worker_image_digest: str
    artifacts: tuple[ReleaseArtifact, ...]
    release_signature_sha256: str
    candidate_sha256: str

    def __post_init__(self) -> None:
        values = (
            self.source_tree_sha256,
            self.closure_activation_sha256,
            self.sbom_sha256,
            self.provenance_sha256,
            self.checksums_sha256,
            self.server_image_digest,
            self.worker_image_digest,
            self.release_signature_sha256,
            self.candidate_sha256,
        )
        if (
            type(self.version) is not str
            or _SEMVER.fullmatch(self.version) is None
            or any(type(value) is not str or _HASH.fullmatch(value) is None for value in values)
            or type(self.artifacts) is not tuple
            or not self.artifacts
            or any(type(item) is not ReleaseArtifact for item in self.artifacts)
            or len({item.artifact_id for item in self.artifacts}) != len(self.artifacts)
            or self.candidate_sha256 != _candidate_hash(self)
        ):
            raise ReleaseCandidateError()

    @classmethod
    def build(
        cls,
        *,
        version: str,
        source_tree_sha256: str,
        closure_activation_sha256: str,
        sbom_sha256: str,
        provenance_sha256: str,
        checksums_sha256: str,
        server_image_digest: str,
        worker_image_digest: str,
        artifacts: tuple[ReleaseArtifact, ...],
        release_signature_sha256: str,
    ) -> ReleaseCandidate:
        value = object.__new__(cls)
        for name, item in {
            "version": version,
            "source_tree_sha256": source_tree_sha256,
            "closure_activation_sha256": closure_activation_sha256,
            "sbom_sha256": sbom_sha256,
            "provenance_sha256": provenance_sha256,
            "checksums_sha256": checksums_sha256,
            "server_image_digest": server_image_digest,
            "worker_image_digest": worker_image_digest,
            "artifacts": artifacts,
            "release_signature_sha256": release_signature_sha256,
            "candidate_sha256": "0" * 64,
        }.items():
            object.__setattr__(value, name, item)
        return cls(
            version,
            source_tree_sha256,
            closure_activation_sha256,
            sbom_sha256,
            provenance_sha256,
            checksums_sha256,
            server_image_digest,
            worker_image_digest,
            artifacts,
            release_signature_sha256,
            _candidate_hash(value),
        )


def _candidate_hash(value: ReleaseCandidate) -> str:
    material = {
        "artifacts": [
            (item.artifact_id, item.checksum_sha256, item.signature_sha256)
            for item in value.artifacts
        ],
        "closure": value.closure_activation_sha256,
        "checksums": value.checksums_sha256,
        "provenance": value.provenance_sha256,
        "release_signature": value.release_signature_sha256,
        "sbom": value.sbom_sha256,
        "server": value.server_image_digest,
        "source": value.source_tree_sha256,
        "version": value.version,
        "worker": value.worker_image_digest,
    }
    return hashlib.sha256(
        _HASH_DOMAIN + json.dumps(material, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


__all__ = ["ReleaseArtifact", "ReleaseCandidate", "ReleaseCandidateError"]
