"""Local content-addressed provider for immutable release publication."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from securecode_ai.core.release_candidate import ReleaseArtifact, ReleaseCandidate
from securecode_ai.core.release_provenance import (
    BuildProvenance,
    SignatureReceipt,
    canonical_provenance,
    checksums,
    release_ready,
)
from securecode_ai.core.release_publisher import (
    AuthorizedPublishRequest,
    PublishAuthorization,
    RemoteRelease,
)
from securecode_ai.core.supply_chain import DependencyPolicy, SbomComponent, canonical_sbom

from .release_provider_support import (
    _CHUNK_BYTES,
    _HASH,
    _ID,
    _MAX_MANIFEST_BYTES,
    _MAX_TAG_BYTES,
    _SCHEMA_VERSION,
    _TAG,
    HmacReleaseAuthority,
    LocalReleaseProviderError,
    _authorization_from_manifest,
    _candidate_from_manifest,
    _canonical_json,
    _destination_root,
    _ensure_directory,
    _ensure_directory_beneath,
    _existing_root,
    _fsync_directory,
    _json_object,
    _link_create_if_absent,
    _manifest_bytes,
    _manifest_relative_path,
    _object_relative_path,
    _open_regular_beneath,
    _read_verified_file,
    _remote_matches,
    _safe_relative_path,
    _same_file_state,
    _stage_bytes,
    _store_identity,
    _tag_relative_path,
    _verify_canonical_json,
    _verify_digest_and_size,
)


@dataclass(frozen=True, slots=True)
class ReleaseArtifactSource:
    """Host-selected relative files for one release artifact and its signature."""

    artifact_id: str
    artifact_relative_path: str
    signature_relative_path: str

    def __post_init__(self) -> None:
        if (
            type(self.artifact_id) is not str
            or _ID.fullmatch(self.artifact_id) is None
            or not _safe_relative_path(self.artifact_relative_path)
            or not _safe_relative_path(self.signature_relative_path)
            or self.artifact_relative_path == self.signature_relative_path
        ):
            raise LocalReleaseProviderError()


@dataclass(frozen=True, slots=True)
class ReleaseEvidenceSource:
    evidence_id: str
    relative_path: str

    def __post_init__(self) -> None:
        if self.evidence_id not in _EVIDENCE_FIELDS or not _safe_relative_path(self.relative_path):
            raise LocalReleaseProviderError()


_EVIDENCE_FIELDS = frozenset(
    {
        "checksums_sha256",
        "closure_activation_sha256",
        "provenance_sha256",
        "release_signature_sha256",
        "sbom_sha256",
        "server_image_digest",
        "source_tree_sha256",
        "worker_image_digest",
    }
)
_CANONICAL_JSON_EVIDENCE = frozenset(
    {"checksums_sha256", "closure_activation_sha256", "provenance_sha256", "sbom_sha256"}
)
_MAX_CANONICAL_EVIDENCE_BYTES = 16 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 16 * 1024
_MAX_SOURCE_BYTES = 16 * 1024 * 1024 * 1024


class LocalReleaseProvider:
    __slots__ = (
        "_authorization",
        "_clock",
        "_destination_fd",
        "_destination_root",
        "_evidence",
        "_source_root",
        "_sources",
        "_store_identity_sha256",
    )

    def __init__(
        self,
        destination_root: str | os.PathLike[str],
        *,
        source_root: str | os.PathLike[str],
        artifacts: tuple[ReleaseArtifactSource, ...],
        evidence: tuple[ReleaseEvidenceSource, ...],
        authorization: HmacReleaseAuthority,
        clock: Callable[[], float] = time.time,
    ) -> None:
        try:
            if os.name != "posix":
                raise LocalReleaseProviderError()
            source = _existing_root(source_root)
            destination = _destination_root(destination_root)
            if (
                source == destination
                or source in destination.parents
                or destination in source.parents
                or type(artifacts) is not tuple
                or not artifacts
                or any(type(item) is not ReleaseArtifactSource for item in artifacts)
                or len({item.artifact_id for item in artifacts}) != len(artifacts)
                or type(evidence) is not tuple
                or len(evidence) != len(_EVIDENCE_FIELDS)
                or any(type(item) is not ReleaseEvidenceSource for item in evidence)
                or {item.evidence_id for item in evidence} != _EVIDENCE_FIELDS
                or type(authorization) is not HmacReleaseAuthority
                or not callable(clock)
            ):
                raise LocalReleaseProviderError()
            _ensure_directory(destination, destination / "tags")
            descriptor = os.open(
                destination,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            if not Path(f"/proc/self/fd/{descriptor}").exists():
                os.close(descriptor)
                raise LocalReleaseProviderError()
            self._source_root = source
            self._destination_root = destination
            self._destination_fd = descriptor
            self._sources = {item.artifact_id: item for item in artifacts}
            self._evidence = {item.evidence_id: item for item in evidence}
            self._authorization = authorization
            self._store_identity_sha256 = _store_identity(destination)
            self._clock = clock
        except LocalReleaseProviderError:
            raise
        except (OSError, TypeError, ValueError):
            raise LocalReleaseProviderError() from None

    def get_tag(
        self, tag: str, authorization: PublishAuthorization | None = None
    ) -> RemoteRelease | None:
        try:
            if authorization is not None and (
                type(authorization) is not PublishAuthorization
                or not self._authorization.verify(authorization, now=int(self._clock()))
                or authorization.store_identity_sha256 != self._store_identity_sha256
            ):
                raise LocalReleaseProviderError()
            if authorization is not None:
                self._consume_authorization(authorization)
            return self._get_tag(tag)
        except LocalReleaseProviderError:
            raise
        except (OSError, TypeError, ValueError):
            raise LocalReleaseProviderError() from None

    def __del__(self) -> None:
        descriptor = getattr(self, "_destination_fd", -1)
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
            self._destination_fd = -1

    def create_release(self, request: AuthorizedPublishRequest) -> RemoteRelease:
        try:
            if type(request) is not AuthorizedPublishRequest:
                raise LocalReleaseProviderError()
            plan = request.plan
            candidate = plan.candidate
            if (
                type(candidate) is not ReleaseCandidate
                or plan.tag != candidate.version
                or plan.candidate_sha256 != candidate.candidate_sha256
                or plan.artifact_checksums
                != tuple(item.checksum_sha256 for item in candidate.artifacts)
                or not self._authorization.verify(request.authorization, now=int(self._clock()))
                or request.authorization.store_identity_sha256 != self._store_identity_sha256
            ):
                raise LocalReleaseProviderError()
            self._consume_authorization(request.authorization)
            existing = self._get_tag(plan.tag)
            if existing is not None:
                if _remote_matches(existing, request):
                    return existing
                raise LocalReleaseProviderError()

            evidence = tuple(
                self._publish_evidence(candidate, name) for name in sorted(_EVIDENCE_FIELDS)
            )
            objects = tuple(self._publish_artifact(item) for item in candidate.artifacts)
            self._verify_release_evidence(candidate)
            manifest = _manifest_bytes(request, objects, evidence)
            manifest_sha256 = hashlib.sha256(manifest).hexdigest()
            manifest_relative = _manifest_relative_path(manifest_sha256)
            self._publish_bytes(manifest, manifest_relative, manifest_sha256)

            tag_bytes = _canonical_json(
                {
                    "candidate_sha256": candidate.candidate_sha256,
                    "manifest_relative_path": manifest_relative,
                    "manifest_sha256": manifest_sha256,
                    "schema_version": _SCHEMA_VERSION,
                    "tag": plan.tag,
                }
            )
            self._publish_tag(tag_bytes, _tag_relative_path(plan.tag))
            remote = self._get_tag(plan.tag)
            if remote is None or not _remote_matches(remote, request):
                raise LocalReleaseProviderError()
            return remote
        except LocalReleaseProviderError:
            raise
        except (OSError, TypeError, ValueError):
            raise LocalReleaseProviderError() from None

    def _get_tag(self, tag: str) -> RemoteRelease | None:
        if type(tag) is not str or _TAG.fullmatch(tag) is None:
            raise LocalReleaseProviderError()
        tag_path = self._destination_path(_tag_relative_path(tag))
        if not tag_path.exists():
            return None
        tag_bytes = _read_verified_file(tag_path, _MAX_TAG_BYTES)
        tag_document = _json_object(tag_bytes)
        if tag_bytes != _canonical_json(tag_document) or set(tag_document) != {
            "candidate_sha256",
            "manifest_relative_path",
            "manifest_sha256",
            "schema_version",
            "tag",
        }:
            raise LocalReleaseProviderError()
        candidate_sha256 = tag_document["candidate_sha256"]
        manifest_sha256 = tag_document["manifest_sha256"]
        manifest_relative = tag_document["manifest_relative_path"]
        if (
            tag_document["schema_version"] != _SCHEMA_VERSION
            or tag_document["tag"] != tag
            or type(candidate_sha256) is not str
            or _HASH.fullmatch(candidate_sha256) is None
            or type(manifest_sha256) is not str
            or _HASH.fullmatch(manifest_sha256) is None
            or manifest_relative != _manifest_relative_path(manifest_sha256)
        ):
            raise LocalReleaseProviderError()
        manifest_path = self._destination_path(manifest_relative)
        manifest_bytes = _read_verified_file(manifest_path, _MAX_MANIFEST_BYTES)
        if hashlib.sha256(manifest_bytes).hexdigest() != manifest_sha256:
            raise LocalReleaseProviderError()
        manifest = _json_object(manifest_bytes)
        if manifest_bytes != _canonical_json(manifest):
            raise LocalReleaseProviderError()
        candidate = _candidate_from_manifest(manifest)
        authorization = _authorization_from_manifest(manifest)
        if (
            candidate.version != tag
            or candidate.candidate_sha256 != candidate_sha256
            or authorization.candidate_sha256 != candidate.candidate_sha256
            or authorization.store_identity_sha256 != self._store_identity_sha256
            or not self._authorization.verify(authorization, now=None)
        ):
            raise LocalReleaseProviderError()
        self._verify_manifest_objects(manifest, candidate)
        return RemoteRelease(
            tag,
            manifest_sha256,
            candidate.candidate_sha256,
            tuple(item.checksum_sha256 for item in candidate.artifacts),
            True,
        )

    def _consume_authorization(self, authorization: PublishAuthorization) -> None:
        value = _canonical_json(
            {
                "authorization_id": authorization.authorization_id,
                "candidate_sha256": authorization.candidate_sha256,
                "key_id": authorization.key_id,
                "nonce": authorization.nonce,
                "signature_sha256": authorization.signature_sha256,
                "store_identity_sha256": authorization.store_identity_sha256,
            }
        )
        relative = f"authorizations/{authorization.key_id}/{authorization.authorization_id}.json"
        self._publish_bytes(value, relative, hashlib.sha256(value).hexdigest())

    def _publish_artifact(self, artifact: ReleaseArtifact) -> dict[str, object]:
        source = self._sources.get(artifact.artifact_id)
        if source is None:
            raise LocalReleaseProviderError()
        artifact_size = self._publish_source(
            source.artifact_relative_path, artifact.checksum_sha256
        )
        signature_size = self._publish_source(
            source.signature_relative_path, artifact.signature_sha256
        )
        self._signature_receipt(artifact.checksum_sha256, artifact.signature_sha256)
        return {
            "artifact_id": artifact.artifact_id,
            "artifact_relative_path": _object_relative_path(artifact.checksum_sha256),
            "artifact_size_bytes": artifact_size,
            "checksum_sha256": artifact.checksum_sha256,
            "signature_relative_path": _object_relative_path(artifact.signature_sha256),
            "signature_sha256": artifact.signature_sha256,
            "signature_size_bytes": signature_size,
        }

    def _signature_receipt(self, payload_sha256: str, object_sha256: str) -> SignatureReceipt:
        value = _read_verified_file(
            self._destination_path(_object_relative_path(object_sha256)),
            _MAX_SIGNATURE_BYTES,
        )
        document = json.loads(value.decode("ascii"))
        if (
            type(document) is not dict
            or set(document) != {"key_id", "payload_sha256", "signature_sha256"}
            or value != _canonical_json(document)
            or document["payload_sha256"] != payload_sha256
            or not self._authorization.owns_key_id(document["key_id"])
            or not self._authorization.verify_evidence_signature(
                payload_sha256, document["signature_sha256"]
            )
        ):
            raise LocalReleaseProviderError()
        return SignatureReceipt(str(document["key_id"]), True, payload_sha256, object_sha256)

    def _verify_release_evidence(self, candidate: ReleaseCandidate) -> None:
        def evidence(name: str, limit: int = _MAX_CANONICAL_EVIDENCE_BYTES) -> bytes:
            digest = getattr(candidate, name)
            return _read_verified_file(self._destination_path(_object_relative_path(digest)), limit)

        checksum_values = {item.artifact_id: item.checksum_sha256 for item in candidate.artifacts}
        if evidence("checksums_sha256") != checksums(checksum_values):
            raise LocalReleaseProviderError()
        provenance_document = json.loads(evidence("provenance_sha256").decode("ascii"))
        if type(provenance_document) is not dict:
            raise LocalReleaseProviderError()
        provenance = BuildProvenance(**provenance_document)
        if canonical_provenance(provenance) != evidence("provenance_sha256"):
            raise LocalReleaseProviderError()
        image_digests = {candidate.server_image_digest, candidate.worker_image_digest}
        artifact_digests = {item.checksum_sha256 for item in candidate.artifacts}
        if (
            provenance.source_tree != candidate.source_tree_sha256
            or provenance.artifact_digest.removeprefix("sha256:") not in artifact_digests
            or provenance.image_digest.removeprefix("sha256:") not in image_digests
        ):
            raise LocalReleaseProviderError()
        sbom_value = evidence("sbom_sha256")
        sbom_document = json.loads(sbom_value.decode("ascii"))
        if type(sbom_document) is not list or not sbom_document:
            raise LocalReleaseProviderError()
        components = tuple(SbomComponent(**item) for item in sbom_document)
        licenses = frozenset(item.license for item in components if item.license is not None)
        if sbom_value != canonical_sbom(components, DependencyPolicy(licenses, frozenset())):
            raise LocalReleaseProviderError()
        signature = self._signature_receipt(
            candidate.provenance_sha256, candidate.release_signature_sha256
        )
        if not release_ready(sbom=sbom_value, provenance=provenance, signature=signature):
            raise LocalReleaseProviderError()

    def _publish_evidence(self, candidate: ReleaseCandidate, name: str) -> dict[str, object]:
        source = self._evidence[name]
        expected = getattr(candidate, name)
        size = self._publish_source(source.relative_path, expected)
        if name in _CANONICAL_JSON_EVIDENCE:
            _verify_canonical_json(
                self._destination_path(_object_relative_path(expected)),
                _MAX_CANONICAL_EVIDENCE_BYTES,
            )
        return {
            "evidence_id": name,
            "relative_path": _object_relative_path(expected),
            "sha256": expected,
            "size_bytes": size,
        }

    def _publish_source(self, relative_path: str, expected_sha256: str) -> int:
        target_relative = _object_relative_path(expected_sha256)
        target = self._destination_path(target_relative, create_parent=True)
        stage_directory = Path(tempfile.mkdtemp(prefix=".release-", dir=target.parent))
        temporary = stage_directory / "content.tmp"
        ready = stage_directory / "content.ready"
        source_fd = -1
        try:
            source_fd = _open_regular_beneath(self._source_root, relative_path)
            before = os.fstat(source_fd)
            if before.st_size < 1 or before.st_size > _MAX_SOURCE_BYTES:
                raise LocalReleaseProviderError()
            digest = hashlib.sha256()
            size = 0
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            output_fd = os.open(temporary, flags, 0o600)
            with (
                os.fdopen(output_fd, "wb") as output,
                os.fdopen(source_fd, "rb") as stream,
            ):
                source_fd = -1
                while chunk := stream.read(_CHUNK_BYTES):
                    digest.update(chunk)
                    size += len(chunk)
                    if size > _MAX_SOURCE_BYTES:
                        raise LocalReleaseProviderError()
                    output.write(chunk)
                after = os.fstat(stream.fileno())
                output.flush()
                os.fsync(output.fileno())
            if (
                digest.hexdigest() != expected_sha256
                or size != before.st_size
                or not _same_file_state(before, after)
            ):
                raise LocalReleaseProviderError()
            temporary.replace(ready)
            _fsync_directory(stage_directory)
            _link_create_if_absent(ready, self._destination_fd, target_relative)
            ready.unlink(missing_ok=True)
            _verify_digest_and_size(target, expected_sha256, size)
            return size
        finally:
            if source_fd >= 0:
                os.close(source_fd)
            temporary.unlink(missing_ok=True)
            ready.unlink(missing_ok=True)
            with suppress(OSError):
                stage_directory.rmdir()

    def _publish_bytes(self, value: bytes, relative_path: str, digest: str) -> None:
        target = self._destination_path(relative_path, create_parent=True)
        ready, stage_directory = _stage_bytes(target.parent, value)
        try:
            _link_create_if_absent(ready, self._destination_fd, relative_path)
            ready.unlink(missing_ok=True)
            _verify_digest_and_size(target, digest, len(value))
        finally:
            ready.unlink(missing_ok=True)
            with suppress(OSError):
                stage_directory.rmdir()

    def _publish_tag(self, value: bytes, relative_path: str) -> None:
        target = self._destination_path(relative_path, create_parent=True)
        ready, stage_directory = _stage_bytes(target.parent, value)
        try:
            _link_create_if_absent(ready, self._destination_fd, relative_path)
            ready.unlink(missing_ok=True)
            _verify_digest_and_size(target, hashlib.sha256(value).hexdigest(), len(value))
        finally:
            ready.unlink(missing_ok=True)
            with suppress(OSError):
                stage_directory.rmdir()

    def _verify_manifest_objects(
        self, manifest: dict[str, object], candidate: ReleaseCandidate
    ) -> None:
        objects = manifest.get("objects")
        if type(objects) is not list or len(objects) != len(candidate.artifacts):
            raise LocalReleaseProviderError()
        for value, artifact in zip(objects, candidate.artifacts, strict=True):
            if type(value) is not dict or set(value) != {
                "artifact_id",
                "artifact_relative_path",
                "artifact_size_bytes",
                "checksum_sha256",
                "signature_relative_path",
                "signature_sha256",
                "signature_size_bytes",
            }:
                raise LocalReleaseProviderError()
            artifact_size = value["artifact_size_bytes"]
            signature_size = value["signature_size_bytes"]
            if (
                value["artifact_id"] != artifact.artifact_id
                or value["checksum_sha256"] != artifact.checksum_sha256
                or value["signature_sha256"] != artifact.signature_sha256
                or value["artifact_relative_path"]
                != _object_relative_path(artifact.checksum_sha256)
                or value["signature_relative_path"]
                != _object_relative_path(artifact.signature_sha256)
                or type(artifact_size) is not int
                or artifact_size < 0
                or type(signature_size) is not int
                or signature_size < 0
            ):
                raise LocalReleaseProviderError()
            _verify_digest_and_size(
                self._destination_path(value["artifact_relative_path"]),
                artifact.checksum_sha256,
                artifact_size,
            )
            _verify_digest_and_size(
                self._destination_path(value["signature_relative_path"]),
                artifact.signature_sha256,
                signature_size,
            )
        evidence = manifest.get("evidence")
        if type(evidence) is not list or len(evidence) != len(_EVIDENCE_FIELDS):
            raise LocalReleaseProviderError()
        expected_evidence = {name: getattr(candidate, name) for name in _EVIDENCE_FIELDS}
        seen: set[str] = set()
        for value in evidence:
            if type(value) is not dict or set(value) != {
                "evidence_id",
                "relative_path",
                "sha256",
                "size_bytes",
            }:
                raise LocalReleaseProviderError()
            evidence_id = value["evidence_id"]
            digest = value["sha256"]
            size = value["size_bytes"]
            if (
                type(evidence_id) is not str
                or evidence_id in seen
                or expected_evidence.get(evidence_id) != digest
                or value["relative_path"] != _object_relative_path(digest)
                or type(size) is not int
                or size < 0
            ):
                raise LocalReleaseProviderError()
            seen.add(evidence_id)
            _verify_digest_and_size(self._destination_path(value["relative_path"]), digest, size)
        if seen != _EVIDENCE_FIELDS:
            raise LocalReleaseProviderError()

    def _destination_path(self, relative_path: object, *, create_parent: bool = False) -> Path:
        if type(relative_path) is not str or not _safe_relative_path(relative_path):
            raise LocalReleaseProviderError()
        if create_parent:
            _ensure_directory_beneath(self._destination_fd, PurePosixPath(relative_path).parent)
        return Path(f"/proc/self/fd/{self._destination_fd}").joinpath(
            *PurePosixPath(relative_path).parts
        )


FileSystemReleaseProvider = LocalReleaseProvider
ContentAddressedReleaseProvider = LocalReleaseProvider


__all__ = [
    "ContentAddressedReleaseProvider",
    "FileSystemReleaseProvider",
    "LocalReleaseProvider",
    "LocalReleaseProviderError",
    "ReleaseArtifactSource",
    "ReleaseEvidenceSource",
]
