"""Explicit, fail-closed local release administration command."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Final, TextIO

from securecode_ai.adapters.release_cli_config import (
    HmacReleaseAuthorizationVerifier,
    read_bounded_local_file,
    read_protected_release_config,
    read_protected_release_key,
    release_store_identity,
    verify_release_layout,
    verify_release_sources,
)
from securecode_ai.adapters.release_provider import (
    LocalReleaseProvider,
    ReleaseArtifactSource,
    ReleaseEvidenceSource,
)
from securecode_ai.contracts import CliExitCode
from securecode_ai.core.release_candidate import ReleaseArtifact, ReleaseCandidate
from securecode_ai.core.release_publisher import (
    AuthorizedPublishRequest,
    PublishAuthorization,
    ReleasePublishDisposition,
    ReleasePublisher,
    RemoteRelease,
)

_MAX_CONFIG_BYTES: Final = 1024 * 1024
_MAX_AUTHORIZATION_BYTES: Final = 16 * 1024
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CONFIG_KEYS: Final = frozenset(
    {
        "artifact_sources",
        "candidate",
        "destination_root",
        "evidence_sources",
        "schema_version",
        "source_root",
    }
)
_PUBLISH_CONFIG_KEYS: Final = _CONFIG_KEYS | {"publish_authority"}
_PUBLISH_AUTHORITY_KEYS: Final = {"key_file", "key_id"}
_CANDIDATE_KEYS: Final = {
    "artifacts",
    "candidate_sha256",
    "checksums_sha256",
    "closure_activation_sha256",
    "provenance_sha256",
    "release_signature_sha256",
    "sbom_sha256",
    "server_image_digest",
    "source_tree_sha256",
    "version",
    "worker_image_digest",
}
_ARTIFACT_KEYS: Final = {"artifact_id", "checksum_sha256", "signature_sha256"}
_SOURCE_KEYS: Final = {"artifact_id", "artifact_relative_path", "signature_relative_path"}
_EVIDENCE_SOURCE_KEYS: Final = {"evidence_id", "relative_path"}
_AUTHORIZATION_KEYS: Final = {
    "action",
    "approver_id",
    "authorization_id",
    "candidate_sha256",
    "expires_at",
    "key_id",
    "nonce",
    "schema_version",
    "signature_sha256",
    "store_identity_sha256",
}


class ReleaseCliError(ValueError):
    """Safe release CLI failure without paths, content, or credentials."""

    def __init__(self) -> None:
        super().__init__("Release command was rejected")
        self.__cause__ = None
        self.__context__ = None


def run_release_command(tokens: tuple[str, ...], *, stdout: TextIO, stderr: TextIO) -> int:
    """Run a dry plan by default or an explicitly authorized publication."""

    try:
        config_path, publish, authorization_path = _parse_tokens(tokens)
        config = _read_object(config_path, _MAX_CONFIG_BYTES, protected=publish)
        candidate, source_root, destination_root, sources, evidence, authority = _parse_config(
            config
        )
        verify_release_layout(source_root, destination_root)
        verify_release_sources(source_root, sources, evidence, candidate)

        if not publish:
            plan = ReleasePublisher(_DryRunProvider()).dry_run(candidate)
            receipt = {
                "action": "DRY_RUN",
                "artifact_checksums": list(plan.artifact_checksums),
                "candidate_sha256": plan.candidate_sha256,
                "disposition": ReleasePublishDisposition.DRY_RUN.value,
                "schema_version": 1,
                "source_disclosed": False,
                "store_identity_sha256": release_store_identity(destination_root),
                "tag": plan.tag,
            }
            stdout.write(_canonical_json(receipt) + "\n")
            return int(CliExitCode.COMPLETED)

        if authorization_path is None:
            raise ReleaseCliError()
        if authority is None:
            raise ReleaseCliError()
        authorization = _read_object(authorization_path, _MAX_AUTHORIZATION_BYTES)
        parsed_authorization = _parse_authorization(authorization, candidate.candidate_sha256)
        try:
            verifier = HmacReleaseAuthorizationVerifier(
                read_protected_release_key(authority[0]), authority[1]
            )
            provider = LocalReleaseProvider(
                destination_root,
                source_root=source_root,
                artifacts=sources,
                evidence=evidence,
                authorization=verifier,
            )
        except Exception:
            stdout.write(_failure_receipt("ERROR") + "\n")
            return int(CliExitCode.OPERATIONAL_ERROR)
        publisher = ReleasePublisher(provider)
        plan = publisher.dry_run(candidate)
        result = publisher.publish(AuthorizedPublishRequest(plan, parsed_authorization))
        receipt = {
            "action": "PUBLISH",
            "artifact_checksums": list(result.artifact_checksums),
            "candidate_sha256": result.candidate_sha256,
            "disposition": result.disposition.value,
            "remote_candidate_sha256": result.remote_candidate_sha256,
            "remote_immutable_id": result.remote_immutable_id,
            "schema_version": 1,
            "source_disclosed": result.source_disclosed,
            "tag": result.tag,
        }
        stdout.write(_canonical_json(receipt) + "\n")
        if result.disposition in {
            ReleasePublishDisposition.PUBLISHED,
            ReleasePublishDisposition.IDEMPOTENT,
        }:
            return int(CliExitCode.COMPLETED)
        return int(CliExitCode.OPERATIONAL_ERROR)
    except KeyboardInterrupt:
        stdout.write(_failure_receipt("CANCELLED") + "\n")
        return int(CliExitCode.CANCELLED_OR_SUPERSEDED)
    except Exception:
        stdout.write(_failure_receipt("ERROR") + "\n")
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)


class _DryRunProvider:
    def get_tag(self, _tag: str, _authorization: object | None = None) -> None:
        return None

    def create_release(self, _request: AuthorizedPublishRequest) -> RemoteRelease:
        raise ReleaseCliError()


def _parse_tokens(tokens: tuple[str, ...]) -> tuple[Path, bool, Path | None]:
    if not tokens or tokens[0] != "release":
        raise ReleaseCliError()
    config: Path | None = None
    authorization: Path | None = None
    publish = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--config" and config is None and index + 1 < len(tokens):
            index += 1
            config = Path(tokens[index])
        elif token == "--publish" and not publish:
            publish = True
        elif token == "--authorization" and authorization is None and index + 1 < len(tokens):
            index += 1
            authorization = Path(tokens[index])
        else:
            raise ReleaseCliError()
        index += 1
    if config is None or (publish != (authorization is not None)):
        raise ReleaseCliError()
    return config, publish, authorization


def _read_object(path: Path, limit: int, *, protected: bool = False) -> dict[str, object]:
    raw = (
        read_protected_release_config(path, limit)
        if protected
        else read_bounded_local_file(path, limit)
    )
    value = json.loads(raw.decode("ascii"))
    if type(value) is not dict or raw != _canonical_json(value).encode("ascii"):
        raise ReleaseCliError()
    return value


def _parse_config(
    value: dict[str, object],
) -> tuple[
    ReleaseCandidate,
    str,
    str,
    tuple[ReleaseArtifactSource, ...],
    tuple[ReleaseEvidenceSource, ...],
    tuple[str, str] | None,
]:
    if frozenset(value) not in {_CONFIG_KEYS, _PUBLISH_CONFIG_KEYS} or value["schema_version"] != 1:
        raise ReleaseCliError()
    source_root = _text(value["source_root"])
    destination_root = _text(value["destination_root"])
    candidate_value = value["candidate"]
    source_values = value["artifact_sources"]
    evidence_values = value["evidence_sources"]
    if type(candidate_value) is not dict or set(candidate_value) != _CANDIDATE_KEYS:
        raise ReleaseCliError()
    artifact_values = candidate_value["artifacts"]
    if type(artifact_values) is not list or not artifact_values or len(artifact_values) > 256:
        raise ReleaseCliError()
    artifacts: list[ReleaseArtifact] = []
    for item in artifact_values:
        if type(item) is not dict or set(item) != _ARTIFACT_KEYS:
            raise ReleaseCliError()
        artifacts.append(
            ReleaseArtifact(
                _text(item["artifact_id"]),
                _text(item["checksum_sha256"]),
                _text(item["signature_sha256"]),
            )
        )
    candidate = ReleaseCandidate(
        _text(candidate_value["version"]),
        _text(candidate_value["source_tree_sha256"]),
        _text(candidate_value["closure_activation_sha256"]),
        _text(candidate_value["sbom_sha256"]),
        _text(candidate_value["provenance_sha256"]),
        _text(candidate_value["checksums_sha256"]),
        _text(candidate_value["server_image_digest"]),
        _text(candidate_value["worker_image_digest"]),
        tuple(artifacts),
        _text(candidate_value["release_signature_sha256"]),
        _text(candidate_value["candidate_sha256"]),
    )
    if type(source_values) is not list or len(source_values) != len(artifacts):
        raise ReleaseCliError()
    sources: list[ReleaseArtifactSource] = []
    for item in source_values:
        if type(item) is not dict or set(item) != _SOURCE_KEYS:
            raise ReleaseCliError()
        sources.append(
            ReleaseArtifactSource(
                _text(item["artifact_id"]),
                _text(item["artifact_relative_path"]),
                _text(item["signature_relative_path"]),
            )
        )
    authority_value = value.get("publish_authority")
    authority: tuple[str, str] | None = None
    if authority_value is not None:
        if type(authority_value) is not dict or set(authority_value) != _PUBLISH_AUTHORITY_KEYS:
            raise ReleaseCliError()
        key_file = _text(authority_value["key_file"])
        key_id = _text(authority_value["key_id"])
        if not Path(key_file).is_absolute() or _ID.fullmatch(key_id) is None:
            raise ReleaseCliError()
        authority = (key_file, key_id)
    if type(evidence_values) is not list or len(evidence_values) != 8:
        raise ReleaseCliError()
    evidence: list[ReleaseEvidenceSource] = []
    for item in evidence_values:
        if type(item) is not dict or set(item) != _EVIDENCE_SOURCE_KEYS:
            raise ReleaseCliError()
        evidence.append(
            ReleaseEvidenceSource(_text(item["evidence_id"]), _text(item["relative_path"]))
        )
    return candidate, source_root, destination_root, tuple(sources), tuple(evidence), authority


def _parse_authorization(
    value: dict[str, object],
    candidate_sha256: str,
) -> PublishAuthorization:
    if set(value) != _AUTHORIZATION_KEYS or value["schema_version"] != 1:
        raise ReleaseCliError()
    action = _text(value["action"])
    approver_id = _text(value["approver_id"])
    authorization_id = _text(value["authorization_id"])
    supplied_candidate = _text(value["candidate_sha256"])
    key_id = _text(value["key_id"])
    nonce = _text(value["nonce"])
    expires_at = value["expires_at"]
    supplied_signature = _text(value["signature_sha256"])
    store_identity_sha256 = _text(value["store_identity_sha256"])
    if type(expires_at) is not int or supplied_candidate != candidate_sha256:
        raise ReleaseCliError()
    return PublishAuthorization(
        authorization_id,
        action,
        approver_id,
        supplied_candidate,
        expires_at,
        key_id,
        nonce,
        store_identity_sha256,
        supplied_signature,
    )


def _text(value: object) -> str:
    if type(value) is not str or not value or len(value) > 4096:
        raise ReleaseCliError()
    return value


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _failure_receipt(disposition: str) -> str:
    return _canonical_json(
        {
            "action": "REJECTED",
            "disposition": disposition,
            "schema_version": 1,
            "source_disclosed": False,
        }
    )


__all__ = ["ReleaseCliError", "run_release_command"]
