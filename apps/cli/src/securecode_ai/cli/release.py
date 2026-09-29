"""Explicit, fail-closed local release administration command."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Final, TextIO

from securecode_ai.adapters.release_cli_config import (
    HmacReleaseAuthorizationVerifier,
    bind_release_sbom_inputs,
    parse_release_dependency_policy,
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
    ReleaseSbomBinding,
    ReleaseSbomInput,
)
from securecode_ai.contracts import CliExitCode
from securecode_ai.core.release_candidate import ReleaseArtifact, ReleaseCandidate
from securecode_ai.core.release_provenance import checksums as release_checksums
from securecode_ai.core.release_publisher import (
    AuthorizedPublishRequest,
    PublishAuthorization,
    ReleasePublishDisposition,
    ReleasePublisher,
    RemoteRelease,
)
from securecode_ai.core.supply_chain import DependencyPolicy

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
_PUBLISH_CONFIG_KEYS: Final = _CONFIG_KEYS | {"dependency_policy", "publish_authority"}
_SBOM_CONFIG_KEYS: Final = _CONFIG_KEYS | {"sbom_binding"}
_PUBLISH_SBOM_CONFIG_KEYS: Final = _PUBLISH_CONFIG_KEYS | {"sbom_binding"}
_SBOM_INPUT_CONFIG_KEYS: Final = _CONFIG_KEYS | {"sbom_inputs"}
_PUBLISH_SBOM_INPUT_CONFIG_KEYS: Final = _PUBLISH_CONFIG_KEYS | {"sbom_inputs"}
_PUBLISH_GENERATED_CONFIG_KEYS: Final = _PUBLISH_SBOM_INPUT_CONFIG_KEYS | {"provenance_inputs"}
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
_SBOM_BINDING_KEYS: Final = {
    "assessment_relative_path",
    "assessment_sha256",
    "report_relative_path",
    "report_sha256",
}
_SBOM_INPUT_KEYS: Final = {"assessment_relative_path", "report_relative_path"}
_PROVENANCE_INPUT_KEYS: Final = {
    "artifact_id",
    "builder_id",
    "image_digest",
    "workflow_sha256",
}
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
        (
            candidate,
            source_root,
            destination_root,
            sources,
            evidence,
            authority,
            dependency_policy,
            sbom_binding,
            sbom_inputs,
            provenance_inputs,
        ) = _parse_config(config)
        verify_release_layout(source_root, destination_root)
        verifier = None
        parsed_authorization = None
        if publish:
            if (
                authorization_path is None
                or authority is None
                or dependency_policy is None
                or provenance_inputs is None
                or sbom_inputs is None
            ):
                raise ReleaseCliError()
            authorization = _read_object(authorization_path, _MAX_AUTHORIZATION_BYTES)
            parsed_authorization = _parse_authorization(authorization, candidate.candidate_sha256)
            verifier = HmacReleaseAuthorizationVerifier(
                read_protected_release_key(authority[0]), authority[1]
            )
            if parsed_authorization.store_identity_sha256 != release_store_identity(
                destination_root
            ) or not verifier.verify(parsed_authorization, now=int(time.time())):
                raise ReleaseCliError()
        elif provenance_inputs is not None:
            raise ReleaseCliError()
        if provenance_inputs is not None:
            if sbom_inputs is None:
                raise ReleaseCliError()
            _generate_release_evidence(
                source_root,
                sources,
                evidence,
                candidate,
                sbom_inputs,
                provenance_inputs,
            )
        if sbom_inputs is not None:
            sbom_binding = bind_release_sbom_inputs(source_root, sbom_inputs)
        verify_release_sources(source_root, sources, evidence, candidate, sbom_binding)

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

        if sbom_binding is None:
            raise ReleaseCliError()
        try:
            if verifier is None or parsed_authorization is None or dependency_policy is None:
                raise ReleaseCliError()
            provider = LocalReleaseProvider(
                destination_root,
                source_root=source_root,
                artifacts=sources,
                evidence=evidence,
                authorization=verifier,
                dependency_policy=dependency_policy,
                sbom_binding=sbom_binding,
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
    DependencyPolicy | None,
    ReleaseSbomBinding | None,
    ReleaseSbomInput | None,
    dict[str, str] | None,
]:
    if (
        frozenset(value)
        not in {
            _CONFIG_KEYS,
            _SBOM_CONFIG_KEYS,
            _PUBLISH_CONFIG_KEYS,
            _PUBLISH_SBOM_CONFIG_KEYS,
            _SBOM_INPUT_CONFIG_KEYS,
            _PUBLISH_SBOM_INPUT_CONFIG_KEYS,
            _PUBLISH_GENERATED_CONFIG_KEYS,
        }
        or value["schema_version"] != 1
    ):
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
    policy_value = value.get("dependency_policy")
    dependency_policy = (
        None if policy_value is None else parse_release_dependency_policy(policy_value)
    )
    binding_value = value.get("sbom_binding")
    sbom_binding = None
    if binding_value is not None:
        if type(binding_value) is not dict or set(binding_value) != _SBOM_BINDING_KEYS:
            raise ReleaseCliError()
        sbom_binding = ReleaseSbomBinding(
            _text(binding_value["report_relative_path"]),
            _text(binding_value["assessment_relative_path"]),
            _text(binding_value["report_sha256"]),
            _text(binding_value["assessment_sha256"]),
        )
    input_value = value.get("sbom_inputs")
    sbom_inputs = None
    if input_value is not None:
        if type(input_value) is not dict or set(input_value) != _SBOM_INPUT_KEYS:
            raise ReleaseCliError()
        sbom_inputs = ReleaseSbomInput(
            _text(input_value["report_relative_path"]),
            _text(input_value["assessment_relative_path"]),
        )
    if sbom_binding is not None and sbom_inputs is not None:
        raise ReleaseCliError()
    provenance_value = value.get("provenance_inputs")
    provenance_inputs = None
    if provenance_value is not None:
        if type(provenance_value) is not dict or set(provenance_value) != _PROVENANCE_INPUT_KEYS:
            raise ReleaseCliError()
        provenance_inputs = {key: _text(provenance_value[key]) for key in _PROVENANCE_INPUT_KEYS}
        if (
            _ID.fullmatch(provenance_inputs["artifact_id"]) is None
            or _ID.fullmatch(provenance_inputs["builder_id"]) is None
            or re.fullmatch(r"[0-9a-f]{64}", provenance_inputs["workflow_sha256"]) is None
        ):
            raise ReleaseCliError()
    if type(evidence_values) is not list or len(evidence_values) != 8:
        raise ReleaseCliError()
    evidence: list[ReleaseEvidenceSource] = []
    for item in evidence_values:
        if type(item) is not dict or set(item) != _EVIDENCE_SOURCE_KEYS:
            raise ReleaseCliError()
        evidence.append(
            ReleaseEvidenceSource(_text(item["evidence_id"]), _text(item["relative_path"]))
        )
    return (
        candidate,
        source_root,
        destination_root,
        tuple(sources),
        tuple(evidence),
        authority,
        dependency_policy,
        sbom_binding,
        sbom_inputs,
        provenance_inputs,
    )


def _generate_release_evidence(
    source_root: str,
    artifacts: tuple[ReleaseArtifactSource, ...],
    evidence: tuple[ReleaseEvidenceSource, ...],
    candidate: ReleaseCandidate,
    sbom_inputs: ReleaseSbomInput,
    provenance_inputs: dict[str, str],
) -> None:
    """Generate release evidence through the repository producer interfaces."""

    root = Path(source_root).resolve(strict=True)
    scripts = Path(__file__).resolve().parents[5] / "scripts"
    assessment_path = root.joinpath(*PurePosixPath(sbom_inputs.assessment_relative_path).parts)
    evidence_paths = {item.evidence_id: item.relative_path for item in evidence}
    release_sbom_path = evidence_paths["sbom_sha256"]
    inventory_path = evidence_paths["provenance_sha256"] + ".inventory.json"
    generated_paths = (
        sbom_inputs.report_relative_path,
        release_sbom_path,
        inventory_path,
        evidence_paths["checksums_sha256"],
        evidence_paths["provenance_sha256"],
    )
    protected_paths = {
        sbom_inputs.assessment_relative_path,
        *(item.artifact_relative_path for item in artifacts),
        *(item.signature_relative_path for item in artifacts),
    }
    if len(generated_paths) != len(set(generated_paths)) or set(generated_paths) & protected_paths:
        raise ReleaseCliError()

    candidate_artifacts = {item.artifact_id: item for item in candidate.artifacts}
    selected_artifact = candidate_artifacts.get(provenance_inputs["artifact_id"])
    if selected_artifact is None or provenance_inputs["image_digest"] not in {
        candidate.server_image_digest,
        candidate.worker_image_digest,
    }:
        raise ReleaseCliError()
    artifact_sources = {item.artifact_id: item for item in artifacts}
    if set(artifact_sources) != set(candidate_artifacts):
        raise ReleaseCliError()
    artifact_checksums = tuple(
        (item.artifact_relative_path, candidate_artifacts[item.artifact_id].checksum_sha256)
        for item in artifacts
    )
    with tempfile.TemporaryDirectory(prefix=".release-evidence-", dir=root) as temporary:
        work = Path(temporary)
        _run_release_script(
            scripts / "sbom.py",
            "--lock",
            str(root / "uv.lock"),
            "--pyproject",
            str(root / "pyproject.toml"),
            "--output",
            str(work / "report.json"),
            "--assessment",
            str(assessment_path),
            "--release-output",
            str(work / "release-sbom.json"),
        )
        report_bytes = (work / "report.json").read_bytes()
        release_sbom = (work / "release-sbom.json").read_bytes()
        _run_release_script(
            scripts / "release_provenance.py",
            "--root",
            str(root),
            "--sbom",
            str(work / "release-sbom.json"),
            "--output",
            str(work / "inventory.json"),
            "--checksums",
            str(work / "checksums.txt"),
            *(
                value
                for path, digest in artifact_checksums
                for value in ("--artifact", path, digest)
            ),
            "--attestation-output",
            str(work / "attestation.json"),
            "--builder-id",
            provenance_inputs["builder_id"],
            "--workflow-sha256",
            provenance_inputs["workflow_sha256"],
            "--artifact-digest",
            selected_artifact.checksum_sha256,
            "--image-digest",
            provenance_inputs["image_digest"],
        )
        inventory_bytes = (work / "inventory.json").read_bytes()
        checksum_bytes = (work / "checksums.txt").read_bytes()
        attestation = json.loads((work / "attestation.json").read_bytes())
    if type(attestation) is not dict:
        raise ReleaseCliError()
    attestation_bytes = _canonical_json(attestation).encode("ascii")
    canonical_artifact_checksums = release_checksums(
        {artifact.artifact_id: artifact.checksum_sha256 for artifact in candidate.artifacts}
    )
    if (
        hashlib.sha256(release_sbom).hexdigest() != candidate.sbom_sha256
        or hashlib.sha256(attestation_bytes).hexdigest() != candidate.provenance_sha256
        or hashlib.sha256(canonical_artifact_checksums).hexdigest() != candidate.checksums_sha256
        or attestation["source_tree"] != candidate.source_tree_sha256
    ):
        raise ReleaseCliError()

    _write_generated_source(root, sbom_inputs.report_relative_path, report_bytes)
    _write_generated_source(
        root,
        release_sbom_path,
        release_sbom,
    )
    _write_generated_source(root, inventory_path, inventory_bytes)
    _write_generated_source(root, evidence_paths["checksums_sha256"], checksum_bytes)
    _write_generated_source(root, evidence_paths["provenance_sha256"], attestation_bytes)


def _run_release_script(script: Path, *arguments: str) -> None:
    """Run one repository evidence producer in an isolated interpreter."""

    try:
        completed = subprocess.run(
            [sys.executable, "-I", str(script), *arguments],
            capture_output=True,
            check=False,
            timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ReleaseCliError() from None
    if completed.returncode != 0:
        raise ReleaseCliError()


def _write_generated_source(root: Path, relative_path: str, payload: bytes) -> None:
    relative = PurePosixPath(relative_path)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or "\\" in relative_path
        or type(payload) is not bytes
    ):
        raise ReleaseCliError()
    target = root.joinpath(*relative.parts)
    current = root
    try:
        for part in relative.parts[:-1]:
            current = current / part
            if current.is_symlink():
                raise ReleaseCliError()
            current.mkdir(exist_ok=True)
            if not current.is_dir():
                raise ReleaseCliError()
        target.parent.resolve(strict=True).relative_to(root)
        if target.exists() or target.is_symlink():
            info = target.stat(follow_symlinks=False)
            if not target.is_file() or target.is_symlink() or info.st_nlink != 1:
                raise ReleaseCliError()
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except ReleaseCliError:
        raise
    except (OSError, ValueError):
        raise ReleaseCliError() from None


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
