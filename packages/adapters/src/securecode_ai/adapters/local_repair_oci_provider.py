"""Immutable Git snapshot to rootless OCI validation composition."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION, ResourceUsage
from securecode_ai.core.regression import RegressionRevisionRole, evaluate_regression
from securecode_ai.core.sandbox import SandboxProfile, _profile_hash
from securecode_ai.core.validation import ValidationStage

from .git_snapshot import GitRevisionSnapshot, OfflineGitObjectReader, materialize_git_snapshot
from .local_repair_diff import validated_diff_paths
from .local_repair_oci_protocol import canonical_json, image_digest
from .local_repair_oci_runtime import DockerCliOciRuntime, LocalRepairOciRuntimeError
from .patch_artifact import StoredPatchArtifact

if TYPE_CHECKING:
    from .local_repair_validation import PreparedLocalOciValidation

_BUNDLE_DOMAIN = b"securecode-ai/local-repair-oci-bundle/v1\x00"
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024


class InstalledLocalOciValidationPort:
    """Prepare one immutable bundle and bind it to a pinned validator image."""

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        selected = os.environ if environment is None else environment
        self._environment = {str(key): str(value) for key, value in selected.items()}

    def prepare(
        self,
        *,
        repository_objects: Path,
        parent_head_sha: str,
        patch: StoredPatchArtifact,
        git_executable: Path,
    ) -> PreparedLocalOciValidation:
        from .local_repair_validation import LocalRepairValidationError, PreparedLocalOciValidation

        temporary: tempfile.TemporaryDirectory[str] | None = None
        runtime: DockerCliOciRuntime | None = None
        try:
            image_reference = self._required_image()
            docker, docker_sha256 = self._docker_executable()
            docker_environment = _approved_docker_environment(self._environment, docker)
            profile = _sandbox_profile()
            reader = OfflineGitObjectReader(
                objects_dir=repository_objects,
                git_executable=git_executable,
            )
            snapshot = materialize_git_snapshot(reader, parent_head_sha)
            if snapshot.head_sha != parent_head_sha:
                raise ValueError
            modes = _snapshot_modes(reader, snapshot)
            temporary = tempfile.TemporaryDirectory(prefix="securecode-repair-oci-")
            owned_temporary = temporary
            root = Path(temporary.name).absolute()
            if "," in str(root):
                raise ValueError
            bundle_sha = _materialize_bundle(root, snapshot, modes, patch, profile, image_reference)
            runtime = DockerCliOciRuntime(
                docker_executable=docker,
                docker_executable_sha256=docker_sha256,
                image_reference=image_reference,
                bundle_root=root,
                bundle_sha256=bundle_sha,
                parent_head_sha=parent_head_sha,
                patch_sha256=patch.architect_result.patch_candidate.unified_diff_sha256,
                profile=profile,
                environment=docker_environment,
                on_close=lambda: _release_temporary(owned_temporary, root),
            )
            receipt = runtime.prepare(
                expected_case_ids=tuple(case.case_id for case in patch.regression.cases)
            )
            fixed_regression = evaluate_regression(
                patch.regression,
                patch.root_cause,
                patch.invariant,
                revision_role=RegressionRevisionRole.FIXED_CANDIDATE,
                evaluated_head_sha=receipt.fixed_head_sha,
                observations=receipt.observations,
            )
            usage = ResourceUsage(
                schema_version=CONTRACT_SCHEMA_VERSION,
                elapsed_ms=0,
                peak_memory_bytes=0,
                cpu_time_ms=0,
            )
            commands = {
                stage.value: (
                    *runtime.command_prefix,
                    "stage",
                    stage.value,
                    "/securecode/input/manifest.json",
                )
                for stage in ValidationStage
            }
            return PreparedLocalOciValidation(
                runtime=runtime,
                image_digest=runtime.image_digest,
                command_allowlist=commands,
                seccomp_profile_id="runtime-default",
                sandbox_profile=profile,
                fixed_head_sha=receipt.fixed_head_sha,
                fixed_regression=fixed_regression,
                stage_resources=(usage,) * len(tuple(ValidationStage)),
                preparation_receipt_sha256=runtime.validation_receipt_sha256(
                    receipt.receipt_sha256
                ),
            )
        except LocalRepairValidationError:
            raise
        except Exception as error:
            if runtime is not None:
                runtime.close()
            elif temporary is not None:
                _release_temporary(temporary, Path(temporary.name))
            reason = (
                error.reason
                if isinstance(error, LocalRepairOciRuntimeError)
                else "VALIDATION_RUNTIME_UNAVAILABLE"
            )
            raise LocalRepairValidationError(reason) from None

    def _required_image(self) -> str:
        reference = self._environment.get("SECURECODE_AI_VALIDATION_IMAGE", "")
        image_digest(reference)
        return reference

    def _docker_executable(self) -> tuple[Path, str]:
        approved_sha256 = self._environment.get("SECURECODE_AI_DOCKER_EXECUTABLE_SHA256", "")
        if re.fullmatch(r"[0-9a-f]{64}", approved_sha256) is None:
            raise LocalRepairOciRuntimeError("OCI_RUNTIME_AUTHORITY_UNAVAILABLE")
        selected = self._environment.get("SECURECODE_AI_DOCKER_EXECUTABLE")
        if selected:
            path = Path(selected)
        else:
            found = shutil.which("docker", path=self._environment.get("PATH"))
            if not found:
                raise LocalRepairOciRuntimeError()
            path = Path(found)
        try:
            absolute = path.resolve(strict=True)
        except OSError:
            raise LocalRepairOciRuntimeError() from None
        if (
            not absolute.is_absolute()
            or not absolute.is_file()
            or absolute.is_symlink()
            or "\x00" in str(absolute)
        ):
            raise LocalRepairOciRuntimeError()
        try:
            observed_sha256 = hashlib.sha256(absolute.read_bytes()).hexdigest()
        except OSError:
            raise LocalRepairOciRuntimeError() from None
        if observed_sha256 != approved_sha256:
            raise LocalRepairOciRuntimeError("OCI_RUNTIME_AUTHORITY_MISMATCH")
        return absolute, approved_sha256


DockerLocalRepairValidationPort = InstalledLocalOciValidationPort


def _sandbox_profile() -> SandboxProfile:
    values: dict[str, object] = {
        "profile_id": "installed-local-rootless-oci",
        "profile_version": "1.0.0",
        "network_disabled": True,
        "credentials_disabled": True,
        "host_access_disabled": True,
        "rootless": True,
        "read_only_root": True,
        "max_cpu_time_ms": 60_000,
        "max_memory_bytes": 512 * 1024 * 1024,
        "max_processes": 64,
        "max_disk_bytes": 256 * 1024 * 1024,
        "max_output_bytes": 131_072,
        "max_elapsed_ms": 120_000,
        "profile_sha256": "0" * 64,
        "schema_version": "1.0.0",
    }
    seed = object.__new__(SandboxProfile)
    for name, value in values.items():
        object.__setattr__(seed, name, value)
    digest = _profile_hash(seed)
    return SandboxProfile(
        profile_id="installed-local-rootless-oci",
        profile_version="1.0.0",
        network_disabled=True,
        credentials_disabled=True,
        host_access_disabled=True,
        rootless=True,
        read_only_root=True,
        max_cpu_time_ms=60_000,
        max_memory_bytes=512 * 1024 * 1024,
        max_processes=64,
        max_disk_bytes=256 * 1024 * 1024,
        max_output_bytes=131_072,
        max_elapsed_ms=120_000,
        profile_sha256=digest,
    )


def _materialize_bundle(
    root: Path,
    snapshot: GitRevisionSnapshot,
    modes: dict[str, str],
    patch: StoredPatchArtifact,
    profile: SandboxProfile,
    image_reference: str,
) -> str:
    source = root / "source"
    source.mkdir()
    files: list[dict[str, object]] = []
    total = 0
    for item in snapshot.files:
        destination = _safe_destination(source, item.path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        _write_once(destination, item.content)
        total += len(item.content)
        files.append(
            {
                "blob_oid": item.blob_oid,
                "content_sha256": item.content_sha256,
                "mode": modes[item.path],
                "path": item.path,
                "size_bytes": len(item.content),
            }
        )
    if total > _MAX_SNAPSHOT_BYTES or total + len(patch.patch_bytes) > profile.max_disk_bytes // 2:
        raise ValueError
    _write_once(root / "patch.diff", patch.patch_bytes)
    candidate = patch.architect_result.patch_candidate
    patch_paths = validated_diff_paths(patch.patch_bytes.decode("utf-8", errors="strict"))
    finding_paths = {location.path for location in patch.finding.locations}
    if not patch_paths or not set(patch_paths).issubset(finding_paths):
        raise ValueError
    base = {
        "files": files,
        "finding": _jsonable(patch.finding),
        "image_digest": image_digest(image_reference),
        "invariant": _jsonable(patch.invariant),
        "parent_head_sha": snapshot.head_sha,
        "parent_tree_oid": snapshot.tree_oid,
        "patch": {
            "path": "patch.diff",
            "allowed_paths": list(patch_paths),
            "sha256": candidate.unified_diff_sha256,
            "size_bytes": len(patch.patch_bytes),
        },
        "protocol_id": "securecode-local-repair-oci",
        "protocol_version": "1.0.0",
        "regression": _jsonable(patch.regression),
        "root_cause": _jsonable(patch.root_cause),
        "schema_version": "1.0.0",
        "stages": [stage.value for stage in ValidationStage],
    }
    bundle_sha = hashlib.sha256(_BUNDLE_DOMAIN + canonical_json(base)).hexdigest()
    manifest = canonical_json({**base, "bundle_sha256": bundle_sha})
    if len(manifest) > _MAX_MANIFEST_BYTES:
        raise ValueError
    _write_once(root / "manifest.json", manifest)
    _make_read_only(root)
    return bundle_sha


def _snapshot_modes(
    reader: OfflineGitObjectReader, snapshot: GitRevisionSnapshot
) -> dict[str, str]:
    entries: dict[str, tuple[str, str]] = {}

    def walk(tree_oid: str, prefix: str, depth: int) -> None:
        if depth > 32 or len(entries) > 4096:
            raise ValueError
        raw = reader.read("tree", tree_oid, max_bytes=4 * 1024 * 1024)
        cursor = 0
        while cursor < len(raw):
            terminator = raw.find(b"\0", cursor)
            if terminator < 0 or terminator + 21 > len(raw):
                raise ValueError
            header = raw[cursor:terminator]
            mode, separator, name_bytes = header.partition(b" ")
            if not separator or not name_bytes or b"/" in name_bytes:
                raise ValueError
            try:
                name = name_bytes.decode("utf-8", errors="strict")
            except UnicodeError:
                raise ValueError from None
            child_oid = raw[terminator + 1 : terminator + 21].hex()
            cursor = terminator + 21
            path = prefix + name
            if mode == b"40000":
                walk(child_oid, path + "/", depth + 1)
            elif mode in {b"100644", b"100755"}:
                if path in entries or len(entries) >= 4096:
                    raise ValueError
                entries[path] = (mode.decode("ascii"), child_oid)
            else:
                raise ValueError

    walk(snapshot.tree_oid, "", 0)
    expected = {item.path: item.blob_oid for item in snapshot.files}
    if set(entries) != set(expected) or any(
        entries[path][1] != blob_oid for path, blob_oid in expected.items()
    ):
        raise ValueError
    return {path: entries[path][0] for path in sorted(entries)}


def _safe_destination(root: Path, relative: str) -> Path:
    if type(relative) is not str or not relative or "\x00" in relative:
        raise ValueError
    destination = (root / Path(*relative.split("/"))).absolute()
    try:
        destination.relative_to(root)
    except ValueError:
        raise ValueError from None
    return destination


def _write_once(path: Path, content: bytes) -> None:
    if type(content) is not bytes or path.exists() or path.is_symlink():
        raise ValueError
    try:
        with path.open("xb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except OSError:
        raise ValueError from None
    if not path.is_file() or path.is_symlink():
        raise ValueError


def _make_read_only(root: Path) -> None:
    read = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    traverse = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_symlink():
            raise ValueError
        path.chmod(read | (traverse if path.is_dir() else 0))
    root.chmod(read | traverse)


def _release_temporary(temporary: tempfile.TemporaryDirectory[str], root: Path) -> None:
    if root.exists():
        for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            with suppress(OSError):
                path.chmod(stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
        with suppress(OSError):
            root.chmod(stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
    temporary.cleanup()


def _approved_docker_environment(environment: Mapping[str, str], docker: Path) -> dict[str, str]:
    if environment.get("DOCKER_HOST") or environment.get("DOCKER_CONTEXT") not in {
        None,
        "",
        "default",
    }:
        raise LocalRepairOciRuntimeError("OCI_RUNTIME_AUTHORITY_UNAVAILABLE")
    allowed = (
        "SystemRoot",
        "WINDIR",
        "PATH",
        "TEMP",
        "TMP",
    )
    selected = {name: environment[name] for name in allowed if name in environment}
    try:
        result = subprocess.run(
            (
                str(docker),
                "context",
                "inspect",
                "default",
                "--format",
                "{{json .Endpoints.docker.Host}}",
            ),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            env=selected,
            timeout=10,
        )
        endpoint = json.loads(result.stdout.decode("utf-8"))
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        raise LocalRepairOciRuntimeError("OCI_RUNTIME_AUTHORITY_UNAVAILABLE") from None
    if result.returncode != 0 or not _local_docker_endpoint(endpoint):
        raise LocalRepairOciRuntimeError("OCI_RUNTIME_AUTHORITY_UNAVAILABLE")
    selected["DOCKER_HOST"] = endpoint
    return selected


def _local_docker_endpoint(value: object) -> bool:
    if type(value) is not str:
        return False
    if os.name == "nt":
        return value.lower() == "npipe:////./pipe/docker_engine"
    if value == "unix:///var/run/docker.sock":
        return True
    if not value.startswith("unix:///run/user/") or not value.endswith("/docker.sock"):
        return False
    user = value.removeprefix("unix:///run/user/").removesuffix("/docker.sock")
    return user.isdigit() and hasattr(os, "getuid") and int(user) == os.getuid()


def _jsonable(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if is_dataclass(value):
        if isinstance(value, type):
            raise TypeError("dataclass type is not a serializable value")
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


__all__ = ["DockerLocalRepairValidationPort", "InstalledLocalOciValidationPort"]
