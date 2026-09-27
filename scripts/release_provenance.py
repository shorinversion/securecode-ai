"""Offline release provenance: commit identity, SBOM hash, tracked-file inventory.

Produces a JSON manifest plus a ``sha256sum -c`` compatible checksum file for the
release contents.  It shells out only to local ``git`` plumbing for the exact
commit and tracked-file list; it never fetches.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tomllib
from pathlib import Path
from typing import Any, Final
import re

SCHEMA_VERSION: Final = "securecode.release-provenance.v1"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}\Z")
_GIT_ENVIRONMENT_KEYS: Final = (
    "PATH",
    "SystemRoot",
    "WINDIR",
    "ComSpec",
    "PATHEXT",
    "SystemDrive",
    "TEMP",
    "TMP",
)


class ProvenanceError(ValueError):
    """Bounded provenance failure that never carries file contents."""


def _git_environment() -> dict[str, str]:
    environment = {
        key: value for key in _GIT_ENVIRONMENT_KEYS if (value := os.environ.get(key)) is not None
    }
    environment.update(
        {
            "GIT_CONFIG_COUNT": "0",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _git(root: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=_git_environment(),
        )
    except (OSError, subprocess.SubprocessError):
        raise ProvenanceError("local git metadata is unavailable") from None
    # ``git ls-files -z`` is path data, so strip only the record terminator.
    # ``str.strip`` would silently alter a tracked name with surrounding
    # whitespace before the checksum manifest is produced.
    return completed.stdout.rstrip("\r\n")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _tracked_files(root: Path) -> list[str]:
    listing = _git(root, "ls-files", "-z")
    names = [name for name in listing.split("\0") if name]
    if not names:
        raise ProvenanceError("tracked file inventory is empty")
    for name in names:
        relative = Path(name)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() != name
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in name)
        ):
            raise ProvenanceError("tracked path is not checksum-safe")
    if len(names) != len(set(names)):
        raise ProvenanceError("tracked file inventory contains duplicates")
    return sorted(names)


def _read_regular(path: Path, *, what: str) -> bytes:
    """Read a stable regular file without following a symlink outside root."""

    try:
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise ProvenanceError(f"{what} is unavailable")
        resolved = path.resolve(strict=True)
        if resolved != path:
            raise ProvenanceError(f"{what} is unavailable")
        return path.read_bytes()
    except ProvenanceError:
        raise
    except (OSError, RuntimeError):
        raise ProvenanceError(f"{what} is unavailable") from None


def _project_version(root: Path) -> str:
    path = root / "pyproject.toml"
    if not path.is_file():
        raise ProvenanceError("pyproject.toml is unavailable")
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        raise ProvenanceError("pyproject.toml cannot be parsed") from None
    project = document.get("project")
    version = project.get("version") if isinstance(project, dict) else None
    if not isinstance(version, str) or not version:
        raise ProvenanceError("project version is unavailable")
    return version


def _source_tree_sha256(root: Path, files: list[dict[str, Any]]) -> str:
    """Match the repository inventory digest used by the execution boundary."""

    digest = hashlib.sha256()
    for item in files:
        name = item.get("path")
        content_sha256 = item.get("sha256")
        size_bytes = item.get("size_bytes")
        if (
            type(name) is not str
            or type(content_sha256) is not str
            or _SHA256.fullmatch(content_sha256) is None
            or type(size_bytes) is not int
            or size_bytes < 0
        ):
            raise ProvenanceError("source tree inventory is invalid")
        path = root / Path(name)
        payload = _read_regular(path, what="tracked file")
        if len(payload) != size_bytes or _sha256_bytes(payload) != content_sha256:
            raise ProvenanceError("source tree inventory changed")
        encoded_name = name.encode("utf-8")
        digest.update(len(encoded_name).to_bytes(8, "big"))
        digest.update(encoded_name)
        digest.update(size_bytes.to_bytes(8, "big"))
        digest.update(bytes.fromhex(content_sha256))
    return digest.hexdigest()


def _require_attestation_text(value: object, *, what: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ProvenanceError(f"{what} is invalid")
    return value


def _require_attestation_hash(value: object, *, what: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ProvenanceError(f"{what} is invalid")
    return value


def _require_attestation_digest(value: object, *, what: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ProvenanceError(f"{what} is invalid")
    return value


def _require_clean_tree(root: Path) -> None:
    for arguments in (("diff", "--quiet", "HEAD", "--"), ("diff", "--cached", "--quiet", "HEAD", "--")):
        try:
            completed = subprocess.run(
                ["git", *arguments],
                cwd=root,
                check=False,
                capture_output=True,
                text=False,
                env=_git_environment(),
            )
        except (OSError, subprocess.SubprocessError):
            raise ProvenanceError("local git status is unavailable") from None
        if completed.returncode != 0:
            raise ProvenanceError("source tree is not clean")


def build_release_attestation(
    *,
    root: Path = REPOSITORY_ROOT,
    builder_id: str,
    workflow_sha256: str,
    artifact_digest: str,
    image_digest: str,
) -> dict[str, str]:
    """Produce the exact provenance document accepted by the release provider.

    Builder, workflow, artifact and image identities are mandatory inputs. They
    are never inferred from package names, local paths, or placeholder values.
    The source tree is derived from the clean checked-out tracked bytes and the
    lock hash is derived from the exact local ``uv.lock`` bytes.
    """

    if not root.is_absolute() or not root.is_dir():
        raise ProvenanceError("repository root is unavailable")
    _require_clean_tree(root)
    manifest, _ = build_provenance(root=root)
    commit = manifest.get("commit")
    if type(commit) is not str or _COMMIT.fullmatch(commit) is None:
        raise ProvenanceError("commit identity is invalid")
    files = manifest.get("files")
    if type(files) is not list:
        raise ProvenanceError("source tree inventory is invalid")
    source_tree = _source_tree_sha256(root, files)
    lock = root / "uv.lock"
    lock_sha256 = _sha256_bytes(_read_regular(lock, what="uv.lock"))
    return {
        "artifact_digest": _require_attestation_digest(
            artifact_digest, what="artifact digest"
        ),
        "builder_id": _require_attestation_text(builder_id, what="builder identity"),
        "image_digest": _require_attestation_digest(image_digest, what="image digest"),
        "lock_sha256": lock_sha256,
        "source_commit": commit,
        "source_tree": source_tree,
        "workflow_sha256": _require_attestation_hash(
            workflow_sha256, what="workflow hash"
        ),
    }


def build_provenance(
    *,
    root: Path = REPOSITORY_ROOT,
    sbom: Path | None = None,
    artifacts: tuple[tuple[str, str], ...] = (),
) -> tuple[dict[str, Any], str]:
    if not root.is_absolute() or not root.is_dir():
        raise ProvenanceError("repository root is unavailable")
    commit = _git(root, "rev-parse", "HEAD")
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise ProvenanceError("commit identity is invalid")

    sbom_sha256: str | None = None
    if sbom is not None:
        sbom_sha256 = _sha256_bytes(_read_regular(sbom, what="sbom file"))

    files: list[dict[str, Any]] = []
    checksum_lines: list[str] = []
    checksum_by_path: dict[str, str] = {}
    inventory = hashlib.sha256()
    for name in _tracked_files(root):
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ProvenanceError("tracked path escapes the repository")
        path = root / relative
        try:
            path.resolve(strict=True).relative_to(root.resolve(strict=True))
        except (OSError, RuntimeError, ValueError):
            raise ProvenanceError("tracked path escapes the repository") from None
        payload = _read_regular(path, what="tracked file")
        digest = _sha256_bytes(payload)
        files.append({"path": name, "sha256": digest, "size_bytes": len(payload)})
        checksum_lines.append(f"{digest}  {name}")
        checksum_by_path[name] = digest
        inventory.update(name.encode("utf-8"))
        inventory.update(b"\0")
        inventory.update(digest.encode("ascii"))
        inventory.update(b"\n")

    if type(artifacts) is not tuple:
        raise ProvenanceError("release artifact inputs are invalid")
    artifact_paths: set[str] = set()
    for item in artifacts:
        if type(item) is not tuple or len(item) != 2:
            raise ProvenanceError("release artifact input is invalid")
        relative_name, expected_digest = item
        if type(relative_name) is not str:
            raise ProvenanceError("release artifact input is invalid")
        relative = Path(relative_name)
        if (
            not relative_name
            or relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() != relative_name
            or "\\" in relative_name
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in relative_name)
            or type(expected_digest) is not str
            or _SHA256.fullmatch(expected_digest) is None
            or relative_name in artifact_paths
        ):
            raise ProvenanceError("release artifact input is invalid")
        artifact_paths.add(relative_name)
        path = root / relative
        try:
            path.resolve(strict=True).relative_to(root.resolve(strict=True))
        except (OSError, RuntimeError, ValueError):
            raise ProvenanceError("release artifact escapes the repository") from None
        payload = _read_regular(path, what="release artifact")
        digest = _sha256_bytes(payload)
        if digest != expected_digest:
            raise ProvenanceError("release artifact digest does not match")
        existing_digest = checksum_by_path.get(relative_name)
        if existing_digest is not None:
            if existing_digest != digest:
                raise ProvenanceError("release artifact checksum conflicts")
            continue
        checksum_lines.append(f"{digest}  {relative_name}")
        checksum_by_path[relative_name] = digest

    manifest = {
        "commit": commit,
        "file_count": len(files),
        "files": files,
        "inventory_sha256": inventory.hexdigest(),
        "project_version": _project_version(root),
        "sbom_sha256": sbom_sha256,
        "schema_version": SCHEMA_VERSION,
    }
    return manifest, "\n".join(checksum_lines) + "\n"


def _write(path: Path, payload: bytes, *, suffix: str) -> None:
    if not path.is_absolute() or path.suffix != suffix:
        raise ProvenanceError(f"output must be an absolute {suffix} path")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--checksums", required=True, type=Path)
    parser.add_argument(
        "--artifact", action="append", nargs=2, metavar=("PATH", "SHA256"), default=[]
    )
    parser.add_argument("--attestation-output", type=Path)
    parser.add_argument("--builder-id")
    parser.add_argument("--workflow-sha256")
    parser.add_argument("--artifact-digest")
    parser.add_argument("--image-digest")
    arguments = parser.parse_args(argv)
    try:
        manifest, checksums = build_provenance(
            root=arguments.root,
            sbom=arguments.sbom,
            artifacts=tuple((path, digest) for path, digest in arguments.artifact),
        )
        _write(
            arguments.output,
            json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True).encode("ascii")
            + b"\n",
            suffix=".json",
        )
        _write(arguments.checksums, checksums.encode("ascii"), suffix=".txt")
        attestation_arguments = (
            arguments.builder_id,
            arguments.workflow_sha256,
            arguments.artifact_digest,
            arguments.image_digest,
        )
        if arguments.attestation_output is not None:
            if any(value is None for value in attestation_arguments):
                raise ProvenanceError("attestation inputs are incomplete")
            attestation = build_release_attestation(
                root=arguments.root,
                builder_id=arguments.builder_id,
                workflow_sha256=arguments.workflow_sha256,
                artifact_digest=arguments.artifact_digest,
                image_digest=arguments.image_digest,
            )
            _write(
                arguments.attestation_output,
                json.dumps(
                    attestation,
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii"),
                suffix=".json",
            )
        elif any(value is not None for value in attestation_arguments):
            raise ProvenanceError("attestation output is required")
    except ProvenanceError as error:
        print(f"PROVENANCE=FAIL: {error}")
        return 1
    except OSError:
        print("PROVENANCE=FAIL: outputs cannot be written")
        return 1
    print(
        f"PROVENANCE=OK files={manifest['file_count']} "
        f"commit={manifest['commit'][:12]} digest={manifest['inventory_sha256'][:16]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
