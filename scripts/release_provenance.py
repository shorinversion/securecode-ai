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

SCHEMA_VERSION: Final = "securecode.release-provenance.v1"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class ProvenanceError(ValueError):
    """Bounded provenance failure that never carries file contents."""


def _git(root: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env={
                **os.environ,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0",
            },
        )
    except (OSError, subprocess.SubprocessError):
        raise ProvenanceError("local git metadata is unavailable") from None
    return completed.stdout.strip()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _tracked_files(root: Path) -> list[str]:
    listing = _git(root, "ls-files", "-z")
    names = [name for name in listing.split("\0") if name]
    if not names:
        raise ProvenanceError("tracked file inventory is empty")
    return sorted(names)


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


def build_provenance(
    *,
    root: Path = REPOSITORY_ROOT,
    sbom: Path | None = None,
) -> tuple[dict[str, Any], str]:
    if not root.is_absolute() or not root.is_dir():
        raise ProvenanceError("repository root is unavailable")
    commit = _git(root, "rev-parse", "HEAD")
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise ProvenanceError("commit identity is invalid")

    sbom_sha256: str | None = None
    if sbom is not None:
        if not sbom.is_absolute() or not sbom.is_file():
            raise ProvenanceError("sbom file is unavailable")
        sbom_sha256 = _sha256_bytes(sbom.read_bytes())

    files: list[dict[str, Any]] = []
    checksum_lines: list[str] = []
    inventory = hashlib.sha256()
    for name in _tracked_files(root):
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ProvenanceError("tracked path escapes the repository")
        path = root / relative
        if not path.is_file():
            raise ProvenanceError("tracked file is unavailable")
        payload = path.read_bytes()
        digest = _sha256_bytes(payload)
        files.append({"path": name, "sha256": digest, "size_bytes": len(payload)})
        checksum_lines.append(f"{digest}  {name}")
        inventory.update(name.encode("utf-8"))
        inventory.update(b"\0")
        inventory.update(digest.encode("ascii"))
        inventory.update(b"\n")

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
    arguments = parser.parse_args(argv)
    try:
        manifest, checksums = build_provenance(root=arguments.root, sbom=arguments.sbom)
        _write(
            arguments.output,
            json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True).encode("ascii")
            + b"\n",
            suffix=".json",
        )
        _write(arguments.checksums, checksums.encode("ascii"), suffix=".txt")
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
