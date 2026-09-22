"""Offline, deterministic CycloneDX 1.5 SBOM generated from the locked workspace.

The generator never contacts a registry: every component, version and hash comes
from the local ``uv.lock`` and ``pyproject.toml``.  The same inputs always produce
byte-identical output, so a release can re-derive and compare the SBOM.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tomllib
import uuid
from pathlib import Path
from typing import Any, Final

BOM_FORMAT: Final = "CycloneDX"
SPEC_VERSION: Final = "1.5"
SCHEMA_VERSION: Final = "securecode.sbom-report.v1"

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = REPOSITORY_ROOT / "uv.lock"
DEFAULT_PYPROJECT = REPOSITORY_ROOT / "pyproject.toml"


class SbomError(ValueError):
    """Bounded SBOM failure that never carries file contents."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _read_toml(path: Path, *, what: str) -> dict[str, Any]:
    if not path.is_absolute() or not path.is_file():
        raise SbomError(f"{what} is unavailable")
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        raise SbomError(f"{what} cannot be parsed") from None


def _hash_of(entry: object) -> tuple[str, str] | None:
    if not isinstance(entry, dict):
        return None
    raw = entry.get("hash")
    if not isinstance(raw, str) or ":" not in raw:
        return None
    algorithm, _, value = raw.partition(":")
    if algorithm != "sha256" or len(value) != 64:
        return None
    if any(character not in "0123456789abcdef" for character in value):
        return None
    return algorithm, value


def _component(package: dict[str, Any], workspace_names: frozenset[str]) -> dict[str, Any]:
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not name:
        raise SbomError("locked package name is invalid")
    if not isinstance(version, str) or not version:
        raise SbomError("locked package version is invalid")
    source = package.get("source")
    edition = source.get("editable") if isinstance(source, dict) else None
    directory = source.get("directory") if isinstance(source, dict) else None
    is_workspace = name in workspace_names or isinstance(edition, str) or isinstance(directory, str)

    hashes: list[dict[str, str]] = []
    for candidate in (package.get("sdist"), *(package.get("wheels") or [])):
        digest = _hash_of(candidate)
        if digest is not None and {"alg": digest[0], "content": digest[1]} not in hashes:
            hashes.append({"alg": digest[0], "content": digest[1]})
    hashes.sort(key=lambda item: (item["alg"], item["content"]))

    component: dict[str, Any] = {
        "bom-ref": f"{name}@{version}",
        "name": name,
        "purl": f"pkg:pypi/{name}@{version}",
        "type": "application" if is_workspace else "library",
        "version": version,
    }
    if hashes:
        component["hashes"] = hashes
    return component


def build_sbom(*, lock: Path = DEFAULT_LOCK, pyproject: Path = DEFAULT_PYPROJECT) -> dict[str, Any]:
    lock_document = _read_toml(lock, what="uv.lock")
    project_document = _read_toml(pyproject, what="pyproject.toml")

    project = project_document.get("project")
    if not isinstance(project, dict):
        raise SbomError("pyproject project table is unavailable")
    project_name = project.get("name")
    project_version = project.get("version")
    if not isinstance(project_name, str) or not project_name:
        raise SbomError("project name is unavailable")
    if not isinstance(project_version, str) or not project_version:
        raise SbomError("project version is unavailable")

    manifest = lock_document.get("manifest")
    members = manifest.get("members") if isinstance(manifest, dict) else None
    workspace_names = frozenset(item for item in (members or []) if isinstance(item, str))

    packages = lock_document.get("package")
    if not isinstance(packages, list) or not packages:
        raise SbomError("uv.lock carries no packages")
    components = [_component(package, workspace_names) for package in packages]
    components.sort(key=lambda item: (item["name"], item["version"]))
    seen: set[str] = set()
    for component in components:
        reference = component["bom-ref"]
        if reference in seen:
            raise SbomError("uv.lock carries a duplicate component reference")
        seen.add(reference)

    serial = uuid.UUID(
        bytes=hashlib.sha256(_canonical([project_name, project_version, components])).digest()[:16],
        version=5,
    )
    return {
        "bomFormat": BOM_FORMAT,
        "components": components,
        "metadata": {
            "component": {
                "bom-ref": f"{project_name}@{project_version}",
                "name": project_name,
                "type": "application",
                "version": project_version,
            },
            "schema_version": SCHEMA_VERSION,
        },
        "serialNumber": f"urn:uuid:{serial}",
        "specVersion": SPEC_VERSION,
        "version": 1,
    }


def _write(document: dict[str, Any], output: Path, *, pretty: bool) -> bytes:
    if not output.is_absolute() or output.suffix != ".json":
        raise SbomError("output must be an absolute .json path")
    payload = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
        sort_keys=True,
    ).encode("ascii")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload + b"\n")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--pyproject", type=Path, default=DEFAULT_PYPROJECT)
    parser.add_argument("--no-pretty", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        document = build_sbom(lock=arguments.lock, pyproject=arguments.pyproject)
        _write(document, arguments.output, pretty=not arguments.no_pretty)
    except SbomError as error:
        print(f"SBOM=FAIL: {error}")
        return 1
    except OSError:
        print("SBOM=FAIL: output cannot be written")
        return 1
    components = document["components"]
    print(
        f"SBOM=OK components={len(components)} "
        f"workspace={sum(1 for item in components if item['type'] == 'application')} "
        f"serial={document['serialNumber']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
