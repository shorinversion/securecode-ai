"""Offline, deterministic CycloneDX 1.5 SBOM generated from the locked workspace.

The generator never contacts a registry: every component, version and hash comes
from the local ``uv.lock`` and ``pyproject.toml``.  The same inputs always produce
byte-identical output, so a release can re-derive and compare the SBOM.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
import uuid
from pathlib import Path
from typing import Any, Final

BOM_FORMAT: Final = "CycloneDX"
SPEC_VERSION: Final = "1.5"
SCHEMA_VERSION: Final = "securecode.sbom-report.v1"
ASSESSMENT_SCHEMA_VERSION: Final = "securecode.sbom-assessment.v1"
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_VULNERABILITY_STATES: Final = frozenset({"resolved", "unresolved", "unknown"})
_REPORT_KEYS: Final = frozenset(
    {"bomFormat", "components", "metadata", "serialNumber", "specVersion", "version"}
)
_REPORT_COMPONENT_KEYS: Final = frozenset({"bom-ref", "name", "purl", "type", "version"})
_ASSESSMENT_KEYS: Final = frozenset({"components", "report_sha256", "schema_version"})
_ASSESSMENT_COMPONENT_KEYS: Final = frozenset(
    {"bom_ref", "content_sha256", "license", "source", "vulnerability_status"}
)
_MAX_ASSESSMENT_BYTES: Final = 16 * 1024 * 1024
_MAX_TEXT_BYTES: Final = 512

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


def _safe_text(value: object) -> bool:
    return (
        type(value) is str
        and value == value.strip()
        and 0 < len(value) <= _MAX_TEXT_BYTES
        and all(ord(character) >= 0x20 and character != "\x7f" for character in value)
    )


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


def _component(package: object, workspace_names: frozenset[str]) -> dict[str, Any]:
    if type(package) is not dict:
        raise SbomError("locked package entry is invalid")
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not name:
        raise SbomError("locked package name is invalid")
    if not isinstance(version, str) or not version:
        raise SbomError("locked package version is invalid")
    source = package.get("source")
    if type(source) is not dict:
        raise SbomError("locked package source is invalid")
    edition = source.get("editable") if isinstance(source, dict) else None
    directory = source.get("directory") if isinstance(source, dict) else None
    is_workspace = name in workspace_names or isinstance(edition, str) or isinstance(directory, str)

    hashes: list[dict[str, str]] = []
    sdist = package.get("sdist")
    wheels = package.get("wheels", [])
    if sdist is not None and type(sdist) is not dict:
        raise SbomError("locked package source distribution is invalid")
    if type(wheels) is not list:
        raise SbomError("locked package wheels are invalid")
    candidates = ([sdist] if sdist is not None else []) + wheels
    for candidate in candidates:
        if type(candidate) is not dict:
            raise SbomError("locked package artifact is invalid")
        digest = _hash_of(candidate)
        if digest is None:
            raise SbomError("locked package artifact hash is invalid")
        if {"alg": digest[0], "content": digest[1]} not in hashes:
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
    if members is None:
        workspace_names = frozenset()
    elif type(members) is list and all(type(item) is str and item for item in members):
        workspace_names = frozenset(members)
    else:
        raise SbomError("workspace members are invalid")

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


def _read_assessment(path: Path) -> dict[str, Any]:
    if (
        not path.is_absolute()
        or path.suffix != ".json"
        or path.is_symlink()
        or not path.is_file()
    ):
        raise SbomError("SBOM assessment is unavailable")
    try:
        resolved = path.resolve(strict=True)
        if resolved != path:
            raise SbomError("SBOM assessment is unavailable")
        payload = path.read_bytes()
        if not 1 <= len(payload) <= _MAX_ASSESSMENT_BYTES:
            raise SbomError("SBOM assessment size is invalid")
        document = json.loads(payload.decode("ascii"))
    except SbomError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise SbomError("SBOM assessment cannot be parsed") from None
    if type(document) is not dict or payload != _canonical(document):
        raise SbomError("SBOM assessment is not canonical")
    return document


def _report_components(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if (
        set(document) != _REPORT_KEYS
        or document["bomFormat"] != BOM_FORMAT
        or document["specVersion"] != SPEC_VERSION
        or type(document["version"]) is not int
        or document["version"] != 1
        or not _safe_text(document["serialNumber"])
    ):
        raise SbomError("CycloneDX report is invalid")
    metadata = document["metadata"]
    if (
        type(metadata) is not dict
        or set(metadata) != {"component", "schema_version"}
        or metadata["schema_version"] != SCHEMA_VERSION
    ):
        raise SbomError("CycloneDX metadata is invalid")
    metadata_component = metadata["component"]
    if (
        type(metadata_component) is not dict
        or set(metadata_component) != {"bom-ref", "name", "type", "version"}
        or any(not _safe_text(metadata_component[name]) for name in metadata_component)
    ):
        raise SbomError("CycloneDX metadata is invalid")
    raw_components = document.get("components")
    if type(raw_components) is not list or not raw_components:
        raise SbomError("CycloneDX report has no components")
    components: dict[str, dict[str, Any]] = {}
    for component in raw_components:
        if type(component) is not dict or set(component) not in {
            _REPORT_COMPONENT_KEYS,
            _REPORT_COMPONENT_KEYS | {"hashes"},
        }:
            raise SbomError("CycloneDX component is invalid")
        bom_ref = component.get("bom-ref")
        name = component.get("name")
        version = component.get("version")
        if (
            not _safe_text(bom_ref)
            or not _safe_text(name)
            or not _safe_text(version)
            or bom_ref in components
            or any(not _safe_text(component[name]) for name in _REPORT_COMPONENT_KEYS)
        ):
            raise SbomError("CycloneDX component identity is invalid")
        components[bom_ref] = component
    return components


def _component_hashes(component: dict[str, Any]) -> frozenset[str]:
    raw_hashes = component.get("hashes", [])
    if type(raw_hashes) is not list:
        raise SbomError("CycloneDX component hashes are invalid")
    values: set[str] = set()
    for value in raw_hashes:
        if type(value) is not dict or set(value) != {"alg", "content"}:
            raise SbomError("CycloneDX component hash is invalid")
        if (
            value["alg"] != "sha256"
            or type(value["content"]) is not str
            or _SHA256.fullmatch(value["content"]) is None
        ):
            raise SbomError("CycloneDX component hash is invalid")
        values.add(value["content"])
    return frozenset(values)


def build_release_sbom(*, document: dict[str, Any], assessment: Path) -> bytes:
    """Build provider evidence from a CycloneDX report and explicit assessment.

    The assessment is the only source for license, vulnerability status and
    component source metadata. Missing or unknown values never receive a
    default. Its report hash binds the release evidence to the exact
    deterministic CycloneDX document.
    """

    if type(document) is not dict:
        raise SbomError("CycloneDX report is invalid")
    report_components = _report_components(document)
    assessment_document = _read_assessment(assessment)
    if (
        set(assessment_document) != _ASSESSMENT_KEYS
        or assessment_document["schema_version"] != ASSESSMENT_SCHEMA_VERSION
        or type(assessment_document["report_sha256"]) is not str
        or _SHA256.fullmatch(assessment_document["report_sha256"]) is None
        or assessment_document["report_sha256"] != _digest(document)
    ):
        raise SbomError("SBOM assessment does not bind the CycloneDX report")
    report_sha256 = assessment_document["report_sha256"]
    raw_assessments = assessment_document["components"]
    if type(raw_assessments) is not list or len(raw_assessments) != len(report_components):
        raise SbomError("SBOM assessment component set is incomplete")
    release_components: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in raw_assessments:
        if type(raw) is not dict or set(raw) != _ASSESSMENT_COMPONENT_KEYS:
            raise SbomError("SBOM assessment component is invalid")
        bom_ref = raw["bom_ref"]
        license_value = raw["license"]
        source = raw["source"]
        status = raw["vulnerability_status"]
        content_sha256 = raw["content_sha256"]
        if (
            not _safe_text(bom_ref)
            or bom_ref in seen
            or bom_ref not in report_components
            or not _safe_text(license_value)
            or license_value.upper() in {"NOASSERTION", "UNKNOWN"}
            or not _safe_text(source)
            or type(status) is not str
            or status not in _VULNERABILITY_STATES
            or status != "resolved"
            or type(content_sha256) is not str
            or _SHA256.fullmatch(content_sha256) is None
        ):
            raise SbomError("SBOM assessment is unresolved")
        report_hashes = _component_hashes(report_components[bom_ref])
        if report_hashes and content_sha256 not in report_hashes:
            raise SbomError("SBOM assessment content is not report-bound")
        seen.add(bom_ref)
        component = report_components[bom_ref]
        bound_source = f"{source}#cyclonedx-sha256={report_sha256}"
        if not _safe_text(bound_source):
            raise SbomError("SBOM assessment source binding is invalid")
        release_components.append(
            {
                "content_sha256": content_sha256,
                "license": license_value,
                "name": component["name"],
                "source": bound_source,
                "version": component["version"],
                "vulnerability_status": status,
            }
        )
    if seen != set(report_components):
        raise SbomError("SBOM assessment component set is incomplete")
    release_components.sort(key=lambda item: (item["name"], item["version"], item["source"]))
    return _canonical(release_components)


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


def _write_release_evidence(payload: bytes, output: Path) -> None:
    if not output.is_absolute() or output.suffix != ".json":
        raise SbomError("release SBOM output must be an absolute .json path")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--pyproject", type=Path, default=DEFAULT_PYPROJECT)
    parser.add_argument("--assessment", type=Path)
    parser.add_argument("--release-output", type=Path)
    parser.add_argument("--no-pretty", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        document = build_sbom(lock=arguments.lock, pyproject=arguments.pyproject)
        if (arguments.assessment is None) != (arguments.release_output is None):
            raise SbomError("assessment and release output must be supplied together")
        if (
            arguments.assessment is not None
            and arguments.output.resolve(strict=False) == arguments.release_output.resolve(strict=False)
        ):
            raise SbomError("CycloneDX and release SBOM outputs must differ")
        release_payload = (
            None
            if arguments.assessment is None
            else build_release_sbom(document=document, assessment=arguments.assessment)
        )
        _write(document, arguments.output, pretty=not arguments.no_pretty)
        if release_payload is not None:
            _write_release_evidence(release_payload, arguments.release_output)
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
        f"serial={document['serialNumber']} report_sha256={_digest(document)}"
    )
    if release_payload is not None:
        print(f"RELEASE_SBOM=OK sha256={hashlib.sha256(release_payload).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
