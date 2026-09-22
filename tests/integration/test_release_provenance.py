"""P8.11 release provenance: commit binding, inventory digest, checksum file."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]

PYPROJECT = """[project]
name = "securecode-ai-workspace"
version = "1.0.0rc1"
"""


_CACHE: dict[str, ModuleType] = {}


def _provenance() -> ModuleType:
    cached = _CACHE.get("provenance")
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(
        "p811_provenance_int", ROOT / "scripts" / "release_provenance.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["p811_provenance_int"] = module
    spec.loader.exec_module(module)
    _CACHE["provenance"] = module
    return module


def _git_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (root / "app.py").write_text("print('ok')" + chr(10), encoding="utf-8")
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    for command in (
        ["git", "init", "--quiet"],
        ["git", "add", "."],
        ["git", "commit", "--quiet", "-m", "init"],
    ):
        subprocess.run(command, cwd=root, check=True, capture_output=True, env=environment)
    return root


def test_provenance_inventory_and_digest(tmp_path: Path) -> None:
    root = _git_repo(tmp_path)
    manifest, checksums = _provenance().build_provenance(root=root)
    assert manifest["schema_version"] == "securecode.release-provenance.v1"
    assert manifest["project_version"] == "1.0.0rc1"
    assert manifest["file_count"] == 2
    assert [item["path"] for item in manifest["files"]] == ["app.py", "pyproject.toml"]
    assert manifest["sbom_sha256"] is None

    lines = checksums.strip().splitlines()
    assert len(lines) == 2
    for line in lines:
        digest, _, name = line.partition("  ")
        assert len(digest) == 64
        assert digest == hashlib.sha256((root / name).read_bytes()).hexdigest()


def test_provenance_digest_is_deterministic(tmp_path: Path) -> None:
    root = _git_repo(tmp_path)
    module = _provenance()
    first = module.build_provenance(root=root)[0]["inventory_sha256"]
    second = module.build_provenance(root=root)[0]["inventory_sha256"]
    assert first == second


def test_provenance_binds_sbom_hash(tmp_path: Path) -> None:
    root = _git_repo(tmp_path)
    sbom = tmp_path / "sbom.json"
    sbom.write_bytes(b'{"bomFormat":"CycloneDX"}' + b"\n")
    manifest, _ = _provenance().build_provenance(root=root, sbom=sbom)
    assert manifest["sbom_sha256"] == hashlib.sha256(sbom.read_bytes()).hexdigest()


def test_provenance_rejects_missing_sbom(tmp_path: Path) -> None:
    root = _git_repo(tmp_path)
    with pytest.raises(_provenance().ProvenanceError):
        _provenance().build_provenance(root=root, sbom=tmp_path / "absent.json")


def test_provenance_rejects_non_repository(tmp_path: Path) -> None:
    with pytest.raises(_provenance().ProvenanceError):
        _provenance().build_provenance(root=tmp_path)


def test_provenance_main_writes_checksum_compatible_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _git_repo(tmp_path)
    output = tmp_path / "prov.json"
    checksums = tmp_path / "prov.txt"
    code = _provenance().main(
        ["--root", str(root), "--output", str(output), "--checksums", str(checksums)]
    )
    assert code == 0
    assert "PROVENANCE=OK files=2" in capsys.readouterr().out
    document: dict[str, Any] = json.loads(output.read_text(encoding="utf-8"))
    assert document["file_count"] == 2
    for line in checksums.read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        assert digest == hashlib.sha256((root / name).read_bytes()).hexdigest()


def test_provenance_main_fails_closed_on_bad_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _provenance().main(
        [
            "--root",
            str(tmp_path / "absent"),
            "--output",
            str(tmp_path / "prov.json"),
            "--checksums",
            str(tmp_path / "prov.txt"),
        ]
    )
    assert code == 1
    assert "PROVENANCE=FAIL:" in capsys.readouterr().out
