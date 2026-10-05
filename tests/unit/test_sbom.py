"""P8.11 supply chain: offline SBOM, provenance and checksum generation."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]

LOCK = """\
version = 1
revision = 3

[manifest]
members = ["demo-app"]

[[package]]
name = "demo-app"
version = "1.2.3"
source = { editable = "." }

[[package]]
name = "requests"
version = "2.32.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://example.invalid/requests-2.32.0.tar.gz", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", size = 100 }
wheels = [
    { url = "https://example.invalid/requests-2.32.0-py3-none-any.whl", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 90 },
    { url = "https://example.invalid/requests-2.32.0-cp312.whl", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 91 },
]
"""

PYPROJECT = """\
[project]
name = "securecode-ai-workspace"
version = "1.2.0"
"""


def _module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_CACHE: dict[str, ModuleType] = {}


def _sbom() -> ModuleType:
    return _CACHE.setdefault("sbom", _module("p811_sbom", ROOT / "scripts" / "sbom.py"))


def _provenance() -> ModuleType:
    return _CACHE.setdefault(
        "provenance", _module("p811_provenance", ROOT / "scripts" / "release_provenance.py")
    )


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    lock = tmp_path / "uv.lock"
    lock.write_text(LOCK, encoding="utf-8")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(PYPROJECT, encoding="utf-8")
    return lock, pyproject


def _git_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
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


# --- SBOM --------------------------------------------------------------------


def test_sbom_document_shape(tmp_path: Path) -> None:
    lock, pyproject = _fixture(tmp_path)
    document = _sbom().build_sbom(lock=lock, pyproject=pyproject)
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert document["version"] == 1
    assert document["serialNumber"].startswith("urn:uuid:")
    assert document["metadata"]["component"]["name"] == "securecode-ai-workspace"
    assert document["metadata"]["component"]["version"] == "1.2.0"


def test_sbom_components_are_sorted_and_typed(tmp_path: Path) -> None:
    lock, pyproject = _fixture(tmp_path)
    document = _sbom().build_sbom(lock=lock, pyproject=pyproject)
    names = [(item["name"], item["version"]) for item in document["components"]]
    assert names == sorted(names)
    kinds = {item["name"]: item["type"] for item in document["components"]}
    assert kinds == {"demo-app": "application", "requests": "library"}


def test_sbom_purl_and_hashes(tmp_path: Path) -> None:
    lock, pyproject = _fixture(tmp_path)
    document = _sbom().build_sbom(lock=lock, pyproject=pyproject)
    requests = next(item for item in document["components"] if item["name"] == "requests")
    assert requests["purl"] == "pkg:pypi/requests@2.32.0"
    assert requests["bom-ref"] == "requests@2.32.0"
    assert requests["hashes"] == [
        {
            "alg": "sha256",
            "content": "1111111111111111111111111111111111111111111111111111111111111111",
        },
        {
            "alg": "sha256",
            "content": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
    ]


def test_sbom_is_deterministic(tmp_path: Path) -> None:
    lock, pyproject = _fixture(tmp_path)
    module = _sbom()
    first = json.dumps(module.build_sbom(lock=lock, pyproject=pyproject), sort_keys=True)
    second = json.dumps(module.build_sbom(lock=lock, pyproject=pyproject), sort_keys=True)
    assert first == second


def test_sbom_serial_is_stable_and_content_derived(tmp_path: Path) -> None:
    lock, pyproject = _fixture(tmp_path)
    module = _sbom()
    first = module.build_sbom(lock=lock, pyproject=pyproject)["serialNumber"]
    second = module.build_sbom(lock=lock, pyproject=pyproject)["serialNumber"]
    assert first == second

    lock.write_text(LOCK.replace('version = "2.32.0"', 'version = "2.33.0"'), encoding="utf-8")
    changed = module.build_sbom(lock=lock, pyproject=pyproject)["serialNumber"]
    assert changed != first


def test_sbom_write_is_byte_identical_across_runs(tmp_path: Path) -> None:
    lock, pyproject = _fixture(tmp_path)
    module = _sbom()
    document = module.build_sbom(lock=lock, pyproject=pyproject)
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    module._write(document, first, pretty=True)
    module._write(document, second, pretty=True)
    assert first.read_bytes() == second.read_bytes()
    assert first.read_bytes().endswith(b"\n")


def test_sbom_rejects_missing_lock(tmp_path: Path) -> None:
    lock, pyproject = _fixture(tmp_path)
    lock.unlink()
    with pytest.raises(_sbom().SbomError):
        _sbom().build_sbom(lock=lock, pyproject=pyproject)


def test_sbom_rejects_corrupt_lock(tmp_path: Path) -> None:
    lock, pyproject = _fixture(tmp_path)
    lock.write_text("this is not = = toml", encoding="utf-8")
    with pytest.raises(_sbom().SbomError):
        _sbom().build_sbom(lock=lock, pyproject=pyproject)


def test_sbom_rejects_empty_packages(tmp_path: Path) -> None:
    lock, pyproject = _fixture(tmp_path)
    lock.write_text("version = 1\n[manifest]\nmembers = []\n", encoding="utf-8")
    with pytest.raises(_sbom().SbomError):
        _sbom().build_sbom(lock=lock, pyproject=pyproject)


def test_sbom_rejects_duplicate_component(tmp_path: Path) -> None:
    lock, pyproject = _fixture(tmp_path)
    duplicate = LOCK + LOCK.split("[[package]]")[2]
    lock.write_text(duplicate, encoding="utf-8")
    with pytest.raises(_sbom().SbomError):
        _sbom().build_sbom(lock=lock, pyproject=pyproject)


def test_sbom_output_must_be_absolute_json(tmp_path: Path) -> None:
    lock, pyproject = _fixture(tmp_path)
    module = _sbom()
    document = module.build_sbom(lock=lock, pyproject=pyproject)
    with pytest.raises(module.SbomError):
        module._write(document, Path("relative.json"), pretty=True)


def test_sbom_main_reports_and_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock, pyproject = _fixture(tmp_path)
    module = _sbom()
    output = tmp_path / "sbom.json"
    assert (
        module.main(["--output", str(output), "--lock", str(lock), "--pyproject", str(pyproject)])
        == 0
    )
    assert "SBOM=OK components=2" in capsys.readouterr().out
    assert output.is_file()

    missing = tmp_path / "absent.json"
    assert (
        module.main(
            [
                "--output",
                str(missing),
                "--lock",
                str(tmp_path / "nope.lock"),
                "--pyproject",
                str(pyproject),
            ]
        )
        == 1
    )
    assert "SBOM=FAIL:" in capsys.readouterr().out


def test_sbom_never_imports_network_modules() -> None:
    source = (ROOT / "scripts" / "sbom.py").read_text(encoding="utf-8")
    for forbidden in ("urllib", "requests", "socket", "http.client", "subprocess"):
        assert forbidden not in source.split('"""', 2)[2]
