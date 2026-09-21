"""P5.13 installed-worker integration boundary checks."""

from __future__ import annotations

import io
import json
import sys
from importlib import util
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKER_SOURCE = ROOT / "apps" / "worker" / "src"
if str(WORKER_SOURCE) not in sys.path:
    sys.path.insert(0, str(WORKER_SOURCE))

from securecode_ai.worker.cli import main  # noqa: E402


def _payload() -> bytes:
    path = ROOT / "tests" / "unit" / "test_ci_worker.py"
    specification = util.spec_from_file_location("p5_11_worker_unit_contract", path)
    if specification is None or specification.loader is None:
        raise RuntimeError("P5.11 fixture is unavailable")
    module = util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return cast(bytes, module._admitted_run().model_dump_json().encode("utf-8"))


@pytest.mark.skipif(sys.platform != "linux", reason="P5.13 is Linux-only")
def test_worker_cli_keeps_input_out_of_the_only_published_result(tmp_path: Path) -> None:
    payload = _payload()
    input_path = tmp_path / "audit-run.json"
    input_path.write_bytes(payload)
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    stdout = io.StringIO()
    stderr = io.StringIO()

    code = main(
        ["--artifact-root", str(artifact_root), "--input", str(input_path)],
        stdout=stdout,
        stderr=stderr,
    )

    artifact = next(artifact_root.glob("tenants/*/*.json"))
    assert code == 0
    published_reference = json.loads(stdout.getvalue())
    assert published_reference["data_class"] == "DC1_INTERNAL_METADATA"
    assert stderr.getvalue() == ""
    assert payload not in artifact.read_bytes()
