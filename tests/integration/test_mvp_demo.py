"""P4.12 clean-room, metadata-only reference demo integration contract."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).parents[2]
DEMO_PATH = ROOT / "demo" / "mvp_cwe89_demo.py"
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "p4_10"


@pytest.fixture(scope="module")
def demo_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("securecode_p4_12_demo", DEMO_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pinned_demo_uses_ephemeral_copy_and_writes_canonical_reports(
    tmp_path: Path,
    demo_module: ModuleType,
) -> None:
    original = {
        path: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (
            FIXTURE_ROOT / "vulnerable" / "app.py",
            FIXTURE_ROOT / "safe" / "app.py",
        )
    }
    output = tmp_path / "demo-output"

    returned = demo_module.run_demo(output)
    persisted = json.loads((output / "mvp-demo-manifest.json").read_text(encoding="ascii"))

    assert persisted == returned
    assert persisted["artifact_schema_version"] == "securecode.p4_12.mvp-demo.v1"
    assert persisted["reference_outcome"] == "COMPLETED"
    assert persisted["product_outcome"] == "NOT_EVALUATED"
    assert persisted["product_pass"] is False
    assert persisted["ephemeral_workspace"] is True
    assert persisted["network_access"] == "not_used"
    assert persisted["signal_counts"] == {
        "vulnerable": 1,
        "safe_control": 0,
        "ephemeral_fixed": 0,
    }
    assert {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in original} == original
    for name, digest in persisted["report_sha256"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
    validation_document = json.loads((output / "validate.json").read_text(encoding="ascii"))
    assert validation_document["product_outcome"] == "NOT_EVALUATED"


def test_demo_rejects_nonempty_output_without_touching_existing_artifact(
    tmp_path: Path,
    demo_module: ModuleType,
) -> None:
    output = tmp_path / "occupied-output"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("keep", encoding="ascii")

    with pytest.raises(demo_module.DemoError):
        demo_module.run_demo(output)
    assert marker.read_text(encoding="ascii") == "keep"


def test_notebook_is_thin_valid_json_with_no_execution_outputs() -> None:
    notebook = json.loads((ROOT / "notebooks" / "mvp_cwe89_demo.ipynb").read_text(encoding="utf-8"))

    assert notebook["nbformat"] == 4
    assert notebook["metadata"]["kernelspec"]["name"] == "python3"
    code_cells = [cell for cell in notebook["cells"] if cell["cell_type"] == "code"]
    assert len(code_cells) == 1
    assert code_cells[0]["execution_count"] is None
    assert code_cells[0]["outputs"] == []
    assert "run_demo" in "".join(code_cells[0]["source"])
