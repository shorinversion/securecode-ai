"""P7.7 benchmark runner failure accounting and Semgrep adapter tests."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from securecode_ai.core.release_benchmark import Configuration

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "run_release_benchmark.py"
SPEC = importlib.util.spec_from_file_location("run_release_benchmark", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _case() -> object:
    return MODULE.Case(
        "cvefixes:repo:1:before", "sha256:" + "0" * 64, "CWE-89", "vulnerable", "python", "lineage"
    )


def test_semgrep_prediction_uses_argument_vector_and_detects_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "rules.yml"
    config.write_text("rules: []\n", encoding="utf-8")
    observed: dict[str, tuple[str, ...] | dict[str, object]] = {}

    def fake_run(arguments: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
        observed["arguments"] = arguments
        observed["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout=json.dumps({"results": [{"check_id": "x"}]}))

    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)

    assert MODULE._semgrep_prediction(_case(), "print('x')\n", command="semgrep", config=config)
    arguments = observed["arguments"]
    assert isinstance(arguments, tuple)
    assert arguments[:5] == ("semgrep", "scan", "--config", str(config), "--json")
    assert observed["kwargs"] == {
        "check": False,
        "capture_output": True,
        "text": True,
        "timeout": 90,
    }


@pytest.mark.parametrize(
    "result",
    (SimpleNamespace(returncode=2, stdout="{}"), SimpleNamespace(returncode=0, stdout="{}")),
)
def test_semgrep_prediction_rejects_failed_or_malformed_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, result: SimpleNamespace
) -> None:
    config = tmp_path / "rules.yml"
    config.write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr(MODULE.subprocess, "run", lambda *_args, **_kwargs: result)

    with pytest.raises(ValueError, match="Semgrep"):
        MODULE._semgrep_prediction(_case(), "print('x')\n", command="semgrep", config=config)


def test_model_failure_is_retained_as_a_cell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "corpus.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE file_change (file_change_id INTEGER, code_before TEXT, code_after TEXT)"
        )
        connection.execute("INSERT INTO file_change VALUES (1, 'print(1)', 'print(2)')")
    case = MODULE.Case(
        "cvefixes:repo:1:before",
        MODULE._sha256("print(1)"),
        "CWE-89",
        "vulnerable",
        "python",
        "lineage",
    )
    monkeypatch.setattr(MODULE, "_deterministic", lambda *_args: False)
    monkeypatch.setattr(
        MODULE,
        "_remote_prediction",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad response")),
    )

    cells = MODULE.run((case,), database, Configuration.MODEL, 1, True)

    assert len(cells) == 1
    assert cells[0].status == "model-failed"
    assert cells[0].fn == 1
    assert cells[0].tp == 0


def test_semgrep_failure_is_retained_as_a_cell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "corpus.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE file_change (file_change_id INTEGER, code_before TEXT, code_after TEXT)"
        )
        connection.execute("INSERT INTO file_change VALUES (1, 'print(1)', 'print(2)')")
    case = MODULE.Case(
        "cvefixes:repo:1:before",
        MODULE._sha256("print(1)"),
        "CWE-89",
        "vulnerable",
        "python",
        "lineage",
    )
    config = tmp_path / "rules.yml"
    config.write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr(MODULE, "_deterministic", lambda *_args: False)
    monkeypatch.setattr(
        MODULE,
        "_semgrep_prediction",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad response")),
    )

    cells = MODULE.run((case,), database, Configuration.SEMGREP, 1, False, semgrep_config=config)

    assert len(cells) == 1
    assert cells[0].status == "semgrep-failed"
