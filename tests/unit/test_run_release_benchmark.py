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


def test_semgrep_rule_checkout_selects_language_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules = tmp_path / "rules"
    python_rules = rules / "python"
    python_rules.mkdir(parents=True)
    observed: dict[str, tuple[str, ...]] = {}

    def fake_run(arguments: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        observed["arguments"] = arguments
        return SimpleNamespace(returncode=0, stdout=json.dumps({"results": []}))

    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)

    assert not MODULE._semgrep_prediction(_case(), "print('x')\n", command="semgrep", config=rules)
    assert observed["arguments"][3] == str(python_rules)


def test_semgrep_batch_maps_results_to_cases_once_per_language(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules = tmp_path / "rules"
    (rules / "python").mkdir(parents=True)
    calls: list[tuple[str, ...]] = []

    def fake_run(arguments: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        calls.append(arguments)
        root = Path(arguments[-1])
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"results": [{"path": str(root / "case-1.py")}]}),
        )

    first = MODULE.Case(
        "cvefixes:repo:1:before",
        "sha256:" + "0" * 64,
        "CWE-89",
        "vulnerable",
        "python",
        "first",
    )
    second = MODULE.Case(
        "cvefixes:repo:2:before",
        "sha256:" + "1" * 64,
        "CWE-89",
        "fixed-safe",
        "python",
        "second",
    )
    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)

    results = MODULE._semgrep_predictions(
        ((first, "print(1)\n"), (second, "print(2)\n")), command="semgrep", config=rules
    )

    assert len(calls) == 1
    assert {(case.lineage, predicted, status) for case, predicted, _latency, status in results} == {
        ("first", False, "completed"),
        ("second", True, "completed"),
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


@pytest.mark.parametrize(
    "lane", (Configuration.MODEL, Configuration.ONE_SHOT, Configuration.SEMGREP)
)
def test_independent_lanes_do_not_require_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lane: Configuration
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
    monkeypatch.setattr(
        MODULE,
        "_deterministic",
        lambda *_args: (_ for _ in ()).throw(AssertionError("scanner invoked")),
    )
    monkeypatch.setattr(MODULE, "_remote_prediction", lambda *_args, **_kwargs: (True, 3))
    monkeypatch.setattr(
        MODULE,
        "_semgrep_predictions",
        lambda cases, **_kwargs: tuple((item, True, 3, "completed") for item, _source in cases),
    )

    cells = MODULE.run(
        (case,), database, lane, 1, lane is not Configuration.SEMGREP, semgrep_config=config
    )

    assert len(cells) == 1
    assert cells[0].status == "completed"
    assert cells[0].tp == 1


def test_hybrid_still_executes_model_when_scanner_fails(
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
    monkeypatch.setattr(
        MODULE,
        "_deterministic",
        lambda *_args: (_ for _ in ()).throw(ValueError("scanner unavailable")),
    )
    monkeypatch.setattr(MODULE, "_remote_prediction", lambda *_args, **_kwargs: (True, 3))

    cells = MODULE.run((case,), database, Configuration.HYBRID, 1, True)

    assert len(cells) == 1
    assert cells[0].status == "scanner-failed"
    assert cells[0].tp == 1


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
        "_semgrep_predictions",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad response")),
    )

    cells = MODULE.run((case,), database, Configuration.SEMGREP, 1, False, semgrep_config=config)

    assert len(cells) == 1
    assert cells[0].status == "semgrep-failed"
