"""P7.7 benchmark runner failure accounting and Semgrep adapter tests."""

from __future__ import annotations

import importlib.util
import io
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


def test_case_offset_selects_a_stable_benchmark_shard(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    cases = [
        {
            "case_id": f"cvefixes:CVE-2024-000{index}:1:before",
            "content_sha256": "sha256:" + "0" * 64,
            "cwe_id": "CWE-89",
            "expected_label": "vulnerable",
            "language": "python",
            "lineage_groups": [f"lineage-{index}"],
        }
        for index in range(3)
    ]
    manifest.write_text(json.dumps({"datasets": [{"cases": cases}]}), encoding="utf-8")

    selected = MODULE._load_cases(manifest, 1, offset=1)

    assert len(selected) == 1
    assert selected[0].case_id == cases[1]["case_id"]
    with pytest.raises(ValueError, match="case offset is invalid"):
        MODULE._load_cases(manifest, 1, offset=-1)


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


def test_remote_prediction_bounds_output_and_records_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_urlopen(request: object, *, timeout: int) -> io.BytesIO:
        assert isinstance(request, MODULE.urllib.request.Request)
        captured["payload"] = json.loads(request.data)
        captured["timeout"] = timeout
        return io.BytesIO(
            json.dumps(
                {
                    "choices": [{"message": {"content": '{"vulnerable":true}'}}],
                    "usage": {"prompt_tokens": 7, "completion_tokens": 2, "total_tokens": 9},
                }
            ).encode()
        )

    monkeypatch.setenv("DEEPSEEK_API_KEY", "unit-test-only")
    monkeypatch.setattr(MODULE.urllib.request, "urlopen", fake_urlopen)

    assert MODULE._remote_prediction(_case(), "print(1)", one_shot=False, max_output_tokens=32) == (
        True,
        9,
        7,
        2,
    )
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["max_tokens"] == 32
    assert payload["reasoning_effort"] == "none"
    assert payload["thinking"] == {"type": "disabled"}
    assert payload["response_format"] == {"type": "json_object"}
    assert captured["timeout"] == 90


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


def test_budget_rejection_prevents_remote_request(
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
    budget = MODULE.RemoteBudget(
        tmp_path / "budget.sqlite",
        "development",
        10_000_000,
        "a" * 40,
        "b" * 64,
        11,
        1,
        1_000_000_000_000,
        1,
    )
    monkeypatch.setattr(
        MODULE,
        "_remote_prediction",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("remote invoked")),
    )

    cells = MODULE.run((case,), database, Configuration.MODEL, 1, True, remote_budget=budget)

    assert len(cells) == 1
    assert cells[0].status == "budget-rejected"


def test_remote_cli_requires_explicit_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifest.json"
    database = tmp_path / "corpus.sqlite"
    output = tmp_path / "result.json"
    manifest.write_text("{}", encoding="utf-8")
    database.touch()
    monkeypatch.setattr(MODULE, "_load_cases", lambda *_args: (_case(),))

    assert (
        MODULE.main(
            (
                "--manifest",
                str(manifest),
                "--database",
                str(database),
                "--configuration",
                "model_native",
                "--output",
                str(output),
                "--allow-public-remote",
            )
        )
        == 1
    )
    assert not output.exists()


def test_remote_budget_uses_configured_total_cap_before_provider_call(
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
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("remote invoked")),
    )
    budget = MODULE.RemoteBudget(
        tmp_path / "budget.sqlite",
        "final",
        1,
        "a" * 40,
        "b" * 64,
        4096,
        64,
        1_000_000,
        1_000_000,
    )

    cells = MODULE.run((case,), database, Configuration.MODEL, 1, True, remote_budget=budget)

    assert cells[0].status == "budget-rejected"
    with sqlite3.connect(budget.ledger) as connection:
        assert connection.execute("SELECT total_cap FROM settings").fetchone() == (1,)


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
    monkeypatch.setattr(MODULE, "_remote_prediction", lambda *_args, **_kwargs: (True, 3, 2, 1))
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
    assert cells[0].kloc == 0.001


def test_hybrid_still_executes_model_when_scanner_raises_unexpected_error(
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
        lambda *_args: (_ for _ in ()).throw(AttributeError("scanner traversal failed")),
    )
    monkeypatch.setattr(MODULE, "_remote_prediction", lambda *_args, **_kwargs: (True, 3, 2, 1))

    cells = MODULE.run((case,), database, Configuration.HYBRID, 1, True)

    assert len(cells) == 1
    assert cells[0].status == "scanner-failed"
    assert cells[0].tp == 1


def test_remote_budget_reserves_case_bound_and_settles_provider_usage(
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
    monkeypatch.setattr(MODULE, "_remote_prediction", lambda *_args, **_kwargs: (True, 6, 5, 1))
    budget = MODULE.RemoteBudget(
        tmp_path / "budget.sqlite",
        "development",
        10_000_000,
        "a" * 40,
        "b" * 64,
        4096,
        64,
        300_000,
        1_200_000,
    )

    cells = MODULE.run((case,), database, Configuration.MODEL, 1, True, remote_budget=budget)

    assert cells[0].status == "completed"
    assert cells[0].cost_microunits == 4
    assert (
        MODULE.BenchmarkSpendGuard(
            budget.ledger, total_cap_micro_usd=budget.total_cap_micro_usd
        ).charged_micro_usd()
        == 4
    )


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
