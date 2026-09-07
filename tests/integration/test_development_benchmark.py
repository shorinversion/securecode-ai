import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "run_development_benchmark", ROOT / "scripts/run_development_benchmark.py"
)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
RECOMPUTE_SPEC = importlib.util.spec_from_file_location(
    "recompute_development_benchmark",
    ROOT / "scripts/recompute_development_benchmark.py",
)
assert RECOMPUTE_SPEC is not None and RECOMPUTE_SPEC.loader is not None
RECOMPUTE = importlib.util.module_from_spec(RECOMPUTE_SPEC)
RECOMPUTE_SPEC.loader.exec_module(RECOMPUTE)


def test_dry_run_expands_frozen_matrix() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_development_benchmark.py",
            "--plan",
            "evaluation/development/run-plan.yaml",
            "--records",
            "evaluation/development/results/run-records.jsonl",
            "--aggregate",
            "evaluation/development/results/aggregate.json",
            "--dry-run",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert '"planned_cells":312' in result.stdout


def test_model_projection_removes_expectation_comments_and_docstrings() -> None:
    source = '# Policy: safe\ndef run():\n    """Violation: vulnerable"""\n    return 1\n'
    projected = RUNNER._model_projection(source)
    assert "Policy" not in projected
    assert "Violation" not in projected
    assert "return 1" in projected


def test_duplicate_json_keys_reject() -> None:
    with pytest.raises(ValueError, match="duplicate JSON key"):
        RUNNER._strict_object(b'{"state":"executed","state":"failed"}')


def test_recomputer_rejects_raw_source_echo() -> None:
    record = json.loads(
        (ROOT / "evaluation/development/results/run-records.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    record["raw_source"] = "must-not-survive"
    with pytest.raises(ValueError, match="raw-source echo"):
        RECOMPUTE._validate_record_shape(record)


def test_recomputer_rejects_duplicate_keys_and_negative_resources() -> None:
    with pytest.raises(ValueError, match="duplicate JSON key"):
        RECOMPUTE._strict_json('{"state":"executed","state":"failed"}')
    plan = json.loads((ROOT / "evaluation/development/run-plan.yaml").read_text(encoding="utf-8"))
    record = json.loads(
        (ROOT / "evaluation/development/results/run-records.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    record["prompt_tokens"] = -1
    with pytest.raises(ValueError, match="token facts"):
        RECOMPUTE._validate_record_values(record, plan)


def test_alias_permutation_is_label_blind_and_varies_primary_position() -> None:
    corpus = json.loads(
        (ROOT / "evaluation/development/corpus-manifest.yaml").read_text(encoding="utf-8")
    )
    rules = json.loads(
        (ROOT / "evaluation/development/corpus/oracle-rules.json").read_text(encoding="utf-8")
    )["rules"]
    positions = set()
    for case in corpus["cases"]:
        if len(case["sources"]) > 1:
            aliases = RUNNER._source_aliases(case)
            positions.add(
                next(
                    alias
                    for alias, path in aliases.items()
                    if path == rules[case["case_id"]]["source_path"]
                )
            )
    assert positions == {"file_1.py", "file_2.py"}


def test_model_response_rejects_out_of_grammar_category(monkeypatch: pytest.MonkeyPatch) -> None:
    plan = json.loads((ROOT / "evaluation/development/run-plan.yaml").read_text(encoding="utf-8"))
    corpus = json.loads(
        (ROOT / "evaluation/development/corpus-manifest.yaml").read_text(encoding="utf-8")
    )
    case = corpus["cases"][0]

    class Response:
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(
                {
                    "model": plan["ollama"]["model"],
                    "response": '{"verdict":"confirmed","category":"garbage","source_file":"file_1.py"}',
                    "done": True,
                    "done_reason": "stop",
                    "prompt_eval_count": 1,
                    "eval_count": 1,
                }
            ).encode("utf-8")

    class Opener:
        def open(self, *_args: object, **_kwargs: object) -> Response:
            return Response()

    monkeypatch.setattr(RUNNER, "OPENER", Opener())
    with pytest.raises(RUNNER.ModelRunError, match="invalid_structured_finding"):
        RUNNER._ollama(
            case,
            ROOT / "evaluation/development",
            plan["ollama"],
            1,
            case["sources"][0]["path"],
        )
