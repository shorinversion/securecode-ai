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


def _sample_record() -> tuple[dict[str, object], dict[str, object]]:
    plan = json.loads((ROOT / "evaluation/development/run-plan.yaml").read_text(encoding="utf-8"))
    record = RUNNER._record(
        plan=plan,
        plan_sha256=RUNNER._sha256_bytes(
            (ROOT / "evaluation/development/run-plan.yaml").read_bytes()
        ),
        case_id="synthetic-case",
        root_cause_group="synthetic-group",
        source_aliases=("file_1.py",),
        configuration="one_shot_llm",
        repetition=1,
        expected="vulnerable",
        state="executed",
        predicted="vulnerable",
        confirmed_finding=True,
        policy_matched=True,
        returned_category="sql",
        returned_source_alias="file_1.py",
        reason=None,
        wall_seconds=0.01,
        prompt_tokens=1,
        generated_tokens=1,
        scanner_signals=None,
        finding_origin="model_native",
    ).document()
    return plan, record


def test_dry_run_expands_frozen_matrix(tmp_path: Path) -> None:
    plan = json.loads((ROOT / "evaluation/development/run-plan.yaml").read_text(encoding="utf-8"))
    plan["bindings"] = {
        "component_sha256": RUNNER._sha256_bytes(
            (ROOT / "scripts/run_development_benchmark.py").read_bytes()
        ),
        "core_sha256": RUNNER._sha256_bytes(
            (ROOT / "packages/core/src/securecode_ai/core/development_benchmark.py").read_bytes()
        ),
        "recompute_sha256": RUNNER._sha256_bytes(
            (ROOT / "scripts/recompute_development_benchmark.py").read_bytes()
        ),
        "corpus_validator_sha256": RUNNER._sha256_bytes(
            (ROOT / "scripts/development_corpus.py").read_bytes()
        ),
        "prompt_sha256": RUNNER._prompt_sha256(),
        "policy_sha256": RUNNER._sha256_text(RUNNER.POLICY_TEXT),
        "schema_sha256": RUNNER._sha256_text(RUNNER.SCHEMA_TEXT),
    }
    plan_path = tmp_path / "run-plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_development_benchmark.py",
            "--plan",
            str(plan_path),
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
    _, record = _sample_record()
    record["raw_source"] = "must-not-survive"
    with pytest.raises(ValueError, match="raw-source echo"):
        RECOMPUTE._validate_record_shape(record)


def test_recomputer_rejects_duplicate_keys_and_negative_resources() -> None:
    with pytest.raises(ValueError, match="duplicate JSON key"):
        RECOMPUTE._strict_json('{"state":"executed","state":"failed"}')
    plan, record = _sample_record()
    record["prompt_tokens"] = -1
    with pytest.raises(ValueError, match="token facts"):
        RECOMPUTE._validate_record_values(record, plan)


def test_recomputer_rejects_legacy_record_schema() -> None:
    plan, record = _sample_record()
    record["schema_version"] = "development-benchmark-record-1.0"
    with pytest.raises(ValueError, match="record value schema drift"):
        RECOMPUTE._validate_record_values(record, plan)


@pytest.mark.parametrize(
    ("returned_category", "returned_source_alias"),
    (("other", "file_1.py"), ("sql", "file_2.py")),
)
def test_recomputer_rejects_unbound_confirmed_category_or_alias(
    returned_category: str, returned_source_alias: str
) -> None:
    plan, record = _sample_record()
    record["policy_matched"] = False
    record["returned_category"] = returned_category
    record["returned_source_alias"] = returned_source_alias
    with pytest.raises(ValueError, match="invalid confirmed finding"):
        RECOMPUTE._validate_record_values(record, plan)


def test_recomputer_rejects_model_facts_on_deterministic_record() -> None:
    plan, record = _sample_record()
    record["configuration"] = "deterministic_only"
    record["scanner_signal_count"] = 0
    with pytest.raises(ValueError, match="deterministic record cannot carry model facts"):
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


def test_deterministic_baseline_uses_product_scanner_without_oracle_prediction() -> None:
    plan = json.loads((ROOT / "evaluation/development/run-plan.yaml").read_text(encoding="utf-8"))
    corpus = json.loads(
        (ROOT / "evaluation/development/corpus-manifest.yaml").read_text(encoding="utf-8")
    )
    rules = json.loads(
        (ROOT / "evaluation/development/corpus/oracle-rules.json").read_text(encoding="utf-8")
    )["rules"]
    cases = {item["case_id"]: item for item in corpus["cases"]}
    vulnerable = RUNNER._deterministic(
        cases["dev-sql-concat_query"],
        ROOT / "evaluation/development",
        plan["candidate_commit"],
        rules["dev-sql-concat_query"]["source_path"],
    )
    safe = RUNNER._deterministic(
        cases["dev-sql-parameterized_query"],
        ROOT / "evaluation/development",
        plan["candidate_commit"],
        rules["dev-sql-parameterized_query"]["source_path"],
    )
    assert vulnerable[:4] == ("vulnerable", True, True, "sql")
    assert vulnerable[5] > 0
    assert safe == ("safe", False, False, None, None, 0)


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


def test_scanner_seeded_prompt_exposes_only_seeded_source_and_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = json.loads((ROOT / "evaluation/development/run-plan.yaml").read_text(encoding="utf-8"))
    corpus = json.loads(
        (ROOT / "evaluation/development/corpus-manifest.yaml").read_text(encoding="utf-8")
    )
    case = corpus["cases"][1]
    seed_alias = "file_1.py"
    aliases = RUNNER._source_aliases(case)
    expected_source = aliases[seed_alias]
    unseeded_aliases = set(aliases).difference({seed_alias})
    rule = json.loads(
        (ROOT / "evaluation/development/corpus/oracle-rules.json").read_text(encoding="utf-8")
    )["rules"][case["case_id"]]
    observed: dict[str, object] = {}

    class Response:
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(
                {
                    "model": plan["ollama"]["model"],
                    "response": (
                        '{"verdict":"confirmed","category":"authz","source_file":"'
                        + seed_alias
                        + '"}'
                    ),
                    "done": True,
                    "done_reason": "stop",
                    "prompt_eval_count": 1,
                    "eval_count": 1,
                }
            ).encode("utf-8")

    class Opener:
        def open(self, request: object, **_kwargs: object) -> Response:
            observed["payload"] = json.loads(request.data.decode("utf-8"))  # type: ignore[attr-defined]
            return Response()

    monkeypatch.setattr(RUNNER, "OPENER", Opener())
    result = RUNNER._ollama(
        case,
        ROOT / "evaluation/development",
        plan["ollama"],
        1,
        expected_source,
        mode="scanner_seeded_investigation",
        seeded_aliases=(seed_alias,),
        scanner_seed_facts=(("authz", seed_alias),),
    )
    assert result[:5] == ("vulnerable", True, True, "authz", seed_alias)
    prompt = observed["payload"]["prompt"]  # type: ignore[index]
    assert f"FILE {seed_alias}" in prompt
    assert "authz@file_1.py" in prompt
    expected_projection = RUNNER._model_projection(
        RUNNER._contained_source(ROOT / "evaluation/development", expected_source).read_text(
            encoding="utf-8"
        )
    )
    assert expected_projection in prompt
    for alias in unseeded_aliases:
        assert f"FILE {alias}" not in prompt
        assert aliases[alias] not in prompt
    assert rule["source_path"] not in prompt
    with pytest.raises(RUNNER.ModelRunError, match="unseeded_structured_finding"):
        RUNNER._ollama(
            case,
            ROOT / "evaluation/development",
            plan["ollama"],
            1,
            expected_source,
            mode="scanner_seeded_investigation",
            seeded_aliases=(seed_alias,),
            scanner_seed_facts=(("sql", seed_alias),),
        )


def test_full_hybrid_prompt_includes_all_sources_and_explicit_zero_seed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = json.loads((ROOT / "evaluation/development/run-plan.yaml").read_text(encoding="utf-8"))
    corpus = json.loads(
        (ROOT / "evaluation/development/corpus-manifest.yaml").read_text(encoding="utf-8")
    )
    case = corpus["cases"][1]
    aliases = RUNNER._source_aliases(case)
    rule = json.loads(
        (ROOT / "evaluation/development/corpus/oracle-rules.json").read_text(encoding="utf-8")
    )["rules"][case["case_id"]]
    observed: dict[str, object] = {}

    class Response:
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(
                {
                    "model": plan["ollama"]["model"],
                    "response": '{"verdict":"no_finding"}',
                    "done": True,
                    "done_reason": "stop",
                    "prompt_eval_count": 1,
                    "eval_count": 1,
                }
            ).encode("utf-8")

    class Opener:
        def open(self, request: object, **_kwargs: object) -> Response:
            observed["payload"] = json.loads(request.data.decode("utf-8"))  # type: ignore[attr-defined]
            return Response()

    monkeypatch.setattr(RUNNER, "OPENER", Opener())
    result = RUNNER._ollama(
        case,
        ROOT / "evaluation/development",
        plan["ollama"],
        1,
        rule["source_path"],
        mode="full_hybrid",
    )
    assert result[:3] == ("safe", False, False)
    prompt = observed["payload"]["prompt"]  # type: ignore[index]
    assert "Deterministic scanner seed facts: none" in prompt
    for alias, path in aliases.items():
        assert f"FILE {alias}" in prompt
        assert (
            RUNNER._model_projection(
                RUNNER._contained_source(ROOT / "evaluation/development", path).read_text(
                    encoding="utf-8"
                )
            )
            in prompt
        )
    assert rule["source_path"] not in prompt


def test_model_native_prompt_is_distinct_and_has_no_scanner_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = json.loads((ROOT / "evaluation/development/run-plan.yaml").read_text(encoding="utf-8"))
    corpus = json.loads(
        (ROOT / "evaluation/development/corpus-manifest.yaml").read_text(encoding="utf-8")
    )
    case = corpus["cases"][0]
    expected_source = case["sources"][0]["path"]
    prompts: list[str] = []

    class Response:
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(
                {
                    "model": plan["ollama"]["model"],
                    "response": '{"verdict":"no_finding"}',
                    "done": True,
                    "done_reason": "stop",
                    "prompt_eval_count": 1,
                    "eval_count": 1,
                }
            ).encode("utf-8")

    class Opener:
        def open(self, request: object, **_kwargs: object) -> Response:
            prompts.append(json.loads(request.data.decode("utf-8"))["prompt"])  # type: ignore[attr-defined]
            return Response()

    monkeypatch.setattr(RUNNER, "OPENER", Opener())
    for mode in ("one_shot_llm", "model_native_only"):
        RUNNER._ollama(
            case,
            ROOT / "evaluation/development",
            plan["ollama"],
            1,
            expected_source,
            mode=mode,
        )
    assert len(prompts) == 2
    assert prompts[0] != prompts[1]
    assert "Perform independent model-native discovery" in prompts[1]
    assert "Deterministic scanner seed facts" not in prompts[1]


def test_all_configurations_emit_records_without_a_live_model(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plan = json.loads((ROOT / "evaluation/development/run-plan.yaml").read_text(encoding="utf-8"))
    plan["bindings"] = {
        "component_sha256": RUNNER._sha256_bytes(
            (ROOT / "scripts/run_development_benchmark.py").read_bytes()
        ),
        "core_sha256": RUNNER._sha256_bytes(
            (ROOT / "packages/core/src/securecode_ai/core/development_benchmark.py").read_bytes()
        ),
        "recompute_sha256": RUNNER._sha256_bytes(
            (ROOT / "scripts/recompute_development_benchmark.py").read_bytes()
        ),
        "corpus_validator_sha256": RUNNER._sha256_bytes(
            (ROOT / "scripts/development_corpus.py").read_bytes()
        ),
        "prompt_sha256": RUNNER._prompt_sha256(),
        "policy_sha256": RUNNER._sha256_text(RUNNER.POLICY_TEXT),
        "schema_sha256": RUNNER._sha256_text(RUNNER.SCHEMA_TEXT),
    }
    plan_path = tmp_path / "run-plan.json"
    records_path = tmp_path / "records.jsonl"
    aggregate_path = tmp_path / "aggregate.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    calls: list[tuple[str, tuple[str, ...], tuple[tuple[str, str], ...]]] = []

    def fake_model(
        *_args: object,
        mode: str,
        seeded_aliases: tuple[str, ...],
        scanner_seed_facts: tuple[tuple[str, str], ...],
    ) -> tuple[object, ...]:
        calls.append((mode, seeded_aliases, scanner_seed_facts))
        if mode == "full_hybrid":
            return "vulnerable", True, False, "path", "file_1.py", 1, 1
        return "safe", False, False, None, None, 1, 1

    monkeypatch.setattr(RUNNER, "_verify_runtime", lambda *_args: None)
    monkeypatch.setattr(RUNNER, "_bounded_ollama", fake_model)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_development_benchmark.py",
            "--plan",
            str(plan_path),
            "--records",
            str(records_path),
            "--aggregate",
            str(aggregate_path),
        ],
    )
    assert RUNNER.main() == 0
    records = [json.loads(line) for line in records_path.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 312
    assert {record["configuration"] for record in records} == set(RUNNER.MODEL_CONFIGURATIONS) | {
        "deterministic_only"
    }
    zero_seed_records = [
        record
        for record in records
        if record["configuration"] == "scanner_seeded_investigation"
        and record["scanner_signal_count"] == 0
    ]
    assert zero_seed_records
    assert all(
        record["predicted_label"] == "safe"
        and record["prompt_tokens"] is None
        and record["finding_origin"] is None
        for record in zero_seed_records
    )
    assert len(calls) < 4 * 24 * 3
    assert all(record["state"] == "executed" for record in records)
    assert {mode for mode, _, _ in calls} == RUNNER.MODEL_CONFIGURATIONS
    assert all(
        not seeded_aliases and not seed_facts
        for mode, seeded_aliases, seed_facts in calls
        if mode in {"one_shot_llm", "model_native_only"}
    )
    assert all(
        seeded_aliases and {alias for _, alias in seed_facts} == set(seeded_aliases)
        for mode, seeded_aliases, seed_facts in calls
        if mode == "scanner_seeded_investigation"
    )
    assert all(
        {alias for _, alias in seed_facts} == set(seeded_aliases)
        for mode, seeded_aliases, seed_facts in calls
        if mode == "full_hybrid"
    )
    assert sum(mode == "one_shot_llm" for mode, _, _ in calls) == 24 * 3
    assert sum(mode == "model_native_only" for mode, _, _ in calls) == 24 * 3
    assert sum(mode == "full_hybrid" for mode, _, _ in calls) == 24 * 3
    assert sum(mode == "scanner_seeded_investigation" for mode, _, _ in calls) == (
        24 * 3 - len(zero_seed_records)
    )
    hybrid_records = [record for record in records if record["configuration"] == "full_hybrid"]
    assert all(
        record["confirmed_finding"] is True
        and record["returned_category"] == "path"
        and record["finding_origin"] == "model_native"
        for record in hybrid_records
    )


@pytest.mark.parametrize("failure", [OSError, ValueError, KeyboardInterrupt])
def test_runtime_preflight_replaces_stale_results_with_complete_not_run_matrix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: type[BaseException]
) -> None:
    plan_path = ROOT / "evaluation/development/run-plan.yaml"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    records_path = tmp_path / "records.jsonl"
    aggregate_path = tmp_path / "aggregate.json"
    records_path.write_text("stale successful records", encoding="utf-8")
    aggregate_path.write_text("stale successful aggregate", encoding="utf-8")

    def unavailable(*_args: object) -> None:
        pending = [json.loads(line) for line in records_path.read_text().splitlines()]
        assert len(pending) == 312
        assert all(row["reason"] == "run_not_completed" for row in pending)
        assert "stale" not in aggregate_path.read_text()
        raise failure("provider detail must not be echoed")

    monkeypatch.setattr(RUNNER, "_verify_runtime", unavailable)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_development_benchmark.py",
            "--plan",
            str(plan_path),
            "--records",
            str(records_path),
            "--aggregate",
            str(aggregate_path),
        ],
    )
    if failure is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            RUNNER.main()
    else:
        assert RUNNER.main() == 1
    rows = [json.loads(line) for line in records_path.read_text().splitlines()]
    assert len(rows) == 312
    assert len({(row["case_id"], row["configuration"], row["repetition"]) for row in rows}) == 312
    assert all(row["state"] == "not_run" and row["predicted_label"] is None for row in rows)
    for row in rows:
        RECOMPUTE._validate_record_shape(row)
        RECOMPUTE._validate_record_values(row, plan)
        assert row["scanner_signal_count"] is None
        for count in (0, 1):
            with pytest.raises(ValueError, match="scanner receipt applicability"):
                RECOMPUTE._validate_record_values({**row, "scanner_signal_count": count}, plan)
        if row["configuration"] in {
            "deterministic_only",
            "scanner_seeded_investigation",
            "full_hybrid",
        }:
            with pytest.raises(ValueError, match="scanner receipt applicability"):
                RECOMPUTE._validate_record_values({**row, "state": "failed"}, plan)
    assert "provider detail" not in records_path.read_text()
    result = json.loads(aggregate_path.read_text())
    assert result["incomplete"] is True
    assert result["planned_cells"] == result["recorded_cells"] == 312
    assert sum(item["not_run"] for item in result["configurations"].values()) == 312
    attribution = result["full_hybrid_origin_attribution"]
    assert attribution["zero_scanner_signal_stratum"]["complete"] is False
    assert attribution["deterministic_candidate_auditor_receipt_coverage"]["complete"] is False
    recomputed_path = tmp_path / "recomputed.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "recompute_development_benchmark.py",
            "--plan",
            str(plan_path),
            "--records",
            str(records_path),
            "--output",
            str(recomputed_path),
        ],
    )
    assert RECOMPUTE.main() == 0
    assert json.loads(recomputed_path.read_text()) == result
