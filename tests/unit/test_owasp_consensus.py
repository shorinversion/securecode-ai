"""Majority vote of independent passes in the OWASP Benchmark scoring."""

import json
from pathlib import Path

import pytest

from scripts.owasp_benchmark_python import (
    Case,
    consensus,
    informative_hints,
    scanner_decides,
    score,
)
from scripts.owasp_bootstrap import bootstrap_difference, load_configuration


def test_cwe_survives_only_with_a_strict_majority() -> None:
    discovery = {"a": {89}, "b": {79}, "c": set()}
    auditor = {"a": {89}, "b": set(), "c": {22}}
    second = {"a": set(), "b": {79, 502}, "c": set()}

    assert consensus(discovery, auditor, second) == {"a": {89}, "b": {79}, "c": set()}


def test_missing_case_counts_as_an_empty_vote() -> None:
    assert consensus({"a": {89}}, {"a": {89}}, {}) == {"a": {89}}
    assert consensus({"a": {89}}, {}, {}) == {"a": set()}


def test_child_and_parent_cwe_vote_for_the_same_weakness() -> None:
    voted = consensus({"a": {643}}, {"a": {91}}, {"a": set()})

    assert voted == {"a": {91, 643}}


def test_weak_hash_comes_from_the_scanner_only() -> None:
    found = {"a": {328, 89}, "b": {79}}
    scanner = {"a": set(), "b": {327}}

    assert scanner_decides(found, scanner) == {"a": {89}, "b": {79, 327}}


def test_consensus_removes_a_lone_false_positive_from_the_score() -> None:
    cases = [("vulnerable", "sqli", True, 89), ("safe", "sqli", False, 89)]
    noisy = {"vulnerable": {89}, "safe": {89}}
    careful = {"vulnerable": {89}, "safe": set()}

    voted = consensus(noisy, careful, careful)

    assert score(cases, noisy)["categories"]["sqli"]["score"] == 0.0
    assert score(cases, voted)["categories"]["sqli"]["score"] == 1.0


def test_hints_raised_on_most_files_are_dropped() -> None:
    scanner = {"a": {306, 89}, "b": {306}, "c": {306, 79}}

    assert informative_hints(scanner) == {"a": {89}, "b": set(), "c": {79}}


def _cases(vulnerable: int, safe: int) -> list[Case]:
    return [(f"v{index}", "sqli", True, 89) for index in range(vulnerable)] + [
        (f"s{index}", "sqli", False, 89) for index in range(safe)
    ]


def test_bootstrap_interval_is_deterministic_and_excludes_zero_for_a_clear_gain() -> None:
    cases = _cases(30, 30)
    perfect = {name: ({89} if vulnerable else set()) for name, _, vulnerable, _ in cases}
    half = {
        name: ({89} if name.startswith("v") and int(name[1:]) % 2 else set()) for name, *_ in cases
    }

    first = bootstrap_difference(cases, perfect, half, reps=200, seed=7)

    assert first == bootstrap_difference(cases, perfect, half, reps=200, seed=7)
    assert first["difference"] == 0.5
    assert 0 < first["low"] <= first["difference"] <= first["high"] < 1
    assert first["reps"] == 200


def test_bootstrap_of_identical_configurations_is_exactly_zero() -> None:
    cases = _cases(10, 10)
    found = {name: {89} for name, *_ in cases}

    assert bootstrap_difference(cases, found, found, reps=50) == {
        "difference": 0.0,
        "low": 0.0,
        "high": 0.0,
        "reps": 50,
    }


def test_bootstrap_interval_straddles_zero_when_the_gain_is_one_case_in_a_big_cell() -> None:
    cases = _cases(100, 100)
    base: dict[str, set[int]] = {name: set() for name, *_ in cases}
    one = {**base, "v0": {89}}

    interval = bootstrap_difference(cases, one, base, reps=400, seed=1)

    assert interval["difference"] == 0.01
    assert interval["low"] == 0.0


def test_bootstrap_needs_enough_draws_for_a_95_percent_interval() -> None:
    with pytest.raises(ValueError, match="at least 20"):
        bootstrap_difference(_cases(2, 2), {}, {}, reps=10)


def test_configurations_are_resolved_from_the_cache(tmp_path: Path) -> None:
    def write(name: str, found: dict[str, list[int]]) -> None:
        (tmp_path / name).write_text(json.dumps({"found": found, "cost": 0}), encoding="utf-8")

    write("model.json", {"a": [89], "b": []})
    write("model-verified.json", {"a": [89], "b": [79]})
    write("second-verified.json", {"a": [], "b": [79]})
    (tmp_path / "scanners.json").write_text(
        json.dumps({"securecode": {"a": [], "b": [327]}, "semgrep": {}, "bandit": {}}),
        encoding="utf-8",
    )

    assert load_configuration("model", tmp_path) == {"a": {89}, "b": set()}
    assert load_configuration("verified+model", tmp_path) == {"a": {89}, "b": {79}}
    assert load_configuration("securecode", tmp_path) == {"a": set(), "b": {327}}
    assert load_configuration("consensus+model+second", tmp_path) == {"a": {89}, "b": {79, 327}}
