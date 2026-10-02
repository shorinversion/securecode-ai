"""Majority vote of independent passes in the OWASP Benchmark scoring."""

from scripts.owasp_benchmark_python import consensus, informative_hints, scanner_decides, score


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
