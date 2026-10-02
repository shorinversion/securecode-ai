"""Majority vote of independent passes in the OWASP Benchmark scoring."""

from scripts.owasp_benchmark_python import consensus, score


def test_cwe_survives_only_with_a_strict_majority() -> None:
    discovery = {"a": {89}, "b": {79}, "c": set()}
    auditor = {"a": {89}, "b": set(), "c": {22}}
    second = {"a": set(), "b": {79, 22}, "c": set()}

    assert consensus(discovery, auditor, second) == {"a": {89}, "b": {79}, "c": set()}


def test_missing_case_counts_as_an_empty_vote() -> None:
    assert consensus({"a": {89}}, {"a": {89}}, {}) == {"a": {89}}
    assert consensus({"a": {89}}, {}, {}) == {"a": set()}


def test_consensus_removes_a_lone_false_positive_from_the_score() -> None:
    cases = [("vulnerable", "sqli", True, 89), ("safe", "sqli", False, 89)]
    noisy = {"vulnerable": {89}, "safe": {89}}
    careful = {"vulnerable": {89}, "safe": set()}

    voted = consensus(noisy, careful, careful)

    assert score(cases, noisy)["categories"]["sqli"]["score"] == 0.0
    assert score(cases, voted)["categories"]["sqli"]["score"] == 1.0
