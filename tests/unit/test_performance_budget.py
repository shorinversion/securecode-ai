from securecode_ai.core.performance_budget import PerformanceBudget
from securecode_ai.core.performance_regression import compare


def test_missing_samples_cannot_pass() -> None:
    assert not compare(PerformanceBudget("1", 1, 1, 1, 1, 1, 1), (), ())["passed"]
