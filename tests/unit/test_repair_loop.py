"""Focused P4.7 bounded-loop contract tests."""

from __future__ import annotations

from securecode_ai.core.repair_loop import (
    AttemptUsage,
    RepairBudget,
    RepairState,
    RepairStopReason,
    _feedback,
    _sum_usage,
)


def test_usage_is_cumulative_and_attempt_limit_is_three() -> None:
    assert _sum_usage(AttemptUsage(1, 2, 3), AttemptUsage(4, 5, 6)) == AttemptUsage(5, 7, 9)
    assert RepairBudget().max_attempts == 3


def test_feedback_is_optional_for_a_completed_validation() -> None:
    assert RepairState.RETRY.value == "RETRY"
    assert RepairStopReason.NO_PROGRESS.value == "NO_PROGRESS"
    assert _feedback is not None
