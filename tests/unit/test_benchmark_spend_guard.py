"""Atomic budget limits, idempotency and uncertain provider completion."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from scripts.benchmark_spend_guard import AttemptQuote, BenchmarkSpendGuard, SpendGuardError


def _quote(identifier: str, phase: str = "development") -> AttemptQuote:
    return AttemptQuote(identifier, phase, "a" * 40, "b" * 64, 6, 1, 1_000_000_000_000, 1)


def test_unknown_attempt_keeps_hold_after_restart_and_replay_is_not_new_call(
    tmp_path: Path,
) -> None:
    path = tmp_path / "budget.db"
    guard = BenchmarkSpendGuard(path)
    assert guard.reserve(_quote("attempt-1"))
    assert not BenchmarkSpendGuard(path).reserve(_quote("attempt-1"))
    with pytest.raises(SpendGuardError):
        BenchmarkSpendGuard(path).reserve(_quote("attempt-2"))
    assert guard.charged_micro_usd() == 6_000_001


def test_parallel_reservations_cannot_exceed_phase_cap(tmp_path: Path) -> None:
    guard = BenchmarkSpendGuard(tmp_path / "budget.db")

    def reserve(identifier: str) -> bool:
        try:
            return guard.reserve(_quote(identifier))
        except SpendGuardError:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = tuple(pool.map(reserve, ("one", "two", "three", "four")))
    assert sum(outcomes) == 1
    assert guard.charged_micro_usd() == 6_000_001


def test_settlement_is_bounded_and_retry_safe(tmp_path: Path) -> None:
    guard = BenchmarkSpendGuard(tmp_path / "budget.db")
    quote = _quote("one")
    guard.reserve(quote)
    with pytest.raises(SpendGuardError):
        guard.settle(quote, input_tokens=7, output_tokens=0)
    assert guard.charged_micro_usd() == 6_000_001
    guard.settle(quote, input_tokens=2, output_tokens=0)
    guard.settle(quote, input_tokens=2, output_tokens=0)
    assert guard.charged_micro_usd() == 2_000_000
    with pytest.raises(SpendGuardError):
        guard.settle(quote, input_tokens=0, output_tokens=0)
    with pytest.raises(SpendGuardError):
        guard.reserve(replace(quote, profile_sha256="c" * 64))
    assert guard.reserve(_quote("two"))


def test_phase_and_total_caps_cannot_be_reconfigured(tmp_path: Path) -> None:
    path = tmp_path / "budget.db"
    guard = BenchmarkSpendGuard(path, total_cap_micro_usd=7_000_000)
    guard.reserve(_quote("one"))
    with pytest.raises(SpendGuardError):
        guard.reserve(_quote("two", "final"))
    with pytest.raises(SpendGuardError):
        BenchmarkSpendGuard(path, total_cap_micro_usd=50_000_000)


def test_prices_round_up_and_boolean_usage_is_rejected(tmp_path: Path) -> None:
    quote = replace(_quote("one"), max_input_tokens=1, input_micro_usd_per_million=1)
    assert quote.reservation_micro_usd == 2
    guard = BenchmarkSpendGuard(tmp_path / "budget.db")
    guard.reserve(quote)
    with pytest.raises(SpendGuardError):
        guard.settle(quote, input_tokens=True, output_tokens=0)


@pytest.mark.parametrize("field", ["max_input_tokens", "max_output_tokens"])
def test_zero_ceiling_cannot_authorize_an_unbounded_free_attempt(field: str) -> None:
    with pytest.raises(SpendGuardError):
        if field == "max_input_tokens":
            replace(_quote("one"), max_input_tokens=0)
        else:
            replace(_quote("one"), max_output_tokens=0)


def test_settlement_replay_rejects_different_usage_with_equal_rounded_cost(tmp_path: Path) -> None:
    quote = replace(_quote("one"), input_micro_usd_per_million=1)
    assert quote.cost(1, 0) == quote.cost(2, 0)
    guard = BenchmarkSpendGuard(tmp_path / "budget.db")
    guard.reserve(quote)
    guard.settle(quote, input_tokens=1, output_tokens=0)
    with pytest.raises(SpendGuardError):
        BenchmarkSpendGuard(tmp_path / "budget.db").settle(quote, input_tokens=2, output_tokens=0)
    assert guard.charged_micro_usd() == 1
