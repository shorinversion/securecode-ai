"""Atomic conservative reservations for public API evaluation, without provider I/O.

Prices and token ceilings must come from the admitted model profile. This guard
is not model admission, a tokenizer, a provider receipt, or authority to call an
API. Unknown/failed attempts retain their full reservation across restarts.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path

_MICRO_USD = 1_000_000
_PHASE_CAPS = {"development": 10 * _MICRO_USD, "final": 40 * _MICRO_USD}


class SpendGuardError(ValueError):
    """Fixed non-echo error: no provider content or credentials are accepted."""

    def __init__(self) -> None:
        super().__init__("benchmark spend reservation rejected")


@dataclass(frozen=True, slots=True)
class AttemptQuote:
    attempt_id: str
    phase: str
    candidate_sha: str
    profile_sha256: str
    max_input_tokens: int
    max_output_tokens: int
    input_micro_usd_per_million: int
    output_micro_usd_per_million: int

    def __post_init__(self) -> None:
        if (
            type(self.attempt_id) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", self.attempt_id) is None
            or type(self.phase) is not str
            or self.phase not in _PHASE_CAPS
            or type(self.candidate_sha) is not str
            or re.fullmatch(r"[0-9a-f]{40}", self.candidate_sha) is None
            or type(self.profile_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.profile_sha256) is None
            or any(
                type(value) is not int or not 1 <= value <= 1_000_000_000
                for value in (self.max_input_tokens, self.max_output_tokens)
            )
            or any(
                type(value) is not int or not 0 < value <= 1_000_000_000_000
                for value in (
                    self.input_micro_usd_per_million,
                    self.output_micro_usd_per_million,
                )
            )
        ):
            raise SpendGuardError()

    @property
    def reservation_micro_usd(self) -> int:
        return self.cost(self.max_input_tokens, self.max_output_tokens)

    def cost(self, input_tokens: int, output_tokens: int) -> int:
        return sum(
            (tokens * price + _MICRO_USD - 1) // _MICRO_USD
            for tokens, price in (
                (input_tokens, self.input_micro_usd_per_million),
                (output_tokens, self.output_micro_usd_per_million),
            )
        )

    @property
    def identity(self) -> str:
        return hashlib.sha256(
            json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


class BenchmarkSpendGuard:
    """SQLite serializes reservations from concurrent workers and survives restart.

    The path must be host-owned ignored state outside any untrusted checkout.
    An existing ledger cannot be reopened with a different total budget.
    Replaying a reservation is not permission for another billable call: each
    actual provider attempt needs a fresh unique attempt_id.
    """

    def __init__(self, path: Path, *, total_cap_micro_usd: int = 50 * _MICRO_USD) -> None:
        if (
            type(total_cap_micro_usd) is not int
            or not 0 < total_cap_micro_usd <= 50 * _MICRO_USD
            or path.is_symlink()
        ):
            raise SpendGuardError()
        self._path = path
        self._total_cap = total_cap_micro_usd
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS settings (singleton INTEGER PRIMARY KEY CHECK(singleton=1), total_cap INTEGER NOT NULL)"
            )
            connection.execute("INSERT OR IGNORE INTO settings VALUES (1, ?)", (self._total_cap,))
            if connection.execute(
                "SELECT total_cap FROM settings WHERE singleton=1"
            ).fetchone() != (self._total_cap,):
                raise SpendGuardError()
            connection.execute(
                "CREATE TABLE IF NOT EXISTS attempts (attempt_id TEXT PRIMARY KEY, phase TEXT NOT NULL, identity TEXT NOT NULL, reserved INTEGER NOT NULL, charged INTEGER NOT NULL, settled INTEGER NOT NULL, settled_input INTEGER, settled_output INTEGER)"
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self._path, timeout=10)) as connection, connection:
            yield connection

    def reserve(self, quote: AttemptQuote) -> bool:
        """Return True only for a newly reserved billable attempt; replay is False."""
        if type(quote) is not AttemptQuote:
            raise SpendGuardError()
        quote = AttemptQuote(**asdict(quote))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT identity FROM attempts WHERE attempt_id=?", (quote.attempt_id,)
            ).fetchone()
            if previous is not None:
                if previous != (quote.identity,):
                    raise SpendGuardError()
                return False
            total = connection.execute("SELECT COALESCE(SUM(charged),0) FROM attempts").fetchone()[
                0
            ]
            phase_total = connection.execute(
                "SELECT COALESCE(SUM(charged),0) FROM attempts WHERE phase=?", (quote.phase,)
            ).fetchone()[0]
            cost = quote.reservation_micro_usd
            if total + cost > self._total_cap or phase_total + cost > _PHASE_CAPS[quote.phase]:
                raise SpendGuardError()
            connection.execute(
                "INSERT INTO attempts VALUES (?,?,?,?,?,0,NULL,NULL)",
                (quote.attempt_id, quote.phase, quote.identity, cost, cost),
            )
            return True

    def settle(self, quote: AttemptQuote, *, input_tokens: int, output_tokens: int) -> None:
        """Settle once with verified usage; missing usage must leave the hold intact."""
        if type(quote) is not AttemptQuote:
            raise SpendGuardError()
        quote = AttemptQuote(**asdict(quote))
        if any(
            type(value) is not int or not 0 <= value <= ceiling
            for value, ceiling in (
                (input_tokens, quote.max_input_tokens),
                (output_tokens, quote.max_output_tokens),
            )
        ):
            raise SpendGuardError()
        actual = quote.cost(input_tokens, output_tokens)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT identity, charged, settled, settled_input, settled_output FROM attempts WHERE attempt_id=?",
                (quote.attempt_id,),
            ).fetchone()
            if previous is None or previous[0] != quote.identity:
                raise SpendGuardError()
            if previous[2]:
                if previous[1] != actual or previous[3:] != (input_tokens, output_tokens):
                    raise SpendGuardError()
                return
            connection.execute(
                "UPDATE attempts SET charged=?, settled=1, settled_input=?, settled_output=? WHERE attempt_id=?",
                (actual, input_tokens, output_tokens, quote.attempt_id),
            )

    def charged_micro_usd(self) -> int:
        with self._connect() as connection:
            return int(
                connection.execute("SELECT COALESCE(SUM(charged),0) FROM attempts").fetchone()[0]
            )
