"""Bootstrap interval of the score difference between two OWASP Benchmark configurations.

Reads only the answers saved in the benchmark cache (``report/benchmark-v2/cache``), so it
needs no network, no scanner and no model.  The resampling is paired and stratified: every
bootstrap draw takes, inside each (category, vulnerable/safe) cell, as many cases as the cell
has, the same cases for both configurations, and rescored the way ``score`` does it.  The
interval is the 2.5th and 97.5th percentile of the score difference.
"""

from __future__ import annotations

import argparse
import json
import random
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from scripts.owasp_benchmark_python import (
    CATEGORY_CWES,
    Case,
    consensus,
    load_cases_file,
    scanner_decides,
)

DEFAULT_CACHE: Final = Path("report/benchmark-v2/cache")
SCANNERS: Final = ("securecode", "semgrep", "bandit")
Found = dict[str, set[int]]


def _read(path: Path) -> Found:
    document = json.loads(path.read_text(encoding="utf-8"))
    return {name: set(values) for name, values in document["found"].items()}


def load_configuration(name: str, cache: Path) -> Found:
    """Resolve a configuration name the way ``owasp_benchmark_python`` names its results.

    ``securecode``, ``semgrep`` and ``bandit`` come from ``scanners.json``; ``MODEL`` is the
    model alone; ``verified+MODEL`` verifies the scanner findings; ``consensus+MODEL+SECOND``
    is the majority of MODEL alone, MODEL verifying and SECOND verifying, with weak hashes
    taken from the scanner.
    """

    if name in SCANNERS:
        document = json.loads((cache / "scanners.json").read_text(encoding="utf-8"))
        return {case: set(values) for case, values in document[name].items()}
    if name.startswith("verified+"):
        return _read(cache / f"{name.removeprefix('verified+')}-verified.json")
    if name.startswith("consensus+"):
        _, model, second = name.split("+", 2)
        return scanner_decides(
            consensus(
                load_configuration(model, cache),
                load_configuration(f"verified+{model}", cache),
                load_configuration(f"verified+{second}", cache),
            ),
            load_configuration("securecode", cache),
        )
    return _read(cache / f"{name}.json")


def _hits(cases: Sequence[Case], found: Mapping[str, set[int]]) -> dict[str, bool]:
    accepted = {name: CATEGORY_CWES[category] for name, category, *_ in cases}
    return {name: bool(found.get(name, set()) & accepted[name]) for name, *_ in cases}


def _score(cells: Mapping[tuple[str, bool], Sequence[int]], hits: Sequence[int]) -> float:
    """Mean over categories of TPR - FPR, from per-cell hit counts."""

    rates: dict[str, float] = {}
    for category in {category for category, _ in cells}:
        positives = sum(hits[index] for index in cells.get((category, True), ()))
        negatives = sum(hits[index] for index in cells.get((category, False), ()))
        vulnerable = len(cells.get((category, True), ()))
        safe = len(cells.get((category, False), ()))
        rates[category] = (positives / vulnerable if vulnerable else 0.0) - (
            negatives / safe if safe else 0.0
        )
    return sum(rates.values()) / len(rates)


def bootstrap_difference(
    cases: Sequence[Case],
    first: Mapping[str, set[int]],
    second: Mapping[str, set[int]],
    *,
    reps: int = 2000,
    seed: int = 0,
) -> dict[str, float]:
    """Score of ``first`` minus score of ``second`` with its 95% bootstrap interval."""

    if reps < 20:
        raise ValueError("at least 20 bootstrap draws are needed for a 95% interval")
    first_hits = _hits(cases, first)
    second_hits = _hits(cases, second)
    order = [name for name, *_ in cases]
    a = [int(first_hits[name]) for name in order]
    b = [int(second_hits[name]) for name in order]
    cells: dict[tuple[str, bool], list[int]] = {}
    for index, (_, category, vulnerable, _) in enumerate(cases):
        cells.setdefault((category, vulnerable), []).append(index)
    estimate = _score(cells, a) - _score(cells, b)
    generator = random.Random(seed)
    differences: list[float] = []
    for _ in range(reps):
        drawn: dict[tuple[str, bool], Sequence[int]] = {}
        sample_a: list[int] = []
        sample_b: list[int] = []
        for key, members in cells.items():
            picks = [members[generator.randrange(len(members))] for _ in members]
            start = len(sample_a)
            sample_a += [a[index] for index in picks]
            sample_b += [b[index] for index in picks]
            drawn[key] = range(start, len(sample_a))
        differences.append(_score(drawn, sample_a) - _score(drawn, sample_b))
    differences.sort()
    return {
        "difference": round(estimate, 4),
        "low": round(differences[int(0.025 * reps)], 4),
        "high": round(differences[int(0.975 * reps) - 1], 4),
        "reps": reps,
    }


def _format(value: float) -> str:
    return f"{value:+.3f}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--cases", type=Path, help="default: <cache>/cases.json")
    parser.add_argument(
        "--pair",
        nargs=2,
        action="append",
        required=True,
        metavar=("FIRST", "SECOND"),
        help="configurations to compare, for example consensus+gpt-oss-120b+luna gpt-oss-120b",
    )
    parser.add_argument("--reps", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--output", type=Path, help="write the intervals as JSON")
    arguments = parser.parse_args(argv)
    cases = load_cases_file(arguments.cases or arguments.cache / "cases.json")
    results: dict[str, Any] = {}
    for first, second in arguments.pair:
        interval = bootstrap_difference(
            cases,
            load_configuration(first, arguments.cache),
            load_configuration(second, arguments.cache),
            reps=arguments.reps,
            seed=arguments.seed,
        )
        results[f"{first} - {second}"] = interval
        print(
            f"{first} - {second}: {_format(interval['difference'])} "
            f"[{_format(interval['low'])}; {_format(interval['high'])}]"
        )
    if arguments.output is not None:
        arguments.output.write_text(
            json.dumps(
                {"reps": arguments.reps, "seed": arguments.seed, "differences": results},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
