"""Run the frozen CVEfixes corpus through the release benchmark lanes.

The runner reads source only from a locally supplied CVEfixes SQLite database.
It verifies every byte against the committed source-free manifest before a
scanner or public-model lane sees it.  Remote execution is opt-in and only
accepts a public corpus, never a repository checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from securecode_ai.adapters.product_scanner import FirstPartyStaticWorker
from securecode_ai.core.release_benchmark import BenchmarkCell, Configuration, aggregate
from securecode_ai.core.repository import RepositoryFile
from securecode_ai.core.scanning import ScannerRequest

from scripts.benchmark_spend_guard import AttemptQuote, BenchmarkSpendGuard, SpendGuardError

LANGUAGE_EXTENSIONS = {"python": ".py", "javascript-typescript": ".ts", "go": ".go"}
MODEL_LANES = frozenset(
    {Configuration.SCANNER, Configuration.MODEL, Configuration.ONE_SHOT, Configuration.HYBRID}
)


@dataclass(frozen=True, slots=True)
class Case:
    case_id: str
    content_sha256: str
    cwe_id: str
    expected_label: str
    language: str
    lineage: str


@dataclass(frozen=True, slots=True)
class RemoteBudget:
    """A conservative, durable reservation policy for public model calls."""

    ledger: Path
    phase: str
    total_cap_micro_usd: int
    candidate_sha: str
    profile_sha256: str
    max_input_tokens: int
    max_output_tokens: int
    input_micro_usd_per_million: int
    output_micro_usd_per_million: int

    def __post_init__(self) -> None:
        phase_cap = {"development": 10_000_000, "final": 40_000_000}.get(self.phase)
        if (
            phase_cap is None
            or type(self.total_cap_micro_usd) is not int
            or not 1 <= self.total_cap_micro_usd <= phase_cap
        ):
            raise ValueError("remote total budget is invalid")

    def reserve(
        self, case: Case, lane: Configuration, repetition: int, *, input_token_bound: int
    ) -> AttemptQuote | None:
        if (
            type(input_token_bound) is not int
            or not 1 <= input_token_bound <= self.max_input_tokens
        ):
            raise RemoteBudgetError()
        identity = hashlib.sha256(f"{case.case_id}:{lane.value}:{repetition}".encode()).hexdigest()
        quote = AttemptQuote(
            attempt_id=f"release-{identity}",
            phase=self.phase,
            candidate_sha=self.candidate_sha,
            profile_sha256=self.profile_sha256,
            max_input_tokens=input_token_bound,
            max_output_tokens=self.max_output_tokens,
            input_micro_usd_per_million=self.input_micro_usd_per_million,
            output_micro_usd_per_million=self.output_micro_usd_per_million,
        )
        try:
            return (
                quote
                if BenchmarkSpendGuard(
                    self.ledger, total_cap_micro_usd=self.total_cap_micro_usd
                ).reserve(quote)
                else None
            )
        except SpendGuardError as error:
            raise RemoteBudgetError() from error

    def settle(self, quote: AttemptQuote, *, input_tokens: int, output_tokens: int) -> int:
        try:
            BenchmarkSpendGuard(self.ledger, total_cap_micro_usd=self.total_cap_micro_usd).settle(
                quote, input_tokens=input_tokens, output_tokens=output_tokens
            )
        except SpendGuardError as error:
            raise RemoteBudgetError() from error
        return quote.cost(input_tokens, output_tokens)


class RemoteBudgetError(ValueError):
    """A fixed non-echo result when an API attempt cannot be reserved."""


def _sha256(source: str) -> str:
    return "sha256:" + hashlib.sha256(source.encode("utf-8")).hexdigest()


def _load_cases(manifest: Path, limit: int | None, *, offset: int = 0) -> tuple[Case, ...]:
    if type(offset) is not int or offset < 0:
        raise ValueError("case offset is invalid")
    document = json.loads(manifest.read_text(encoding="utf-8"))
    datasets = document.get("datasets")
    if type(datasets) is not list or len(datasets) != 1:
        raise ValueError("manifest must contain one resolved dataset")
    cases: list[Case] = []
    for raw in datasets[0].get("cases", []):
        if type(raw) is not dict:
            raise ValueError("manifest case is invalid")
        lineages = raw.get("lineage_groups")
        if type(lineages) is not list or len(lineages) != 1:
            raise ValueError("manifest case lineage is invalid")
        values = (
            raw.get("case_id"),
            raw.get("content_sha256"),
            raw.get("cwe_id"),
            raw.get("expected_label"),
            raw.get("language"),
            lineages[0],
        )
        if not all(type(value) is str and value for value in values):
            raise ValueError("manifest case identity is invalid")
        cases.append(Case(*(str(value) for value in values)))
    selected = tuple(sorted(cases, key=lambda item: item.case_id))
    selected = selected[offset:]
    if limit is not None:
        selected = selected[:limit]
    if not selected:
        raise ValueError("no selected cases")
    return selected


def _source(connection: sqlite3.Connection, case: Case) -> str:
    parts = case.case_id.rsplit(":", 1)
    if len(parts) != 2 or parts[1] not in {"before", "after"}:
        raise ValueError("unsupported case identity")
    lineage = parts[0].split(":")
    if len(lineage) != 3 or lineage[0] != "cvefixes":
        raise ValueError("unsupported case lineage")
    row = connection.execute(
        "SELECT code_before, code_after FROM file_change WHERE file_change_id = ?", (lineage[2],)
    ).fetchone()
    if row is None or type(row[0]) is not str or type(row[1]) is not str:
        raise ValueError(f"source unavailable for {case.case_id}")
    source = row[0] if parts[1] == "before" else row[1]
    if _sha256(source) != case.content_sha256:
        raise ValueError(f"source identity drift for {case.case_id}")
    return source


def _deterministic(case: Case, source: str) -> bool:
    revision = hashlib.sha1(case.case_id.encode("ascii")).hexdigest()
    request = ScannerRequest(
        request_id="benchmark-" + hashlib.sha256(case.case_id.encode()).hexdigest(),
        tenant_id="public-benchmark",
        repository_id="cvefixes-public",
        head_sha=revision,
        file=RepositoryFile(
            "case" + LANGUAGE_EXTENSIONS[case.language], len(source.encode()), _sha256(source)[7:]
        ),
        source=source.encode(),
    )
    return bool(FirstPartyStaticWorker().scan(request).signals)


def _remote_prediction(
    case: Case, source: str, *, one_shot: bool, max_output_tokens: int = 64
) -> tuple[bool, int, int, int]:
    key = os.environ.get("DEEPSEEK_API_KEY")
    endpoint = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
    model = os.environ.get("DEEPSEEK_MODEL", "deepseek-flash")
    if not key:
        raise ValueError("DEEPSEEK_API_KEY is required for remote lanes")
    example = '\nExample: {"vulnerable": false}\n' if one_shot else ""
    prompt = (
        'Classify this public CVEfixes source only. Return strict json {"vulnerable":boolean}. '
        "Do not explain.\nLanguage: " + case.language + example + "\nSource:\n" + source
    )
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "response_format": {"type": "json_object"},
        "temperature": 0,
        "thinking": {"type": "disabled"},
        "reasoning_effort": "none",
        "max_tokens": max_output_tokens,
    }
    request = urllib.request.Request(
        endpoint + "/chat/completions",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            frame = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise ValueError("remote model request failed") from error
    try:
        usage = frame["usage"]
        input_tokens = int(usage["prompt_tokens"])
        output_tokens = int(usage["completion_tokens"])
        value = json.loads(frame["choices"][0]["message"]["content"])["vulnerable"]
        tokens = int(usage["total_tokens"])
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("remote model response is invalid") from error
    if (
        type(value) is not bool
        or min(input_tokens, output_tokens, tokens) < 0
        or tokens != input_tokens + output_tokens
        or output_tokens > max_output_tokens
    ):
        raise ValueError("remote model response is invalid")
    return value, tokens, input_tokens, output_tokens


def _semgrep_prediction(
    case: Case,
    source: str,
    *,
    command: str,
    config: Path,
) -> bool:
    """Run one pinned local Semgrep configuration without retaining source bytes."""
    if not command or not (config.is_file() or config.is_dir()):
        raise ValueError("Semgrep command or configuration is unavailable")
    language_config = config
    if config.is_dir():
        language_config = (
            config
            / {
                "python": "python",
                "javascript-typescript": "javascript",
                "go": "go",
            }[case.language]
        )
    if not (language_config.is_file() or language_config.is_dir()):
        raise ValueError("Semgrep language configuration is unavailable")
    suffix = LANGUAGE_EXTENSIONS[case.language]
    with tempfile.TemporaryDirectory(prefix="securecode-ai-benchmark-") as directory:
        source_path = Path(directory) / ("case" + suffix)
        source_path.write_text(source, encoding="utf-8", newline="\n")
        try:
            completed = subprocess.run(
                (
                    command,
                    "scan",
                    "--config",
                    str(language_config),
                    "--json",
                    "--no-git-ignore",
                    "--quiet",
                    str(source_path),
                ),
                check=False,
                capture_output=True,
                text=True,
                timeout=90,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("Semgrep invocation failed") from error
    if completed.returncode not in {0, 1}:
        raise ValueError("Semgrep invocation failed")
    try:
        results = json.loads(completed.stdout)["results"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("Semgrep response is invalid") from error
    if type(results) is not list:
        raise ValueError("Semgrep response is invalid")
    return bool(results)


def _semgrep_predictions(
    cases: tuple[tuple[Case, str], ...],
    *,
    command: str,
    config: Path,
) -> tuple[tuple[Case, bool, int, str], ...]:
    """Batch local Semgrep by language so rules compile once per language."""
    grouped: dict[str, list[tuple[Case, str]]] = {}
    for case, source in cases:
        grouped.setdefault(case.language, []).append((case, source))
    predictions: list[tuple[Case, bool, int, str]] = []
    for language, values in grouped.items():
        language_config = config
        if config.is_dir():
            language_config = (
                config
                / {
                    "python": "python",
                    "javascript-typescript": "javascript",
                    "go": "go",
                }[language]
            )
        if not (language_config.is_file() or language_config.is_dir()):
            raise ValueError("Semgrep language configuration is unavailable")
        with tempfile.TemporaryDirectory(prefix="securecode-ai-benchmark-") as directory:
            root = Path(directory)
            names: dict[str, Case] = {}
            for index, (case, source) in enumerate(values):
                name = f"case-{index}{LANGUAGE_EXTENSIONS[language]}"
                (root / name).write_text(source, encoding="utf-8", newline="\n")
                names[name] = case
            started = time.monotonic_ns()
            try:
                completed = subprocess.run(
                    (
                        command,
                        "scan",
                        "--config",
                        str(language_config),
                        "--json",
                        "--no-git-ignore",
                        "--quiet",
                        str(root),
                    ),
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ValueError("Semgrep invocation failed") from error
            elapsed = (time.monotonic_ns() - started) // 1_000_000
            if completed.returncode not in {0, 1}:
                raise ValueError("Semgrep invocation failed")
            try:
                results = json.loads(completed.stdout)["results"]
            except (KeyError, TypeError, json.JSONDecodeError) as error:
                raise ValueError("Semgrep response is invalid") from error
            if type(results) is not list:
                raise ValueError("Semgrep response is invalid")
            matched: set[str] = set()
            for result in results:
                if type(result) is not dict or type(result.get("path")) is not str:
                    raise ValueError("Semgrep response is invalid")
                name = Path(result["path"]).name
                if name not in names:
                    raise ValueError("Semgrep response is invalid")
                matched.add(name)
            per_case_latency = elapsed // len(values)
            predictions.extend(
                (case, name in matched, per_case_latency, "completed")
                for name, case in names.items()
            )
    return tuple(predictions)


def _cell(
    case: Case,
    lane: Configuration,
    repetition: int,
    predicted: bool,
    latency_ms: int,
    tokens: int,
    status: str = "completed",
    source_lines: int = 0,
    cost_microunits: int = 0,
) -> BenchmarkCell:
    vulnerable = case.expected_label == "vulnerable"
    return BenchmarkCell(
        configuration=lane,
        language={"python": "python", "javascript-typescript": "js-ts", "go": "go"}[case.language],
        cwe=case.cwe_id,
        lineage=hashlib.sha256(case.lineage.encode()).hexdigest(),
        repetition=repetition,
        status=status,
        tp=int(predicted and vulnerable),
        fp=int(predicted and not vulnerable),
        tn=int(not predicted and not vulnerable),
        fn=int(not predicted and vulnerable),
        kloc=max(source_lines, 0) / 1000,
        latency_ms=latency_ms,
        tokens=tokens,
        cost_microunits=cost_microunits,
    )


def run(
    cases: Iterable[Case],
    database: Path,
    lane: Configuration,
    repetitions: int,
    remote: bool,
    *,
    semgrep_command: str = "semgrep",
    semgrep_config: Path | None = None,
    remote_budget: RemoteBudget | None = None,
) -> tuple[BenchmarkCell, ...]:
    if lane in MODEL_LANES and not remote:
        raise ValueError("remote lanes require --allow-public-remote")
    uri = database.resolve(strict=True).as_uri() + "?mode=ro&immutable=1"
    cells: list[BenchmarkCell] = []
    with sqlite3.connect(uri, uri=True) as connection:
        if lane is Configuration.SEMGREP:
            if semgrep_config is None:
                raise ValueError("Semgrep configuration is unavailable")
            sources = tuple((case, _source(connection, case)) for case in cases)
            try:
                predictions = _semgrep_predictions(
                    sources, command=semgrep_command, config=semgrep_config
                )
            except ValueError:
                return tuple(
                    _cell(
                        case,
                        lane,
                        repetition,
                        False,
                        0,
                        0,
                        "semgrep-failed",
                        len(source.splitlines()),
                    )
                    for case, source in sources
                    for repetition in range(1, repetitions + 1)
                )
            source_lines = {case.case_id: len(source.splitlines()) for case, source in sources}
            return tuple(
                _cell(
                    case,
                    lane,
                    repetition,
                    predicted,
                    latency,
                    0,
                    status,
                    source_lines[case.case_id],
                )
                for case, predicted, latency, status in predictions
                for repetition in range(1, repetitions + 1)
            )
        for case in cases:
            source = _source(connection, case)
            scanner: bool | None = None
            scanner_failed = False
            if lane in {Configuration.DETERMINISTIC, Configuration.SCANNER, Configuration.HYBRID}:
                try:
                    scanner = _deterministic(case, source)
                except Exception:
                    scanner_failed = True
                    if lane is not Configuration.HYBRID:
                        for repetition in range(1, repetitions + 1):
                            cells.append(
                                _cell(
                                    case,
                                    lane,
                                    repetition,
                                    False,
                                    0,
                                    0,
                                    "scanner-failed",
                                    len(source.splitlines()),
                                )
                            )
                        continue
            for repetition in range(1, repetitions + 1):
                started = time.monotonic_ns()
                tokens = 0
                input_tokens = 0
                output_tokens = 0
                cost_microunits = 0
                budget_quote: AttemptQuote | None = None
                try:
                    if (
                        lane in MODEL_LANES
                        and (lane is not Configuration.SCANNER or bool(scanner))
                        and remote_budget is not None
                    ):
                        budget_quote = remote_budget.reserve(
                            case,
                            lane,
                            repetition,
                            input_token_bound=len(source.encode("utf-8")) + 2048,
                        )
                        if budget_quote is None:
                            raise RemoteBudgetError()
                    if lane is Configuration.DETERMINISTIC:
                        predicted = bool(scanner)
                    elif lane is Configuration.SCANNER:
                        if scanner:
                            prediction = _remote_prediction(
                                case,
                                source,
                                one_shot=False,
                                max_output_tokens=(
                                    remote_budget.max_output_tokens
                                    if remote_budget is not None
                                    else 64
                                ),
                            )
                            predicted, tokens, input_tokens, output_tokens = prediction
                        else:
                            predicted = False
                    elif lane is Configuration.MODEL:
                        prediction = _remote_prediction(
                            case,
                            source,
                            one_shot=False,
                            max_output_tokens=(
                                remote_budget.max_output_tokens if remote_budget else 64
                            ),
                        )
                        predicted, tokens, input_tokens, output_tokens = prediction
                    elif lane is Configuration.ONE_SHOT:
                        prediction = _remote_prediction(
                            case,
                            source,
                            one_shot=True,
                            max_output_tokens=(
                                remote_budget.max_output_tokens if remote_budget else 64
                            ),
                        )
                        predicted, tokens, input_tokens, output_tokens = prediction
                    elif lane is Configuration.HYBRID:
                        prediction = _remote_prediction(
                            case,
                            source,
                            one_shot=False,
                            max_output_tokens=(
                                remote_budget.max_output_tokens if remote_budget else 64
                            ),
                        )
                        model, tokens, input_tokens, output_tokens = prediction
                        predicted = bool(scanner) or model
                    else:
                        raise ValueError("unsupported benchmark configuration")
                    if budget_quote is not None:
                        assert remote_budget is not None
                        cost_microunits = remote_budget.settle(
                            budget_quote,
                            input_tokens=input_tokens,
                            output_tokens=output_tokens,
                        )
                except RemoteBudgetError:
                    cells.append(_cell(case, lane, repetition, False, 0, 0, "budget-rejected"))
                    continue
                except (SpendGuardError, ValueError):
                    cells.append(_cell(case, lane, repetition, False, 0, 0, "model-failed"))
                    continue
                cells.append(
                    _cell(
                        case,
                        lane,
                        repetition,
                        predicted,
                        (time.monotonic_ns() - started) // 1_000_000,
                        tokens,
                        "scanner-failed" if scanner_failed else "completed",
                        len(source.splitlines()),
                        cost_microunits,
                    )
                )
    return tuple(cells)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument(
        "--configuration",
        choices=[item.value for item in Configuration if item is not Configuration.CODEQL],
        required=True,
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--allow-public-remote", action="store_true")
    parser.add_argument("--semgrep-command", default="semgrep")
    parser.add_argument("--semgrep-config", type=Path)
    parser.add_argument("--spend-ledger", type=Path)
    parser.add_argument("--budget-phase", choices=("development", "final"))
    parser.add_argument("--total-budget-microusd", type=int)
    parser.add_argument("--candidate-sha")
    parser.add_argument("--profile-sha256")
    parser.add_argument("--max-input-tokens", type=int)
    parser.add_argument("--max-output-tokens", type=int)
    parser.add_argument("--input-microusd-per-million", type=int)
    parser.add_argument("--output-microusd-per-million", type=int)
    arguments = parser.parse_args(argv)
    try:
        if (
            (arguments.limit is not None and arguments.limit < 1) or arguments.offset < 0
        ) or not 1 <= arguments.repetitions <= 3:
            raise ValueError("limit, offset and repetitions are invalid")
        lane = Configuration(arguments.configuration)
        remote_budget: RemoteBudget | None = None
        if lane in MODEL_LANES:
            values = (
                arguments.spend_ledger,
                arguments.budget_phase,
                arguments.total_budget_microusd,
                arguments.candidate_sha,
                arguments.profile_sha256,
                arguments.max_input_tokens,
                arguments.max_output_tokens,
                arguments.input_microusd_per_million,
                arguments.output_microusd_per_million,
            )
            if any(value is None for value in values):
                raise ValueError("remote lanes require an explicit spend budget")
            assert arguments.spend_ledger is not None
            assert arguments.budget_phase is not None
            assert arguments.total_budget_microusd is not None
            assert arguments.candidate_sha is not None
            assert arguments.profile_sha256 is not None
            assert arguments.max_input_tokens is not None
            assert arguments.max_output_tokens is not None
            assert arguments.input_microusd_per_million is not None
            assert arguments.output_microusd_per_million is not None
            remote_budget = RemoteBudget(
                arguments.spend_ledger,
                arguments.budget_phase,
                arguments.total_budget_microusd,
                arguments.candidate_sha,
                arguments.profile_sha256,
                arguments.max_input_tokens,
                arguments.max_output_tokens,
                arguments.input_microusd_per_million,
                arguments.output_microusd_per_million,
            )
        cells = run(
            _load_cases(
                arguments.manifest.resolve(strict=True), arguments.limit, offset=arguments.offset
            ),
            arguments.database,
            lane,
            arguments.repetitions,
            arguments.allow_public_remote,
            semgrep_command=arguments.semgrep_command,
            semgrep_config=(
                arguments.semgrep_config.resolve(strict=True)
                if arguments.semgrep_config is not None
                else None
            ),
            remote_budget=remote_budget,
        )
        result: dict[str, Any] = {
            "cells": [asdict(cell) for cell in cells],
            "aggregate": asdict(aggregate(cells, lane)),
        }
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"RELEASE_BENCHMARK=FAIL: {error}")
        return 1
    print(f"RELEASE_BENCHMARK=PASS cells={len(cells)} lane={lane.value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
