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


def _sha256(source: str) -> str:
    return "sha256:" + hashlib.sha256(source.encode("utf-8")).hexdigest()


def _load_cases(manifest: Path, limit: int | None) -> tuple[Case, ...]:
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


def _remote_prediction(case: Case, source: str, *, one_shot: bool) -> tuple[bool, int]:
    key = os.environ.get("DEEPSEEK_API_KEY")
    endpoint = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
    model = os.environ.get("DEEPSEEK_MODEL", "deepseek-flash")
    if not key:
        raise ValueError("DEEPSEEK_API_KEY is required for remote lanes")
    example = '\nExample: {"vulnerable": false}\n' if one_shot else ""
    prompt = (
        'Classify this public CVEfixes source only. Return strict JSON {"vulnerable":boolean}. '
        "Do not explain.\nLanguage: " + case.language + example + "\nSource:\n" + source
    )
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "response_format": {"type": "json_object"},
        "temperature": 0,
        "thinking": {"type": "disabled"},
        "reasoning_effort": "none",
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
        value = json.loads(frame["choices"][0]["message"]["content"])["vulnerable"]
        tokens = int(frame.get("usage", {}).get("total_tokens", 0))
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("remote model response is invalid") from error
    if type(value) is not bool or tokens < 0:
        raise ValueError("remote model response is invalid")
    return value, tokens


def _semgrep_prediction(
    case: Case,
    source: str,
    *,
    command: str,
    config: Path,
) -> bool:
    """Run one pinned local Semgrep configuration without retaining source bytes."""
    if not command or not config.is_file():
        raise ValueError("Semgrep command or configuration is unavailable")
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
                    str(config),
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


def _cell(
    case: Case,
    lane: Configuration,
    repetition: int,
    predicted: bool,
    latency_ms: int,
    tokens: int,
    status: str = "completed",
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
        kloc=len(case.case_id) / 1000,
        latency_ms=latency_ms,
        tokens=tokens,
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
) -> tuple[BenchmarkCell, ...]:
    if lane in MODEL_LANES and not remote:
        raise ValueError("remote lanes require --allow-public-remote")
    uri = database.resolve(strict=True).as_uri() + "?mode=ro&immutable=1"
    cells: list[BenchmarkCell] = []
    with sqlite3.connect(uri, uri=True) as connection:
        for case in cases:
            source = _source(connection, case)
            scanner: bool | None = None
            scanner_failed = False
            if lane in {Configuration.DETERMINISTIC, Configuration.SCANNER, Configuration.HYBRID}:
                try:
                    scanner = _deterministic(case, source)
                except (TypeError, ValueError, RuntimeError):
                    scanner_failed = True
                    if lane is not Configuration.HYBRID:
                        for repetition in range(1, repetitions + 1):
                            cells.append(
                                _cell(case, lane, repetition, False, 0, 0, "scanner-failed")
                            )
                        continue
            for repetition in range(1, repetitions + 1):
                started = time.monotonic_ns()
                tokens = 0
                try:
                    if lane is Configuration.DETERMINISTIC:
                        predicted = bool(scanner)
                    elif lane is Configuration.SCANNER:
                        predicted, tokens = (
                            _remote_prediction(case, source, one_shot=False)
                            if scanner
                            else (False, 0)
                        )
                    elif lane is Configuration.MODEL:
                        predicted, tokens = _remote_prediction(case, source, one_shot=False)
                    elif lane is Configuration.ONE_SHOT:
                        predicted, tokens = _remote_prediction(case, source, one_shot=True)
                    elif lane is Configuration.HYBRID:
                        model, tokens = _remote_prediction(case, source, one_shot=False)
                        predicted = bool(scanner) or model
                    elif lane is Configuration.SEMGREP:
                        if semgrep_config is None:
                            raise ValueError("Semgrep configuration is unavailable")
                        predicted = _semgrep_prediction(
                            case,
                            source,
                            command=semgrep_command,
                            config=semgrep_config,
                        )
                    else:
                        raise ValueError("unsupported benchmark configuration")
                except ValueError:
                    status = "semgrep-failed" if lane is Configuration.SEMGREP else "model-failed"
                    cells.append(_cell(case, lane, repetition, False, 0, 0, status))
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
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--allow-public-remote", action="store_true")
    parser.add_argument("--semgrep-command", default="semgrep")
    parser.add_argument("--semgrep-config", type=Path)
    arguments = parser.parse_args(argv)
    try:
        if (
            arguments.limit is not None and arguments.limit < 1
        ) or not 1 <= arguments.repetitions <= 3:
            raise ValueError("limit and repetitions are invalid")
        lane = Configuration(arguments.configuration)
        cells = run(
            _load_cases(arguments.manifest.resolve(strict=True), arguments.limit),
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
