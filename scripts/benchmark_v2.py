"""Benchmark v2: a larger paired CVEfixes corpus and more baseline tools.

Subcommands:

* ``cache``: copy the sources of the manifest cases from the full CVEfixes database
  into a small SQLite file with the same ``file_change`` columns;
* ``run --tool NAME``: run one tool over every applicable case and append one JSON line
  per case (resumable);
* ``aggregate``: compute precision, recall, F1, false-positive rate, pair
  discrimination and bootstrap intervals, and write ``results.json`` and a report.

Tools: ``securecode`` (first-party scanners), ``semgrep``, ``bandit`` (Python),
``gosec`` (Go, Docker image), ``njsscan`` (JavaScript/TypeScript) and ``deepseek``
(direct classification). Full-pipeline records of ``scripts/run_pipeline_benchmark.py``
can be added to the aggregate as another configuration.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import sqlite3
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Final

from scripts.run_release_benchmark import (
    LANGUAGE_EXTENSIONS,
    Case,
    _deterministic,
    _load_cases,
    _remote_prediction,
    _source,
)

OPEN_WEIGHT_MODELS: Final = (
    "qwen3.8-27b",
    "qwen3.6-35b",
    "qwen3.6-fp8",
    "gpt-oss-120b",
    "gpt-oss-20b",
    "gemma-4-31b",
)
TOOLS: Final = (
    "securecode",
    "semgrep",
    "bandit",
    "gosec",
    "eslint",
    "deepseek",
    "luna",
    "glm",
    *OPEN_WEIGHT_MODELS,
)
TOOL_LANGUAGES: Final = {
    "bandit": frozenset({"python"}),
    "gosec": frozenset({"go"}),
    "eslint": frozenset({"javascript-typescript"}),
}
LANGUAGE_NAMES: Final = {
    "python": "Python",
    "javascript-typescript": "JavaScript/TypeScript",
    "go": "Go",
}
_CHUNK: Final = 200
_DEEPSEEK_INPUT_PRICE: Final = 150_000
_DEEPSEEK_OUTPUT_PRICE: Final = 600_000

Record = dict[str, Any]


# --------------------------------------------------------------------------- cache


def build_cache(manifest: Path, database: Path, output: Path) -> int:
    """Copy the before/after sources of every manifest lineage into ``output``."""

    cases = _load_cases(manifest, None)
    identifiers = sorted({case.case_id.rsplit(":", 1)[0].split(":")[2] for case in cases})
    source = sqlite3.connect(database.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    if output.exists():
        raise ValueError("cache file already exists")
    target = sqlite3.connect(output)
    target.execute(
        "CREATE TABLE file_change (file_change_id TEXT PRIMARY KEY, code_before TEXT, "
        "code_after TEXT)"
    )
    # One pass over the large table: file_change_id is not indexed in the release database.
    wanted = set(identifiers)
    placeholders = ",".join("?" for _ in identifiers)
    copied = 0
    for row in source.execute(
        "SELECT file_change_id, code_before, code_after FROM file_change "
        f"WHERE file_change_id IN ({placeholders})",
        identifiers,
    ):
        if row[0] in wanted:
            wanted.discard(row[0])
            target.execute("INSERT INTO file_change VALUES (?, ?, ?)", row)
            copied += 1
    if wanted:
        raise ValueError(f"{len(wanted)} file changes are missing")
    target.commit()
    target.close()
    connection = sqlite3.connect(output)
    for case in cases:
        _source(connection, case)
    connection.close()
    return len(identifiers)


# --------------------------------------------------------------------------- tools


def _write_cases(
    root: Path, values: Sequence[tuple[Case, str]], *, per_directory: bool = False
) -> dict[str, Case]:
    names: dict[str, Case] = {}
    for index, (case, source) in enumerate(values):
        name = f"case{index}/main.go" if per_directory else f"case-{index}"
        name += "" if per_directory else LANGUAGE_EXTENSIONS[case.language]
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8", newline="\n")
        names[name] = case
    return names


def _match(names: dict[str, Case], reported: Iterable[str], root: Path) -> set[str]:
    matched: set[str] = set()
    for path in reported:
        normalized = path.replace("\\", "/")
        for name in names:
            if normalized.endswith("/" + name) or normalized == name:
                matched.add(name)
    del root
    return matched


def _semgrep(values: Sequence[tuple[Case, str]], config: Path) -> dict[str, Record]:
    language = values[0][0].language
    directory = {"python": "python", "javascript-typescript": "javascript", "go": "go"}
    with tempfile.TemporaryDirectory(prefix="bench-semgrep-") as temporary:
        root = Path(temporary)
        names = _write_cases(root, values)
        completed = subprocess.run(
            (
                "semgrep",
                "scan",
                "--config",
                str(config / directory[language]),
                "--json",
                "--no-git-ignore",
                "--quiet",
                "--metrics=off",
                str(root),
            ),
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=1800,
        )
        document = json.loads(completed.stdout)
        matched = _match(names, (item["path"] for item in document.get("results", [])), root)
        failed = _match(
            names,
            (item.get("path", "") for item in document.get("errors", []) if item.get("path")),
            root,
        )
    return _records(names, matched, failed)


def _bandit(values: Sequence[tuple[Case, str]]) -> dict[str, Record]:
    with tempfile.TemporaryDirectory(prefix="bench-bandit-") as temporary:
        root = Path(temporary)
        names = _write_cases(root, values)
        completed = subprocess.run(
            ("bandit", "-r", str(root), "-f", "json", "-q"),
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=1800,
        )
        document = json.loads(completed.stdout)
        matched = _match(names, (item["filename"] for item in document.get("results", [])), root)
        failed = _match(names, (item["filename"] for item in document.get("errors", [])), root)
    return _records(names, matched, failed)


def _gosec(values: Sequence[tuple[Case, str]]) -> dict[str, Record]:
    with tempfile.TemporaryDirectory(prefix="bench-gosec-") as temporary:
        root = Path(temporary)
        names = _write_cases(root, values, per_directory=True)
        (root / "go.mod").write_text("module bench\n\ngo 1.22\n", encoding="utf-8")
        completed = subprocess.run(
            (
                "docker",
                "run",
                "--rm",
                "--network=none",
                "-v",
                f"{root}:/src",
                "-w",
                "/src",
                "securego/gosec:latest",
                "-fmt=json",
                "-no-fail",
                "-quiet",
                "./...",
            ),
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=3600,
        )
        start = completed.stdout.find("{")
        document = json.loads(completed.stdout[start:]) if start >= 0 else {}
        matched = _match(names, (item["file"] for item in document.get("Issues") or []), root)
        errors = document.get("Golang errors") or {}
        failed = _match(names, errors.keys(), root) - matched
    return _records(names, matched, failed)


ESLINT_HOME: Final = Path.home() / ".codex" / "tools" / "eslint-security"


def _eslint(values: Sequence[tuple[Case, str]]) -> dict[str, Record]:
    """ESLint 9 with every eslint-plugin-security rule; typescript-eslint parses JS and TS.

    ESLint only lints files below its configuration, so the cases are written into a
    temporary directory inside the tool installation.
    """

    ESLINT_HOME.joinpath("cases").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="bench-", dir=ESLINT_HOME / "cases") as temporary:
        root = Path(temporary)
        names = _write_cases(root, values)
        completed = subprocess.run(
            (
                shutil.which("npx") or "npx",
                "eslint",
                "-c",
                "eslint.config.mjs",
                "--format",
                "json",
                str(root),
            ),
            cwd=ESLINT_HOME,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=3600,
        )
        document = json.loads(completed.stdout or "[]")
        reported = [
            item["filePath"]
            for item in document
            if any(message.get("ruleId") for message in item.get("messages", []))
        ]
        broken = [
            item["filePath"]
            for item in document
            if any(message.get("fatal") for message in item.get("messages", []))
        ]
        matched = _match(names, reported, root)
        failed = _match(names, broken, root)
    return _records(names, matched, failed)


def _llm(provider_name: str) -> Callable[[Sequence[tuple[Case, str]]], dict[str, Record]]:
    """Direct classification of one file by an OpenAI-compatible model."""

    from scripts.llm_providers import PROVIDERS, complete_json

    provider = PROVIDERS[provider_name]
    cost_field = "cost_microusd" if provider.currency == "USD" else "cost_microrub"

    def one(item: tuple[Case, str]) -> tuple[str, Record]:
        case, source = item
        if len(source.encode("utf-8")) > 400_000:
            return case.case_id, {"predicted": False, "status": "failed"}
        prompt = (
            'Classify this public CVEfixes source only. Return strict json {"vulnerable":boolean}. '
            "Do not explain.\nLanguage: " + case.language + "\nSource:\n" + source
        )
        try:
            answer, cost = complete_json(provider, prompt)
        except ValueError:
            return case.case_id, {"predicted": False, "status": "failed"}
        value = answer.get("vulnerable")
        if type(value) is not bool:
            return case.case_id, {"predicted": False, "status": "failed", cost_field: cost}
        return case.case_id, {"predicted": value, "status": "completed", cost_field: cost}

    def run(values: Sequence[tuple[Case, str]]) -> dict[str, Record]:
        with ThreadPoolExecutor(max_workers=8) as pool:
            return dict(pool.map(one, values))

    return run


def _records(names: dict[str, Case], matched: set[str], failed: set[str]) -> dict[str, Record]:
    return {
        case.case_id: {
            "predicted": name in matched,
            "status": "failed" if name in failed and name not in matched else "completed",
        }
        for name, case in names.items()
    }


def _securecode_one(item: tuple[Case, str]) -> tuple[str, Record]:
    case, source = item
    try:
        return case.case_id, {"predicted": _deterministic(case, source), "status": "completed"}
    except Exception:
        return case.case_id, {"predicted": False, "status": "failed"}


def _securecode(values: Sequence[tuple[Case, str]]) -> dict[str, Record]:
    with ProcessPoolExecutor(max_workers=8) as pool:
        return dict(pool.map(_securecode_one, values))


def _deepseek(values: Sequence[tuple[Case, str]]) -> dict[str, Record]:
    def one(item: tuple[Case, str]) -> tuple[str, Record]:
        case, source = item
        if len(source.encode("utf-8")) > 900_000:
            return case.case_id, {"predicted": False, "status": "failed"}
        for attempt in range(3):
            try:
                predicted, _, prompt, completion = _remote_prediction(case, source, one_shot=False)
            except ValueError:
                time.sleep(2 * (attempt + 1))
                continue
            cost = (
                prompt * _DEEPSEEK_INPUT_PRICE + completion * _DEEPSEEK_OUTPUT_PRICE
            ) // 1_000_000
            return case.case_id, {
                "predicted": predicted,
                "status": "completed",
                "cost_microusd": cost,
            }
        return case.case_id, {"predicted": False, "status": "failed"}

    with ThreadPoolExecutor(max_workers=8) as pool:
        return dict(pool.map(one, values))


def run_tool(
    tool: str,
    cases: Sequence[Case],
    connection: sqlite3.Connection,
    output: Path,
    *,
    semgrep_config: Path | None,
) -> int:
    done: set[str] = set()
    if output.is_file():
        done = {
            json.loads(line)["case_id"]
            for line in output.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
    languages = TOOL_LANGUAGES.get(tool)
    pending = [
        case
        for case in cases
        if case.case_id not in done and (languages is None or case.language in languages)
    ]
    runners: dict[str, Callable[[Sequence[tuple[Case, str]]], dict[str, Record]]] = {
        "securecode": _securecode,
        "bandit": _bandit,
        "gosec": _gosec,
        "eslint": _eslint,
        "deepseek": _deepseek,
        "luna": _llm("luna"),
        "glm": _llm("glm"),
        **{model: _llm(model) for model in OPEN_WEIGHT_MODELS},
    }
    written = 0
    with output.open("a", encoding="utf-8") as sink:
        by_language: dict[str, list[Case]] = {}
        for case in pending:
            by_language.setdefault(case.language, []).append(case)
        for language_cases in by_language.values():
            for start in range(0, len(language_cases), _CHUNK):
                chunk = [
                    (case, _source(connection, case))
                    for case in language_cases[start : start + _CHUNK]
                ]
                began = time.monotonic()
                if tool == "semgrep":
                    if semgrep_config is None:
                        raise ValueError("--semgrep-config is required")
                    records = _semgrep(chunk, semgrep_config)
                else:
                    records = runners[tool](chunk)
                elapsed = int((time.monotonic() - began) * 1000) // max(1, len(chunk))
                for case, _ in chunk:
                    record = {"case_id": case.case_id, "tool": tool, "latency_ms": elapsed}
                    record.update(
                        records.get(case.case_id, {"predicted": False, "status": "failed"})
                    )
                    sink.write(json.dumps(record, sort_keys=True) + "\n")
                    written += 1
                sink.flush()
                print(
                    f"{tool} {language_cases[0].language} {start + len(chunk)}/{len(language_cases)}",
                    flush=True,
                )
    return written


# --------------------------------------------------------------------------- aggregate


def _manifest_rows(manifest: Path) -> dict[str, dict[str, str]]:
    document = json.loads(manifest.read_text(encoding="utf-8"))
    return {
        raw["case_id"]: {
            "label": raw["expected_label"],
            "language": raw["language"],
            "split": raw["split"],
            "pair": raw["lineage_groups"][0],
            "cwe": raw["cwe_id"],
        }
        for raw in document["datasets"][0]["cases"]
    }


def _load_predictions(path: Path) -> dict[str, Record]:
    records: dict[str, Record] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            item = json.loads(line)
            records[item["case_id"]] = item
    return records


def _pipeline(path: Path) -> dict[str, Record]:
    records: dict[str, Record] = {}
    for item in _load_predictions(path).values():
        records[item["case_id"]] = {
            "predicted": item.get("status") == "fail",
            "status": "completed" if item.get("status") in {"pass", "fail"} else "failed",
            "cost_microusd": item.get("cost_microusd", 0),
        }
    return records


def _metrics(
    rows: dict[str, dict[str, str]], records: dict[str, Record], scope: Iterable[str]
) -> Record:
    ids = [case_id for case_id in scope if case_id in records]
    vulnerable = [case_id for case_id in ids if rows[case_id]["label"] == "vulnerable"]
    safe = [case_id for case_id in ids if rows[case_id]["label"] != "vulnerable"]
    tp = sum(bool(records[case_id]["predicted"]) for case_id in vulnerable)
    fp = sum(bool(records[case_id]["predicted"]) for case_id in safe)
    completed = sum(records[case_id]["status"] == "completed" for case_id in ids)
    pairs: dict[str, dict[str, bool]] = {}
    for case_id in ids:
        pairs.setdefault(rows[case_id]["pair"], {})[rows[case_id]["label"]] = bool(
            records[case_id]["predicted"]
        )
    complete_pairs = [pair for pair in pairs.values() if len(pair) == 2]
    discriminated = sum(pair["vulnerable"] and not pair["fixed-safe"] for pair in complete_pairs)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / len(vulnerable) if vulnerable else 0.0
    return {
        "cases": len(ids),
        "analyzed": round(completed / len(ids), 4) if ids else 0.0,
        "tp": tp,
        "fp": fp,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4)
        if precision + recall
        else 0.0,
        "false_positive_rate": round(fp / len(safe), 4) if safe else 0.0,
        "pair_discrimination": round(discriminated / len(complete_pairs), 4)
        if complete_pairs
        else 0.0,
        "cost_usd": round(sum(records[i].get("cost_microusd", 0) for i in ids) / 1e6, 4),
        "cost_rub": round(sum(records[i].get("cost_microrub", 0) for i in ids) / 1e6, 2),
    }


def _bootstrap_recall_difference(
    rows: dict[str, dict[str, str]],
    left: dict[str, Record],
    right: dict[str, Record],
    scope: Sequence[str],
    *,
    iterations: int = 5000,
    seed: int = 20261001,
) -> tuple[float, float, float]:
    pairs = sorted(
        {rows[case_id]["pair"] for case_id in scope if case_id in left and case_id in right}
    )
    vulnerable = {
        rows[case_id]["pair"]: case_id
        for case_id in scope
        if rows[case_id]["label"] == "vulnerable" and case_id in left and case_id in right
    }
    pairs = [pair for pair in pairs if pair in vulnerable]
    if not pairs:
        return 0.0, 0.0, 0.0

    def difference(sample: Sequence[str]) -> float:
        hits_left = sum(bool(left[vulnerable[pair]]["predicted"]) for pair in sample)
        hits_right = sum(bool(right[vulnerable[pair]]["predicted"]) for pair in sample)
        return (hits_left - hits_right) / len(sample)

    generator = random.Random(seed)
    samples = sorted(
        difference([generator.choice(pairs) for _ in pairs]) for _ in range(iterations)
    )
    return (
        round(difference(pairs), 4),
        round(samples[int(0.025 * iterations)], 4),
        round(samples[int(0.975 * iterations) - 1], 4),
    )


def _union(*sources: dict[str, Record]) -> dict[str, Record]:
    shared = set.intersection(*(set(source) for source in sources))
    return {
        case_id: {
            "predicted": any(bool(source[case_id]["predicted"]) for source in sources),
            "status": "completed"
            if all(source[case_id]["status"] == "completed" for source in sources)
            else "failed",
            "cost_microusd": sum(source[case_id].get("cost_microusd", 0) for source in sources),
        }
        for case_id in shared
    }


def aggregate(manifest: Path, predictions: Path, output: Path, pipeline: Path | None) -> Record:
    rows = _manifest_rows(manifest)
    configurations: dict[str, dict[str, Record]] = {}
    for tool in TOOLS:
        path = predictions / f"{tool}.jsonl"
        if path.is_file():
            configurations[tool] = _load_predictions(path)
    for model in ("deepseek", "luna"):
        if "securecode" in configurations and model in configurations:
            configurations[f"securecode+{model}"] = _union(
                configurations["securecode"], configurations[model]
            )
    if "securecode" in configurations and "semgrep" in configurations:
        configurations["securecode+semgrep"] = _union(
            configurations["securecode"], configurations["semgrep"]
        )
    if pipeline is not None and pipeline.is_file():
        configurations["pipeline"] = _pipeline(pipeline)
    scopes: dict[str, list[str]] = {"all": sorted(rows)}
    scopes["held-out"] = [
        case_id for case_id in scopes["all"] if rows[case_id]["split"] == "held-out"
    ]
    for language in LANGUAGE_NAMES:
        scopes[language] = [
            case_id for case_id in scopes["all"] if rows[case_id]["language"] == language
        ]
    result: Record = {"cases": len(rows), "configurations": {}}
    for name, records in configurations.items():
        result["configurations"][name] = {
            scope: _metrics(rows, records, ids) for scope, ids in scopes.items()
        }
    if "semgrep" in configurations:
        comparisons: Record = {}
        for name in configurations:
            if name == "semgrep":
                continue
            comparisons[name] = {
                scope: _bootstrap_recall_difference(
                    rows, configurations[name], configurations["semgrep"], scopes[scope]
                )
                for scope in ("all", "held-out")
            }
        result["recall_difference_vs_semgrep"] = comparisons
    output.mkdir(parents=True, exist_ok=True)
    (output / "results.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


# --------------------------------------------------------------------------- CLI


def _environment_from_dotenv() -> None:
    dotenv = Path.cwd() / ".env"
    if dotenv.is_file():
        for line in dotenv.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.strip().partition("=")
            if separator and key.startswith("DEEPSEEK_"):
                os.environ.setdefault(key, value.strip().strip("'\""))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    cache = commands.add_parser("cache")
    cache.add_argument("--manifest", required=True, type=Path)
    cache.add_argument("--database", required=True, type=Path)
    cache.add_argument("--output", required=True, type=Path)
    run = commands.add_parser("run")
    run.add_argument("--tool", required=True, choices=TOOLS)
    run.add_argument("--manifest", required=True, type=Path)
    run.add_argument("--database", required=True, type=Path)
    run.add_argument("--output", required=True, type=Path)
    run.add_argument("--semgrep-config", type=Path)
    run.add_argument("--split", choices=("development", "calibration", "held-out"))
    summary = commands.add_parser("aggregate")
    summary.add_argument("--manifest", required=True, type=Path)
    summary.add_argument("--predictions", required=True, type=Path)
    summary.add_argument("--output", required=True, type=Path)
    summary.add_argument("--pipeline", type=Path)
    arguments = parser.parse_args(argv)
    if arguments.command == "cache":
        count = build_cache(arguments.manifest, arguments.database, arguments.output)
        print(f"cached {count} file changes")
        return 0
    if arguments.command == "run":
        if arguments.tool in {"semgrep", "bandit"} and shutil.which(arguments.tool) is None:
            raise SystemExit(f"{arguments.tool} is not installed")
        _environment_from_dotenv()
        from scripts.llm_providers import load_dotenv

        load_dotenv()
        cases: Sequence[Case] = _load_cases(arguments.manifest, None)
        if arguments.split is not None:
            rows = _manifest_rows(arguments.manifest)
            cases = [case for case in cases if rows[case.case_id]["split"] == arguments.split]
        connection = sqlite3.connect(arguments.database)
        written = run_tool(
            arguments.tool,
            cases,
            connection,
            arguments.output,
            semgrep_config=arguments.semgrep_config,
        )
        print(f"{arguments.tool}: {written} new records")
        return 0
    result = aggregate(
        arguments.manifest, arguments.predictions, arguments.output, arguments.pipeline
    )
    print(
        json.dumps(
            {name: value["all"] for name, value in result["configurations"].items()}, indent=2
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
