"""Run the frozen CVEfixes corpus through the full product pipeline.

Every case is committed alone into a temporary git repository and analysed with
``securecode analyze`` semantics: scanners, model-native Discovery, Auditor,
Skeptic and the finding gate.  A case counts as flagged when the final report
has at least one finding.  Results are appended to a JSONL file, so an
interrupted run resumes where it stopped.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import tempfile
import time
from collections.abc import Sequence
from concurrent.futures import Future, ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from securecode_ai.adapters.local_product_trial import TrialAnalysisError, run_trial_analysis
from securecode_ai.core.reports import ReportFormat

from scripts.run_release_benchmark import LANGUAGE_EXTENSIONS, Case, _load_cases, _source

_GIT_IDENTITY = ("-c", "user.name=SecureCode Benchmark", "-c", "user.email=benchmark@invalid")


def _environment() -> dict[str, str]:
    values = dict(os.environ)
    dotenv = Path.cwd() / ".env"
    if dotenv.is_file():
        for line in dotenv.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.strip().partition("=")
            if separator and key.startswith("DEEPSEEK_"):
                values.setdefault(key, value.strip().strip("'\""))
    return values


def analyse_case(case: Case, source: str, max_cost_microusd: int) -> dict[str, Any]:
    """Analyse one case in its own repository; never raises."""

    started = time.monotonic()
    record: dict[str, Any] = {
        "case_id": case.case_id,
        "cwe": case.cwe_id,
        "expected_label": case.expected_label,
        "language": case.language,
    }
    with tempfile.TemporaryDirectory(prefix="securecode-bench-") as directory:
        root = Path(directory)
        (root / ("case" + LANGUAGE_EXTENSIONS[case.language])).write_text(
            source, encoding="utf-8", newline=""
        )
        for command in (
            ("init", "-q"),
            ("add", "--all"),
            (*_GIT_IDENTITY, "commit", "-qm", "case"),
        ):
            subprocess.run(["git", "-C", directory, *command], check=True, capture_output=True)
        try:
            analysis = run_trial_analysis(
                directory,
                provider="deepseek",
                report_format=ReportFormat.JSON,
                environment=_environment(),
                max_cost_microusd=max_cost_microusd,
            )
        except TrialAnalysisError as error:
            record.update(status="error", error=str(error))
        except Exception as error:  # one broken case must not stop the corpus
            record.update(status="error", error=type(error).__name__ + ": " + str(error)[:200])
        else:
            results = json.loads(analysis.result.sarif_rendered)["runs"][0].get("results", [])
            report = json.loads(analysis.result.rendered)
            record["failed_units"] = sorted(
                ":".join(
                    str(unit.get(key))
                    for key in ("stage_id", "coverage_status", "model_call_status", "reason_code")
                )
                for unit in report.get("coverage_manifest", {}).get("units", [])
                if unit.get("coverage_status") != "COMPLETED" and unit.get("required")
            )
            record.update(
                health=report.get("analysis_health"),
                status={0: "pass", 2: "fail"}.get(analysis.result.exit_code, "indeterminate"),
                exit_code=int(analysis.result.exit_code),
                flagged=bool(results),
                findings=sorted({str(item.get("ruleId")) for item in results}),
                cost_microusd=analysis.cost_microusd,
                tokens=analysis.result.model_tokens,
            )
    record["latency_ms"] = int((time.monotonic() - started) * 1000)
    return record


def _metrics(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Score every case; errors and degraded runs count as not flagged.

    ``confirmed`` flags a case only for a confirmed finding (exit 2).
    ``needs_review`` also flags a healthy run that left a candidate unresolved
    (exit 3): the product fails closed and asks a human to look.
    """

    def flagged(item: dict[str, Any], mode: str) -> bool:
        if item.get("status") == "fail":
            return True
        return (
            mode == "needs_review"
            and item.get("status") == "indeterminate"
            and item.get("health") == "HEALTHY"
        )

    vulnerable = [item for item in records if item["expected_label"] == "vulnerable"]
    safe = [item for item in records if item["expected_label"] != "vulnerable"]
    result: dict[str, Any] = {
        "cases": len(records),
        "errors": sum(item.get("status") == "error" for item in records),
        "degraded": sum(
            item.get("status") == "indeterminate" and item.get("health") != "HEALTHY"
            for item in records
        ),
        "cost_usd": round(sum(item.get("cost_microusd", 0) for item in records) / 1e6, 4),
    }
    for mode in ("confirmed", "needs_review"):
        tp = sum(flagged(item, mode) for item in vulnerable)
        fp = sum(flagged(item, mode) for item in safe)
        result[mode] = {
            "tp": tp,
            "fp": fp,
            "recall": round(tp / len(vulnerable), 4) if vulnerable else None,
            "false_positive_rate": round(fp / len(safe), 4) if safe else None,
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        }
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="JSONL results (appended)")
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--split", choices=("development", "calibration", "held-out"))
    parser.add_argument(
        "--stop-at-usd", type=float, default=5.0, help="stop submitting new cases past this spend"
    )
    parser.add_argument("--max-cost-usd-per-case", type=float, default=1.0)
    arguments = parser.parse_args(argv)

    cases = _load_cases(arguments.manifest, None)
    splits = {
        raw["case_id"]: raw.get("split")
        for raw in json.loads(arguments.manifest.read_text(encoding="utf-8"))["datasets"][0][
            "cases"
        ]
    }
    if arguments.split is not None:
        cases = tuple(case for case in cases if splits[case.case_id] == arguments.split)
    if arguments.limit is not None:
        cases = cases[: arguments.limit]
    done: dict[str, dict[str, Any]] = {}
    if arguments.output.is_file():
        for line in arguments.output.read_text(encoding="utf-8").splitlines():
            if line.strip():
                item = json.loads(line)
                if item.get("status") != "error":
                    done[item["case_id"]] = item
    pending = [case for case in cases if case.case_id not in done]
    connection = sqlite3.connect(f"file:{arguments.database}?mode=ro", uri=True)
    budget = max(1, int(arguments.max_cost_usd_per_case * 1_000_000))
    print(f"cases={len(cases)} done={len(done)} pending={len(pending)}", flush=True)
    spent = sum(item.get("cost_microusd", 0) for item in done.values())
    stop_at = int(arguments.stop_at_usd * 1_000_000)
    with (
        ProcessPoolExecutor(max_workers=arguments.workers) as pool,
        arguments.output.open("a", encoding="utf-8") as sink,
    ):
        queue = list(pending)
        running: dict[Future[dict[str, Any]], Case] = {}
        index = 0
        while queue or running:
            while queue and len(running) < arguments.workers and spent < stop_at:
                case = queue.pop(0)
                running[pool.submit(analyse_case, case, _source(connection, case), budget)] = case
            if not running:
                print(
                    f"spend limit reached at ${spent / 1e6:.2f}; {len(queue)} cases left",
                    flush=True,
                )
                break
            finished = next(as_completed(running))
            running.pop(finished)
            record = finished.result()
            index += 1
            spent += record.get("cost_microusd", 0)
            done[record["case_id"]] = record
            sink.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
            sink.flush()
            print(
                f"[{index}/{len(pending)}] ${spent / 1e6:.2f} {record['case_id']} {record['status']} "
                f"{record.get('health')} {record.get('findings', record.get('error'))}",
                flush=True,
            )
    records = [done[case.case_id] for case in cases if case.case_id in done]
    held_out = {case_id for case_id, split in splits.items() if split == "held-out"}
    summary = {
        "method": "full product pipeline per case (scanners, Discovery, Auditor, Skeptic, gate)",
        "all": _metrics(records),
        "held-out": _metrics([item for item in records if item["case_id"] in held_out]),
        "by_language": {
            language: _metrics([item for item in records if item["language"] == language])
            for language in sorted({item["language"] for item in records})
        },
    }
    rendered = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True)
    if arguments.summary is not None:
        arguments.summary.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
