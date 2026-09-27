"""Validate and summarize the source-free submission benchmark evidence."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import random
import sqlite3
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from typing import Any

ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "evidence"
PROJECT = ROOT.parents[1]
MANIFEST = EVIDENCE / "cvefixes-manifest.json"
ITERATIONS = 5000
SEED = 20260927
LANGUAGES = {"python": "python", "javascript-typescript": "js-ts", "go": "go"}
LANES = {
    "deterministic_only": ("deterministic-600x1.json", 1),
    "scanner_seeded": ("deepseek-scanner-seeded-600x1.json", 1),
    "model_native": ("deepseek-model-native-600x3.json", 3),
    "one_shot": ("deepseek-one-shot-600x3.json", 3),
    "full_hybrid": ("deepseek-full-hybrid-600x3.json", 3),
    "semgrep": ("semgrep-600x3.json", 3),
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ratio(numerator: int | float, denominator: int | float) -> float | None:
    return numerator / denominator if denominator else None


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return ordered[index]


def _truth(cell: dict[str, Any]) -> str:
    flags = [cell.get(key) for key in ("tp", "fp", "tn", "fn")]
    if any(type(value) is not int or value not in (0, 1) for value in flags):
        raise ValueError("confusion flags must be binary integers")
    if sum(flags) != 1:
        raise ValueError("each benchmark cell must have exactly one confusion flag")
    if cell["tp"] or cell["fn"]:
        return "vulnerable"
    return "fixed-safe"


def _confusion(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {key: sum(row["cell"][key] for row in rows) for key in ("tp", "fp", "tn", "fn")}


def _metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = _confusion(rows)
    precision = _ratio(counts["tp"], counts["tp"] + counts["fp"])
    recall = _ratio(counts["tp"], counts["tp"] + counts["fn"])
    f1 = (
        _ratio(2 * precision * recall, precision + recall)
        if precision is not None and recall is not None
        else None
    )
    status_counts = Counter(row["cell"].get("status", "missing") for row in rows)
    kloc = sum(float(row["cell"].get("kloc", 0)) for row in rows)
    latency_rows = [row["cell"] for row in rows if int(row["cell"].get("cost_microunits", 0)) > 0]
    if not latency_rows:
        latency_rows = [row["cell"] for row in rows if int(row["cell"].get("latency_ms", 0)) > 0]
    latencies = [float(row.get("latency_ms", 0)) for row in latency_rows]
    case_count = len({row["case_id"] for row in rows})
    completed_cases = len(
        {row["case_id"] for row in rows if row["cell"].get("status") == "completed"}
    )
    return {
        "cases": case_count,
        "cells": len(rows),
        "completed_cells": status_counts.get("completed", 0),
        "failed_cells": len(rows) - status_counts.get("completed", 0),
        "completion_rate": _ratio(status_counts.get("completed", 0), len(rows)),
        "completed_cases": completed_cases,
        "status_counts": dict(sorted(status_counts.items())),
        **counts,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positives_per_kloc": _ratio(counts["fp"], kloc),
        "kloc_denominator": kloc,
        "localized_vulnerable_cells": sum(row["cell"].get("localized", 0) for row in rows),
        "vulnerable_cells": counts["tp"] + counts["fn"],
        "localization_rate": _ratio(
            sum(row["cell"].get("localized", 0) for row in rows),
            counts["tp"] + counts["fn"],
        ),
        "latency_call_count": len(latencies),
        "latency_p50_ms": median(latencies) if latencies else None,
        "latency_p95_ms": _percentile(latencies, 0.95),
        "tokens": sum(int(row["cell"].get("tokens", 0)) for row in rows),
        "cell_cost_usd": sum(int(row["cell"].get("cost_microunits", 0)) for row in rows)
        / 1_000_000,
        "unsafe_patch_observations": sum(int(row["cell"].get("unsafe_patches", 0)) for row in rows),
        "regression_observations": sum(int(row["cell"].get("regressions", 0)) for row in rows),
        "ram_measurements_present": any(int(row["cell"].get("ram_mb", 0)) > 0 for row in rows),
        "vram_measurements_present": any(int(row["cell"].get("vram_mb", 0)) > 0 for row in rows),
    }


def _bootstrap(
    rows: list[dict[str, Any]], iterations: int, seed: int
) -> dict[str, list[float] | None]:
    by_lineage: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_lineage[row["lineage"]].append(row)
    groups = [_confusion(by_lineage[lineage]) for lineage in sorted(by_lineage)]
    if not groups:
        return {"precision": None, "recall": None, "f1": None}
    rng = random.Random(seed)
    samples: dict[str, list[float]] = {"precision": [], "recall": [], "f1": []}
    for _ in range(iterations):
        totals = dict.fromkeys(("tp", "fp", "tn", "fn"), 0)
        for _ in groups:
            selected = groups[rng.randrange(len(groups))]
            for key in totals:
                totals[key] += selected[key]
        precision = _ratio(totals["tp"], totals["tp"] + totals["fp"])
        recall = _ratio(totals["tp"], totals["tp"] + totals["fn"])
        f1 = (
            _ratio(2 * precision * recall, precision + recall)
            if precision is not None and recall is not None
            else None
        )
        for key, value in (("precision", precision), ("recall", recall), ("f1", f1)):
            if value is not None:
                samples[key].append(value)
    return {
        key: [float(_percentile(values, 0.025)), float(_percentile(values, 0.975))]
        if values
        else None
        for key, values in samples.items()
    }


def _paired_recall_bootstrap(
    left: list[dict[str, Any]], right: list[dict[str, Any]], iterations: int, seed: int
) -> dict[str, Any]:
    def group(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        values: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            if row["expected_label"] == "vulnerable":
                values[row["lineage"]].append(row)
        return values

    left_groups, right_groups = group(left), group(right)
    keys = sorted(left_groups)
    if not keys or keys != sorted(right_groups):
        raise ValueError("paired recall lanes do not contain matching vulnerable lineages")
    for key in keys:
        if not left_groups[key] or not right_groups[key]:
            raise ValueError("paired recall lineage is missing predictions")

    def recall(rows: list[dict[str, Any]]) -> float:
        c = _confusion(rows)
        return float(_ratio(c["tp"], c["tp"] + c["fn"]) or 0.0)

    observed = recall(left) - recall(right)
    rng = random.Random(seed)
    deltas: list[float] = []
    for _ in range(iterations):
        draw_left: list[dict[str, Any]] = []
        draw_right: list[dict[str, Any]] = []
        for _ in keys:
            key = rng.choice(keys)
            draw_left.extend(left_groups[key])
            draw_right.extend(right_groups[key])
        deltas.append(recall(draw_left) - recall(draw_right))
    return {
        "comparison": "full_hybrid minus semgrep recall",
        "paired_lineage_groups": len(keys),
        "observed_difference": observed,
        "cluster_bootstrap_95_percentile_interval": [
            _percentile(deltas, 0.025),
            _percentile(deltas, 0.975),
        ],
        "bootstrap_iterations": iterations,
        "seed": seed,
    }


def _spend_ledgers() -> dict[str, Any]:
    records: dict[str, Any] = {}
    final_totals = {
        "attempts": 0,
        "settled_attempts": 0,
        "settled_usd": 0,
        "pending_attempts": 0,
        "pending_usd": 0,
    }
    for path in sorted(EVIDENCE.glob("deepseek-*-spend*.sqlite")):
        with sqlite3.connect(path) as connection:
            row = connection.execute(
                "SELECT COUNT(*), "
                "SUM(CASE WHEN settled = 1 THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN settled = 1 THEN charged ELSE 0 END), "
                "SUM(CASE WHEN settled = 0 THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN settled = 0 THEN reserved ELSE 0 END) "
                "FROM attempts"
            ).fetchone()
        attempts, settled_count, charged, pending_count, reserved = (
            int(value or 0) for value in row
        )
        record = {
            "attempts": attempts,
            "settled_attempts": settled_count,
            "settled_charged_usd": charged / 1_000_000,
            "pending_attempts": pending_count,
            "pending_reserved_usd": reserved / 1_000_000,
            "sha256": _sha256(path.read_bytes()),
            "scope": "development" if "development" in path.name else "final",
        }
        records[path.name] = record
        if record["scope"] == "final":
            final_totals["attempts"] += attempts
            final_totals["settled_attempts"] += settled_count
            final_totals["settled_usd"] += charged
            final_totals["pending_attempts"] += pending_count
            final_totals["pending_usd"] += reserved
    return {
        "ledgers": records,
        "final_scope": {
            "attempts": final_totals["attempts"],
            "settled_attempts": final_totals["settled_attempts"],
            "settled_charged_usd": final_totals["settled_usd"] / 1_000_000,
            "pending_attempts": final_totals["pending_attempts"],
            "pending_reserved_usd": final_totals["pending_usd"] / 1_000_000,
            "settled_plus_pending_exposure_usd": (
                final_totals["settled_usd"] + final_totals["pending_usd"]
            )
            / 1_000_000,
            "development_scope_is_separate": True,
        },
    }


def _verify_candidate_source_manifest() -> tuple[int, str]:
    path = EVIDENCE / "candidate-source-manifest.json"
    raw = path.read_bytes()
    entries = json.loads(raw)
    if not isinstance(entries, list) or len(entries) != 603:
        raise ValueError("candidate source manifest must contain 603 files")
    root = PROJECT.resolve()
    observed: set[str] = set()
    for entry in entries:
        relative = entry.get("path")
        if not isinstance(relative, str) or not relative or ".." in Path(relative).parts:
            raise ValueError("candidate source manifest contains an unsafe path")
        source = (PROJECT / relative).resolve()
        if not source.is_relative_to(root) or relative in observed:
            raise ValueError("candidate source manifest contains a duplicate or escaped path")
        observed.add(relative)
        try:
            content = source.read_bytes()
        except OSError as error:
            raise ValueError("a candidate source file is missing") from error
        if len(content) != entry.get("bytes") or _sha256(content) != entry.get("sha256"):
            raise ValueError("a candidate source file does not match its recorded hash")
    return len(entries), _sha256(raw)


def _load() -> tuple[
    dict[str, Any], dict[str, list[dict[str, Any]]], dict[str, Any], dict[str, int]
]:
    manifest_bytes = MANIFEST.read_bytes()
    manifest = json.loads(manifest_bytes)
    cases = sorted(manifest["datasets"][0]["cases"], key=lambda item: item["case_id"])
    if len(cases) != 600:
        raise ValueError("pinned source-free manifest must have exactly 600 cases")
    key_to_case: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for case in cases:
        key = (
            LANGUAGES[case["language"]],
            case["cwe_id"],
            hashlib.sha256(case["lineage_groups"][0].encode("utf-8")).hexdigest(),
            case["expected_label"],
        )
        if key in key_to_case:
            raise ValueError("manifest does not uniquely identify case by lane identity and label")
        key_to_case[key] = case

    outputs: dict[str, list[dict[str, Any]]] = {}
    hashes: dict[str, str] = {"cvefixes-manifest.json": _sha256(manifest_bytes)}
    raw_cell_counts: dict[str, int] = {}
    for lane, (filename, expected_repetitions) in LANES.items():
        path = EVIDENCE / filename
        raw = path.read_bytes()
        result = json.loads(raw)
        cells = result.get("cells")
        if not isinstance(cells, list) or len(cells) != 600 * expected_repetitions:
            raise ValueError(f"{lane} must have 600 cases x {expected_repetitions} repetitions")
        if any(cell.get("configuration") != lane for cell in cells):
            raise ValueError(f"{lane} output contains a mismatched configuration")
        seen: Counter[tuple[str, str, str, int]] = Counter()
        rows: list[dict[str, Any]] = []
        for cell in cells:
            truth = _truth(cell)
            key = (cell.get("language"), cell.get("cwe"), cell.get("lineage"), truth)
            case = key_to_case.get(key)
            if case is None:
                raise ValueError(f"{lane} contains a row not present in the frozen manifest")
            repetition = cell.get("repetition")
            if type(repetition) is not int or repetition not in range(1, expected_repetitions + 1):
                raise ValueError(f"{lane} has an invalid repetition number")
            if cell["status"] == "completed" and _truth(cell) != case["expected_label"]:
                raise ValueError(f"{lane} prediction is not bound to the manifest label")
            identity = (case["case_id"], lane, cell["lineage"], repetition)
            seen[(case["case_id"], cell["lineage"], truth, repetition)] += 1
            rows.append(
                {
                    "case_id": case["case_id"],
                    "expected_label": case["expected_label"],
                    "language": case["language"],
                    "split": case["split"],
                    "cwe": case["cwe_id"],
                    "lineage": cell["lineage"],
                    "cell": cell,
                    "identity": identity,
                }
            )
        expected_keys = {
            (
                case["case_id"],
                hashlib.sha256(case["lineage_groups"][0].encode("utf-8")).hexdigest(),
                case["expected_label"],
                rep,
            )
            for case in cases
            for rep in range(1, expected_repetitions + 1)
        }
        if set(seen) != expected_keys or any(count != 1 for count in seen.values()):
            raise ValueError(f"{lane} has missing or duplicate case/repetition rows")
        raw_cell_counts[lane] = len(rows)
        if lane == "semgrep":
            by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for row in rows:
                by_case[row["case_id"]].append(row)
            for case_rows in by_case.values():
                reference = case_rows[0]["cell"]
                reference_result = (
                    reference["tp"],
                    reference["fp"],
                    reference["tn"],
                    reference["fn"],
                    reference["status"],
                )
                if any(
                    (
                        row["cell"]["tp"],
                        row["cell"]["fp"],
                        row["cell"]["tn"],
                        row["cell"]["fn"],
                        row["cell"]["status"],
                    )
                    != reference_result
                    for row in case_rows[1:]
                ):
                    raise ValueError("Semgrep repetitions are not identical for one or more cases")
            rows = [row for row in rows if row["cell"]["repetition"] == 1]
        outputs[lane] = rows
        hashes[filename] = _sha256(raw)
    return manifest, outputs, hashes, raw_cell_counts


def main() -> None:
    manifest, outputs, input_hashes, raw_cell_counts = _load()
    summaries: dict[str, Any] = {}
    for lane, rows in outputs.items():
        summaries[lane] = {
            **_metrics(rows),
            "raw_output_cells": raw_cell_counts[lane],
            "scored_repetitions": 1 if lane == "semgrep" else LANES[lane][1],
            "cluster_bootstrap_95_percentile_intervals": _bootstrap(rows, ITERATIONS, SEED),
            "output_file": LANES[lane][0],
            "output_sha256": input_hashes[LANES[lane][0]],
            "provenance": "fresh"
            if lane == "deterministic_only"
            else "paired-derived"
            if lane in {"scanner_seeded", "full_hybrid"}
            else "reused-archived"
            if lane in {"model_native", "one_shot", "semgrep"}
            else "unknown",
        }

    strata: list[dict[str, Any]] = []
    for lane, rows in outputs.items():
        dimensions = {
            "language": lambda row: LANGUAGES[row["language"]],
            "split": lambda row: row["split"],
            "language_split": lambda row: f"{LANGUAGES[row['language']]}:{row['split']}",
            "cwe": lambda row: row["cwe"],
        }
        for dimension, getter in dimensions.items():
            groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for row in rows:
                groups[getter(row)].append(row)
            for key, subset in sorted(groups.items()):
                strata.append(
                    {"lane": lane, "dimension": dimension, "group": key, **_metrics(subset)}
                )

    paired = {
        split: _paired_recall_bootstrap(
            [row for row in outputs["full_hybrid"] if split == "all" or row["split"] == split],
            [row for row in outputs["semgrep"] if split == "all" or row["split"] == split],
            ITERATIONS,
            SEED,
        )
        for split in ("all", "held-out")
    }
    ledgers = _spend_ledgers()
    source_file_count, candidate_hash = _verify_candidate_source_manifest()
    aggregate = {
        "schema_version": "securecode.submission-benchmark-aggregate.v1",
        "created_at_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "candidate_source_manifest_sha256": candidate_hash,
        "candidate_source_files": source_file_count,
        "dataset": {
            "manifest_sha256": input_hashes["cvefixes-manifest.json"],
            "content_sha256": manifest["datasets"][0]["content_sha256"],
            "cases": 600,
            "license_spdx": manifest["datasets"][0].get("license_spdx", "NOASSERTION"),
            "languages": {
                lang: sum(case["language"] == lang for case in manifest["datasets"][0]["cases"])
                for lang in sorted({case["language"] for case in manifest["datasets"][0]["cases"]})
            },
            "splits": dict(
                sorted(Counter(case["split"] for case in manifest["datasets"][0]["cases"]).items())
            ),
            "lineage_groups": len(
                {case["lineage_groups"][0] for case in manifest["datasets"][0]["cases"]}
            ),
        },
        "input_sha256": dict(sorted(input_hashes.items())),
        "bootstrap": {
            "method": "paired resampling of lineage groups, retaining vulnerable/fixed pair and all repetitions",
            "iterations": ITERATIONS,
            "seed": SEED,
        },
        "paired_comparison": paired,
        "spend": ledgers,
        "lanes": summaries,
        "limitations": [
            "The 600-case public corpus manifest is marked NOASSERTION for licensing; no source blobs are included.",
            "Archived model-native and one-shot results are raw direct model classifications, not the complete SecureCode verdict pipeline.",
            "Semgrep output is scored using any-finding-in-file and is not CWE-aligned.",
            "The deterministic scanner failed on 253 of 600 cases; full-hybrid rows retain those failures in the completion denominator.",
            "scanner_seeded and full_hybrid are paired post-hoc compositions that reused existing predictions and made zero new model requests.",
            "No full repair study was performed; zero patch counters are not evidence of repair safety.",
            "RAM and VRAM were not measured. The reported model latency is API-call latency, not end-to-end scan latency.",
            "The archived direct model outputs predate the current benchmark-runner exception-accounting fix; their own candidate and profile pins are retained separately.",
        ],
    }

    csv_path = ROOT / "stratified-metrics.csv"
    fieldnames = [
        "lane",
        "dimension",
        "group",
        "cases",
        "cells",
        "completed_cells",
        "failed_cells",
        "completion_rate",
        "tp",
        "fp",
        "tn",
        "fn",
        "precision",
        "recall",
        "f1",
        "false_positives_per_kloc",
        "kloc_denominator",
        "localized_vulnerable_cells",
        "vulnerable_cells",
        "localization_rate",
        "latency_call_count",
        "latency_p50_ms",
        "latency_p95_ms",
        "tokens",
        "cell_cost_usd",
        "unsafe_patch_observations",
        "regression_observations",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(strata)

    json_path = ROOT / "aggregate.json"
    json_path.write_text(
        json.dumps(aggregate, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    output_files = {filename: EVIDENCE / filename for filename, _ in LANES.values()}
    output_files.update(
        {
            "lane-composition.json": ROOT / "lane-composition.json",
            "deterministic-shards.json": EVIDENCE / "deterministic-shards.json",
            "aggregate.json": json_path,
            "stratified-metrics.csv": csv_path,
            "README.md": ROOT / "README.md",
            "report.html": ROOT / "report.html",
            "style.html": ROOT / "style.html",
            "build_report_pdf.py": ROOT / "build_report_pdf.py",
            "project-README.md": PROJECT / "README.md",
        }
    )
    pdf_path = PROJECT / "output" / "pdf" / "securecode-ai-submission-benchmark.pdf"
    if pdf_path.is_file():
        output_files[pdf_path.name] = pdf_path
    plan_path = EVIDENCE / "run-plan.json"
    run_plan = json.loads(plan_path.read_text(encoding="utf-8"))
    run_plan["status"] = "ANALYSIS_COMPLETE_WITH_LIMITATIONS"
    run_plan["completed_at_utc"] = aggregate["created_at_utc"]
    run_plan["deterministic_output_sha256"] = input_hashes["deterministic-600x1.json"]
    run_plan["aggregate_output_sha256"] = _sha256(json_path.read_bytes())
    run_plan["stratified_metrics_sha256"] = _sha256(csv_path.read_bytes())
    run_plan["paired_comparison"] = paired
    run_plan["validated_candidate_source_files"] = source_file_count
    run_plan["validated_candidate_source_manifest_sha256"] = candidate_hash
    run_plan["outputs_sha256"] = {
        name: _sha256(path.read_bytes()) for name, path in sorted(output_files.items())
    }
    run_plan["analysis_boundary"] = (
        "All configured diagnostic outputs were validated against the frozen manifest. "
        "The model-native and one-shot outputs are archived direct classifications; "
        "scanner_seeded and full_hybrid are derived paired compositions, not live SecureCode pipeline runs."
    )
    plan_path.write_text(
        json.dumps(run_plan, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    outputs_hashes = {
        json_path.name: _sha256(json_path.read_bytes()),
        csv_path.name: _sha256(csv_path.read_bytes()),
        plan_path.name: _sha256(plan_path.read_bytes()),
        "README.md": _sha256((ROOT / "README.md").read_bytes()),
    }
    manifest_out = {
        "schema_version": "securecode.submission-benchmark-output-manifest.v1",
        "input_sha256": aggregate["input_sha256"],
        "analysis_script_sha256": _sha256(Path(__file__).read_bytes()),
        "outputs_sha256": outputs_hashes,
    }
    manifest_path = ROOT / "aggregate-output-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest_out, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        json.dumps(
            {
                "lanes": {
                    name: {
                        key: value[key]
                        for key in (
                            "cases",
                            "cells",
                            "completed_cells",
                            "failed_cells",
                            "completion_rate",
                            "tp",
                            "fp",
                            "tn",
                            "fn",
                            "precision",
                            "recall",
                            "f1",
                            "cell_cost_usd",
                        )
                    }
                    for name, value in summaries.items()
                },
                "paired_comparison": paired,
                "spend": ledgers["final_scope"],
                "output_sha256": outputs_hashes,
            },
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
