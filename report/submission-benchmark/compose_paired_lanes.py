"""Create paired, post-hoc benchmark ablations without additional API calls."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "evidence"
PROJECT = ROOT.parents[1]
MANIFEST = PROJECT / "evaluation/release-corpus/cvefixes-manifest.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _prediction(cell: dict[str, Any]) -> bool:
    flags = [cell.get(key) for key in ("tp", "fp", "tn", "fn")]
    if any(type(flag) is not int for flag in flags) or sum(flags) != 1:
        raise ValueError("benchmark cell confusion flags are invalid")
    return bool(cell["tp"] or cell["fp"])


def _validate_identity(cell: dict[str, Any], case: dict[str, Any], repetition: int) -> None:
    language = {"python": "python", "javascript-typescript": "js-ts", "go": "go"}[
        case["language"]
    ]
    lineage = hashlib.sha256(case["lineage_groups"][0].encode()).hexdigest()
    if (
        cell.get("language"),
        cell.get("cwe"),
        cell.get("lineage"),
        cell.get("repetition"),
    ) != (language, case["cwe_id"], lineage, repetition):
        raise ValueError("benchmark lane row identity is invalid")
    vulnerable = case["expected_label"] == "vulnerable"
    predicted = _prediction(cell)
    expected_flags = (
        int(predicted and vulnerable),
        int(predicted and not vulnerable),
        int(not predicted and not vulnerable),
        int(not predicted and vulnerable),
    )
    if tuple(cell[key] for key in ("tp", "fp", "tn", "fn")) != expected_flags:
        raise ValueError("benchmark lane label binding is invalid")


def _cell(
    base: dict[str, Any],
    case: dict[str, Any],
    configuration: str,
    repetition: int,
    predicted: bool,
    status: str,
    *,
    include_model_usage: bool,
) -> dict[str, Any]:
    vulnerable = case["expected_label"] == "vulnerable"
    result = {
        "configuration": configuration,
        "language": base["language"],
        "cwe": base["cwe"],
        "lineage": base["lineage"],
        "repetition": repetition,
        "status": status,
        "tp": int(predicted and vulnerable),
        "fp": int(predicted and not vulnerable),
        "tn": int(not predicted and not vulnerable),
        "fn": int(not predicted and vulnerable),
        "kloc": base["kloc"],
        "localized": base.get("localized", 0) if include_model_usage else 0,
        "latency_ms": base["latency_ms"] if include_model_usage else 0,
        "tokens": base["tokens"] if include_model_usage else 0,
        "cost_microunits": base["cost_microunits"] if include_model_usage else 0,
        "ram_mb": base.get("ram_mb", 0) if include_model_usage else 0,
        "vram_mb": base.get("vram_mb", 0) if include_model_usage else 0,
        "unsafe_patches": 0,
        "regressions": 0,
        "correct_secure": 0,
    }
    return result


def _compose() -> dict[str, Any]:
    cases = sorted(_read(MANIFEST)["datasets"][0]["cases"], key=lambda row: row["case_id"])
    deterministic_path = EVIDENCE / "deterministic-600x1.json"
    model_path = EVIDENCE / "deepseek-model-native-600x3.json"
    deterministic = _read(deterministic_path)["cells"]
    model_native = _read(model_path)["cells"]
    if len(cases) != 600 or len(deterministic) != 600 or len(model_native) != 1800:
        raise ValueError("paired benchmark lanes have unexpected row counts")

    scanner_seeded: list[dict[str, Any]] = []
    full_hybrid: list[dict[str, Any]] = []
    scanner_positive_count = 0
    scanner_failure_count = 0
    for index, case in enumerate(cases):
        scanner = deterministic[index]
        _validate_identity(scanner, case, 1)
        scanner_failed = scanner.get("status") != "completed"
        scanner_positive = _prediction(scanner) and not scanner_failed
        scanner_failure_count += int(scanner_failed)
        scanner_positive_count += int(scanner_positive)
        for repetition in range(1, 4):
            model = model_native[index * 3 + repetition - 1]
            _validate_identity(model, case, repetition)
            model_completed = model.get("status") == "completed"
            model_positive = _prediction(model) if model_completed else False

            if scanner_failed:
                seeded = _cell(
                    model,
                    case,
                    "scanner_seeded",
                    1,
                    False,
                    "scanner-failed",
                    include_model_usage=False,
                )
            elif not scanner_positive:
                seeded = _cell(
                    model,
                    case,
                    "scanner_seeded",
                    1,
                    False,
                    "completed",
                    include_model_usage=False,
                )
            elif not model_completed:
                seeded = _cell(
                    model,
                    case,
                    "scanner_seeded",
                    1,
                    False,
                    str(model["status"]),
                    include_model_usage=False,
                )
            else:
                seeded = _cell(
                    model,
                    case,
                    "scanner_seeded",
                    1,
                    model_positive,
                    "completed",
                    include_model_usage=repetition == 1,
                )
            if repetition == 1:
                scanner_seeded.append(seeded)

            if not model_completed:
                hybrid = _cell(
                    model,
                    case,
                    "full_hybrid",
                    repetition,
                    False,
                    str(model["status"]),
                    include_model_usage=True,
                )
            else:
                hybrid = _cell(
                    model,
                    case,
                    "full_hybrid",
                    repetition,
                    scanner_positive or model_positive,
                    "scanner-failed" if scanner_failed else "completed",
                    include_model_usage=True,
                )
            full_hybrid.append(hybrid)

    inputs = {
        deterministic_path.name: _sha256(deterministic_path),
        model_path.name: _sha256(model_path),
        "cvefixes-manifest.json": _sha256(MANIFEST),
    }
    artifacts = {
        "scanner_seeded": {
            "configuration": "scanner_seeded",
            "method": "post-hoc paired subset: reuse model-native repetition 1 only when the deterministic lane is positive",
            "new_remote_calls": 0,
            "reused_model_predictions": scanner_positive_count,
            "scanner_failed_cells": scanner_failure_count,
            "inputs_sha256": inputs,
            "cells": scanner_seeded,
        },
        "full_hybrid": {
            "configuration": "full_hybrid",
            "method": "post-hoc paired union of deterministic signals and the same-case model-native prediction for each repetition",
            "new_remote_calls": 0,
            "reused_model_predictions": len(full_hybrid),
            "scanner_failed_cells_per_repetition": scanner_failure_count,
            "inputs_sha256": inputs,
            "cells": full_hybrid,
        },
    }
    output_names = {
        "scanner_seeded": "deepseek-scanner-seeded-600x1.json",
        "full_hybrid": "deepseek-full-hybrid-600x3.json",
    }
    for name, value in artifacts.items():
        path = EVIDENCE / output_names[name]
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    return {
        "schema_version": "securecode.submission-benchmark-lane-composition.v1",
        "method": "paired post-hoc composition; no additional model request was made",
        "inputs_sha256": inputs,
        "scanner_seeded_new_remote_calls": 0,
        "scanner_seeded_reused_predictions": scanner_positive_count,
        "full_hybrid_new_remote_calls": 0,
        "full_hybrid_reused_predictions": len(full_hybrid),
        "scanner_failed_cases": scanner_failure_count,
        "output_sha256": {
            name: _sha256(EVIDENCE / filename)
            for name, filename in output_names.items()
        },
    }


if __name__ == "__main__":
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    result = _compose()
    record = ROOT / "lane-composition.json"
    record.write_text(
        json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
