"""Independently recompute P7.17 denominators from JSONL facts."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from math import ceil
from pathlib import Path
from typing import Any

CONFIGURATIONS = (
    "deterministic_only",
    "scanner_seeded_investigation",
    "model_native_only",
    "one_shot_llm",
    "full_hybrid",
)
RECORD_KEYS = {
    "schema_version",
    "study_id",
    "case_id",
    "configuration",
    "repetition",
    "expected_label",
    "state",
    "predicted_label",
    "confirmed_finding",
    "policy_matched",
    "returned_category",
    "returned_source_alias",
    "reason",
    "run_plan_sha256",
    "candidate_commit",
    "corpus_content_sha256",
    "component_sha256",
    "prompt_sha256",
    "policy_sha256",
    "schema_sha256",
    "model_name",
    "model_digest",
    "runtime_name",
    "runtime_version",
    "quantization",
    "temperature",
    "seed",
    "budget_tokens",
    "budget_calls",
    "budget_wall_seconds",
    "budget_retries",
    "wall_seconds",
    "prompt_tokens",
    "generated_tokens",
    "scanner_signal_count",
    "provider_cost",
}


def _load(path: Path) -> dict[str, Any]:
    value = _strict_json(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("object required")
    return value


def _strict_json(payload: str) -> object:
    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    return json.loads(payload, object_pairs_hook=pairs_hook)


def _validate_record_shape(record: object) -> dict[str, Any]:
    if type(record) is not dict or set(record) != RECORD_KEYS:
        raise ValueError("record schema drift or raw-source echo")
    return record


def _validate_record_values(record: dict[str, Any], plan: dict[str, Any]) -> None:
    if (
        record["schema_version"] != "development-benchmark-record-1.0"
        or record["study_id"] != plan["study_id"]
        or type(record["case_id"]) is not str
        or not record["case_id"]
        or record["configuration"] not in CONFIGURATIONS
        or type(record["repetition"]) is not int
        or not 1 <= record["repetition"] <= plan["repetitions"][record["configuration"]]
        or record["expected_label"] not in ("vulnerable", "safe")
        or record["state"] not in ("executed", "not_run", "failed")
    ):
        raise ValueError("record value schema drift")
    for name in (
        "budget_tokens",
        "budget_calls",
        "budget_wall_seconds",
        "budget_retries",
    ):
        if type(record[name]) is not int or record[name] < 0:
            raise ValueError("negative or invalid budget fact")
    for name in ("wall_seconds", "provider_cost"):
        if record[name] is not None and (type(record[name]) is not float or record[name] < 0):
            raise ValueError("negative or invalid resource fact")
    token_values = (record["prompt_tokens"], record["generated_tokens"])
    if (token_values[0] is None) != (token_values[1] is None) or any(
        value is not None and (type(value) is not int or value < 0) for value in token_values
    ):
        raise ValueError("invalid paired token facts")
    if record["state"] == "executed":
        if (
            record["predicted_label"] not in ("vulnerable", "safe")
            or type(record["confirmed_finding"]) is not bool
            or type(record["policy_matched"]) is not bool
            or (record["policy_matched"] and not record["confirmed_finding"])
            or record["reason"] is not None
        ):
            raise ValueError("contradictory executed verdict")
        if record["confirmed_finding"]:
            if (
                record["predicted_label"] != "vulnerable"
                or type(record["returned_category"]) is not str
                or type(record["returned_source_alias"]) is not str
            ):
                raise ValueError("invalid confirmed finding")
        elif (
            record["predicted_label"] != "safe"
            or record["policy_matched"]
            or record["returned_category"] is not None
            or record["returned_source_alias"] is not None
        ):
            raise ValueError("invalid no-finding verdict")
    elif (
        record["predicted_label"] is not None
        or record["confirmed_finding"] is not None
        or record["policy_matched"] is not None
        or record["returned_category"] is not None
        or record["returned_source_alias"] is not None
        or type(record["reason"]) is not str
        or not record["reason"]
    ):
        raise ValueError("invalid non-success verdict")


def _ratio(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator


def _f(precision: float | None, recall: float | None, beta2: int) -> float | None:
    if precision is None or recall is None or precision + recall == 0:
        return None
    return (1 + beta2) * precision * recall / (beta2 * precision + recall)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    plan = _load(args.plan)
    root = Path(__file__).resolve().parents[1]
    expected_bindings = {
        "component_sha256": f"sha256:{hashlib.sha256((root / 'scripts/run_development_benchmark.py').read_bytes()).hexdigest()}",
        "core_sha256": f"sha256:{hashlib.sha256((root / 'packages/core/src/securecode_ai/core/development_benchmark.py').read_bytes()).hexdigest()}",
        "recompute_sha256": f"sha256:{hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}",
        "corpus_validator_sha256": f"sha256:{hashlib.sha256((root / 'scripts/development_corpus.py').read_bytes()).hexdigest()}",
        "prompt_sha256": plan["bindings"]["prompt_sha256"],
        "policy_sha256": plan["bindings"]["policy_sha256"],
        "schema_sha256": plan["bindings"]["schema_sha256"],
    }
    if plan["bindings"] != expected_bindings:
        raise ValueError("component binding drift")
    expected_environment = {
        "host_mode": "local-native",
        "evaluation_image": None,
        "os": platform.platform(),
        "architecture": platform.machine(),
        "python_implementation": sys.implementation.name,
        "python_version": platform.python_version(),
        "uv_lock_sha256": f"sha256:{hashlib.sha256((root / 'uv.lock').read_bytes()).hexdigest()}",
    }
    if plan.get("environment") != expected_environment:
        raise ValueError("execution environment drift")
    corpus = _load(Path(plan["corpus_manifest"]))
    if corpus["corpus_content_sha256"] != plan["corpus_content_sha256"]:
        raise ValueError("stale corpus binding")
    plan_sha = f"sha256:{hashlib.sha256(args.plan.read_bytes()).hexdigest()}"
    labels = {item["case_id"]: item["expected_label"] for item in corpus["cases"]}
    cases = {item["case_id"]: item for item in corpus["cases"]}
    oracle_rules = _load(Path(plan["corpus_manifest"]).parent / "corpus/oracle-rules.json")["rules"]
    planned = {
        (case_id, configuration, repetition): label
        for case_id, label in labels.items()
        for configuration in CONFIGURATIONS
        for repetition in range(1, plan["repetitions"][configuration] + 1)
    }
    records: dict[tuple[str, str, int], dict[str, Any]] = {}
    for line in args.records.read_text(encoding="utf-8").splitlines():
        record = _validate_record_shape(_strict_json(line))
        _validate_record_values(record, plan)
        identity = (record["case_id"], record["configuration"], record["repetition"])
        if identity in records or planned.get(identity) != record["expected_label"]:
            raise ValueError("duplicate or unbound record")
        if (
            record["run_plan_sha256"] != plan_sha
            or record["candidate_commit"] != plan["candidate_commit"]
            or record["corpus_content_sha256"] != plan["corpus_content_sha256"]
            or record["component_sha256"] != plan["bindings"]["component_sha256"]
            or record["policy_sha256"] != plan["bindings"]["policy_sha256"]
            or record["schema_sha256"] != plan["bindings"]["schema_sha256"]
            or record["state"] not in ("executed", "not_run", "failed")
        ):
            raise ValueError("record binding drift")
        if record["configuration"] == "one_shot_llm":
            expected_model = plan["ollama"]
            if (
                record["prompt_sha256"] != plan["bindings"]["prompt_sha256"]
                or record["model_name"] != expected_model["model"]
                or record["model_digest"] != expected_model["digest"]
                or record["runtime_name"] != "ollama"
                or record["runtime_version"] != expected_model["version"]
                or record["quantization"] != expected_model["quantization"]
                or record["temperature"] != expected_model["temperature"]
                or record["seed"] != expected_model["seed"]
                or record["budget_tokens"] != plan["budget"]["tokens"]
                or record["budget_calls"] != plan["budget"]["calls"]
                or record["budget_wall_seconds"] != plan["budget"]["wall_seconds"]
                or record["budget_retries"] != plan["budget"]["retries"]
            ):
                raise ValueError("model or budget binding drift")
        if record["state"] == "executed":
            if (
                record["predicted_label"] not in ("vulnerable", "safe")
                or type(record["confirmed_finding"]) is not bool
                or type(record["policy_matched"]) is not bool
                or (record["policy_matched"] and not record["confirmed_finding"])
                or record["reason"] is not None
            ):
                raise ValueError("fail-open executed record")
            if record["confirmed_finding"]:
                case = cases[record["case_id"]]
                ordered_sources = sorted(
                    case["sources"],
                    key=lambda item: hashlib.sha256(
                        f"{case['case_id']}\0{item['path']}".encode()
                    ).digest(),
                )
                aliases = {
                    f"file_{index}.py": item["path"]
                    for index, item in enumerate(ordered_sources, start=1)
                }
                expected_category = (
                    case["lineage_group"].removeprefix("lineage-").removesuffix("-v1")
                )
                independently_matched = (
                    record["returned_category"] == expected_category
                    and record["returned_source_alias"] in aliases
                    and aliases[record["returned_source_alias"]]
                    == oracle_rules[record["case_id"]]["source_path"]
                )
                if record["policy_matched"] != independently_matched:
                    raise ValueError("root-cause match drift")
            elif (
                record["returned_category"] is not None
                or record["returned_source_alias"] is not None
                or record["policy_matched"]
            ):
                raise ValueError("no-finding match drift")
        elif (
            record["predicted_label"] is not None
            or record["confirmed_finding"] is not None
            or record["policy_matched"] is not None
            or record["returned_category"] is not None
            or record["returned_source_alias"] is not None
            or not record["reason"]
        ):
            raise ValueError("invalid non-success record")
        records[identity] = record
    if set(records) != set(planned):
        raise ValueError("missing planned record")

    summaries: dict[str, dict[str, object]] = {}
    for configuration in CONFIGURATIONS:
        count = {
            "TP": 0,
            "FP": 0,
            "safe_FP": 0,
            "unmatched_FP": 0,
            "FN": 0,
            "TN": 0,
            "missing_safe": 0,
            "planned": 0,
            "executed": 0,
            "not_run": 0,
            "failed": 0,
        }
        vulnerable_total = safe_total = 0
        for identity, label in planned.items():
            if identity[1] != configuration:
                continue
            count["planned"] += 1
            vulnerable_total += label == "vulnerable"
            safe_total += label == "safe"
            record = records[identity]
            count[record["state"]] += 1
            if record["state"] != "executed":
                count["FN" if label == "vulnerable" else "missing_safe"] += 1
            elif label == "vulnerable":
                if record["confirmed_finding"] and record["policy_matched"]:
                    count["TP"] += 1
                else:
                    count["FN"] += 1
                    if record["confirmed_finding"]:
                        count["FP"] += 1
                        count["unmatched_FP"] += 1
            else:
                if record["confirmed_finding"]:
                    count["FP"] += 1
                    count["safe_FP"] += 1
                else:
                    count["TN"] += 1
        precision = _ratio(count["TP"], count["TP"] + count["FP"])
        recall = _ratio(count["TP"], count["TP"] + count["FN"])
        summaries[configuration] = {
            **count,
            "precision": precision,
            "recall": recall,
            "f1": _f(precision, recall, 1),
            "f2": _f(precision, recall, 4),
            "vulnerable_reconciles": count["TP"] + count["FN"] == vulnerable_total,
            "safe_reconciles": count["TN"] + count["safe_FP"] + count["missing_safe"] == safe_total,
            "eligible_vulnerable_repairs": vulnerable_total,
            "validated_root_cause_repairs": 0,
            "development_e2e_remediation_rate": 0.0 if vulnerable_total else None,
        }
    e2e_rows: list[dict[str, object]] = []
    micro_eligible = 0
    for configuration in CONFIGURATIONS:
        repetitions = sorted({item[2] for item in planned if item[1] == configuration})
        for repetition in repetitions:
            eligible = sum(
                1
                for identity, label in planned.items()
                if identity[1] == configuration
                and identity[2] == repetition
                and label == "vulnerable"
            )
            micro_eligible += eligible
            e2e_rows.append(
                {
                    "configuration": configuration,
                    "repetition": repetition,
                    "eligible_vulnerable_repairs": eligible,
                    "validated_root_cause_repairs": 0,
                    "rate": 0.0 if eligible else None,
                }
            )
    result = {
        "schema_version": "development-benchmark-aggregate-1.0",
        "planned_cells": len(planned),
        "recorded_cells": len(records),
        "incomplete": len(records) != len(planned)
        or any(
            item["not_run"] or item["failed"] or item["planned"] != item["executed"]
            for item in summaries.values()
        ),
        "configurations": summaries,
        "repair_metrics": {
            "attempted_patches": 0,
            "correct_and_secure_rate": None,
            "root_cause_repair_rate": None,
        },
        "additional_finding_overlap": None,
        "development_e2e_remediation": {
            "per_configuration_repetition": e2e_rows,
            "micro": {
                "eligible_vulnerable_repairs": micro_eligible,
                "validated_root_cause_repairs": 0,
                "rate": 0.0 if micro_eligible else None,
            },
        },
        "resources": _resource_facts(records),
        "incomplete_reasons": {
            configuration: {
                "not_run": summaries[configuration]["not_run"],
                "failed": summaries[configuration]["failed"],
            }
            for configuration in CONFIGURATIONS
            if summaries[configuration]["not_run"] or summaries[configuration]["failed"]
        },
    }
    args.output.write_bytes((json.dumps(result, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    return 0


def _resource_facts(records: dict[tuple[str, str, int], dict[str, Any]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for configuration in CONFIGURATIONS:
        selected = [item for identity, item in records.items() if identity[1] == configuration]
        walls = sorted(
            float(item["wall_seconds"]) for item in selected if item["wall_seconds"] is not None
        )
        reasons: dict[str, int] = {}
        for item in selected:
            if item["reason"]:
                reason = str(item["reason"])
                reasons[reason] = reasons.get(reason, 0) + 1
        token_rows = [
            item
            for item in selected
            if item["prompt_tokens"] is not None and item["generated_tokens"] is not None
        ]
        result[configuration] = {
            "planned_calls": len(selected),
            "measured_wall_count": len(walls),
            "wall_seconds_total": sum(walls),
            "latency_p50_seconds": _percentile(walls, 0.50),
            "latency_p95_seconds": _percentile(walls, 0.95),
            "token_fact_count": len(token_rows),
            "prompt_tokens_total": sum(int(item["prompt_tokens"]) for item in token_rows),
            "generated_tokens_total": sum(int(item["generated_tokens"]) for item in token_rows),
            "provider_cost": None,
            "peak_cpu_seconds": None,
            "peak_ram_bytes": None,
            "peak_vram_bytes": None,
            "failure_reason_counts": reasons,
        }
    return result


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    return values[max(0, ceil(fraction * len(values)) - 1)]


if __name__ == "__main__":
    raise SystemExit(main())
