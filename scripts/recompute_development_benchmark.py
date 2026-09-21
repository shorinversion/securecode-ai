"""Independently recompute P7.17 denominators from JSONL facts."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import sys
from collections.abc import Iterable
from math import ceil
from pathlib import Path
from typing import Any, cast

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
    "root_cause_group",
    "source_aliases",
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
    "finding_origin",
    "remediation_attempted",
    "remediation_data_only",
    "remediation_sandbox_receipt_sha256",
    "remediation_sandbox_validated",
    "remediation_oracle_validated",
    "remediation_existing_regression_passed",
    "remediation_no_new_blocking_regressions",
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
        record["schema_version"] != "development-benchmark-record-1.1"
        or record["study_id"] != plan["study_id"]
        or type(record["case_id"]) is not str
        or not record["case_id"]
        or type(record["root_cause_group"]) is not str
        or not record["root_cause_group"]
        or type(record["source_aliases"]) not in (list, tuple)
        or not record["source_aliases"]
        or len(set(record["source_aliases"])) != len(record["source_aliases"])
        or any(not _is_source_alias(alias) for alias in record["source_aliases"])
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
    model_identity = (
        record["prompt_sha256"],
        record["model_name"],
        record["model_digest"],
        record["runtime_name"],
        record["runtime_version"],
        record["quantization"],
        record["temperature"],
    )
    if record["configuration"] == "deterministic_only":
        if (
            any(value is not None for value in model_identity)
            or record["seed"] is not None
            or any(
                record[name] != 0
                for name in (
                    "budget_tokens",
                    "budget_calls",
                    "budget_wall_seconds",
                    "budget_retries",
                )
            )
            or record["prompt_tokens"] is not None
            or record["generated_tokens"] is not None
        ):
            raise ValueError("deterministic record cannot carry model facts")
    elif (
        any(value is None for value in model_identity)
        or record["budget_tokens"] == 0
        or record["budget_calls"] == 0
        or record["budget_wall_seconds"] == 0
    ):
        raise ValueError("model record requires bound model facts")
    if record["temperature"] is not None and (
        type(record["temperature"]) is not float or record["temperature"] < 0
    ):
        raise ValueError("invalid temperature")
    if record["seed"] is not None and (type(record["seed"]) is not int or record["seed"] < 0):
        raise ValueError("invalid seed")
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
                or record["returned_category"] not in {"authz", "path", "sql", "command"}
                or record["returned_source_alias"] not in record["source_aliases"]
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
    if record["finding_origin"] is not None and record["finding_origin"] not in {
        "deterministic",
        "model_native",
        "hybrid",
    }:
        raise ValueError("invalid finding origin")
    if record["confirmed_finding"] is not True and record["finding_origin"] is not None:
        raise ValueError("origin without a finding")
    if record["confirmed_finding"] is True and record["finding_origin"] is None:
        raise ValueError("confirmed finding requires an origin")
    allowed_origins = {
        "deterministic_only": {"deterministic"},
        "scanner_seeded_investigation": {"deterministic"},
        "model_native_only": {"model_native"},
        "one_shot_llm": {"model_native"},
        "full_hybrid": {"deterministic", "model_native", "hybrid"},
    }
    if (
        record["finding_origin"] is not None
        and record["finding_origin"] not in allowed_origins[record["configuration"]]
    ):
        raise ValueError("finding origin is incompatible with configuration")
    scanner_configurations = {
        "deterministic_only",
        "scanner_seeded_investigation",
        "full_hybrid",
    }
    requires_scanner_receipt = (
        record["configuration"] in scanner_configurations and record["state"] != "not_run"
    )
    if requires_scanner_receipt != (record["scanner_signal_count"] is not None):
        raise ValueError("scanner receipt applicability drift")
    if (
        record["configuration"] == "scanner_seeded_investigation"
        and record["scanner_signal_count"] == 0
        and (
            record["state"] != "executed"
            or record["confirmed_finding"] is not False
            or record["predicted_label"] != "safe"
        )
    ):
        raise ValueError("zero scanner seed cannot invoke independent discovery")
    remediation_values = (
        record["remediation_data_only"],
        record["remediation_sandbox_receipt_sha256"],
        record["remediation_sandbox_validated"],
        record["remediation_oracle_validated"],
        record["remediation_existing_regression_passed"],
        record["remediation_no_new_blocking_regressions"],
    )
    if type(record["remediation_attempted"]) is not bool:
        raise ValueError("invalid remediation state")
    if not record["remediation_attempted"]:
        if any(value is not None for value in remediation_values):
            raise ValueError("unattempted remediation validation facts")
    elif (
        record["remediation_data_only"] is not True
        or type(record["remediation_sandbox_receipt_sha256"]) is not str
        or len(record["remediation_sandbox_receipt_sha256"]) != 64
        or any(
            character not in "0123456789abcdef"
            for character in record["remediation_sandbox_receipt_sha256"]
        )
        or any(
            type(value) is not bool
            for value in (
                record["remediation_sandbox_validated"],
                record["remediation_oracle_validated"],
                record["remediation_existing_regression_passed"],
                record["remediation_no_new_blocking_regressions"],
            )
        )
    ):
        raise ValueError("invalid remediation validation facts")
    if (
        record["remediation_attempted"]
        and record["remediation_sandbox_validated"]
        and record["remediation_oracle_validated"]
        and record["remediation_existing_regression_passed"]
        and record["remediation_no_new_blocking_regressions"]
        and (
            record["state"] != "executed"
            or record["expected_label"] != "vulnerable"
            or not record["confirmed_finding"]
            or not record["policy_matched"]
        )
    ):
        raise ValueError("validated remediation requires a matched vulnerable finding")


def _ratio(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator


def _f(precision: float | None, recall: float | None, beta2: int) -> float | None:
    if precision is None or recall is None or precision + recall == 0:
        return None
    return (1 + beta2) * precision * recall / (beta2 * precision + recall)


def _validate_detection_only_record(record: dict[str, Any]) -> None:
    """A supplemental detection run cannot attest to patches it never executed."""
    if record.get("remediation_attempted") is not False or any(
        record.get(key) is not None
        for key in (
            "remediation_data_only",
            "remediation_sandbox_receipt_sha256",
            "remediation_sandbox_validated",
            "remediation_oracle_validated",
            "remediation_existing_regression_passed",
            "remediation_no_new_blocking_regressions",
        )
    ):
        raise ValueError("detection-only run cannot claim remediation")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    plan = _load(args.plan)
    root = Path(__file__).resolve().parents[1]
    supplemental = plan.get("schema_version") == "development-benchmark-plan-1.1"
    if plan.get("schema_version") not in {
        "development-benchmark-plan-1.0",
        "development-benchmark-plan-1.1",
    }:
        raise ValueError("unsupported development plan schema")
    admission = None
    if supplemental:
        if args.receipt is None:
            raise ValueError("supplemental recomputation requires execution receipt")
        helper_path = root / "scripts/development_run_admission.py"
        spec = importlib.util.spec_from_file_location(
            "_securecode_recompute_admission", helper_path
        )
        if spec is None or spec.loader is None:
            raise ValueError("supplemental admission helper unavailable")
        helper = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = helper
        spec.loader.exec_module(helper)
        declared = plan.get("execution", {}).get("paths", {})
        if (
            type(declared) is not dict
            or set(declared) != {"plan", "records", "aggregate", "recomputed", "receipt"}
            or any(type(value) is not str for value in declared.values())
        ):
            raise ValueError("missing closed supplemental output paths")
        paths = {name: root / value for name, value in declared.items()}
        paths.update(
            plan=args.plan.resolve(),
            records=args.records.resolve(),
            recomputed=args.output.resolve(),
            receipt=args.receipt.resolve(),
        )
        admission = helper.admit_run(
            root=root,
            plan_path=args.plan,
            action="recompute",
            argv=tuple(sys.argv[1:]),
            paths=paths,
        )
        helper.verify_imported_package_bindings(admission.plan)
    expected_bindings = {
        "component_sha256": f"sha256:{hashlib.sha256((root / 'scripts/run_development_benchmark.py').read_bytes()).hexdigest()}",
        "core_sha256": f"sha256:{hashlib.sha256((root / 'packages/core/src/securecode_ai/core/development_benchmark.py').read_bytes()).hexdigest()}",
        "recompute_sha256": f"sha256:{hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}",
        "corpus_validator_sha256": f"sha256:{hashlib.sha256((root / 'scripts/development_corpus.py').read_bytes()).hexdigest()}",
        "prompt_sha256": plan["bindings"]["prompt_sha256"],
        "policy_sha256": plan["bindings"]["policy_sha256"],
        "schema_sha256": plan["bindings"]["schema_sha256"],
    }
    if supplemental:
        # Share candidate identity hashing only; metric recomputation stays independent.
        identity_spec = importlib.util.spec_from_file_location(
            "_securecode_recompute_candidate_identity",
            root / "scripts/run_development_benchmark.py",
        )
        if identity_spec is None or identity_spec.loader is None:
            raise ValueError("candidate identity implementation unavailable")
        identity_module = importlib.util.module_from_spec(identity_spec)
        sys.modules[identity_spec.name] = identity_module
        identity_spec.loader.exec_module(identity_module)
        expected_bindings = identity_module._current_bindings(admitted=True)
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
        if plan.get("schema_version") == "development-benchmark-plan-1.1":
            _validate_detection_only_record(record)
        identity = (record["case_id"], record["configuration"], record["repetition"])
        if identity in records or planned.get(identity) != record["expected_label"]:
            raise ValueError("duplicate or unbound record")
        case = cases[record["case_id"]]
        if record["root_cause_group"] != case["root_cause_group"]:
            raise ValueError("root-cause group binding drift")
        ordered_sources = sorted(
            case["sources"],
            key=lambda item: hashlib.sha256(f"{case['case_id']}\0{item['path']}".encode()).digest(),
        )
        aliases = {
            f"file_{index}.py": item["path"] for index, item in enumerate(ordered_sources, start=1)
        }
        if tuple(record["source_aliases"]) != tuple(aliases):
            raise ValueError("source-alias map binding drift")
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
        if record["configuration"] != "deterministic_only":
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
            "validated_root_cause_repairs": _validated_repair_count(
                record for record in records.values() if record["configuration"] == configuration
            ),
            "development_e2e_remediation_rate": _ratio(
                _validated_repair_count(
                    record
                    for record in records.values()
                    if record["configuration"] == configuration
                ),
                vulnerable_total,
            ),
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
            validated = _validated_repair_count(
                record
                for identity, record in records.items()
                if identity[1] == configuration and identity[2] == repetition
            )
            micro_eligible += eligible
            e2e_rows.append(
                {
                    "configuration": configuration,
                    "repetition": repetition,
                    "eligible_vulnerable_repairs": eligible,
                    "validated_root_cause_repairs": validated,
                    "rate": _ratio(validated, eligible),
                }
            )
    result = {
        "schema_version": "development-benchmark-aggregate-1.1",
        "planned_cells": len(planned),
        "recorded_cells": len(records),
        "incomplete": len(records) != len(planned)
        or any(
            item["not_run"] or item["failed"] or item["planned"] != item["executed"]
            for item in summaries.values()
        ),
        "configurations": summaries,
        "repair_metrics": {
            "attempted_patches": sum(
                record["remediation_attempted"] for record in records.values()
            ),
            "sandbox_validated_patches": sum(
                record["remediation_attempted"] and bool(record["remediation_sandbox_validated"])
                for record in records.values()
            ),
            "independently_validated_patches": _validated_repair_count(records.values()),
            "correct_and_secure_rate": None,
            "root_cause_repair_rate": None,
        },
        "additional_finding_overlap": _finding_origins(records),
        "full_hybrid_origin_attribution": _full_hybrid_origin_attribution(
            records, summaries["full_hybrid"]
        ),
        "development_e2e_remediation": {
            "per_configuration_repetition": e2e_rows,
            "micro": {
                "eligible_vulnerable_repairs": micro_eligible,
                "validated_root_cause_repairs": _validated_repair_count(records.values()),
                "rate": _ratio(_validated_repair_count(records.values()), micro_eligible),
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
    if (
        admission is not None
        and args.output.read_bytes() != admission.paths["aggregate"].read_bytes()
    ):
        raise ValueError("independent aggregate bytes differ from execution aggregate")
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


def _validated_repair_count(records: Iterable[dict[str, Any]]) -> int:
    return sum(
        record["remediation_attempted"]
        and record["remediation_sandbox_validated"] is True
        and record["remediation_oracle_validated"] is True
        and record["remediation_existing_regression_passed"] is True
        and record["remediation_no_new_blocking_regressions"] is True
        for record in records
    )


def _finding_origins(
    records: dict[tuple[str, str, int], dict[str, Any]],
) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for configuration in CONFIGURATIONS:
        result[configuration] = {
            origin: len(
                {
                    (record["case_id"], record["root_cause_group"])
                    for identity, record in records.items()
                    if identity[1] == configuration
                    and record["confirmed_finding"] is True
                    and record["policy_matched"] is True
                    and record["finding_origin"] == origin
                }
            )
            for origin in ("deterministic", "model_native", "hybrid")
        }
    return result


def _confusion_matrix(records: Iterable[dict[str, Any]]) -> dict[str, object]:
    selected = tuple(records)
    count: dict[str, int] = {
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
    for record in selected:
        count["planned"] += 1
        count[str(record["state"])] += 1
        if record["state"] != "executed":
            count["FN" if record["expected_label"] == "vulnerable" else "missing_safe"] += 1
        elif record["expected_label"] == "vulnerable":
            if record["confirmed_finding"] and record["policy_matched"]:
                count["TP"] += 1
            else:
                count["FN"] += 1
                if record["confirmed_finding"]:
                    count["FP"] += 1
                    count["unmatched_FP"] += 1
        elif record["confirmed_finding"]:
            count["FP"] += 1
            count["safe_FP"] += 1
        else:
            count["TN"] += 1
    precision = _ratio(count["TP"], count["TP"] + count["FP"])
    recall = _ratio(count["TP"], count["TP"] + count["FN"])
    return {
        **count,
        "precision": precision,
        "recall": recall,
        "f1": _f(precision, recall, 1),
        "f2": _f(precision, recall, 4),
        "vulnerable_reconciles": count["TP"] + count["FN"]
        == sum(record["expected_label"] == "vulnerable" for record in selected),
        "safe_reconciles": count["TN"] + count["safe_FP"] + count["missing_safe"]
        == sum(record["expected_label"] == "safe" for record in selected),
    }


def _full_hybrid_origin_attribution(
    records: dict[tuple[str, str, int], dict[str, Any]], global_matrix: dict[str, object]
) -> dict[str, object]:
    selected = tuple(record for identity, record in records.items() if identity[1] == "full_hybrid")
    origins: dict[str, dict[str, int]] = {
        origin: {"TP": 0, "FP": 0} for origin in ("deterministic", "model_native", "hybrid")
    }
    unattributed = {"FN": 0, "TN": 0, "missing_safe": 0}
    deterministic_candidate_cells = 0
    auditor_receipt_cells = 0
    confirmed_cells = 0
    attributed_cells = 0
    for record in selected:
        if record["scanner_signal_count"] is None and record["state"] != "not_run":
            raise ValueError("full-hybrid record is missing scanner receipt")
        if record["scanner_signal_count"] is not None and record["scanner_signal_count"] > 0:
            deterministic_candidate_cells += 1
            auditor_receipt_cells += record["state"] == "executed"
        if record["state"] != "executed":
            unattributed["FN" if record["expected_label"] == "vulnerable" else "missing_safe"] += 1
            continue
        if record["confirmed_finding"]:
            origin = record["finding_origin"]
            if origin is None:
                raise ValueError("confirmed full-hybrid cell is missing origin")
            confirmed_cells += 1
            attributed_cells += 1
            bucket = origins[str(origin)]
            if record["expected_label"] == "vulnerable" and record["policy_matched"]:
                bucket["TP"] += 1
            else:
                bucket["FP"] += 1
                if record["expected_label"] == "vulnerable":
                    unattributed["FN"] += 1
        elif record["expected_label"] == "vulnerable":
            unattributed["FN"] += 1
        else:
            unattributed["TN"] += 1
    global_tp = cast(int, global_matrix["TP"])
    global_fp = cast(int, global_matrix["FP"])
    global_fn = cast(int, global_matrix["FN"])
    global_tn = cast(int, global_matrix["TN"])
    global_missing_safe = cast(int, global_matrix["missing_safe"])
    global_vulnerable = global_tp + global_fn
    per_origin = {
        origin: {
            **bucket,
            "confirmed_precision": _ratio(bucket["TP"], bucket["TP"] + bucket["FP"]),
            "recall_contribution": _ratio(bucket["TP"], global_vulnerable),
        }
        for origin, bucket in origins.items()
    }
    zero_scanner_records = tuple(
        record for record in selected if record["scanner_signal_count"] == 0
    )
    reconciliation_items = {
        "TP": {
            "attributed": sum(bucket["TP"] for bucket in origins.values()),
            "global": global_tp,
        },
        "FP": {
            "attributed": sum(bucket["FP"] for bucket in origins.values()),
            "global": global_fp,
        },
        "FN": {"unattributed": unattributed["FN"], "global": global_fn},
        "TN": {"unattributed": unattributed["TN"], "global": global_tn},
        "missing_safe": {
            "unattributed": unattributed["missing_safe"],
            "global": global_missing_safe,
        },
    }
    reconciliation_complete = all(
        (values.get("attributed") if "attributed" in values else values["unattributed"])
        == values["global"]
        for values in reconciliation_items.values()
    )
    zero_matrix = _confusion_matrix(zero_scanner_records)
    scanner_receipts_complete = all(
        record["scanner_signal_count"] is not None for record in selected
    )
    return {
        "per_origin": per_origin,
        "unattributed": unattributed,
        "zero_scanner_signal_stratum": {
            "matrix": zero_matrix,
            "complete": scanner_receipts_complete
            and zero_matrix["planned"] == zero_matrix["executed"],
        },
        "deterministic_candidate_auditor_receipt_coverage": {
            "deterministic_candidate_cells": deterministic_candidate_cells,
            "auditor_receipt_cells": auditor_receipt_cells,
            "dropped_candidate_cells": deterministic_candidate_cells - auditor_receipt_cells,
            "coverage": _ratio(auditor_receipt_cells, deterministic_candidate_cells),
            "complete": scanner_receipts_complete
            and auditor_receipt_cells == deterministic_candidate_cells,
        },
        "confirmed_cell_origin_coverage": {
            "confirmed_cells": confirmed_cells,
            "attributed_cells": attributed_cells,
            "complete": confirmed_cells == attributed_cells,
        },
        "reconciliation": {**reconciliation_items, "complete": reconciliation_complete},
    }


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    return values[max(0, ceil(fraction * len(values)) - 1)]


def _is_source_alias(value: object) -> bool:
    if type(value) is not str or not value.startswith("file_") or not value.endswith(".py"):
        return False
    number = value[5:-3]
    return number.isdecimal() and number != "0" and str(int(number)) == number


if __name__ == "__main__":
    raise SystemExit(main())
