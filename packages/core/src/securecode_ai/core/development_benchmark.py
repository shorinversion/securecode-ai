"""Fail-closed facts and denominator aggregation for the P7.17 study."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from math import ceil
from typing import Literal

Configuration = Literal[
    "deterministic_only",
    "scanner_seeded_investigation",
    "model_native_only",
    "one_shot_llm",
    "full_hybrid",
]
State = Literal["executed", "not_run", "failed"]
Label = Literal["vulnerable", "safe"]
CONFIGURATIONS: tuple[Configuration, ...] = (
    "deterministic_only",
    "scanner_seeded_investigation",
    "model_native_only",
    "one_shot_llm",
    "full_hybrid",
)


@dataclass(frozen=True, slots=True)
class Record:
    """One immutable planned case/configuration/repetition outcome."""

    schema_version: str
    study_id: str
    case_id: str
    configuration: Configuration
    repetition: int
    expected_label: Label
    state: State
    predicted_label: Label | None
    confirmed_finding: bool | None
    policy_matched: bool | None
    returned_category: str | None
    returned_source_alias: str | None
    reason: str | None
    run_plan_sha256: str
    candidate_commit: str
    corpus_content_sha256: str
    component_sha256: str
    prompt_sha256: str | None
    policy_sha256: str
    schema_sha256: str
    model_name: str | None
    model_digest: str | None
    runtime_name: str | None
    runtime_version: str | None
    quantization: str | None
    temperature: float | None
    seed: int | None
    budget_tokens: int
    budget_calls: int
    budget_wall_seconds: int
    budget_retries: int
    wall_seconds: float | None
    prompt_tokens: int | None
    generated_tokens: int | None
    scanner_signal_count: int | None
    provider_cost: float | None

    def __post_init__(self) -> None:
        if (
            self.schema_version != "development-benchmark-record-1.0"
            or not self.study_id
            or not self.case_id
            or self.configuration not in CONFIGURATIONS
            or type(self.repetition) is not int
            or self.repetition < 1
            or self.expected_label not in ("vulnerable", "safe")
        ):
            raise ValueError("invalid record identity")
        for digest in (
            self.run_plan_sha256,
            self.corpus_content_sha256,
            self.component_sha256,
            self.policy_sha256,
            self.schema_sha256,
        ):
            _require_sha256(digest)
        if self.prompt_sha256 is not None:
            _require_sha256(self.prompt_sha256)
        if self.model_digest is not None:
            _require_sha256(self.model_digest)
        if not self.candidate_commit.startswith("git-sha1:") or not _is_lower_hex(
            self.candidate_commit[9:], 40
        ):
            raise ValueError("invalid candidate commit")
        for budget_value in (
            self.budget_tokens,
            self.budget_calls,
            self.budget_wall_seconds,
            self.budget_retries,
        ):
            if type(budget_value) is not int or budget_value < 0:
                raise ValueError("invalid budget")
        if self.state == "executed":
            if (
                self.predicted_label not in ("vulnerable", "safe")
                or type(self.confirmed_finding) is not bool
                or type(self.policy_matched) is not bool
                or (self.policy_matched and not self.confirmed_finding)
                or self.reason is not None
            ):
                raise ValueError("executed record must contain exactly one prediction")
            if self.confirmed_finding:
                if (
                    type(self.returned_category) is not str
                    or not self.returned_category
                    or type(self.returned_source_alias) is not str
                    or not self.returned_source_alias
                ):
                    raise ValueError("confirmed finding requires match inputs")
            elif self.returned_category is not None or self.returned_source_alias is not None:
                raise ValueError("no-finding record cannot contain match inputs")
        elif (
            self.predicted_label is not None
            or self.confirmed_finding is not None
            or self.policy_matched is not None
            or self.returned_category is not None
            or self.returned_source_alias is not None
            or not self.reason
        ):
            raise ValueError("non-success requires a reason and no prediction")
        for measurement in (self.wall_seconds, self.provider_cost):
            if measurement is not None and (type(measurement) is not float or measurement < 0):
                raise ValueError("invalid resource measurement")
        if self.temperature is not None and (
            type(self.temperature) is not float or self.temperature < 0
        ):
            raise ValueError("invalid temperature")
        if self.seed is not None and (type(self.seed) is not int or self.seed < 0):
            raise ValueError("invalid seed")
        for count_value in (
            self.prompt_tokens,
            self.generated_tokens,
            self.scanner_signal_count,
        ):
            if count_value is not None and (type(count_value) is not int or count_value < 0):
                raise ValueError("invalid resource count")

    @property
    def identity(self) -> tuple[str, Configuration, int]:
        return self.case_id, self.configuration, self.repetition

    def document(self) -> dict[str, object]:
        return asdict(self)


def planned_cells(
    cases: list[tuple[str, Label]], repetitions: dict[str, int]
) -> tuple[tuple[str, Configuration, int, Label], ...]:
    """Expand the frozen matrix with explicit configuration repetitions."""

    if set(repetitions) != set(CONFIGURATIONS):
        raise ValueError("configuration repetition set is incomplete")
    result: list[tuple[str, Configuration, int, Label]] = []
    for case_id, label in cases:
        if not case_id or label not in ("vulnerable", "safe"):
            raise ValueError("invalid planned case")
        for configuration in CONFIGURATIONS:
            repeat_count = repetitions[configuration]
            if type(repeat_count) is not int or repeat_count < 1:
                raise ValueError("invalid repetition count")
            result.extend(
                (case_id, configuration, repetition, label)
                for repetition in range(1, repeat_count + 1)
            )
    if len({row[:3] for row in result}) != len(result):
        raise ValueError("duplicate planned cell")
    return tuple(result)


def aggregate(
    planned: tuple[tuple[str, Configuration, int, Label], ...],
    records: tuple[Record, ...],
) -> dict[str, object]:
    """Aggregate every cell; a non-success can never become clean."""

    plan = {
        (case_id, configuration, repetition): label
        for case_id, configuration, repetition, label in planned
    }
    if len(plan) != len(planned):
        raise ValueError("duplicate planned cell")
    observed: dict[tuple[str, str, int], Record] = {}
    for record in records:
        if plan.get(record.identity) != record.expected_label or record.identity in observed:
            raise ValueError("unbound or duplicate record")
        observed[record.identity] = record
    if set(observed) != set(plan):
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
        for case_id, _, repetition, label in (row for row in planned if row[1] == configuration):
            count["planned"] += 1
            current = observed.get((case_id, configuration, repetition))
            if current is None:
                count["FN" if label == "vulnerable" else "missing_safe"] += 1
                continue
            count[current.state] += 1
            if current.state != "executed":
                count["FN" if label == "vulnerable" else "missing_safe"] += 1
            elif label == "vulnerable":
                if current.confirmed_finding and current.policy_matched:
                    count["TP"] += 1
                else:
                    count["FN"] += 1
                    if current.confirmed_finding:
                        count["FP"] += 1
                        count["unmatched_FP"] += 1
            else:
                if current.confirmed_finding:
                    count["FP"] += 1
                    count["safe_FP"] += 1
                else:
                    count["TN"] += 1
        precision = _ratio(count["TP"], count["TP"] + count["FP"])
        recall = _ratio(count["TP"], count["TP"] + count["FN"])
        vulnerable_total = sum(
            1 for row in planned if row[1] == configuration and row[3] == "vulnerable"
        )
        safe_total = sum(1 for row in planned if row[1] == configuration and row[3] == "safe")
        summaries[configuration] = {
            **count,
            "precision": precision,
            "recall": recall,
            "f1": _f_score(precision, recall, beta_squared=1),
            "f2": _f_score(precision, recall, beta_squared=4),
            "vulnerable_reconciles": count["TP"] + count["FN"] == vulnerable_total,
            "safe_reconciles": count["TN"] + count["safe_FP"] + count["missing_safe"] == safe_total,
            "eligible_vulnerable_repairs": vulnerable_total,
            "validated_root_cause_repairs": 0,
            "development_e2e_remediation_rate": 0.0 if vulnerable_total else None,
        }
    incomplete = len(records) != len(planned) or any(
        item["not_run"] or item["failed"] or item["planned"] != item["executed"]
        for item in summaries.values()
    )
    e2e_rows: list[dict[str, object]] = []
    micro_eligible = 0
    for configuration in CONFIGURATIONS:
        repetitions = sorted({row[2] for row in planned if row[1] == configuration})
        for repetition in repetitions:
            eligible = sum(
                1
                for row in planned
                if row[1] == configuration and row[2] == repetition and row[3] == "vulnerable"
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
    return {
        "schema_version": "development-benchmark-aggregate-1.0",
        "planned_cells": len(planned),
        "recorded_cells": len(records),
        "incomplete": incomplete,
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


def _resource_facts(records: tuple[Record, ...]) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for configuration in CONFIGURATIONS:
        selected = [record for record in records if record.configuration == configuration]
        walls = sorted(
            record.wall_seconds for record in selected if record.wall_seconds is not None
        )
        reasons: dict[str, int] = {}
        for record in selected:
            if record.reason:
                reasons[record.reason] = reasons.get(record.reason, 0) + 1
        token_rows = [
            record
            for record in selected
            if record.prompt_tokens is not None and record.generated_tokens is not None
        ]
        result[configuration] = {
            "planned_calls": len(selected),
            "measured_wall_count": len(walls),
            "wall_seconds_total": sum(walls),
            "latency_p50_seconds": _percentile(walls, 0.50),
            "latency_p95_seconds": _percentile(walls, 0.95),
            "token_fact_count": len(token_rows),
            "prompt_tokens_total": sum(record.prompt_tokens or 0 for record in token_rows),
            "generated_tokens_total": sum(record.generated_tokens or 0 for record in token_rows),
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


def _ratio(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator


def _f_score(precision: float | None, recall: float | None, *, beta_squared: int) -> float | None:
    if precision is None or recall is None or precision + recall == 0:
        return None
    return (1 + beta_squared) * precision * recall / (beta_squared * precision + recall)


def _require_sha256(value: str) -> None:
    if not value.startswith("sha256:") or not _is_lower_hex(value[7:], 64):
        raise ValueError("invalid SHA-256 identity")


def _is_lower_hex(value: object, length: int) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


__all__ = ["CONFIGURATIONS", "Record", "aggregate", "planned_cells"]
