"""Fail-closed facts and denominator aggregation for the P7.17 study."""

from __future__ import annotations

from dataclasses import asdict, dataclass
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
FindingOrigin = Literal["deterministic", "model_native", "hybrid"]
CONFIGURATIONS: tuple[Configuration, ...] = (
    "deterministic_only",
    "scanner_seeded_investigation",
    "model_native_only",
    "one_shot_llm",
    "full_hybrid",
)


def _is_lower_hex(value: object, length: int) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_sha256(value: str) -> None:
    if not value.startswith("sha256:") or not _is_lower_hex(value[7:], 64):
        raise ValueError("invalid SHA-256 identity")


def _is_source_alias(value: object) -> bool:
    if type(value) is not str or not value.startswith("file_") or not value.endswith(".py"):
        return False
    number = value[5:-3]
    return number.isdecimal() and number != "0" and str(int(number)) == number


@dataclass(frozen=True, slots=True)
class Record:
    """One immutable planned case/configuration/repetition outcome."""

    schema_version: str
    study_id: str
    case_id: str
    root_cause_group: str
    source_aliases: tuple[str, ...]
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
    finding_origin: FindingOrigin | None
    remediation_attempted: bool
    remediation_data_only: bool | None
    remediation_sandbox_receipt_sha256: str | None
    remediation_sandbox_validated: bool | None
    remediation_oracle_validated: bool | None
    remediation_existing_regression_passed: bool | None
    remediation_no_new_blocking_regressions: bool | None

    def __post_init__(self) -> None:
        if (
            self.schema_version != "development-benchmark-record-1.1"
            or not self.study_id
            or not self.case_id
            or not self.root_cause_group
            or not self.source_aliases
            or len(set(self.source_aliases)) != len(self.source_aliases)
            or any(not _is_source_alias(alias) for alias in self.source_aliases)
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
        model_identity = (
            self.prompt_sha256,
            self.model_name,
            self.model_digest,
            self.runtime_name,
            self.runtime_version,
            self.quantization,
            self.temperature,
        )
        if self.configuration == "deterministic_only" and (
            any(value is not None for value in model_identity)
            or self.seed is not None
            or any(
                value != 0
                for value in (
                    self.budget_tokens,
                    self.budget_calls,
                    self.budget_wall_seconds,
                    self.budget_retries,
                )
            )
            or self.prompt_tokens is not None
            or self.generated_tokens is not None
        ):
            raise ValueError("deterministic record cannot carry model facts")
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
        if self.configuration != "deterministic_only" and (
            any(value is None for value in model_identity)
            or self.budget_tokens == 0
            or self.budget_calls == 0
            or self.budget_wall_seconds == 0
        ):
            raise ValueError("model record requires bound model facts")
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
                    self.returned_category not in {"authz", "path", "sql", "command"}
                    or self.returned_source_alias not in self.source_aliases
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
        if self.finding_origin is not None and self.finding_origin not in {
            "deterministic",
            "model_native",
            "hybrid",
        }:
            raise ValueError("invalid finding origin")
        if self.confirmed_finding is not True and self.finding_origin is not None:
            raise ValueError("origin requires a confirmed finding")
        if self.confirmed_finding is True and self.finding_origin is None:
            raise ValueError("confirmed finding requires an origin")
        allowed_origins = {
            "deterministic_only": {"deterministic"},
            "scanner_seeded_investigation": {"deterministic"},
            "model_native_only": {"model_native"},
            "one_shot_llm": {"model_native"},
            "full_hybrid": {"deterministic", "model_native", "hybrid"},
        }
        if (
            self.finding_origin is not None
            and self.finding_origin not in allowed_origins[self.configuration]
        ):
            raise ValueError("finding origin is incompatible with configuration")
        scanner_configurations = {
            "deterministic_only",
            "scanner_seeded_investigation",
            "full_hybrid",
        }
        requires_scanner_receipt = (
            self.configuration in scanner_configurations and self.state != "not_run"
        )
        if requires_scanner_receipt != (self.scanner_signal_count is not None):
            raise ValueError("scanner receipt applicability drift")
        if (
            self.configuration == "scanner_seeded_investigation"
            and self.scanner_signal_count == 0
            and (
                self.state != "executed"
                or self.confirmed_finding is not False
                or self.predicted_label != "safe"
            )
        ):
            raise ValueError("zero scanner seed cannot invoke independent discovery")
        remediation_values = (
            self.remediation_data_only,
            self.remediation_sandbox_receipt_sha256,
            self.remediation_sandbox_validated,
            self.remediation_oracle_validated,
            self.remediation_existing_regression_passed,
            self.remediation_no_new_blocking_regressions,
        )
        if type(self.remediation_attempted) is not bool:
            raise ValueError("invalid remediation state")
        if not self.remediation_attempted:
            if any(value is not None for value in remediation_values):
                raise ValueError("unattempted remediation cannot carry validation facts")
        elif (
            self.remediation_data_only is not True
            or type(self.remediation_sandbox_receipt_sha256) is not str
            or not _is_lower_hex(self.remediation_sandbox_receipt_sha256, 64)
            or any(
                type(value) is not bool
                for value in (
                    self.remediation_sandbox_validated,
                    self.remediation_oracle_validated,
                    self.remediation_existing_regression_passed,
                    self.remediation_no_new_blocking_regressions,
                )
            )
        ):
            raise ValueError("invalid remediation validation facts")
        if (
            self.remediation_attempted
            and self.remediation_sandbox_validated
            and self.remediation_oracle_validated
            and self.remediation_existing_regression_passed
            and self.remediation_no_new_blocking_regressions
            and (
                self.state != "executed"
                or self.expected_label != "vulnerable"
                or not self.confirmed_finding
                or not self.policy_matched
            )
        ):
            raise ValueError("validated remediation requires a matched vulnerable finding")

    @property
    def identity(self) -> tuple[str, Configuration, int]:
        return self.case_id, self.configuration, self.repetition

    def document(self) -> dict[str, object]:
        return asdict(self)
