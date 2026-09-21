"""Immutable benchmark cells and fail-closed release comparison."""

from __future__ import annotations

import hashlib
import json
import math
import random
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Final

from .release_metrics import f1, percentile, ratio, wilson_lower

_TOKEN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}\Z")
_COMPLETED: Final = "completed"


class Configuration(StrEnum):
    DETERMINISTIC = "deterministic_only"
    SCANNER = "scanner_seeded"
    MODEL = "model_native"
    ONE_SHOT = "one_shot"
    HYBRID = "full_hybrid"
    SEMGREP = "semgrep"
    CODEQL = "codeql"


_REQUIRED: Final = frozenset(
    {
        Configuration.DETERMINISTIC,
        Configuration.SCANNER,
        Configuration.MODEL,
        Configuration.ONE_SHOT,
        Configuration.HYBRID,
        Configuration.SEMGREP,
    }
)
_MODEL_CONFIGURATIONS: Final = frozenset(
    {Configuration.MODEL, Configuration.ONE_SHOT, Configuration.HYBRID}
)
_LANGUAGES: Final = frozenset({"python", "js-ts", "go"})


class BenchmarkValidationError(ValueError):
    """Raised when benchmark evidence is malformed or ambiguous."""


@dataclass(frozen=True, slots=True)
class BenchmarkCell:
    configuration: Configuration
    language: str
    cwe: str
    lineage: str
    repetition: int
    status: str
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    kloc: float = 0
    localized: int = 0
    latency_ms: int = 0
    tokens: int = 0
    cost_microunits: int = 0
    ram_mb: int = 0
    vram_mb: int = 0
    unsafe_patches: int = 0
    regressions: int = 0
    correct_secure: int = 0

    def __post_init__(self) -> None:
        if (
            type(self.configuration) is not Configuration
            or self.language not in _LANGUAGES
            or not _token(self.cwe)
            or not _token(self.lineage)
            or type(self.repetition) is not int
            or not 1 <= self.repetition <= 3
            or not _token(self.status)
        ):
            raise BenchmarkValidationError("invalid benchmark cell identity")
        counts = (
            self.tp,
            self.fp,
            self.tn,
            self.fn,
            self.localized,
            self.latency_ms,
            self.tokens,
            self.cost_microunits,
            self.ram_mb,
            self.vram_mb,
            self.unsafe_patches,
            self.regressions,
            self.correct_secure,
        )
        if any(type(value) is not int or value < 0 for value in counts):
            raise BenchmarkValidationError("benchmark counts must be non-negative integers")
        if type(self.kloc) not in {int, float} or not math.isfinite(self.kloc) or self.kloc < 0:
            raise BenchmarkValidationError("kloc must be finite and non-negative")
        if self.localized > self.tp + self.fn:
            raise BenchmarkValidationError("localized count exceeds vulnerable denominator")
        if self.correct_secure > self.tp + self.fn:
            raise BenchmarkValidationError("repair count exceeds vulnerable denominator")


@dataclass(frozen=True, slots=True)
class Aggregate:
    configuration: Configuration
    tp: int
    fp: int
    tn: int
    fn: int
    valid: float
    precision: float
    recall: float
    f1: float
    precision_lower: float
    latency_p50: int
    latency_p95: int
    unsafe: int

    def __post_init__(self) -> None:
        if type(self.configuration) is not Configuration:
            raise BenchmarkValidationError("invalid aggregate configuration")
        if any(
            type(value) is not int or value < 0
            for value in (
                self.tp,
                self.fp,
                self.tn,
                self.fn,
                self.latency_p50,
                self.latency_p95,
                self.unsafe,
            )
        ):
            raise BenchmarkValidationError("invalid aggregate count")
        metrics = (self.valid, self.precision, self.recall, self.f1, self.precision_lower)
        if any(not _bounded_metric(value) for value in metrics):
            raise BenchmarkValidationError("invalid aggregate metric")
        if self.precision_lower > self.precision or self.latency_p50 > self.latency_p95:
            raise BenchmarkValidationError("inconsistent aggregate metric")


def aggregate(cells: tuple[BenchmarkCell, ...], configuration: Configuration) -> Aggregate:
    """Aggregate one configuration while keeping failed cells in completion denominators."""
    if type(cells) is not tuple or type(configuration) is not Configuration:
        raise BenchmarkValidationError("invalid aggregate request")
    if any(type(cell) is not BenchmarkCell for cell in cells):
        raise BenchmarkValidationError("invalid benchmark cell")
    values = tuple(cell for cell in cells if cell.configuration is configuration)
    tp = sum(cell.tp for cell in values)
    fp = sum(cell.fp for cell in values)
    tn = sum(cell.tn for cell in values)
    fn = sum(cell.fn for cell in values)
    completion = ratio(sum(cell.status == _COMPLETED for cell in values), len(values))
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    completed_latencies = tuple(cell.latency_ms for cell in values if cell.status == _COMPLETED)
    return Aggregate(
        configuration=configuration,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        valid=completion,
        precision=precision,
        recall=recall,
        f1=f1(precision, recall),
        precision_lower=wilson_lower(tp, tp + fp),
        latency_p50=percentile(completed_latencies, 0.50),
        latency_p95=percentile(completed_latencies, 0.95),
        unsafe=sum(cell.unsafe_patches for cell in values),
    )


def release_ready(
    hybrid: Aggregate,
    sast: Aggregate,
    paired_recall_lower: float | None = None,
) -> bool:
    """Apply release thresholds without accepting missing or mismatched evidence."""
    if type(hybrid) is not Aggregate or type(sast) is not Aggregate:
        return False
    if hybrid.configuration is not Configuration.HYBRID:
        return False
    if sast.configuration not in {Configuration.SEMGREP, Configuration.CODEQL}:
        return False
    if hybrid.tp + hybrid.fp == 0 or hybrid.tp + hybrid.fn == 0:
        return False
    if sast.tp + sast.fn == 0:
        return False
    if not isinstance(paired_recall_lower, (int, float)) or isinstance(paired_recall_lower, bool):
        return False
    if not math.isfinite(paired_recall_lower) or paired_recall_lower <= 0.0:
        return False
    return (
        hybrid.valid >= 0.99
        and sast.valid >= 0.99
        and hybrid.precision_lower >= 0.90
        and hybrid.recall - sast.recall >= 0.05
        and hybrid.unsafe == 0
    )


def paired_bootstrap_lower(
    hybrid: tuple[BenchmarkCell, ...],
    sast: tuple[BenchmarkCell, ...],
    samples: int = 1000,
) -> float:
    """Return the deterministic paired 95% lower bound for recall improvement.

    Sampling occurs over matched lineage groups. Repetitions stay inside their
    lineage, preventing a large family or a duplicate row from being treated as
    independent evidence.
    """
    if (
        type(hybrid) is not tuple
        or type(sast) is not tuple
        or type(samples) is not int
        or samples < 1
        or any(type(cell) is not BenchmarkCell for cell in hybrid + sast)
    ):
        return -1.0
    if any(cell.configuration is not Configuration.HYBRID for cell in hybrid):
        return -1.0
    sast_configurations = {cell.configuration for cell in sast}
    if len(sast_configurations) != 1 or not sast_configurations.issubset(
        {Configuration.SEMGREP, Configuration.CODEQL}
    ):
        return -1.0
    hybrid_keys = {(cell.language, cell.cwe, cell.lineage, cell.repetition) for cell in hybrid}
    sast_keys = {(cell.language, cell.cwe, cell.lineage, cell.repetition) for cell in sast}
    hybrid_cases = {key[:3] for key in hybrid_keys}
    sast_cases = {key[:3] for key in sast_keys}
    if hybrid_cases != sast_cases or len(hybrid_keys) != len(hybrid) or len(sast_keys) != len(sast):
        return -1.0
    left = _lineage_recall(hybrid)
    right = _lineage_recall(sast)
    if left is None or right is None or left.keys() != right.keys() or not left:
        return -1.0
    deltas = tuple(left[key] - right[key] for key in sorted(left))
    generator = random.Random(0)
    estimates = []
    for _ in range(samples):
        estimate = sum(generator.choice(deltas) for _ in deltas) / len(deltas)
        estimates.append(estimate)
    return _quantile_lower(tuple(estimates), 0.025)


def validate_matrix(cells: tuple[BenchmarkCell, ...]) -> bool:
    """Validate uniqueness, required configurations and matched case coverage."""
    if (
        type(cells) is not tuple
        or not cells
        or any(type(cell) is not BenchmarkCell for cell in cells)
    ):
        return False
    configurations = {cell.configuration for cell in cells}
    if not _REQUIRED.issubset(configurations):
        return False
    identities = [
        (cell.configuration, cell.language, cell.cwe, cell.lineage, cell.repetition)
        for cell in cells
    ]
    if len(set(identities)) != len(identities):
        return False
    case_sets: dict[Configuration, set[tuple[str, str, str]]] = defaultdict(set)
    repetitions: dict[tuple[Configuration, str, str, str], set[int]] = defaultdict(set)
    for cell in cells:
        case = (cell.language, cell.cwe, cell.lineage)
        case_sets[cell.configuration].add(case)
        repetitions[(cell.configuration, *case)].add(cell.repetition)
    reference = case_sets[Configuration.HYBRID]
    if not reference or any(case_sets[configuration] != reference for configuration in _REQUIRED):
        return False
    for key, observed in repetitions.items():
        expected = {1, 2, 3} if key[0] in _MODEL_CONFIGURATIONS else {1}
        if observed != expected:
            return False
    return True


def canonical_hash(
    cells: tuple[BenchmarkCell, ...],
    *,
    plan_pin: str,
    corpus_pin: str,
    config_pin: str,
) -> str:
    if (
        type(cells) is not tuple
        or any(type(cell) is not BenchmarkCell for cell in cells)
        or any(not _token(pin) for pin in (plan_pin, corpus_pin, config_pin))
    ):
        raise BenchmarkValidationError("invalid benchmark hash request")
    material = {
        "cells": [asdict(cell) for cell in cells],
        "config": config_pin,
        "corpus": corpus_pin,
        "plan": plan_pin,
    }
    payload = json.dumps(
        material,
        default=str,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _lineage_recall(
    cells: tuple[BenchmarkCell, ...],
) -> dict[tuple[str, str, str], float] | None:
    grouped: dict[tuple[str, str, str], list[BenchmarkCell]] = defaultdict(list)
    seen: set[tuple[str, str, str, int]] = set()
    for cell in cells:
        if cell.status != _COMPLETED:
            return None
        identity = (cell.language, cell.cwe, cell.lineage, cell.repetition)
        if identity in seen:
            return None
        seen.add(identity)
        grouped[identity[:3]].append(cell)
    result: dict[tuple[str, str, str], float] = {}
    for key, group in grouped.items():
        repetitions = {cell.repetition for cell in group}
        if repetitions != set(range(1, max(repetitions) + 1)):
            return None
        true_positive = sum(cell.tp for cell in group)
        false_negative = sum(cell.fn for cell in group)
        if true_positive + false_negative == 0:
            return None
        result[key] = ratio(true_positive, true_positive + false_negative)
    return result


def _quantile_lower(values: tuple[float, ...], quantile: float) -> float:
    ordered = sorted(values)
    rank = max(0, math.ceil(quantile * len(ordered)) - 1)
    return ordered[rank]


def _token(value: object) -> bool:
    return type(value) is str and _TOKEN.fullmatch(value) is not None


def _bounded_metric(value: object) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    return math.isfinite(value) and 0.0 <= value <= 1.0


__all__ = [
    "Aggregate",
    "BenchmarkCell",
    "BenchmarkValidationError",
    "Configuration",
    "aggregate",
    "canonical_hash",
    "paired_bootstrap_lower",
    "release_ready",
    "validate_matrix",
]
