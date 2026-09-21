"""Budgeted RLM-inspired discovery experiment, restricted to evaluation-only output."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import StrEnum

from .code_index import CodeIndex


class ExperimentSplit(StrEnum):
    DEVELOPMENT = "DEVELOPMENT"
    HELD_OUT = "HELD_OUT"


@dataclass(frozen=True, slots=True)
class ExperimentPins:
    corpus_sha256: str
    model_sha256: str
    prompt_sha256: str
    tool_sha256: str
    policy_sha256: str
    index_sha256: str


@dataclass(frozen=True, slots=True)
class ExperimentBudget:
    max_calls: int
    max_tokens: int
    max_result_bytes: int
    max_wall_ms: int
    max_recursion_depth: int


@dataclass(frozen=True, slots=True)
class ExperimentCell:
    case_id: str
    split: ExperimentSplit
    variant: str
    status: str
    calls: int
    tokens: int
    result_bytes: int
    wall_ms: int
    depth: int


def run_cell(
    *,
    index: CodeIndex,
    case_id: str,
    split: ExperimentSplit,
    variant: str,
    pins: ExperimentPins,
    budget: ExperimentBudget,
    query_id: str,
) -> ExperimentCell:
    if (
        not case_id
        or variant not in {"baseline", "rlm"}
        or any(len(value) != 64 for value in asdict(pins).values())
    ):
        raise ValueError("experiment identity is invalid")
    if budget.max_calls < 1 or budget.max_result_bytes < 0 or budget.max_recursion_depth < 0:
        raise ValueError("experiment budget is invalid")
    result = index.query(query_id, limit=min(64, budget.max_calls))
    status = "COMPLETED" if result.result_bytes <= budget.max_result_bytes else "BUDGET_EXHAUSTED"
    return ExperimentCell(case_id, split, variant, status, 1, 0, result.result_bytes, 0, 0)


def canonical_receipt(
    *, pins: ExperimentPins, cells: tuple[ExperimentCell, ...]
) -> dict[str, object]:
    if any(
        cell.split is ExperimentSplit.HELD_OUT and "expect" in cell.case_id.lower()
        for cell in cells
    ):
        raise ValueError("locked expectation metadata is forbidden")
    material = {
        "evaluation_only": True,
        "promoted": False,
        "pins": asdict(pins),
        "cells": [asdict(cell) for cell in cells],
    }
    return {
        "result_sha256": hashlib.sha256(
            json.dumps(
                material, default=str, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            ).encode("ascii")
        ).hexdigest(),
        "metadata": material,
    }
