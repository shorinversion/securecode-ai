"""Validate and merge the twelve deterministic-only benchmark shards."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from securecode_ai.core.release_benchmark import BenchmarkCell, Configuration, aggregate


ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "evidence"
PROJECT = ROOT.parents[1]
MANIFEST = PROJECT / "evaluation/release-corpus/cvefixes-manifest.json"
SHARDS = EVIDENCE / "deterministic-shards"
OUTPUT = EVIDENCE / "deterministic-600x1.json"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _language(value: str) -> str:
    return {"python": "python", "javascript-typescript": "js-ts", "go": "go"}[value]


def _validate_cell(cell: dict[str, Any], case: dict[str, Any], index: int) -> None:
    lineage = hashlib.sha256(case["lineage_groups"][0].encode()).hexdigest()
    identity = (
        cell.get("configuration"),
        cell.get("language"),
        cell.get("cwe"),
        cell.get("lineage"),
        cell.get("repetition"),
    )
    expected = (
        Configuration.DETERMINISTIC.value,
        _language(case["language"]),
        case["cwe_id"],
        lineage,
        1,
    )
    if identity != expected:
        raise ValueError(f"deterministic shard row identity mismatch at case {index}")
    flags = tuple(cell.get(key) for key in ("tp", "fp", "tn", "fn"))
    if any(type(flag) is not int for flag in flags) or sum(flags) != 1:
        raise ValueError(f"deterministic confusion flags invalid at case {index}")
    predicted = bool(cell["tp"] or cell["fp"])
    vulnerable = case["expected_label"] == "vulnerable"
    if flags != (
        int(predicted and vulnerable),
        int(predicted and not vulnerable),
        int(not predicted and not vulnerable),
        int(not predicted and vulnerable),
    ):
        raise ValueError(f"deterministic label mismatch at case {index}")


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    cases = sorted(manifest["datasets"][0]["cases"], key=lambda row: row["case_id"])
    if len(cases) != 600:
        raise ValueError("the pinned manifest must contain 600 cases")
    all_cells: list[dict[str, Any]] = []
    shard_records: list[dict[str, Any]] = []
    for shard_index in range(12):
        offset = shard_index * 50
        path = SHARDS / f"deterministic-shard-{shard_index:02d}.json"
        raw = path.read_bytes()
        result = json.loads(raw)
        cells = result.get("cells")
        if not isinstance(cells, list) or len(cells) != 50:
            raise ValueError(f"shard {shard_index} must contain exactly 50 cells")
        for local_index, cell in enumerate(cells):
            _validate_cell(cell, cases[offset + local_index], offset + local_index)
        all_cells.extend(cells)
        shard_records.append(
            {
                "file": path.relative_to(EVIDENCE).as_posix(),
                "offset": offset,
                "cell_count": len(cells),
                "sha256": _sha256(raw),
            }
        )
    if len(all_cells) != 600:
        raise ValueError("merged deterministic result must contain 600 cells")
    cells = tuple(
        BenchmarkCell(**{**cell, "configuration": Configuration(cell["configuration"])})
        for cell in all_cells
    )
    result = {
        "cells": all_cells,
        "aggregate": asdict(aggregate(cells, Configuration.DETERMINISTIC)),
        "shard_composition": "12 contiguous 50-case ranges from the same sorted pinned manifest",
    }
    OUTPUT.write_text(
        json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    record = {
        "schema_version": "securecode.submission-deterministic-shards.v1",
        "manifest_sha256": _sha256(MANIFEST.read_bytes()),
        "dataset_digest": manifest["datasets"][0]["content_sha256"],
        "total_cases": len(cases),
        "total_cells": len(all_cells),
        "shards": shard_records,
        "merged_output_sha256": _sha256(OUTPUT.read_bytes()),
        "status_counts": {
            status: sum(cell["status"] == status for cell in all_cells)
            for status in sorted({cell["status"] for cell in all_cells})
        },
    }
    (EVIDENCE / "deterministic-shards.json").write_text(
        json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
