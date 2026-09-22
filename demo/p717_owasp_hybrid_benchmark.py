"""Reconcile the public OWASP Python corpus through SecureCode discovery lanes.

The runner never executes corpus files and never sends them to a provider.  It
consumes a separately recorded, source-bound model discovery stream, produces
independent CWE-89 scanner evidence from the same file bytes, and records the
two lanes and their verdict.  Reports contain case identifiers, hashes and
metrics only.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import stat
from dataclasses import dataclass
from pathlib import Path

from securecode_ai.adapters import (
    analyze_python_ast,
    build_python_symbol_index,
    scan_python_cwe89,
)

_SCHEMA = "securecode.p717.owasp-hybrid.v1"
_EXPECTED = "expectedresults-0.1.csv"
_MODEL_RECORD_MAX_BYTES = 512 * 1024


class BenchmarkError(ValueError):
    """Safe benchmark setup error without source-content echoing."""


@dataclass(frozen=True, slots=True)
class Case:
    case_id: str
    expected_vulnerable: bool
    cwe: str
    source: Path
    source_sha256: str


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _load_cases(dataset: Path) -> tuple[Case, ...]:
    expected = dataset / _EXPECTED
    code = dataset / "testcode"
    if not expected.is_file() or not code.is_dir():
        raise BenchmarkError("OWASP dataset layout is invalid")
    cases: list[Case] = []
    with expected.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader, None)
        if header is None or len(header) < 4 or header[0].strip().lstrip("#").strip() != "test name":
            raise BenchmarkError("OWASP expected-results header is invalid")
        for row in reader:
            if len(row) < 4:
                raise BenchmarkError("OWASP expected-results row is invalid")
            case_id = row[0].strip()
            vulnerable = row[2].strip()
            cwe_number = row[3].strip()
            cwe = f"CWE-{cwe_number}" if cwe_number.isdigit() else None
            if not isinstance(case_id, str) or not isinstance(cwe, str):
                raise BenchmarkError("OWASP expected-results row is invalid")
            if vulnerable not in {"true", "false"}:
                raise BenchmarkError("OWASP expected-results label is invalid")
            source = code / f"{case_id}.py"
            try:
                mode = source.lstat().st_mode
                content = source.read_bytes()
            except OSError as error:
                raise BenchmarkError("OWASP source cannot be read") from error
            if not stat.S_ISREG(mode) or source.is_symlink() or not content:
                raise BenchmarkError("OWASP source is unsafe or empty")
            cases.append(Case(case_id, vulnerable == "true", cwe, source, _sha256(content)))
    if len(cases) != len({case.case_id for case in cases}) or not cases:
        raise BenchmarkError("OWASP cases are duplicated or empty")
    return tuple(sorted(cases, key=lambda item: item.case_id))


def _load_model_records(path: Path, cases: tuple[Case, ...]) -> dict[str, dict[str, object]]:
    expected_hashes = {case.case_id: case.source_sha256 for case in cases}
    records: dict[str, dict[str, object]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise BenchmarkError("model record stream cannot be read") from error
    for line in lines:
        if not line or len(line.encode("utf-8")) > _MODEL_RECORD_MAX_BYTES:
            continue
        try:
            item = json.loads(line, object_pairs_hook=_closed_object)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(item, dict):
            continue
        case_id = item.get("case_id")
        digest = item.get("source_sha256")
        status = item.get("status")
        result = item.get("result")
        if (
            not isinstance(case_id, str)
            or expected_hashes.get(case_id) != digest
            or status != "completed"
            or not isinstance(result, dict)
            or type(result.get("vulnerable")) is not bool
            or case_id in records
        ):
            continue
        records[case_id] = item
    return records


def _scanner(case: Case) -> dict[str, object]:
    try:
        source = case.source.read_bytes()
        if _sha256(source) != case.source_sha256:
            raise BenchmarkError("OWASP source changed during benchmark")
        index = build_python_symbol_index(
            repository_id="owasp-benchmark-python",
            revision=case.source_sha256[:40],
            path=case.source.name,
            content_sha256=case.source_sha256,
            source=source,
        )
        result = scan_python_cwe89(index, analyze_python_ast(index))
        return {
            "status": "SUCCEEDED",
            "supported_cwe": "CWE-89",
            "signal_count": len(result.signals),
            "signal_lines": sorted({signal.sink.start_point.row + 1 for signal in result.signals}),
            "scan_sha256": result.scan_sha256,
        }
    except Exception:
        return {
            "status": "INDETERMINATE",
            "supported_cwe": "CWE-89",
            "signal_count": 0,
            "signal_lines": [],
            "scan_sha256": None,
        }


def _model_vulnerable(record: dict[str, object] | None) -> bool | None:
    if record is None:
        return None
    result = record.get("result")
    if not isinstance(result, dict) or type(result.get("vulnerable")) is not bool:
        return None
    return result["vulnerable"]


def _metric(rows: list[dict[str, object]], key: str) -> dict[str, object]:
    completed = [row for row in rows if type(row.get(key)) is bool]
    tp = sum(row["expected_vulnerable"] is True and row[key] is True for row in completed)
    fp = sum(row["expected_vulnerable"] is False and row[key] is True for row in completed)
    fn = sum(row["expected_vulnerable"] is True and row[key] is False for row in completed)
    tn = sum(row["expected_vulnerable"] is False and row[key] is False for row in completed)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return {
        "denominator": len(rows),
        "valid": len(completed),
        "missing_or_indeterminate": len(rows) - len(completed),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None,
    }


def _run(dataset: Path, records_path: Path) -> dict[str, object]:
    cases = _load_cases(dataset)
    records = _load_model_records(records_path, cases)
    rows: list[dict[str, object]] = []
    for case in cases:
        scanner = _scanner(case)
        model = _model_vulnerable(records.get(case.case_id))
        scanner_vulnerable: bool | None = (
            bool(scanner["signal_count"])
            if scanner["status"] == "SUCCEEDED" and case.cwe == "CWE-89"
            else None
        )
        hybrid: bool | None
        if model is None:
            hybrid = None
        elif scanner_vulnerable is None:
            hybrid = model
        else:
            hybrid = model or scanner_vulnerable
        rows.append(
            {
                "case_id": case.case_id,
                "cwe": case.cwe,
                "expected_vulnerable": case.expected_vulnerable,
                "source_sha256": case.source_sha256,
                "model_vulnerable": model,
                "scanner_vulnerable": scanner_vulnerable,
                "hybrid_vulnerable": hybrid,
                "scanner": scanner,
                "model_record_status": "COMPLETED" if model is not None else "MISSING_OR_INVALID",
            }
        )
    return {
        "schema_version": _SCHEMA,
        "dataset": {
            "path": str(dataset.resolve()),
            "expected_results_sha256": _sha256((dataset / _EXPECTED).read_bytes()),
            "case_count": len(cases),
        },
        "model_record_stream": {
            "path": str(records_path.resolve()),
            "sha256": _sha256(records_path.read_bytes()),
            "accepted_records": len(records),
        },
        "coverage": {
            "scanner_native_cwe": ["CWE-89"],
            "model_lane": "DeepSeek public-corpus discovery stream",
            "verdict": "model OR independent scanner for CWE-89; model only outside scanner support",
        },
        "metrics": {
            "model": _metric(rows, "model_vulnerable"),
            "scanner_cwe89_only": _metric(rows, "scanner_vulnerable"),
            "hybrid": _metric(rows, "hybrid_vulnerable"),
        },
        "by_cwe": {
            cwe: {
                "count": len(selected),
                "model": _metric(selected, "model_vulnerable"),
                "hybrid": _metric(selected, "hybrid_vulnerable"),
            }
            for cwe in sorted({row["cwe"] for row in rows})
            for selected in [[row for row in rows if row["cwe"] == cwe]]
        },
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--model-records", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = _run(args.dataset, args.model_records)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report["metrics"], ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
