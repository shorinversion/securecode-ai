"""Fail-closed metadata inventory for a future external release corpus.

The command intentionally accepts only an explicit local JSON manifest. It
does not fetch, open, compile, or execute candidate corpus sources. Its output
is a source-free count and eligibility report, never a benchmark result.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final, NoReturn, cast

SCHEMA_VERSION: Final = "securecode.release-corpus-inventory.v1"
_DIGEST_PREFIX: Final = "sha256:"
_SPLITS: Final = frozenset({"development", "calibration", "held-out"})
_LABELS: Final = frozenset({"vulnerable", "fixed-safe"})
_TOPOLOGIES: Final = frozenset({"single-file", "inter-file"})
_ROOT_KEYS: Final = frozenset({"datasets", "schema_version"})
_DATASET_KEYS: Final = frozenset(
    {
        "cases",
        "content_sha256",
        "dataset_id",
        "license_spdx",
        "revision",
        "resolution",
        "source_id",
        "version",
    }
)
_CASE_KEYS: Final = frozenset(
    {
        "case_id",
        "content_sha256",
        "cwe_id",
        "expected_label",
        "language",
        "lineage_groups",
        "split",
        "topology",
    }
)
_MINIMUM_CASES: Final = 600
_LANGUAGE_MINIMUMS: Final = {"go": 200, "javascript-typescript": 200, "python": 200}
_LANGUAGE_LABEL_MINIMUM: Final = 100
_SPLIT_NUMERATORS: Final = {"development": 40, "calibration": 20, "held-out": 40}
_MAX_MANIFEST_BYTES: Final = 16 * 1024 * 1024
_CWE_PREFIX: Final = "CWE-"
_MAX_CWE_DIGITS: Final = 6


class ReleaseCorpusInventoryError(ValueError):
    """Closed failure for untrusted release-candidate inventory metadata."""


def _fail(message: str) -> NoReturn:
    raise ReleaseCorpusInventoryError(message)


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON key")
        result[key] = value
    return result


def _reject_number(_: str) -> NoReturn:
    _fail("JSON numbers are not permitted")


def _object(value: object, name: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(f"{name} must be an object")
    return cast(dict[str, Any], value)


def _array(value: object, name: str) -> list[Any]:
    if type(value) is not list:
        _fail(f"{name} must be an array")
    return value


def _string(value: object, name: str) -> str:
    if type(value) is not str or not value:
        _fail(f"{name} must be a non-empty string")
    return value


def _digest(value: object, name: str) -> str:
    encoded = _string(value, name)
    digest = encoded.removeprefix(_DIGEST_PREFIX)
    if (
        not encoded.startswith(_DIGEST_PREFIX)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        _fail(f"{name} must be a typed lowercase SHA-256 digest")
    return digest


def _closed_keys(document: dict[str, Any], expected: frozenset[str], name: str) -> None:
    if set(document) != expected:
        _fail(f"{name} keys are not closed")


def _load_manifest(path: Path) -> dict[str, Any]:
    if not path.is_absolute() or path.is_symlink():
        _fail("manifest must be an absolute regular file")
    try:
        resolved = path.resolve(strict=True)
        if resolved != path:
            _fail("manifest must be an absolute regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow:
            flags |= nofollow
        descriptor = os.open(resolved, flags)
        with os.fdopen(descriptor, "rb") as handle:
            details = os.fstat(handle.fileno())
            if not stat.S_ISREG(details.st_mode):
                _fail("manifest must be an absolute regular file")
            encoded = handle.read(_MAX_MANIFEST_BYTES + 1)
        if len(encoded) > _MAX_MANIFEST_BYTES:
            _fail("manifest must be an absolute regular file")
        value = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_number,
            parse_float=_reject_number,
            parse_int=_reject_number,
        )
    except ReleaseCorpusInventoryError:
        raise
    except (OSError, RecursionError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ReleaseCorpusInventoryError("manifest is unreadable or invalid JSON") from error
    return _object(value, "manifest")


def inventory_manifest(path: Path) -> dict[str, object]:
    """Validate metadata and return only source-free counts and shortfalls."""

    manifest = _load_manifest(path)
    _closed_keys(manifest, _ROOT_KEYS, "manifest")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        _fail("manifest schema version is invalid")
    datasets = _array(manifest.get("datasets"), "datasets")
    if not datasets:
        _fail("datasets must not be empty")

    dataset_ids: set[str] = set()
    case_ids: set[str] = set()
    content_ids: set[str] = set()
    lineage_splits: dict[str, str] = {}
    by_language = dict.fromkeys(_LANGUAGE_MINIMUMS, 0)
    by_split = dict.fromkeys(sorted(_SPLITS), 0)
    by_cwe: dict[str, int] = {}
    by_label = dict.fromkeys(sorted(_LABELS), 0)
    by_language_label = {
        language: dict.fromkeys(sorted(_LABELS), 0) for language in sorted(_LANGUAGE_MINIMUMS)
    }
    by_topology = dict.fromkeys(sorted(_TOPOLOGIES), 0)
    total = 0
    excluded_dataset_count = 0

    for raw_dataset in datasets:
        dataset = _object(raw_dataset, "dataset")
        _closed_keys(dataset, _DATASET_KEYS, "dataset")
        dataset_id = _string(dataset.get("dataset_id"), "dataset_id")
        if dataset_id in dataset_ids:
            _fail("dataset_id must be unique")
        dataset_ids.add(dataset_id)
        _string(dataset.get("version"), "version")
        _string(dataset.get("source_id"), "source_id")
        _string(dataset.get("revision"), "revision")
        _string(dataset.get("license_spdx"), "license_spdx")
        _digest(dataset.get("content_sha256"), "dataset content_sha256")
        resolution = _string(dataset.get("resolution"), "dataset resolution")
        if resolution not in {"resolved", "unresolved"}:
            _fail("dataset resolution is invalid")

        cases = _array(dataset.get("cases"), "dataset cases")
        if not cases:
            _fail("dataset cases must not be empty")
        if resolution == "unresolved":
            excluded_dataset_count += 1
            continue
        for raw_case in cases:
            case = _object(raw_case, "case")
            _closed_keys(case, _CASE_KEYS, "case")
            case_id = _string(case.get("case_id"), "case_id")
            if case_id in case_ids:
                _fail("case_id must be unique")
            case_ids.add(case_id)
            content_id = _digest(case.get("content_sha256"), "case content_sha256")
            if content_id in content_ids:
                _fail("case content identity must be unique")
            content_ids.add(content_id)
            language = _string(case.get("language"), "case language")
            if language not in by_language:
                _fail("case language is unsupported")
            cwe_id = _string(case.get("cwe_id"), "case cwe_id")
            cwe_number = cwe_id.removeprefix(_CWE_PREFIX)
            if (
                not cwe_id.startswith(_CWE_PREFIX)
                or not cwe_number
                or len(cwe_number) > _MAX_CWE_DIGITS
                or not cwe_number.isascii()
                or not cwe_number.isdecimal()
                or cwe_number.startswith("0")
            ):
                _fail("case cwe_id is invalid")
            label = _string(case.get("expected_label"), "case expected_label")
            if label not in _LABELS:
                _fail("case expected_label is invalid")
            topology = _string(case.get("topology"), "case topology")
            if topology not in _TOPOLOGIES:
                _fail("case topology is invalid")
            split = _string(case.get("split"), "case split")
            if split not in _SPLITS:
                _fail("case split is invalid")
            lineages = _array(case.get("lineage_groups"), "case lineage_groups")
            if not lineages:
                _fail("case lineage_groups must not be empty")
            local_lineages: set[str] = set()
            for raw_lineage in lineages:
                lineage = _string(raw_lineage, "lineage_group")
                if lineage in local_lineages:
                    _fail("case lineage_groups must be unique")
                local_lineages.add(lineage)
                previous_split = lineage_splits.setdefault(lineage, split)
                if previous_split != split:
                    _fail("lineage group crosses splits")
            total += 1
            by_language[language] += 1
            by_split[split] += 1
            by_cwe[cwe_id] = by_cwe.get(cwe_id, 0) + 1
            by_label[label] += 1
            by_language_label[language][label] += 1
            by_topology[topology] += 1

    shortfalls = _shortfalls(total, by_language, by_language_label, by_split)
    split_ratio_valid = _has_exact_split_ratio(total, by_split)
    return {
        "schema_version": SCHEMA_VERSION,
        "dataset_count": len(dataset_ids),
        "excluded_dataset_count": excluded_dataset_count,
        "case_count": total,
        "language_counts": dict(sorted(by_language.items())),
        "split_counts": dict(sorted(by_split.items())),
        "cwe_counts": dict(sorted(by_cwe.items())),
        "label_counts": dict(sorted(by_label.items())),
        "language_label_counts": {
            language: dict(sorted(labels.items()))
            for language, labels in sorted(by_language_label.items())
        },
        "topology_counts": dict(sorted(by_topology.items())),
        "lineage_group_count": len(lineage_splits),
        "release_candidate_eligible": (
            not shortfalls and split_ratio_valid and excluded_dataset_count == 0
        ),
        "shortfalls": shortfalls,
        "split_ratio_valid": split_ratio_valid,
    }


def _shortfalls(
    total: int,
    by_language: dict[str, int],
    by_language_label: dict[str, dict[str, int]],
    by_split: dict[str, int],
) -> dict[str, int]:
    result = {"case_count": max(0, _MINIMUM_CASES - total)}
    for language, required in _LANGUAGE_MINIMUMS.items():
        result[f"language:{language}"] = max(0, required - by_language[language])
        for label in sorted(_LABELS):
            result[f"language_label:{language}:{label}"] = max(
                0, _LANGUAGE_LABEL_MINIMUM - by_language_label[language][label]
            )
    for split, numerator in _SPLIT_NUMERATORS.items():
        required = (_MINIMUM_CASES * numerator) // 100
        result[f"split:{split}"] = max(0, required - by_split[split])
    return {key: value for key, value in sorted(result.items()) if value}


def _has_exact_split_ratio(total: int, by_split: dict[str, int]) -> bool:
    return total > 0 and all(
        by_split[split] * 100 == total * numerator for split, numerator in _SPLIT_NUMERATORS.items()
    )


def canonical_inventory_json(path: Path) -> str:
    """Render the validated source-free inventory with stable bytes."""

    return (
        json.dumps(
            inventory_manifest(path), ensure_ascii=True, separators=(",", ":"), sort_keys=True
        )
        + "\n"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        print(canonical_inventory_json(arguments.manifest), end="")
    except ReleaseCorpusInventoryError:
        print("release corpus inventory rejected", file=sys.stderr)
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
