"""Fail-closed, source-free provenance preflight for a release corpus batch.

The command reads exactly one explicit local JSON input.  It deliberately does
not dereference source identifiers, download data, run commands, or execute
candidate source.  A positive result only says that supplied metadata pins are
complete; it is not corpus admission or an evaluation result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final, NoReturn, cast

SCHEMA_VERSION: Final = "securecode.release-corpus-preflight.v1"
_DIGEST_PREFIX: Final = "sha256:"
_MAX_INPUT_BYTES: Final = 16 * 1024 * 1024
_SPLITS: Final = frozenset({"development", "calibration", "held-out"})
_PINNED: Final = "pinned"
_UNRESOLVED: Final = "unresolved"
_ROOT_KEYS: Final = frozenset({"batches", "schema_version"})
_BATCH_KEYS: Final = frozenset(
    {"acquisition", "batch_id", "caller_resolved", "cases", "dataset", "source"}
)
_SOURCE_KEYS: Final = frozenset({"license_evidence", "license_spdx", "revision", "source_id"})
_DATASET_KEYS: Final = frozenset(
    {
        "content_evidence",
        "content_sha256",
        "dataset_id",
        "license_evidence",
        "license_spdx",
        "version",
    }
)
_ACQUISITION_KEYS: Final = frozenset({"procedure_id", "procedure_sha256"})
_CASE_KEYS: Final = frozenset(
    {"case_id", "content_evidence", "content_sha256", "ground_truth", "lineage", "split"}
)
_LINEAGE_KEYS: Final = frozenset({"clone", "cve_fix", "repository", "root_cause"})
_GROUND_TRUTH_KEYS: Final = frozenset({"evidence", "label", "status"})
_EVIDENCE_KEYS: Final = frozenset({"sha256", "status"})
_PREREQUISITES: Final = (
    "source_license",
    "dataset_license",
    "content",
    "ground_truth",
)
_SOURCE_LICENSE_DOMAIN: Final = "securecode.release-corpus-preflight.source-license.v1"
_DATASET_LICENSE_DOMAIN: Final = "securecode.release-corpus-preflight.dataset-license.v1"
_DATASET_CONTENT_DOMAIN: Final = "securecode.release-corpus-preflight.dataset-content.v1"
_CASE_CONTENT_DOMAIN: Final = "securecode.release-corpus-preflight.case-content.v1"
_GROUND_TRUTH_DOMAIN: Final = "securecode.release-corpus-preflight.ground-truth.v1"
_ACQUISITION_DOMAIN: Final = "securecode.release-corpus-preflight.acquisition.v1"


class ReleaseCorpusPreflightError(ValueError):
    """Closed failure for untrusted release-corpus provenance metadata."""


def _fail(message: str) -> NoReturn:
    raise ReleaseCorpusPreflightError(message)


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
    return encoded


def _closed_keys(document: dict[str, Any], expected: frozenset[str], name: str) -> None:
    if set(document) != expected:
        _fail(f"{name} keys are not closed")


def _immutable_revision(value: object) -> str:
    revision = _string(value, "source revision")
    commit = revision.removeprefix("commit:")
    if (
        not revision.startswith("commit:")
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
    ):
        _fail("source revision must be an immutable lowercase commit SHA-1")
    return revision


def _binding_digest(domain: str, fields: dict[str, object]) -> str:
    encoded = json.dumps(
        {"domain": domain, **fields}, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return _DIGEST_PREFIX + hashlib.sha256(encoded).hexdigest()


def _evidence_pin(value: object, name: str, expected_digest: str) -> bool:
    pin = _object(value, name)
    _closed_keys(pin, _EVIDENCE_KEYS, name)
    status = pin.get("status")
    evidence = pin.get("sha256")
    if status == _PINNED:
        actual_digest = _digest(evidence, f"{name} sha256")
        if actual_digest != expected_digest:
            _fail(f"{name} does not bind its metadata")
        return True
    if status == _UNRESOLVED and evidence is None:
        return False
    _fail(f"{name} must be a pinned digest or explicit unresolved evidence")


def _ground_truth_pin(value: object, expected_digest: str) -> bool:
    ground_truth = _object(value, "ground_truth")
    _closed_keys(ground_truth, _GROUND_TRUTH_KEYS, "ground_truth")
    status = ground_truth.get("status")
    evidence = ground_truth.get("evidence")
    if status == _PINNED:
        actual_digest = _digest(evidence, "ground_truth evidence")
        if actual_digest != expected_digest:
            _fail("ground_truth does not bind its metadata")
        return True
    if status == _UNRESOLVED and evidence is None:
        return False
    _fail("ground_truth must be a pinned digest or explicit unresolved evidence")


def _load_input(path: Path) -> dict[str, Any]:
    """Read only the explicitly supplied JSON file through one file descriptor."""

    if not path.is_absolute() or path.is_symlink():
        _fail("input must be an absolute regular file")
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow:
            flags |= nofollow
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            details = os.fstat(handle.fileno())
            if not stat.S_ISREG(details.st_mode):
                _fail("input must be an absolute regular file")
            encoded = handle.read(_MAX_INPUT_BYTES + 1)
        if len(encoded) > _MAX_INPUT_BYTES:
            _fail("input must be an absolute regular file")
        value = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_number,
            parse_float=_reject_number,
            parse_int=_reject_number,
        )
    except ReleaseCorpusPreflightError:
        raise
    except (OSError, RecursionError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ReleaseCorpusPreflightError("input is unreadable or invalid JSON") from error
    return _object(value, "input")


def preflight_manifest(path: Path) -> dict[str, object]:
    """Validate provenance pins and return deterministic source-free readiness counts."""

    document = _load_input(path)
    _closed_keys(document, _ROOT_KEYS, "input")
    if document.get("schema_version") != SCHEMA_VERSION:
        _fail("input schema version is invalid")
    batches = _array(document.get("batches"), "batches")
    if not batches:
        _fail("batches must not be empty")

    batch_ids: set[str] = set()
    dataset_ids: set[str] = set()
    case_ids: set[str] = set()
    content_ids: set[str] = set()
    lineage_splits: dict[tuple[str, str], str] = {}
    split_counts = dict.fromkeys(sorted(_SPLITS), 0)
    unresolved = dict.fromkeys(_PREREQUISITES, 0)
    ready_batch_count = 0
    ready_case_count = 0
    caller_resolved_batch_count = 0
    case_count = 0

    for raw_batch in batches:
        batch = _object(raw_batch, "batch")
        _closed_keys(batch, _BATCH_KEYS, "batch")
        batch_id = _string(batch.get("batch_id"), "batch_id")
        if batch_id in batch_ids:
            _fail("batch_id must be unique")
        batch_ids.add(batch_id)
        if type(batch.get("caller_resolved")) is not bool:
            _fail("caller_resolved must be a boolean")
        if batch["caller_resolved"]:
            caller_resolved_batch_count += 1

        source = _object(batch.get("source"), "source")
        _closed_keys(source, _SOURCE_KEYS, "source")
        source_id = _string(source.get("source_id"), "source_id")
        revision = _immutable_revision(source.get("revision"))
        source_license_spdx = _string(source.get("license_spdx"), "source license_spdx")
        source_license_ready = _evidence_pin(
            source.get("license_evidence"),
            "source license_evidence",
            _binding_digest(
                _SOURCE_LICENSE_DOMAIN,
                {"license_spdx": source_license_spdx, "revision": revision, "source_id": source_id},
            ),
        )

        dataset = _object(batch.get("dataset"), "dataset")
        _closed_keys(dataset, _DATASET_KEYS, "dataset")
        dataset_id = _string(dataset.get("dataset_id"), "dataset_id")
        if dataset_id in dataset_ids:
            _fail("dataset_id must be unique")
        dataset_ids.add(dataset_id)
        version = _string(dataset.get("version"), "dataset version")
        dataset_license_spdx = _string(dataset.get("license_spdx"), "dataset license_spdx")
        dataset_content_sha256 = _digest(dataset.get("content_sha256"), "dataset content_sha256")
        dataset_license_ready = _evidence_pin(
            dataset.get("license_evidence"),
            "dataset license_evidence",
            _binding_digest(
                _DATASET_LICENSE_DOMAIN,
                {
                    "dataset_id": dataset_id,
                    "license_spdx": dataset_license_spdx,
                    "revision": revision,
                    "source_id": source_id,
                    "version": version,
                },
            ),
        )
        dataset_content_ready = _evidence_pin(
            dataset.get("content_evidence"),
            "dataset content_evidence",
            _binding_digest(
                _DATASET_CONTENT_DOMAIN,
                {
                    "content_sha256": dataset_content_sha256,
                    "dataset_id": dataset_id,
                    "revision": revision,
                    "source_id": source_id,
                    "version": version,
                },
            ),
        )

        acquisition = _object(batch.get("acquisition"), "acquisition")
        _closed_keys(acquisition, _ACQUISITION_KEYS, "acquisition")
        procedure_id = _string(acquisition.get("procedure_id"), "acquisition procedure_id")
        procedure_digest = _digest(
            acquisition.get("procedure_sha256"), "acquisition procedure_sha256"
        )
        if procedure_digest != _binding_digest(
            _ACQUISITION_DOMAIN,
            {"procedure_id": procedure_id, "revision": revision, "source_id": source_id},
        ):
            _fail("acquisition procedure_sha256 does not bind its metadata")

        cases = _array(batch.get("cases"), "batch cases")
        if not cases:
            _fail("batch cases must not be empty")
        batch_content_ready = dataset_content_ready
        batch_ground_truth_ready = True
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
            split = _string(case.get("split"), "case split")
            if split not in _SPLITS:
                _fail("case split is invalid")
            lineage = _object(case.get("lineage"), "case lineage")
            _closed_keys(lineage, _LINEAGE_KEYS, "case lineage")
            lineage_record: dict[str, str] = {}
            for dimension in sorted(_LINEAGE_KEYS):
                group = _string(lineage.get(dimension), f"lineage {dimension}")
                lineage_record[dimension] = group
                identity = (dimension, group)
                previous_split = lineage_splits.setdefault(identity, split)
                if previous_split != split:
                    _fail("lineage group crosses splits")
            content_ready = _evidence_pin(
                case.get("content_evidence"),
                "case content_evidence",
                _binding_digest(
                    _CASE_CONTENT_DOMAIN,
                    {
                        "case_id": case_id,
                        "content_sha256": content_id,
                        "dataset_id": dataset_id,
                        "revision": revision,
                        "source_id": source_id,
                        "version": version,
                        "split": split,
                        "lineage": lineage_record,
                    },
                ),
            )
            ground_truth = _object(case.get("ground_truth"), "ground_truth")
            _closed_keys(ground_truth, _GROUND_TRUTH_KEYS, "ground_truth")
            ground_truth_label = _string(ground_truth.get("label"), "ground_truth label")
            ground_truth_ready = _ground_truth_pin(
                ground_truth,
                _binding_digest(
                    _GROUND_TRUTH_DOMAIN,
                    {
                        "case_id": case_id,
                        "content_sha256": content_id,
                        "dataset_id": dataset_id,
                        "revision": revision,
                        "source_id": source_id,
                        "version": version,
                        "label": ground_truth_label,
                        "split": split,
                        "lineage": lineage_record,
                    },
                ),
            )
            batch_content_ready = batch_content_ready and content_ready
            batch_ground_truth_ready = batch_ground_truth_ready and ground_truth_ready
            case_count += 1
            split_counts[split] += 1

        if not source_license_ready:
            unresolved["source_license"] += 1
        if not dataset_license_ready:
            unresolved["dataset_license"] += 1
        if not batch_content_ready:
            unresolved["content"] += 1
        if not batch_ground_truth_ready:
            unresolved["ground_truth"] += 1
        batch_ready = (
            source_license_ready
            and dataset_license_ready
            and batch_content_ready
            and batch_ground_truth_ready
        )
        if batch_ready:
            ready_batch_count += 1
            ready_case_count += len(cases)

    unresolved_prerequisites = {key: value for key, value in unresolved.items() if value}
    batch_count = len(batch_ids)
    return {
        "schema_version": SCHEMA_VERSION,
        "batch_count": batch_count,
        "ready_batch_count": ready_batch_count,
        "unresolved_batch_count": batch_count - ready_batch_count,
        "case_count": case_count,
        "ready_case_count": ready_case_count,
        "unresolved_case_count": case_count - ready_case_count,
        "split_counts": dict(sorted(split_counts.items())),
        "lineage_group_count": len(lineage_splits),
        "caller_resolved_batch_count": caller_resolved_batch_count,
        "preflight_ready": ready_batch_count == batch_count,
        "unresolved_prerequisites": unresolved_prerequisites,
    }


def canonical_preflight_json(path: Path) -> str:
    """Render a stable, source-free preflight report."""

    return (
        json.dumps(
            preflight_manifest(path), ensure_ascii=True, separators=(",", ":"), sort_keys=True
        )
        + "\n"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        print(canonical_preflight_json(arguments.input), end="")
    except ReleaseCorpusPreflightError:
        print("release corpus preflight rejected", file=sys.stderr)
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
