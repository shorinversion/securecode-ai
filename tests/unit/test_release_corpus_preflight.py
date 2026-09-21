"""P7.49 source-free release-corpus provenance preflight controls."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "release_corpus_preflight.py"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "p7_6" / "release-corpus-preflight.json"
SPEC = importlib.util.spec_from_file_location("release_corpus_preflight", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _fixture() -> dict[str, Any]:
    value = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _write(tmp_path: Path, value: object) -> Path:
    path = tmp_path / "release-corpus-preflight.json"
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return path


def test_complete_exact_batch_reports_source_free_readiness() -> None:
    result = MODULE.preflight_manifest(FIXTURE_PATH)

    assert result == {
        "schema_version": MODULE.SCHEMA_VERSION,
        "batch_count": 1,
        "ready_batch_count": 1,
        "unresolved_batch_count": 0,
        "case_count": 1,
        "ready_case_count": 1,
        "unresolved_case_count": 0,
        "split_counts": {"calibration": 0, "development": 1, "held-out": 0},
        "lineage_group_count": 4,
        "caller_resolved_batch_count": 1,
        "preflight_ready": True,
        "unresolved_prerequisites": {},
    }
    rendered = MODULE.canonical_preflight_json(FIXTURE_PATH)
    assert "source:example-public" not in rendered
    assert rendered.endswith("\n")


def test_caller_resolution_flag_cannot_grant_readiness(tmp_path: Path) -> None:
    candidate = _fixture()
    candidate["batches"][0]["source"]["license_evidence"] = {
        "status": "unresolved",
        "sha256": None,
    }

    result = MODULE.preflight_manifest(_write(tmp_path, candidate))

    assert result["caller_resolved_batch_count"] == 1
    assert result["preflight_ready"] is False
    assert result["unresolved_batch_count"] == 1
    assert result["unresolved_prerequisites"] == {"source_license": 1}


@pytest.mark.parametrize(
    ("path", "replacement", "message"),
    (
        (("batches", 0, "source", "source_id"), "source:replacement", "does not bind"),
        (("batches", 0, "source", "revision"), "commit:" + "f" * 40, "does not bind"),
        (("batches", 0, "source", "license_spdx"), "Apache-2.0", "does not bind"),
        (("batches", 0, "dataset", "license_spdx"), "Apache-2.0", "does not bind"),
        (("batches", 0, "dataset", "content_sha256"), "sha256:" + "0" * 64, "does not bind"),
        (("batches", 0, "cases", 0, "content_sha256"), "sha256:" + "0" * 64, "does not bind"),
        (("batches", 0, "cases", 0, "ground_truth", "label"), "fixed-safe", "does not bind"),
        (
            ("batches", 0, "cases", 0, "ground_truth", "evidence"),
            "sha256:" + "0" * 64,
            "does not bind",
        ),
    ),
)
def test_replacing_bound_metadata_is_rejected(
    tmp_path: Path, path: tuple[object, ...], replacement: str, message: str
) -> None:
    candidate = _fixture()
    target: Any = candidate
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement

    with pytest.raises(MODULE.ReleaseCorpusPreflightError, match=message):
        MODULE.preflight_manifest(_write(tmp_path, candidate))


@pytest.mark.parametrize(
    "path",
    (
        ("batches", 0, "source", "license_evidence", "sha256"),
        ("batches", 0, "dataset", "license_evidence", "sha256"),
        ("batches", 0, "dataset", "content_evidence", "sha256"),
        ("batches", 0, "cases", 0, "content_evidence", "sha256"),
        ("batches", 0, "cases", 0, "ground_truth", "evidence"),
    ),
)
def test_replacing_a_bound_evidence_pin_is_rejected(
    tmp_path: Path, path: tuple[object, ...]
) -> None:
    candidate = _fixture()
    target: Any = candidate
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = "sha256:" + "0" * 64

    with pytest.raises(MODULE.ReleaseCorpusPreflightError, match="does not bind"):
        MODULE.preflight_manifest(_write(tmp_path, candidate))


@pytest.mark.parametrize(
    "path, replacement",
    (
        (("batches", 0, "cases", 0, "split"), "held-out"),
        (("batches", 0, "cases", 0, "lineage", "repository"), "repo:replacement"),
        (("batches", 0, "cases", 0, "lineage", "cve_fix"), "cve-fix:replacement"),
        (("batches", 0, "cases", 0, "lineage", "clone"), "clone:replacement"),
        (("batches", 0, "cases", 0, "lineage", "root_cause"), "root-cause:replacement"),
    ),
)
def test_split_and_each_lineage_dimension_are_bound_to_case_evidence(
    tmp_path: Path, path: tuple[object, ...], replacement: str
) -> None:
    candidate = _fixture()
    target: Any = candidate
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement

    with pytest.raises(MODULE.ReleaseCorpusPreflightError, match="does not bind"):
        MODULE.preflight_manifest(_write(tmp_path, candidate))


@pytest.mark.parametrize(
    "path, message",
    (
        (("batches", 0, "source", "revision"), "immutable lowercase commit"),
        (("batches", 0, "acquisition", "procedure_sha256"), "typed lowercase SHA-256"),
        (("batches", 0, "dataset", "content_sha256"), "typed lowercase SHA-256"),
    ),
)
def test_mutable_or_unpinned_identity_is_rejected(
    tmp_path: Path, path: tuple[object, ...], message: str
) -> None:
    candidate = _fixture()
    target: Any = candidate
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = "branch:main"

    with pytest.raises(MODULE.ReleaseCorpusPreflightError, match=message):
        MODULE.preflight_manifest(_write(tmp_path, candidate))


@pytest.mark.parametrize("field", ("repository", "cve_fix", "clone", "root_cause"))
def test_every_lineage_dimension_is_required(tmp_path: Path, field: str) -> None:
    candidate = _fixture()
    del candidate["batches"][0]["cases"][0]["lineage"][field]

    with pytest.raises(MODULE.ReleaseCorpusPreflightError, match="lineage keys are not closed"):
        MODULE.preflight_manifest(_write(tmp_path, candidate))


def test_any_complete_lineage_dimension_crossing_splits_is_rejected(tmp_path: Path) -> None:
    candidate = _fixture()
    copied = copy.deepcopy(candidate["batches"][0]["cases"][0])
    copied["case_id"] = "case-b"
    copied["content_sha256"] = "sha256:" + "1" * 64
    copied["split"] = "held-out"
    copied["lineage"]["clone"] = "clone:case-b"
    candidate["batches"][0]["cases"].append(copied)

    with pytest.raises(MODULE.ReleaseCorpusPreflightError, match="crosses splits"):
        MODULE.preflight_manifest(_write(tmp_path, candidate))


def test_balanced_but_ground_truth_unproven_batch_is_unresolved(tmp_path: Path) -> None:
    candidate = _fixture()
    original = candidate["batches"][0]["cases"][0]
    cases: list[dict[str, Any]] = []
    for index, split in enumerate(("development", "calibration", "held-out")):
        case = copy.deepcopy(original)
        case["case_id"] = f"case-{index}"
        case["content_sha256"] = "sha256:" + f"{index + 1:064x}"
        case["split"] = split
        case["lineage"] = {
            "repository": f"repo:{index}",
            "cve_fix": f"cve-fix:{index}",
            "clone": f"clone:{index}",
            "root_cause": f"root-cause:{index}",
        }
        case["content_evidence"] = {
            "status": "pinned",
            "sha256": MODULE._binding_digest(
                MODULE._CASE_CONTENT_DOMAIN,
                {
                    "case_id": case["case_id"],
                    "content_sha256": case["content_sha256"],
                    "dataset_id": candidate["batches"][0]["dataset"]["dataset_id"],
                    "revision": candidate["batches"][0]["source"]["revision"],
                    "source_id": candidate["batches"][0]["source"]["source_id"],
                    "version": candidate["batches"][0]["dataset"]["version"],
                    "split": case["split"],
                    "lineage": case["lineage"],
                },
            ),
        }
        case["ground_truth"] = {
            "status": "unresolved",
            "evidence": None,
            "label": "vulnerable",
        }
        cases.append(case)
    candidate["batches"][0]["cases"] = cases

    result = MODULE.preflight_manifest(_write(tmp_path, candidate))

    assert result["split_counts"] == {"calibration": 1, "development": 1, "held-out": 1}
    assert result["preflight_ready"] is False
    assert result["ready_case_count"] == 0
    assert result["unresolved_case_count"] == 3
    assert result["unresolved_prerequisites"] == {"ground_truth": 1}


def test_duplicate_case_identity_and_relative_input_are_rejected(tmp_path: Path) -> None:
    candidate = _fixture()
    duplicate = copy.deepcopy(candidate["batches"][0]["cases"][0])
    duplicate["case_id"] = "other-case"
    candidate["batches"][0]["cases"].append(duplicate)

    with pytest.raises(MODULE.ReleaseCorpusPreflightError, match="identity must be unique"):
        MODULE.preflight_manifest(_write(tmp_path, candidate))
    with pytest.raises(MODULE.ReleaseCorpusPreflightError, match="absolute regular file"):
        MODULE.preflight_manifest(Path("relative.json"))


def test_duplicate_json_keys_are_rejected(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":"securecode.release-corpus-preflight.v1","schema_version":"x","batches":[]}',
        encoding="utf-8",
    )

    with pytest.raises(MODULE.ReleaseCorpusPreflightError, match="duplicate JSON key"):
        MODULE.preflight_manifest(duplicate)
