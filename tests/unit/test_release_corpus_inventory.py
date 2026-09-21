"""P7.6 metadata-only release corpus inventory controls."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "release_corpus_inventory.py"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "p7_6" / "release-corpus-inventory.json"
SPEC = importlib.util.spec_from_file_location("release_corpus_inventory", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _fixture() -> dict[str, Any]:
    value = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _write(tmp_path: Path, value: object) -> Path:
    path = tmp_path / "release-corpus-inventory.json"
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return path


def test_valid_candidate_reports_counts_and_release_shortfalls() -> None:
    result = MODULE.inventory_manifest(FIXTURE_PATH)

    assert result["case_count"] == 6
    assert result["dataset_count"] == 1
    assert result["excluded_dataset_count"] == 0
    assert result["language_counts"] == {"go": 2, "javascript-typescript": 2, "python": 2}
    assert result["language_label_counts"] == {
        "go": {"fixed-safe": 1, "vulnerable": 1},
        "javascript-typescript": {"fixed-safe": 1, "vulnerable": 1},
        "python": {"fixed-safe": 1, "vulnerable": 1},
    }
    assert result["split_counts"] == {"calibration": 2, "development": 2, "held-out": 2}
    assert result["release_candidate_eligible"] is False
    assert result["shortfalls"] == {
        "case_count": 594,
        "language:go": 198,
        "language:javascript-typescript": 198,
        "language:python": 198,
        "language_label:go:fixed-safe": 99,
        "language_label:go:vulnerable": 99,
        "language_label:javascript-typescript:fixed-safe": 99,
        "language_label:javascript-typescript:vulnerable": 99,
        "language_label:python:fixed-safe": 99,
        "language_label:python:vulnerable": 99,
        "split:calibration": 118,
        "split:development": 238,
        "split:held-out": 238,
    }


def test_unresolved_dataset_is_excluded_from_counts(tmp_path: Path) -> None:
    candidate = _fixture()
    candidate["datasets"][0]["resolution"] = "unresolved"

    result = MODULE.inventory_manifest(_write(tmp_path, candidate))

    assert result["case_count"] == 0
    assert result["excluded_dataset_count"] == 1
    assert result["release_candidate_eligible"] is False


def test_lineage_cross_split_is_rejected(tmp_path: Path) -> None:
    candidate = _fixture()
    candidate["datasets"][0]["cases"][1]["lineage_groups"] = ["repo:py-dev"]

    with pytest.raises(MODULE.ReleaseCorpusInventoryError, match="crosses splits"):
        MODULE.inventory_manifest(_write(tmp_path, candidate))


@pytest.mark.parametrize(
    "mutate",
    (
        lambda document: document["datasets"][0].update({"unexpected": True}),
        lambda document: document["datasets"][0]["cases"][0].update({"language": "ruby"}),
        lambda document: document["datasets"][0]["cases"][1].update(
            {"content_sha256": document["datasets"][0]["cases"][0]["content_sha256"]}
        ),
        lambda document: document["datasets"][0].update({"resolution": "unknown"}),
    ),
)
def test_malformed_metadata_is_rejected(tmp_path: Path, mutate: object) -> None:
    candidate = copy.deepcopy(_fixture())
    assert callable(mutate)
    mutate(candidate)

    with pytest.raises(MODULE.ReleaseCorpusInventoryError):
        MODULE.inventory_manifest(_write(tmp_path, candidate))


def test_duplicate_json_keys_and_relative_manifest_are_rejected(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":"securecode.release-corpus-inventory.v1","schema_version":"x","datasets":[]}',
        encoding="utf-8",
    )

    with pytest.raises(MODULE.ReleaseCorpusInventoryError, match="duplicate JSON key"):
        MODULE.inventory_manifest(duplicate)
    with pytest.raises(MODULE.ReleaseCorpusInventoryError, match="absolute regular file"):
        MODULE.inventory_manifest(Path("relative.json"))


def test_deep_json_is_a_closed_rejection(tmp_path: Path) -> None:
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 10_000 + "0" + "]" * 10_000, encoding="utf-8")

    with pytest.raises(MODULE.ReleaseCorpusInventoryError, match="invalid JSON"):
        MODULE.inventory_manifest(deep)


@pytest.mark.parametrize("payload", ("9" * 5_000, "NaN", "1.0"))
def test_json_numbers_are_a_closed_rejection(tmp_path: Path, payload: str) -> None:
    numeric = tmp_path / "numeric.json"
    numeric.write_text(payload, encoding="utf-8")

    with pytest.raises(MODULE.ReleaseCorpusInventoryError):
        MODULE.inventory_manifest(numeric)


def test_manifest_over_the_read_limit_is_rejected(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MODULE._MAX_MANIFEST_BYTES + 1))

    with pytest.raises(MODULE.ReleaseCorpusInventoryError, match="absolute regular file"):
        MODULE.inventory_manifest(oversized)


def test_manifest_uses_a_nonblocking_descriptor_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _write(tmp_path, _fixture())
    observed: dict[str, int] = {}
    original_open = MODULE.os.open

    def track_open(path: object, flags: int, *args: int) -> int:
        observed["flags"] = flags
        descriptor: object = original_open(path, flags, *args)
        assert type(descriptor) is int
        return descriptor

    monkeypatch.setattr(MODULE.os, "open", track_open)

    MODULE.inventory_manifest(manifest)

    assert observed["flags"] & getattr(MODULE.os, "O_NONBLOCK", 0) == getattr(
        MODULE.os, "O_NONBLOCK", 0
    )


@pytest.mark.parametrize("cwe_id", ("CWE-not-a-number", "CWE-0", "CWE-000001", "CWE-1234567"))
def test_cwe_id_requires_bounded_positive_ascii_integer(tmp_path: Path, cwe_id: str) -> None:
    candidate = _fixture()
    candidate["datasets"][0]["cases"][0]["cwe_id"] = cwe_id

    with pytest.raises(MODULE.ReleaseCorpusInventoryError, match="cwe_id"):
        MODULE.inventory_manifest(_write(tmp_path, candidate))


def test_exact_600_case_three_language_inventory_is_eligible(tmp_path: Path) -> None:
    languages = ("python", "javascript-typescript", "go")
    splits = ("development",) * 240 + ("calibration",) * 120 + ("held-out",) * 240
    cases: list[dict[str, object]] = []
    for index, split in enumerate(splits):
        language = languages[index % len(languages)]
        cases.append(
            {
                "case_id": f"case-{index}",
                "content_sha256": "sha256:" + f"{index:064x}",
                "cwe_id": "CWE-89",
                "expected_label": "vulnerable" if index % 2 else "fixed-safe",
                "language": language,
                "lineage_groups": [f"repo:{index}", f"root:{index}"],
                "split": split,
                "topology": "inter-file" if index % 3 == 0 else "single-file",
            }
        )
    candidate = _fixture()
    candidate["datasets"][0]["cases"] = cases

    result = MODULE.inventory_manifest(_write(tmp_path, candidate))

    assert result["case_count"] == 600
    assert result["language_counts"] == {
        "go": 200,
        "javascript-typescript": 200,
        "python": 200,
    }
    assert result["language_label_counts"] == {
        "go": {"fixed-safe": 100, "vulnerable": 100},
        "javascript-typescript": {"fixed-safe": 100, "vulnerable": 100},
        "python": {"fixed-safe": 100, "vulnerable": 100},
    }
    assert result["split_counts"] == {"calibration": 120, "development": 240, "held-out": 240}
    assert result["release_candidate_eligible"] is True
    assert result["shortfalls"] == {}
    assert result["split_ratio_valid"] is True


def test_split_minima_do_not_replace_the_exact_40_20_40_ratio(tmp_path: Path) -> None:
    languages = ("python", "javascript-typescript", "go")
    splits = ("development",) * 260 + ("calibration",) * 120 + ("held-out",) * 240
    cases: list[dict[str, object]] = []
    for index, split in enumerate(splits):
        cases.append(
            {
                "case_id": f"case-{index}",
                "content_sha256": "sha256:" + f"{index:064x}",
                "cwe_id": "CWE-89",
                "expected_label": "vulnerable" if index % 2 else "fixed-safe",
                "language": languages[index % len(languages)],
                "lineage_groups": [f"repo:{index}"],
                "split": split,
                "topology": "single-file",
            }
        )
    candidate = _fixture()
    candidate["datasets"][0]["cases"] = cases

    result = MODULE.inventory_manifest(_write(tmp_path, candidate))

    assert result["shortfalls"] == {}
    assert result["split_ratio_valid"] is False
    assert result["release_candidate_eligible"] is False


def test_global_label_balance_does_not_replace_per_language_balance(tmp_path: Path) -> None:
    languages = ("python", "javascript-typescript", "go")
    splits = ("development",) * 240 + ("calibration",) * 120 + ("held-out",) * 240
    cases: list[dict[str, object]] = []
    for index, split in enumerate(splits):
        language = languages[index % len(languages)]
        if language == "python":
            label = "vulnerable"
        elif language == "go":
            label = "fixed-safe"
        else:
            label = "vulnerable" if (index // len(languages)) % 2 else "fixed-safe"
        cases.append(
            {
                "case_id": f"case-{index}",
                "content_sha256": "sha256:" + f"{index:064x}",
                "cwe_id": "CWE-89",
                "expected_label": label,
                "language": language,
                "lineage_groups": [f"repo:{index}"],
                "split": split,
                "topology": "single-file",
            }
        )
    candidate = _fixture()
    candidate["datasets"][0]["cases"] = cases

    result = MODULE.inventory_manifest(_write(tmp_path, candidate))

    assert result["label_counts"] == {"fixed-safe": 300, "vulnerable": 300}
    assert result["language_label_counts"]["go"] == {"fixed-safe": 200, "vulnerable": 0}
    assert result["shortfalls"] == {
        "language_label:go:vulnerable": 100,
        "language_label:python:fixed-safe": 100,
    }
    assert result["release_candidate_eligible"] is False
