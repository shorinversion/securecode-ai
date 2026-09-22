"""Build the source-free 600-case CVEfixes release-corpus manifest.

The database is opened immutable and read-only.  Source bytes are used only to
calculate identities; neither the manifest nor the command output contain a
source fragment.  A benchmark runner can later re-open the same local database
and reject a case whose hash no longer matches this frozen manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

SCHEMA_VERSION = "securecode.release-corpus-inventory.v1"
DATASET_ID = "cvefixes-v1.0.8-paired-python-js-ts-go"
LANGUAGES = (
    ("python", ("Python",)),
    ("javascript-typescript", ("JavaScript", "TypeScript")),
    ("go", ("Go",)),
)
SPLITS = (("development", 40), ("calibration", 20), ("held-out", 40))


@dataclass(frozen=True, slots=True)
class Pair:
    cve_id: str
    file_change_id: str
    cwe_id: str
    language: str


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return "sha256:" + hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _connection(path: Path) -> sqlite3.Connection:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ValueError("database must be an absolute regular file")
    uri = path.as_uri() + "?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True)


def _single_cwes(connection: sqlite3.Connection) -> dict[str, str]:
    result: dict[str, str] = {}
    for cve_id, cwe_id, count in connection.execute(
        """SELECT cve_id, MIN(cwe_id), COUNT(DISTINCT cwe_id)
        FROM cwe_classification WHERE cwe_id GLOB 'CWE-[0-9]*' GROUP BY cve_id"""
    ):
        if type(cve_id) is str and type(cwe_id) is str and count == 1:
            result[cve_id] = cwe_id
    return result


def _hash_to_cve(
    connection: sqlite3.Connection, cwes: dict[str, str]
) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for cve_id, commit_hash in connection.execute("SELECT cve_id, hash FROM fixes"):
        if type(cve_id) is str and type(commit_hash) is str and cve_id in cwes:
            result.setdefault(commit_hash, (cve_id, cwes[cve_id]))
    return result


def _pairs(
    connection: sqlite3.Connection, languages: tuple[str, ...], label: str
) -> Iterable[tuple[Pair, str, str]]:
    cwes = _single_cwes(connection)
    commits = _hash_to_cve(connection, cwes)
    maximum = connection.execute("SELECT MAX(rowid) FROM file_change").fetchone()[0]
    if type(maximum) is not int or maximum < 1:
        raise ValueError("CVEfixes file-change table is unavailable")
    wanted = set(languages)
    step = 7919
    start = 104729 % maximum
    for offset in range(maximum):
        rowid = ((start + offset * step) % maximum) + 1
        row = connection.execute(
            """SELECT file_change_id, hash, programming_language, code_before, code_after
            FROM file_change WHERE rowid = ?""",
            (rowid,),
        ).fetchone()
        if row is None or row[2] not in wanted or row[1] not in commits:
            continue
        file_change_id, commit_hash, _, before, after = row
        if not all(
            type(item) is str and item for item in (file_change_id, commit_hash, before, after)
        ):
            continue
        cve_id, cwe_id = commits[commit_hash]
        yield Pair(cve_id, file_change_id, cwe_id, label), before, after


def _split(group_index: int) -> str:
    cursor = 0
    for name, count in SPLITS:
        cursor += count
        if group_index < cursor:
            return name
    raise ValueError("split selection overflow")


def _case(pair: Pair, content: str, *, revision: str, label: str, split: str) -> dict[str, object]:
    lineage = f"cvefixes:{pair.cve_id}:{pair.file_change_id}"
    return {
        "case_id": f"{lineage}:{revision}",
        "content_sha256": _digest(content),
        "cwe_id": pair.cwe_id,
        "expected_label": label,
        "language": pair.language,
        "lineage_groups": [lineage],
        "split": split,
        "topology": "single-file",
    }


def build_manifest(database: Path) -> dict[str, object]:
    """Select 100 paired, non-overlapping lineage groups per language."""
    selected_cases: list[dict[str, object]] = []
    seen_content: set[str] = set()
    with _connection(database) as connection:
        for label, database_languages in LANGUAGES:
            selected = 0
            for pair, before_source, after_source in _pairs(connection, database_languages, label):
                before = _digest(before_source)
                after = _digest(after_source)
                if before == after or before in seen_content or after in seen_content:
                    continue
                split = _split(selected)
                selected_cases.extend(
                    (
                        _case(
                            pair, before_source, revision="before", label="vulnerable", split=split
                        ),
                        _case(
                            pair, after_source, revision="after", label="fixed-safe", split=split
                        ),
                    )
                )
                seen_content.update((before, after))
                selected += 1
                if selected == 100:
                    break
            if selected != 100:
                raise ValueError(f"insufficient eligible CVEfixes pairs for {label}")

    cases = sorted(selected_cases, key=lambda item: str(item["case_id"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "datasets": [
            {
                "dataset_id": DATASET_ID,
                "version": "1.0.8",
                "source_id": "zenodo:10.5281/zenodo.4476563",
                "revision": "sqlite:CVEfixes_v1.0.8.sqlite",
                "license_spdx": "NOASSERTION",
                "content_sha256": _canonical_digest(cases),
                "resolution": "resolved",
                "cases": cases,
            }
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        manifest = build_manifest(arguments.database.resolve(strict=True))
        output = arguments.output.resolve()
        if not output.is_absolute() or output.suffix != ".json":
            raise ValueError("output must be an absolute JSON path")
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    except (OSError, sqlite3.Error, ValueError) as error:
        print(f"CVEFIXES_MANIFEST=FAIL: {error}")
        return 1
    datasets = cast(list[dict[str, Any]], manifest["datasets"])
    print(f"CVEFIXES_MANIFEST=PASS cases={len(cast(list[object], datasets[0]['cases']))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
