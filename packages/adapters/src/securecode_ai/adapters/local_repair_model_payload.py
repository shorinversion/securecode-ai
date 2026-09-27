"""Strict Architect wire validation and retained canonical payload handling."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .git_snapshot import GitRevisionSnapshot
from .local_repair_contracts import LocalRepairBinding
from .local_repair_diff import validated_diff_paths
from .local_repair_model_schema import (
    _ARCHITECT_REQUIRED_FIELDS,
    _MAX_DIFF_BYTES,
    _MAX_DIFF_CHARACTERS,
    _SYMBOL_KIND_PATTERN,
    _SYMBOL_NAME_PATTERN,
)

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_SYMBOL_KIND = re.compile(_SYMBOL_KIND_PATTERN + r"\Z")
_SYMBOL_NAME = re.compile(_SYMBOL_NAME_PATTERN + r"\Z")
_WIRE_SYMBOL_FIELDS = {
    "path",
    "symbol_kind",
    "symbol_name",
    "start_line",
    "end_line",
}


def canonical_architect_payload(
    value: object,
    *,
    binding: LocalRepairBinding,
    snapshot: GitRevisionSnapshot,
    allowed_paths: tuple[str, ...],
) -> bytes:
    document = validated_architect_document(
        value,
        binding=binding,
        snapshot=snapshot,
        allowed_paths=allowed_paths,
    )
    return json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def validated_retained_architect_document(
    value: object,
    *,
    binding: LocalRepairBinding,
    snapshot: GitRevisionSnapshot,
    allowed_paths: tuple[str, ...],
) -> dict[str, Any]:
    if type(value) is not dict or type(value.get("touched_symbols")) is not list:
        raise ValueError
    wire = dict(value)
    wire["touched_symbols"] = [
        {key: item[key] for key in _WIRE_SYMBOL_FIELDS}
        for item in value["touched_symbols"]
        if type(item) is dict and set(item) == _WIRE_SYMBOL_FIELDS | {"symbol_sha256"}
    ]
    if len(wire["touched_symbols"]) != len(value["touched_symbols"]):
        raise ValueError
    rebuilt = validated_architect_document(
        wire,
        binding=binding,
        snapshot=snapshot,
        allowed_paths=allowed_paths,
    )
    if rebuilt != value:
        raise ValueError
    return rebuilt


def validated_architect_document(
    value: object,
    *,
    binding: LocalRepairBinding,
    snapshot: GitRevisionSnapshot,
    allowed_paths: tuple[str, ...],
) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError
    document = dict(value)
    if set(document) != set(_ARCHITECT_REQUIRED_FIELDS):
        raise ValueError
    expected = {
        "schema_version": "1.0.0",
        "finding_id": binding.finding.finding_id,
        "root_cause_id": binding.root_cause.record_id,
        "invariant_id": binding.invariant.invariant_id,
        "regression_descriptor_id": binding.regression.descriptor_id,
        "head_sha": binding.finding.repository_revision.head_sha,
    }
    if any(document.get(key) != item for key, item in expected.items()):
        raise ValueError
    diff = document.get("unified_diff")
    rationale = document.get("rationale")
    symbols = document.get("touched_symbols")
    try:
        if type(rationale) is str:
            rationale.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ValueError from None
    if (
        type(diff) is not str
        or not diff
        or len(diff) > _MAX_DIFF_CHARACTERS
        or len(diff.encode("utf-8")) > _MAX_DIFF_BYTES
        or type(rationale) is not str
        or not rationale.strip()
        or len(rationale) > 4096
        or _CONTROL.search(rationale)
        or type(symbols) is not list
        or not 1 <= len(symbols) <= 256
    ):
        raise ValueError
    changed_paths = validated_diff_paths(diff)
    if not changed_paths or not set(changed_paths).issubset(allowed_paths):
        raise ValueError
    files = {item.path: item for item in snapshot.files}
    checked_symbols = []
    for raw in symbols:
        if type(raw) is not dict or set(raw) != _WIRE_SYMBOL_FIELDS:
            raise ValueError
        item = dict(raw)
        path = item["path"]
        start, end = item["start_line"], item["end_line"]
        if (
            type(path) is not str
            or path not in allowed_paths
            or type(start) is not int
            or type(end) is not int
            or start < 1
            or end < start
            or type(item["symbol_kind"]) is not str
            or type(item["symbol_name"]) is not str
            or _SYMBOL_KIND.fullmatch(item["symbol_kind"]) is None
            or _SYMBOL_NAME.fullmatch(item["symbol_name"]) is None
        ):
            raise ValueError
        lines = files[path].content.splitlines(keepends=True)
        if end > len(lines):
            raise ValueError
        item["symbol_sha256"] = hashlib.sha256(b"".join(lines[start - 1 : end])).hexdigest()
        checked_symbols.append(item)
    ordered = sorted(
        checked_symbols, key=lambda item: (item["path"], item["start_line"], item["symbol_name"])
    )
    if len({(item["path"], item["start_line"], item["symbol_name"]) for item in ordered}) != len(
        ordered
    ):
        raise ValueError
    document["touched_symbols"] = ordered
    return document


__all__ = [
    "canonical_architect_payload",
    "validated_architect_document",
    "validated_retained_architect_document",
]
