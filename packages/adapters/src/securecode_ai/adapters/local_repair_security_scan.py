"""Deterministic multi-language CWE-89 scan used by OCI repair validation."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from . import cst, cwe89, cwe89_multilanguage, python_ast
from .local_repair_oci_protocol import canonical_json


class SecurityScanError(ValueError):
    """The isolated repository cannot be scanned completely."""


def scan_cwe89_repository(root: Path, manifest: dict[str, Any], revision: str) -> tuple[str, int]:
    finding = manifest["finding"]
    repository = finding["repository_revision"]["repository_id"]
    records: list[tuple[str, str, int]] = []
    scanned_paths: set[str] = set()
    total = 0
    builders: dict[str, Any] = {
        ".py": cst.build_python_symbol_index,
        ".pyi": cst.build_python_symbol_index,
        ".js": cst.build_javascript_symbol_index,
        ".jsx": cst.build_javascript_symbol_index,
        ".mjs": cst.build_javascript_symbol_index,
        ".cjs": cst.build_javascript_symbol_index,
        ".ts": cst.build_typescript_symbol_index,
        ".mts": cst.build_typescript_symbol_index,
        ".cts": cst.build_typescript_symbol_index,
        ".tsx": cst.build_typescript_symbol_index,
        ".go": cst.build_go_symbol_index,
    }
    for file in sorted(
        item for item in root.rglob("*") if item.is_file() and ".git" not in item.parts
    ):
        builder = builders.get(file.suffix.lower())
        if builder is None:
            continue
        content = file.read_bytes()
        relative = file.relative_to(root).as_posix()
        index = builder(
            repository_id=repository,
            revision=revision,
            path=relative,
            content_sha256=hashlib.sha256(content).hexdigest(),
            source=content,
        )
        result: Any
        if index.language == "python":
            result = cwe89.scan_python_cwe89(index, python_ast.analyze_python_ast(index))
        else:
            scanners: dict[str, Any] = {
                "javascript": cwe89_multilanguage.scan_javascript_cwe89,
                "typescript": cwe89_multilanguage.scan_typescript_cwe89,
                "go": cwe89_multilanguage.scan_go_cwe89,
            }
            result = scanners[index.language](index)
        total += len(result.signals)
        scanned_paths.add(relative)
        records.append((relative, result.scan_sha256, len(result.signals)))
    required_paths = {
        item["path"] for item in finding["locations"] if type(item) is dict and "path" in item
    }
    if not records or not required_paths or not required_paths.issubset(scanned_paths):
        raise SecurityScanError
    return hashlib.sha256(canonical_json(records)).hexdigest(), total


__all__ = ["SecurityScanError", "scan_cwe89_repository"]
