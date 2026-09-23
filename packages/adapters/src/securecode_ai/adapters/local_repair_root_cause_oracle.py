"""Independent fail-closed root-cause oracle for local CWE-89 repair validation."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import cst, cwe89, cwe89_multilanguage, python_ast

_FINGERPRINT_DOMAIN = b"securecode-ai/root-cause-fingerprint/v1\x00"
_CWE89_RULE_ID = "cwe-89-sql-interpolation"


class RootCauseOracleError(ValueError):
    """The exact root cause cannot be classified without guessing."""


@dataclass(frozen=True, slots=True, order=True)
class Cwe89SignalIdentity:
    """Revision-independent scanner identity for one exact causal flow."""

    path: str
    detector: str
    source: tuple[int, int, int, int]
    interpolation: tuple[int, int, int, int]
    sink: tuple[int, int, int, int]


@dataclass(frozen=True, slots=True)
class Cwe89RepairSignalComparison:
    """Per-finding scanner comparison with no repository-clean assumption."""

    parent_signal_count: int
    fixed_signal_count: int
    target_signal_removed: bool
    new_signal_count: int

    @property
    def passed(self) -> bool:
        return self.target_signal_removed and self.new_signal_count == 0


def _safe_path(root: Path, relative: str) -> Path:
    if type(relative) is not str or not relative or "\x00" in relative or "\\" in relative:
        raise RootCauseOracleError
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        raise RootCauseOracleError from None
    return candidate


def evaluate_cwe89_root_cause(root: Path, manifest: dict[str, Any]) -> str:
    """Independently classify the exact CWE-89 sink as vulnerable or safely bound."""

    sink = _target_sink(manifest)
    start = sink.get("start")
    end = sink.get("end")
    if type(start) is not dict or type(end) is not dict:
        raise RootCauseOracleError
    start_line = start.get("line")
    end_line = end.get("line")
    if type(start_line) is not int or type(end_line) is not int or not 1 <= start_line <= end_line:
        raise RootCauseOracleError
    path = _safe_path(root, sink["path"])
    if path.is_symlink() or not path.is_file():
        raise RootCauseOracleError
    source = path.read_text(encoding="utf-8", errors="strict")
    suffix = path.suffix.lower()
    if suffix in {".py", ".pyi"}:
        return _python_sql_state(source, start_line, end_line)
    if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".go"}:
        lines = source.splitlines()
        snippet = "\n".join(lines[max(0, start_line - 2) : min(len(lines), end_line + 1)])
        return _text_sql_state(snippet, suffix)
    raise RootCauseOracleError


def compare_cwe89_repair_signals(
    parent_root: Path,
    fixed_root: Path,
    manifest: dict[str, Any],
    *,
    parent_revision: str,
    fixed_revision: str,
) -> Cwe89RepairSignalComparison:
    """Require the bound target signal to disappear and forbid new signals."""

    target = _target_sink(manifest)
    parent = set(_scan_signal_identities(parent_root, manifest, parent_revision))
    fixed = set(_scan_signal_identities(fixed_root, manifest, fixed_revision))
    target_matches = {signal for signal in parent if _same_sink(signal, target)}
    if len(target_matches) != 1:
        raise RootCauseOracleError
    target_signal = next(iter(target_matches))
    allowed_fixed = parent - {target_signal}
    return Cwe89RepairSignalComparison(
        parent_signal_count=len(parent),
        fixed_signal_count=len(fixed),
        target_signal_removed=not any(_same_sink(signal, target) for signal in fixed),
        new_signal_count=len(fixed - allowed_fixed),
    )


def _target_sink(manifest: dict[str, Any]) -> dict[str, Any]:
    finding = manifest.get("finding")
    root_cause = manifest.get("root_cause")
    if (
        type(finding) is not dict
        or finding.get("cwe_id") != "CWE-89"
        or type(root_cause) is not dict
    ):
        raise RootCauseOracleError
    repository = finding.get("repository_revision")
    graph_ref = finding.get("evidence_graph_ref")
    evidence = root_cause.get("evidence")
    locations = finding.get("locations")
    evidence_ids = finding.get("evidence_ids")
    fingerprint = finding.get("root_cause_fingerprint")
    if (
        type(repository) is not dict
        or type(repository.get("tenant_id")) is not str
        or type(graph_ref) is not dict
        or type(evidence) is not dict
        or type(locations) is not list
        or not locations
        or type(evidence_ids) is not list
        or type(fingerprint) is not str
        or root_cause.get("finding_id") != finding.get("finding_id")
        or root_cause.get("candidate_id") != finding.get("candidate_id")
        or root_cause.get("candidate_version") != finding.get("candidate_version")
        or root_cause.get("tenant_id") != repository.get("tenant_id")
        or root_cause.get("repository_id") != repository.get("repository_id")
        or root_cause.get("head_sha") != repository.get("head_sha")
        or root_cause.get("root_cause_fingerprint") != fingerprint
        or root_cause.get("evidence_graph_id") != graph_ref.get("content_id")
        or root_cause.get("evidence_graph_sha256") != graph_ref.get("content_sha256")
    ):
        raise RootCauseOracleError
    causal_ids = (
        evidence.get("source_evidence_id"),
        evidence.get("propagation_evidence_id"),
        evidence.get("sink_evidence_id"),
    )
    if (
        any(type(value) is not str for value in causal_ids)
        or len(set(causal_ids)) != 3
        or not set(causal_ids).issubset(set(evidence_ids))
    ):
        raise RootCauseOracleError
    matches = [
        location
        for location in locations
        if type(location) is dict
        and _location_fingerprint(repository["tenant_id"], location) == fingerprint
    ]
    if len(matches) != 1:
        raise RootCauseOracleError
    sink = matches[0]
    if type(sink.get("path")) is not str:
        raise RootCauseOracleError
    return sink


def _location_fingerprint(tenant_id: str, location: dict[str, Any]) -> str:
    start = location.get("start")
    end = location.get("end")
    if (
        type(start) is not dict
        or type(end) is not dict
        or type(location.get("path")) is not str
        or type(location.get("content_sha256")) is not str
        or any(type(value) is not int for value in (start.get("line"), start.get("column")))
        or any(type(value) is not int for value in (end.get("line"), end.get("column")))
    ):
        raise RootCauseOracleError
    material = {
        "location": {
            "content_sha256": location["content_sha256"],
            "end": {"column": end["column"], "line": end["line"]},
            "path": location["path"],
            "start": {"column": start["column"], "line": start["line"]},
        },
        "rule_id": _CWE89_RULE_ID,
        "tenant_id": tenant_id,
    }
    encoded = json.dumps(
        material, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(_FINGERPRINT_DOMAIN + encoded).hexdigest()


def _scan_signal_identities(
    root: Path, manifest: dict[str, Any], revision: str
) -> tuple[Cwe89SignalIdentity, ...]:
    finding = manifest["finding"]
    repository = finding["repository_revision"]["repository_id"]
    output: list[Cwe89SignalIdentity] = []
    scanned_paths: set[str] = set()
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
            scanner = {
                "javascript": cwe89_multilanguage.scan_javascript_cwe89,
                "typescript": cwe89_multilanguage.scan_typescript_cwe89,
                "go": cwe89_multilanguage.scan_go_cwe89,
            }[index.language]
            result = scanner(index)
        for signal in result.signals:
            output.append(
                Cwe89SignalIdentity(
                    path=relative,
                    detector=signal.detector,
                    source=_range_identity(signal.source),
                    interpolation=_range_identity(signal.interpolation),
                    sink=_range_identity(signal.sink),
                )
            )
        scanned_paths.add(relative)
    required_paths = {
        item["path"] for item in finding["locations"] if type(item) is dict and "path" in item
    }
    if not scanned_paths or not required_paths or not required_paths.issubset(scanned_paths):
        raise RootCauseOracleError
    return tuple(sorted(output))


def _range_identity(value: Any) -> tuple[int, int, int, int]:
    return (
        value.start_point.row + 1,
        value.start_point.column + 1,
        value.end_point.row + 1,
        value.end_point.column + 1,
    )


def _same_sink(signal: Cwe89SignalIdentity, target: dict[str, Any]) -> bool:
    start = target["start"]
    end = target["end"]
    return signal.path == target["path"] and signal.sink == (
        start["line"],
        start["column"],
        end["line"],
        end["column"],
    )


def _python_sql_state(source: str, start_line: int, end_line: int) -> str:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        raise RootCauseOracleError from None
    candidates = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.attr.lower() if isinstance(node.func, ast.Attribute) else ""
        node_end = getattr(node, "end_lineno", node.lineno)
        if (
            name in {"execute", "executemany", "query"}
            and node.lineno <= end_line
            and node_end >= start_line
        ):
            candidates.append(node)
    if len(candidates) != 1 or not candidates[0].args:
        raise RootCauseOracleError
    call = candidates[0]
    query = call.args[0]
    if isinstance(query, (ast.JoinedStr, ast.BinOp)) or (
        isinstance(query, ast.Call)
        and isinstance(query.func, ast.Attribute)
        and query.func.attr in {"format", "format_map"}
    ):
        return "VULNERABLE"
    if isinstance(query, ast.Constant) and isinstance(query.value, str):
        placeholders = ("?", "%s", ":", "$1")
        if len(call.args) >= 2 and any(item in query.value for item in placeholders):
            return "SAFE"
    raise RootCauseOracleError


def _text_sql_state(snippet: str, suffix: str) -> str:
    lowered = snippet.lower()
    if not re.search(r"\.(?:query|queryrow|exec|execute)\s*\(", lowered):
        raise RootCauseOracleError
    if (
        "${" in snippet
        or "fmt.sprintf" in lowered
        or re.search(r"[\"'`]\s*\+|\+\s*[A-Za-z_$]", snippet)
    ):
        return "VULNERABLE"
    placeholder = "?" in snippet or bool(re.search(r"\$[1-9][0-9]*", snippet))
    has_arguments = bool(re.search(r"\.(?:query|queryrow|exec|execute)\s*\([^,]+,", lowered, re.S))
    if placeholder and has_arguments:
        return "SAFE"
    if suffix == ".go" and "fmt.sprintf" in lowered:
        return "VULNERABLE"
    raise RootCauseOracleError


__all__ = [
    "Cwe89RepairSignalComparison",
    "Cwe89SignalIdentity",
    "RootCauseOracleError",
    "compare_cwe89_repair_signals",
    "evaluate_cwe89_root_cause",
]
