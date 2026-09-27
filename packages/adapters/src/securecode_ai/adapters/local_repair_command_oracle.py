"""Independent Python CWE-78 oracle for isolated repair validation.

The production scanner is deliberately not imported here.  This module only
checks the retained operation binding against CPython's AST and treats every
unresolved alias, malformed range, or ambiguous call as indeterminate.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class CommandOracleError(ValueError):
    """The retained command binding cannot be independently verified."""


@dataclass(frozen=True, slots=True, order=True)
class Cwe78SignalIdentity:
    """One independent unsafe command call identity."""

    path: str
    operation: str
    detail: str
    source: tuple[int, int, int, int]
    sink: tuple[int, int, int, int]


@dataclass(frozen=True, slots=True)
class Cwe78RepairSignalComparison:
    """Independent before/after command signal comparison."""

    parent_signal_count: int
    fixed_signal_count: int
    target_signal_removed: bool
    new_signal_count: int

    @property
    def passed(self) -> bool:
        return self.target_signal_removed and self.new_signal_count == 0


_OPERATIONS = frozenset(
    {
        "os.system",
        "os.popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "subprocess.argv",
    }
)
_SHELL_ALWAYS = frozenset(
    {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}
)
_SHELL_CAPABLE = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
    }
)
_SAFE_QUOTERS = frozenset(
    {"shlex.quote", "shlex.join", "pipes.quote", "subprocess.list2cmdline"}
)
_LOCATION_KEYS = frozenset(
    {"schema_version", "extensions", "path", "start", "end", "content_sha256"}
)


def validate_cwe78_manifest_contract(manifest: dict[str, Any]) -> None:
    """Validate the exact scanner-to-root-cause-to-invariant binding."""

    finding, root_cause, invariant, binding = _target_binding(manifest)
    finding_commands = finding.get("command_operation_evidence")
    root_commands = root_cause.get("command_operation_evidence")
    invariant_commands = invariant.get("command_operation_evidence")
    if (
        type(finding_commands) is not list
        or type(root_commands) is not list
        or type(invariant_commands) is not list
        or len(finding_commands) != 1
        or len(root_commands) != 1
        or len(invariant_commands) != 1
        or _binding_core(finding_commands[0]) != binding
        or _binding_core(root_commands[0]) != binding
        or _binding_core(invariant_commands[0]) != binding
        or invariant.get("invariant_id") != "CWE-78-COMMAND-SAFETY"
        or invariant.get("property_name") != "command execution operation safety"
    ):
        raise CommandOracleError
    evidence_ids = finding.get("evidence_ids")
    root_evidence = root_cause.get("evidence")
    required = invariant.get("required_evidence_ids")
    if (
        type(evidence_ids) is not list
        or type(root_evidence) is not dict
        or type(required) is not list
        or not {binding["scanner_signal_id"], *binding["evidence_ids"]}.issubset(
            set(evidence_ids)
        )
        or tuple(root_evidence.get(key) for key in _ROOT_EVIDENCE_KEYS)
        != (binding["source_evidence_id"], binding["flow_evidence_id"], binding["sink_evidence_id"])
        or set(required)
        != {
            binding["source_evidence_id"],
            binding["flow_evidence_id"],
            binding["sink_evidence_id"],
        }
    ):
        raise CommandOracleError


def evaluate_cwe78_root_cause(root: Path, manifest: dict[str, Any]) -> str:
    """Classify the exact bound operation as ``VULNERABLE`` or ``SAFE``."""

    _finding, _root_cause, _invariant, binding = _target_binding(manifest)
    path = _safe_path(root, binding["sink"]["path"])
    if path.is_symlink() or not path.is_file():
        raise CommandOracleError
    source = path.read_bytes()
    tree = _parse(source)
    aliases = _imports(tree)
    calls = _matching_calls(tree, binding["operation"], binding["sink"], aliases)
    if len(calls) > 1:
        raise CommandOracleError
    if not calls:
        return "SAFE"
    call = calls[0]
    if _is_unsafe(call, binding["operation"], binding["detail"], aliases):
        if not _has_exact_source(tree, binding["source"]):
            raise CommandOracleError
        return "VULNERABLE"
    return "SAFE"


def compare_cwe78_repair_signals(
    parent_root: Path,
    fixed_root: Path,
    manifest: dict[str, Any],
    *,
    parent_revision: str,
    fixed_revision: str,
) -> Cwe78RepairSignalComparison:
    """Require target removal and forbid newly introduced unsafe calls."""

    _finding, _root_cause, _invariant, binding = _target_binding(manifest)
    parent = set(_scan_repository(parent_root, manifest, parent_revision))
    fixed = set(_scan_repository(fixed_root, manifest, fixed_revision))
    target = {
        item for item in parent if _same_target(item, binding)
    }
    if len(target) != 1:
        raise CommandOracleError
    target_signal = next(iter(target))
    allowed_fixed = parent - {target_signal}
    return Cwe78RepairSignalComparison(
        parent_signal_count=len(parent),
        fixed_signal_count=len(fixed),
        target_signal_removed=not any(_same_target(item, binding) for item in fixed),
        new_signal_count=len(fixed - allowed_fixed),
    )


def scan_cwe78_repository(
    root: Path, manifest: dict[str, Any], revision: str
) -> tuple[str, int]:
    """Return a canonical hash and count for independently unsafe Python calls."""

    signals = _scan_repository(root, manifest, revision)
    material = [
        {
            "detail": item.detail,
            "operation": item.operation,
            "path": item.path,
            "sink": item.sink,
            "source": item.source,
        }
        for item in signals
    ]
    digest = hashlib.sha256(
        json.dumps(material, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
            "ascii"
        )
    ).hexdigest()
    return digest, len(signals)


_ROOT_EVIDENCE_KEYS = (
    "source_evidence_id",
    "propagation_evidence_id",
    "sink_evidence_id",
)


def _target_binding(
    manifest: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    if type(manifest) is not dict:
        raise CommandOracleError
    finding = manifest.get("finding")
    root_cause = manifest.get("root_cause")
    invariant = manifest.get("invariant")
    if type(finding) is not dict or type(root_cause) is not dict or type(invariant) is not dict:
        raise CommandOracleError
    if finding.get("cwe_id") != "CWE-78":
        raise CommandOracleError
    revision = finding.get("repository_revision")
    graph_ref = finding.get("evidence_graph_ref")
    commands = finding.get("command_operation_evidence")
    if type(revision) is not dict or type(graph_ref) is not dict or type(commands) is not list:
        raise CommandOracleError
    if len(commands) != 1:
        raise CommandOracleError
    binding = _binding_core(commands[0])
    if (
        root_cause.get("finding_id") != finding.get("finding_id")
        or root_cause.get("candidate_id") != finding.get("candidate_id")
        or root_cause.get("candidate_version") != finding.get("candidate_version")
        or root_cause.get("tenant_id") != revision.get("tenant_id")
        or root_cause.get("repository_id") != revision.get("repository_id")
        or root_cause.get("head_sha") != revision.get("head_sha")
        or root_cause.get("root_cause_fingerprint") != finding.get("root_cause_fingerprint")
        or root_cause.get("evidence_graph_id") != graph_ref.get("content_id")
        or root_cause.get("evidence_graph_sha256") != graph_ref.get("content_sha256")
        or invariant.get("finding_id") != finding.get("finding_id")
        or invariant.get("root_cause_id") != root_cause.get("record_id")
        or invariant.get("candidate_id") != finding.get("candidate_id")
        or invariant.get("candidate_version") != finding.get("candidate_version")
        or invariant.get("tenant_id") != revision.get("tenant_id")
        or invariant.get("repository_id") != revision.get("repository_id")
        or invariant.get("head_sha") != revision.get("head_sha")
        or invariant.get("root_cause_fingerprint") != finding.get("root_cause_fingerprint")
        or invariant.get("evidence_graph_id") != graph_ref.get("content_id")
        or invariant.get("evidence_graph_sha256") != graph_ref.get("content_sha256")
    ):
        raise CommandOracleError
    evidence_ids = finding.get("evidence_ids")
    root_evidence = root_cause.get("evidence")
    required = invariant.get("required_evidence_ids")
    if (
        type(evidence_ids) is not list
        or type(root_evidence) is not dict
        or type(required) is not list
        or not {binding["scanner_signal_id"], *binding["evidence_ids"]}.issubset(
            set(evidence_ids)
        )
        or tuple(root_evidence.get(key) for key in _ROOT_EVIDENCE_KEYS)
        != (binding["source_evidence_id"], binding["flow_evidence_id"], binding["sink_evidence_id"])
        or set(required)
        != {
            binding["source_evidence_id"],
            binding["flow_evidence_id"],
            binding["sink_evidence_id"],
        }
    ):
        raise CommandOracleError
    return finding, root_cause, invariant, binding


def _binding_core(value: object) -> dict[str, Any]:
    if type(value) is not dict:
        raise CommandOracleError
    source = value.get("source")
    sink = value.get("sink")
    operation = value.get("operation")
    detail = value.get("detail")
    scanner_signal_id = value.get("scanner_signal_id")
    source_id = value.get("source_evidence_id")
    sink_id = value.get("sink_evidence_id")
    flow_id = value.get("flow_evidence_id")
    _validate_location(source)
    _validate_location(sink)
    if (
        type(scanner_signal_id) is not str
        or type(operation) is not str
        or operation not in _OPERATIONS
        or type(detail) is not str
        or detail not in {"untrusted_command_to_shell", "untrusted_command_token_to_argv"}
        or type(source_id) is not str
        or type(sink_id) is not str
        or type(flow_id) is not str
        or len({source_id, sink_id, flow_id}) != 3
        or source["path"] != sink["path"]
        or source["content_sha256"] != sink["content_sha256"]
        or source == sink
    ):
        raise CommandOracleError
    if operation == "subprocess.argv" and detail != "untrusted_command_token_to_argv":
        raise CommandOracleError
    if operation != "subprocess.argv" and detail != "untrusted_command_to_shell":
        raise CommandOracleError
    return {
        "detail": detail,
        "flow_evidence_id": flow_id,
        "operation": operation,
        "scanner_signal_id": scanner_signal_id,
        "sink": sink,
        "sink_evidence_id": sink_id,
        "source": source,
        "source_evidence_id": source_id,
        "evidence_ids": (source_id, sink_id, flow_id),
    }


def _validate_location(value: object) -> None:
    if type(value) is not dict or set(value) != _LOCATION_KEYS:
        raise CommandOracleError
    start = value.get("start")
    end = value.get("end")
    if (
        type(value.get("schema_version")) is not str
        or type(value.get("extensions")) is not list
        or type(value.get("path")) is not str
        or not value["path"]
        or "\\" in value["path"]
        or type(value.get("content_sha256")) is not str
        or len(value["content_sha256"]) != 64
        or type(start) is not dict
        or type(end) is not dict
        or set(start) != {"schema_version", "extensions", "line", "column"}
        or set(end) != {"schema_version", "extensions", "line", "column"}
        or any(type(item.get(key)) is not int or item[key] < 1 for item in (start, end) for key in ("line", "column"))
        or (start["line"], start["column"]) > (end["line"], end["column"])
    ):
        raise CommandOracleError


def _safe_path(root: Path, relative: str) -> Path:
    if type(relative) is not str or not relative or "\x00" in relative or "\\" in relative:
        raise CommandOracleError
    parts = relative.split("/")
    if relative.startswith("/") or any(part in {"", ".", ".."} for part in parts):
        raise CommandOracleError
    base = root.resolve()
    candidate = base.joinpath(*parts)
    if candidate.is_symlink():
        raise CommandOracleError
    try:
        candidate.resolve().relative_to(base)
    except ValueError:
        raise CommandOracleError from None
    return candidate


def _parse(source: bytes) -> ast.Module:
    try:
        return ast.parse(source.decode("utf-8", errors="strict"))
    except (SyntaxError, UnicodeError, ValueError):
        raise CommandOracleError from None


def _imports(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.name in {"os", "subprocess", "shlex", "pipes"}:
                    aliases[item.asname or item.name] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module in {"os", "subprocess", "shlex", "pipes"}:
            for item in node.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    return aliases


def _qualified_name(node: ast.AST, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id if node.id in {"os", "subprocess"} else None)
    if isinstance(node, ast.Attribute):
        base = _qualified_name(node.value, aliases)
        return f"{base}.{node.attr}" if base is not None else None
    return None


def _matching_calls(
    tree: ast.Module,
    operation: str,
    sink: dict[str, Any],
    aliases: dict[str, str],
) -> list[ast.Call]:
    result: list[ast.Call] = []
    expected = _SHELL_CAPABLE if operation == "subprocess.argv" else {operation}
    target = _range_tuple(sink)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        canonical = _qualified_name(node.func, aliases)
        if canonical not in expected:
            continue
        current = _node_range(node)
        if current == target or _range_overlaps(current, target):
            result.append(node)
    return result


def _is_unsafe(call: ast.Call, operation: str, detail: str, aliases: dict[str, str]) -> bool:
    canonical = _qualified_name(call.func, aliases)
    argument = _call_argument(call)
    if argument is None:
        raise CommandOracleError
    if operation == "subprocess.argv":
        if canonical not in _SHELL_CAPABLE or detail != "untrusted_command_token_to_argv":
            raise CommandOracleError
        shell = _shell_mode(call)
        if shell is True or shell is None:
            raise CommandOracleError
        first = argument.elts[0] if isinstance(argument, (ast.List, ast.Tuple)) and argument.elts else argument
        return not (isinstance(first, ast.Constant) and type(first.value) is str)
    if canonical != operation or detail != "untrusted_command_to_shell":
        raise CommandOracleError
    if operation in _SHELL_CAPABLE and _shell_mode(call) is False:
        return False
    if isinstance(argument, ast.Call) and _qualified_name(argument.func, aliases) in _SAFE_QUOTERS:
        return False
    return not (isinstance(argument, ast.Constant) and type(argument.value) is str)


def _call_argument(call: ast.Call) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg in {"command", "cmd", "args"}:
            return keyword.value
    return call.args[0] if call.args else None


def _shell_mode(call: ast.Call) -> bool | None:
    for keyword in call.keywords:
        if keyword.arg == "shell":
            if isinstance(keyword.value, ast.Constant) and type(keyword.value.value) is bool:
                return keyword.value.value
            return None
    return False


def _has_exact_source(tree: ast.Module, source: dict[str, Any]) -> bool:
    target = _range_tuple(source)
    return any(_node_range(node) == target for node in ast.walk(tree) if isinstance(node, ast.expr))


def _node_range(node: ast.AST) -> tuple[int, int, int, int]:
    start_line = getattr(node, "lineno", None)
    start_col = getattr(node, "col_offset", None)
    end_line = getattr(node, "end_lineno", None)
    end_col = getattr(node, "end_col_offset", None)
    if any(type(value) is not int for value in (start_line, start_col, end_line, end_col)):
        raise CommandOracleError
    return (start_line, start_col + 1, end_line, end_col + 1)


def _range_tuple(value: dict[str, Any]) -> tuple[int, int, int, int]:
    start = value["start"]
    end = value["end"]
    return (start["line"], start["column"], end["line"], end["column"])


def _range_overlaps(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> bool:
    return left[0] <= right[2] and right[0] <= left[2]


def _scan_repository(root: Path, manifest: dict[str, Any], revision: str) -> tuple[Cwe78SignalIdentity, ...]:
    _finding, _root_cause, _invariant, binding = _target_binding(manifest)
    paths = {
        item["path"]
        for item in manifest["finding"].get("locations", ())
        if type(item) is dict and type(item.get("path")) is str
    }
    if not paths or any(not path.endswith((".py", ".pyi")) for path in paths):
        raise CommandOracleError
    output: list[Cwe78SignalIdentity] = []
    for relative in sorted(paths):
        path = _safe_path(root, relative)
        if path.is_symlink() or not path.is_file():
            raise CommandOracleError
        tree = _parse(path.read_bytes())
        aliases = _imports(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            canonical = _qualified_name(node.func, aliases)
            candidates = _SHELL_CAPABLE | _SHELL_ALWAYS
            if canonical not in candidates:
                continue
            for operation, detail in _candidate_modes(node, canonical, aliases):
                if _is_unsafe(node, operation, detail, aliases):
                    current = _node_range(node)
                    output.append(
                        Cwe78SignalIdentity(
                            path=relative,
                            operation=operation,
                            detail=detail,
                            source=current,
                            sink=current,
                        )
                    )
    return tuple(sorted(set(output)))


def _candidate_modes(
    call: ast.Call, canonical: str | None, aliases: dict[str, str]
) -> tuple[tuple[str, str], ...]:
    if canonical is None:
        return ()
    if canonical in _SHELL_ALWAYS:
        return ((canonical, "untrusted_command_to_shell"),)
    if canonical not in _SHELL_CAPABLE:
        return ()
    shell = _shell_mode(call)
    if shell is False:
        return (("subprocess.argv", "untrusted_command_token_to_argv"),)
    return ((canonical, "untrusted_command_to_shell"),)


def _same_target(signal: Cwe78SignalIdentity, binding: dict[str, Any]) -> bool:
    return (
        signal.path == binding["sink"]["path"]
        and signal.sink == _range_tuple(binding["sink"])
        and signal.operation == binding["operation"]
        and signal.detail == binding["detail"]
    )


__all__ = [
    "CommandOracleError",
    "Cwe78RepairSignalComparison",
    "Cwe78SignalIdentity",
    "compare_cwe78_repair_signals",
    "evaluate_cwe78_root_cause",
    "scan_cwe78_repository",
    "validate_cwe78_manifest_contract",
]
