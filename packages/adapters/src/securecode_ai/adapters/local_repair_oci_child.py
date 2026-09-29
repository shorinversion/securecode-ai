"""Pinned child protocol executed only inside the rootless validation image."""

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Final, Protocol, cast

from securecode_ai.core.regression import (
    RegressionCaseResult,
    RegressionExpectedOutcome,
    RegressionObservationStatus,
)

from .local_repair_command_oracle import (
    Cwe78RepairSignalComparison,
    compare_cwe78_repair_signals,
    evaluate_cwe78_root_cause,
    scan_cwe78_repository,
    validate_cwe78_manifest_contract,
)
from .local_repair_oci_commands import compile_plan, test_plan
from .local_repair_oci_protocol import (
    build_preparation_document,
    build_stage_document,
    canonical_json,
    closed_json,
)
from .local_repair_root_cause_oracle import (
    Cwe89RepairSignalComparison,
    compare_cwe89_repair_signals,
    evaluate_cwe89_root_cause,
)
from .local_repair_security_scan import scan_cwe89_repository

_BUNDLE_DOMAIN: Final = b"securecode-ai/local-repair-oci-bundle/v1\x00"
_RESULT_DOMAIN: Final = b"securecode-ai/local-repair-oci-result/v1\x00"
_INPUT = Path("/securecode/input")
_WORKSPACE = Path("/workspace/repository")
_STAGES: Final = (
    "validation-diff-parse",
    "validation-ephemeral-checkout",
    "validation-patch-apply",
    "validation-language-policy",
    "validation-compile-types",
    "validation-existing-tests",
    "validation-security-poc",
    "validation-security-poc-plus",
    "validation-post-patch-scan",
    "validation-regression-scan",
    "validation-resource-policy",
)
_INDETERMINATE_EXIT = 78


class ChildProtocolError(ValueError):
    pass


class _ResourceUsage(Protocol):
    ru_utime: float
    ru_stime: float
    ru_maxrss: int


class _ResourceModule(Protocol):
    RUSAGE_SELF: int
    RUSAGE_CHILDREN: int

    def getrusage(self, who: int) -> _ResourceUsage: ...


def _load_resource() -> _ResourceModule | None:
    try:
        import resource
    except ModuleNotFoundError:
        return None
    return cast(_ResourceModule, resource)


_RESOURCE = _load_resource()


def main(arguments: list[str] | None = None) -> int:
    argv = sys.argv[1:] if arguments is None else arguments
    if len(argv) != 2 or argv[0] not in {"prepare", "stage"}:
        return 2
    manifest_path = Path(argv[1])
    try:
        manifest = _manifest(manifest_path)
        fixed_head = _materialize_and_patch(manifest)
        if argv[0] == "prepare":
            output = _prepare_document(manifest, fixed_head)
            exit_code = 0
        else:
            return 2
    except Exception:
        return 2
    sys.stdout.buffer.write(output + b"\n")
    return exit_code


def stage_main(arguments: list[str]) -> int:
    if len(arguments) != 3 or arguments[0] != "stage" or arguments[1] not in _STAGES:
        return 2
    stage = arguments[1]
    started = time.monotonic()
    try:
        if _RESOURCE is None:
            raise ChildProtocolError
        cpu_started = _cpu_milliseconds()
        network_started = _network_packets()
        manifest = _manifest(Path(arguments[2]))
        fixed_head = _materialize_and_patch(manifest)
        exit_code, result_material = _run_stage(stage, manifest)
        elapsed = max(0, int((time.monotonic() - started) * 1000))
        cpu = max(0, _cpu_milliseconds() - cpu_started)
        usage = _RESOURCE.getrusage(_RESOURCE.RUSAGE_SELF)
        children = _RESOURCE.getrusage(_RESOURCE.RUSAGE_CHILDREN)
        peak = max(usage.ru_maxrss, children.ru_maxrss) * 1024
        output = build_stage_document(
            stage_id=stage,
            parent_head_sha=manifest["parent_head_sha"],
            fixed_head_sha=fixed_head,
            patch_sha256=manifest["patch"]["sha256"],
            bundle_sha256=manifest["bundle_sha256"],
            selected_image_digest=manifest["image_digest"],
            exit_code=exit_code,
            elapsed_ms=elapsed,
            cpu_time_ms=cpu,
            peak_memory_bytes=peak,
            disk_bytes=_directory_bytes(_WORKSPACE.parent),
            processes_peak=_processes_peak(),
            network_packets=max(0, _network_packets() - network_started),
            oom_killed=False,
            timed_out=False,
            result_sha256=hashlib.sha256(
                _RESULT_DOMAIN
                + canonical_json(
                    {
                        "fixed_head_sha": fixed_head,
                        "passed": exit_code == 0,
                        "result": result_material,
                        "stage_id": stage,
                    }
                )
            ).hexdigest(),
        )
    except Exception:
        return 2
    sys.stdout.buffer.write(output + b"\n")
    return exit_code


def _prepare_document(manifest: dict[str, Any], fixed_head: str) -> bytes:
    cases = manifest["regression"]["cases"]
    try:
        parent_state = _evaluate_root_cause(_INPUT / "source", manifest)
        fixed_state = _evaluate_root_cause(_WORKSPACE, manifest)
        if parent_state != "VULNERABLE" or fixed_state != "SAFE":
            raise ChildProtocolError
        observations = tuple(
            RegressionCaseResult(
                case_id=case["case_id"],
                status=RegressionObservationStatus.OBSERVED,
                observed_outcome=RegressionExpectedOutcome.NO_VIOLATION,
                output_sha256=hashlib.sha256(
                    (case["case_id"] + "\x00" + parent_state + "\x00" + fixed_state).encode("ascii")
                ).hexdigest(),
                output_size_bytes=1,
            )
            for case in cases
        )
    except Exception:
        observations = tuple(
            RegressionCaseResult(
                case_id=case["case_id"],
                status=RegressionObservationStatus.ORACLE_ERROR,
                observed_outcome=None,
                output_sha256=None,
                output_size_bytes=0,
            )
            for case in cases
        )
    return build_preparation_document(
        parent_head_sha=manifest["parent_head_sha"],
        fixed_head_sha=fixed_head,
        patch_sha256=manifest["patch"]["sha256"],
        bundle_sha256=manifest["bundle_sha256"],
        selected_image_digest=manifest["image_digest"],
        observations=observations,
    )


def _manifest(path: Path) -> dict[str, Any]:
    if path != _INPUT / "manifest.json" or path.is_symlink() or not path.is_file():
        raise ChildProtocolError
    document = closed_json(path.read_bytes())
    required = {
        "bundle_sha256",
        "files",
        "finding",
        "image_digest",
        "invariant",
        "parent_head_sha",
        "parent_tree_oid",
        "patch",
        "protocol_id",
        "protocol_version",
        "regression",
        "root_cause",
        "schema_version",
        "stages",
    }
    if (
        set(document) != required
        or document.get("schema_version") != "1.0.0"
        or document.get("protocol_id") != "securecode-local-repair-oci"
        or document.get("protocol_version") != "1.0.0"
        or document.get("stages") != list(_STAGES)
        or type(document.get("files")) is not list
        or type(document.get("patch")) is not dict
        or type(document.get("regression")) is not dict
    ):
        raise ChildProtocolError
    bundle = document.pop("bundle_sha256")
    expected = hashlib.sha256(_BUNDLE_DOMAIN + canonical_json(document)).hexdigest()
    document["bundle_sha256"] = bundle
    if bundle != expected:
        raise ChildProtocolError
    if document["finding"].get("cwe_id") == "CWE-78":
        validate_cwe78_manifest_contract(document)
    return document


def _materialize_and_patch(manifest: dict[str, Any]) -> str:
    if _WORKSPACE.exists():
        shutil.rmtree(_WORKSPACE)
    _WORKSPACE.mkdir(parents=True)
    expected_paths: set[str] = set()
    expected_files: dict[str, tuple[str, str]] = {}
    for raw in manifest["files"]:
        if type(raw) is not dict or set(raw) != {
            "blob_oid",
            "content_sha256",
            "mode",
            "path",
            "size_bytes",
        }:
            raise ChildProtocolError
        relative = raw["path"]
        source = _safe_path(_INPUT / "source", relative)
        destination = _safe_path(_WORKSPACE, relative)
        if source.is_symlink() or not source.is_file() or relative in expected_paths:
            raise ChildProtocolError
        content = source.read_bytes()
        if (
            len(content) != raw["size_bytes"]
            or hashlib.sha256(content).hexdigest() != raw["content_sha256"]
        ):
            raise ChildProtocolError
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        if raw["mode"] not in {"100644", "100755"}:
            raise ChildProtocolError
        destination.chmod(0o755 if raw["mode"] == "100755" else 0o644)
        expected_paths.add(relative)
        expected_files[relative] = (raw["content_sha256"], raw["mode"])
    input_items = tuple((_INPUT / "source").rglob("*"))
    if any(item.is_symlink() for item in input_items):
        raise ChildProtocolError
    actual = {
        item.relative_to(_INPUT / "source").as_posix() for item in input_items if item.is_file()
    }
    if actual != expected_paths:
        raise ChildProtocolError
    patch = _INPUT / "patch.diff"
    patch_meta = manifest["patch"]
    patch_bytes = patch.read_bytes()
    allowed_paths = patch_meta.get("allowed_paths")
    if (
        patch.is_symlink()
        or patch_meta.get("path") != "patch.diff"
        or type(allowed_paths) is not list
        or not allowed_paths
        or any(type(item) is not str or item not in expected_paths for item in allowed_paths)
        or allowed_paths != sorted(set(allowed_paths))
        or patch_meta.get("size_bytes") != len(patch_bytes)
        or patch_meta.get("sha256") != hashlib.sha256(patch_bytes).hexdigest()
    ):
        raise ChildProtocolError
    git = shutil.which("git")
    if not git:
        raise ChildProtocolError
    _command((git, "init", "--quiet", str(_WORKSPACE)), cwd=_WORKSPACE, timeout=10)
    _git(git, "apply", "--check", "--whitespace=nowarn", str(patch))
    _git(git, "apply", "--whitespace=nowarn", str(patch))
    workspace_items = tuple(_WORKSPACE.rglob("*"))
    if any(item.is_symlink() for item in workspace_items):
        raise ChildProtocolError
    actual_files: dict[str, tuple[str, str]] = {}
    for item in workspace_items:
        if not item.is_file() or ".git" in item.parts:
            continue
        mode = item.stat().st_mode & 0o777
        if mode not in {0o644, 0o755}:
            raise ChildProtocolError
        actual_files[item.relative_to(_WORKSPACE).as_posix()] = (
            hashlib.sha256(item.read_bytes()).hexdigest(),
            "100755" if mode == 0o755 else "100644",
        )
    if set(actual_files) != expected_paths:
        raise ChildProtocolError
    changed_paths = {
        path for path, identity in actual_files.items() if identity != expected_files[path]
    }
    if changed_paths != set(allowed_paths):
        raise ChildProtocolError
    _git(git, "add", "--all")
    tree = _git(git, "write-tree").decode("ascii").strip()
    parent = manifest["parent_head_sha"]
    commit = (
        f"tree {tree}\nparent {parent}\n"
        "author SecureCode Validator <validator@invalid> 0 +0000\n"
        "committer SecureCode Validator <validator@invalid> 0 +0000\n\n"
        "SecureCode ephemeral validation candidate\n"
    ).encode("ascii")
    return hashlib.sha1(
        f"commit {len(commit)}\0".encode("ascii") + commit,
        usedforsecurity=False,
    ).hexdigest()


def _run_stage(stage: str, manifest: dict[str, Any]) -> tuple[int, dict[str, object]]:
    if stage in {
        "validation-diff-parse",
        "validation-ephemeral-checkout",
        "validation-patch-apply",
    }:
        return 0, {"control": stage}
    if stage == "validation-resource-policy":
        return (0 if _isolation_canaries() else 1), {"control": stage}
    fixed = _current_fixed_head(manifest)
    if stage == "validation-language-policy":
        scan_hash, _ = _scan_repository(_WORKSPACE, manifest, fixed)
        return 0, {"scan_sha256": scan_hash}
    if stage == "validation-compile-types":
        plan = compile_plan(_WORKSPACE)
        if plan.indeterminate_reason is not None:
            return _INDETERMINATE_EXIT, {
                "command_count": len(plan.commands),
                "reason": plan.indeterminate_reason,
            }
        passed = bool(plan.commands) and _run_commands(plan.commands)
        if not passed:
            return 1, {"command_count": len(plan.commands)}
        return 0, {"command_count": len(plan.commands)}
    if stage == "validation-existing-tests":
        plan = test_plan(_WORKSPACE)
        if plan.indeterminate_reason is not None:
            return _INDETERMINATE_EXIT, {
                "command_count": len(plan.commands),
                "reason": plan.indeterminate_reason,
            }
        return (0 if plan.commands and _run_commands(plan.commands) else 1), {
            "command_count": len(plan.commands)
        }
    if stage in {
        "validation-security-poc",
        "validation-security-poc-plus",
    }:
        parent_state = _evaluate_root_cause(_INPUT / "source", manifest)
        fixed_state = _evaluate_root_cause(_WORKSPACE, manifest)
        return (0 if parent_state == "VULNERABLE" and fixed_state == "SAFE" else 1), {
            "fixed_root_cause_state": fixed_state,
            "parent_root_cause_state": parent_state,
        }
    if stage == "validation-post-patch-scan":
        scan_hash, count = _scan_repository(_WORKSPACE, manifest, fixed)
        fixed_state = _evaluate_root_cause(_WORKSPACE, manifest)
        comparison = _compare_repair_signals(manifest, fixed)
        return (0 if fixed_state == "SAFE" and comparison.passed else 1), {
            "fixed_root_cause_state": fixed_state,
            "new_signal_count": comparison.new_signal_count,
            "scan_sha256": scan_hash,
            "signal_count": count,
            "target_signal_removed": comparison.target_signal_removed,
        }
    if stage == "validation-regression-scan":
        parent_state = _evaluate_root_cause(_INPUT / "source", manifest)
        fixed_state = _evaluate_root_cause(_WORKSPACE, manifest)
        original_hash, original_count = _scan_repository(
            _INPUT / "source", manifest, manifest["parent_head_sha"]
        )
        fixed_hash, fixed_count = _scan_repository(_WORKSPACE, manifest, fixed)
        comparison = _compare_repair_signals(manifest, fixed)
        return (
            0 if parent_state == "VULNERABLE" and fixed_state == "SAFE" and comparison.passed else 1
        ), {
            "fixed_scan_sha256": fixed_hash,
            "fixed_signal_count": fixed_count,
            "fixed_root_cause_state": fixed_state,
            "new_signal_count": comparison.new_signal_count,
            "original_scan_sha256": original_hash,
            "original_signal_count": original_count,
            "parent_root_cause_state": parent_state,
            "target_signal_removed": comparison.target_signal_removed,
        }
    raise ChildProtocolError


def _target_cwe(manifest: dict[str, Any]) -> str:
    finding = manifest.get("finding")
    if type(finding) is not dict:
        raise ChildProtocolError
    cwe_id = finding.get("cwe_id")
    if type(cwe_id) is not str:
        raise ChildProtocolError
    return cwe_id


def _evaluate_root_cause(root: Path, manifest: dict[str, Any]) -> str:
    if _target_cwe(manifest) == "CWE-89":
        return evaluate_cwe89_root_cause(root, manifest)
    if _target_cwe(manifest) == "CWE-78":
        return evaluate_cwe78_root_cause(root, manifest)
    raise ChildProtocolError


def _scan_repository(root: Path, manifest: dict[str, Any], revision: str) -> tuple[str, int]:
    if _target_cwe(manifest) == "CWE-89":
        return scan_cwe89_repository(root, manifest, revision)
    if _target_cwe(manifest) == "CWE-78":
        return scan_cwe78_repository(root, manifest, revision)
    raise ChildProtocolError


def _compare_repair_signals(
    manifest: dict[str, Any], fixed: str
) -> Cwe89RepairSignalComparison | Cwe78RepairSignalComparison:
    if _target_cwe(manifest) == "CWE-89":
        return compare_cwe89_repair_signals(
            _INPUT / "source",
            _WORKSPACE,
            manifest,
            parent_revision=manifest["parent_head_sha"],
            fixed_revision=fixed,
        )
    if _target_cwe(manifest) == "CWE-78":
        return compare_cwe78_repair_signals(
            _INPUT / "source",
            _WORKSPACE,
            manifest,
            parent_revision=manifest["parent_head_sha"],
            fixed_revision=fixed,
        )
    raise ChildProtocolError


def _run_commands(commands: tuple[tuple[str, ...], ...]) -> bool:
    return all(
        _command(command, cwd=_WORKSPACE, timeout=60, check=False) == 0 for command in commands
    )


def _git(executable: str, *arguments: str) -> bytes:
    return cast(
        bytes,
        _command(
            (
                executable,
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.autocrlf=false",
                *arguments,
            ),
            cwd=_WORKSPACE,
            timeout=30,
            capture=True,
        ),
    )


def _command(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    timeout: int,
    check: bool = True,
    capture: bool = False,
) -> bytes | int:
    environment = {
        "HOME": "/tmp",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "TMPDIR": "/tmp",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "",
        "PYTHONNOUSERSITE": "1",
    }
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(
                argv,
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=output,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            if check:
                raise ChildProtocolError from None
            return 255
        if check and result.returncode != 0:
            raise ChildProtocolError
        if not capture:
            return result.returncode
        output.seek(0)
        value = output.read(4097)
        if len(value) > 4096:
            raise ChildProtocolError
        return value


def _current_fixed_head(manifest: dict[str, Any]) -> str:
    git = shutil.which("git")
    if not git:
        raise ChildProtocolError
    tree = _git(git, "write-tree").decode("ascii").strip()
    parent = manifest["parent_head_sha"]
    commit = (
        f"tree {tree}\nparent {parent}\n"
        "author SecureCode Validator <validator@invalid> 0 +0000\n"
        "committer SecureCode Validator <validator@invalid> 0 +0000\n\n"
        "SecureCode ephemeral validation candidate\n"
    ).encode("ascii")
    return hashlib.sha1(
        f"commit {len(commit)}\0".encode("ascii") + commit, usedforsecurity=False
    ).hexdigest()


def _safe_path(root: Path, relative: object) -> Path:
    if type(relative) is not str or not relative or "\x00" in relative or "\\" in relative:
        raise ChildProtocolError
    path = (root / Path(*relative.split("/"))).absolute()
    try:
        path.relative_to(root)
    except ValueError:
        raise ChildProtocolError from None
    return path


def _directory_bytes(root: Path) -> int:
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ChildProtocolError
        if path.is_file():
            total += path.stat().st_size
    return total


def _network_packets() -> int:
    try:
        total = 0
        for line in Path("/proc/net/dev").read_text(encoding="ascii").splitlines()[2:]:
            name, _, values = line.partition(":")
            if name.strip() == "lo":
                continue
            fields = values.split()
            total += int(fields[1]) + int(fields[9])
        return total
    except Exception:
        raise ChildProtocolError from None


def _isolation_canaries() -> bool:
    if not _process_security_canaries():
        return False
    if any(
        path.exists()
        for path in (
            Path("/var/run/docker.sock"),
            Path("/run/docker.sock"),
            Path("/host"),
            Path("/root/.docker/config.json"),
        )
    ):
        return False
    if any(
        marker in name.upper()
        for name in os.environ
        for marker in ("TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API_KEY", "ACCESS_KEY")
    ):
        return False
    try:
        if {name for _index, name in socket.if_nameindex()} != {"lo"}:
            return False
    except OSError:
        return False
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.2)
    try:
        return probe.connect_ex(("192.0.2.1", 9)) != 0
    finally:
        probe.close()


def _process_security_canaries() -> bool:
    get_uid = getattr(os, "geteuid", None)
    get_gid = getattr(os, "getegid", None)
    if not callable(get_uid) or not callable(get_gid):
        return False
    try:
        if get_uid() != 65532 or get_gid() != 65532:
            return False
        status = Path("/proc/self/status").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return False
    fields: dict[str, str] = {}
    for line in status.splitlines():
        key, separator, value = line.partition(":")
        if key in {
            "Uid",
            "Gid",
            "NoNewPrivs",
            "Seccomp",
            "CapInh",
            "CapPrm",
            "CapEff",
            "CapAmb",
        }:
            if not separator or key in fields:
                return False
            fields[key] = value.strip()
    if (
        fields.get("Uid") != "65532 65532 65532 65532"
        or fields.get("Gid") != "65532 65532 65532 65532"
        or fields.get("NoNewPrivs") != "1"
        or fields.get("Seccomp") != "2"
    ):
        return False
    for name in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
        capability = fields.get(name)
        if (
            capability is None
            or not capability
            or any(character not in "0123456789abcdefABCDEF" for character in capability)
        ):
            return False
        if int(capability, 16) != 0:
            return False
    return True


def _processes_peak() -> int:
    for path in (Path("/sys/fs/cgroup/pids.peak"), Path("/sys/fs/cgroup/pids.current")):
        try:
            return max(1, int(path.read_text(encoding="ascii").strip()))
        except (OSError, ValueError):
            continue
    raise ChildProtocolError


def _cpu_milliseconds() -> int:
    if _RESOURCE is None:
        raise ChildProtocolError
    own = _RESOURCE.getrusage(_RESOURCE.RUSAGE_SELF)
    children = _RESOURCE.getrusage(_RESOURCE.RUSAGE_CHILDREN)
    return int((own.ru_utime + own.ru_stime + children.ru_utime + children.ru_stime) * 1000)


if __name__ == "__main__":
    selected = sys.argv[1:]
    raise SystemExit(stage_main(selected) if selected[:1] == ["stage"] else main(selected))
