"""Offline, deterministic P4.12 composition for the pinned CWE-89 reference.

The script uses only synthetic repository fixtures.  It copies them into an
ephemeral workspace, emits metadata-only CLI reports, and never applies a
patch, contacts a network service, reads credentials, or declares product PASS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from pathlib import Path

from securecode_ai.adapters import (
    analyze_python_ast,
    build_python_symbol_index,
    scan_python_cwe89,
)
from securecode_ai.cli import RepairCli, RepairFormat, render_receipt
from securecode_ai.contracts import CliCommand, CliExitCode

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE_ROOT = _REPOSITORY_ROOT / "tests" / "fixtures" / "p4_10"
_MANIFEST_NAME = "mvp-demo-manifest.json"
_REPORT_NAMES = {
    "scan": "scan.json",
    "fix": "fix.json",
    "validate": "validate.json",
    "markdown": "final-report.md",
    "html": "final-report.html",
    "sarif": "final-report.sarif",
}
_PATCH_OLD = b'return db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()'
_PATCH_NEW = b'return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()'


class DemoError(ValueError):
    """Bounded diagnostic for invalid local demo setup or immutable inputs."""


def run_demo(output_directory: Path) -> dict[str, object]:
    """Run the reference composition and write deterministic, redacted artifacts.

    ``output_directory`` must be absent or empty.  The fixture tree is copied to
    a temporary directory and the source fixture digests are verified both before
    and after execution, so the demo cannot mutate its pinned original inputs.
    """

    destination = _checked_destination(output_directory)
    source_manifest = _load_manifest(_FIXTURE_ROOT / "manifest.json")
    vulnerable_source = _FIXTURE_ROOT / "vulnerable" / "app.py"
    safe_source = _FIXTURE_ROOT / "safe" / "app.py"
    original_digests = {
        "vulnerable": _sha256(vulnerable_source.read_bytes()),
        "safe_control": _sha256(safe_source.read_bytes()),
    }
    _verify_fixture_manifest(source_manifest, original_digests)

    with tempfile.TemporaryDirectory(prefix="securecode-p4-12-") as temporary:
        workspace = Path(temporary) / "reference"
        shutil.copytree(_FIXTURE_ROOT, workspace)
        execution = _run_ephemeral_reference(workspace, source_manifest)

    if original_digests != {
        "vulnerable": _sha256(vulnerable_source.read_bytes()),
        "safe_control": _sha256(safe_source.read_bytes()),
    }:
        raise DemoError("pinned fixture integrity changed during demo")

    destination.mkdir(parents=True, exist_ok=True)
    reports = _write_reports(destination, execution["receipts"])
    manifest = _build_manifest(source_manifest, original_digests, execution, reports)
    _write_canonical(destination / _MANIFEST_NAME, manifest)
    return manifest


def _run_ephemeral_reference(
    workspace: Path,
    fixture_manifest: dict[str, object],
) -> dict[str, object]:
    identities = fixture_manifest.get("identities")
    if not isinstance(identities, dict):
        raise DemoError("reference identities are invalid")
    repository_id = _required_text(identities, "repository_id")
    vulnerable_head = _required_text(identities, "vulnerable_head_sha")
    fixed_head = _required_text(identities, "fixed_head_sha")
    vulnerable_path = workspace / "vulnerable" / "app.py"
    safe_path = workspace / "safe" / "app.py"
    fixed_path = workspace / "fixed" / "app.py"

    vulnerable_signals = _scan(vulnerable_path, repository_id, vulnerable_head)
    safe_signals = _scan(safe_path, repository_id, fixed_head)
    fixed_path.parent.mkdir()
    fixed_path.write_bytes(_fixed_bytes(vulnerable_path.read_bytes()))
    fixed_signals = _scan(fixed_path, repository_id, fixed_head)
    patch_sha256 = _sha256(_PATCH_OLD + b"\x00" + _PATCH_NEW)

    cli = RepairCli(
        scan=lambda target: _scan_metadata(target, vulnerable_signals, safe_signals),
        fix=lambda target: _fix_metadata(target, patch_sha256, vulnerable_signals),
        validate=lambda target: _validate_metadata(target, fixed_signals),
    )
    receipts = {
        "scan": cli.run(CliCommand.SCAN, "p4_10_vulnerable"),
        "fix": cli.run(CliCommand.FIX, "p4_10_candidate"),
        "validate": cli.run(CliCommand.VALIDATE, "p4_10_ephemeral_candidate"),
    }
    if any(receipt.exit_code is not CliExitCode.COMPLETED for receipt in receipts.values()):
        raise DemoError("reference CLI composition was not completed")
    return {
        "receipts": receipts,
        "signal_counts": {
            "vulnerable": len(vulnerable_signals),
            "safe_control": len(safe_signals),
            "ephemeral_fixed": len(fixed_signals),
        },
        "patch_sha256": patch_sha256,
    }


def _scan(path: Path, repository_id: str, revision: str) -> tuple[object, ...]:
    source = path.read_bytes()
    index = build_python_symbol_index(
        repository_id=repository_id,
        revision=revision,
        path="app.py",
        content_sha256=_sha256(source),
        source=source,
    )
    return scan_python_cwe89(index, analyze_python_ast(index)).signals


def _scan_metadata(
    target: str,
    vulnerable_signals: tuple[object, ...],
    safe_signals: tuple[object, ...],
) -> dict[str, object]:
    if target != "p4_10_vulnerable" or len(vulnerable_signals) != 1 or safe_signals:
        return {"exit_code": int(CliExitCode.POLICY_FAIL), "reason": "reference_scan_mismatch"}
    return {
        "case_id": "CWE89-VULN-001",
        "deterministic_signal_count": len(vulnerable_signals),
        "safe_control_signal_count": len(safe_signals),
    }


def _fix_metadata(
    target: str,
    patch_sha256: str,
    vulnerable_signals: tuple[object, ...],
) -> dict[str, object]:
    if target != "p4_10_candidate" or len(vulnerable_signals) != 1:
        return {"exit_code": int(CliExitCode.POLICY_FAIL), "reason": "reference_fix_mismatch"}
    return {
        "candidate_status": "SUGGESTED_REFERENCE_PATCH",
        "patch_sha256": patch_sha256,
        "patch_applied_to_original": False,
    }


def _validate_metadata(target: str, fixed_signals: tuple[object, ...]) -> dict[str, object]:
    if target != "p4_10_ephemeral_candidate" or fixed_signals:
        return {
            "exit_code": int(CliExitCode.POLICY_FAIL),
            "reason": "reference_validation_mismatch",
        }
    return {
        "ephemeral_candidate_cwe89_signal_count": len(fixed_signals),
        "validation_scope": "pinned_reference_composition",
        "original_checkout_changed": False,
    }


def _write_reports(destination: Path, receipts: object) -> dict[str, str]:
    if not isinstance(receipts, dict):
        raise DemoError("reference receipts are invalid")
    scan = receipts.get("scan")
    fix = receipts.get("fix")
    validate = receipts.get("validate")
    if scan is None or fix is None or validate is None:
        raise DemoError("reference receipts are incomplete")
    documents = {
        _REPORT_NAMES["scan"]: render_receipt(scan, RepairFormat.JSON),
        _REPORT_NAMES["fix"]: render_receipt(fix, RepairFormat.JSON),
        _REPORT_NAMES["validate"]: render_receipt(validate, RepairFormat.JSON),
        _REPORT_NAMES["markdown"]: render_receipt(validate, RepairFormat.MARKDOWN),
        _REPORT_NAMES["html"]: render_receipt(validate, RepairFormat.HTML),
        _REPORT_NAMES["sarif"]: render_receipt(validate, RepairFormat.SARIF),
    }
    result: dict[str, str] = {}
    for name in sorted(documents):
        payload = documents[name]
        (destination / name).write_bytes(payload)
        result[name] = _sha256(payload)
    return result


def _build_manifest(
    fixture_manifest: dict[str, object],
    original_digests: dict[str, str],
    execution: dict[str, object],
    reports: dict[str, str],
) -> dict[str, object]:
    dataset = fixture_manifest.get("dataset")
    if not isinstance(dataset, dict):
        raise DemoError("reference dataset is invalid")
    counts = execution.get("signal_counts")
    patch_sha256 = execution.get("patch_sha256")
    if not isinstance(counts, dict) or not isinstance(patch_sha256, str):
        raise DemoError("reference execution is invalid")
    return {
        "artifact_schema_version": "securecode.p4_12.mvp-demo.v1",
        "dataset": dataset,
        "ephemeral_workspace": True,
        "network_access": "not_used",
        "original_fixture_sha256": original_digests,
        "patch_sha256": patch_sha256,
        "product_outcome": "NOT_EVALUATED",
        "product_pass": False,
        "reference_outcome": "COMPLETED",
        "report_sha256": reports,
        "signal_counts": counts,
        "limitations": [
            "The run covers one pinned synthetic Python CWE-89 reference only.",
            "It does not establish general detection accuracy, release readiness, or gate GO.",
            "CLI completion is an operation receipt and is not a product PASS claim.",
            "The demo does not apply a patch, create an SCM change, or replace full G4 evidence.",
        ],
    }


def _verify_fixture_manifest(manifest: dict[str, object], digests: dict[str, str]) -> None:
    dataset = manifest.get("dataset")
    cases = manifest.get("cases")
    if (
        not isinstance(dataset, dict)
        or dataset.get("dataset_id") != "SC-MVP-CWE89"
        or not isinstance(cases, list)
        or digests["vulnerable"] != _case_digest(cases, "CWE89-VULN-001")
        or digests["safe_control"] != _case_digest(cases, "CWE89-SAFE-001")
    ):
        raise DemoError("pinned fixture manifest does not match source bytes")


def _case_digest(cases: list[object], case_id: str) -> str:
    for item in cases:
        if isinstance(item, dict) and item.get("case_id") == case_id:
            parts = item.get("sha256_parts")
            if (
                isinstance(parts, list)
                and len(parts) == 8
                and all(isinstance(part, str) and len(part) == 8 for part in parts)
            ):
                return "".join(parts)
    raise DemoError("pinned fixture digest is invalid")


def _fixed_bytes(vulnerable: bytes) -> bytes:
    if vulnerable.count(_PATCH_OLD) != 1:
        raise DemoError("reference patch input is invalid")
    return vulnerable.replace(_PATCH_OLD, _PATCH_NEW, 1)


def _checked_destination(value: Path) -> Path:
    if not isinstance(value, Path):
        raise DemoError("output directory must be a pathlib Path")
    destination = value.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise DemoError("output directory must be absent or empty")
    return destination


def _load_manifest(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise DemoError("pinned fixture manifest is unavailable") from None
    if not isinstance(value, dict):
        raise DemoError("pinned fixture manifest is invalid")
    return value


def _required_text(value: dict[str, object], field: str) -> str:
    result = value.get(field)
    if type(result) is not str or not result:
        raise DemoError("reference identity is invalid")
    return result


def _write_canonical(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the offline pinned CWE-89 MVP demo.")
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Absent or empty directory for generated metadata-only artifacts.",
    )
    arguments = parser.parse_args(argv)
    try:
        manifest = run_demo(arguments.output)
    except DemoError as error:
        print(f"demo_error={error}")
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    print(json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return int(CliExitCode.COMPLETED)


if __name__ == "__main__":
    raise SystemExit(main())
