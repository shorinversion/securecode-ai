"""P5.13 unit contracts for the installed Linux CI worker command."""

from __future__ import annotations

import io
import json
import sys
from importlib import util
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKER_SOURCE = ROOT / "apps" / "worker" / "src"
if str(WORKER_SOURCE) not in sys.path:
    sys.path.insert(0, str(WORKER_SOURCE))

from securecode_ai.contracts import AuditRunOutcome, CliExitCode  # noqa: E402
from securecode_ai.worker import cli  # noqa: E402


def _fixture() -> Any:
    path = ROOT / "tests" / "unit" / "test_ci_worker.py"
    specification = util.spec_from_file_location("p5_11_worker_unit_contract", path)
    if specification is None or specification.loader is None:
        raise RuntimeError("P5.11 fixture is unavailable")
    module = util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _payload(outcome: AuditRunOutcome = AuditRunOutcome.PASS) -> bytes:
    fixture = _fixture()
    return cast(bytes, fixture._admitted_run(outcome=outcome).model_dump_json().encode("utf-8"))


@pytest.mark.skipif(sys.platform != "linux", reason="P5.13 is Linux-only")
@pytest.mark.parametrize("outcome", list(AuditRunOutcome))
def test_stdin_publishes_only_the_p512_artifact_for_each_admitted_outcome(
    tmp_path: Path, outcome: AuditRunOutcome
) -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()

    code = cli.main(
        ["--artifact-root", str(tmp_path)],
        stdin=io.BytesIO(_payload(outcome)),
        stdout=stdout,
        stderr=stderr,
    )

    stored = tuple(tmp_path.glob("tenants/*/*.json"))
    assert code == int(
        {
            AuditRunOutcome.PASS: CliExitCode.COMPLETED,
            AuditRunOutcome.FAIL: CliExitCode.POLICY_FAIL,
            AuditRunOutcome.INDETERMINATE: CliExitCode.INDETERMINATE,
            AuditRunOutcome.ERROR: CliExitCode.OPERATIONAL_ERROR,
            AuditRunOutcome.CANCELLED: CliExitCode.CANCELLED_OR_SUPERSEDED,
            AuditRunOutcome.SUPERSEDED: CliExitCode.CANCELLED_OR_SUPERSEDED,
        }[outcome]
    )
    assert len(stored) == 1
    artifact_reference = json.loads(stdout.getvalue())
    assert artifact_reference["data_class"] == "DC1_INTERNAL_METADATA"
    assert stderr.getvalue() == ""
    assert json.loads(stored[0].read_text(encoding="ascii"))["audit_outcome"] == outcome.value


@pytest.mark.skipif(sys.platform != "linux", reason="P5.13 is Linux-only")
def test_file_input_replay_is_idempotent(tmp_path: Path) -> None:
    input_path = tmp_path / "audit-run.json"
    input_path.write_bytes(_payload())
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()

    first = cli.main(["--artifact-root", str(artifact_root), "--input", str(input_path)])
    second = cli.main(["--input", str(input_path), "--artifact-root", str(artifact_root)])

    assert (first, second) == (0, 0)
    assert len(tuple(artifact_root.glob("tenants/*/*.json"))) == 1


@pytest.mark.skipif(sys.platform != "linux", reason="P5.13 is Linux-only")
def test_json_whitespace_prefix_keeps_the_admitted_result(tmp_path: Path) -> None:
    stdout = io.StringIO()

    code = cli.main(
        ["--artifact-root", str(tmp_path)],
        stdin=io.BytesIO(b" \n\t" + _payload()),
        stdout=stdout,
    )

    assert code == int(CliExitCode.COMPLETED)
    assert json.loads(stdout.getvalue())["data_class"] == "DC1_INTERNAL_METADATA"
    assert len(tuple(tmp_path.glob("tenants/*/*.json"))) == 1


@pytest.mark.parametrize(
    "payload",
    (
        b"",
        b"{}",
        b"{}{}",
        b'{"schema_version":"0.2.0","schema_version":"0.2.0"}',
        pytest.param(b"{" + b"x" * (8 * 1024 * 1024 + 1) + b"}", id="oversize"),
        pytest.param(b"[" * 10_000 + b"0" + b"]" * 10_000, id="deep-invalid"),
    ),
)
def test_invalid_documents_fail_closed(payload: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_require_linux", lambda: None)
    monkeypatch.setattr(cli, "_validate_artifact_root", lambda root: None)
    stderr = io.StringIO()

    code = cli.main(
        ["--artifact-root", "/configured-root"], stdin=io.BytesIO(payload), stderr=stderr
    )

    assert code == int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    assert stderr.getvalue() == "invalid worker input\n"


@pytest.mark.skipif(sys.platform != "linux", reason="P5.13 is Linux-only")
def test_unknown_and_stale_audit_runs_fail_closed_before_artifact_write(tmp_path: Path) -> None:
    unknown = json.loads(_payload())
    unknown["unexpected"] = True
    stale = json.loads(_payload(AuditRunOutcome.SUPERSEDED))
    stale["current_head_sha"] = stale["execution_identity"]["repository_revision"]["head_sha"]

    for document in (unknown, stale):
        stderr = io.StringIO()
        code = cli.main(
            ["--artifact-root", str(tmp_path)],
            stdin=io.BytesIO(json.dumps(document).encode("utf-8")),
            stderr=stderr,
        )
        assert code == int(CliExitCode.INVALID_USAGE_OR_CONFIG)
        assert stderr.getvalue() == "invalid worker input\n"
    assert not tuple(tmp_path.glob("tenants/*/*.json"))


@pytest.mark.skipif(sys.platform != "linux", reason="P5.13 is Linux-only")
def test_relative_file_or_artifact_root_fails_closed_without_publication(tmp_path: Path) -> None:
    input_path = tmp_path / "audit-run.json"
    input_path.write_bytes(_payload())
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    stderr = io.StringIO()

    relative_input = cli.main(
        ["--artifact-root", str(artifact_root), "--input", input_path.name], stderr=stderr
    )
    relative_root = cli.main(
        ["--artifact-root", "artifacts"], stdin=io.BytesIO(_payload()), stderr=stderr
    )

    assert (relative_input, relative_root) == (
        int(CliExitCode.INVALID_USAGE_OR_CONFIG),
        int(CliExitCode.INVALID_USAGE_OR_CONFIG),
    )
    assert stderr.getvalue() == "invalid worker input\ninvalid worker input\n"
    assert not tuple(artifact_root.glob("tenants/*/*.json"))


def test_non_linux_rejects_without_publication(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "platform", "win32")

    code = cli.main(["--artifact-root", str(tmp_path)], stdin=io.BytesIO(_payload()), stderr=stderr)

    assert code == int(CliExitCode.OPERATIONAL_ERROR)
    assert stderr.getvalue() == "worker operation failed\n"
    assert not tuple(tmp_path.iterdir())
