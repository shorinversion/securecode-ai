"""Installed product CLI must use actual host admission, not repair receipts."""

import json
import os
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from securecode_ai.adapters.local_product_host_primitives import _ProtectedAnchor
from securecode_ai.contracts import CliErrorCode, CliErrorResult

from tests.unit.test_local_product_host import synthetic_anchor as _untyped_synthetic_anchor

synthetic_anchor: Callable[[int], _ProtectedAnchor] = _untyped_synthetic_anchor

SOURCE = (
    b'def get_user(request, db):\n user_id = request.args.get("user_id")\n'
    b' return db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()\n'
)


@contextmanager
def scripted_peer(
    *,
    zero: bool = False,
    failure: bool = False,
    refuse_skeptic: bool = False,
    verdict: str = "CONFIRMED",
    late_auditor_failure: bool = False,
) -> Iterator[tuple[int, list[str], list[object]]]:
    """Ephemeral protocol peer, expressly not a provider accuracy test."""
    roles: list[str] = []
    received: list[object] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def do_POST(self) -> None:
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            context = json.loads(payload["messages"][-1]["content"])
            role = context["trusted_controls"]["role"]
            roles.append(role)
            received.append(context)
            if failure or (
                late_auditor_failure and role == "auditor" and roles.count("auditor") > 1
            ):
                self.send_response(503)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if role == "discovery":
                locations = context["untrusted_source_locations"]
                root = max(locations, key=lambda item: item["location"]["start"]["line"])
                result: object = {
                    "candidates": []
                    if zero
                    else [
                        {
                            "rule_id": "cwe-89-sql-interpolation",
                            "root_evidence_id": root["evidence_id"],
                            "evidence_ids": [root["evidence_id"]],
                        }
                    ]
                }
            elif role == "auditor":
                cited = [
                    item
                    for evidence in context["untrusted_evidence"]
                    for item in evidence["evidence_ids"]
                ]
                result = {
                    "finding_verdict": verdict,
                    "cited_evidence_ids": cited,
                    "rationale": "scripted protocol plumbing only",
                }
            else:
                result = {"finding_verdict": verdict, "objections": []}
            body = json.dumps(
                {
                    "id": "scripted-local",
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {
                                "content": json.dumps(result),
                                "refusal": "REFUSED"
                                if refuse_skeptic and role == "skeptic"
                                else None,
                            },
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5},
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    peer = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=peer.serve_forever, daemon=True)
    thread.start()
    try:
        yield peer.server_port, roles, received
    finally:
        peer.shutdown()
        peer.server_close()
        thread.join(timeout=5)


def git_repository(tmp_path: Path, *, source: bytes = SOURCE, manifest: bool = False) -> Path:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "a.py").write_bytes(source)
    if manifest:
        (checkout / "requirements.txt").write_bytes(b"requests==2.19.0\n")
    for arguments in (
        ("init",),
        ("add", "."),
        (
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "public scripted fixture",
        ),
    ):
        subprocess.run(["git", "-C", str(checkout), *arguments], capture_output=True, check=True)
    return checkout


def installed_child(
    tmp_path: Path,
    checkout: Path,
    port: int,
    *,
    report_format: str = "json",
    output: Path | None = None,
    extra: tuple[str, ...] = (),
    mutation: str = "",
) -> subprocess.CompletedProcess[str]:
    root = Path(__file__).resolve().parents[2]
    launcher = tmp_path / "installed_plumbing_child.py"
    # Only this child simulates the OS administrator boundary. Production has no
    # environment, repository or CLI hook capable of installing this replacement.
    launcher.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(root)!r})\n"
        "if __name__ == '__main__':\n"
        " from tests.unit.test_local_product_host import synthetic_anchor\n"
        " from securecode_ai.adapters import local_product_host as host\n"
        f" anchor = synthetic_anchor({port})\n"
        f" {mutation or 'pass'}\n"
        " host._read_platform_anchor = lambda: anchor\n"
        " from securecode_ai.cli.application import main\n"
        " raise SystemExit(main())\n",
        encoding="utf-8",
    )
    arguments = [
        sys.executable,
        "-I",
        str(launcher),
        "scan",
        str(checkout),
        "--format",
        report_format,
        "--json",
        *extra,
    ]
    if output is not None:
        arguments.extend(("--output", str(output)))
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.startswith("SECURECODE_"):
            del environment[name]
    environment["APPDATA"] = str(tmp_path / "user-config")
    environment["XDG_CONFIG_HOME"] = str(tmp_path / "user-config")
    return subprocess.run(
        arguments, env=environment, capture_output=True, text=True, timeout=60, check=False
    )


def test_actual_installed_default_reaches_all_guarded_roles_and_core_report(tmp_path: Path) -> None:
    checkout = git_repository(tmp_path)
    with scripted_peer() as (port, roles, _received):
        result = installed_child(tmp_path, checkout, port)
    document = json.loads(result.stdout)
    assert result.returncode == 2, result.stdout + result.stderr
    assert roles[0] == "discovery" and set(roles) == {"discovery", "auditor", "skeptic"}
    assert document["outcome"] == "FAIL"
    assert document["coverage_manifest"]["coverage_complete"]
    assert document["findings"][0]["cwe_id"] == "CWE-89"
    assert "product_outcome" not in document


@pytest.mark.parametrize("publication_change", ["none", "cancel", "stale"])
def test_actual_local_runner_direct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, publication_change: str
) -> None:
    from securecode_ai.adapters import local_product_host as host_module
    from securecode_ai.adapters import local_product_runner as runner
    from securecode_ai.core.reports import ReportFormat

    checkout = git_repository(tmp_path)
    with scripted_peer() as (port, roles, _received):
        anchor = synthetic_anchor(port)
        monkeypatch.setattr(host_module, "_read_platform_anchor", lambda: anchor)
        host = host_module.load_local_product_host()
        result = runner._run_local_product_scan(
            host, str(checkout), ReportFormat.JSON, runner.resolve_local_product_configuration(host)
        )
    assert result.exit_code == 2
    assert roles[0] == "discovery" and set(roles) == {"discovery", "auditor", "skeptic"}
    import hashlib

    reference = result.composition.report.findings[0].finding.evidence_graph_ref
    assert reference.size_bytes == len(result.graph_artifact) > 0
    assert reference.content_sha256 == hashlib.sha256(result.graph_artifact).hexdigest()
    if publication_change == "cancel":
        result.cancel()
        with pytest.raises(runner.LocalProductCancelledError):
            result.require_publication()
    elif publication_change == "stale":
        subprocess.run(
            [
                "git",
                "-C",
                str(checkout),
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--allow-empty",
                "-m",
                "new HEAD",
            ],
            check=True,
            capture_output=True,
        )
        with pytest.raises(runner.LocalProductSupersededError):
            result.require_publication()


@pytest.mark.parametrize("verdict", ["CONFIRMED", "REJECTED_WITH_EVIDENCE"])
@pytest.mark.parametrize(
    "approval_change",
    [
        "unchanged",
        "revoked",
        "malformed",
        "unprotected",
        "record-bytes",
        "bundle",
        "policy",
        "manifest",
    ],
)
def test_actual_publication_requires_exact_fresh_protected_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    verdict: str,
    approval_change: str,
) -> None:
    import hashlib
    from dataclasses import replace

    from securecode_ai.adapters import local_product_host as host_module
    from securecode_ai.adapters import local_product_runner as runner
    from securecode_ai.contracts import ComponentPin, EgressPolicyDocument
    from securecode_ai.core.reports import ReportFormat
    from securecode_ai.core.runtime import build_default_workflow_definition

    checkout = git_repository(tmp_path)
    with scripted_peer(verdict=verdict) as (port, _roles, _received):
        anchor = synthetic_anchor(port)
        monkeypatch.setattr(host_module, "_read_platform_anchor", lambda: anchor)
        host = host_module.load_local_product_host()
        result = runner.run_local_product_scan(
            host=host,
            target=str(checkout),
            report_format=ReportFormat.JSON,
            configuration=runner.resolve_local_product_configuration(host),
        )
    original_outcome = result.composition.run.audit_outcome
    assert result.exit_code == (2 if verdict == "CONFIRMED" else 0)
    sarif = json.loads(result.sarif_rendered)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["automationDetails"]["id"] == result.composition.run.run_id
    if approval_change == "unchanged":
        calls = []

        def fresh() -> object:
            calls.append("protected-reader")
            return anchor

        monkeypatch.setattr(host_module, "_read_platform_anchor", fresh)
        result.require_publication()
        assert calls == ["protected-reader"]
        return
    if approval_change in {"revoked", "unprotected"}:

        def denied() -> None:
            raise host_module.LocalProductHostError()

        monkeypatch.setattr(host_module, "_read_platform_anchor", denied)
    else:
        record, manifest = json.loads(anchor.approval_record), json.loads(anchor.artifact_manifest)
        if approval_change == "malformed":
            raw_record = b'{"schema_version":'
        elif approval_change == "record-bytes":
            raw_record = anchor.approval_record + b"\n"
        else:
            if approval_change == "bundle":
                record["bundle"]["review_receipt"]["component_id"] = "alternate-independent-review"
                bundle = host_module.LocalProviderEvidenceBundle.model_validate_json(
                    json.dumps(record["bundle"])
                )
                record["bundle_sha256"] = bundle.content_sha256
                record["pins"]["approved_bundle_sha256"] = bundle.content_sha256
                record["pins"]["review_receipt"] = bundle.review_receipt.model_dump(mode="json")
            elif approval_change == "policy":
                record["policy"]["rules"][0]["max_bytes"] += 1024
                policy = EgressPolicyDocument.model_validate_json(json.dumps(record["policy"]))
                record["policy_sha256"] = policy.canonical_content_hash()
                pin = ComponentPin(
                    schema_version="0.2.0",
                    component_id=policy.policy_id,
                    component_version=policy.policy_version,
                    content_sha256=policy.canonical_content_hash(),
                )
                manifest["workflow_sha256"] = build_default_workflow_definition(
                    policy_pin=pin
                ).component_pin.content_sha256
            else:
                manifest["skeptic_prompt_sha256"] = "0" * 64
            raw_record = host_module._canonical(record)
        raw_manifest = host_module._canonical(manifest)
        changed = replace(
            anchor,
            approval_record=raw_record,
            approval_record_sha256=hashlib.sha256(raw_record).hexdigest(),
            artifact_manifest=raw_manifest,
            artifact_manifest_sha256=hashlib.sha256(raw_manifest).hexdigest(),
        )
        monkeypatch.setattr(host_module, "_read_platform_anchor", lambda: changed)
        if approval_change != "malformed":
            # The new protected record is internally valid and freshly reviewed.
            # It still cannot replace the authority of this existing run.
            assert (
                host_module.load_local_product_host().approval_record_sha256
                == changed.approval_record_sha256
            )
    with pytest.raises(runner.LocalProductUnavailableError):
        result.require_publication()
    assert result.composition.run.audit_outcome is original_outcome


@pytest.mark.parametrize("report_format", ["sarif", "markdown", "html"])
def test_actual_installed_report_formats_retain_policy_fail(
    tmp_path: Path, report_format: str
) -> None:
    checkout = git_repository(tmp_path)
    output = tmp_path / ("report." + report_format)
    with scripted_peer() as (port, roles, _received):
        result = installed_child(
            tmp_path, checkout, port, report_format=report_format, output=output
        )
    assert result.returncode == 2, result.stdout + result.stderr
    assert roles[0] == "discovery" and set(roles) == {"discovery", "auditor", "skeptic"}
    assert output.read_bytes().decode().rstrip("\n") == result.stdout.rstrip("\n")
    assert "CWE-89" in result.stdout


@pytest.mark.parametrize("failure", [False, True])
def test_zero_scanner_still_invokes_mandatory_discovery(tmp_path: Path, failure: bool) -> None:
    checkout = git_repository(tmp_path, source=b"answer = 42\n")
    with scripted_peer(zero=True, failure=failure) as (port, roles, _received):
        result = installed_child(tmp_path, checkout, port)
    assert roles == ["discovery"]
    assert result.returncode == 3, result.stdout + result.stderr


def test_manifest_without_production_adapter_is_non_pass(tmp_path: Path) -> None:
    checkout = git_repository(tmp_path, source=b"answer = 42\n", manifest=True)
    with scripted_peer(zero=True) as (port, roles, _received):
        result = installed_child(tmp_path, checkout, port)
    document = json.loads(result.stdout)
    assert result.returncode == 3, result.stdout + result.stderr
    assert roles == ["discovery"]
    assert not document["coverage_manifest"]["coverage_complete"]


def test_actual_refuted_candidate_completes_nonblocking_zero_exit(tmp_path: Path) -> None:
    checkout = git_repository(tmp_path)
    with scripted_peer(verdict="REJECTED_WITH_EVIDENCE") as (port, roles, _received):
        result = installed_child(tmp_path, checkout, port)
    document = json.loads(result.stdout)
    assert result.returncode == 0, result.stdout + result.stderr
    assert document["outcome"] == "PASS" and not document["findings"]
    assert set(roles) == {"discovery", "auditor", "skeptic"}


def test_known_fail_survives_later_auditor_degradation(tmp_path: Path) -> None:
    checkout = git_repository(tmp_path)
    with scripted_peer(late_auditor_failure=True) as (port, roles, _received):
        result = installed_child(tmp_path, checkout, port)
    document = json.loads(result.stdout)
    assert result.returncode == 2, result.stdout + result.stderr
    assert document["outcome"] == "FAIL" and document["findings"]
    assert not document["coverage_manifest"]["coverage_complete"]
    assert roles.count("auditor") == 2


@pytest.mark.parametrize(
    "kind", ["file", "subdirectory", "data-class", "endpoint", "unknown-selector", "forged-anchor"]
)
def test_installed_admission_selection_negatives_send_zero_provider_bytes(
    tmp_path: Path, kind: str
) -> None:
    checkout = git_repository(tmp_path)
    target = checkout
    extra: tuple[str, ...] = ()
    mutation = ""
    if kind == "file":
        target = checkout / "a.py"
    elif kind == "subdirectory":
        target = checkout / "src"
        target.mkdir()
    elif kind in {"data-class", "endpoint", "unknown-selector"}:
        config = tmp_path / "selection.json"
        config.write_text(
            json.dumps(
                {"data_class": "DC1_PUBLIC"}
                if kind == "data-class"
                else {"endpoint": "http://invalid"}
                if kind == "endpoint"
                else {"provider_profile": "unknown@1.0.0"}
            ),
            encoding="utf-8",
        )
        extra = ("--config", str(config))
    else:
        mutation = "from dataclasses import replace; anchor = replace(anchor, approval_record_sha256='0' * 64)"
    with scripted_peer() as (port, roles, _received):
        result = installed_child(tmp_path, target, port, extra=extra, mutation=mutation)
    assert result.returncode == (3 if kind == "forged-anchor" else 5), result.stdout + result.stderr
    assert roles == []


def test_secret_path_never_crosses_actual_installed_provider_boundary(tmp_path: Path) -> None:
    canary = b"development-" + b"credential-example"
    checkout = git_repository(tmp_path, source=b'password = "' + canary + b'"\nexecute(value)\n')
    with scripted_peer() as (port, roles, received):
        result = installed_child(tmp_path, checkout, port)
    assert result.returncode == 3, result.stdout + result.stderr
    assert roles == []
    assert canary.decode() not in json.dumps(received) + result.stdout + result.stderr


def test_existing_output_is_preserved_after_real_scan(tmp_path: Path) -> None:
    checkout = git_repository(tmp_path)
    output = checkout / "a.py"
    before = output.read_bytes()
    with scripted_peer() as (port, _roles, _received):
        result = installed_child(tmp_path, checkout, port, output=output)
    assert result.returncode == 4, result.stdout + result.stderr
    assert output.read_bytes() == before


def test_installed_scan_missing_host_admission_is_closed_product_error(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    host = tmp_path / "host"
    host.mkdir()
    environment = dict(os.environ)
    environment["LOCALAPPDATA"] = str(host)
    environment["XDG_CONFIG_HOME"] = str(host)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "securecode_ai.cli",
            "scan",
            str(checkout),
            "--format",
            "json",
            "--json",
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    document = json.loads(result.stdout)
    parsed = CliErrorResult.model_validate_json(result.stdout)
    assert result.returncode == parsed.exit_code == 3
    assert parsed.error.error_code is CliErrorCode.ANALYSIS_INDETERMINATE
    assert "product_outcome" not in document
