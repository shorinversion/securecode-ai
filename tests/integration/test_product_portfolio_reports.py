"""Actual guarded report delivery for the existing four-CWE product portfolio."""

from __future__ import annotations

import json
from dataclasses import asdict

import pytest
from securecode_ai.adapters.product_audit import ProductAuditComposition, compose_product_audit
from securecode_ai.contracts import CandidateOrigin, ModelCallStatus

from tests.unit.test_product_audit import _actual_flow

_VULNERABLE_CASES = (
    (
        "CWE-78",
        "command.py",
        b"import subprocess\ndef check(request):\n subprocess.run(request.args.get('cmd'), shell=True)\n",
        "A03:2021",
    ),
    (
        "CWE-22",
        "path.py",
        b"import os\ndef check(request):\n open(os.path.join('/srv', request.args.get('file')))\n",
        "A01:2021",
    ),
    (
        "CWE-918",
        "ssrf.py",
        b"import requests\ndef check(request):\n requests.get(request.args.get('url'))\n",
        "A10:2021",
    ),
    (
        "CWE-862",
        "authz.py",
        b"def check(request, repo):\n repo.get(request.args.get('id'))\n",
        "A01:2021",
    ),
    (
        "CWE-78",
        "command.js",
        b"function check(req) { exec(req.query.cmd); }\n",
        "A03:2021",
    ),
    (
        "CWE-22",
        "path.js",
        b"function check(req) { fs.readFile(path.join(root, req.query.file)); }\n",
        "A01:2021",
    ),
    (
        "CWE-918",
        "ssrf.js",
        b"function check(req) { fetch(req.query.url); }\n",
        "A10:2021",
    ),
    (
        "CWE-862",
        "authz.js",
        b"function check(req, repo) { repo.get(req.params.id); }\n",
        "A01:2021",
    ),
    (
        "CWE-78",
        "command.ts",
        b"function check(req: Request): void { exec(req.query.cmd); }\n",
        "A03:2021",
    ),
    (
        "CWE-22",
        "path.ts",
        b"function check(req: Request): void { fs.readFile(path.join(root, req.query.file)); }\n",
        "A01:2021",
    ),
    (
        "CWE-918",
        "ssrf.ts",
        b"function check(req: Request): void { fetch(req.query.url); }\n",
        "A10:2021",
    ),
    (
        "CWE-862",
        "authz.ts",
        b"function check(req: Request, repo: Repo): void { repo.get(req.params.id); }\n",
        "A01:2021",
    ),
    (
        "CWE-78",
        "command.go",
        b'package api\nimport "os/exec"\nfunc check(r *Request) { exec.Command("sh", "-c", r.URL.Query().Get("cmd")) }\n',
        "A03:2021",
    ),
    (
        "CWE-22",
        "path.go",
        b'package api\nimport ("os"; "path/filepath")\nfunc check(r *Request) { os.ReadFile(filepath.Join(root, r.URL.Query().Get("file"))) }\n',
        "A01:2021",
    ),
    (
        "CWE-918",
        "ssrf.go",
        b'package api\nimport "net/http"\nfunc check(r *Request) { http.Get(r.URL.Query().Get("url")) }\n',
        "A10:2021",
    ),
    (
        "CWE-862",
        "authz.go",
        b'package api\nfunc check(r *Request, repo Repo) { repo.Find(r.URL.Query().Get("id")) }\n',
        "A01:2021",
    ),
)


_SAFE_CASES = (
    (
        "CWE-78",
        "command.py",
        b"import subprocess\ndef check(request):\n subprocess.run('date', shell=False)\n",
    ),
    (
        "CWE-22",
        "path.py",
        b"import os\ndef check(request):\n open(os.path.join('/srv', 'readme.txt'))\n",
    ),
    (
        "CWE-918",
        "ssrf.py",
        b"import requests\ndef check(request):\n requests.get('https://api.example.test')\n",
    ),
    (
        "CWE-862",
        "authz.py",
        b"def check(request, repo):\n authorize(current_user, request.args.get('id'))\n repo.get(request.args.get('id'))\n",
    ),
    ("CWE-78", "command.js", b"function check(req) { exec('date'); }\n"),
    ("CWE-22", "path.js", b"function check(req) { fs.readFile(path.join(root, 'readme.txt')); }\n"),
    ("CWE-918", "ssrf.js", b"function check(req) { fetch('https://api.example.test'); }\n"),
    (
        "CWE-862",
        "authz.js",
        b"function check(req, repo) { authorize(currentUser, req.params.id); repo.get(req.params.id); }\n",
    ),
    ("CWE-78", "command.ts", b"function check(req: Request): void { exec('date'); }\n"),
    (
        "CWE-22",
        "path.ts",
        b"function check(req: Request): void { fs.readFile(path.join(root, 'readme.txt')); }\n",
    ),
    (
        "CWE-918",
        "ssrf.ts",
        b"function check(req: Request): void { fetch('https://api.example.test'); }\n",
    ),
    (
        "CWE-862",
        "authz.ts",
        b"function check(req: Request, repo: Repo): void { authorize(currentUser, req.params.id); repo.get(req.params.id); }\n",
    ),
    ("CWE-78", "command.go", b'package api\nfunc check(r *Request) { exec.Command("date") }\n'),
    (
        "CWE-22",
        "path.go",
        b'package api\nfunc check(r *Request) { os.ReadFile(filepath.Join(root, "readme.txt")) }\n',
    ),
    (
        "CWE-918",
        "ssrf.go",
        b'package api\nfunc check(r *Request) { http.Get("https://api.example.test") }\n',
    ),
    (
        "CWE-862",
        "authz.go",
        b'package api\nfunc check(r *Request, repo Repo) { authorize(currentUser, r.URL.Query().Get("id")); repo.Find(r.URL.Query().Get("id")) }\n',
    ),
)


@pytest.mark.parametrize(("cwe_id", "path", "source", "owasp_category"), _VULNERABLE_CASES)
def test_actual_guarded_portfolio_finding_renders_for_each_language(
    monkeypatch: pytest.MonkeyPatch, cwe_id: str, path: str, source: bytes, owasp_category: str
) -> None:
    flow, review, host, endpoint, _ = _actual_flow(
        monkeypatch, hybrid=True, source=source, path=path, cwe_id=cwe_id
    )

    assert len(flow.graph.candidates) == 1
    assert flow.graph.candidates[0].candidate_origin is CandidateOrigin.HYBRID
    assert host.deterministic_scan is not None and host.deterministic_scan.is_complete
    assert review.has_known_blocking_finding
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditComposition
    finding = result.report.findings[0]
    assert finding.classification.cwe_id == cwe_id
    assert finding.classification.owasp_category == owasp_category
    assert finding.classification.severity.value == "HIGH"
    assert finding.classification.confidence.value == "UNSCORED"
    assert (
        finding.classification.provenance.mapping_id
        == "securecode-product-portfolio-classification"
    )
    assert review.outcomes[0].finding_gate is not None
    assert review.outcomes[0].finding_gate.severity is finding.classification.severity
    rendered = json.loads(result.json_report)["findings"][0]
    assert rendered["cwe_id"] == cwe_id
    assert rendered["owasp_category"] == owasp_category
    assert rendered["severity"] == finding.classification.severity.value
    assert rendered["mapping_provenance"] == asdict(finding.classification.provenance)
    for text in (
        cwe_id,
        owasp_category,
        finding.classification.severity.value,
        finding.classification.provenance.mapping_id,
        result.run.audit_outcome.value,
    ):
        assert text.encode("ascii") in result.html_report
    assert source not in result.json_report + result.html_report
    assert result.run.audit_outcome.value == "FAIL"
    assert len(endpoint.requests) == 3


@pytest.mark.parametrize(("cwe_id", "path", "source"), _SAFE_CASES)
def test_actual_guarded_portfolio_safe_controls_remain_indeterminate_not_clean(
    monkeypatch: pytest.MonkeyPatch, cwe_id: str, path: str, source: bytes
) -> None:
    flow, review, host, endpoint, _ = _actual_flow(
        monkeypatch, count=0, source=source, path=path, cwe_id=cwe_id
    )

    assert not flow.graph.candidates
    assert host.deterministic_scan is not None and host.deterministic_scan.is_complete
    assert not host.deterministic_scan.graph.candidates
    assert not review.has_known_blocking_finding
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditComposition
    assert result.report.findings == ()
    assert result.run.audit_outcome.value == "INDETERMINATE"
    assert not result.run.coverage_manifest.coverage_complete
    assert source not in result.json_report + result.html_report
    assert len(endpoint.requests) == 1


def test_actual_model_native_portfolio_candidate_uses_host_rule_and_root_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scripted guarded model-native candidate remains distinct from scanner coverage."""

    flow, review, host, endpoint, _ = _actual_flow(
        monkeypatch,
        source=(
            b"import requests\ndef check(request):\n requests.get('https://api.example.test')\n"
        ),
        path="native-ssrf.py",
        cwe_id="CWE-918",
    )

    assert host.deterministic_scan is not None and host.deterministic_scan.is_complete
    assert not host.deterministic_scan.graph.candidates
    assert flow.discovery.receipt.model_call_status is ModelCallStatus.SUCCEEDED
    assert flow.graph.candidates[0].candidate_origin is CandidateOrigin.MODEL_NATIVE
    assert review.has_known_blocking_finding
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditComposition
    assert result.report.findings[0].classification.cwe_id == "CWE-918"
    assert result.report.findings[0].classification.severity.value == "HIGH"
    assert b"https://api.example.test" not in result.json_report + result.html_report
    assert len(endpoint.requests) == 3
