"""A detected secret never leaves the host: checked on the request bytes models receive.

The repository holds one file with a credential and a SQL injection next to it. The real
product composition runs Discovery and the Auditor against a scripted model endpoint,
and the Architect against a capturing completion function. Every outgoing body must
carry the file with the redaction marker and never the value.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Unpack

import pytest
from securecode_ai.adapters.product_scan import ProductCandidateFlow, ProductCompositionFailure
from securecode_ai.adapters.secret_detection import SecretFingerprintKey

from tests.integration.test_product_execution import StateProbe, _FlowKwargs

CANARY = b"development-" + b"credential-example"
SOURCE = (
    b'password = "' + CANARY + b'"\n'
    b"def lookup(request, db):\n"
    b' id = request.args.get("id")\n'
    b' return db.execute(f"SELECT * FROM users WHERE id = {id}")\n'
)


def test_no_model_request_carries_a_detected_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    from securecode_ai.adapters.product_audit import ProductAuditComposition, execute_product_audit
    from securecode_ai.adapters.product_review import run_product_candidate_review
    from securecode_ai.core.classification import FindingSeverity

    from tests.unit import test_product_audit
    from tests.unit.test_native_sources import repository

    endpoints: list[object] = []
    from tests.unit.test_openai_compatible_local import _LocalEndpoint as original_endpoint

    class RecordingEndpoint(original_endpoint):
        def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
            endpoints.append(self)
            super().install(monkeypatch)

    monkeypatch.setattr("tests.unit.test_product_audit._LocalEndpoint", RecordingEndpoint)
    from securecode_ai.adapters.product_scan import run_product_candidate_flow as original

    captured: list[_FlowKwargs] = []

    class Prepared(Exception):
        pass

    def run(**kwargs: Unpack[_FlowKwargs]) -> ProductCandidateFlow | ProductCompositionFailure:
        return original(**kwargs)

    def capture(**kwargs: Unpack[_FlowKwargs]) -> ProductCandidateFlow | ProductCompositionFailure:
        captured.append(kwargs)
        raise Prepared

    monkeypatch.setattr("tests.unit.test_product_audit.run_product_candidate_flow", run)
    _flow, _review, host, _endpoint, _ = test_product_audit._actual_flow(
        monkeypatch, count=0, source=SOURCE
    )
    monkeypatch.setattr("tests.unit.test_product_audit.run_product_candidate_flow", capture)
    with pytest.raises(Prepared):
        test_product_audit._actual_flow(monkeypatch, count=0, source=SOURCE)
    kwargs = captured[-1]
    endpoint = endpoints[-1]
    reader, _, _ = repository("a.py", SOURCE)

    result = execute_product_audit(
        reader=reader,
        host=replace(host, state_probe=StateProbe()),
        content_key=b"p" * 32,
        fingerprint_key=SecretFingerprintKey("fixture", b"k" * 32),
        dependency_scanner=None,
        model_plan=kwargs["model_plan"],
        model_backend=kwargs["model_backend"],
        auditor_factory=lambda graph, tools: kwargs["auditor_factory"](graph),
        review_factory=lambda flow, tools: run_product_candidate_review(
            flow,
            auditor_identity_for=lambda candidate, receipt: "auditor",
            severity_for=lambda candidate: FindingSeverity.HIGH,
            skeptic=object(),
        ),
        finalize_host=lambda flow, review, bound: bound,
        investigation_budget=kwargs["investigation_budget"],
        tool_budget=kwargs["model_plan"].tool_budget,
    )

    # The fixture's Auditor and Skeptic are stubs bound to the raw catalogue, so the
    # requests checked here are Discovery's; the Auditor's masked reads are covered by
    # test_verified_secret_file_is_served_masked_to_discovery_auditor_and_skeptic.
    bodies = [body for _, _, body in endpoint.requests]  # type: ignore[attr-defined]
    assert bodies, "Discovery did not call the model"
    assert not any(CANARY in body for body in bodies)
    assert all(b"redacted:" in body for body in bodies), "the secret file was not sent masked"
    if type(result) is ProductAuditComposition:
        for report in (result.json_report, result.html_report):
            assert CANARY not in report


def test_architect_prompt_and_fix_never_carry_a_detected_secret() -> None:
    from securecode_ai.adapters.trial_architect import FixFinding, propose_fixes
    from securecode_ai.cli.analyze import _secret_safe_reader

    from tests.integration.test_product_execution import execute

    execution = execute(source=SOURCE)
    analysis = SimpleNamespace(
        result=SimpleNamespace(
            composition=SimpleNamespace(
                host_inputs=SimpleNamespace(deterministic_execution=execution)
            )
        )
    )
    reader = _secret_safe_reader(lambda path: SOURCE.decode(), analysis)  # type: ignore[arg-type]
    prompts: list[str] = []

    def complete(system: str, user: str) -> str:
        prompts.append(system + user)
        return (
            '{"explanation": "Parameterize the query.", "edits": [{"start_line": 4, '
            '"end_line": 4, "replacement": " return db.execute(\\"SELECT * FROM users '
            'WHERE id = ?\\", (id,))"}]}'
        )

    (fix,) = propose_fixes(
        [FixFinding("finding-1", "CWE-89", "a.py", 4, 4, "deterministic")],
        complete,
        read_source=reader,
        apply_check=lambda _path, _source, diff: diff.startswith("--- a/"),
    )

    assert prompts and all(CANARY.decode() not in prompt for prompt in prompts)
    assert any("redacted:" in prompt for prompt in prompts)
    assert CANARY.decode() not in fix.diff
