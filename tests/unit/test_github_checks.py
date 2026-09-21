"""P5.8 exact-head, advisory Check Run outcome projections."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
from securecode_ai.adapters.github_app import GithubAppAdapter, GithubWebhookDelivery
from securecode_ai.adapters.github_checks import (
    GithubCheckConclusion,
    GithubCheckDisposition,
    GithubCheckError,
    GithubCheckPublisher,
    GithubCheckReason,
    GithubCheckRequest,
)
from securecode_ai.contracts import AuditRunOutcome
from securecode_ai.core.scm_run_state import SCMRunState

ROOT = Path(__file__).resolve().parents[2]
SECRET = b"check-webhook-secret"
HEAD = "a" * 40
NEW_HEAD = "b" * 40


def _fixture() -> Any:
    path = ROOT / "tests" / "unit" / "test_ci_worker.py"
    spec = importlib.util.spec_from_file_location("p58_worker_fixture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("P5.1 fixture unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _admit(run: Any) -> tuple[GithubAppAdapter, str, dict[str, str]]:
    source = {"head": HEAD}
    adapter = GithubAppAdapter(
        webhook_secret=SECRET,
        run_state=SCMRunState(),
        head_resolver=lambda _installation, _repository: source["head"],
    )
    raw = json.dumps(
        {
            "action": "synchronize",
            "installation": {"id": "installation-1"},
            "repository": {"id": run.execution_identity.repository_revision.repository_id},
            "pull_request": {"head": {"sha": HEAD}},
        },
        separators=(",", ":"),
    ).encode()
    admission = adapter.receive(
        GithubWebhookDelivery(
            delivery_id="delivery-1",
            event="pull_request",
            signature_sha256="sha256=" + hmac.new(SECRET, raw, hashlib.sha256).hexdigest(),
            raw_body=raw,
            execution_identity=run.execution_identity,
        )
    )
    return adapter, admission.admission.run_id, source


@pytest.mark.parametrize(
    ("outcome", "reason", "conclusion"),
    (
        (AuditRunOutcome.PASS, GithubCheckReason.NONE, GithubCheckConclusion.SUCCESS),
        (AuditRunOutcome.FAIL, GithubCheckReason.NONE, GithubCheckConclusion.FAILURE),
        (
            AuditRunOutcome.INDETERMINATE,
            GithubCheckReason.MANDATORY_COVERAGE_INCOMPLETE,
            GithubCheckConclusion.ACTION_REQUIRED,
        ),
        (
            AuditRunOutcome.ERROR,
            GithubCheckReason.PROVIDER_MODEL_FAILURE,
            GithubCheckConclusion.ACTION_REQUIRED,
        ),
        (AuditRunOutcome.CANCELLED, GithubCheckReason.CANCELLED, GithubCheckConclusion.CANCELLED),
    ),
)
def test_exact_head_outcomes_are_deterministic_and_always_advisory(
    outcome: AuditRunOutcome,
    reason: GithubCheckReason,
    conclusion: GithubCheckConclusion,
) -> None:
    fixture = _fixture()
    run = fixture._admitted_run(
        outcome=outcome,
        missing_coverage=outcome is AuditRunOutcome.INDETERMINATE,
    )
    adapter, run_id, _ = _admit(run)

    receipt = GithubCheckPublisher(adapter).project(GithubCheckRequest(run_id, run, reason))

    assert receipt.disposition is GithubCheckDisposition.CREATED
    assert receipt.projection is not None
    assert receipt.projection.conclusion is conclusion
    assert receipt.projection.advisory
    assert not receipt.projection.required_check
    assert not receipt.projection.blocking
    assert not receipt.projection.merge_authority


def test_duplicate_delivery_projection_is_idempotent_and_stale_sha_is_suppressed() -> None:
    run = _fixture()._admitted_run()
    adapter, run_id, source = _admit(run)
    publisher = GithubCheckPublisher(adapter)
    request = GithubCheckRequest(run_id, run)

    first = publisher.project(request)
    duplicate = publisher.project(request)
    source["head"] = NEW_HEAD
    stale = publisher.project(request)

    assert first.disposition is GithubCheckDisposition.CREATED
    assert duplicate.disposition is GithubCheckDisposition.IDEMPOTENT
    assert stale.disposition is GithubCheckDisposition.SUPERSEDED
    assert stale.projection is None


def test_pre_calibration_blocking_and_invalid_reason_are_rejected() -> None:
    run = _fixture()._admitted_run()
    adapter, run_id, _ = _admit(run)

    with pytest.raises(GithubCheckError):
        GithubCheckRequest(run_id, run, pre_calibration=False)
    with pytest.raises(GithubCheckError):
        GithubCheckRequest(run_id, run, GithubCheckReason.PROVIDER_MODEL_FAILURE)
    assert GithubCheckPublisher(adapter)


def test_recorded_superseded_outcome_never_projects_a_check() -> None:
    run = _fixture()._admitted_run(outcome=AuditRunOutcome.SUPERSEDED)
    adapter, run_id, _ = _admit(run)

    receipt = GithubCheckPublisher(adapter).project(GithubCheckRequest(run_id, run))

    assert receipt.disposition is GithubCheckDisposition.SUPERSEDED
    assert receipt.projection is None
