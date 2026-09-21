"""P5.6 exact-head, safe GitHub summary projection contracts."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
from securecode_ai.adapters.github_app import GithubAppAdapter, GithubWebhookDelivery
from securecode_ai.adapters.github_summary import (
    GithubSummaryDisposition,
    GithubSummaryError,
    GithubSummaryErrorCode,
    GithubSummaryPublisher,
    GithubSummaryRequest,
)
from securecode_ai.contracts import AuditRunOutcome
from securecode_ai.core.scm_run_state import SCMRunState

ROOT = Path(__file__).resolve().parents[2]
SECRET = b"summary-webhook-secret"
HEAD = "a" * 40
NEW_HEAD = "b" * 40


def _worker_fixture() -> Any:
    path = ROOT / "tests" / "unit" / "test_ci_worker.py"
    specification = importlib.util.spec_from_file_location("p56_worker_fixture", path)
    if specification is None or specification.loader is None:
        raise RuntimeError("P5.1 fixture is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _adapter(*, current_head: str = HEAD) -> tuple[GithubAppAdapter, dict[str, str]]:
    source = {"head": current_head}
    adapter = GithubAppAdapter(
        webhook_secret=SECRET,
        run_state=SCMRunState(),
        head_resolver=lambda _installation, _repository: source["head"],
    )
    return adapter, source


def _admit(adapter: GithubAppAdapter, audit_run: Any, delivery_id: str = "delivery-1") -> str:
    raw_body = json.dumps(
        {
            "action": "synchronize",
            "installation": {"id": "installation-1"},
            "repository": {"id": audit_run.execution_identity.repository_revision.repository_id},
            "pull_request": {
                "head": {"sha": audit_run.execution_identity.repository_revision.head_sha}
            },
        },
        separators=(",", ":"),
    ).encode("utf-8")
    signature = "sha256=" + hmac.new(SECRET, raw_body, hashlib.sha256).hexdigest()
    receipt = adapter.receive(
        GithubWebhookDelivery(
            delivery_id=delivery_id,
            event="pull_request",
            signature_sha256=signature,
            raw_body=raw_body,
            execution_identity=audit_run.execution_identity,
        )
    )
    return receipt.admission.run_id


def test_duplicate_projection_updates_one_safe_summary_for_exact_pass() -> None:
    audit_run = _worker_fixture()._admitted_run()
    adapter, _ = _adapter()
    run_id = _admit(adapter, audit_run)
    publisher = GithubSummaryPublisher(adapter)

    first = publisher.project(GithubSummaryRequest(scm_run_id=run_id, audit_run=audit_run))
    duplicate = publisher.project(GithubSummaryRequest(scm_run_id=run_id, audit_run=audit_run))

    assert first.disposition is GithubSummaryDisposition.CREATED
    assert duplicate.disposition is GithubSummaryDisposition.IDEMPOTENT
    assert first.projection is not None
    assert duplicate.projection is not None
    assert first.projection.comment_idempotency_key == duplicate.projection.comment_idempotency_key
    assert "SecureCode AI: PASS" in first.projection.rendered_markdown
    assert "Merge authority: status/check only" in first.projection.rendered_markdown


def test_missing_coverage_renders_non_clean_recovery_without_unsafe_input() -> None:
    audit_run = _worker_fixture()._admitted_run(
        outcome=AuditRunOutcome.INDETERMINATE,
        missing_coverage=True,
    )
    adapter, _ = _adapter()
    publisher = GithubSummaryPublisher(adapter)

    receipt = publisher.project(
        GithubSummaryRequest(scm_run_id=_admit(adapter, audit_run), audit_run=audit_run)
    )

    assert receipt.projection is not None
    rendered = receipt.projection.rendered_markdown
    assert "non-passing; this is not a clean result" in rendered
    assert "intake:STAGE_FAILED" in rendered
    assert "rerun the listed required analysis" in rendered
    assert rendered.isascii()
    assert "\x1b" not in rendered


def test_ref_move_returns_superseded_without_summary_projection() -> None:
    audit_run = _worker_fixture()._admitted_run()
    adapter, source = _adapter()
    run_id = _admit(adapter, audit_run)
    source["head"] = NEW_HEAD

    receipt = GithubSummaryPublisher(adapter).project(
        GithubSummaryRequest(scm_run_id=run_id, audit_run=audit_run)
    )

    assert receipt.disposition is GithubSummaryDisposition.SUPERSEDED
    assert receipt.projection is None


def test_audit_identity_mismatch_is_rejected_before_rendering() -> None:
    audit_run = _worker_fixture()._admitted_run()
    adapter, _ = _adapter()
    publisher = GithubSummaryPublisher(adapter)
    run_id = _admit(adapter, audit_run)
    mismatched = audit_run.model_copy(update={"current_head_sha": NEW_HEAD})

    with pytest.raises(GithubSummaryError) as error:
        publisher.project(GithubSummaryRequest(scm_run_id=run_id, audit_run=mismatched))

    assert error.value.code is GithubSummaryErrorCode.IDENTITY_MISMATCH
