"""P5.7 changed-line, confirmed-new finding annotation contracts."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
from typing import Any

from securecode_ai.adapters.github_annotations import (
    MAX_GITHUB_ANNOTATIONS,
    GithubAnnotationCandidate,
    GithubAnnotationPublisher,
    GithubAnnotationRequest,
    GithubAnnotationSuppression,
    GithubChangedLine,
)
from securecode_ai.adapters.github_app import GithubAppAdapter, GithubWebhookDelivery
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    FindingVerdict,
    SourceLocation,
    SourcePosition,
)
from securecode_ai.core.scm_run_state import SCMRunState

ROOT = Path(__file__).resolve().parents[2]
SECRET = b"annotation-webhook-secret"
HEAD = "a" * 40
NEW_HEAD = "b" * 40
HASH = "a" * 64


def _fixture() -> Any:
    path = ROOT / "tests" / "unit" / "test_reports.py"
    spec = importlib.util.spec_from_file_location("p57_reports_fixture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("report fixture unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _safe_finding() -> Any:
    finding = _fixture()._finding()
    location = SourceLocation(
        schema_version=CONTRACT_SCHEMA_VERSION,
        path="src/app.py",
        start=SourcePosition(schema_version=CONTRACT_SCHEMA_VERSION, line=3, column=2),
        end=SourcePosition(schema_version=CONTRACT_SCHEMA_VERSION, line=3, column=12),
        content_sha256=HASH,
    )
    return finding.model_copy(update={"locations": (location,)})


def _adapter(identity: Any) -> tuple[GithubAppAdapter, dict[str, str]]:
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
            "repository": {"id": identity.repository_revision.repository_id},
            "pull_request": {"head": {"sha": HEAD}},
        },
        separators=(",", ":"),
    ).encode()
    receipt = adapter.receive(
        GithubWebhookDelivery(
            delivery_id="delivery-1",
            event="pull_request",
            signature_sha256="sha256=" + hmac.new(SECRET, raw, hashlib.sha256).hexdigest(),
            raw_body=raw,
            execution_identity=identity,
        )
    )
    source["run"] = receipt.admission.run_id
    return adapter, source


def _request(
    identity: Any, finding: Any, *, new: bool = True, lines: tuple[GithubChangedLine, ...] = ()
) -> GithubAnnotationRequest:
    adapter, source = _adapter(identity)
    _ADAPTERS[source["run"]] = adapter
    return GithubAnnotationRequest(
        scm_run_id=source["run"],
        execution_identity=identity,
        candidates=(GithubAnnotationCandidate(finding, new),),
        changed_lines=lines or (GithubChangedLine("src/app.py", 3, HASH),),
    )


_ADAPTERS: dict[str, GithubAppAdapter] = {}


def test_confirmed_precise_new_changed_finding_projects_one_annotation() -> None:
    identity = _fixture()._run().execution_identity
    request = _request(identity, _safe_finding())

    receipt = GithubAnnotationPublisher(_ADAPTERS[request.scm_run_id]).project(request)

    assert len(receipt.annotations) == 1
    annotation = receipt.annotations[0]
    assert annotation.path == "src/app.py"
    assert annotation.start_line == 3
    assert not annotation.merge_authority
    assert "source" not in annotation.message.lower()


def test_legacy_unconfirmed_unchanged_and_ambiguous_findings_are_suppressed() -> None:
    identity = _fixture()._run().execution_identity
    finding = _safe_finding()
    candidates = (
        GithubAnnotationCandidate(finding.model_copy(update={"finding_id": "legacy"}), False),
        GithubAnnotationCandidate(
            finding.model_copy(
                update={"finding_id": "unconfirmed", "finding_verdict": FindingVerdict.CONFLICTING}
            ),
            True,
        ),
        GithubAnnotationCandidate(finding.model_copy(update={"finding_id": "unchanged"}), True),
        GithubAnnotationCandidate(
            finding.model_copy(
                update={"finding_id": "ambiguous", "locations": finding.locations * 2}
            ),
            True,
        ),
    )
    adapter, source = _adapter(identity)
    request = GithubAnnotationRequest(source["run"], identity, candidates, ())

    receipt = GithubAnnotationPublisher(adapter).project(request)

    assert receipt.annotations == ()
    assert {item.reason for item in receipt.suppressions} == {
        GithubAnnotationSuppression.LEGACY,
        GithubAnnotationSuppression.UNCONFIRMED,
        GithubAnnotationSuppression.UNCHANGED_LINE,
        GithubAnnotationSuppression.AMBIGUOUS_LOCATION,
    }


def test_over_limit_and_stale_runs_never_emit_extra_annotations() -> None:
    identity = _fixture()._run().execution_identity
    finding = _safe_finding()
    candidates = tuple(
        GithubAnnotationCandidate(
            finding.model_copy(update={"finding_id": f"finding-{index}"}), True
        )
        for index in range(MAX_GITHUB_ANNOTATIONS + 1)
    )
    adapter, source = _adapter(identity)
    request = GithubAnnotationRequest(
        source["run"], identity, candidates, (GithubChangedLine("src/app.py", 3, HASH),)
    )

    receipt = GithubAnnotationPublisher(adapter).project(request)
    source["head"] = NEW_HEAD
    stale = GithubAnnotationPublisher(adapter).project(request)

    assert len(receipt.annotations) == MAX_GITHUB_ANNOTATIONS
    assert receipt.suppressions[-1].reason is GithubAnnotationSuppression.VOLUME_LIMIT
    assert stale.annotations == ()
    assert all(item.reason is GithubAnnotationSuppression.STALE_RUN for item in stale.suppressions)
