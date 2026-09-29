"""P5.9 SCM-safe artifact and optional SARIF projection contracts."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from securecode_ai.adapters.github_app import GithubAppAdapter, GithubWebhookDelivery
from securecode_ai.adapters.scm_artifacts import (
    MAX_UPLOAD_ATTEMPTS,
    SCMArtifactCapabilities,
    SCMArtifactDisposition,
    SCMArtifactError,
    SCMArtifactInput,
    SCMArtifactPublisher,
    SCMArtifactRequest,
    SCMArtifactSuppression,
)
from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION, ArtifactRef, DataClass
from securecode_ai.core.scm_run_state import SCMRunState

ROOT = Path(__file__).resolve().parents[2]
SECRET = b"artifact-webhook-secret"
HEAD = "a" * 40
NEW_HEAD = "b" * 40
HASH = "c" * 64


def _fixture() -> Any:
    path = ROOT / "tests" / "unit" / "test_ci_worker.py"
    spec = importlib.util.spec_from_file_location("p59_worker_fixture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("P5.1 fixture unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _artifact(
    *,
    content_id: str = "artifact-1",
    data_class: DataClass = DataClass.INTERNAL_METADATA,
) -> ArtifactRef:
    return ArtifactRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        tenant_id="tenant-1",
        content_id=content_id,
        content_sha256=HASH,
        size_bytes=1024,
        data_class=data_class,
    )


def _input(
    *,
    name: str = "reports/audit.json",
    media_type: str = "application/json",
    artifact: ArtifactRef | None = None,
    reference: str | None = None,
) -> SCMArtifactInput:
    item = artifact or _artifact()
    return SCMArtifactInput(
        artifact=item,
        safe_name=name,
        media_type=media_type,
        metadata_reference=reference or f"scm://artifact/{item.content_id}",
    )


def _admit(identity: Any) -> tuple[GithubAppAdapter, str, dict[str, str]]:
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
    return adapter, receipt.admission.run_id, source


def _request(
    run_id: str, identity: Any, *items: SCMArtifactInput, sarif: bool = False
) -> SCMArtifactRequest:
    return SCMArtifactRequest(
        scm_run_id=run_id,
        execution_identity=identity,
        artifacts=tuple(items),
        capabilities=SCMArtifactCapabilities(sarif_upload_enabled=sarif),
    )


def _publisher(adapter: GithubAppAdapter) -> SCMArtifactPublisher:
    return SCMArtifactPublisher(
        adapter,
        connection=sqlite3.connect(":memory:", check_same_thread=False),
    )


def test_exact_head_metadata_artifact_is_idempotent_and_never_merge_authority() -> None:
    identity = _fixture()._admitted_run().execution_identity
    adapter, run_id, _ = _admit(identity)
    publisher = _publisher(adapter)
    request = _request(run_id, identity, _input())

    first = publisher.project(request)
    duplicate = publisher.project(request)
    key = first.uploads[0].upload_idempotency_key
    publisher.record_upload_result(key, succeeded=True, attempt_id="upload-attempt-1")
    uploaded_replay = publisher.project(request)

    assert first.uploads[0].disposition is SCMArtifactDisposition.CREATED
    # A replay before any upload succeeded still reports the pending upload.
    assert duplicate.uploads[0].disposition is SCMArtifactDisposition.CREATED
    assert duplicate.uploads[0].upload_idempotency_key == key
    assert uploaded_replay.uploads[0].disposition is SCMArtifactDisposition.IDEMPOTENT
    assert first.uploads[0].audit_outcome_changed is False
    assert first.uploads[0].merge_authority is False
    assert first.merge_authority is False


def test_optional_sarif_capability_absence_is_observable_without_upload() -> None:
    identity = _fixture()._admitted_run().execution_identity
    adapter, run_id, _ = _admit(identity)
    sarif = _input(name="reports/findings.sarif", media_type="application/sarif+json")

    absent = _publisher(adapter).project(_request(run_id, identity, sarif, sarif=False))

    assert absent.uploads == ()
    assert absent.suppressions[0].reason is SCMArtifactSuppression.SARIF_CAPABILITY_ABSENT

    enabled = _publisher(adapter).project(_request(run_id, identity, sarif, sarif=True))
    assert enabled.uploads[0].disposition is SCMArtifactDisposition.CREATED


def test_upload_failures_are_bounded_retry_receipts_and_never_pass() -> None:
    identity = _fixture()._admitted_run().execution_identity
    adapter, run_id, _ = _admit(identity)
    publisher = _publisher(adapter)
    initial = publisher.project(_request(run_id, identity, _input()))
    key = initial.uploads[0].upload_idempotency_key

    retries = [
        publisher.record_upload_result(key, succeeded=False, attempt_id=f"attempt-{index}")
        for index in range(1, MAX_UPLOAD_ATTEMPTS + 1)
    ]

    assert all(receipt.audit_outcome_changed is False for receipt in retries)
    assert all(receipt.merge_authority is False for receipt in retries)
    assert retries[-1].disposition is SCMArtifactDisposition.FAILED
    assert retries[-1].retry_allowed is False
    assert (
        publisher.record_upload_result(key, succeeded=True, attempt_id="late-success").disposition
        is SCMArtifactDisposition.FAILED
    )


def test_upload_attempts_survive_database_and_publisher_recreation(tmp_path: Path) -> None:
    identity = _fixture()._admitted_run().execution_identity
    adapter, run_id, _ = _admit(identity)
    database = tmp_path / "scm-artifacts.sqlite3"
    connection = sqlite3.connect(database, check_same_thread=False)
    request = _request(run_id, identity, _input())
    first_publisher = SCMArtifactPublisher(adapter, connection=connection)
    first = first_publisher.project(request)
    key = first.uploads[0].upload_idempotency_key

    failed = first_publisher.record_upload_result(key, succeeded=False, attempt_id="transport-1")
    connection.close()
    reopened = sqlite3.connect(database, check_same_thread=False)
    resumed_publisher = SCMArtifactPublisher(adapter, connection=reopened)
    replayed = resumed_publisher.project(request)
    duplicate_failure = resumed_publisher.record_upload_result(
        key, succeeded=False, attempt_id="transport-1"
    )
    with pytest.raises(SCMArtifactError):
        resumed_publisher.record_upload_result(key, succeeded=True, attempt_id="transport-1")
    failed_again = resumed_publisher.record_upload_result(
        key, succeeded=False, attempt_id="transport-2"
    )

    assert failed.attempt_count == 1
    assert replayed.uploads[0].disposition is SCMArtifactDisposition.RETRY_READY
    assert replayed.uploads[0].retry_allowed is True
    assert replayed.uploads[0].attempt_count == 1
    assert duplicate_failure.attempt_count == 1
    assert failed_again.attempt_count == 2
    assert failed_again.disposition is SCMArtifactDisposition.RETRY_READY


def test_success_result_is_durable_and_duplicate_delivery_is_idempotent(tmp_path: Path) -> None:
    identity = _fixture()._admitted_run().execution_identity
    adapter, run_id, _ = _admit(identity)
    database = tmp_path / "scm-artifact-success.sqlite3"
    connection = sqlite3.connect(database, check_same_thread=False)
    publisher = SCMArtifactPublisher(adapter, connection=connection)
    initial = publisher.project(_request(run_id, identity, _input()))
    key = initial.uploads[0].upload_idempotency_key

    uploaded = publisher.record_upload_result(key, succeeded=True, attempt_id="upload-attempt-1")
    connection.close()
    reopened = sqlite3.connect(database, check_same_thread=False)
    resumed = SCMArtifactPublisher(adapter, connection=reopened)
    replayed = resumed.record_upload_result(key, succeeded=True, attempt_id="upload-attempt-1")

    assert uploaded.disposition is SCMArtifactDisposition.UPLOADED
    assert uploaded.attempt_count == 1
    assert replayed.disposition is SCMArtifactDisposition.IDEMPOTENT
    assert replayed.attempt_count == 1


def test_stale_run_suppresses_projection_and_transport_result() -> None:
    identity = _fixture()._admitted_run().execution_identity
    adapter, run_id, source = _admit(identity)
    publisher = _publisher(adapter)
    request = _request(run_id, identity, _input())
    initial = publisher.project(request)
    source["head"] = NEW_HEAD

    stale = publisher.project(request)
    transport = publisher.record_upload_result(
        initial.uploads[0].upload_idempotency_key,
        succeeded=True,
        attempt_id="stale-upload",
    )

    assert stale.uploads == ()
    assert stale.suppressions[0].reason is SCMArtifactSuppression.STALE_RUN
    assert transport.disposition is SCMArtifactDisposition.SUPERSEDED
    assert transport.audit_outcome_changed is False


def test_source_class_and_unallowlisted_reference_are_refused() -> None:
    with pytest.raises(SCMArtifactError):
        _input(artifact=_artifact(data_class=DataClass.CONFIDENTIAL_SOURCE))
    with pytest.raises(SCMArtifactError):
        _input(reference="http://evil.example/report.json")

    identity = _fixture()._admitted_run().execution_identity
    adapter, run_id, _ = _admit(identity)
    allowed_shape_but_unallowlisted = _input(reference="https://other.example/report.json")

    with pytest.raises(SCMArtifactError):
        _publisher(adapter).project(_request(run_id, identity, allowed_shape_but_unallowlisted))
