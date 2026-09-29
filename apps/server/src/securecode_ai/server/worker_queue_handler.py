"""Connected-worker HTTP handler backed by the durable run queue."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Final, cast

from securecode_ai.adapters.scm_head import SCMHeadUnavailable
from securecode_ai.contracts import (
    AnalysisHealth,
    ArtifactRef,
    DataClass,
    EvidenceKind,
    RunExecutionIdentity,
    TrustLabel,
)
from securecode_ai.core.baseline_fingerprints import (
    BaselineChangedScope,
    BaselineFingerprintComparison,
    BaselineFingerprintError,
)
from securecode_ai.core.evidence_graph import EvidenceGraph
from securecode_ai.core.scm_policy import ScmPolicyDocument

from .artifact_upload_verifier import LocalArtifactUploadVerifier
from .baseline_store import BaselineStoreError, DurableBaselineStore
from .osv_relay import OsvMetadataRelay
from .ports import ServiceRequest, ServiceResponse, ServiceUnavailableError
from .residency_registry import ResidencyConflict, ResidencyDecision, ResidencyGuard
from .worker_artifact_authorization import (
    ArtifactAuthorizationDenied,
    SqliteArtifactAuthorizationStore,
)
from .worker_completion_evidence import load_verified_terminal_audit_run
from .worker_findings import WorkerFindingRecord, parse_worker_findings
from .worker_findings_store import complete_worker_run
from .worker_queue import SqliteWorkerQueue, WorkerQueueClaimHandler, WorkerQueueConflict
from .worker_queue_models import WorkerQueueLease, identity_document
from .worker_resource_models import WorkerResourceSettlement
from .worker_scm_policy import record_run_advisory_policy, record_run_scm_policy

_EVENT_KINDS: Final = frozenset(
    {
        "RUN_STARTED",
        "RUN_COMPLETED",
        "RUN_CANCELLED",
        "RUN_SUPERSEDED",
        "RUN_FAILED",
    }
)
_COMMIT_OUTCOMES: Final = frozenset({"PASS", "FAIL", "INDETERMINATE"})
_COMPLETION_KEYS: Final = frozenset(
    {
        "execution_identity_hash",
        "outcome",
        "run_id",
        "schema_version",
        "worker_id",
    }
)
_MAX_EVENT_SEQUENCE: Final = 2_147_483_647


class WorkerQueueHandler:
    """Serve claims, lease changes, evidence commits, and terminal outcomes."""

    def __init__(
        self,
        *,
        queue: SqliteWorkerQueue,
        artifact_authorizations: SqliteArtifactAuthorizationStore,
        uploaded_artifacts: LocalArtifactUploadVerifier,
        baseline_store: DurableBaselineStore | None = None,
        lineage_resolver: object | None = None,
        changed_lines_resolver: object | None = None,
        policy_resolver: Callable[[object], ScmPolicyDocument] | None = None,
        osv_relay: OsvMetadataRelay | None = None,
        residency_guard: ResidencyGuard | None = None,
        residency_region: str | None = None,
    ) -> None:
        self._queue = queue
        self._claims = WorkerQueueClaimHandler(queue)
        self._artifact_authorizations = artifact_authorizations
        self._uploaded_artifacts = uploaded_artifacts
        self._baseline_store = baseline_store
        if lineage_resolver is not None and not callable(lineage_resolver):
            raise ValueError("SCM lineage resolver configuration is invalid")
        self._lineage_resolver = cast(Callable[..., tuple[str, ...]] | None, lineage_resolver)
        if changed_lines_resolver is not None and not callable(changed_lines_resolver):
            raise ValueError("SCM changed-line resolver configuration is invalid")
        self._changed_lines_resolver = cast(
            Callable[..., tuple[tuple[str, int], ...]] | None,
            changed_lines_resolver,
        )
        if policy_resolver is not None and not callable(policy_resolver):
            raise ValueError("SCM policy resolver configuration is invalid")
        self._policy_resolver = policy_resolver
        if osv_relay is not None and type(osv_relay) is not OsvMetadataRelay:
            raise ValueError("OSV relay configuration is invalid")
        if (residency_guard is None) != (residency_region is None):
            raise ValueError("worker residency configuration is incomplete")
        if residency_guard is not None and not callable(
            getattr(residency_guard, "require_region", None)
        ):
            raise ValueError("worker residency guard is invalid")
        self._osv_relay = osv_relay or OsvMetadataRelay(queue=queue)
        self._residency_guard = residency_guard
        self._residency_region = residency_region

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        residency_response = self._residency_response(request.identity.tenant_id)
        if residency_response is not None:
            return residency_response
        if request.action == "worker_sessions.create":
            try:
                return await self._claims.dispatch(request)
            except sqlite3.Error:
                raise ServiceUnavailableError() from None
        if request.action == "worker_sessions.osv.query":
            try:
                return await self._osv_relay.dispatch(request)
            except sqlite3.Error:
                raise ServiceUnavailableError() from None
            except WorkerQueueConflict:
                return _denied(
                    409,
                    "WORKER_CONFLICT",
                    "worker lease conflicts with current state",
                )
            except (TypeError, ValueError):
                return _denied(
                    409,
                    "WORKER_CONFLICT",
                    "worker lease conflicts with current state",
                )
        try:
            return self._dispatch_session(request)
        except ArtifactAuthorizationDenied:
            return _denied(
                403,
                "ARTIFACT_AUTHORIZATION_DENIED",
                "artifact upload is not authorized",
            )
        except sqlite3.Error:
            raise ServiceUnavailableError() from None
        except (BaselineStoreError, WorkerQueueConflict, KeyError, TypeError, ValueError):
            return _denied(
                409,
                "WORKER_CONFLICT",
                "worker lease conflicts with current state",
            )

    async def dispatch_accounted_completion(
        self,
        request: ServiceRequest,
        *,
        settlement: WorkerResourceSettlement,
        resource_clock: Callable[[], int],
    ) -> ServiceResponse:
        """Atomically settle resources and complete one validated worker run."""

        residency_response = self._residency_response(request.identity.tenant_id)
        if residency_response is not None:
            return residency_response
        try:
            document = _document(request)
            session_id = request.path_params.get("session_id")
            worker_id = _required_text(document, "worker_id")
            run_id = _required_text(document, "run_id")
            identity_hash = _required_text(document, "execution_identity_hash")
            if request.action != "worker_sessions.complete" or not session_id:
                raise WorkerQueueConflict()
            expected_version = _version(request.precondition)
            outcome = _required_text(document, "outcome")
            findings = _completion_findings(document, outcome)
            connection = _queue_connection(self._queue)
            verified_terminal = load_verified_terminal_audit_run(
                connection=connection,
                artifact_root=_artifact_root(self._uploaded_artifacts),
                tenant_id=request.identity.tenant_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
                outcome=outcome,
                findings=findings,
                include_graph=True,
            )
            if verified_terminal is None:
                audit_run = None
                evidence_graph = None
            elif type(verified_terminal) is tuple and len(verified_terminal) == 2:
                audit_run, evidence_graph = verified_terminal
            else:
                raise WorkerQueueConflict()
            terminal_transaction_effect = None
            baseline_store = self._baseline_store
            if audit_run is not None:
                baseline_comparison: BaselineFingerprintComparison | None = None
                changed_scope: BaselineChangedScope | None = None
                confirmed_fingerprints = tuple(
                    sorted(
                        {
                            finding.root_cause_fingerprint
                            for finding in findings
                            if finding.finding_id in audit_run.finding_ids
                            and finding.verdict == "CONFIRMED"
                            and finding.revision_sha == audit_run.current_head_sha
                        }
                    )
                )
                revision = audit_run.execution_identity.repository_revision
                if (
                    baseline_store is not None
                    and self._lineage_resolver is not None
                    and revision.base_sha is not None
                ):
                    try:
                        lineage = self._lineage_resolver(
                            run_id=run_id,
                            execution_identity_hash=identity_hash,
                            base_sha=revision.base_sha,
                            head_sha=revision.head_sha,
                        )
                        baseline_comparison = baseline_store.compare_for_audit(
                            audit_run,
                            commit_lineage=lineage,
                            verified_finding_fingerprints=confirmed_fingerprints,
                        )
                    except (BaselineStoreError, SCMHeadUnavailable, TypeError, ValueError):
                        baseline_comparison = None
                if (
                    baseline_comparison is not None
                    and self._changed_lines_resolver is not None
                    and revision.base_sha is not None
                ):
                    try:
                        changed_lines = self._changed_lines_resolver(
                            run_id=run_id,
                            execution_identity_hash=identity_hash,
                            base_sha=revision.base_sha,
                            head_sha=revision.head_sha,
                        )
                        changed_scope = BaselineChangedScope(
                            tenant_id=revision.tenant_id,
                            base_sha=revision.base_sha,
                            head_sha=revision.head_sha,
                            changed_lines=changed_lines,
                            finding_locations=_finding_locations(findings),
                            data_flow_locations=_data_flow_locations(
                                evidence_graph,
                                confirmed_fingerprints,
                            ),
                        )
                        changed_scope.validate_for(baseline_comparison)
                    except (
                        BaselineFingerprintError,
                        SCMHeadUnavailable,
                        TypeError,
                        ValueError,
                    ):
                        changed_scope = None

                def record_completion_policy(cursor: sqlite3.Cursor) -> None:
                    if (
                        baseline_store is not None
                        and audit_run.analysis_health is AnalysisHealth.HEALTHY
                        and audit_run.coverage_manifest.coverage_complete
                    ):
                        baseline_store.record_in_transaction(
                            cursor,
                            audit_run,
                            verified_finding_fingerprints=confirmed_fingerprints,
                        )
                    if self._policy_resolver is None:
                        record_run_advisory_policy(
                            cursor,
                            audit_run=audit_run,
                            baseline_comparison=baseline_comparison,
                            changed_scope=changed_scope,
                            verified_findings=findings,
                        )
                    else:
                        record_run_scm_policy(
                            cursor,
                            audit_run=audit_run,
                            policy=self._policy_resolver(audit_run),
                            baseline_comparison=baseline_comparison,
                            changed_scope=changed_scope,
                            verified_findings=findings,
                        )

                terminal_transaction_effect = record_completion_policy
            lease = complete_worker_run(
                connection,
                lease_seconds=_queue_lease_seconds(self._queue),
                now=_queue_clock(self._queue),
                tenant_id=request.identity.tenant_id,
                session_id=session_id,
                worker_id=worker_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
                expected_version=expected_version,
                outcome=outcome,
                findings=findings,
                resource_settlement=settlement,
                resource_clock=resource_clock,
                terminal_transaction_effect=terminal_transaction_effect,
            )
            return _lease_response(lease)
        except sqlite3.Error:
            raise ServiceUnavailableError() from None
        except (BaselineStoreError, WorkerQueueConflict, KeyError, TypeError, ValueError):
            return _denied(
                409,
                "WORKER_CONFLICT",
                "worker lease conflicts with current state",
            )

    def _residency_response(self, tenant_id: str) -> ServiceResponse | None:
        guard = self._residency_guard
        if guard is None:
            return None
        region = self._residency_region
        if type(region) is not str or not region:
            raise ServiceUnavailableError()
        try:
            decision = guard.require_region(tenant_id=tenant_id, region=region)
        except ResidencyConflict:
            return _denied(
                403,
                "RESIDENCY_DENIED",
                "worker residency policy denied the request",
            )
        except Exception:
            raise ServiceUnavailableError() from None
        if (
            type(decision) is not ResidencyDecision
            or decision.tenant_id != tenant_id
            or decision.source_region != region
            or decision.destination_region != region
            or not decision.same_region
        ):
            raise ServiceUnavailableError()
        return None

    def _dispatch_session(self, request: ServiceRequest) -> ServiceResponse:
        document = _document(request)
        session_id = request.path_params.get("session_id")
        base_keys = {"execution_identity_hash", "run_id", "schema_version", "worker_id"}
        expected_keys = {
            "worker_sessions.heartbeat": base_keys,
            "worker_sessions.events.append": base_keys | {"events"},
            "worker_sessions.artifacts.commit": base_keys
            | {"artifact_ref", "authorization_id", "purpose"},
        }.get(request.action)
        if expected_keys is None or document.get("schema_version") != "0.2.0":
            raise WorkerQueueConflict()
        if request.action == "worker_sessions.artifacts.commit":
            if set(document) not in {
                expected_keys,
                expected_keys | {"binding"},
            }:
                raise WorkerQueueConflict()
        elif set(document) != expected_keys:
            raise WorkerQueueConflict()
        worker_id = _required_text(document, "worker_id")
        run_id = _required_text(document, "run_id")
        identity_hash = _required_text(document, "execution_identity_hash")
        if not session_id:
            raise WorkerQueueConflict()
        tenant_id = request.identity.tenant_id
        expected_version = _version(request.precondition)
        if request.action == "worker_sessions.heartbeat":
            lease = self._queue.heartbeat(
                tenant_id=tenant_id,
                session_id=session_id,
                worker_id=worker_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
                expected_version=expected_version,
            )
        elif request.action == "worker_sessions.events.append":
            events = _events(document.get("events"), run_id, identity_hash)
            lease = self._queue.advance(
                tenant_id=tenant_id,
                session_id=session_id,
                worker_id=worker_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
                expected_version=expected_version,
                events=events,
            )
        elif request.action == "worker_sessions.artifacts.commit":
            purpose = _required_text(document, "purpose")
            if purpose != "repair-patch" and "binding" in document:
                raise WorkerQueueConflict()
            artifact = _artifact(document)
            run_identity = _run_execution_identity(
                _queue_connection(self._queue),
                tenant_id=request.identity.tenant_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
            )
            repository_id = run_identity.repository_revision.repository_id
            binding = None
            if purpose == "repair-patch":
                binding = _repair_binding(
                    document.get("binding"),
                    tenant_id=request.identity.tenant_id,
                    repository_id=repository_id,
                    run_id=run_id,
                    execution_identity_hash=identity_hash,
                    head_sha=run_identity.repository_revision.head_sha,
                    artifact=artifact,
                )
            authorization = self._artifact_authorizations.require(
                tenant_id=request.identity.tenant_id,
                authorization_id=_required_text(document, "authorization_id"),
                repository_id=repository_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
                content_sha256=artifact.content_sha256,
                size_bytes=artifact.size_bytes,
                purpose=purpose,
                request_sha256=_artifact_authorization_request_sha256(
                    artifact=artifact,
                    execution_identity_hash=identity_hash,
                    method="PUT",
                    purpose=purpose,
                    repository_id=repository_id,
                    run_id=run_id,
                    schema_version="0.2.0",
                    session_id=session_id,
                    worker_id=worker_id,
                ),
            )
            if (
                authorization.worker_id != worker_id
                or authorization.content_id != artifact.content_id
                or authorization.data_class != artifact.data_class.value
            ):
                raise ArtifactAuthorizationDenied()
            self._uploaded_artifacts.require(
                tenant_id=request.identity.tenant_id,
                authorization_id=authorization.authorization_id,
                worker_id=worker_id,
                repository_id=repository_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
                content_sha256=artifact.content_sha256,
                size_bytes=artifact.size_bytes,
                purpose=authorization.purpose,
                authorization=authorization,
            )
            committed_artifact: dict[str, object] = {
                "authorization_id": authorization.authorization_id,
                "content_id": artifact.content_id,
                "content_sha256": artifact.content_sha256,
                "data_class": artifact.data_class.value,
                "purpose": authorization.purpose,
                "size_bytes": artifact.size_bytes,
            }
            if binding is not None:
                committed_artifact["binding"] = binding
            if artifact.expires_at is not None:
                committed_artifact["expires_at"] = artifact.expires_at.isoformat()
            lease = self._queue.advance(
                tenant_id=tenant_id,
                session_id=session_id,
                worker_id=worker_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
                expected_version=expected_version,
                artifact=committed_artifact,
            )
        elif request.action == "worker_sessions.complete":
            raise ServiceUnavailableError()
        else:
            raise ServiceUnavailableError()
        return _lease_response(lease)


def _finding_locations(
    findings: tuple[WorkerFindingRecord, ...],
) -> tuple[tuple[str, tuple[tuple[str, int, int], ...]], ...]:
    grouped: dict[str, set[tuple[str, int, int]]] = {}
    for finding in findings:
        if finding.verdict != "CONFIRMED":
            continue
        locations = grouped.setdefault(finding.root_cause_fingerprint, set())
        locations.update((item.path, item.start_line, item.end_line) for item in finding.locations)
    return tuple(
        (fingerprint, tuple(sorted(locations)))
        for fingerprint, locations in sorted(grouped.items())
    )


def _data_flow_locations(
    graph: EvidenceGraph | None,
    fingerprints: tuple[str, ...],
) -> tuple[tuple[str, tuple[tuple[str, int, int], ...]], ...]:
    if graph is None:
        return ()
    selected = set(fingerprints)
    evidence_by_id = {item.evidence_id: item for item in graph.evidence}
    grouped: dict[str, set[tuple[str, int, int]]] = {}
    for candidate in graph.candidates:
        fingerprint = candidate.root_cause_fingerprint
        if fingerprint not in selected:
            continue
        for evidence_id in candidate.evidence_ids:
            evidence = evidence_by_id.get(evidence_id)
            if (
                evidence is None
                or evidence.evidence_kind is not EvidenceKind.DATA_FLOW
                or evidence.trust_label is not TrustLabel.TRUSTED_DETERMINISTIC
                or evidence.location is None
            ):
                continue
            location = evidence.location
            grouped.setdefault(fingerprint, set()).add(
                (location.path, location.start.line, location.end.line)
            )
    return tuple(
        (fingerprint, tuple(sorted(locations)))
        for fingerprint, locations in sorted(grouped.items())
    )


def _events(
    value: object,
    run_id: str,
    execution_identity_hash: str,
) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise WorkerQueueConflict()
    admitted: list[Mapping[str, object]] = []
    previous_sequence = 0
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {
            "event_hash",
            "event_id",
            "kind",
            "sequence",
        }:
            raise WorkerQueueConflict()
        sequence = item["sequence"]
        event_id = item["event_id"]
        event_hash = item["event_hash"]
        kind = item["kind"]
        if (
            type(sequence) is not int
            or not previous_sequence < sequence <= _MAX_EVENT_SEQUENCE
            or type(kind) is not str
            or kind not in _EVENT_KINDS
            or type(event_id) is not str
            or type(event_hash) is not str
        ):
            raise WorkerQueueConflict()
        digest = _event_hash(run_id, execution_identity_hash, sequence, kind)
        if event_hash != digest or event_id != f"worker-{sequence}-{digest[:32]}":
            raise WorkerQueueConflict()
        admitted.append(dict(item))
        previous_sequence = sequence
    return tuple(admitted)


def _event_hash(run_id: str, identity_hash: str, sequence: int, kind: str) -> str:
    value = {
        "execution_identity_hash": identity_hash,
        "kind": kind,
        "run_id": run_id,
        "sequence": sequence,
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _artifact(document: Mapping[str, object]) -> ArtifactRef:
    value = document.get("artifact_ref")
    if not isinstance(value, Mapping):
        raise ArtifactAuthorizationDenied()
    try:
        return ArtifactRef.model_validate_json(
            json.dumps(dict(value), separators=(",", ":"), sort_keys=True)
        )
    except (RecursionError, TypeError, ValueError):
        raise ArtifactAuthorizationDenied() from None


def _artifact_authorization_request_sha256(
    *,
    artifact: ArtifactRef,
    execution_identity_hash: str,
    method: str,
    purpose: str,
    repository_id: str,
    run_id: str,
    schema_version: str,
    session_id: str,
    worker_id: str,
) -> str:
    request = {
        "artifact_ref": artifact.model_dump(mode="json"),
        "execution_identity_hash": execution_identity_hash,
        "method": method,
        "purpose": purpose,
        "repository_id": repository_id,
        "run_id": run_id,
        "schema_version": schema_version,
        "session_id": session_id,
        "worker_id": worker_id,
    }
    encoded = json.dumps(
        request,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _completion_findings(
    document: Mapping[str, object], outcome: str
) -> tuple[WorkerFindingRecord, ...]:
    commits = outcome in _COMMIT_OUTCOMES
    if (
        (commits and frozenset(document) != _COMPLETION_KEYS | {"findings", "resource_usage"})
        or (
            not commits
            and frozenset(document) not in {_COMPLETION_KEYS, _COMPLETION_KEYS | {"resource_usage"}}
        )
        or document.get("schema_version") != "0.2.0"
    ):
        raise WorkerQueueConflict()
    return parse_worker_findings(
        document.get("findings"),
        required=commits,
        supplied="findings" in document,
    )


def _document(request: ServiceRequest) -> Mapping[str, object]:
    if not isinstance(request.document, Mapping):
        raise WorkerQueueConflict()
    return request.document


def _required_text(document: Mapping[str, object], name: str) -> str:
    value = document.get(name)
    if not isinstance(value, str) or not value:
        raise WorkerQueueConflict()
    return value


def _repair_binding(
    value: object,
    *,
    tenant_id: str,
    repository_id: str,
    run_id: str,
    execution_identity_hash: str,
    head_sha: str,
    artifact: ArtifactRef,
) -> dict[str, object]:
    required = {
        "execution_identity_hash",
        "finding_id",
        "head_sha",
        "manifest_sha256",
        "patch_size_bytes",
        "patch_sha256",
        "patch_status_sha256",
        "repository_id",
        "run_id",
        "tenant_id",
        "validation_result_sha256",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != required
        or artifact.data_class is not DataClass.CONFIDENTIAL_SOURCE
        or artifact.content_sha256 == ""
    ):
        raise WorkerQueueConflict()
    for name, expected in (
        ("tenant_id", tenant_id),
        ("repository_id", repository_id),
        ("run_id", run_id),
        ("execution_identity_hash", execution_identity_hash),
    ):
        if value.get(name) != expected:
            raise WorkerQueueConflict()
    if value.get("head_sha") != head_sha:
        raise WorkerQueueConflict()
    for name in ("tenant_id", "repository_id", "run_id", "finding_id"):
        item = value.get(name)
        if type(item) is not str or not item:
            raise WorkerQueueConflict()
    stored_head_sha = value.get("head_sha")
    if type(stored_head_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", stored_head_sha) is None:
        raise WorkerQueueConflict()
    for name in (
        "execution_identity_hash",
        "manifest_sha256",
        "patch_sha256",
        "patch_status_sha256",
        "validation_result_sha256",
    ):
        digest = value.get(name)
        if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise WorkerQueueConflict()
    size = value.get("patch_size_bytes")
    if type(size) is not int or not 1 <= size <= 131_072:
        raise WorkerQueueConflict()
    return dict(value)


def _version(value: str | None) -> int:
    if type(value) is not str or not value:
        raise WorkerQueueConflict()
    unquoted = value
    if unquoted.startswith('"') or unquoted.endswith('"'):
        if len(unquoted) < 3 or not (unquoted.startswith('"') and unquoted.endswith('"')):
            raise WorkerQueueConflict()
        unquoted = unquoted[1:-1]
    if not unquoted.isascii() or not unquoted.isdecimal() or len(unquoted) > 10:
        raise WorkerQueueConflict()
    version = int(unquoted)
    if not 1 <= version <= 2_147_483_647:
        raise WorkerQueueConflict()
    return version


def _queue_connection(queue: SqliteWorkerQueue) -> sqlite3.Connection:
    connection = getattr(queue, "_connection", None)
    if not isinstance(connection, sqlite3.Connection):
        raise WorkerQueueConflict()
    return connection


def _run_repository_id(
    connection: sqlite3.Connection,
    *,
    tenant_id: str,
    run_id: str,
    execution_identity_hash: str,
) -> str:
    return _run_execution_identity(
        connection,
        tenant_id=tenant_id,
        run_id=run_id,
        execution_identity_hash=execution_identity_hash,
    ).repository_revision.repository_id


def _run_execution_identity(
    connection: sqlite3.Connection,
    *,
    tenant_id: str,
    run_id: str,
    execution_identity_hash: str,
) -> RunExecutionIdentity:
    row = connection.execute(
        """SELECT execution_identity_json FROM worker_run_queue
           WHERE tenant_id=? AND run_id=?""",
        (tenant_id, run_id),
    ).fetchone()
    if row is None:
        raise WorkerQueueConflict()
    raw_identity = row["execution_identity_json"]
    if type(raw_identity) is not str:
        raise WorkerQueueConflict()
    identity = identity_document(raw_identity)
    if identity.execution_identity_hash != execution_identity_hash:
        raise WorkerQueueConflict()
    return identity


def _artifact_root(verifier: LocalArtifactUploadVerifier) -> Path:
    root = getattr(verifier, "_root", None)
    if not isinstance(root, Path) or not root.is_absolute():
        raise WorkerQueueConflict()
    return root


def _queue_lease_seconds(queue: SqliteWorkerQueue) -> int:
    value = getattr(queue, "_lease_seconds", None)
    if type(value) is not int or not 5 <= value <= 3600:
        raise WorkerQueueConflict()
    return value


def _queue_clock(queue: SqliteWorkerQueue) -> Callable[[], datetime]:
    value = getattr(queue, "_now", None)
    if not callable(value):
        raise WorkerQueueConflict()
    return cast(Callable[[], datetime], value)


def _lease_response(lease: WorkerQueueLease) -> ServiceResponse:
    return ServiceResponse(
        200,
        {
            "command": lease.command,
            "run_id": lease.run_id,
            "session_id": lease.session_id,
            "terminal": lease.terminal,
            "version": lease.version,
            "outcome": lease.outcome,
        },
        {"etag": f'"{lease.version}"'},
    )


def _denied(status: int, code: str, message: str) -> ServiceResponse:
    return ServiceResponse(status, {"error": {"code": code, "message": message}})


__all__ = ["WorkerQueueHandler"]
