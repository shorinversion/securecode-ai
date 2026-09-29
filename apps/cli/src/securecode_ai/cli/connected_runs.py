"""Submission, run lifecycle, and run-result CLI operations."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TextIO, cast

from securecode_ai.adapters.local_durable_files import durable_delete, durable_write_new
from securecode_ai.adapters.patch_artifact import (
    PatchArtifactError,
    PatchArtifactStore,
    default_patch_artifact_root,
)

from .connected_transport import (
    INITIAL_POLL_SECONDS,
    MAX_BINARY_RESPONSE_BYTES,
    MAXIMUM_POLL_SECONDS,
    ConnectedApi,
    ConnectedArtifactApi,
    ConnectedCliError,
    ConnectedCliErrorCode,
    ConnectedOperation,
    ConnectedRunReceipt,
    ConnectedRunRequest,
    HttpConnectedApi,
    _commit,
    _exact_version_precondition,
    _idempotency_key,
    _identifier,
    _receipt,
)

MAX_POLL_ATTEMPTS = 120
_MAX_AUDIT_PAGE_EVENTS = 250
_AUDIT_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")


@dataclass(frozen=True, slots=True)
class ConnectedRunSettings:
    """Operator-supplied connected configuration resolved from the environment."""

    base_url: str
    token: str
    tenant_id: str
    repository_id: str
    head_sha: str
    idempotency_key: str
    base_sha: str | None = None
    change_id: str | None = None
    operation: ConnectedOperation = ConnectedOperation.SCAN
    scm_provider: str | None = None


def settings_from_environment(
    environment: Mapping[str, str],
    *,
    fresh: bool = False,
    operation: ConnectedOperation = ConnectedOperation.SCAN,
) -> ConnectedRunSettings:
    """Read connected-mode settings without ever logging their values.

    Unless ``fresh`` is requested, the submission key is derived from the exact
    revision so a retried command resumes the recorded run instead of duplicating
    it; ``SECURECODE_IDEMPOTENCY_KEY`` still overrides both.
    """

    def required(name: str) -> str:
        value = environment.get(name)
        if type(value) is not str or not value:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        return value

    if type(operation) is not ConnectedOperation:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    scm_provider = _configured_scm_provider(environment.get("SECURECODE_SCM_PROVIDER"))
    return ConnectedRunSettings(
        base_url=required("SECURECODE_CONTROL_PLANE_URL"),
        token=required("SECURECODE_CONTROL_PLANE_TOKEN"),
        tenant_id=required("SECURECODE_TENANT_ID"),
        repository_id=required("SECURECODE_REPOSITORY_ID"),
        head_sha=required("SECURECODE_HEAD_SHA"),
        idempotency_key=(
            environment.get("SECURECODE_IDEMPOTENCY_KEY")
            or (new_idempotency_key() if fresh else _pending_key(environment, operation=operation))
        ),
        base_sha=environment.get("SECURECODE_BASE_SHA") or None,
        change_id=environment.get("SECURECODE_CHANGE_ID") or None,
        operation=operation,
        scm_provider=scm_provider,
    )


def _pending_key(
    environment: Mapping[str, str], *, operation: ConnectedOperation = ConnectedOperation.SCAN
) -> str:
    """Compose the resumable key from the settings the operator supplied."""

    def value(name: str) -> str:
        raw = environment.get(name)
        return raw if isinstance(raw, str) else ""

    material = json.dumps(
        {
            "base_sha": value("SECURECODE_BASE_SHA") or None,
            "change_id": value("SECURECODE_CHANGE_ID") or None,
            "head_sha": value("SECURECODE_HEAD_SHA"),
            "repository_id": value("SECURECODE_REPOSITORY_ID"),
            "scm_provider": value("SECURECODE_SCM_PROVIDER") or None,
            "tenant_id": value("SECURECODE_TENANT_ID"),
            "operation": operation.value,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "cli-" + hashlib.sha256(material).hexdigest()[:48]


def _configured_scm_provider(value: object) -> str | None:
    if value is None or value == "":
        return None
    if type(value) is not str or value not in {"github", "gitlab"}:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return value


def run_connected(
    settings: ConnectedRunSettings,
    *,
    api: ConnectedApi | None = None,
    poll_status: bool = True,
    attempts: int = 1,
    sleeper: Callable[[float], None] | None = None,
) -> ConnectedRunReceipt:
    """Submit one revision and (optionally) report its terminal state."""

    if type(attempts) is not int or not 1 <= attempts <= MAX_POLL_ATTEMPTS:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    request = ConnectedRunRequest(
        tenant_id=settings.tenant_id,
        repository_id=settings.repository_id,
        head_sha=settings.head_sha,
        idempotency_key=settings.idempotency_key,
        base_sha=settings.base_sha,
        change_id=settings.change_id,
        operation=settings.operation,
        scm_provider=settings.scm_provider,
    )
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    submission = client.submit(request, token=settings.token)
    receipt = _receipt(submission)
    _require_run_binding(receipt, run_id=receipt.run_id, head_sha=settings.head_sha)
    _require_run_scope(submission, settings)
    if not poll_status:
        return receipt
    latest = receipt
    delay = INITIAL_POLL_SECONDS
    for attempt in range(attempts):
        document = client.status(receipt.run_id, token=settings.token)
        latest = _receipt(document)
        # The submitted revision is the immutable binding for the whole poll.
        # Comparing against the previous response would let a later response
        # silently move the operator onto another HEAD.
        _require_run_binding(latest, run_id=receipt.run_id, head_sha=settings.head_sha)
        _require_run_scope(document, settings)
        if latest.terminal:
            return latest
        if attempt + 1 < attempts and sleeper is not None:
            sleeper(delay)
            delay = min(delay * 2, MAXIMUM_POLL_SECONDS)
    if not latest.terminal:
        raise ConnectedCliError(ConnectedCliErrorCode.RUN_NOT_TERMINAL)
    return latest


def fetch_run(
    settings: ConnectedRunSettings, run_id: str, *, api: ConnectedApi | None = None
) -> ConnectedRunReceipt:
    """Read one run's current durable state without mutating anything."""

    if not _identifier(run_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.status(run_id, token=settings.token)
    receipt = _receipt(document)
    _require_run_binding(receipt, run_id=run_id, head_sha=settings.head_sha)
    _require_run_scope(document, settings)
    return receipt


def cancel_run(
    settings: ConnectedRunSettings,
    run_id: str,
    *,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedRunReceipt:
    """Request cancellation; the caller supplies the observed state precondition."""

    if not _identifier(run_id) or not _run_version_precondition(if_match):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or _cancel_idempotency_key(
        settings,
        run_id=run_id,
        if_match=if_match,
    )
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.cancel(
        run_id,
        token=settings.token,
        if_match=if_match,
        idempotency_key=key,
    )
    receipt = _receipt(document)
    _require_run_binding(receipt, run_id=run_id, head_sha=settings.head_sha)
    _require_run_scope(document, settings)
    return receipt


def _require_run_binding(
    receipt: ConnectedRunReceipt,
    *,
    run_id: str,
    head_sha: str,
) -> None:
    """Reject a valid-looking response that belongs to another run or revision."""

    if (
        not isinstance(receipt, ConnectedRunReceipt)
        or not _identifier(run_id)
        or not _commit(head_sha)
        or receipt.run_id != run_id
        or receipt.head_sha != head_sha
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)


def _require_run_scope(document: Mapping[str, object], settings: ConnectedRunSettings) -> None:
    """Reject a receipt that crosses the configured tenant or repository scope."""

    if (
        not isinstance(document, Mapping)
        or document.get("tenant_id") != settings.tenant_id
        or document.get("repository_id") != settings.repository_id
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)


def _cancel_idempotency_key(
    settings: ConnectedRunSettings,
    *,
    run_id: str,
    if_match: str,
) -> str:
    """Keep retries for one exact cancellation stable across CLI restarts."""

    material = json.dumps(
        {
            "if_match": if_match,
            "operation": "cancel",
            "run_id": run_id,
            "tenant_id": settings.tenant_id,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "cli-" + hashlib.sha256(material).hexdigest()[:48]


def render_receipt(receipt: ConnectedRunReceipt, output: TextIO) -> None:
    """Write the canonical source-free reference for shell consumption."""

    output.write(json.dumps(receipt.document(), sort_keys=True, separators=(",", ":")) + "\n")


def new_idempotency_key() -> str:
    """A fresh key, for callers that explicitly want a new run."""

    return "cli-" + uuid.uuid4().hex


def resumable_idempotency_key(settings: ConnectedRunSettings) -> str:
    """Derive a stable key from the exact submission so retries resume one run.

    Re-running the same command for the same revision therefore replays the
    recorded admission instead of opening a second run, which is what a CI
    job retry needs. Callers that want a genuinely new run generate a fresh key.
    """

    material = json.dumps(
        {
            "base_sha": settings.base_sha,
            "change_id": settings.change_id,
            "head_sha": settings.head_sha,
            "repository_id": settings.repository_id,
            "scm_provider": settings.scm_provider,
            "tenant_id": settings.tenant_id,
            "operation": settings.operation.value,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "cli-" + hashlib.sha256(material).hexdigest()[:48]


def parse_run_arguments(tokens: tuple[str, ...]) -> tuple[str, str | None]:
    """Parse `securecode status|cancel <run_id> [--if-match <value>]`."""

    run_id: str | None = None
    if_match: str | None = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--if-match":
            if index + 1 >= len(tokens) or if_match is not None:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            if_match = tokens[index + 1]
            index += 2
            continue
        if token.startswith("-") or run_id is not None:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        run_id = token
        index += 1
    if run_id is None or not _identifier(run_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if if_match is not None and not _run_version_precondition(if_match):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return run_id, if_match


def _run_version_precondition(value: object) -> bool:
    """Match the server cancellation precondition grammar before sending it."""

    return _exact_version_precondition(value, minimum=1)


def parse_connected_arguments(tokens: tuple[str, ...]) -> tuple[Path | None, bool, bool]:
    """Parse scan-only connected arguments used by the CI command."""

    target, wait, fresh, operation = parse_connected_arguments_with_operation(tokens)
    if operation is not ConnectedOperation.SCAN:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return target, wait, fresh


def parse_connected_arguments_with_operation(
    tokens: tuple[str, ...],
) -> tuple[Path | None, bool, bool, ConnectedOperation]:
    """Parse `securecode connect [target] [--wait] [--new-run] [--operation ...]`."""

    target: Path | None = None
    wait = False
    fresh = False
    operation = ConnectedOperation.SCAN
    operation_seen = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--wait":
            if wait:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            wait = True
            index += 1
        elif token == "--new-run":
            if fresh:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            fresh = True
            index += 1
        elif token == "--operation":
            if index + 1 >= len(tokens) or operation_seen:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            try:
                operation = ConnectedOperation(tokens[index + 1])
            except ValueError:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION) from None
            operation_seen = True
            index += 2
        elif token.startswith("-"):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        elif target is None:
            target = Path(token)
            index += 1
        else:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return target, wait, fresh, operation


def timestamp() -> str:
    """Canonical UTC timestamp helper shared by connected receipts."""

    return datetime.now(UTC).isoformat()


class ResultKind(StrEnum):
    """Readable run outputs exposed by the control plane."""

    FINDINGS = "findings"
    ARTIFACTS = "artifacts"
    EVENTS = "events"

    @property
    def path(self) -> str:
        return f"/api/v1/runs/{{run_id}}/{self.value}"


@dataclass(frozen=True, slots=True)
class ConnectedCollection:
    """One bounded, source-free readout document for a run."""

    run_id: str
    kind: ResultKind
    document: Mapping[str, object]

    def render(self) -> str:
        return json.dumps(self.document, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def fetch_audit(
    settings: ConnectedRunSettings,
    run_id: str,
    *,
    start: int = 1,
    end: int | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read and verify one bounded page of the immutable run audit chain."""

    if (
        not _identifier(run_id)
        or type(start) is not int
        or start < 1
        or (end is not None and (type(end) is not int or end < start))
        or (end is not None and end - start + 1 > _MAX_AUDIT_PAGE_EVENTS)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    query = {"start": str(start)}
    if end is not None:
        query["end"] = str(end)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read(
        f"/api/v1/runs/{run_id}/audit",
        token=settings.token,
        query=query,
    )
    _validate_run_audit_document(
        document,
        tenant_id=settings.tenant_id,
        run_id=run_id,
        start=start,
        end=end,
    )
    return ConnectedCollection(run_id=run_id, kind=ResultKind.EVENTS, document=document)


def parse_audit_arguments(tokens: tuple[str, ...]) -> tuple[str, int, int | None]:
    """Parse one audit page with explicit, bounded sequence cursors."""

    if (
        type(tokens) is not tuple
        or len(tokens) > 5
        or any(type(token) is not str or len(token) > 512 for token in tokens)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    run_id: str | None = None
    start = 1
    end: int | None = None
    start_seen = False
    end_seen = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in {"--start", "--end"}:
            if index + 1 >= len(tokens):
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            raw = tokens[index + 1]
            if not raw.isascii() or not raw.isdecimal() or len(raw) > 10:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            value = int(raw)
            if not 1 <= value <= 2_147_483_647:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            if token == "--start":
                if start_seen:
                    raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
                start = value
                start_seen = True
            else:
                if end_seen:
                    raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
                end = value
                end_seen = True
            index += 2
            continue
        if token.startswith("-") or run_id is not None or not _identifier(token):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        run_id = token
        index += 1
    if run_id is None or (
        end is not None and (end < start or end - start + 1 > _MAX_AUDIT_PAGE_EVENTS)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return run_id, start, end


def _validate_run_audit_document(
    document: Mapping[str, object],
    *,
    tenant_id: str,
    run_id: str,
    start: int,
    end: int | None,
) -> None:
    fields = {
        "manifest_sha256",
        "document",
    }
    if type(document) is not dict or set(document) != fields:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    body = document.get("document")
    expected_fields = {
        "tenant_id",
        "run_id",
        "range_start",
        "range_end",
        "head_sequence",
        "has_more",
        "next_start",
        "chain_head",
        "events",
        "authority",
    }
    if type(body) is not dict or set(body) != expected_fields:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    events = body.get("events")
    range_end = body.get("range_end")
    head = body.get("head_sequence")
    next_start = body.get("next_start")
    if (
        body.get("tenant_id") != tenant_id
        or body.get("run_id") != run_id
        or body.get("range_start") != start
        or type(range_end) is not int
        or type(head) is not int
        or head < 0
        or range_end < start - 1
        or range_end > head
        or start > head + 1
        or (end is not None and range_end > end)
        or type(body.get("has_more")) is not bool
        or body.get("has_more") != (head > range_end)
        or (next_start != range_end + 1 if head > range_end else next_start is not None)
        or body.get("authority") != "NONE"
        or not _sha256(body.get("chain_head"))
        or type(events) is not list
        or len(events) > _MAX_AUDIT_PAGE_EVENTS
        or (range_end - start + 1) != len(events)
        or not _sha256(document.get("manifest_sha256"))
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    previous_hash: str | None = None
    for index, event in enumerate(events):
        if type(event) is not dict or set(event) != {
            "tenant_id",
            "repository_id",
            "run_id",
            "actor_id",
            "action",
            "execution_identity_hash",
            "sequence",
            "previous_hash",
            "attributes",
            "created_at",
            "event_hash",
        }:
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
        sequence = start + index
        if (
            event.get("tenant_id") != tenant_id
            or event.get("run_id") != run_id
            or type(event.get("repository_id")) is not str
            or _AUDIT_IDENTIFIER.fullmatch(event["repository_id"]) is None
            or type(event.get("actor_id")) is not str
            or _AUDIT_IDENTIFIER.fullmatch(event["actor_id"]) is None
            or type(event.get("action")) is not str
            or _AUDIT_IDENTIFIER.fullmatch(event["action"]) is None
            or type(event.get("sequence")) is not int
            or event["sequence"] != sequence
            or not _sha256(event.get("execution_identity_hash"))
            or not _sha256(event.get("previous_hash"))
            or (index == 0 and sequence == 1 and event["previous_hash"] != "0" * 64)
            or (previous_hash is not None and event["previous_hash"] != previous_hash)
            or not _sha256(event.get("event_hash"))
            or not _audit_event_hash_matches(event)
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
        attributes = event.get("attributes")
        if (
            type(attributes) is not dict
            or len(attributes) > 4
            or any(
                key not in {"outcome", "reason_code", "resource_type", "retention_marked"}
                for key in attributes
            )
            or any(
                (
                    key == "outcome"
                    and (
                        type(value) is not str
                        or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", value)
                    )
                )
                or (
                    key == "reason_code"
                    and (
                        type(value) is not str
                        or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value) is None
                    )
                )
                or (key == "resource_type" and value not in {"metadata", "artifact", "audit"})
                or (key == "retention_marked" and type(value) is not bool)
                for key, value in attributes.items()
            )
            or type(event.get("created_at")) is not str
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
        try:
            created_at = datetime.fromisoformat(event["created_at"])
        except ValueError:
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID) from None
        if created_at.tzinfo is None or created_at.utcoffset() != UTC.utcoffset(created_at):
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
        previous_hash = event["event_hash"]
    expected_chain_head = previous_hash or ("0" * 64 if range_end == 0 else None)
    if expected_chain_head is None or body["chain_head"] != expected_chain_head:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    canonical_body = json.dumps(
        body,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if hashlib.sha256(canonical_body).hexdigest() != document["manifest_sha256"]:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)


def _audit_event_hash_matches(event: Mapping[str, object]) -> bool:
    material = {
        "tenant_id": event.get("tenant_id"),
        "repository_id": event.get("repository_id"),
        "run_id": event.get("run_id"),
        "actor_id": event.get("actor_id"),
        "action": event.get("action"),
        "execution_identity_hash": event.get("execution_identity_hash"),
        "sequence": event.get("sequence"),
        "previous_hash": event.get("previous_hash"),
        "attributes": event.get("attributes"),
        "created_at": event.get("created_at"),
    }
    if type(material["attributes"]) is not dict or type(material["created_at"]) is not str:
        return False
    encoded = json.dumps(
        material,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest() == event.get("event_hash")


@dataclass(frozen=True, slots=True)
class ImportedRepairPatch:
    """Source-free receipt for one locally imported, bound patch bundle."""

    selector: str
    manifest_sha256: str
    patch_size_bytes: int

    def document(self) -> dict[str, object]:
        return {
            "manifest_sha256": self.manifest_sha256,
            "patch_size_bytes": self.patch_size_bytes,
            "selector": self.selector,
        }


def fetch_results(
    settings: ConnectedRunSettings,
    run_id: str,
    kind: ResultKind,
    *,
    content_sha256: str | None = None,
    cursor: str | None = None,
    limit: int = 50,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read findings, artifacts or events for one run without mutating anything."""

    if not _identifier(run_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if type(kind) is not ResultKind:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if (
        type(limit) is not int
        or not 1 <= limit <= 100
        or (cursor is not None and not _valid_cursor(cursor))
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if content_sha256 is not None and (
        kind is not ResultKind.ARTIFACTS
        or not _sha256(content_sha256)
        or cursor is not None
        or limit != 50
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    run_document = client.status(run_id, token=settings.token)
    run_receipt = _receipt(run_document)
    _require_run_binding(run_receipt, run_id=run_id, head_sha=settings.head_sha)
    if (
        run_document.get("tenant_id") != settings.tenant_id
        or run_document.get("repository_id") != settings.repository_id
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    query: dict[str, str] | None
    if content_sha256 is not None:
        query = {"content_sha256": content_sha256}
    else:
        query = {"limit": str(limit)}
        if cursor is not None:
            query["cursor"] = cursor
    document = client.read(
        kind.path.format(run_id=run_id),
        token=settings.token,
        query=query,
    )
    if not isinstance(document, Mapping) or not document:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if content_sha256 is None:
        items = document.get("items")
        next_cursor = document.get("next_cursor")
        if (
            set(document) != {"items", "next_cursor"}
            or type(items) is not list
            or len(items) > limit
            or any(type(item) is not dict for item in items)
            or (next_cursor is not None and not _valid_cursor(next_cursor))
            or (next_cursor is not None and next_cursor == cursor)
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
        for item in items:
            _validate_result_item(
                kind,
                item,
                head_sha=settings.head_sha,
                tenant_id=settings.tenant_id,
            )
    elif not _valid_artifact_content(document, content_sha256):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return ConnectedCollection(run_id=run_id, kind=kind, document=document)


def download_artifact(
    settings: ConnectedRunSettings,
    run_id: str,
    content_sha256: str,
    *,
    api: ConnectedArtifactApi | None = None,
) -> bytes:
    """Download one committed artifact without converting it to JSON."""

    if not _identifier(run_id) or not _sha256(content_sha256):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    run_document = client.status(run_id, token=settings.token)
    receipt = _receipt(run_document)
    _require_run_binding(receipt, run_id=run_id, head_sha=settings.head_sha)
    if (
        run_document.get("tenant_id") != settings.tenant_id
        or run_document.get("repository_id") != settings.repository_id
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    content = client.download(run_id, content_sha256, token=settings.token)
    if (
        type(content) is not bytes
        or not 1 <= len(content) <= MAX_BINARY_RESPONSE_BYTES
        or hashlib.sha256(content).hexdigest() != content_sha256
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return content


def download_repair_patch(
    settings: ConnectedRunSettings,
    run_id: str,
    finding_id: str,
    patch_sha256: str,
    *,
    api: ConnectedArtifactApi | None = None,
) -> bytes:
    """Download one repair bundle bound to the live run and exact patch."""

    if not _identifier(run_id) or not _identifier(finding_id) or not _sha256(patch_sha256):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    run_document = client.status(run_id, token=settings.token)
    receipt = _receipt(run_document)
    _require_run_binding(receipt, run_id=run_id, head_sha=settings.head_sha)
    _require_run_scope(run_document, settings)
    execution_identity_hash = run_document.get("execution_identity_hash")
    if not _sha256(execution_identity_hash):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    content = client.download_repair_patch(
        run_id,
        finding_id,
        patch_sha256,
        token=settings.token,
    )
    _decode_repair_patch_bundle(
        content,
        expected={
            "execution_identity_hash": execution_identity_hash,
            "finding_id": finding_id,
            "head_sha": settings.head_sha,
            "repository_id": settings.repository_id,
            "run_id": run_id,
            "tenant_id": settings.tenant_id,
            "patch_sha256": patch_sha256,
        },
    )
    return content


def import_repair_patch_bundle(
    environment: Mapping[str, str],
    target: Path,
    content: bytes,
    *,
    expected: Mapping[str, object] | None = None,
) -> ImportedRepairPatch:
    """Validate and atomically re-import a server bundle into local patch storage."""

    if not isinstance(environment, Mapping) or not isinstance(target, Path):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    binding, patch_bytes, manifest_bytes = _decode_repair_patch_bundle(
        content,
        expected=expected,
    )
    try:
        store = PatchArtifactStore(
            root=default_patch_artifact_root(environment),
            checkout=target,
        )
        selector = "sha256:" + str(binding["patch_sha256"])
        directory = store.root / str(binding["patch_sha256"])[:2]
        if directory.exists() or directory.is_symlink():
            if directory.is_symlink() or not directory.is_dir():
                raise PatchArtifactError("PATCH_ARTIFACT_UNAVAILABLE")
        else:
            directory.mkdir(mode=0o700)
        patch_path = directory / (str(binding["patch_sha256"]) + ".patch")
        manifest_path = directory / (str(binding["patch_sha256"]) + ".json")
        created: list[Path] = []
        try:
            if _write_import_file(patch_path, patch_bytes):
                created.append(patch_path)
            if _write_import_file(manifest_path, manifest_bytes):
                created.append(manifest_path)
            stored = store.load(selector)
            revision = stored.finding.repository_revision
            if (
                stored.patch_bytes != patch_bytes
                or stored.manifest_sha256 != str(binding["manifest_sha256"])
                or stored.finding.finding_id != binding["finding_id"]
                or revision.tenant_id != binding["tenant_id"]
                or revision.repository_id != binding["repository_id"]
                or revision.head_sha != binding["head_sha"]
            ):
                raise PatchArtifactError("PATCH_CONTRACT_MISMATCH")
        except Exception:
            for path in reversed(created):
                with suppress(OSError):
                    durable_delete(path)
            raise
    except ConnectedCliError:
        raise
    except (OSError, PatchArtifactError, TypeError, ValueError):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID) from None
    return ImportedRepairPatch(
        selector=selector,
        manifest_sha256=str(binding["manifest_sha256"]),
        # _decode_repair_patch_bundle requires patch_size_bytes to be exactly an int.
        patch_size_bytes=cast(int, binding["patch_size_bytes"]),
    )


def _write_import_file(path: Path, content: bytes) -> bool:
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file():
            raise PatchArtifactError("PATCH_ARTIFACT_UNAVAILABLE")
        try:
            existing = path.read_bytes()
        except OSError:
            raise PatchArtifactError("PATCH_ARTIFACT_UNAVAILABLE") from None
        if existing != content:
            raise PatchArtifactError("PATCH_ARTIFACT_COLLISION")
        return False
    try:
        durable_write_new(path, content)
    except FileExistsError:
        return _write_import_file(path, content)
    except OSError:
        raise PatchArtifactError("PATCH_ARTIFACT_UNAVAILABLE") from None
    return True


_REPAIR_PATCH_BINDING_KEYS = frozenset(
    {
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
)


def _decode_repair_patch_bundle(
    content: bytes,
    *,
    expected: Mapping[str, object] | None,
) -> tuple[dict[str, object], bytes, bytes]:
    if type(content) is not bytes or not 1 <= len(content) <= MAX_BINARY_RESPONSE_BYTES:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    try:
        document = json.loads(
            content.decode("ascii"),
            object_pairs_hook=_closed_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID) from None
    if (
        type(document) is not dict
        or set(document) != {"binding", "manifest_base64", "patch_base64", "schema_version"}
        or document.get("schema_version") != "securecode.repair-patch.v1"
        or type(document.get("binding")) is not dict
        or set(document["binding"]) != _REPAIR_PATCH_BINDING_KEYS
        or type(document.get("manifest_base64")) is not str
        or type(document.get("patch_base64")) is not str
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    binding = document["binding"]
    if (
        not _identifier(binding.get("tenant_id"))
        or not _identifier(binding.get("repository_id"))
        or not _identifier(binding.get("run_id"))
        or not _identifier(binding.get("finding_id"))
        or not _commit(binding.get("head_sha"))
        or any(
            not _sha256(binding.get(name))
            for name in (
                "execution_identity_hash",
                "manifest_sha256",
                "patch_sha256",
                "patch_status_sha256",
                "validation_result_sha256",
            )
        )
        or type(binding.get("patch_size_bytes")) is not int
        or not 1 <= binding["patch_size_bytes"] <= 131_072
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if expected is not None and any(binding.get(key) != value for key, value in expected.items()):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    try:
        encoded_manifest = document["manifest_base64"]
        encoded_patch = document["patch_base64"]
        manifest_bytes = base64.b64decode(encoded_manifest.encode("ascii"), validate=True)
        patch_bytes = base64.b64decode(encoded_patch.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID) from None
    if (
        not manifest_bytes
        or len(manifest_bytes) > 1_048_576
        or not patch_bytes
        or len(patch_bytes) != binding["patch_size_bytes"]
        or hashlib.sha256(manifest_bytes).hexdigest() != binding["manifest_sha256"]
        or hashlib.sha256(patch_bytes).hexdigest() != binding["patch_sha256"]
        or base64.b64encode(manifest_bytes).decode("ascii") != encoded_manifest
        or base64.b64encode(patch_bytes).decode("ascii") != encoded_patch
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return dict(binding), patch_bytes, manifest_bytes


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result or "\x00" in key:
            raise ValueError
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> object:
    raise ValueError


def parse_results_arguments(tokens: tuple[str, ...]) -> tuple[str, ResultKind]:
    """Parse `securecode results <run_id> --kind findings|artifacts|events`."""

    run_id: str | None = None
    kind: ResultKind | None = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--kind":
            if index + 1 >= len(tokens) or kind is not None:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            try:
                kind = ResultKind(tokens[index + 1])
            except ValueError:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION) from None
            index += 2
            continue
        if token.startswith("-") or run_id is not None:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        run_id = token
        index += 1
    if run_id is None or not _identifier(run_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return run_id, kind if kind is not None else ResultKind.FINDINGS


def parse_download_arguments(tokens: tuple[str, ...]) -> tuple[str, str, Path]:
    """Parse `securecode download <run_id> <sha256> --output <path>`."""

    if (
        type(tokens) is not tuple
        or len(tokens) > 7
        or any(type(token) is not str or len(token) > 4096 for token in tokens)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    run_id: str | None = None
    content_sha256: str | None = None
    output: str | None = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--output":
            if index + 1 >= len(tokens) or output is not None:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            output = tokens[index + 1]
            index += 2
            continue
        if token.startswith("-"):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if run_id is None:
            run_id = token
        elif content_sha256 is None:
            content_sha256 = token
        else:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        index += 1
    if (
        run_id is None
        or content_sha256 is None
        or output is None
        or output == "-"
        or "\x00" in output
        or not _identifier(run_id)
        or not _sha256(content_sha256)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return run_id, content_sha256, Path(output)


def parse_repair_download_arguments(
    tokens: tuple[str, ...],
) -> tuple[str, str, str, Path]:
    """Parse `securecode repair-download <run_id> <finding_id> <patch_sha256> --target <path>`."""

    if (
        type(tokens) is not tuple
        or len(tokens) > 7
        or any(type(token) is not str or len(token) > 4096 for token in tokens)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    run_id: str | None = None
    finding_id: str | None = None
    patch_sha256: str | None = None
    target: str | None = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--target":
            if index + 1 >= len(tokens) or target is not None:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            target = tokens[index + 1]
            index += 2
            continue
        if token.startswith("-"):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if run_id is None:
            run_id = token
        elif finding_id is None:
            finding_id = token
        elif patch_sha256 is None:
            patch_sha256 = token
        else:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        index += 1
    if (
        run_id is None
        or finding_id is None
        or patch_sha256 is None
        or target is None
        or target == "-"
        or "\x00" in target
        or not _identifier(run_id)
        or not _identifier(finding_id)
        or not _sha256(patch_sha256)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return run_id, finding_id, patch_sha256, Path(target)


def parse_results_arguments_with_content(
    tokens: tuple[str, ...],
) -> tuple[str, ResultKind, str | None]:
    """Parse run result selection with an optional committed artifact digest."""

    parsed = parse_results_arguments_with_page(tokens)
    return parsed[0], parsed[1], parsed[2]


def parse_results_arguments_with_page(
    tokens: tuple[str, ...],
) -> tuple[str, ResultKind, str | None, str | None, int]:
    """Parse a run collection and its bounded cursor page."""

    if (
        type(tokens) is not tuple
        or len(tokens) > 9
        or any(type(token) is not str or len(token) > 512 for token in tokens)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)

    run_id: str | None = None
    kind: ResultKind | None = None
    content_sha256: str | None = None
    cursor: str | None = None
    limit = 50
    limit_seen = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--kind":
            if index + 1 >= len(tokens) or kind is not None:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            try:
                kind = ResultKind(tokens[index + 1])
            except ValueError:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION) from None
            index += 2
            continue
        if token == "--cursor":
            if index + 1 >= len(tokens) or cursor is not None:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            cursor = tokens[index + 1]
            index += 2
            continue
        if token == "--limit":
            if index + 1 >= len(tokens) or limit_seen:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            raw_limit = tokens[index + 1]
            if not raw_limit.isascii() or not raw_limit.isdecimal() or len(raw_limit) > 3:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            limit = int(raw_limit)
            limit_seen = True
            index += 2
            continue
        if token == "--content-sha256":
            if index + 1 >= len(tokens) or content_sha256 is not None:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            content_sha256 = tokens[index + 1]
            index += 2
            continue
        if token.startswith("-") or run_id is not None:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        run_id = token
        index += 1
    selected_kind = kind if kind is not None else ResultKind.FINDINGS
    if (
        run_id is None
        or not _identifier(run_id)
        or (content_sha256 is not None and not _sha256(content_sha256))
        or (content_sha256 is not None and selected_kind is not ResultKind.ARTIFACTS)
        or not 1 <= limit <= 100
        or (cursor is not None and not _valid_cursor(cursor))
        or (content_sha256 is not None and (cursor is not None or limit_seen))
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return run_id, selected_kind, content_sha256, cursor, limit


def _valid_cursor(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 512
        and all(
            character.isascii() and (character.isalnum() or character in "-_")
            for character in value
        )
    )


def _valid_artifact_content(document: Mapping[str, object], expected_digest: str) -> bool:
    if set(document) != {
        "committed_at",
        "content_base64",
        "content_encoding",
        "content_id",
        "content_sha256",
        "data_class",
        "purpose",
        "size_bytes",
    }:
        return False
    encoded = document.get("content_base64")
    size = document.get("size_bytes")
    if (
        type(encoded) is not str
        or type(size) is not int
        or not 1 <= size <= 700_000
        or document.get("content_encoding") != "base64"
        or document.get("content_sha256") != expected_digest
        or type(document.get("content_id")) is not str
        or not document["content_id"]
        or document.get("data_class")
        not in {"DC0_PUBLIC", "DC1_INTERNAL_METADATA", "DC2_CONFIDENTIAL_SECURITY"}
        or document.get("purpose")
        not in {
            "audit-report",
            "audit-run",
            "evidence-graph",
            "repair-report",
            "sarif-report",
        }
        or type(document.get("committed_at")) is not str
        or not document["committed_at"]
    ):
        return False
    try:
        content = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        return False
    return len(content) == size and hashlib.sha256(content).hexdigest() == expected_digest


def _validate_result_item(
    kind: ResultKind,
    item: dict[str, object],
    *,
    head_sha: str,
    tenant_id: str,
) -> None:
    if kind is ResultKind.FINDINGS:
        if not _valid_result_finding(item, head_sha=head_sha, tenant_id=tenant_id):
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    elif kind is ResultKind.EVENTS:
        if not _valid_result_event(item):
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    elif kind is ResultKind.ARTIFACTS and not _valid_result_artifact(item):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)


def _valid_result_finding(item: Mapping[str, object], *, head_sha: str, tenant_id: str) -> bool:
    required = {
        "blocking",
        "confidence",
        "cwe_id",
        "evidence_graph_ref",
        "finding_id",
        "locations",
        "revision_sha",
        "root_cause_fingerprint",
        "severity",
        "verdict",
    }
    cwe_id = item.get("cwe_id")
    locations = item.get("locations")
    reference = item.get("evidence_graph_ref")
    return (
        set(item) == required
        and _valid_identifier(item.get("finding_id"))
        and item.get("revision_sha") == head_sha
        and _sha256(item.get("root_cause_fingerprint"))
        and type(item.get("blocking")) is bool
        and item.get("confidence") == "UNSCORED"
        and item.get("severity") in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        and item.get("verdict")
        in {
            "CONFIRMED",
            "REJECTED_WITH_EVIDENCE",
            "NEEDS_MORE_EVIDENCE",
            "CONFLICTING",
            "NOT_EVALUATED",
        }
        and type(cwe_id) is str
        and cwe_id.startswith("CWE-")
        and 1 <= len(cwe_id[4:]) <= 6
        and cwe_id[4:].isascii()
        and cwe_id[4:].isdigit()
        and not cwe_id[4:].startswith("0")
        and type(locations) is list
        and 1 <= len(locations) <= 4096
        and all(_valid_result_location(location) for location in locations)
        and _valid_evidence_reference(reference, tenant_id=tenant_id)
    )


def _valid_result_location(value: object) -> bool:
    if type(value) is not dict or set(value) != {"end_line", "path", "start_line"}:
        return False
    path = value.get("path")
    start_line = value.get("start_line")
    end_line = value.get("end_line")
    return (
        type(path) is str
        and bool(path)
        and path == path.strip()
        and len(path) <= 1024
        and "\\" not in path
        and all(character.isprintable() for character in path)
        and type(start_line) is int
        and start_line >= 1
        and type(end_line) is int
        and end_line >= start_line
    )


def _valid_evidence_reference(value: object, *, tenant_id: str) -> bool:
    if type(value) is not dict:
        return False
    keys = frozenset(value)
    if keys not in {
        frozenset({"tenant_id", "content_id", "content_sha256", "size_bytes", "data_class"}),
        frozenset(
            {
                "tenant_id",
                "content_id",
                "content_sha256",
                "size_bytes",
                "data_class",
                "expires_at",
            }
        ),
    }:
        return False
    size = value.get("size_bytes")
    expires_at = value.get("expires_at")
    return (
        value.get("tenant_id") == tenant_id
        and _valid_identifier(value.get("content_id"))
        and _sha256(value.get("content_sha256"))
        and type(size) is int
        and size >= 0
        and value.get("data_class") == "DC2_CONFIDENTIAL_SECURITY"
        and (
            "expires_at" not in value
            or expires_at is None
            or (type(expires_at) is str and _utc_timestamp(expires_at))
        )
    )


def _valid_result_event(item: Mapping[str, object]) -> bool:
    if item.get("event_id") == "securecode-policy-decision-v1":
        return _valid_policy_event(item)
    event_hash = item.get("event_hash")
    worker_sequence = item.get("worker_sequence")
    sequence = item.get("sequence")
    kind = item.get("kind")
    event_id = item.get("event_id")
    return (
        set(item) == {"event_hash", "kind", "worker_sequence", "sequence", "event_id"}
        and _sha256(event_hash)
        and type(kind) is str
        and kind
        in {
            "RUN_STARTED",
            "RUN_COMPLETED",
            "RUN_CANCELLED",
            "RUN_SUPERSEDED",
            "RUN_FAILED",
        }
        and type(worker_sequence) is int
        and 1 <= worker_sequence <= 2_147_483_647
        and type(sequence) is int
        and 1 <= sequence <= 2_147_483_647
        and type(event_id) is str
        and event_id == f"worker-{worker_sequence}-{str(event_hash)[:32]}"
    )


def _valid_policy_event(item: Mapping[str, object]) -> bool:
    """Validate the source-free policy event emitted into the run stream."""

    if set(item) != {"kind", "policy_decision", "sequence", "event_id"}:
        return False
    sequence = item.get("sequence")
    decision = item.get("policy_decision")
    if (
        item.get("kind") != "SCM_POLICY_DECISION"
        or type(sequence) is not int
        or not 1 <= sequence <= 2_147_483_647
        or not isinstance(decision, Mapping)
    ):
        return False
    required = {
        "blocks_merge",
        "decision_sha256",
        "enforcement",
        "error_code",
        "input_hashes",
        "is_passing",
        "matched_rule_ids",
        "mode",
        "observed_audit_outcome",
        "policy_id",
        "policy_version",
        "publication_permitted",
        "schema_version",
    }
    if set(decision) != required:
        return False
    error_code = decision.get("error_code")
    if error_code is not None and (
        type(error_code) is not str
        or error_code
        not in {
            "INVALID_INPUT",
            "PRECALIBRATION_BLOCKING",
            "BASELINE_REQUIRED",
            "BASELINE_IDENTITY_MISMATCH",
            "CHANGED_SCOPE_REQUIRED",
            "UNMAPPED_BLOCKING_FINDING",
            "MANDATORY_COVERAGE_INCOMPLETE",
            "HUMAN_REVIEW_REQUIRED",
            "CONFIDENCE_UNAVAILABLE",
        }
    ):
        return False
    matched_rule_ids = decision.get("matched_rule_ids")
    if (
        type(matched_rule_ids) is not list
        or not 1 <= len(matched_rule_ids) <= 16
        or any(not _valid_identifier(value) for value in matched_rule_ids)
        or len(set(matched_rule_ids)) != len(matched_rule_ids)
    ):
        return False
    input_hashes = decision.get("input_hashes")
    if input_hashes is not None:
        if not isinstance(input_hashes, Mapping) or set(input_hashes) != {
            "audit_run_sha256",
            "baseline_comparison_sha256",
            "changed_scope_sha256",
            "execution_identity_sha256",
            "policy_document_sha256",
        }:
            return False
        if any(
            not _sha256(value)
            for name, value in input_hashes.items()
            if name not in {"baseline_comparison_sha256", "changed_scope_sha256"}
        ) or any(
            value is not None and not _sha256(value)
            for name, value in input_hashes.items()
            if name in {"baseline_comparison_sha256", "changed_scope_sha256"}
        ):
            return False
    policy_id = decision.get("policy_id")
    policy_version = decision.get("policy_version")
    enforcement = decision.get("enforcement")
    mode = decision.get("mode")
    observed_outcome = decision.get("observed_audit_outcome")
    if policy_id is not None and not _valid_identifier(policy_id):
        return False
    if policy_version is not None and not _valid_identifier(policy_version):
        return False
    return (
        decision.get("schema_version") == "securecode.scm-policy.v1"
        and type(decision.get("blocks_merge")) is bool
        and type(decision.get("is_passing")) is bool
        and type(decision.get("publication_permitted")) is bool
        and type(enforcement) is str
        and enforcement in {"ADVISORY", "ALLOW", "BLOCK", "NON_PASS"}
        and (mode is None or (type(mode) is str and mode in {"advisory", "new_code", "strict"}))
        and (
            observed_outcome is None
            or (
                type(observed_outcome) is str
                and observed_outcome in {"PASS", "FAIL", "INDETERMINATE", "CANCELLED", "SUPERSEDED"}
            )
        )
        and _sha256(decision.get("decision_sha256"))
        and (
            error_code is not None
            or (
                policy_id is not None
                and policy_version is not None
                and mode is not None
                and observed_outcome is not None
                and input_hashes is not None
            )
        )
    )


def _valid_result_artifact(item: Mapping[str, object]) -> bool:
    size = item.get("size_bytes")
    committed_at = item.get("committed_at")
    return (
        set(item)
        == {
            "content_id",
            "content_sha256",
            "purpose",
            "size_bytes",
            "data_class",
            "committed_at",
        }
        and _valid_identifier(item.get("content_id"))
        and _sha256(item.get("content_sha256"))
        and item.get("purpose")
        in {
            "audit-report",
            "audit-run",
            "evidence-graph",
            "repair-report",
            "sarif-report",
        }
        and type(size) is int
        and 1 <= size <= MAX_BINARY_RESPONSE_BYTES
        and item.get("data_class")
        in {"DC0_PUBLIC", "DC1_INTERNAL_METADATA", "DC2_CONFIDENTIAL_SECURITY"}
        and type(committed_at) is str
        and _utc_timestamp(committed_at)
    )


def _valid_identifier(value: object) -> bool:
    return type(value) is str and _identifier(value)


def _utc_timestamp(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def _sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
