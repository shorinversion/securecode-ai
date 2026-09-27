"""Approval, finding, policy, health, and event operations."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from .connected_runs import (
    ConnectedCollection,
    ConnectedRunSettings,
    ResultKind,
)
from .connected_transport import (
    ConnectedApi,
    ConnectedCliError,
    ConnectedCliErrorCode,
    HttpConnectedApi,
    _commit,
    _idempotency_key,
    _identifier,
    _precondition,
    _version_precondition,
)
from .connected_validation import _sha256

_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_APPROVAL_STATES = frozenset({"PENDING", "APPROVED", "REJECTED", "REVOKED", "EXPIRED"})
_MAX_VERSION = 2_147_483_647


@dataclass(frozen=True, slots=True)
class ApprovalDraft:
    """Operator-supplied fields for one approval request."""

    approval_id: str
    repository_id: str
    run_id: str
    finding_id: str
    execution_identity_hash: str
    expires_at: str
    patch_sha256: str | None = None
    validation_result_sha256: str | None = None
    manifest_sha256: str | None = None
    patch_status_sha256: str | None = None

    def __post_init__(self) -> None:
        if (
            not _identifier(self.approval_id)
            or not _identifier(self.repository_id)
            or not _identifier(self.run_id)
            or not _identifier(self.finding_id)
            or not _sha256(self.execution_identity_hash)
            or not _timestamp(self.expires_at)
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        patch_digests = (
            self.patch_sha256,
            self.validation_result_sha256,
            self.manifest_sha256,
            self.patch_status_sha256,
        )
        if any(value is not None for value in patch_digests) and (
            any(value is None for value in patch_digests)
            or any(not _sha256(value) for value in patch_digests)
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if self.approval_id.startswith("repair-") and any(value is None for value in patch_digests):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if self.approval_id.startswith("repair-"):
            if self.approval_id != repair_approval_id(
                self.run_id,
                self.finding_id,
                self.patch_sha256 or "",
            ):
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)


def _timestamp(value: object) -> bool:
    if type(value) is not str or not 20 <= len(value) <= 40:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == UTC.utcoffset(parsed)


def _approval_version_precondition(value: object) -> bool:
    return _version_precondition(value, minimum=1)


def repair_approval_id(run_id: str, finding_id: str, patch_sha256: str) -> str:
    """Derive the stable approval identity for one exact repair candidate."""

    if not _identifier(run_id) or not _identifier(finding_id) or not _sha256(patch_sha256):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    selector = "sha256:" + patch_sha256
    return "repair-" + hashlib.sha256(
        f"{run_id}\x00{finding_id}\x00{selector}".encode("ascii")
    ).hexdigest()[:48]


def _approval_decision_idempotency_key(
    *,
    settings: ConnectedRunSettings,
    approval_id: str,
    approve: bool,
    reason_code: str,
    rationale: str,
    if_match: str,
) -> str:
    """Return a retry-stable key for this exact approval decision request."""

    payload = json.dumps(
        {
            "approval_id": approval_id,
            "approve": approve,
            "if_match": if_match,
            "operation": "approval-decision",
            "rationale_sha256": hashlib.sha256(rationale.encode("utf-8")).hexdigest(),
            "reason_code": reason_code,
            "tenant_id": settings.tenant_id,
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "cli-" + hashlib.sha256(payload).hexdigest()[:48]


def _approval_create_idempotency_key(request_document: Mapping[str, object]) -> str:
    """Derive a stable key from the complete approval creation request."""

    payload = json.dumps(
        request_document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "repair-request-" + hashlib.sha256(payload).hexdigest()


def _finding_decision_idempotency_key(
    *,
    settings: ConnectedRunSettings,
    finding_id: str,
    run_id: str,
    revision_sha: str,
    decision_type: str,
    reason: str,
    if_match: str,
) -> str:
    """Return a retry-stable key for one exact finding decision."""

    payload = json.dumps(
        {
            "decision_type": decision_type,
            "finding_id": finding_id,
            "if_match": if_match,
            "operation": "finding-decision",
            "reason_sha256": hashlib.sha256(reason.encode("utf-8")).hexdigest(),
            "revision_sha": revision_sha,
            "run_id": run_id,
            "tenant_id": settings.tenant_id,
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "cli-" + hashlib.sha256(payload).hexdigest()[:48]


def create_approval(
    settings: ConnectedRunSettings,
    draft: ApprovalDraft,
    *,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Open one pending approval bound to an exact run and identity."""

    request_document = {
        "approval_id": draft.approval_id,
        "repository_id": draft.repository_id,
        "run_id": draft.run_id,
        "finding_id": draft.finding_id,
        "execution_identity_hash": draft.execution_identity_hash,
        "expires_at": draft.expires_at,
    }
    for name in (
        "patch_sha256",
        "validation_result_sha256",
        "manifest_sha256",
        "patch_status_sha256",
    ):
        value = getattr(draft, name)
        if value is not None:
            request_document[name] = value
    key = idempotency_key or _approval_create_idempotency_key(request_document)
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    expected_binding = {
        "approval_id": draft.approval_id,
        "repository_id": draft.repository_id,
        "run_id": draft.run_id,
        "finding_id": draft.finding_id,
        "execution_identity_hash": draft.execution_identity_hash,
        "patch_sha256": draft.patch_sha256,
        "validation_result_sha256": draft.validation_result_sha256,
        "manifest_sha256": draft.manifest_sha256,
        "patch_status_sha256": draft.patch_status_sha256,
    }
    try:
        document = client.mutate(
            "/api/v1/approvals",
            document=request_document,
            token=settings.token,
            idempotency_key=key,
        )
    except ConnectedCliError as error:
        # A committed POST can still produce an ambiguous response at the
        # transport boundary. Re-read the exact approval before surfacing a
        # failure, preserving idempotent operator retries.
        if error.code is not ConnectedCliErrorCode.PROTOCOL_INVALID:
            raise
        document = client.read(
            f"/api/v1/approvals/{draft.approval_id}", token=settings.token
        )
        safe_document = _validated_approval(
            document,
            expected=expected_binding,
            expected_expires_at=draft.expires_at,
        )
    else:
        try:
            safe_document = _validated_approval(
                document,
                expected={**expected_binding, "state": "PENDING", "version": 1},
                expected_expires_at=draft.expires_at,
            )
        except ConnectedCliError as error:
            if error.code is not ConnectedCliErrorCode.PROTOCOL_INVALID:
                raise
            replay_document = client.read(
                f"/api/v1/approvals/{draft.approval_id}", token=settings.token
            )
            safe_document = _validated_approval(
                replay_document,
                expected=expected_binding,
                expected_expires_at=draft.expires_at,
            )
    return ConnectedCollection(
        run_id=draft.run_id, kind=ResultKind.FINDINGS, document=safe_document
    )


def read_approval(
    settings: ConnectedRunSettings,
    approval_id: str,
    *,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read one approval's durable state."""

    if not _identifier(approval_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read(f"/api/v1/approvals/{approval_id}", token=settings.token)
    safe_document = _validated_approval(document, expected={"approval_id": approval_id})
    return ConnectedCollection(
        run_id=approval_id, kind=ResultKind.FINDINGS, document=safe_document
    )


def decide_approval(
    settings: ConnectedRunSettings,
    approval_id: str,
    *,
    approve: bool,
    reason_code: str,
    rationale: str,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Record an approval decision against the observed state precondition."""

    if not _identifier(approval_id) or not _approval_version_precondition(if_match):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if (
        type(approve) is not bool
        or type(reason_code) is not str
        or _REASON_CODE.fullmatch(reason_code) is None
        or type(rationale) is not str
        or not rationale
        or any(ord(character) < 32 and character not in "\t\n" for character in rationale)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if len(rationale) > 1024:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or _approval_decision_idempotency_key(
        settings=settings,
        approval_id=approval_id,
        approve=approve,
        reason_code=reason_code,
        rationale=rationale,
        if_match=if_match,
    )
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    expected_version = _version_from_precondition(if_match)
    expected_state = "APPROVED" if approve else "REJECTED"
    expected_decision = {
        "reason_code": reason_code,
        "rationale_sha256": hashlib.sha256(rationale.encode("utf-8")).hexdigest(),
    }
    try:
        document = client.mutate(
            f"/api/v1/approvals/{approval_id}:decide",
            document={"approve": approve, "reason_code": reason_code, "rationale": rationale},
            token=settings.token,
            idempotency_key=key,
            if_match=if_match,
        )
    except ConnectedCliError as error:
        if error.code not in {
            ConnectedCliErrorCode.PROTOCOL_INVALID,
            ConnectedCliErrorCode.UNREACHABLE,
        }:
            raise
        try:
            replay = client.read(
                f"/api/v1/approvals/{approval_id}", token=settings.token
            )
            safe_document = _validated_approval(
                replay,
                expected={
                    "approval_id": approval_id,
                    "state": expected_state,
                    "version": expected_version + 1,
                },
                expected_decision=expected_decision,
            )
        except ConnectedCliError:
            raise error
        return ConnectedCollection(
            run_id=approval_id, kind=ResultKind.FINDINGS, document=safe_document
        )
    safe_document = _validated_approval(
        document,
        expected={
            "approval_id": approval_id,
            "state": expected_state,
            "version": expected_version + 1,
        },
        expected_decision=expected_decision,
    )
    return ConnectedCollection(
        run_id=approval_id, kind=ResultKind.FINDINGS, document=safe_document
    )


def _version_from_precondition(value: str) -> int:
    if value.startswith('W/"') and value.endswith('"'):
        value = value[3:-1]
    elif value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return int(value)


def _validated_approval(
    document: object,
    *,
    expected: dict[str, object],
    expected_decision: dict[str, object] | None = None,
    expected_expires_at: str | None = None,
) -> dict[str, object]:
    """Whitelist the durable approval projection before it reaches stdout."""

    if not isinstance(document, dict):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    fields = {
        "approval_id",
        "tenant_id",
        "repository_id",
        "run_id",
        "finding_id",
        "execution_identity_hash",
        "patch_sha256",
        "validation_result_sha256",
        "manifest_sha256",
        "patch_status_sha256",
        "state",
        "version",
        "expires_at",
    }
    if not fields.issubset(document) or set(document) - fields - {"decision"}:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if (
        any(
            not _identifier(document.get(name))
            for name in ("approval_id", "tenant_id", "repository_id", "run_id", "finding_id")
        )
        or not _sha256(document.get("execution_identity_hash"))
        or document.get("state") not in _APPROVAL_STATES
        or type(document.get("version")) is not int
        or not 1 <= document["version"] <= _MAX_VERSION
        or not _timestamp(document.get("expires_at"))
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    patch_digests = tuple(
        document.get(name)
        for name in (
            "patch_sha256",
            "validation_result_sha256",
            "manifest_sha256",
            "patch_status_sha256",
        )
    )
    if any(value is not None for value in patch_digests) and (
        any(value is None for value in patch_digests)
        or any(not _sha256(value) for value in patch_digests)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if document["approval_id"].startswith("repair-") and any(
        value is None for value in patch_digests
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if any(document.get(name) != value for name, value in expected.items()):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if expected_expires_at is not None:
        actual_expiry = datetime.fromisoformat(document["expires_at"].replace("Z", "+00:00"))
        expected_expiry = datetime.fromisoformat(expected_expires_at.replace("Z", "+00:00"))
        if actual_expiry != expected_expiry:
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)

    safe_document = {name: document[name] for name in fields}
    decision = document.get("decision")
    has_decision = document["state"] in {"APPROVED", "REJECTED", "REVOKED"}
    if (
        has_decision != (decision is not None)
        or (expected_decision is not None and not has_decision)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if expected_decision is not None or decision is not None:
        if not isinstance(decision, dict) or set(decision) != {
            "actor_id",
            "reason_code",
            "rationale_sha256",
            "created_at",
        }:
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
        if (
            not _identifier(decision.get("actor_id"))
            or type(decision.get("reason_code")) is not str
            or _REASON_CODE.fullmatch(decision["reason_code"]) is None
            or not _sha256(decision.get("rationale_sha256"))
            or not _timestamp(decision.get("created_at"))
            or (
                expected_decision is not None
                and any(decision.get(name) != value for name, value in expected_decision.items())
            )
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
        safe_document["decision"] = {
            name: decision[name]
            for name in ("actor_id", "reason_code", "rationale_sha256", "created_at")
        }
    return safe_document


def parse_approval_arguments(tokens: tuple[str, ...]) -> dict[str, str]:
    """Parse the shared `--flag value` shape used by approval commands."""

    parsed: dict[str, str] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("--") or index + 1 >= len(tokens):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        name = token[2:]
        if not name or name in parsed:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        parsed[name] = tokens[index + 1]
        index += 2
    return parsed


def fetch_finding(
    settings: ConnectedRunSettings,
    finding_id: str,
    *,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read one finding document by its identifier."""

    if not _identifier(finding_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read(f"/api/v1/findings/{finding_id}", token=settings.token)
    return ConnectedCollection(run_id=finding_id, kind=ResultKind.FINDINGS, document=document)


def fetch_policies(
    settings: ConnectedRunSettings,
    *,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read the control plane's effective policy documents."""

    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read("/api/v1/policies", token=settings.token)
    return ConnectedCollection(run_id="policies", kind=ResultKind.FINDINGS, document=document)


def check_health(
    settings: ConnectedRunSettings,
    *,
    live: bool = False,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Check readiness (default) or liveness of the configured control plane."""

    if type(live) is not bool:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    route = "/api/v1/health/live" if live else "/api/v1/health/ready"
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read(route, token=settings.token)
    return ConnectedCollection(run_id="health", kind=ResultKind.FINDINGS, document=document)


def parse_single_argument(tokens: tuple[str, ...]) -> str:
    """Parse exactly one required positional identifier."""

    if len(tokens) != 1 or tokens[0].startswith("-") or not _identifier(tokens[0]):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return tokens[0]


def fetch_events(
    settings: ConnectedRunSettings,
    run_id: str,
    *,
    cursor: str | None = None,
    limit: int | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read one page of a run's event feed, newest cursor supplied by the server."""

    if not _identifier(run_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    query: dict[str, str] = {}
    if cursor is not None:
        if not _cursor(cursor):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        query["cursor"] = cursor
    if limit is not None:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        query["limit"] = str(limit)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read(
        f"/api/v1/runs/{run_id}/events",
        token=settings.token,
        query=query or None,
    )
    page_limit = 50 if limit is None else limit
    if not isinstance(document, Mapping) or set(document) != {"items", "next_cursor"}:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    items = document.get("items")
    next_cursor = document.get("next_cursor")
    if (
        type(items) is not list
        or len(items) > page_limit
        or any(type(item) is not dict for item in items)
        or (next_cursor is not None and not _cursor(next_cursor))
        or (next_cursor is not None and next_cursor == cursor)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return ConnectedCollection(run_id=run_id, kind=ResultKind.EVENTS, document=document)


def _cursor(value: object) -> bool:
    """A server-issued page cursor: bounded, URL-safe, opaque to the CLI."""

    if type(value) is not str or not value.isascii() or not 1 <= len(value) <= 512:
        return False
    return all(character.isalnum() or character in "-_" for character in value)


def parse_event_arguments(tokens: tuple[str, ...]) -> tuple[str, str | None, int | None]:
    """Parse `securecode events <run_id> [--cursor TOKEN] [--limit N]`."""

    run_id: str | None = None
    cursor: str | None = None
    limit: int | None = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in {"--cursor", "--limit"}:
            if index + 1 >= len(tokens):
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            value = tokens[index + 1]
            if token == "--cursor":
                if cursor is not None:
                    raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
                if not _cursor(value):
                    raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
                cursor = value
            else:
                if limit is not None:
                    raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
                if not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= 100:
                    raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
                limit = int(value)
            index += 2
            continue
        if token.startswith("-") or run_id is not None:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        run_id = token
        index += 1
    if run_id is None or not _identifier(run_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return run_id, cursor, limit


def parse_health_arguments(tokens: tuple[str, ...]) -> bool:
    """Parse `securecode health [--live]` and return whether liveness was asked."""

    live = False
    for token in tokens:
        if token == "--live":
            if live:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            live = True
        else:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return live


def decide_finding(
    settings: ConnectedRunSettings,
    finding_id: str,
    *,
    run_id: str,
    revision_sha: str,
    decision_type: str,
    reason: str,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Record one human decision on a finding at an exact revision."""

    if not _identifier(finding_id) or not _identifier(run_id) or not _identifier(decision_type):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if not _commit(revision_sha) or not _precondition(if_match) or not reason:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if len(decision_type) > 64 or len(reason) > 1024:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or _finding_decision_idempotency_key(
        settings=settings,
        finding_id=finding_id,
        run_id=run_id,
        revision_sha=revision_sha,
        decision_type=decision_type,
        reason=reason,
        if_match=if_match,
    )
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        f"/api/v1/findings/{finding_id}/decisions",
        document={
            "run_id": run_id,
            "revision_sha": revision_sha,
            "decision_type": decision_type,
            "reason": reason,
        },
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    return ConnectedCollection(run_id=run_id, kind=ResultKind.FINDINGS, document=document)
