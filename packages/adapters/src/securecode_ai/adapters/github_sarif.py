"""Opt-in, exact-head GitHub Code Scanning SARIF transport.

The publisher accepts only the committed SARIF projection produced for one
durable run.  It never writes checks, comments, merge state, or policy
outcomes.  A local receipt prevents duplicate submissions after GitHub
returns an upload id; processing remains pending until GitHub reports
completion.  A crash between the remote response and receipt save remains an
at-least-once boundary because GitHub does not provide an exactly-once
contract for this endpoint.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import re
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final, Protocol

from .github_api import GitHubApi, GitHubError

_MAX_SARIF_BYTES: Final = 700_000
_MAX_JSON_DEPTH: Final = 12
_MAX_JSON_ITEMS: Final = 100_000
_MAX_TEXT_BYTES: Final = 4_096
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TENANT: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_PR_NUMBER: Final = re.compile(r"[1-9][0-9]{0,9}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_UPLOAD_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/github-sarif/v1\x00"
_SARIF_VERSION: Final = "2.1.0"


class GithubSarifErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    CAPABILITY_REQUIRED = "CAPABILITY_REQUIRED"
    UNSUPPORTED_REF = "UNSUPPORTED_REF"
    SARIF_INVALID = "SARIF_INVALID"
    HEAD_UNAVAILABLE = "HEAD_UNAVAILABLE"
    REMOTE_REJECTED = "REMOTE_REJECTED"
    RECEIPT_UNAVAILABLE = "RECEIPT_UNAVAILABLE"
    RECEIPT_CONFLICT = "RECEIPT_CONFLICT"
    UPLOAD_UNCERTAIN = "UPLOAD_UNCERTAIN"


class GithubSarifError(RuntimeError):
    """Redacted SARIF transport failure."""

    def __init__(self, code: GithubSarifErrorCode, *, retryable: bool = False) -> None:
        if type(code) is not GithubSarifErrorCode or type(retryable) is not bool:
            raise TypeError("GitHub SARIF error is invalid")
        self.code = code
        self.retryable = retryable
        super().__init__("GitHub SARIF publication was rejected")
        self.__cause__ = None
        self.__context__ = None


class GithubSarifStatus(StrEnum):
    WRITTEN = "WRITTEN"
    IDEMPOTENT = "IDEMPOTENT"
    PENDING = "PENDING"
    STALE_SUPPRESSED = "STALE_SUPPRESSED"


@dataclass(frozen=True, slots=True)
class GithubSarifReceipt:
    """Metadata-only result of one SARIF submission."""

    status: GithubSarifStatus
    upload_idempotency_key: str
    attempt_count: int
    observed_head_sha: str
    remote_upload_id: str | None = None
    merge_authority: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.status) is not GithubSarifStatus
            or _ID.fullmatch(self.upload_idempotency_key) is None
            or type(self.attempt_count) is not int
            or not 1 <= self.attempt_count <= 2_147_483_647
            or _COMMIT_SHA.fullmatch(self.observed_head_sha) is None
            or (
                self.remote_upload_id is not None
                and _UPLOAD_ID.fullmatch(self.remote_upload_id) is None
            )
            or self.merge_authority is not False
        ):
            raise GithubSarifError(GithubSarifErrorCode.RECEIPT_CONFLICT)


class GithubPullRequestHeadReader(Protocol):
    def __call__(self, installation_id: str, repository_id: str, change_id: str) -> str: ...


class GithubSarifPublisher:
    """Submit one committed SARIF report for a numeric GitHub pull request."""

    __slots__ = ("_api", "_connection", "_head", "_lock")

    def __init__(
        self,
        api: GitHubApi,
        *,
        pull_request_head: GithubPullRequestHeadReader,
        connection: sqlite3.Connection,
        permissions: Mapping[str, str],
    ) -> None:
        if (
            not isinstance(api, GitHubApi)
            or not callable(pull_request_head)
            or not isinstance(connection, sqlite3.Connection)
            or type(permissions) is not dict
            or permissions.get("security_events") != "write"
        ):
            raise GithubSarifError(GithubSarifErrorCode.CAPABILITY_REQUIRED)
        self._api = api
        self._head = pull_request_head
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        self._lock = RLock()
        try:
            with self._receipt_savepoint() as cursor:
                cursor.execute(
                    """CREATE TABLE IF NOT EXISTS github_sarif_uploads (
                    upload_key TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    execution_identity_hash TEXT NOT NULL,
                    installation_id TEXT NOT NULL,
                    repository_id TEXT NOT NULL,
                    change_id TEXT NOT NULL,
                    expected_head TEXT NOT NULL,
                    ref TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('IN_FLIGHT', 'PENDING', 'SUBMITTED')),
                    remote_upload_id TEXT
                    )"""
                )
        except sqlite3.Error:
            raise GithubSarifError(GithubSarifErrorCode.RECEIPT_UNAVAILABLE) from None

    def publish(
        self,
        *,
        tenant_id: str,
        run_id: str,
        execution_identity_hash: str,
        installation_id: str,
        repository_id: str,
        change_id: str,
        expected_head: str,
        artifact_sha256: str,
        content: bytes,
        delivery_key: str,
    ) -> GithubSarifReceipt:
        """Upload SARIF only while the bound pull request still has exact HEAD."""

        _validate_request(
            tenant_id=tenant_id,
            run_id=run_id,
            execution_identity_hash=execution_identity_hash,
            installation_id=installation_id,
            repository_id=repository_id,
            change_id=change_id,
            expected_head=expected_head,
            artifact_sha256=artifact_sha256,
            content=content,
            delivery_key=delivery_key,
        )
        ref = _pull_request_ref(change_id)
        _validate_sarif(content, run_id, execution_identity_hash)
        payload, payload_sha256 = _payload(content, expected_head, ref)
        upload_key = _upload_key(
            tenant_id,
            run_id,
            execution_identity_hash,
            installation_id,
            repository_id,
            change_id,
            expected_head,
            artifact_sha256,
        )
        with self._lock:
            observed = self._head_or_error(installation_id, repository_id, change_id)
            if observed != expected_head:
                return _stale_receipt(upload_key, observed, self._existing_attempt(upload_key))
            try:
                repository = self._api.repository_path_for_id(installation_id, repository_id)
            except (KeyboardInterrupt, SystemExit, GeneratorExit):
                raise
            except GitHubError as error:
                raise GithubSarifError(
                    GithubSarifErrorCode.REMOTE_REJECTED,
                    retryable=error.retryable,
                ) from None
            except Exception:
                raise GithubSarifError(
                    GithubSarifErrorCode.REMOTE_REJECTED,
                    retryable=True,
                ) from None
            observed = self._head_or_error(installation_id, repository_id, change_id)
            if observed != expected_head:
                return _stale_receipt(upload_key, observed, self._existing_attempt(upload_key))
            row = self._load(upload_key)
            idempotency_key = delivery_key + ":sarif"
            attempt_count = 1
            if row is not None:
                _check_row(
                    row,
                    tenant_id=tenant_id,
                    run_id=run_id,
                    execution_identity_hash=execution_identity_hash,
                    installation_id=installation_id,
                    repository_id=repository_id,
                    change_id=change_id,
                    expected_head=expected_head,
                    ref=ref,
                    artifact_sha256=artifact_sha256,
                    payload_sha256=payload_sha256,
                )
                attempt_count = int(row["attempt_count"])
                stored_idempotency_key = row["idempotency_key"]
                if type(stored_idempotency_key) is not str or _ID.fullmatch(
                    stored_idempotency_key
                ) is None:
                    raise GithubSarifError(GithubSarifErrorCode.RECEIPT_CONFLICT)
                idempotency_key = stored_idempotency_key
                if row["status"] == "SUBMITTED":
                    remote_id = _required_upload_id(row["remote_upload_id"])
                    observed = self._head_or_error(installation_id, repository_id, change_id)
                    if observed != expected_head:
                        return GithubSarifReceipt(
                            GithubSarifStatus.STALE_SUPPRESSED,
                            upload_key,
                            attempt_count,
                            observed,
                            remote_id,
                        )
                    return GithubSarifReceipt(
                        GithubSarifStatus.IDEMPOTENT,
                        upload_key,
                        attempt_count,
                        observed,
                        remote_id,
                    )
                if row["status"] == "PENDING":
                    remote_id = _required_upload_id(row["remote_upload_id"])
                    processing_status = self._processing_status(
                        repository,
                        installation_id,
                        remote_id,
                    )
                    observed = self._head_or_error(installation_id, repository_id, change_id)
                    if observed != expected_head:
                        return GithubSarifReceipt(
                            GithubSarifStatus.STALE_SUPPRESSED,
                            upload_key,
                            attempt_count,
                            observed,
                            remote_id,
                        )
                    if processing_status == "complete":
                        self._mark_submitted(upload_key, remote_id)
                        return GithubSarifReceipt(
                            GithubSarifStatus.IDEMPOTENT,
                            upload_key,
                            attempt_count,
                            observed,
                            remote_id,
                        )
                    return GithubSarifReceipt(
                        GithubSarifStatus.PENDING,
                        upload_key,
                        attempt_count,
                        observed,
                        remote_id,
                    )
                attempt_count += 1
                idempotency_key = str(row["idempotency_key"])
            self._mark_in_flight(
                upload_key=upload_key,
                tenant_id=tenant_id,
                run_id=run_id,
                execution_identity_hash=execution_identity_hash,
                installation_id=installation_id,
                repository_id=repository_id,
                change_id=change_id,
                expected_head=expected_head,
                ref=ref,
                artifact_sha256=artifact_sha256,
                payload_sha256=payload_sha256,
                idempotency_key=idempotency_key,
                attempt_count=attempt_count,
            )
            try:
                response = self._api.request(
                    "POST",
                    repository + "/code-scanning/sarifs",
                    installation_id=installation_id,
                    document={
                        "commit_sha": expected_head,
                        "ref": ref,
                        "sarif": payload,
                    },
                    idempotency_key=idempotency_key,
                )
            except (KeyboardInterrupt, SystemExit, GeneratorExit):
                raise
            except GitHubError as error:
                raise GithubSarifError(
                    GithubSarifErrorCode.REMOTE_REJECTED,
                    retryable=error.retryable,
                ) from None
            except Exception:
                raise GithubSarifError(
                    GithubSarifErrorCode.UPLOAD_UNCERTAIN,
                    retryable=True,
                ) from None
            if response.status != 202 or type(response.document) is not dict:
                raise GithubSarifError(GithubSarifErrorCode.REMOTE_REJECTED)
            remote_id = _required_upload_id(_response_upload_id(response.document))
            self._mark_pending(upload_key, remote_id)
            processing_status = self._processing_status(
                repository,
                installation_id,
                remote_id,
            )
            if processing_status == "complete":
                self._mark_submitted(upload_key, remote_id)
            observed = self._head_or_error(installation_id, repository_id, change_id)
            if observed != expected_head:
                return GithubSarifReceipt(
                    GithubSarifStatus.STALE_SUPPRESSED,
                    upload_key,
                    attempt_count,
                    observed,
                    remote_id,
                )
            return GithubSarifReceipt(
                GithubSarifStatus.WRITTEN
                if processing_status == "complete"
                else GithubSarifStatus.PENDING,
                upload_key,
                attempt_count,
                observed,
                remote_id,
            )

    def _head_or_error(self, installation_id: str, repository_id: str, change_id: str) -> str:
        try:
            value = self._head(installation_id, repository_id, change_id)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise GithubSarifError(
                GithubSarifErrorCode.HEAD_UNAVAILABLE,
                retryable=True,
            ) from None
        if type(value) is not str or _COMMIT_SHA.fullmatch(value) is None:
            raise GithubSarifError(GithubSarifErrorCode.HEAD_UNAVAILABLE, retryable=True)
        return value

    def _processing_status(
        self,
        repository: str,
        installation_id: str,
        remote_id: str,
    ) -> str:
        try:
            response = self._api.request(
                "GET",
                repository + "/code-scanning/sarifs/" + remote_id,
                installation_id=installation_id,
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except GitHubError as error:
            raise GithubSarifError(
                GithubSarifErrorCode.REMOTE_REJECTED,
                retryable=error.retryable,
            ) from None
        except Exception:
            raise GithubSarifError(
                GithubSarifErrorCode.REMOTE_REJECTED,
                retryable=True,
            ) from None
        document = response.document
        processing_status = document.get("processing_status") if type(document) is dict else None
        if response.status != 200 or processing_status not in {
            "pending",
            "processing",
            "complete",
            "failed",
        }:
            raise GithubSarifError(GithubSarifErrorCode.REMOTE_REJECTED)
        if processing_status == "failed":
            raise GithubSarifError(GithubSarifErrorCode.REMOTE_REJECTED)
        return processing_status

    def _load(self, upload_key: str) -> sqlite3.Row | None:
        try:
            return self._connection.execute(
                "SELECT * FROM github_sarif_uploads WHERE upload_key=?",
                (upload_key,),
            ).fetchone()
        except sqlite3.Error:
            raise GithubSarifError(GithubSarifErrorCode.RECEIPT_UNAVAILABLE) from None

    def _existing_attempt(self, upload_key: str) -> int:
        row = self._load(upload_key)
        if row is None:
            return 1
        value = row["attempt_count"]
        return value if type(value) is int and value > 0 else 1

    @contextmanager
    def _receipt_savepoint(self) -> Iterator[sqlite3.Cursor]:
        cursor = self._connection.cursor()
        savepoint = "securecode_github_sarif_receipt"
        try:
            cursor.execute("SAVEPOINT " + savepoint)
            yield cursor
            cursor.execute("RELEASE SAVEPOINT " + savepoint)
        except BaseException:
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT " + savepoint)
            except sqlite3.Error:
                pass
            try:
                cursor.execute("RELEASE SAVEPOINT " + savepoint)
            except sqlite3.Error:
                pass
            raise
        finally:
            cursor.close()

    def _mark_in_flight(self, **values: object) -> None:
        try:
            with self._receipt_savepoint() as cursor:
                cursor.execute(
                    """INSERT INTO github_sarif_uploads (
                    upload_key, tenant_id, run_id, execution_identity_hash,
                    installation_id, repository_id, change_id, expected_head,
                    ref, artifact_sha256, payload_sha256, idempotency_key,
                    attempt_count, status, remote_upload_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'IN_FLIGHT', NULL)
                ON CONFLICT(upload_key) DO UPDATE SET
                    attempt_count=excluded.attempt_count,
                    status='IN_FLIGHT'
                    WHERE github_sarif_uploads.status='IN_FLIGHT'
                    """,
                    (
                        values["upload_key"],
                        values["tenant_id"],
                        values["run_id"],
                        values["execution_identity_hash"],
                        values["installation_id"],
                        values["repository_id"],
                        values["change_id"],
                        values["expected_head"],
                        values["ref"],
                        values["artifact_sha256"],
                        values["payload_sha256"],
                        values["idempotency_key"],
                        values["attempt_count"],
                    )
                )
                if cursor.rowcount != 1:
                    raise GithubSarifError(GithubSarifErrorCode.RECEIPT_CONFLICT)
        except GithubSarifError:
            raise
        except sqlite3.Error:
            raise GithubSarifError(GithubSarifErrorCode.RECEIPT_UNAVAILABLE) from None

    def _mark_pending(self, upload_key: str, remote_id: str) -> None:
        try:
            with self._receipt_savepoint() as cursor:
                cursor.execute(
                    """UPDATE github_sarif_uploads
                       SET status='PENDING', remote_upload_id=?
                       WHERE upload_key=? AND status='IN_FLIGHT'""",
                    (remote_id, upload_key),
                )
                if cursor.rowcount != 1:
                    raise GithubSarifError(GithubSarifErrorCode.RECEIPT_CONFLICT)
        except GithubSarifError:
            raise
        except sqlite3.Error:
            raise GithubSarifError(GithubSarifErrorCode.RECEIPT_UNAVAILABLE) from None

    def _mark_submitted(self, upload_key: str, remote_id: str) -> None:
        try:
            with self._receipt_savepoint() as cursor:
                cursor.execute(
                    """UPDATE github_sarif_uploads
                       SET status='SUBMITTED', remote_upload_id=?
                       WHERE upload_key=? AND status IN ('IN_FLIGHT', 'PENDING')""",
                    (remote_id, upload_key),
                )
                if cursor.rowcount != 1:
                    raise GithubSarifError(GithubSarifErrorCode.RECEIPT_CONFLICT)
        except GithubSarifError:
            raise
        except sqlite3.Error:
            raise GithubSarifError(GithubSarifErrorCode.RECEIPT_UNAVAILABLE) from None


def _validate_request(**values: object) -> None:
    if (
        type(values["tenant_id"]) is not str
        or _TENANT.fullmatch(values["tenant_id"]) is None
        or type(values["run_id"]) is not str
        or _ID.fullmatch(values["run_id"]) is None
        or type(values["execution_identity_hash"]) is not str
        or _SHA256.fullmatch(values["execution_identity_hash"]) is None
        or type(values["installation_id"]) is not str
        or _ID.fullmatch(values["installation_id"]) is None
        or type(values["repository_id"]) is not str
        or not re.fullmatch(r"[1-9][0-9]{0,19}", values["repository_id"])
        or type(values["change_id"]) is not str
        or _PR_NUMBER.fullmatch(values["change_id"]) is None
        or type(values["expected_head"]) is not str
        or _COMMIT_SHA.fullmatch(values["expected_head"]) is None
        or type(values["artifact_sha256"]) is not str
        or _SHA256.fullmatch(values["artifact_sha256"]) is None
        or type(values["content"]) is not bytes
        or not 1 <= len(values["content"]) <= _MAX_SARIF_BYTES
        or hashlib.sha256(values["content"]).hexdigest() != values["artifact_sha256"]
        or type(values["delivery_key"]) is not str
        or _ID.fullmatch(values["delivery_key"]) is None
    ):
        raise GithubSarifError(GithubSarifErrorCode.INVALID_REQUEST)


def _pull_request_ref(change_id: str) -> str:
    if _PR_NUMBER.fullmatch(change_id) is None:
        raise GithubSarifError(GithubSarifErrorCode.UNSUPPORTED_REF)
    return "refs/pull/" + change_id + "/head"


def _payload(content: bytes, expected_head: str, ref: str) -> tuple[str, str]:
    compressed = gzip.compress(content, compresslevel=9, mtime=0)
    encoded = base64.b64encode(compressed).decode("ascii")
    body = json.dumps(
        {"commit_sha": expected_head, "ref": ref, "sarif": encoded},
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if len(body) > 1_048_576:
        raise GithubSarifError(GithubSarifErrorCode.SARIF_INVALID)
    return encoded, hashlib.sha256(body).hexdigest()


def _validate_sarif(content: bytes, run_id: str, identity_hash: str) -> None:
    try:
        document = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise GithubSarifError(GithubSarifErrorCode.SARIF_INVALID) from None
    if type(document) is not dict or document.get("version") != _SARIF_VERSION:
        raise GithubSarifError(GithubSarifErrorCode.SARIF_INVALID)
    runs = document.get("runs")
    if type(runs) is not list or len(runs) != 1 or type(runs[0]) is not dict:
        raise GithubSarifError(GithubSarifErrorCode.SARIF_INVALID)
    run = runs[0]
    automation = run.get("automationDetails")
    properties = run.get("properties")
    if (
        type(automation) is not dict
        or automation.get("id") != run_id
        or type(properties) is not dict
        or properties.get("executionIdentityHash") != identity_hash
        or type(run.get("results")) is not list
    ):
        raise GithubSarifError(GithubSarifErrorCode.SARIF_INVALID)
    try:
        too_large = _json_depth(document) > _MAX_JSON_DEPTH or _json_items(document) > _MAX_JSON_ITEMS
    except RecursionError:
        raise GithubSarifError(GithubSarifErrorCode.SARIF_INVALID) from None
    if too_large:
        raise GithubSarifError(GithubSarifErrorCode.SARIF_INVALID)
    if _contains_forbidden_source_fields(document):
        raise GithubSarifError(GithubSarifErrorCode.SARIF_INVALID)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate SARIF key")
        result[key] = value
    return result


def _json_depth(value: object, depth: int = 0) -> int:
    if type(value) is dict:
        return max(((_json_depth(item, depth + 1) for item in value.values())), default=depth)
    if type(value) is list:
        return max(((_json_depth(item, depth + 1) for item in value)), default=depth)
    return depth


def _json_items(value: object) -> int:
    if type(value) is dict:
        return len(value) + sum(_json_items(item) for item in value.values())
    if type(value) is list:
        return len(value) + sum(_json_items(item) for item in value)
    if type(value) is str:
        return len(value.encode("utf-8")) // _MAX_TEXT_BYTES + 1
    return 1


def _contains_forbidden_source_fields(value: object) -> bool:
    if type(value) is dict:
        if any(key in {"snippet", "sourceContent", "source_content"} for key in value):
            return True
        return any(_contains_forbidden_source_fields(item) for item in value.values())
    if type(value) is list:
        return any(_contains_forbidden_source_fields(item) for item in value)
    return False


def _upload_key(*values: str) -> str:
    encoded = json.dumps(values, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return "github-sarif-" + hashlib.sha256(_HASH_DOMAIN + encoded).hexdigest()[:40]


def _optional_upload_id(value: object) -> str | None:
    if value is None:
        return None
    return value if type(value) is str and _UPLOAD_ID.fullmatch(value) else None


def _required_upload_id(value: object) -> str:
    if type(value) is not str or _UPLOAD_ID.fullmatch(value) is None:
        raise GithubSarifError(GithubSarifErrorCode.REMOTE_REJECTED)
    return value


def _response_upload_id(document: dict[str, object] | None) -> str | None:
    if document is None:
        return None
    identities: list[str] = []
    for name in ("id", "upload_uuid"):
        if name not in document:
            continue
        value = document[name]
        if value is None:
            raise GithubSarifError(GithubSarifErrorCode.REMOTE_REJECTED)
        upload_id = _optional_upload_id(value)
        if upload_id is None:
            raise GithubSarifError(GithubSarifErrorCode.REMOTE_REJECTED)
        identities.append(upload_id)
    if len(set(identities)) > 1:
        raise GithubSarifError(GithubSarifErrorCode.REMOTE_REJECTED)
    return identities[0] if identities else None


def _check_row(row: sqlite3.Row, **expected: str) -> None:
    for name, value in expected.items():
        if row[name] != value:
            raise GithubSarifError(GithubSarifErrorCode.RECEIPT_CONFLICT)
    if row["status"] not in {"IN_FLIGHT", "PENDING", "SUBMITTED"}:
        raise GithubSarifError(GithubSarifErrorCode.RECEIPT_CONFLICT)
    if type(row["attempt_count"]) is not int or row["attempt_count"] < 1:
        raise GithubSarifError(GithubSarifErrorCode.RECEIPT_CONFLICT)


def _stale_receipt(upload_key: str, observed: str, attempt_count: int) -> GithubSarifReceipt:
    return GithubSarifReceipt(
        GithubSarifStatus.STALE_SUPPRESSED,
        upload_key,
        max(1, attempt_count),
        observed,
    )


__all__ = [
    "GithubPullRequestHeadReader",
    "GithubSarifError",
    "GithubSarifErrorCode",
    "GithubSarifPublisher",
    "GithubSarifReceipt",
    "GithubSarifStatus",
]
