"""Bounded authenticated GitLab REST transport for publication writer ports.

The access token stays private to this transport. It returns external identifiers
or redacted typed errors and reconciles ambiguous mutations through owned remote
markers before a caller retries.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .gitlab_api_responses import (
    bounded_json,
    discussion_id,
    integer_id,
    safe_path,
    status_matches,
)
from .gitlab_ci import GitlabExternalStatus, GitlabExternalStatusProjection
from .gitlab_discussions import GitlabDiscussionProjection
from .scm_diff import (
    MAX_SCM_CHANGED_LINES,
    SCMDiffError,
    parse_unified_diff_changed_lines,
)

MAX_GITLAB_REQUEST_BYTES: Final = 16_384
MAX_GITLAB_RESPONSE_BYTES: Final = 65_536
MAX_GITLAB_JSON_DEPTH: Final = 8
MAX_GITLAB_JSON_ITEMS: Final = 100
MAX_GITLAB_PAGES: Final = 100
DEFAULT_TIMEOUT_SECONDS: Final = 5.0
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CWE_ID: Final = re.compile(r"CWE-[1-9][0-9]{0,5}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_BASE_PATH: Final = re.compile(r"(?:/[A-Za-z0-9._/-]{1,255})?\Z")


class GitlabAPIErrorCode(StrEnum):
    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    INVALID_REQUEST = "INVALID_REQUEST"
    TRANSPORT_FAILED = "TRANSPORT_FAILED"
    RETRYABLE = "RETRYABLE"
    REMOTE_REJECTED = "REMOTE_REJECTED"
    REDIRECT_BLOCKED = "REDIRECT_BLOCKED"
    RESPONSE_INVALID = "RESPONSE_INVALID"
    CONFLICT = "CONFLICT"


class GitlabAPIError(ValueError):
    """Redacted transport failure with no token, URL detail, or remote body."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GitlabAPIErrorCode) -> None:
        if type(code) is not GitlabAPIErrorCode:
            raise TypeError("GitLab API error code is invalid")
        self.code = code
        self.safe_message = "GitLab API request was rejected"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GitlabHTTPRequest:
    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes | None
    timeout_seconds: float


@dataclass(frozen=True, slots=True)
class GitlabHTTPResponse:
    """Transient response body, which cannot enter a durable writer receipt."""

    status_code: int
    url: str
    body: bytes

    def __post_init__(self) -> None:
        if (
            type(self.status_code) is not int
            or not 100 <= self.status_code <= 599
            or type(self.url) is not str
            or type(self.body) is not bytes
        ):
            raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)


GitlabRequester = Callable[[GitlabHTTPRequest], GitlabHTTPResponse]


class GitlabRestAPI:
    """Authenticated REST implementation of the GitlabAuthenticatedAPI port."""

    __slots__ = ("_base_url", "_origin", "_requester", "_timeout_seconds", "_token")

    def __init__(
        self,
        *,
        base_url: str,
        private_token: str,
        requester: object | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if (
            not _valid_base_url(base_url)
            or type(private_token) is not str
            or not private_token
            or len(private_token) > 4096
            or any(ord(character) < 33 or ord(character) > 126 for character in private_token)
            or type(timeout_seconds) not in {int, float}
            or isinstance(timeout_seconds, bool)
            or not 0.1 <= float(timeout_seconds) <= 30.0
            or (requester is not None and not callable(requester))
        ):
            raise GitlabAPIError(GitlabAPIErrorCode.INVALID_CONFIGURATION)
        self._base_url = _canonical_base_url(base_url)
        self._origin = _origin(self._base_url)
        self._token = private_token
        self._timeout_seconds = float(timeout_seconds)
        self._requester = (
            cast(GitlabRequester, requester) if requester is not None else _urllib_request
        )

    def upsert_merge_request_note(
        self,
        *,
        project_id: str,
        merge_request_iid: str,
        idempotency_key: str,
        body: str,
    ) -> str:
        """Update only the note whose first line exactly matches the owned marker."""

        _validate_identifiers(project_id, merge_request_iid, idempotency_key)
        marker = f"<!-- securecode-ai-gitlab-summary:{idempotency_key} -->"
        if not _safe_body(body) or not body.startswith(marker + "\n"):
            raise GitlabAPIError(GitlabAPIErrorCode.INVALID_REQUEST)
        notes = self._list_all(
            self._mr_path(project_id, merge_request_iid, "notes"), idempotency_key
        )
        matches = [
            item
            for item in notes
            if type(item) is dict
            and type(item.get("body")) is str
            and item["body"].split("\n", 1)[0] == marker
        ]
        if len(matches) > 1:
            raise GitlabAPIError(GitlabAPIErrorCode.CONFLICT)
        try:
            if matches:
                note_id = _response_id(matches[0])
                response = self._json_request(
                    "PUT",
                    self._mr_path(project_id, merge_request_iid, f"notes/{note_id}"),
                    {"body": body},
                    idempotency_key,
                    expected_statuses=frozenset({200}),
                )
            else:
                response = self._json_request(
                    "POST",
                    self._mr_path(project_id, merge_request_iid, "notes"),
                    {"body": body},
                    idempotency_key,
                    expected_statuses=frozenset({201}),
                )
        except GitlabAPIError as error:
            reconciled = self._find_note(project_id, merge_request_iid, idempotency_key, body)
            if reconciled is not None:
                return reconciled
            raise error
        return _note_response_id(response, body)

    def merge_request_head(self, *, project_id: str, merge_request_iid: str) -> str:
        """Read the current MR head from the authenticated GitLab authority."""

        _validate_identifiers(project_id, merge_request_iid, "head-read")
        request_key = (
            "head-" + hashlib.sha256(f"{project_id}\x00{merge_request_iid}".encode()).hexdigest()
        )
        response = self._json_request(
            "GET",
            self._mr_path(project_id, merge_request_iid, "").rstrip("/"),
            None,
            request_key,
            expected_statuses=frozenset({200}),
        )
        if type(response) is not dict:
            raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
        diff_refs = response.get("diff_refs")
        sha = response.get("sha")
        if type(diff_refs) is dict and diff_refs.get("head_sha") is not None:
            sha = diff_refs.get("head_sha")
        if type(sha) is not str or re.fullmatch(r"[0-9a-f]{40}", sha) is None:
            raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
        return sha

    def merge_request_diff_refs(
        self, *, project_id: str, merge_request_iid: str
    ) -> tuple[str, str, str]:
        """Return complete GitLab diff refs for a merge request."""

        _validate_identifiers(project_id, merge_request_iid, "diff-refs")
        request_key = (
            "diff-refs-"
            + hashlib.sha256(f"{project_id}\x00{merge_request_iid}".encode()).hexdigest()
        )
        response = self._json_request(
            "GET",
            self._mr_path(project_id, merge_request_iid, "").rstrip("/"),
            None,
            request_key,
            expected_statuses=frozenset({200}),
        )
        if type(response) is not dict or type(response.get("diff_refs")) is not dict:
            raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
        refs = cast(dict[str, object], response["diff_refs"])
        base_sha, start_sha, head_sha = (
            refs.get("base_sha"),
            refs.get("start_sha"),
            refs.get("head_sha"),
        )
        if any(
            type(value) is not str or re.fullmatch(r"[0-9a-f]{40}", value) is None
            for value in (base_sha, start_sha, head_sha)
        ):
            raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
        return cast(str, base_sha), cast(str, start_sha), cast(str, head_sha)

    def compare_commit_lineage(
        self, *, project_id: str, base_sha: str, head_sha: str
    ) -> tuple[str, ...]:
        """Return a verified first-parent chain for an exact straight comparison."""

        response = self._compare_commit_document(
            project_id=project_id,
            base_sha=base_sha,
            head_sha=head_sha,
            operation="lineage",
        )
        return _verified_gitlab_commit_lineage(response, base_sha=base_sha, head_sha=head_sha)

    def compare_commit_changed_lines(
        self, *, project_id: str, base_sha: str, head_sha: str
    ) -> tuple[tuple[str, int], ...]:
        """Return complete changed HEAD locations for an exact straight comparison."""

        return tuple(
            (path, line)
            for path, line, _old_path, _deleted in self.compare_commit_changed_line_paths(
                project_id=project_id,
                base_sha=base_sha,
                head_sha=head_sha,
            )
        )

    def compare_commit_changed_line_paths(
        self, *, project_id: str, base_sha: str, head_sha: str
    ) -> tuple[tuple[str, int, str, bool], ...]:
        """Return verified changed lines with old paths for exact GitLab diff positions."""

        response = self._compare_commit_document(
            project_id=project_id,
            base_sha=base_sha,
            head_sha=head_sha,
            operation="changed-lines",
        )
        _verified_gitlab_commit_lineage(response, base_sha=base_sha, head_sha=head_sha)
        diffs = response.get("diffs")
        if type(diffs) is not list or len(diffs) >= MAX_GITLAB_JSON_ITEMS:
            raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
        if base_sha == head_sha:
            if diffs:
                raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
            return ()
        if not diffs:
            raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
        changed: set[tuple[str, int, str, bool]] = set()
        seen_paths: set[str] = set()
        for item in diffs:
            if type(item) is not dict:
                raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
            new_path = item.get("new_path")
            old_path = item.get("old_path")
            if type(new_path) is not str or type(old_path) is not str:
                raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
            flags = ("new_file", "deleted_file", "renamed_file", "too_large", "collapsed")
            if any(key in item and type(item[key]) is not bool for key in flags):
                raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
            if item.get("too_large") is True or item.get("collapsed") is True:
                raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
            path = (
                old_path
                if new_path == "/dev/null" or item.get("deleted_file") is True
                else new_path
            )
            if path in seen_paths:
                raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
            seen_paths.add(path)
            try:
                parsed = parse_unified_diff_changed_lines(item.get("diff"), expected_path=path)
            except (SCMDiffError, TypeError, ValueError):
                raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID) from None
            deleted = new_path == "/dev/null" or item.get("deleted_file") is True
            changed.update((changed_path, line, old_path, deleted) for changed_path, line in parsed)
            if len(changed) > MAX_SCM_CHANGED_LINES:
                raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
        return tuple(sorted(changed))

    def _compare_commit_document(
        self, *, project_id: str, base_sha: str, head_sha: str, operation: str
    ) -> dict[str, object]:
        _validate_identifiers(project_id, operation + "-read", operation + "-read")
        if any(
            type(value) is not str or re.fullmatch(r"[0-9a-f]{40}", value) is None
            for value in (base_sha, head_sha)
        ):
            raise GitlabAPIError(GitlabAPIErrorCode.INVALID_REQUEST)
        path = (
            f"projects/{_segment(project_id)}/repository/compare?"
            f"from={quote(base_sha, safe='')}&to={quote(head_sha, safe='')}&straight=true"
        )
        response = self._json_request(
            "GET",
            path,
            None,
            operation
            + "-"
            + hashlib.sha256(f"{project_id}\x00{base_sha}\x00{head_sha}".encode()).hexdigest(),
            expected_statuses=frozenset({200}),
        )
        if type(response) is not dict or response.get("compare_timeout") is not False:
            raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
        return response

    def create_merge_request_discussion(
        self,
        *,
        project_id: str,
        merge_request_iid: str,
        idempotency_key: str,
        projection: GitlabDiscussionProjection,
    ) -> str:
        """POST a discussion only at the exact changed-line position."""

        _validate_identifiers(project_id, merge_request_iid, idempotency_key)
        if not _valid_discussion_projection(projection):
            raise GitlabAPIError(GitlabAPIErrorCode.INVALID_REQUEST)
        old_path = projection.old_path or projection.new_path
        if not safe_path(old_path):
            raise GitlabAPIError(GitlabAPIErrorCode.INVALID_REQUEST)
        marker = f"<!-- securecode-ai-gitlab-discussion:{idempotency_key} -->"
        body = marker + "\n" + projection.body
        existing = self._find_discussion(
            project_id, merge_request_iid, idempotency_key, body, projection, old_path
        )
        if existing is not None:
            return existing
        payload = {
            "body": body,
            "position": {
                "base_sha": projection.base_sha,
                "head_sha": projection.head_sha,
                "new_line": projection.new_line,
                "new_path": projection.new_path,
                "old_path": old_path,
                "position_type": "text",
                "start_sha": projection.start_sha,
            },
        }
        try:
            response = self._json_request(
                "POST",
                self._mr_path(project_id, merge_request_iid, "discussions"),
                payload,
                idempotency_key,
                expected_statuses=frozenset({201}),
            )
            identifier = discussion_id(response, body, projection, old_path)
            if identifier is None:
                raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
            return identifier
        except GitlabAPIError as error:
            reconciled = self._find_discussion(
                project_id, merge_request_iid, idempotency_key, body, projection, old_path
            )
            if reconciled is not None:
                return reconciled
            raise error

    def set_external_status(
        self,
        *,
        project_id: str,
        merge_request_iid: str,
        idempotency_key: str,
        projection: GitlabExternalStatusProjection,
    ) -> str:
        """Set the optional external status response for the exact projected SHA."""

        _validate_identifiers(project_id, merge_request_iid, idempotency_key)
        if not _valid_external_status_projection(projection, idempotency_key):
            raise GitlabAPIError(GitlabAPIErrorCode.INVALID_REQUEST)
        state = {
            GitlabExternalStatus.PASSED: "success",
            GitlabExternalStatus.FAILED: "failed",
        }.get(projection.status)
        if state is None:
            raise GitlabAPIError(GitlabAPIErrorCode.INVALID_REQUEST)
        name = f"securecode-ai:{idempotency_key}"
        existing = self._find_status(project_id, idempotency_key, projection, state, name)
        if existing is not None:
            return existing
        try:
            response = self._json_request(
                "POST",
                f"projects/{_segment(project_id)}/statuses/{_segment(projection.head_sha)}",
                {"description": projection.safe_summary, "name": name, "state": state},
                idempotency_key,
                expected_statuses=frozenset({201}),
            )
            return _status_id(response, projection, state, name)
        except GitlabAPIError as error:
            reconciled = self._find_status(project_id, idempotency_key, projection, state, name)
            if reconciled is not None:
                return reconciled
            raise error

    def _list_all(self, path: str, key: str) -> list[object]:
        result: list[object] = []
        for page in range(1, MAX_GITLAB_PAGES + 1):
            separator = "&" if "?" in path else "?"
            value = self._json_request(
                "GET",
                f"{path}{separator}per_page=100&page={page}",
                None,
                key,
                expected_statuses=frozenset({200}),
            )
            if type(value) is not list:
                raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
            result.extend(value)
            if len(value) < MAX_GITLAB_JSON_ITEMS:
                return result
        raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)

    def _find_note(self, project: str, change: str, key: str, body: str) -> str | None:
        marker = body.split("\n", 1)[0]
        notes = self._list_all(self._mr_path(project, change, "notes"), key)
        matches = [item for item in notes if type(item) is dict and item.get("body") == body]
        conflicts = [
            item
            for item in notes
            if type(item) is dict
            and type(item.get("body")) is str
            and item["body"].split("\n", 1)[0] == marker
        ]
        if len(matches) == 1 and len(conflicts) == 1:
            return _response_id(matches[0])
        if conflicts:
            raise GitlabAPIError(GitlabAPIErrorCode.CONFLICT)
        return None

    def _find_discussion(
        self,
        project: str,
        change: str,
        key: str,
        body: str,
        projection: GitlabDiscussionProjection,
        old_path: str,
    ) -> str | None:
        marker = body.split("\n", 1)[0]
        matches: list[str] = []
        conflicts = False
        for item in self._list_all(self._mr_path(project, change, "discussions"), key):
            if type(item) is not dict or type(item.get("notes")) is not list:
                continue
            owned = [
                note
                for note in item["notes"]
                if type(note) is dict
                and type(note.get("body")) is str
                and note["body"].split("\n", 1)[0] == marker
            ]
            if owned:
                try:
                    identifier = discussion_id(item, body, projection, old_path)
                    if identifier is None:
                        raise ValueError
                    matches.append(identifier)
                except ValueError:
                    conflicts = True
        if conflicts or len(matches) > 1:
            raise GitlabAPIError(GitlabAPIErrorCode.CONFLICT)
        return matches[0] if matches else None

    def _find_status(
        self,
        project: str,
        key: str,
        projection: GitlabExternalStatusProjection,
        state: str,
        name: str,
    ) -> str | None:
        path = (
            f"projects/{_segment(project)}/repository/commits/"
            f"{_segment(projection.head_sha)}/statuses?all=true&name={_segment(name)}"
        )
        statuses = self._list_all(path, key)
        owned = [
            item
            for item in statuses
            if type(item) is dict
            and item.get("sha") == projection.head_sha
            and item.get("name") == name
        ]
        matches = [item for item in owned if status_matches(item, projection, state, name)]
        if len(owned) != len(matches):
            raise GitlabAPIError(GitlabAPIErrorCode.CONFLICT)
        if not matches:
            return None
        return _response_id(matches[-1])

    def _mr_path(self, project_id: str, merge_request_iid: str, suffix: str) -> str:
        return (
            f"projects/{_segment(project_id)}/merge_requests/{_segment(merge_request_iid)}/{suffix}"
        )

    def _json_request(
        self,
        method: str,
        relative_path: str,
        payload: Mapping[str, object] | None,
        idempotency_key: str,
        *,
        expected_statuses: frozenset[int],
    ) -> object:
        if type(relative_path) is not str or not relative_path or relative_path.startswith("/"):
            raise GitlabAPIError(GitlabAPIErrorCode.INVALID_REQUEST)
        body = _json_body(payload) if payload is not None else None
        response = self._send(
            GitlabHTTPRequest(
                method=method,
                url=f"{self._base_url}/{relative_path}",
                headers=(
                    ("Accept", "application/json"),
                    ("Content-Type", "application/json"),
                    ("Idempotency-Key", idempotency_key),
                    ("PRIVATE-TOKEN", self._token),
                ),
                body=body,
                timeout_seconds=self._timeout_seconds,
            )
        )
        if 300 <= response.status_code < 400 or not _same_origin(response.url, self._origin):
            raise GitlabAPIError(GitlabAPIErrorCode.REDIRECT_BLOCKED)
        if response.status_code == 429 or 500 <= response.status_code <= 599:
            raise GitlabAPIError(GitlabAPIErrorCode.RETRYABLE)
        if response.status_code not in expected_statuses:
            raise GitlabAPIError(GitlabAPIErrorCode.REMOTE_REJECTED)
        try:
            return bounded_json(response.body)
        except ValueError:
            raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID) from None

    def _send(self, request: GitlabHTTPRequest) -> GitlabHTTPResponse:
        try:
            response = self._requester(request)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise GitlabAPIError(GitlabAPIErrorCode.TRANSPORT_FAILED) from None
        if (
            type(response) is not GitlabHTTPResponse
            or len(response.body) > MAX_GITLAB_RESPONSE_BYTES
        ):
            raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
        return response


def _valid_base_url(value: object) -> bool:
    if type(value) is not str or len(value) > 512 or not value.isascii():
        return False
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or _SAFE_BASE_PATH.fullmatch(parsed.path.rstrip("/")) is None
    ):
        return False
    hostname = parsed.hostname
    return hostname is not None and (parsed.scheme == "https" or _is_loopback(hostname))


def _canonical_base_url(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _origin(value: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(value)
    if parsed.hostname is None:
        raise GitlabAPIError(GitlabAPIErrorCode.INVALID_CONFIGURATION)
    try:
        port = parsed.port
    except ValueError:
        raise GitlabAPIError(GitlabAPIErrorCode.INVALID_CONFIGURATION) from None
    return parsed.scheme, parsed.hostname.lower(), port


def _same_origin(value: object, origin: tuple[str, str, int | None]) -> bool:
    if type(value) is not str:
        return False
    try:
        return _origin(value) == origin
    except GitlabAPIError:
        return False


def _is_loopback(hostname: str) -> bool:
    return hostname.lower() == "localhost" or hostname in {"127.0.0.1", "::1"}


def _segment(value: str) -> str:
    return quote(value, safe="")


def _validate_identifiers(
    project_id: object, merge_request_iid: object, idempotency_key: object
) -> None:
    if any(
        type(value) is not str or _ID.fullmatch(value) is None
        for value in (project_id, merge_request_iid, idempotency_key)
    ):
        raise GitlabAPIError(GitlabAPIErrorCode.INVALID_REQUEST)


def _safe_body(value: object) -> bool:
    if type(value) is not str or not value:
        return False
    try:
        size = len(value.encode("ascii", "strict"))
    except UnicodeEncodeError:
        return False
    return size <= MAX_GITLAB_REQUEST_BYTES and all(
        character == "\n" or 32 <= ord(character) <= 126 for character in value
    )


def _valid_discussion_projection(value: object) -> bool:
    if type(value) is not GitlabDiscussionProjection:
        return False
    projection = value
    return (
        type(projection.finding_id) is str
        and _ID.fullmatch(projection.finding_id) is not None
        and type(projection.cwe_id) is str
        and _CWE_ID.fullmatch(projection.cwe_id) is not None
        and type(projection.new_path) is str
        and safe_path(projection.new_path)
        and (
            projection.old_path is None
            or (type(projection.old_path) is str and safe_path(projection.old_path))
        )
        and type(projection.new_line) is int
        and not isinstance(projection.new_line, bool)
        and projection.new_line >= 1
        and all(
            type(sha) is str and _COMMIT_SHA.fullmatch(sha) is not None
            for sha in (projection.base_sha, projection.start_sha, projection.head_sha)
        )
        and projection.base_sha != projection.head_sha
        and type(projection.merge_authority) is bool
        and not projection.merge_authority
        and _safe_body(projection.body)
    )


def _valid_external_status_projection(value: object, idempotency_key: str) -> bool:
    if type(value) is not GitlabExternalStatusProjection:
        return False
    projection = value
    return (
        type(projection.idempotency_key) is str
        and projection.idempotency_key == idempotency_key
        and _ID.fullmatch(projection.idempotency_key) is not None
        and type(projection.execution_identity_hash) is str
        and _SHA256.fullmatch(projection.execution_identity_hash) is not None
        and type(projection.head_sha) is str
        and _COMMIT_SHA.fullmatch(projection.head_sha) is not None
        and type(projection.status) is GitlabExternalStatus
        and type(projection.publish) is bool
        and projection.publish
        and type(projection.merge_authority) is bool
        and _safe_body(projection.safe_summary)
    )


def _json_body(payload: Mapping[str, object]) -> bytes:
    try:
        body = json.dumps(
            payload, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    except (TypeError, ValueError):
        raise GitlabAPIError(GitlabAPIErrorCode.INVALID_REQUEST) from None
    if len(body) > MAX_GITLAB_REQUEST_BYTES:
        raise GitlabAPIError(GitlabAPIErrorCode.INVALID_REQUEST)
    return body


def _response_id(value: object) -> str:
    if type(value) is not dict:
        raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
    identifier = integer_id(value)
    if identifier is None:
        raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
    return identifier


def _note_response_id(value: object, expected_body: str) -> str:
    if type(value) is not dict or value.get("body") != expected_body:
        raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
    return _response_id(value)


def _verified_gitlab_commit_lineage(
    response: dict[str, object], *, base_sha: str, head_sha: str
) -> tuple[str, ...]:
    commits = response.get("commits")
    latest = response.get("commit")
    if type(commits) is not list or len(commits) > 250 or type(latest) is not dict:
        raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
    if base_sha == head_sha:
        if commits or latest.get("id") != head_sha:
            raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
        return (base_sha,)
    lineage = [base_sha]
    for item in commits:
        if type(item) is not dict:
            raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
        commit_sha = item.get("id")
        parents = item.get("parent_ids")
        if (
            type(commit_sha) is not str
            or re.fullmatch(r"[0-9a-f]{40}", commit_sha) is None
            or type(parents) is not list
            or not parents
            or parents[0] != lineage[-1]
            or commit_sha in lineage
        ):
            raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
        lineage.append(commit_sha)
    if lineage[-1] != head_sha or latest.get("id") != head_sha:
        raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
    return tuple(lineage)


def _status_id(
    value: object, projection: GitlabExternalStatusProjection, state: str, name: str
) -> str:
    if not status_matches(value, projection, state, name):
        raise GitlabAPIError(GitlabAPIErrorCode.RESPONSE_INVALID)
    return _response_id(value)


def _urllib_request(request: GitlabHTTPRequest) -> GitlabHTTPResponse:
    native = Request(
        request.url, data=request.body, headers=dict(request.headers), method=request.method
    )
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(native, timeout=request.timeout_seconds) as response:
            return GitlabHTTPResponse(
                response.status, response.geturl(), response.read(MAX_GITLAB_RESPONSE_BYTES + 1)
            )
    except HTTPError as error:
        return GitlabHTTPResponse(
            error.code, error.geturl(), error.read(MAX_GITLAB_RESPONSE_BYTES + 1)
        )
    except URLError:
        raise GitlabAPIError(GitlabAPIErrorCode.TRANSPORT_FAILED) from None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, request: Request, fp: object, code: int, msg: str, headers: object, newurl: str
    ) -> None:
        return None


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_GITLAB_JSON_DEPTH",
    "MAX_GITLAB_JSON_ITEMS",
    "MAX_GITLAB_REQUEST_BYTES",
    "MAX_GITLAB_RESPONSE_BYTES",
    "GitlabAPIError",
    "GitlabAPIErrorCode",
    "GitlabHTTPRequest",
    "GitlabHTTPResponse",
    "GitlabRequester",
    "GitlabRestAPI",
]
