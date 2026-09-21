"""Fail-closed reference GitHub App webhook admission.

This module intentionally has no HTTP client, credential lookup, repository
checkout, or SCM write capability.  Its caller supplies the exact raw webhook
body and an injected authenticated current-HEAD reader.
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final, Protocol, TypeGuard, cast

from securecode_ai.contracts import AuditRunOutcome, RunExecutionIdentity
from securecode_ai.core.scm_run_state import (
    AdmissionDisposition,
    SCMRunAdmissionReceipt,
    SCMRunAdmissionRequest,
    SCMRunPublicationReceipt,
    SCMRunStateError,
    SCMRunStateErrorCode,
)

MAX_WEBHOOK_BYTES: Final = 16_777_216
MAX_JSON_DEPTH: Final = 8
MAX_JSON_ITEMS: Final = 32
MAX_JSON_SCALAR_BYTES: Final = 2_048
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_SIGNATURE: Final = re.compile(r"sha256=[0-9a-f]{64}\Z")
_PULL_REQUEST_ACTIONS: Final = frozenset({"opened", "reopened", "synchronize"})

GITHUB_APP_REQUIRED_PERMISSIONS: Final = {
    "metadata": "read",
    "pull_requests": "write",
    "issues": "write",
    "checks": "write",
    "contents": "none",
}
GITHUB_APP_OPTIONAL_PERMISSIONS: Final = {"security_events": "write"}


class GithubAppErrorCode(StrEnum):
    """Bounded public reasons for refusing a GitHub delivery."""

    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    DELIVERY_INVALID = "DELIVERY_INVALID"
    PAYLOAD_INVALID = "PAYLOAD_INVALID"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    HEAD_UNAVAILABLE = "HEAD_UNAVAILABLE"
    STATE_REJECTED = "STATE_REJECTED"
    RUN_UNKNOWN = "RUN_UNKNOWN"


class GithubAppError(ValueError):
    """Safe adapter error that deliberately excludes raw payload and credentials."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: GithubAppErrorCode) -> None:
        if type(code) is not GithubAppErrorCode:
            raise TypeError("GitHub App error code is invalid")
        self.code = code
        self.safe_message = "GitHub App delivery was rejected"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class GithubWebhookDelivery:
    """Raw authenticated-delivery envelope before any payload parsing."""

    delivery_id: str
    event: str
    signature_sha256: str
    raw_body: bytes
    execution_identity: RunExecutionIdentity

    def __post_init__(self) -> None:
        if (
            type(self.delivery_id) is not str
            or _ID.fullmatch(self.delivery_id) is None
            or self.event != "pull_request"
            or type(self.signature_sha256) is not str
            or _SIGNATURE.fullmatch(self.signature_sha256) is None
            or type(self.raw_body) is not bytes
            or not self.raw_body
            or len(self.raw_body) > MAX_WEBHOOK_BYTES
            or type(self.execution_identity) is not RunExecutionIdentity
        ):
            raise GithubAppError(GithubAppErrorCode.DELIVERY_INVALID)


@dataclass(frozen=True, slots=True)
class GithubDeliveryReceipt:
    """Redacted authenticated delivery result, suitable for durable audit metadata."""

    delivery_id: str
    event: str
    installation_id: str
    repository_id: str
    head_sha: str
    admission: SCMRunAdmissionReceipt


@dataclass(frozen=True, slots=True)
class _RunBinding:
    installation_id: str
    repository_id: str
    change_id: str
    execution_identity_hash: str


class _SCMRunStatePort(Protocol):
    def admit(
        self,
        request: SCMRunAdmissionRequest,
        *,
        current_head_sha: str,
    ) -> SCMRunAdmissionReceipt: ...

    def authorize_publication(
        self,
        run_id: str,
        *,
        current_head_sha: str,
    ) -> SCMRunPublicationReceipt: ...

    def complete(
        self,
        run_id: str,
        outcome: AuditRunOutcome,
        *,
        current_head_sha: str,
    ) -> SCMRunPublicationReceipt: ...


TrustedHeadResolver = Callable[..., str]


class GithubAppAdapter:
    """Authenticate allowed GitHub PR deliveries and admit exact-SHA runs."""

    __slots__ = (
        "_delivery_sha256_by_id",
        "_head_resolver",
        "_lock",
        "_run_bindings",
        "_run_state",
        "_webhook_secret",
    )

    def __init__(
        self,
        *,
        webhook_secret: bytes,
        run_state: object,
        head_resolver: object,
    ) -> None:
        if (
            type(webhook_secret) is not bytes
            or not webhook_secret
            or len(webhook_secret) > MAX_JSON_SCALAR_BYTES
            or not _is_run_state(run_state)
            or not callable(head_resolver)
        ):
            raise GithubAppError(GithubAppErrorCode.INVALID_CONFIGURATION)
        self._webhook_secret = webhook_secret
        self._run_state = run_state
        self._head_resolver = cast(TrustedHeadResolver, head_resolver)
        self._delivery_sha256_by_id: dict[str, str] = {}
        self._run_bindings: dict[str, _RunBinding] = {}
        self._lock = RLock()

    def receive(self, delivery: GithubWebhookDelivery) -> GithubDeliveryReceipt:
        """Verify raw HMAC first, then parse and admit one allowed PR delivery."""

        if type(delivery) is not GithubWebhookDelivery:
            raise GithubAppError(GithubAppErrorCode.DELIVERY_INVALID)
        self._verify_signature(delivery.raw_body, delivery.signature_sha256)
        delivery_sha256 = hashlib.sha256(delivery.raw_body).hexdigest()
        with self._lock:
            previous_sha256 = self._delivery_sha256_by_id.setdefault(
                delivery.delivery_id,
                delivery_sha256,
            )
        if previous_sha256 != delivery_sha256:
            raise GithubAppError(GithubAppErrorCode.STATE_REJECTED)
        payload = _parse_payload(delivery.raw_body)
        installation_id, repository_id, change_id, payload_head_sha = _pull_request_metadata(
            payload
        )
        identity = delivery.execution_identity
        revision = identity.repository_revision
        if (
            installation_id is None
            or repository_id != revision.repository_id
            or payload_head_sha != revision.head_sha
        ):
            raise GithubAppError(GithubAppErrorCode.IDENTITY_MISMATCH)
        current_head_sha = self._current_head(installation_id, repository_id, change_id)
        try:
            admission = self._run_state.admit(
                SCMRunAdmissionRequest(
                    delivery_id=delivery.delivery_id,
                    installation_id=f"{installation_id}:pr:{change_id}",
                    execution_identity=identity,
                    authorized_head_sha=revision.head_sha,
                ),
                current_head_sha=current_head_sha,
            )
        except SCMRunStateError as error:
            raise GithubAppError(GithubAppErrorCode.STATE_REJECTED) from error
        if admission.disposition is not AdmissionDisposition.SUPERSEDED:
            with self._lock:
                self._run_bindings[admission.run_id] = _RunBinding(
                    installation_id=installation_id,
                    repository_id=repository_id,
                    change_id=change_id,
                    execution_identity_hash=identity.execution_identity_hash,
                )
        return GithubDeliveryReceipt(
            delivery_id=delivery.delivery_id,
            event=delivery.event,
            installation_id=installation_id,
            repository_id=repository_id,
            head_sha=revision.head_sha,
            admission=admission,
        )

    def authorize_publication(self, run_id: str) -> SCMRunPublicationReceipt:
        """Refresh the trusted source HEAD before granting publication authority."""

        binding = self._binding(run_id)
        return self._run_state_call(
            run_id,
            lambda current_head_sha: self._run_state.authorize_publication(
                run_id,
                current_head_sha=current_head_sha,
            ),
            binding,
        )

    def complete(self, run_id: str, outcome: AuditRunOutcome) -> SCMRunPublicationReceipt:
        """Refresh HEAD before recording a final outcome; stale results are superseded."""

        if type(outcome) is not AuditRunOutcome:
            raise GithubAppError(GithubAppErrorCode.DELIVERY_INVALID)
        binding = self._binding(run_id)
        return self._run_state_call(
            run_id,
            lambda current_head_sha: self._run_state.complete(
                run_id,
                outcome,
                current_head_sha=current_head_sha,
            ),
            binding,
        )

    def _binding(self, run_id: str) -> _RunBinding:
        if type(run_id) is not str or _ID.fullmatch(run_id) is None:
            raise GithubAppError(GithubAppErrorCode.RUN_UNKNOWN)
        with self._lock:
            binding = self._run_bindings.get(run_id)
        if binding is not None:
            return binding
        binding = self._restore_binding(run_id)
        with self._lock:
            return self._run_bindings.setdefault(run_id, binding)

    def _restore_binding(self, run_id: str) -> _RunBinding:
        provider_target = getattr(self._run_state, "provider_target", None)
        if not callable(provider_target):
            raise GithubAppError(GithubAppErrorCode.RUN_UNKNOWN)
        try:
            target = provider_target(run_id)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except SCMRunStateError as error:
            code = (
                GithubAppErrorCode.RUN_UNKNOWN
                if error.code is SCMRunStateErrorCode.RUN_UNKNOWN
                else GithubAppErrorCode.STATE_REJECTED
            )
            raise GithubAppError(code) from error
        except Exception as error:
            raise GithubAppError(GithubAppErrorCode.STATE_REJECTED) from error
        provider = getattr(target, "provider", None)
        installation_id = getattr(target, "installation_id", None)
        repository_id = getattr(target, "repository_id", None)
        change_id = getattr(target, "change_id", None)
        execution_identity_hash = getattr(target, "execution_identity_hash", None)
        if (
            provider != "github"
            or type(installation_id) is not str
            or _ID.fullmatch(installation_id) is None
            or type(repository_id) is not str
            or _ID.fullmatch(repository_id) is None
            or type(change_id) is not str
            or _ID.fullmatch(change_id) is None
            or type(execution_identity_hash) is not str
            or _SHA256.fullmatch(execution_identity_hash) is None
        ):
            raise GithubAppError(GithubAppErrorCode.STATE_REJECTED)
        return _RunBinding(
            installation_id=installation_id,
            repository_id=repository_id,
            change_id=change_id,
            execution_identity_hash=execution_identity_hash,
        )

    def _run_state_call(
        self,
        run_id: str,
        operation: Callable[[str], SCMRunPublicationReceipt],
        binding: _RunBinding,
    ) -> SCMRunPublicationReceipt:
        current_head_sha = self._current_head(
            binding.installation_id,
            binding.repository_id,
            binding.change_id,
        )
        try:
            receipt = operation(current_head_sha)
        except SCMRunStateError as error:
            raise GithubAppError(GithubAppErrorCode.STATE_REJECTED) from error
        if (
            type(receipt) is not SCMRunPublicationReceipt
            or receipt.run_id != run_id
            or receipt.execution_identity_hash != binding.execution_identity_hash
        ):
            raise GithubAppError(GithubAppErrorCode.IDENTITY_MISMATCH)
        return receipt

    def _verify_signature(self, raw_body: bytes, signature_sha256: str) -> None:
        expected = (
            "sha256="
            + hmac.new(
                self._webhook_secret,
                raw_body,
                hashlib.sha256,
            ).hexdigest()
        )
        if not hmac.compare_digest(expected, signature_sha256):
            raise GithubAppError(GithubAppErrorCode.AUTHENTICATION_FAILED)

    def _current_head(
        self,
        installation_id: str,
        repository_id: str,
        change_id: str,
    ) -> str:
        try:
            resolver_signature = inspect.signature(self._head_resolver)
            try:
                resolver_signature.bind(installation_id, repository_id, change_id)
            except TypeError:
                resolver_signature.bind(installation_id, repository_id)
                current_head_sha = self._head_resolver(installation_id, repository_id)
            else:
                current_head_sha = self._head_resolver(
                    installation_id,
                    repository_id,
                    change_id,
                )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception as error:
            raise GithubAppError(GithubAppErrorCode.HEAD_UNAVAILABLE) from error
        if type(current_head_sha) is not str or _COMMIT_SHA.fullmatch(current_head_sha) is None:
            raise GithubAppError(GithubAppErrorCode.HEAD_UNAVAILABLE)
        return current_head_sha


def _is_run_state(value: object) -> TypeGuard[_SCMRunStatePort]:
    return all(
        callable(getattr(value, method, None))
        for method in ("admit", "authorize_publication", "complete")
    )


def github_app_permissions(*, enable_sarif: bool = False) -> Mapping[str, str]:
    """Return the smallest GitHub App permission manifest for enabled capabilities."""

    if type(enable_sarif) is not bool:
        raise GithubAppError(GithubAppErrorCode.INVALID_CONFIGURATION)
    permissions = dict(GITHUB_APP_REQUIRED_PERMISSIONS)
    if enable_sarif:
        permissions.update(GITHUB_APP_OPTIONAL_PERMISSIONS)
    return permissions


def _parse_payload(raw_body: bytes) -> dict[str, object]:
    try:
        decoded = raw_body.decode("utf-8", "strict")
        parsed = json.loads(
            decoded,
            object_pairs_hook=_no_duplicate_object,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        _PayloadRejected,
    ) as error:
        raise GithubAppError(GithubAppErrorCode.PAYLOAD_INVALID) from error
    if type(parsed) is not dict:
        raise GithubAppError(GithubAppErrorCode.PAYLOAD_INVALID)
    return parsed


def _no_duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _PayloadRejected
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise _PayloadRejected


def _pull_request_metadata(payload: dict[str, object]) -> tuple[str, str, str, str]:
    if payload.get("action") not in _PULL_REQUEST_ACTIONS:
        raise GithubAppError(GithubAppErrorCode.PAYLOAD_INVALID)
    installation_id = _github_identifier(_object_field(payload, "installation"), "id")
    repository_id = _github_identifier(_object_field(payload, "repository"), "id")
    pull_request = _object_field(payload, "pull_request")
    head = _object_field(pull_request, "head")
    head_sha = head.get("sha")
    if (
        installation_id is None
        or repository_id is None
        or type(head_sha) is not str
        or _COMMIT_SHA.fullmatch(head_sha) is None
    ):
        raise GithubAppError(GithubAppErrorCode.PAYLOAD_INVALID)
    change_id = _github_identifier(payload, "number") or head_sha
    return installation_id, repository_id, change_id, head_sha


def _object_field(value: Mapping[str, object], name: str) -> dict[str, object]:
    field = value.get(name)
    if type(field) is not dict:
        raise GithubAppError(GithubAppErrorCode.PAYLOAD_INVALID)
    return field


def _github_identifier(value: Mapping[str, object], name: str) -> str | None:
    raw_identifier = value.get(name)
    if type(raw_identifier) is int and raw_identifier > 0:
        identifier = str(raw_identifier)
    elif type(raw_identifier) is str:
        identifier = raw_identifier
    else:
        return None
    return identifier if _ID.fullmatch(identifier) is not None else None


class _PayloadRejected(ValueError):
    pass


__all__ = [
    "GITHUB_APP_OPTIONAL_PERMISSIONS",
    "GITHUB_APP_REQUIRED_PERMISSIONS",
    "MAX_JSON_DEPTH",
    "MAX_JSON_ITEMS",
    "MAX_JSON_SCALAR_BYTES",
    "MAX_WEBHOOK_BYTES",
    "GithubAppAdapter",
    "GithubAppError",
    "GithubAppErrorCode",
    "GithubDeliveryReceipt",
    "GithubWebhookDelivery",
    "github_app_permissions",
]
