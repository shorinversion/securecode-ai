"""Durable, integrity-checked local patch status for explicit human approval."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from securecode_ai.contracts import ComponentPin, PatchStatus, ValidationResult
from securecode_ai.core.diff_review import review_semantic_diff
from securecode_ai.core.patch_status import (
    PatchStatusState,
    approve_patch_locally,
    mark_patch_validated,
    promote_patch_candidate,
    start_patch_status,
)

from .local_durable_files import durable_replace, durable_write_new
from .local_patch_status_lock import (
    StatusFileLockBusy,
    StatusFileLockError,
    status_file_lock,
)
from .patch_artifact import StoredPatchArtifact, selector_digest

_MAX_STATUS_BYTES: Final = 262_144
_KEYS_V1: Final = frozenset(
    {
        "approval",
        "artifact_sha256",
        "capability",
        "policy",
        "schema_version",
        "selector",
        "state_sha256",
        "status",
        "validation",
    }
)
_KEYS: Final = _KEYS_V1 | {"approval_request_sha256"}
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")


class LocalPatchStatusError(ValueError):
    """Fixed, non-echoing failure at the local approval boundary."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__("local patch status is unavailable")
        self.__cause__ = None
        self.__context__ = None


class LocalPatchStatusStore:
    """Persist a reconstructable Core ``PatchStatusState`` beside one artifact."""

    def record_validated(
        self, artifact: StoredPatchArtifact, validation: ValidationResult
    ) -> tuple[PatchStatusState, str]:
        path = _status_path(artifact)
        with _lock(path):
            _require_artifact_present(artifact)
            if path.exists():
                state, capability, _ = self._load_unlocked(artifact)
                if (
                    state.patch.patch_status is not PatchStatus.VALIDATED
                    or state.validation != validation
                    or capability is None
                ):
                    raise LocalPatchStatusError("PATCH_STATUS_CONFLICT")
                return state, capability
            state = mark_patch_validated(
                promote_patch_candidate(
                    start_patch_status(artifact.architect_result.patch_candidate)
                ),
                validation,
            )
            capability = secrets.token_hex(32)
            _write_new(path, _status_document(artifact, state, capability))
            return state, capability

    def approve(
        self,
        artifact: StoredPatchArtifact,
        *,
        artifact_sha256: str,
        capability: str,
        approval_id: str,
        approver_id: str,
        policy: ComponentPin,
        approved_at: datetime,
    ) -> PatchStatusState:
        if (
            artifact_sha256 != artifact.architect_result.patch_candidate.unified_diff_sha256
            or artifact_sha256 != selector_digest(artifact.selector)
            or type(capability) is not str
        ):
            raise LocalPatchStatusError("PATCH_APPROVAL_BINDING_MISMATCH")
        request_sha256 = _approval_request_hash(
            artifact,
            artifact_sha256=artifact_sha256,
            capability=capability,
            approval_id=approval_id,
            approver_id=approver_id,
            policy=policy,
        )
        path = _status_path(artifact)
        with _lock(path):
            _require_artifact_present(artifact)
            state, expected_capability, stored_request_sha256 = self._load_unlocked(artifact)
            if state.patch.patch_status is PatchStatus.APPROVED:
                if stored_request_sha256 is not None and hmac.compare_digest(
                    request_sha256, stored_request_sha256
                ):
                    return state
                raise LocalPatchStatusError("PATCH_APPROVAL_CONFLICT")
            if (
                state.patch.patch_status is not PatchStatus.VALIDATED
                or expected_capability is None
                or not hmac.compare_digest(capability, expected_capability)
            ):
                raise LocalPatchStatusError("PATCH_APPROVAL_CAPABILITY_INVALID")
            if state.validation is None:
                raise LocalPatchStatusError("PATCH_VALIDATION_REQUIRED")
            review = review_semantic_diff(artifact.architect_result, state.validation)
            approved = approve_patch_locally(
                state,
                review,
                approval_id=approval_id,
                approver_id=approver_id,
                policy=policy,
                approved_at=approved_at,
            )
            _replace(
                path,
                _status_document(
                    artifact,
                    approved,
                    None,
                    approval_request_sha256=request_sha256,
                ),
            )
            return approved

    def load(self, artifact: StoredPatchArtifact) -> PatchStatusState:
        state, _, _ = self._load_unlocked(artifact)
        return state

    def _load_unlocked(
        self, artifact: StoredPatchArtifact
    ) -> tuple[PatchStatusState, str | None, str | None]:
        path = _status_path(artifact)
        try:
            if path.is_symlink() or not path.is_file():
                raise OSError
            raw = path.read_bytes()
        except OSError:
            raise LocalPatchStatusError("PATCH_STATUS_NOT_FOUND") from None
        if not raw or len(raw) > _MAX_STATUS_BYTES:
            raise LocalPatchStatusError("PATCH_STATUS_INVALID")
        document = _closed_json(raw)
        keys = frozenset(document)
        if keys not in {_KEYS_V1, _KEYS} or raw != _canonical(document):
            raise LocalPatchStatusError("PATCH_STATUS_INVALID")
        digest = artifact.architect_result.patch_candidate.unified_diff_sha256
        if (
            document["schema_version"] not in {"1.0.0", "1.1.0"}
            or (document["schema_version"] == "1.0.0") != (keys == _KEYS_V1)
            or document["selector"] != artifact.selector
            or document["artifact_sha256"] != digest
            or type(document["validation"]) is not dict
        ):
            raise LocalPatchStatusError("PATCH_STATUS_BINDING_MISMATCH")
        try:
            validation = ValidationResult.model_validate_json(_canonical(document["validation"]))
            state = mark_patch_validated(
                promote_patch_candidate(
                    start_patch_status(artifact.architect_result.patch_candidate)
                ),
                validation,
            )
            capability = document["capability"]
            approval_request_sha256 = document.get("approval_request_sha256")
            if document["status"] == PatchStatus.APPROVED.value:
                approval = _mapping(document["approval"])
                policy = ComponentPin.model_validate_json(_canonical(_mapping(document["policy"])))
                approved_at = datetime.fromisoformat(_string(approval["approved_at"]))
                if (
                    approved_at.tzinfo is not UTC
                    or capability is not None
                    or type(approval_request_sha256) is not str
                    or _SHA256.fullmatch(approval_request_sha256) is None
                ):
                    raise ValueError
                review = review_semantic_diff(artifact.architect_result, validation)
                state = approve_patch_locally(
                    state,
                    review,
                    approval_id=_string(approval["approval_id"]),
                    approver_id=_string(approval["approver_id"]),
                    policy=policy,
                    approved_at=approved_at,
                )
            elif (
                document["status"] != PatchStatus.VALIDATED.value
                or type(capability) is not str
                or len(capability) != 64
                or document["approval"] is not None
                or document["policy"] is not None
                or approval_request_sha256 is not None
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise LocalPatchStatusError("PATCH_STATUS_INVALID") from None
        if document["state_sha256"] != state.state_sha256:
            raise LocalPatchStatusError("PATCH_STATUS_INTEGRITY_FAILURE")
        return state, capability, approval_request_sha256


def _status_document(
    artifact: StoredPatchArtifact,
    state: PatchStatusState,
    capability: str | None,
    *,
    approval_request_sha256: str | None = None,
) -> bytes:
    approval = state.approval
    return _canonical(
        {
            "approval": None
            if approval is None
            else {
                "approval_id": approval.approval_id,
                "approved_at": approval.approved_at.isoformat(),
                "approver_id": approval.approver_id,
            },
            "artifact_sha256": artifact.architect_result.patch_candidate.unified_diff_sha256,
            "approval_request_sha256": approval_request_sha256,
            "capability": capability,
            "policy": None if approval is None else approval.policy.model_dump(mode="json"),
            "schema_version": "1.1.0",
            "selector": artifact.selector,
            "state_sha256": state.state_sha256,
            "status": state.patch.patch_status.value,
            "validation": state.validation.model_dump(mode="json") if state.validation else None,
        }
    )


def _approval_request_hash(
    artifact: StoredPatchArtifact,
    *,
    artifact_sha256: str,
    capability: str,
    approval_id: str,
    approver_id: str,
    policy: ComponentPin,
) -> str:
    if (
        type(capability) is not str
        or type(approval_id) is not str
        or type(approver_id) is not str
        or type(policy) is not ComponentPin
    ):
        raise LocalPatchStatusError("PATCH_APPROVAL_BINDING_MISMATCH")
    material = _canonical(
        {
            "approval_id": approval_id,
            "approver_id": approver_id,
            "artifact_sha256": artifact_sha256,
            "capability_sha256": hashlib.sha256(capability.encode("utf-8")).hexdigest(),
            "policy": policy.model_dump(mode="json"),
            "schema_version": "1.0.0",
            "selector": artifact.selector,
        }
    )
    return hashlib.sha256(b"securecode-ai/local-approval-request/v1\x00" + material).hexdigest()


def _status_path(artifact: StoredPatchArtifact) -> Path:
    digest = selector_digest(artifact.selector)
    expected = artifact.patch_path.parent / f"{digest}.patch"
    if artifact.patch_path != expected or artifact.patch_path.is_symlink():
        raise LocalPatchStatusError("PATCH_STATUS_BINDING_MISMATCH")
    return artifact.patch_path.parent / f"{digest}.status.json"


def _require_artifact_present(artifact: StoredPatchArtifact) -> None:
    manifest = artifact.patch_path.with_suffix(".json")
    if (
        artifact.patch_path.is_symlink()
        or manifest.is_symlink()
        or not artifact.patch_path.is_file()
        or not manifest.is_file()
    ):
        raise LocalPatchStatusError("PATCH_ARTIFACT_NOT_FOUND")


@contextmanager
def _lock(path: Path) -> Iterator[None]:
    lock = path.parent / ".status.lock"
    try:
        with status_file_lock(lock):
            yield
    except StatusFileLockBusy:
        raise LocalPatchStatusError("PATCH_STATUS_BUSY") from None
    except StatusFileLockError:
        raise LocalPatchStatusError("PATCH_STATUS_UNAVAILABLE") from None


def _write_new(path: Path, content: bytes) -> None:
    try:
        durable_write_new(path, content)
    except FileExistsError:
        raise LocalPatchStatusError("PATCH_STATUS_CONFLICT") from None
    except OSError:
        raise LocalPatchStatusError("PATCH_STATUS_UNAVAILABLE") from None


def _replace(path: Path, content: bytes) -> None:
    try:
        durable_replace(path, content)
    except OSError:
        raise LocalPatchStatusError("PATCH_STATUS_UNAVAILABLE") from None


def _closed_json(raw: bytes) -> dict[str, Any]:
    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if type(key) is not str or key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=object_pairs)
    except Exception:
        raise LocalPatchStatusError("PATCH_STATUS_INVALID") from None
    return _mapping(value)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    except (TypeError, ValueError):
        raise LocalPatchStatusError("PATCH_STATUS_INVALID") from None


def _mapping(value: object) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise LocalPatchStatusError("PATCH_STATUS_INVALID")
    return dict(value)


def _string(value: object) -> str:
    if type(value) is not str:
        raise LocalPatchStatusError("PATCH_STATUS_INVALID")
    return value


__all__ = ["LocalPatchStatusError", "LocalPatchStatusStore"]
