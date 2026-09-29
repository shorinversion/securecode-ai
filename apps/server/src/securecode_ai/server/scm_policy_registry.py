"""Load immutable, tenant-scoped SCM policy documents by exact run pin."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Final

from securecode_ai.contracts import AuditRun, RunExecutionIdentity
from securecode_ai.core.scm_policy import ScmPolicyDocument, ScmPolicyMode

from .policy_store import PolicyStore
from .profiles import ProfileConflict, ScanProfile
from .secure_files import read_json_object

_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ENTRY_KEYS: Final = frozenset({"tenant_id", "policy_id", "policy_version", "content"})


class ScmPolicyRegistry:
    """Resolve a policy loaded at startup without following mutable assignments."""

    def __init__(self, documents: Mapping[tuple[str, str, str, str], ScmPolicyDocument]) -> None:
        if not isinstance(documents, Mapping) or not 1 <= len(documents) <= 64:
            raise ValueError("SCM policy registry is empty")
        validated: dict[tuple[str, str, str, str], ScmPolicyDocument] = {}
        for key, policy in documents.items():
            if (
                type(key) is not tuple
                or len(key) != 4
                or any(type(value) is not str for value in key)
                or _IDENTIFIER.fullmatch(key[0]) is None
                or type(policy) is not ScmPolicyDocument
                or policy.content is None
                or (policy.policy_id, policy.policy_version, policy.content_sha256) != key[1:]
            ):
                raise ValueError("SCM policy registry is invalid")
            validated[key] = policy
        self._documents = MappingProxyType(validated)

    def __call__(self, audit_run: object) -> ScmPolicyDocument:
        if type(audit_run) is not AuditRun:
            raise ValueError("SCM policy run is invalid")
        return self._for_identity(audit_run.execution_identity)

    def validate_identity(self, identity: RunExecutionIdentity) -> None:
        self._for_identity(identity)

    def _for_identity(self, identity: RunExecutionIdentity) -> ScmPolicyDocument:
        if type(identity) is not RunExecutionIdentity:
            raise ValueError("SCM policy identity is invalid")
        pin = identity.policy
        tenant_id = identity.repository_revision.tenant_id
        key = (tenant_id, pin.component_id, pin.component_version, pin.content_sha256)
        try:
            return self._documents[key]
        except KeyError:
            raise ValueError("SCM policy document is unavailable for the run pin") from None


class PolicyStoreScmPolicyResolver:
    """Resolve one run's policy through the durable tenant assignment.

    ``PolicyStore`` stores monotonically increasing integer profile versions,
    while the execution identity uses the repository-wide ``SemVer`` pin.  A
    profile version is therefore represented as ``<integer>.0.0`` at the
    runtime boundary.  The conversion is deliberately exact: a run carrying
    a different id, version, or content digest cannot consume the active
    assignment, even when it belongs to the same repository.
    """

    __slots__ = ("_store",)

    def __init__(self, store: PolicyStore) -> None:
        if type(store) is not PolicyStore:
            raise TypeError("policy store is invalid")
        self._store = store

    def __call__(self, audit_run: object) -> ScmPolicyDocument:
        if type(audit_run) is not AuditRun:
            raise ProfileConflict("durable policy run is invalid")
        identity = audit_run.execution_identity
        profile = self._profile_for_identity(identity)
        return self._document_for_profile(profile)

    def validate_identity(self, identity: RunExecutionIdentity) -> None:
        self._profile_for_identity(identity)

    def _profile_for_identity(self, identity: RunExecutionIdentity) -> ScanProfile:
        if type(identity) is not RunExecutionIdentity:
            raise ValueError("durable policy identity is invalid")
        revision = identity.repository_revision
        try:
            profile = self._store.resolve_profile(
                tenant_id=revision.tenant_id,
                repository_id=revision.repository_id,
            )
        except ProfileConflict:
            raise ProfileConflict("durable policy assignment is unavailable") from None
        if type(profile) is not ScanProfile or profile.tenant_id != revision.tenant_id:
            raise ProfileConflict("durable policy assignment is invalid")

        policy_version = _profile_policy_version(profile)
        pin = identity.policy
        if (
            pin.component_id != profile.profile_id
            or pin.component_version != policy_version
            or pin.content_sha256 != profile.content_sha256
        ):
            raise ValueError("durable policy assignment is not bound to the run")
        return profile

    @staticmethod
    def _document_for_profile(profile: ScanProfile) -> ScmPolicyDocument:
        policy_version = _profile_policy_version(profile)
        mode = ScmPolicyMode(profile.rollout.value)
        try:
            policy = ScmPolicyDocument.from_content(
                policy_id=profile.profile_id,
                policy_version=policy_version,
                content_sha256=profile.content_sha256,
                content=profile.content,
                mode=mode,
            )
            if profile.calibrated and policy.calibration_record_sha256 is None:
                raise ValueError("calibration record is missing")
            if not profile.calibrated:
                return policy
            return ScmPolicyDocument.from_content(
                policy_id=profile.profile_id,
                policy_version=policy_version,
                content_sha256=profile.content_sha256,
                content=profile.content,
                mode=mode,
                calibration_record_sha256=policy.calibration_record_sha256,
                calibration_verified=True,
            )
        except (TypeError, ValueError):
            raise ProfileConflict("durable policy profile is invalid") from None


def _profile_policy_version(profile: ScanProfile) -> str:
    if type(profile.version) is not int or profile.version < 1:
        raise ProfileConflict("durable policy version is invalid")
    return f"{profile.version}.0.0"


def load_scm_policy_registry(path: Path) -> ScmPolicyRegistry:
    """Read a bounded JSON registry and verify every typed document digest."""

    raw = read_json_object(path, 1_048_576)
    if set(raw) != {"documents"}:
        raise ValueError("SCM policy registry is invalid")
    entries = raw["documents"]
    if type(entries) is not list or not 1 <= len(entries) <= 64:
        raise ValueError("SCM policy registry is invalid")
    documents: dict[tuple[str, str, str, str], ScmPolicyDocument] = {}
    version_hashes: dict[tuple[str, str, str], str] = {}
    for entry in entries:
        if type(entry) is not dict or set(entry) != _ENTRY_KEYS:
            raise ValueError("SCM policy registry is invalid")
        tenant_id = entry["tenant_id"]
        policy_id = entry["policy_id"]
        policy_version = entry["policy_version"]
        content = entry["content"]
        if (
            type(tenant_id) is not str
            or _IDENTIFIER.fullmatch(tenant_id) is None
            or type(policy_id) is not str
            or type(policy_version) is not str
            or type(content) is not dict
        ):
            raise ValueError("SCM policy registry is invalid")
        try:
            canonical = json.dumps(
                content,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            digest = hashlib.sha256(canonical.encode("ascii")).hexdigest()
            policy = ScmPolicyDocument.from_content(
                policy_id=policy_id,
                policy_version=policy_version,
                content_sha256=digest,
                content=content,
            )
        except (TypeError, ValueError):
            raise ValueError("SCM policy registry is invalid") from None
        version_key = (tenant_id, policy_id, policy_version)
        if (
            version_key in version_hashes
            or (tenant_id, policy_id, policy_version, digest) in documents
        ):
            raise ValueError("SCM policy version is duplicated")
        version_hashes[version_key] = digest
        documents[(tenant_id, policy_id, policy_version, digest)] = policy
    return ScmPolicyRegistry(documents)


__all__ = [
    "PolicyStoreScmPolicyResolver",
    "ScmPolicyRegistry",
    "load_scm_policy_registry",
]
