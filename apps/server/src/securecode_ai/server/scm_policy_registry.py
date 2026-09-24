"""Load immutable, tenant-scoped SCM policy documents by exact run pin."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Final

from securecode_ai.contracts import AuditRun
from securecode_ai.core.scm_policy import ScmPolicyDocument

from .secure_files import read_json_object

_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ENTRY_KEYS: Final = frozenset({"tenant_id", "policy_id", "policy_version", "content"})


class ScmPolicyRegistry:
    """Resolve a policy loaded at startup without following mutable assignments."""

    def __init__(self, documents: Mapping[tuple[str, str, str, str], ScmPolicyDocument]) -> None:
        if not documents:
            raise ValueError("SCM policy registry is empty")
        self._documents = dict(documents)

    def __call__(self, audit_run: object) -> ScmPolicyDocument:
        if type(audit_run) is not AuditRun:
            raise ValueError("SCM policy run is invalid")
        identity = audit_run.execution_identity
        pin = identity.policy
        tenant_id = identity.repository_revision.tenant_id
        key = (tenant_id, pin.component_id, pin.component_version, pin.content_sha256)
        try:
            return self._documents[key]
        except KeyError:
            raise ValueError("SCM policy document is unavailable for the run pin") from None


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
        if version_key in version_hashes or (tenant_id, policy_id, policy_version, digest) in documents:
            raise ValueError("SCM policy version is duplicated")
        version_hashes[version_key] = digest
        documents[(tenant_id, policy_id, policy_version, digest)] = policy
    return ScmPolicyRegistry(documents)


__all__ = ["ScmPolicyRegistry", "load_scm_policy_registry"]
