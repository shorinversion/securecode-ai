"""Reloadable bootstrap identities backed by direct values or protected files."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .ports import VerifiedIdentity
from .secure_files import decode_ascii_secret, read_secret_bytes

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


@dataclass(frozen=True, slots=True)
class BootstrapIdentity:
    token_sha256: str
    identity: VerifiedIdentity


class HashedTokenIdentityVerifier:
    """Bootstrap verifier that retains hashes instead of bearer tokens."""

    __slots__ = ("_identities",)

    def __init__(self, identities: tuple[BootstrapIdentity, ...]) -> None:
        if not identities or len({item.token_sha256 for item in identities}) != len(identities):
            raise ValueError("bootstrap identities are invalid")
        self._identities = identities

    def verify_bearer(self, token: str) -> VerifiedIdentity | None:
        if type(token) is not str or not 32 <= len(token) <= 8192:
            return None
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        matched: VerifiedIdentity | None = None
        for item in self._identities:
            if hmac.compare_digest(digest, item.token_sha256):
                matched = item.identity
        return matched


def load_bootstrap_identities(
    values: Mapping[str, str],
    *,
    required: bool = True,
) -> tuple[BootstrapIdentity, ...]:
    tenant_id = values.get("SECURECODE_BOOTSTRAP_TENANT_ID")
    any_token = any(
        values.get(name) is not None
        for name in (
            "SECURECODE_BOOTSTRAP_ADMIN_TOKEN",
            "SECURECODE_BOOTSTRAP_ADMIN_TOKEN_FILE",
            "SECURECODE_BOOTSTRAP_WORKER_TOKEN",
            "SECURECODE_BOOTSTRAP_WORKER_TOKEN_FILE",
            "SECURECODE_BOOTSTRAP_SCM_TOKEN",
            "SECURECODE_BOOTSTRAP_SCM_TOKEN_FILE",
        )
    )
    if not any_token and not required:
        return ()
    if type(tenant_id) is not str or _ID.fullmatch(tenant_id) is None:
        raise ValueError("bootstrap identity is not configured")
    items: list[BootstrapIdentity] = []
    admin_token = _configured_token(
        values,
        "SECURECODE_BOOTSTRAP_ADMIN_TOKEN",
        "SECURECODE_BOOTSTRAP_ADMIN_TOKEN_FILE",
    )
    if admin_token is not None:
        items.append(
            _identity(
                admin_token,
                VerifiedIdentity("bootstrap-admin", tenant_id, frozenset({"admin"}), False),
            )
        )
    worker_token = _configured_token(
        values,
        "SECURECODE_BOOTSTRAP_WORKER_TOKEN",
        "SECURECODE_BOOTSTRAP_WORKER_TOKEN_FILE",
    )
    if worker_token is not None:
        repositories = _repository_scope(values.get("SECURECODE_BOOTSTRAP_WORKER_REPOSITORIES", ""))
        if not repositories:
            raise ValueError("bootstrap worker repository scope is invalid")
        items.append(
            _identity(
                worker_token,
                VerifiedIdentity(
                    "bootstrap-worker",
                    tenant_id,
                    frozenset({"worker"}),
                    True,
                    repositories,
                ),
            )
        )
    scm_token = _configured_token(
        values,
        "SECURECODE_BOOTSTRAP_SCM_TOKEN",
        "SECURECODE_BOOTSTRAP_SCM_TOKEN_FILE",
    )
    if scm_token is not None:
        items.append(
            _identity(
                scm_token,
                VerifiedIdentity("bootstrap-scm", tenant_id, frozenset({"scm"}), True),
            )
        )
    if not items:
        raise ValueError("bootstrap identity is not configured")
    return tuple(items)


def _repository_scope(value: str) -> frozenset[str]:
    repositories = frozenset(item.strip() for item in value.split(",") if item.strip())
    if any(_ID.fullmatch(item) is None for item in repositories):
        raise ValueError("bootstrap worker repository scope is invalid")
    return repositories


def _configured_token(values: Mapping[str, str], direct_name: str, file_name: str) -> str | None:
    direct = values.get(direct_name)
    configured_file = values.get(file_name)
    if direct is not None and configured_file is not None:
        raise ValueError("bootstrap identity has multiple token sources")
    if configured_file is None:
        return None if direct is None else _validated_token(direct)
    token = decode_ascii_secret(read_secret_bytes(Path(configured_file), minimum=32, maximum=8192))
    return _validated_token(token)


def _validated_token(token: str) -> str:
    if not 32 <= len(token) <= 8192:
        raise ValueError("bootstrap identity token is invalid")
    return token


def _identity(token: str, identity: VerifiedIdentity) -> BootstrapIdentity:
    return BootstrapIdentity(
        token_sha256=hashlib.sha256(token.encode("utf-8")).hexdigest(),
        identity=identity,
    )


__all__ = [
    "BootstrapIdentity",
    "HashedTokenIdentityVerifier",
    "load_bootstrap_identities",
]
