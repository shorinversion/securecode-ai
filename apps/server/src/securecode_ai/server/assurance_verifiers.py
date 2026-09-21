"""Host-owned verifier identity registry for assurance evidence admission."""

from __future__ import annotations

import hmac
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Final

from .secure_files import read_json_object

_INLINE_ENV: Final = "SECURECODE_ASSURANCE_VERIFIER_REGISTRY"
_FILE_ENV: Final = "SECURECODE_ASSURANCE_VERIFIER_REGISTRY_FILE"
_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_MAX_CONFIG_BYTES: Final = 65_536
_MAX_VERIFIERS: Final = 256


class AssuranceVerifierRegistryError(ValueError):
    """Source-free rejection for invalid configuration or verifier binding."""

    def __init__(self) -> None:
        super().__init__("assurance verifier registry rejected the request")


class AssuranceVerifierRegistry:
    """Immutable subject-to-verifier-digest allowlist owned by the host."""

    __slots__ = ("_identities",)

    def __init__(self, identities: Mapping[str, str]) -> None:
        if type(identities) is not dict or len(identities) > _MAX_VERIFIERS:
            raise AssuranceVerifierRegistryError()

        copied: dict[str, str] = {}
        for verifier_id, identity_sha256 in identities.items():
            if (
                type(verifier_id) is not str
                or _IDENTIFIER.fullmatch(verifier_id) is None
                or type(identity_sha256) is not str
                or _SHA256.fullmatch(identity_sha256) is None
                or verifier_id in copied
            ):
                raise AssuranceVerifierRegistryError()
            copied[verifier_id] = identity_sha256
        self._identities = copied

    @classmethod
    def deny_all(cls) -> AssuranceVerifierRegistry:
        return cls({})

    def bind(self, verifier_id: str, supplied_sha256: str) -> str:
        if (
            type(verifier_id) is not str
            or type(supplied_sha256) is not str
            or _SHA256.fullmatch(supplied_sha256) is None
        ):
            raise AssuranceVerifierRegistryError()

        expected = self._identities.get(verifier_id)
        if expected is None or not hmac.compare_digest(expected, supplied_sha256):
            raise AssuranceVerifierRegistryError()
        return expected


def load_assurance_verifier_registry(
    environment: Mapping[str, str],
) -> AssuranceVerifierRegistry:
    """Load one strict registry source, or return a deny-all registry."""

    if not isinstance(environment, Mapping):
        raise AssuranceVerifierRegistryError()

    inline = environment.get(_INLINE_ENV)
    file_name = environment.get(_FILE_ENV)
    if inline is not None and file_name is not None:
        raise AssuranceVerifierRegistryError()
    if inline is None and file_name is None:
        return AssuranceVerifierRegistry.deny_all()

    if inline is not None:
        document = _inline_document(inline)
    else:
        if type(file_name) is not str or not file_name:
            raise AssuranceVerifierRegistryError()
        try:
            document = read_json_object(Path(file_name), _MAX_CONFIG_BYTES)
        except (OSError, ValueError):
            raise AssuranceVerifierRegistryError() from None
    return AssuranceVerifierRegistry(_string_mapping(document))


def _inline_document(value: object) -> dict[str, object]:
    if type(value) is not str:
        raise AssuranceVerifierRegistryError()
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise AssuranceVerifierRegistryError() from None
    if not 1 <= len(encoded) <= _MAX_CONFIG_BYTES:
        raise AssuranceVerifierRegistryError()

    def reject_duplicate_keys(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, item in pairs:
            if key in document:
                raise AssuranceVerifierRegistryError()
            document[key] = item
        return document

    try:
        document = json.loads(
            value,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(AssuranceVerifierRegistryError()),
        )
    except (
        AssuranceVerifierRegistryError,
        json.JSONDecodeError,
        RecursionError,
        UnicodeError,
    ):
        raise AssuranceVerifierRegistryError() from None
    if type(document) is not dict:
        raise AssuranceVerifierRegistryError()
    return document


def _string_mapping(document: dict[str, object]) -> dict[str, str]:
    if len(document) > _MAX_VERIFIERS:
        raise AssuranceVerifierRegistryError()

    values: dict[str, str] = {}
    for key, value in document.items():
        if type(key) is not str or type(value) is not str:
            raise AssuranceVerifierRegistryError()
        values[key] = value
    return values


__all__ = [
    "AssuranceVerifierRegistry",
    "AssuranceVerifierRegistryError",
    "load_assurance_verifier_registry",
]
