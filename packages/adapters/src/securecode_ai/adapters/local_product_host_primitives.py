"""Protected administrative host admission for installed local Core scans."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Final, NoReturn

_MAX_ANCHOR_VALUE_BYTES: Final = 1_048_576
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_WINDOWS_HKLM: Final = -2147483646  # Native LONG_PTR sign extension of predefined HKEY.
_WINDOWS_KEY_READ_64: Final = 0x00020019 | 0x0100
_WINDOWS_ERROR_SUCCESS: Final = 0
_WINDOWS_REG_BINARY: Final = 3
_WINDOWS_OWNER_SECURITY_INFORMATION: Final = 0x00000001
_WINDOWS_DACL_SECURITY_INFORMATION: Final = 0x00000004
_WINDOWS_SE_REGISTRY_KEY: Final = 4
_WINDOWS_ACCESS_ALLOWED_ACE_TYPE: Final = 0
_WINDOWS_SENSITIVE_ACCESS: Final = (
    0x00000002 | 0x00000004 | 0x00010000 | 0x00040000 | 0x00080000 | 0x10000000 | 0x40000000
)
_WINDOWS_TRUSTED_OWNERS: Final = frozenset(
    {
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    }
)
_WINDOWS_LOW_TRUST_SIDS: Final = frozenset(
    {"S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-4", "S-1-5-32-545"}
)
_ANCHOR_KEYS: Final = frozenset(
    {
        "schema_version",
        "approved_profile",
        "policy",
        "bundle",
        "pins",
        "profile_sha256",
        "policy_sha256",
        "bundle_sha256",
    }
)
_MANIFEST_KEYS: Final = frozenset(
    {
        "workflow_sha256",
        "stage_catalogue_sha256",
        "discovery_prompt_sha256",
        "auditor_prompt_sha256",
        "skeptic_prompt_sha256",
        "skeptic_schema_sha256",
        "git_executable_sha256",
    }
)


class LocalProductHostError(ValueError):
    """Closed source-free installed-host refusal."""

    def __init__(self) -> None:
        super().__init__("local product host approval is unavailable")


def _reject() -> NoReturn:
    raise LocalProductHostError()


def _closed_object(pairs: list[tuple[object, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if type(key) is not str or key in value or "\x00" in key:
            _reject()
        _assert_no_nul(item)
        value[key] = item
    return value


def _assert_no_nul(value: object) -> None:
    if isinstance(value, str) and "\x00" in value:
        _reject()
    if isinstance(value, (list, tuple)):
        for item in value:
            _assert_no_nul(item)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class _ProtectedAnchor:
    approval_record: bytes
    approval_record_sha256: str
    artifact_manifest: bytes
    artifact_manifest_sha256: str


def _parse_record(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > _MAX_ANCHOR_VALUE_BYTES or b"\x00" in raw:
        _reject()
    try:
        record = json.loads(raw.decode("utf-8"), object_pairs_hook=_closed_object)
        if type(record) is not dict or set(record) != _ANCHOR_KEYS:
            _reject()
        if record["schema_version"] != "1.0.0":
            _reject()
        for name in ("profile_sha256", "policy_sha256", "bundle_sha256"):
            if type(record[name]) is not str or _SHA256.fullmatch(record[name]) is None:
                _reject()
        return record
    except (TypeError, UnicodeError, ValueError, json.JSONDecodeError):
        _reject()


def _parse_manifest(raw: bytes) -> dict[str, str]:
    if type(raw) is not bytes or not raw or len(raw) > _MAX_ANCHOR_VALUE_BYTES or b"\x00" in raw:
        _reject()
    try:
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=_closed_object)
        if type(manifest) is not dict or set(manifest) != _MANIFEST_KEYS:
            _reject()
        if any(
            type(value) is not str or _SHA256.fullmatch(value) is None
            for value in manifest.values()
        ):
            _reject()
        return dict(manifest)
    except (TypeError, UnicodeError, ValueError, json.JSONDecodeError):
        _reject()
