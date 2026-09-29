"""Load host-owned revalidation pins for assurance reports.

The report endpoint deliberately has no pin fields in its request.  This
module is the server-side composition point for the two pin snapshots used by
the report: the pins recorded for an exact execution identity and the pins
currently accepted by the deployment.  The source is a protected, bounded
JSON file and is re-read for every resolution so a controlled configuration
rotation takes effect without accepting self-attested request data.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Final

from .assurance_reports import (
    AssurancePinsProvider,
    UnavailableAssurancePinsProvider,
)
from .revalidation import CurrentPins
from .secure_files import read_json_object

_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_PIN_VALUE: Final = re.compile(r"[\x21-\x7e]{1,256}\Z")
_PIN_NAMES: Final = ("source", "policy", "dependency", "environment", "operational")
_PIN_NAME_SET: Final = frozenset(_PIN_NAMES)
_SHARED_ENTRY_KEYS: Final = frozenset(
    {"repository_id", "execution_identity_hash", "recorded", "current"}
)
_TENANT_ENTRY_KEYS: Final = frozenset(
    {"tenant_id", "repository_id", "execution_identity_hash", "recorded", "current"}
)
_MAX_SOURCE_BYTES: Final = 1_048_576
_MAX_ENTRIES: Final = 256


class AssurancePinsConfigurationError(ValueError):
    """The protected assurance-pins source is absent or malformed."""


class FileAssurancePinsProvider:
    """Resolve immutable tenant scope keys from a protected pins file."""

    __slots__ = ("_expected_tenant", "_path")

    def __init__(self, path: Path, *, tenant_id: str | None = None) -> None:
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or ".." in path.parts
            or (tenant_id is not None and not _identifier(tenant_id))
        ):
            raise AssurancePinsConfigurationError()
        self._path = path
        self._expected_tenant = tenant_id
        self._load()

    def resolve(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        execution_identity_hash: str,
    ) -> tuple[CurrentPins, CurrentPins] | None:
        if (
            not _identifier(tenant_id)
            or not _identifier(repository_id)
            or not _sha256(execution_identity_hash)
        ):
            raise AssurancePinsConfigurationError()
        entries = self._load()
        return entries.get((tenant_id, repository_id, execution_identity_hash))

    def _load(
        self,
    ) -> Mapping[tuple[str, str, str], tuple[CurrentPins, CurrentPins]]:
        try:
            document = read_json_object(self._path, _MAX_SOURCE_BYTES)
        except (OSError, TypeError, ValueError):
            raise AssurancePinsConfigurationError() from None
        keys = set(document)
        if keys not in (
            {"schema_version", "entries"},
            {"schema_version", "tenant_id", "entries"},
        ):
            raise AssurancePinsConfigurationError()
        if document["schema_version"] != 1:
            raise AssurancePinsConfigurationError()
        inherited_tenant = document.get("tenant_id")
        if keys == {"schema_version", "tenant_id", "entries"} and not _identifier(inherited_tenant):
            raise AssurancePinsConfigurationError()
        if (
            inherited_tenant is not None
            and self._expected_tenant is not None
            and inherited_tenant != self._expected_tenant
        ):
            raise AssurancePinsConfigurationError()
        raw_entries = document["entries"]
        if type(raw_entries) is not list or not 1 <= len(raw_entries) <= _MAX_ENTRIES:
            raise AssurancePinsConfigurationError()
        entries: dict[tuple[str, str, str], tuple[CurrentPins, CurrentPins]] = {}
        for raw_entry in raw_entries:
            if type(raw_entry) is not dict:
                raise AssurancePinsConfigurationError()
            entry_keys = set(raw_entry)
            if inherited_tenant is None:
                if entry_keys != _TENANT_ENTRY_KEYS:
                    raise AssurancePinsConfigurationError()
                tenant_id = raw_entry["tenant_id"]
            else:
                if entry_keys != _SHARED_ENTRY_KEYS:
                    raise AssurancePinsConfigurationError()
                tenant_id = inherited_tenant
            if not _identifier(tenant_id):
                raise AssurancePinsConfigurationError()
            repository_id = raw_entry["repository_id"]
            identity_hash = raw_entry["execution_identity_hash"]
            if not _identifier(repository_id) or not _sha256(identity_hash):
                raise AssurancePinsConfigurationError()
            key = (tenant_id, repository_id, identity_hash)
            if key in entries:
                raise AssurancePinsConfigurationError()
            entries[key] = (
                _current_pins(raw_entry["recorded"]),
                _current_pins(raw_entry["current"]),
            )
        return MappingProxyType(entries)


def build_assurance_pins_provider(
    values: Mapping[str, str],
    *,
    tenant_id: str | None = None,
) -> AssurancePinsProvider:
    """Compose the host-owned provider, or an explicit fail-closed provider."""

    if not isinstance(values, Mapping) or (tenant_id is not None and not _identifier(tenant_id)):
        raise AssurancePinsConfigurationError()
    raw_path = values.get("SECURECODE_ASSURANCE_PINS_FILE")
    if raw_path is None:
        return UnavailableAssurancePinsProvider()
    if type(raw_path) is not str or not raw_path:
        raise AssurancePinsConfigurationError()
    try:
        return FileAssurancePinsProvider(Path(raw_path), tenant_id=tenant_id)
    except (OSError, TypeError, ValueError):
        raise AssurancePinsConfigurationError() from None


def _current_pins(value: object) -> CurrentPins:
    if type(value) is not dict or set(value) != _PIN_NAME_SET:
        raise AssurancePinsConfigurationError()
    pin_values = tuple(value[name] for name in _PIN_NAMES)
    if any(type(pin) is not str or _PIN_VALUE.fullmatch(pin) is None for pin in pin_values):
        raise AssurancePinsConfigurationError()
    return CurrentPins(*pin_values)


def _identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


__all__ = [
    "AssurancePinsConfigurationError",
    "FileAssurancePinsProvider",
    "build_assurance_pins_provider",
]
