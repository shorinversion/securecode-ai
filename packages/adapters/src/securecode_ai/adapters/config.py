"""Secret-safe configuration and credential adapters."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final, Self, SupportsIndex

from securecode_ai.core import EgressProfileId, ProviderProfile

_MAX_PROFILE_BYTES: Final = 1024 * 1024
_MAX_CREDENTIAL_BYTES: Final = 64 * 1024
_SAFE_ID: Final = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_PROFILE_SELECTOR: Final = re.compile(
    r"^(?P<id>[a-z0-9][a-z0-9._-]{2,63})@(?P<version>(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))$"
)
_ENV_SELECTION_KEYS: Final = {
    "SECURECODE_PROVIDER_PROFILE": "provider_profile",
    "SECURECODE_POLICY_PROFILE": "policy_profile",
    "SECURECODE_EGRESS_PROFILE": "egress_profile",
}
_SELECTION_KEYS: Final = frozenset(_ENV_SELECTION_KEYS.values())
_SECURITY_FIELD_MARKERS: Final = (
    "api_key",
    "api_dialect",
    "base_url",
    "budget",
    "capabilit",
    "credential",
    "data_terms",
    "endpoint",
    "model",
    "password",
    "provider_kind",
    "secret",
    "token",
)


class ConfigSource(StrEnum):
    DEFAULTS = "defaults"
    USER = "user"
    REPOSITORY = "repository"
    ENVIRONMENT = "environment"
    CLI = "cli"
    APPROVED_REGISTRY = "approved_registry"


class ConfigDiagnosticCode(StrEnum):
    INVALID_PROFILE = "INVALID_PROFILE"
    IMMUTABLE_PROFILE_CONFLICT = "IMMUTABLE_PROFILE_CONFLICT"
    UNKNOWN_PROFILE = "UNKNOWN_PROFILE"
    UNKNOWN_CONFIG_KEY = "UNKNOWN_CONFIG_KEY"
    SECURITY_FIELD_OVERRIDE = "SECURITY_FIELD_OVERRIDE"
    INVALID_CONFIG_VALUE = "INVALID_CONFIG_VALUE"
    MISSING_CONFIG_VALUE = "MISSING_CONFIG_VALUE"
    UNSUPPORTED_EGRESS_PROFILE = "UNSUPPORTED_EGRESS_PROFILE"
    MISSING_CREDENTIAL = "MISSING_CREDENTIAL"
    INVALID_CREDENTIAL = "INVALID_CREDENTIAL"
    UNSUPPORTED_CREDENTIAL_BACKEND = "UNSUPPORTED_CREDENTIAL_BACKEND"
    CREDENTIAL_SCOPE_MISMATCH = "CREDENTIAL_SCOPE_MISMATCH"
    CREDENTIAL_CLOSED = "CREDENTIAL_CLOSED"


@dataclass(frozen=True, slots=True)
class ConfigDiagnostic:
    code: ConfigDiagnosticCode
    source: ConfigSource
    field: str
    safe_message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code.value,
            "source": self.source.value,
            "field": self.field,
            "safe_message": self.safe_message,
        }


class ConfigError(ValueError):
    def __init__(self, *diagnostics: ConfigDiagnostic) -> None:
        if not diagnostics:
            raise ValueError("ConfigError requires at least one safe diagnostic")
        self.diagnostics = tuple(diagnostics)
        super().__init__("; ".join(item.safe_message for item in diagnostics))

    def as_dict(self) -> dict[str, object]:
        return {"diagnostics": [item.as_dict() for item in self.diagnostics]}


def _diagnostic(
    code: ConfigDiagnosticCode,
    source: ConfigSource,
    field: str,
    message: str,
) -> ConfigError:
    return ConfigError(ConfigDiagnostic(code, source, field, message))


def _closed_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def parse_provider_profile(data: str | bytes) -> ProviderProfile:
    """Parse untrusted profile bytes without ever echoing their content."""

    try:
        encoded = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        if not encoded or len(encoded) > _MAX_PROFILE_BYTES or b"\x00" in encoded:
            raise ValueError("profile byte envelope is invalid")
        raw = json.loads(encoded.decode("utf-8"), object_pairs_hook=_closed_json_object)
        if not isinstance(raw, dict):
            raise ValueError("profile root is not an object")
        return ProviderProfile.model_validate(raw)
    except (RecursionError, UnicodeError, TypeError, ValueError):
        raise _diagnostic(
            ConfigDiagnosticCode.INVALID_PROFILE,
            ConfigSource.APPROVED_REGISTRY,
            "provider_profile",
            "provider profile failed closed validation",
        ) from None


class ProviderProfileRegistry:
    """Immutable exact-version registry; lower-trust config selects from it."""

    __slots__ = ("_hashes", "_profiles")

    _IMMUTABLE_STORAGE_FIELDS: Final = frozenset({"_hashes", "_profiles"})

    def __setattr__(self, name: str, value: object) -> None:
        if name in self._IMMUTABLE_STORAGE_FIELDS and hasattr(self, name):
            raise AttributeError("provider profile registry storage is immutable")
        object.__setattr__(self, name, value)

    def __init__(self, profiles: Iterable[ProviderProfile]) -> None:
        registered: dict[str, bytes] = {}
        hashes: dict[str, str] = {}
        for supplied in profiles:
            try:
                profile = ProviderProfile.model_validate(supplied.model_dump(mode="python"))
            except (AttributeError, TypeError, ValueError):
                raise _diagnostic(
                    ConfigDiagnosticCode.INVALID_PROFILE,
                    ConfigSource.APPROVED_REGISTRY,
                    "provider_profile",
                    "provider profile failed closed validation",
                ) from None
            selector = profile.selector
            content_hash = profile.canonical_content_hash()
            if selector in hashes and hashes[selector] != content_hash:
                raise _diagnostic(
                    ConfigDiagnosticCode.IMMUTABLE_PROFILE_CONFLICT,
                    ConfigSource.APPROVED_REGISTRY,
                    "provider_profile",
                    "an immutable provider profile version has conflicting content",
                )
            registered[selector] = json.dumps(
                profile.model_dump(mode="json"),
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            hashes[selector] = content_hash
        self._profiles = MappingProxyType(registered)
        self._hashes = MappingProxyType(hashes)

    def select(self, selector: str) -> ProviderProfile:
        if not isinstance(selector, str) or not _PROFILE_SELECTOR.fullmatch(selector):
            raise _diagnostic(
                ConfigDiagnosticCode.INVALID_CONFIG_VALUE,
                ConfigSource.APPROVED_REGISTRY,
                "provider_profile",
                "provider profile selector is invalid",
            )
        try:
            encoded = self._profiles[selector]
        except KeyError:
            raise _diagnostic(
                ConfigDiagnosticCode.UNKNOWN_PROFILE,
                ConfigSource.APPROVED_REGISTRY,
                "provider_profile",
                "selected provider profile is not approved",
            ) from None
        try:
            profile = ProviderProfile.model_validate_json(encoded)
        except (TypeError, ValueError):
            raise _diagnostic(
                ConfigDiagnosticCode.INVALID_PROFILE,
                ConfigSource.APPROVED_REGISTRY,
                "provider_profile",
                "approved provider profile failed integrity validation",
            ) from None
        if profile.canonical_content_hash() != self._hashes[selector]:
            raise _diagnostic(
                ConfigDiagnosticCode.IMMUTABLE_PROFILE_CONFLICT,
                ConfigSource.APPROVED_REGISTRY,
                "provider_profile",
                "approved provider profile failed integrity validation",
            )
        return profile

    def require_registered(self, supplied: ProviderProfile) -> ProviderProfile:
        """Return registry-owned bytes only when selector and content both match."""

        try:
            candidate = ProviderProfile.model_validate(supplied.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError):
            raise _diagnostic(
                ConfigDiagnosticCode.INVALID_PROFILE,
                ConfigSource.APPROVED_REGISTRY,
                "provider_profile",
                "provider profile failed closed validation",
            ) from None
        approved = self.select(candidate.selector)
        if candidate.canonical_content_hash() != approved.canonical_content_hash():
            raise _diagnostic(
                ConfigDiagnosticCode.IMMUTABLE_PROFILE_CONFLICT,
                ConfigSource.APPROVED_REGISTRY,
                "provider_profile",
                "provider profile content does not match the approved immutable version",
            )
        return approved

    def safe_inventory(self) -> tuple[dict[str, str], ...]:
        return tuple(
            {
                "selector": selector,
                "content_sha256": self._hashes[selector],
            }
            for selector in sorted(self._profiles)
        )


@dataclass(frozen=True, slots=True)
class SelectionProvenance:
    key: str
    source: ConfigSource


@dataclass(frozen=True, slots=True)
class EffectiveConfiguration:
    provider_profile: ProviderProfile
    policy_profile_id: str
    egress_profile: EgressProfileId
    provenance: tuple[SelectionProvenance, ...]

    def safe_snapshot(self) -> dict[str, object]:
        return {
            "provider_profile": self.provider_profile.selector,
            "provider_profile_sha256": self.provider_profile.canonical_content_hash(),
            "credential_ref": self.provider_profile.credential_ref,
            "policy_profile": self.policy_profile_id,
            "egress_profile": self.egress_profile.value,
            "provenance": {
                item.key: item.source.value
                for item in sorted(self.provenance, key=lambda item: item.key)
            },
        }

    def canonical_content_hash(self) -> str:
        payload = json.dumps(
            self.safe_snapshot(),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


def _validate_selection_layer(
    values: Mapping[str, object],
    source: ConfigSource,
) -> dict[str, str]:
    if any(not isinstance(key, str) for key in values):
        raise _diagnostic(
            ConfigDiagnosticCode.UNKNOWN_CONFIG_KEY,
            source,
            "configuration",
            "configuration contains an unknown key",
        )
    normalized: dict[str, str] = {}
    for key in sorted(values):
        lowered = key.lower()
        if any(marker in lowered for marker in _SECURITY_FIELD_MARKERS):
            raise _diagnostic(
                ConfigDiagnosticCode.SECURITY_FIELD_OVERRIDE,
                source,
                "provider_security_fields",
                "provider security fields and secrets cannot be overridden by this layer",
            )
        if key not in _SELECTION_KEYS:
            raise _diagnostic(
                ConfigDiagnosticCode.UNKNOWN_CONFIG_KEY,
                source,
                "configuration",
                "configuration contains an unknown key",
            )
        value = values[key]
        if not isinstance(value, str) or not value or value != value.strip() or len(value) > 256:
            raise _diagnostic(
                ConfigDiagnosticCode.INVALID_CONFIG_VALUE,
                source,
                key,
                "configuration selection value is invalid",
            )
        normalized[key] = value
    return normalized


def _environment_selection(environment: Mapping[str, str]) -> dict[str, str]:
    if any(
        isinstance(key, str) and key.upper().startswith("SECURECODE_LLM_") for key in environment
    ):
        raise _diagnostic(
            ConfigDiagnosticCode.SECURITY_FIELD_OVERRIDE,
            ConfigSource.ENVIRONMENT,
            "provider_security_fields",
            "provider URL, model, budgets and credentials come only from the approved profile",
        )
    return {
        selection_key: environment[env_key]
        for env_key, selection_key in _ENV_SELECTION_KEYS.items()
        if env_key in environment
    }


def resolve_configuration(
    *,
    registry: ProviderProfileRegistry,
    defaults: Mapping[str, object],
    user: Mapping[str, object] | None = None,
    repository: Mapping[str, object] | None = None,
    environment: Mapping[str, str] | None = None,
    cli: Mapping[str, object] | None = None,
) -> EffectiveConfiguration:
    """Resolve the frozen CLI precedence using selection-only lower-trust layers."""

    layers = (
        (ConfigSource.DEFAULTS, defaults),
        (ConfigSource.USER, user or {}),
        (ConfigSource.REPOSITORY, repository or {}),
        (ConfigSource.ENVIRONMENT, _environment_selection(environment or {})),
        (ConfigSource.CLI, cli or {}),
    )
    selected: dict[str, str] = {}
    selected_sources: dict[str, ConfigSource] = {}
    for source, raw_layer in layers:
        layer = _validate_selection_layer(raw_layer, source)
        for key, value in layer.items():
            selected[key] = value
            selected_sources[key] = source
    missing = sorted(_SELECTION_KEYS - selected.keys())
    if missing:
        raise ConfigError(
            *(
                ConfigDiagnostic(
                    ConfigDiagnosticCode.MISSING_CONFIG_VALUE,
                    ConfigSource.DEFAULTS,
                    field,
                    "required configuration selection is missing",
                )
                for field in missing
            )
        )

    profile = registry.select(selected["provider_profile"])
    try:
        egress = EgressProfileId(selected["egress_profile"])
    except ValueError:
        raise _diagnostic(
            ConfigDiagnosticCode.INVALID_CONFIG_VALUE,
            selected_sources["egress_profile"],
            "egress_profile",
            "selected egress profile is invalid",
        ) from None
    if egress not in profile.egress_profiles:
        raise _diagnostic(
            ConfigDiagnosticCode.UNSUPPORTED_EGRESS_PROFILE,
            selected_sources["egress_profile"],
            "egress_profile",
            "selected egress profile is not supported by the provider profile",
        )
    policy_profile = selected["policy_profile"]
    if not _SAFE_ID.fullmatch(policy_profile):
        raise _diagnostic(
            ConfigDiagnosticCode.INVALID_CONFIG_VALUE,
            selected_sources["policy_profile"],
            "policy_profile",
            "selected policy profile is invalid",
        )
    return EffectiveConfiguration(
        provider_profile=profile,
        policy_profile_id=policy_profile,
        egress_profile=egress,
        provenance=tuple(
            SelectionProvenance(key, selected_sources[key]) for key in sorted(selected_sources)
        ),
    )


class CredentialLease:
    """Ephemeral, host-bound secret buffer that refuses rendering and serialization."""

    __slots__ = ("_authority", "_buffer", "_closed", "_profile_selector", "_reference")

    _IMMUTABLE_SCOPE_FIELDS: Final = frozenset({"_authority", "_profile_selector", "_reference"})

    def __setattr__(self, name: str, value: object) -> None:
        if name in self._IMMUTABLE_SCOPE_FIELDS and hasattr(self, name):
            raise AttributeError("credential lease scope is immutable")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        value: str,
        profile: ProviderProfile,
        registry: ProviderProfileRegistry,
    ) -> None:
        profile = registry.require_registered(profile)
        if profile.credential_ref is None:
            raise ValueError("credential lease requires a credential reference")
        try:
            encoded = value.encode("utf-8")
        except (AttributeError, UnicodeError):
            raise _diagnostic(
                ConfigDiagnosticCode.INVALID_CREDENTIAL,
                ConfigSource.ENVIRONMENT,
                "credential_ref",
                "environment credential is invalid",
            ) from None
        if (
            not encoded
            or len(encoded) > _MAX_CREDENTIAL_BYTES
            or value.isspace()
            or any(byte in {0, 10, 13} for byte in encoded)
        ):
            raise _diagnostic(
                ConfigDiagnosticCode.INVALID_CREDENTIAL,
                ConfigSource.ENVIRONMENT,
                "credential_ref",
                "environment credential is invalid",
            )
        self._buffer = bytearray(encoded)
        self._closed = False
        self._authority = profile.endpoint.authority
        self._profile_selector = profile.selector
        self._reference = profile.credential_ref

    @property
    def authority(self) -> str:
        return self._authority

    @property
    def profile_selector(self) -> str:
        return self._profile_selector

    @property
    def reference(self) -> str:
        return self._reference

    def __repr__(self) -> str:
        return "CredentialLease(<redacted>)"

    __str__ = __repr__

    def __copy__(self) -> Self:
        raise TypeError("credential leases cannot be copied")

    def __deepcopy__(self, memo: object) -> Self:
        del memo
        raise TypeError("credential leases cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        del protocol
        raise TypeError("credential leases cannot be serialized")

    def safe_snapshot(self) -> dict[str, object]:
        return {
            "profile": self.profile_selector,
            "authority": self.authority,
            "credential_ref": self.reference,
            "closed": self._closed,
            "value": "<redacted>",
        }

    def reveal_for(self, *, profile_selector: str, authority: str) -> str:
        if self._closed:
            raise _diagnostic(
                ConfigDiagnosticCode.CREDENTIAL_CLOSED,
                ConfigSource.ENVIRONMENT,
                "credential_ref",
                "credential lease is closed",
            )
        if profile_selector != self.profile_selector or authority.lower() != self.authority:
            raise _diagnostic(
                ConfigDiagnosticCode.CREDENTIAL_SCOPE_MISMATCH,
                ConfigSource.ENVIRONMENT,
                "credential_ref",
                "credential is not authorized for the requested profile and authority",
            )
        return self._buffer.decode("utf-8")

    def close(self) -> None:
        for index in range(len(self._buffer)):
            self._buffer[index] = 0
        self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


def resolve_environment_credential(
    profile: ProviderProfile,
    environment: Mapping[str, str],
    *,
    registry: ProviderProfileRegistry,
) -> CredentialLease | None:
    approved_profile = registry.require_registered(profile)
    reference = approved_profile.credential_ref
    if reference is None:
        return None
    scheme, _, name = reference.partition("://")
    if scheme != "env":
        raise _diagnostic(
            ConfigDiagnosticCode.UNSUPPORTED_CREDENTIAL_BACKEND,
            ConfigSource.ENVIRONMENT,
            "credential_ref",
            "credential backend is not available in this runtime",
        )
    value = environment.get(name)
    if value is None:
        raise _diagnostic(
            ConfigDiagnosticCode.MISSING_CREDENTIAL,
            ConfigSource.ENVIRONMENT,
            "credential_ref",
            "required environment credential is unavailable",
        )
    return CredentialLease(value=value, profile=approved_profile, registry=registry)


__all__ = [
    "ConfigDiagnostic",
    "ConfigDiagnosticCode",
    "ConfigError",
    "ConfigSource",
    "CredentialLease",
    "EffectiveConfiguration",
    "ProviderProfileRegistry",
    "SelectionProvenance",
    "parse_provider_profile",
    "resolve_configuration",
    "resolve_environment_credential",
]
