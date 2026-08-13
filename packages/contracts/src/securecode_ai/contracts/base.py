"""Closed, version-aware primitives shared by SecureCode AI wire contracts."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Final, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

CONTRACT_SCHEMA_VERSION: Final = "0.2.0"
CONTRACT_SCHEMA_MAJOR: Final = 0
CONTRACT_SCHEMA_MINIMUM: Final = (0, 2, 0)

_SEMVER_PATTERN: Final = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")

SemVer = Annotated[str, StringConstraints(pattern=_SEMVER_PATTERN.pattern, max_length=64)]
OpaqueId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
CommitSha = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
ReasonCode = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{1,63}$", max_length=64),
]


class DataClass(StrEnum):
    """Information classification labels; labels are not the classified content."""

    PUBLIC = "DC0_PUBLIC"
    INTERNAL_METADATA = "DC1_INTERNAL_METADATA"
    CONFIDENTIAL_SECURITY = "DC2_CONFIDENTIAL_SECURITY"
    CONFIDENTIAL_SOURCE = "DC3_CONFIDENTIAL_SOURCE"
    RESTRICTED = "DC4_RESTRICTED"


class ExtensionDataClass(StrEnum):
    """Classes permitted inside the ordinary extension envelope."""

    PUBLIC = "DC0_PUBLIC"
    INTERNAL_METADATA = "DC1_INTERNAL_METADATA"
    CONFIDENTIAL_SECURITY = "DC2_CONFIDENTIAL_SECURITY"


class ClosedModel(BaseModel):
    """Trust-boundary base: immutable and closed to unknown fields."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class ContractExtension(ClosedModel):
    """Metadata-only preservation envelope for additive same-major data."""

    namespace: OpaqueId
    extension_version: SemVer
    data_class: ExtensionDataClass
    tenant_id: OpaqueId
    content_id: OpaqueId
    payload_sha256: Sha256
    payload_size_bytes: int = Field(ge=0, le=9_007_199_254_740_991)


class WireModel(ClosedModel):
    """Base for versioned nested and root wire objects."""

    schema_version: SemVer
    extensions: tuple[ContractExtension, ...] = Field(default=(), max_length=32)

    @field_validator("extensions")
    @classmethod
    def _canonicalize_extensions(
        cls, value: tuple[ContractExtension, ...]
    ) -> tuple[ContractExtension, ...]:
        return tuple(sorted(value, key=lambda extension: extension.namespace))

    @model_validator(mode="after")
    def _validate_wire_version(self) -> Self:
        match = _SEMVER_PATTERN.fullmatch(self.schema_version)
        if match is None:  # pragma: no cover - the field pattern rejects this first
            raise ValueError("schema_version must be semantic version syntax")
        version = tuple(int(match.group(index)) for index in (1, 2, 3))
        if version[0] != CONTRACT_SCHEMA_MAJOR:
            raise ValueError("unsupported contract schema major version")
        if version < CONTRACT_SCHEMA_MINIMUM:
            raise ValueError("contract schema version predates the supported baseline")
        namespaces = [extension.namespace for extension in self.extensions]
        if len(namespaces) != len(set(namespaces)):
            raise ValueError("extension namespaces must be unique")
        return self
