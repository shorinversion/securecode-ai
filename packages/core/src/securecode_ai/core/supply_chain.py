"""Canonical source-free SBOM policy boundary."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Final

_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_VULNERABILITY_STATES: Final = frozenset({"resolved", "unresolved", "unknown"})
_MAX_TEXT: Final = 512


class SupplyChainConflict(ValueError):
    """A dependency manifest cannot be admitted under the supplied policy."""

    def __init__(self, reason: str = "supply chain evidence was rejected") -> None:
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class SbomComponent:
    name: str
    version: str
    license: str | None
    source: str
    content_sha256: str
    vulnerability_status: str = "unknown"

    def __post_init__(self) -> None:
        if any(not _safe_text(value) for value in (self.name, self.version, self.source)):
            raise ValueError("component identity is invalid")
        if self.license is not None and not _safe_text(self.license):
            raise ValueError("component license is invalid")
        if type(self.content_sha256) is not str or _SHA256.fullmatch(self.content_sha256) is None:
            raise ValueError("component digest is invalid")
        if self.vulnerability_status not in _VULNERABILITY_STATES:
            raise ValueError("component vulnerability status is invalid")


@dataclass(frozen=True, slots=True)
class DependencyPolicy:
    allowed_licenses: frozenset[str]
    denied_names: frozenset[str]

    def __post_init__(self) -> None:
        if (
            type(self.allowed_licenses) is not frozenset
            or not self.allowed_licenses
            or any(not _safe_text(value) for value in self.allowed_licenses)
            or type(self.denied_names) is not frozenset
            or any(not _safe_text(value) for value in self.denied_names)
        ):
            raise ValueError("dependency policy is invalid")

    def permits(self, item: SbomComponent) -> bool:
        return (
            type(item) is SbomComponent
            and item.name not in self.denied_names
            and item.license is not None
            and item.license in self.allowed_licenses
            and item.vulnerability_status == "resolved"
        )


def canonical_sbom(
    components: tuple[SbomComponent, ...],
    policy: DependencyPolicy,
) -> bytes:
    """Validate policy admission and serialize all security-relevant fields."""
    if type(components) is not tuple or not components:
        raise SupplyChainConflict("SBOM is empty")
    if type(policy) is not DependencyPolicy:
        raise SupplyChainConflict("dependency policy is invalid")
    if any(type(component) is not SbomComponent for component in components):
        raise SupplyChainConflict("SBOM component type is invalid")
    identities = [(item.name, item.version) for item in components]
    if len(set(identities)) != len(identities):
        raise SupplyChainConflict("SBOM contains duplicate components")
    if any(not policy.permits(component) for component in components):
        raise SupplyChainConflict("SBOM violates dependency policy")
    document = [
        {
            "content_sha256": component.content_sha256,
            "license": component.license,
            "name": component.name,
            "source": component.source,
            "version": component.version,
            "vulnerability_status": component.vulnerability_status,
        }
        for component in sorted(
            components,
            key=lambda value: (value.name, value.version, value.source),
        )
    ]
    return json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _safe_text(value: object) -> bool:
    return (
        type(value) is str
        and value == value.strip()
        and 0 < len(value) <= _MAX_TEXT
        and all(ord(character) >= 0x20 and character != "\x7f" for character in value)
    )


__all__ = [
    "DependencyPolicy",
    "SbomComponent",
    "SupplyChainConflict",
    "canonical_sbom",
]
