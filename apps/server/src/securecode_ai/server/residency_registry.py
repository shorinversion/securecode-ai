"""Durable tenant residency profiles and fail-closed transfer decisions.

The provider profile carries the provider's declared residency terms, while
this module stores the tenant's own placement policy.  Keeping the two
profiles separate prevents a provider declaration from being mistaken for a
tenant authorization.  A transfer is permitted only when both endpoints are
in the tenant allowlist and the operation is explicitly same-region.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Protocol

from .residency import ResidencyDenied, ResidencyProfile, require_transfer

_SCHEMA_VERSION: Final = 1
_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")

RESIDENCY_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS tenant_residency_profiles (
        tenant_id TEXT NOT NULL PRIMARY KEY,
        version INTEGER NOT NULL CHECK (version >= 1),
        regions_json TEXT NOT NULL,
        profile_sha256 TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )""",
)


class ResidencyConflict(RuntimeError):
    """A residency profile or placement decision is invalid or stale."""


@dataclass(frozen=True, slots=True)
class ResidencyDecision:
    """Source-free proof of one placement authorization."""

    tenant_id: str
    source_region: str
    destination_region: str
    profile_sha256: str
    profile_version: int
    same_region: bool

    def __post_init__(self) -> None:
        if (
            type(self.profile_sha256) is not str
            or len(self.profile_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.profile_sha256)
            or type(self.profile_version) is not int
            or self.profile_version < 1
            or type(self.same_region) is not bool
        ):
            raise ResidencyConflict("residency decision is invalid")
        _require_identifier(self.tenant_id)
        _require_region(self.source_region)
        _require_region(self.destination_region)
        if self.same_region != (self.source_region == self.destination_region):
            raise ResidencyConflict("residency decision region relationship is invalid")

    def document(self) -> dict[str, object]:
        return {
            "destination_region": self.destination_region,
            "profile_sha256": self.profile_sha256,
            "profile_version": self.profile_version,
            "same_region": self.same_region,
            "source_region": self.source_region,
            "tenant_id": self.tenant_id,
        }


class ResidencyGuard(Protocol):
    """Minimal port for services that persist data in a region."""

    def require_region(self, *, tenant_id: str, region: str) -> ResidencyDecision: ...


class SqliteResidencyRegistry:
    """SQLite-backed tenant allowlists with optimistic profile updates."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        deployment_region: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        if deployment_region is not None:
            _require_region(deployment_region)
        self._db = connection
        self._db.row_factory = sqlite3.Row
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self._configured_tenants: frozenset[str] | None = None
        self._deployment_region = deployment_region
        self._initialize_schema()

    def set_profile(
        self,
        profile: ResidencyProfile,
        *,
        expected_version: int | None = None,
    ) -> ResidencyProfile:
        if type(profile) is not ResidencyProfile:
            raise ResidencyConflict("residency profile is invalid")
        if expected_version is not None and (
            type(expected_version) is not int or expected_version < 1
        ):
            raise ResidencyConflict("residency profile version is invalid")
        profile_hash = _profile_hash(profile)
        with self._lock:
            cursor = self._db.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                row = cursor.execute(
                    """SELECT version, profile_sha256, regions_json
                       FROM tenant_residency_profiles WHERE tenant_id=?""",
                    (profile.tenant_id,),
                ).fetchone()
                if row is None:
                    if expected_version is not None:
                        raise ResidencyConflict("residency profile is unknown")
                    version = 1
                    cursor.execute(
                        """INSERT INTO tenant_residency_profiles (
                               tenant_id, version, regions_json, profile_sha256, updated_at
                           ) VALUES (?, ?, ?, ?, ?)""",
                        (
                            profile.tenant_id,
                            version,
                            _regions_json(profile),
                            profile_hash,
                            _utc(self._clock()).isoformat(),
                        ),
                    )
                else:
                    current_version = _stored_version(row["version"])
                    stored_profile = _profile_from_row(
                        profile.tenant_id,
                        row["regions_json"],
                        row["profile_sha256"],
                    )
                    if expected_version != current_version:
                        raise ResidencyConflict("residency profile version changed")
                    if stored_profile == profile:
                        self._db.commit()
                        return profile
                    version = current_version + 1
                    cursor.execute(
                        """UPDATE tenant_residency_profiles
                           SET version=?, regions_json=?, profile_sha256=?, updated_at=?
                           WHERE tenant_id=? AND version=?""",
                        (
                            version,
                            _regions_json(profile),
                            profile_hash,
                            _utc(self._clock()).isoformat(),
                            profile.tenant_id,
                            current_version,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise ResidencyConflict("residency profile update lost a race")
                self._db.commit()
                return profile
            except Exception:
                self._db.rollback()
                raise
            finally:
                cursor.close()

    def get(self, *, tenant_id: str) -> tuple[ResidencyProfile, int, str]:
        _require_identifier(tenant_id)
        with self._lock:
            row = self._db.execute(
                """SELECT version, regions_json, profile_sha256
                   FROM tenant_residency_profiles WHERE tenant_id=?""",
                (tenant_id,),
            ).fetchone()
            if row is None:
                raise ResidencyConflict("residency profile is unavailable")
            version = _stored_version(row["version"])
            profile = _profile_from_row(tenant_id, row["regions_json"], row["profile_sha256"])
            return profile, version, str(row["profile_sha256"])

    def require_region(self, *, tenant_id: str, region: str) -> ResidencyDecision:
        if self._deployment_region is None:
            raise ResidencyConflict("deployment region is not configured")
        return self.authorize_transfer(
            tenant_id=tenant_id,
            source_region=self._deployment_region,
            destination_region=region,
        )

    def restrict_to_configured_tenants(self, tenant_ids: Collection[str]) -> None:
        """Use only explicitly configured tenants while retaining durable profiles."""
        try:
            retained = frozenset(tenant_ids)
        except TypeError as error:
            raise ResidencyConflict("residency tenant set is invalid") from error
        for tenant_id in retained:
            _require_identifier(tenant_id)
        with self._lock:
            self._configured_tenants = retained

    def authorize_transfer(
        self,
        *,
        tenant_id: str,
        source_region: str,
        destination_region: str,
    ) -> ResidencyDecision:
        with self._lock:
            _require_identifier(tenant_id)
            if self._configured_tenants is not None and tenant_id not in self._configured_tenants:
                raise ResidencyConflict("residency profile is not configured")
            profile, version, profile_hash = self.get(tenant_id=tenant_id)
            try:
                require_transfer(
                    profile,
                    source_region=source_region,
                    destination_region=destination_region,
                )
            except (ResidencyDenied, TypeError, ValueError) as error:
                raise ResidencyConflict("residency transfer is denied") from error
            return ResidencyDecision(
                tenant_id=tenant_id,
                source_region=source_region,
                destination_region=destination_region,
                profile_sha256=profile_hash,
                profile_version=version,
                same_region=source_region == destination_region,
            )

    def _initialize_schema(self) -> None:
        try:
            for statement in RESIDENCY_SCHEMA_STATEMENTS:
                self._db.execute(statement)
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise


def _profile_hash(profile: ResidencyProfile) -> str:
    return _digest(
        {
            "schema_version": _SCHEMA_VERSION,
            "tenant_id": profile.tenant_id,
            "allowed_regions": sorted(profile.allowed_regions),
        }
    )


def _regions_json(profile: ResidencyProfile) -> str:
    return json.dumps(
        sorted(profile.allowed_regions),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    )


def _profile_from_row(tenant_id: str, raw_regions: object, raw_hash: object) -> ResidencyProfile:
    if type(raw_regions) is not str or type(raw_hash) is not str:
        raise ResidencyConflict("stored residency profile is invalid")
    try:
        regions = json.loads(raw_regions)
    except json.JSONDecodeError as error:
        raise ResidencyConflict("stored residency profile is invalid") from error
    if type(regions) is not list or not all(type(region) is str for region in regions):
        raise ResidencyConflict("stored residency profile is invalid")
    if len(regions) != len(set(regions)):
        raise ResidencyConflict("stored residency profile is invalid")
    try:
        profile = ResidencyProfile(tenant_id, frozenset(regions))
    except (TypeError, ValueError):
        raise ResidencyConflict("stored residency profile is invalid") from None
    if raw_regions != _regions_json(profile):
        raise ResidencyConflict("stored residency profile is invalid")
    if _profile_hash(profile) != raw_hash:
        raise ResidencyConflict("stored residency profile hash is invalid")
    return profile


def _digest(value: object) -> str:
    try:
        payload = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise ResidencyConflict("residency profile is invalid") from error
    return hashlib.sha256(payload).hexdigest()


def _require_identifier(value: object) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ResidencyConflict("tenant identifier is invalid")


def _require_region(value: object) -> None:
    if type(value) is not str or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", value) is None:
        raise ResidencyConflict("residency region is invalid")


def _stored_version(value: object) -> int:
    if type(value) is not int or value < 1:
        raise ResidencyConflict("stored residency version is invalid")
    return value


def _utc(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ResidencyConflict("residency clock returned an invalid timestamp")
    try:
        result = value.astimezone(UTC)
    except (TypeError, ValueError, OverflowError) as error:
        raise ResidencyConflict("residency clock returned an invalid timestamp") from error
    if result.utcoffset() != UTC.utcoffset(result):
        raise ResidencyConflict("residency clock returned an invalid timestamp")
    return result


_MAX_RESIDENCY_TENANTS: Final = 64
_MAX_RESIDENCY_REGIONS: Final = 64


def load_residency_registry(
    connection: sqlite3.Connection,
    values: Mapping[str, str],
) -> SqliteResidencyRegistry:
    """Load the strict tenant allowlist and reconcile durable profiles."""

    if not isinstance(values, Mapping):
        raise TypeError("environment values must be a mapping")
    raw_deployment_region = values.get("SECURECODE_DATA_REGION")
    deployment_region = raw_deployment_region if raw_deployment_region else None
    if deployment_region is not None:
        try:
            _require_region(deployment_region)
        except ResidencyConflict:
            raise ValueError("residency configuration is invalid") from None
    registry = SqliteResidencyRegistry(connection, deployment_region=deployment_region)
    raw = values.get("SECURECODE_TENANT_RESIDENCY_REGIONS")
    if not raw:
        registry.restrict_to_configured_tenants(())
        return registry
    if deployment_region is None:
        raise ValueError("residency deployment region is required")
    if type(raw) is not str or not raw:
        raise ValueError("residency configuration is invalid")
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        raise ValueError("residency configuration is invalid") from None
    if type(document) is not dict or len(document) > _MAX_RESIDENCY_TENANTS:
        raise ValueError("residency configuration is invalid")
    profiles: list[ResidencyProfile] = []
    for tenant_id, raw_regions in document.items():
        if type(tenant_id) is not str:
            raise ValueError("residency configuration is invalid")
        try:
            _require_identifier(tenant_id)
        except ResidencyConflict:
            raise ValueError("residency configuration is invalid") from None
        if (
            type(raw_regions) is not list
            or not 1 <= len(raw_regions) <= _MAX_RESIDENCY_REGIONS
            or not all(type(region) is str for region in raw_regions)
            or len(raw_regions) != len(set(raw_regions))
        ):
            raise ValueError("residency configuration is invalid")
        try:
            for region in raw_regions:
                _require_region(region)
            profiles.append(ResidencyProfile(tenant_id, frozenset(raw_regions)))
        except (ResidencyConflict, TypeError, ValueError):
            raise ValueError("residency configuration is invalid") from None
    for profile in profiles:
        try:
            _, version, _ = registry.get(tenant_id=profile.tenant_id)
        except ResidencyConflict:
            registry.set_profile(profile)
        else:
            registry.set_profile(profile, expected_version=version)
    registry.restrict_to_configured_tenants(document.keys())
    return registry


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate residency tenant")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


__all__ = [
    "RESIDENCY_SCHEMA_STATEMENTS",
    "ResidencyConflict",
    "ResidencyDecision",
    "ResidencyGuard",
    "SqliteResidencyRegistry",
    "load_residency_registry",
]
