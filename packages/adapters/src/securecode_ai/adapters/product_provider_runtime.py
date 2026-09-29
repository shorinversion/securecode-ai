"""Approved provider composition for the real product checkout runner."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from securecode_ai.contracts import (
    DataClass,
    EgressPolicyDocument,
    ModelPurpose,
    ProviderKind,
    ProviderProfile,
)

from .config import (
    ConfigSource,
    CredentialLease,
    EffectiveConfiguration,
    ProviderProfileRegistry,
    SelectionProvenance,
    parse_provider_profile,
    resolve_environment_credential,
)
from .endpoint import Resolver
from .model import CredentialSupplier
from .openai_compatible_remote import OpenAICompatibleRemoteHttpsConnector
from .product_runtime_contracts import ProviderConnector
from .remote_provider_budget import RemoteProviderBudgetPort, RemoteProviderSpendPolicy
from .remote_provider_budget_sqlite import build_sqlite_remote_provider_budget

_MAX_DOCUMENT_BYTES: Final = 1_048_576
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_DECIMAL: Final = re.compile(r"(?:0|[1-9][0-9]{0,17})\Z")
_BUDGET_ENV: Final = {
    "WINDOW_MS": "window_ms",
    "MAX_CALLS": "max_calls_per_window",
    "MAX_CONCURRENT_CALLS": "max_concurrent_calls",
    "MAX_TOKENS": "max_tokens_per_window",
    "MAX_COST_MICROUNITS": "max_cost_microunits_per_window",
    "INPUT_MICROUNITS_PER_MILLION_TOKENS": "input_cost_microunits_per_million_tokens",
    "OUTPUT_MICROUNITS_PER_MILLION_TOKENS": "output_cost_microunits_per_million_tokens",
}


class ProductProviderConfigurationError(ValueError):
    """Safe fail-closed configuration error for a product provider runtime."""


@dataclass(frozen=True, slots=True)
class ProductProviderOperation:
    """One purpose-bound provider operation and its independent spend scope."""

    purpose: ModelPurpose
    profile: ProviderProfile
    policy: EgressPolicyDocument
    registry: ProviderProfileRegistry
    resolver: Resolver
    connector: ProviderConnector
    credential_supplier: CredentialSupplier
    spend_budget: RemoteProviderBudgetPort

    def __post_init__(self) -> None:
        if (
            self.purpose is not ModelPurpose.PATCH_GENERATION
            or type(self.profile) is not ProviderProfile
            or type(self.policy) is not EgressPolicyDocument
            or type(self.registry) is not ProviderProfileRegistry
            or not callable(getattr(self.resolver, "resolve", None))
            or not callable(getattr(self.connector, "connect", None))
            or not callable(getattr(self.connector, "send", None))
            or not callable(self.credential_supplier)
            or not all(
                callable(getattr(self.spend_budget, name, None))
                for name in ("reserve", "settle", "charge_maximum", "release")
            )
        ):
            raise ProductProviderConfigurationError("remote provider operation is invalid")


class ApprovedPublicResolver:
    """Resolve only globally routable addresses for the approved authority."""

    __slots__ = ()

    def resolve(self, authority: str, port: int) -> tuple[str, ...]:
        if (
            type(authority) is not str
            or not authority
            or type(port) is not int
            or not 1 <= port <= 65535
        ):
            raise ProductProviderConfigurationError("remote endpoint resolver rejected")
        try:
            raw = socket.getaddrinfo(authority, port, type=socket.SOCK_STREAM)
            addresses = {
                ipaddress.ip_address(item[4][0]).compressed
                for item in raw
                if isinstance(item[4][0], str) and ipaddress.ip_address(item[4][0]).is_global
            }
        except (OSError, ValueError, IndexError, TypeError):
            raise ProductProviderConfigurationError("remote endpoint resolution failed") from None
        if not addresses or len(addresses) > 32:
            raise ProductProviderConfigurationError("remote endpoint resolution failed")
        return tuple(sorted(addresses))


@dataclass(frozen=True, slots=True)
class ProductProviderRuntime:
    """All approved ports required by the installed product composition."""

    profile: ProviderProfile
    policy: EgressPolicyDocument
    configuration: EffectiveConfiguration
    registry: ProviderProfileRegistry
    resolver: Resolver
    connector: ProviderConnector
    credential_supplier: CredentialSupplier
    spend_budget: RemoteProviderBudgetPort
    repair_operation: ProductProviderOperation | None = None

    def __post_init__(self) -> None:
        if (
            type(self.profile) is not ProviderProfile
            or type(self.policy) is not EgressPolicyDocument
            or type(self.configuration) is not EffectiveConfiguration
            or type(self.registry) is not ProviderProfileRegistry
            or self.profile.provider_kind is not ProviderKind.OPENAI_COMPATIBLE_REMOTE
            or type(self.profile.protocol_framing_token_upper_bound) is not int
            or self.configuration.provider_profile != self.profile
            or self.configuration.policy_profile_id != self.policy.policy_id
            or self.configuration.egress_profile is not self.policy.profile
            or self.policy.profile not in self.profile.egress_profiles
            or not callable(getattr(self.resolver, "resolve", None))
            or not callable(getattr(self.connector, "connect", None))
            or not callable(getattr(self.connector, "send", None))
            or not callable(self.credential_supplier)
            or not all(
                callable(getattr(self.spend_budget, name, None))
                for name in ("reserve", "settle", "charge_maximum", "release")
            )
        ):
            raise ProductProviderConfigurationError("remote provider runtime is invalid")
        if self.registry.require_registered(self.profile) != self.profile:
            raise ProductProviderConfigurationError("remote provider profile is not registered")
        if self.repair_operation is not None and (
            self.repair_operation.profile != self.profile
            or self.repair_operation.policy != self.policy
            or self.repair_operation.registry is not self.registry
            or self.repair_operation.credential_supplier is not self.credential_supplier
        ):
            raise ProductProviderConfigurationError("remote repair operation is not bound")

    def close(self) -> None:
        close = getattr(self.spend_budget, "close", None)
        try:
            if callable(close):
                close()
        finally:
            if self.repair_operation is not None:
                repair_close = getattr(self.repair_operation.spend_budget, "close", None)
                if callable(repair_close):
                    repair_close()

    def repair(self) -> ProductProviderOperation:
        operation = self.repair_operation
        if operation is None:
            raise ProductProviderConfigurationError("remote repair budget is unavailable")
        return operation


def load_product_provider_runtime(
    *,
    profile_path: str | Path,
    policy_path: str | Path,
    environment: Mapping[str, str],
    tenant_id: str,
    expected_profile_sha256: str | None,
    expected_policy_sha256: str | None,
    expected_egress_sha256: str | None,
    expected_configuration_sha256: str | None = None,
) -> ProductProviderRuntime:
    """Load and bind a remote profile, policy and durable spend budget.

    Every identity hash is mandatory for the connected worker path. The
    configuration is rejected before resolver use or provider HTTP bytes.
    """

    if not isinstance(environment, Mapping) or not isinstance(tenant_id, str) or not tenant_id:
        raise ProductProviderConfigurationError("remote provider configuration is invalid")
    for value in (
        expected_profile_sha256,
        expected_policy_sha256,
        expected_egress_sha256,
    ):
        if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
            raise ProductProviderConfigurationError("remote provider pin is missing")
    profile_bytes = _read_document(profile_path)
    policy_bytes = _read_document(policy_path)
    profile = parse_provider_profile(profile_bytes)
    policy = _parse_policy(policy_bytes)
    if (
        profile.canonical_content_hash() != expected_profile_sha256
        or policy.canonical_content_hash() != expected_policy_sha256
        or policy.canonical_content_hash() != expected_egress_sha256
        or policy.tenant_scope != tenant_id
        or profile.provider_kind is not ProviderKind.OPENAI_COMPATIBLE_REMOTE
        or profile.data_terms.maximum_input_data_class is not DataClass.CONFIDENTIAL_SOURCE
        or not {
            ModelPurpose.MODEL_NATIVE_DISCOVERY,
            ModelPurpose.CANDIDATE_INVESTIGATION,
            ModelPurpose.SKEPTIC_REVIEW,
        }.issubset(set(profile.data_terms.allowed_purposes))
        or policy.profile not in profile.egress_profiles
    ):
        raise ProductProviderConfigurationError("remote provider admission rejected")
    registry = ProviderProfileRegistry((profile,))
    configuration = EffectiveConfiguration(
        provider_profile=profile,
        policy_profile_id=policy.policy_id,
        egress_profile=policy.profile,
        provenance=(
            SelectionProvenance("egress_profile", ConfigSource.APPROVED_REGISTRY),
            SelectionProvenance("policy_profile", ConfigSource.APPROVED_REGISTRY),
            SelectionProvenance("provider_profile", ConfigSource.APPROVED_REGISTRY),
        ),
    )
    if expected_configuration_sha256 is not None and (
        _SHA256.fullmatch(expected_configuration_sha256) is None
        or configuration.canonical_content_hash() != expected_configuration_sha256
    ):
        raise ProductProviderConfigurationError("remote configuration pin rejected")
    spend_policy = _spend_policy(environment, tenant_id=tenant_id, model_id=profile.model_id)
    budget = build_sqlite_remote_provider_budget(environment, policy=spend_policy)
    if budget is None:
        raise ProductProviderConfigurationError("remote spend budget is unavailable")
    connector = OpenAICompatibleRemoteHttpsConnector(profile=profile, spend_budget=budget)

    def credential_supplier(selected: ProviderProfile) -> CredentialLease | None:
        return resolve_environment_credential(selected, environment, registry=registry)

    repair_operation: ProductProviderOperation | None = None
    if (
        ModelPurpose.PATCH_GENERATION in profile.data_terms.allowed_purposes
        and _policy_allows_patch_generation(policy, profile)
    ):
        repair_environment = dict(environment)
        repair_path = environment.get("SECURECODE_REMOTE_REPAIR_SPEND_DB")
        main_path = environment.get("SECURECODE_REMOTE_SPEND_DB")
        distinct_repair_path: str | None = None
        if isinstance(repair_path, str) and repair_path and isinstance(main_path, str):
            try:
                if Path(repair_path).absolute() != Path(main_path).absolute():
                    distinct_repair_path = repair_path
            except (OSError, ValueError):
                distinct_repair_path = None
        if distinct_repair_path is not None:
            repair_environment["SECURECODE_REMOTE_SPEND_DB"] = distinct_repair_path
            for suffix in _BUDGET_ENV:
                repair_environment["SECURECODE_REMOTE_SPEND_" + suffix] = environment.get(
                    "SECURECODE_REMOTE_REPAIR_SPEND_" + suffix,
                    "",
                )
            try:
                repair_policy = _spend_policy(
                    repair_environment,
                    tenant_id=tenant_id,
                    model_id=profile.model_id,
                )
                repair_budget = build_sqlite_remote_provider_budget(
                    repair_environment, policy=repair_policy
                )
            except ProductProviderConfigurationError:
                repair_budget = None
            if repair_budget is not None:
                repair_connector = OpenAICompatibleRemoteHttpsConnector(
                    profile=profile, spend_budget=repair_budget
                )
                repair_operation = ProductProviderOperation(
                    purpose=ModelPurpose.PATCH_GENERATION,
                    profile=profile,
                    policy=policy,
                    registry=registry,
                    resolver=ApprovedPublicResolver(),
                    connector=repair_connector,
                    credential_supplier=credential_supplier,
                    spend_budget=repair_budget,
                )

    runtime = ProductProviderRuntime(
        profile=profile,
        policy=policy,
        configuration=configuration,
        registry=registry,
        resolver=ApprovedPublicResolver(),
        connector=connector,
        credential_supplier=credential_supplier,
        spend_budget=budget,
        repair_operation=repair_operation,
    )
    return runtime


def _read_document(path: str | Path) -> bytes:
    candidate = Path(path)
    descriptor = -1
    try:
        if not candidate.is_absolute() or candidate.is_symlink():
            raise ValueError
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if os.name != "nt":
            flags |= getattr(os, "O_NOFOLLOW", 0)
        else:
            flags |= getattr(os, "O_BINARY", 0)
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        named = os.lstat(candidate)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (reparse and getattr(opened, "st_file_attributes", 0) & reparse)
            or not stat.S_ISREG(named.st_mode)
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            or opened.st_size > _MAX_DOCUMENT_BYTES
        ):
            raise ValueError
        buffer = bytearray()
        while len(buffer) <= _MAX_DOCUMENT_BYTES:
            chunk = os.read(
                descriptor,
                min(65_536, _MAX_DOCUMENT_BYTES + 1 - len(buffer)),
            )
            if not chunk:
                break
            buffer.extend(chunk)
        if len(buffer) > _MAX_DOCUMENT_BYTES:
            raise ValueError
    except (OSError, ValueError):
        raise ProductProviderConfigurationError("remote provider document is unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    data = bytes(buffer)
    if not data or len(data) > _MAX_DOCUMENT_BYTES or b"\x00" in data:
        raise ProductProviderConfigurationError("remote provider document is invalid")
    return data


def _parse_policy(data: bytes) -> EgressPolicyDocument:
    try:
        pairs = json.loads(data.decode("utf-8"), object_pairs_hook=_closed_pairs)
        return EgressPolicyDocument.model_validate_json(
            json.dumps(pairs, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        )
    except (RecursionError, UnicodeError, TypeError, ValueError):
        raise ProductProviderConfigurationError("remote egress policy is invalid") from None


def _closed_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate policy member")
        result[key] = value
    return result


def _spend_policy(
    environment: Mapping[str, str],
    *,
    tenant_id: str,
    model_id: str,
    prefix: str = "SECURECODE_REMOTE_SPEND_",
) -> RemoteProviderSpendPolicy:
    values: dict[str, int] = {}
    for suffix, field in _BUDGET_ENV.items():
        raw = environment.get(prefix + suffix)
        if not isinstance(raw, str) or _DECIMAL.fullmatch(raw) is None:
            raise ProductProviderConfigurationError("remote spend budget is invalid")
        values[field] = int(raw)
    try:
        return RemoteProviderSpendPolicy(tenant_id=tenant_id, model_id=model_id, **values)
    except Exception:
        raise ProductProviderConfigurationError("remote spend budget is invalid") from None


def _policy_allows_patch_generation(policy: EgressPolicyDocument, profile: ProviderProfile) -> bool:
    destination = f"profile://{profile.profile_id}"
    return any(
        rule.effect.value == "allow"
        and ModelPurpose.PATCH_GENERATION.value in rule.purposes
        and destination in rule.destinations
        and DataClass.CONFIDENTIAL_SOURCE in rule.data_classes
        and tuple(rule.requires_transforms) == ("bounded_repository_view",)
        and isinstance(rule.max_bytes, int)
        and rule.max_bytes > 0
        for rule in policy.rules
    )


__all__ = [
    "ApprovedPublicResolver",
    "ProductProviderConfigurationError",
    "ProductProviderOperation",
    "ProductProviderRuntime",
    "load_product_provider_runtime",
]
